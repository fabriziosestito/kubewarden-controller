package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/kubewarden/kubewarden-controller/internal/certs"
	"github.com/kubewarden/kubewarden-controller/internal/constants"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type CertController struct {
	client.Client
	Log                 logr.Logger
	DeploymentNamespace string
}

const (
	caCertValidityDuration     = 10 * 365 * 24 * time.Hour
	serverCertValidityDuration = 1 * 365 * 24 * time.Hour
	lookAheadDuration          = 60 * time.Hour
	tickerDuration             = 12 * time.Hour
)

// Start begins the periodic reconciler.
func (r *CertController) Start(ctx context.Context) error {
	r.Log.Info("Starting CertController ticker")

	ticker := time.NewTicker(tickerDuration)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.Log.Info("Stopping CertController")
			return nil
		case <-ticker.C:
			if err := r.reconcile(ctx); err != nil {
				r.Log.Error(err, "Failed to")
			}
		}
	}
}

func (r *CertController) NeedLeaderElection() bool {
	return true
}

func (r *CertController) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.Add(r); err != nil {
		return fmt.Errorf("failed enrolling controller with manager: %w", err)
	}

	return nil
}

// reconcile performs the periodic reconciliation logic.
func (r *CertController) reconcile(ctx context.Context) error {
	// get the CA cert
	caCertSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: constants.CARootSecretName, Namespace: r.DeploymentNamespace}, caCertSecret); err != nil {
		return fmt.Errorf("failed to get CA cert secret: %w", err)
	}
	caCert, ok := caCertSecret.Data[constants.CARootCert]
	if !ok {
		return fmt.Errorf("secret is not well formed, missing %s", "ca.crt")
	}
	caPrivateKey, ok := caCertSecret.Data[constants.CARootPrivateKey]
	if !ok {
		return fmt.Errorf("secret is not well formed, missing %s", "ca.key")
	}

	// get the webhook server cert webhookServerCertSecret
	webhookServerCertSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: constants.WebhookServerCertSecretName, Namespace: r.DeploymentNamespace}, webhookServerCertSecret); err != nil {
		return fmt.Errorf("failed to get webhook server cert secret: %w", err)
	}
	// rotate the server cert
	dnsName := "webhook-server.kubewarden.svc"
	if err := r.reconcileServerCert(ctx, webhookServerCertSecret, caCert, caPrivateKey, dnsName); err != nil {
		return fmt.Errorf("failed to rotate server cert: %w", err)
	}

	serverCertSecretList := &corev1.SecretList{}
	err := r.List(ctx,
		serverCertSecretList,
		client.InNamespace(r.DeploymentNamespace),
		client.MatchingLabels{
			"app.kubernetes.io/part-of":   "kubewarden",
			"app.kubernetes.io/component": "policy-server",
		},
	)
	if err != nil {
		return fmt.Errorf("failed to list policy server cert secrets: %w", err)
	}

	for _, serverCertSecret := range serverCertSecretList.Items {
		// reconcileServerCert for policy server
		dnsName := fmt.Sprintf("%s.%s.svc", serverCertSecret.Name, r.DeploymentNamespace)
		if err := r.reconcileServerCert(ctx, &serverCertSecret, caCert, caPrivateKey, dnsName); err != nil {
			return fmt.Errorf("failed to rotate server cert: %w", err)
		}
	}

	return nil
}

func (r *CertController) reconcileServerCert(ctx context.Context, serverCertSecret *corev1.Secret, caCert, caPrivateKey []byte, dnsName string) error {
	cert, ok := serverCertSecret.Data[constants.ServerCert]
	if !ok {
		return fmt.Errorf("secret is not well formed, missing %s", constants.ServerCert)
	}
	privateKey, ok := serverCertSecret.Data[constants.ServerKey]
	if !ok {
		return fmt.Errorf("secret is not well formed, missing %s", constants.ServerKey)
	}

	validCert, err := ValidCert(caCert, cert, privateKey, "webhook-server", nil, time.Now())
	if err != nil {
		return fmt.Errorf("failed to validate cert: %w", err)
	}
	if validCert {
		return nil
	}

	// generate a new server rotateServerCert
	newCert, newPrivateKey, err := certs.GenerateCert(caCert, caPrivateKey, dnsName, []string{dnsName})
	if err != nil {
		return fmt.Errorf("failed to generate cert: %w", err)
	}

	serverCertSecret.Data[constants.ServerCert] = newCert
	serverCertSecret.Data[constants.ServerKey] = newPrivateKey

	if err := r.Update(ctx, serverCertSecret); err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	return nil
}

func ValidCert(caCert, cert, key []byte, dnsName string, keyUsages *[]x509.ExtKeyUsage, at time.Time) (bool, error) {
	if len(caCert) == 0 || len(cert) == 0 || len(key) == 0 {
		return false, errors.New("empty cert")
	}

	pool := x509.NewCertPool()
	caDer, _ := pem.Decode(caCert)
	if caDer == nil {
		return false, errors.New("bad CA cert")
	}
	cac, err := x509.ParseCertificate(caDer.Bytes)
	if err != nil {
		return false, errors.Wrap(err, "parsing CA cert")
	}
	pool.AddCert(cac)

	_, err = tls.X509KeyPair(cert, key)
	if err != nil {
		return false, errors.Wrap(err, "building key pair")
	}

	b, _ := pem.Decode(cert)
	if b == nil {
		return false, errors.New("bad private key")
	}

	crt, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return false, errors.Wrap(err, "parsing cert")
	}

	opt := x509.VerifyOptions{
		DNSName:     dnsName,
		Roots:       pool,
		CurrentTime: at,
	}
	if keyUsages != nil {
		opt.KeyUsages = *keyUsages
	}

	_, err = crt.Verify(opt)
	if err != nil {
		return false, errors.Wrap(err, "verifying cert")
	}
	return true, nil
}

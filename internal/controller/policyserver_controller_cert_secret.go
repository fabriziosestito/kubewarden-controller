package controller

import (
	"context"
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	policiesv1 "github.com/kubewarden/kubewarden-controller/api/policies/v1"
	"github.com/kubewarden/kubewarden-controller/internal/certs"
	"github.com/kubewarden/kubewarden-controller/internal/constants"
)

// Reconcile the certificate to be used by the policy server for TLS. The
// generated certificate is signed by the CA certificate provided in the
// caSecret. The generated certificate is stored in a secret.
func (r *PolicyServerReconciler) reconcilePolicyServerCertSecret(ctx context.Context, policyServer *policiesv1.PolicyServer) error {
	caSecret := &corev1.Secret{}

	err := r.Client.Get(ctx, types.NamespacedName{Name: constants.CARootSecretName, Namespace: r.DeploymentsNamespace}, caSecret)
	if err != nil {
		return fmt.Errorf("failed to fetch CA secret: %w", err)
	}

	policyServerSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: r.DeploymentsNamespace,
			Name:      policyServer.NameWithPrefix(),
		},
	}

	_, err = controllerutil.CreateOrPatch(ctx, r.Client, policyServerSecret, func() error {
		if err := controllerutil.SetOwnerReference(policyServer, policyServerSecret, r.Client.Scheme()); err != nil {
			return errors.Join(errors.New("failed to set policy server secret owner reference"), err)
		}

		// check if secret has the required data
		_, hasTLSCert := policyServerSecret.Data[constants.PolicyServerTLSCert]
		_, hasTLSKey := policyServerSecret.Data[constants.PolicyServerTLSKey]
		if !hasTLSCert || !hasTLSKey {
			caCert, caPrivateKey, err := extractCAFromSecret(caSecret)
			if err != nil {
				return err
			}

			cert, privateKey, err := certs.GenerateCert(
				caCert,
				caPrivateKey,
				fmt.Sprintf("%s.%s.svc", policyServer.NameWithPrefix(), r.DeploymentsNamespace),
				[]string{fmt.Sprintf("%s.%s.svc", policyServer.NameWithPrefix(), r.DeploymentsNamespace)},
			)
			if err != nil {
				return fmt.Errorf("cannot generate policy-server %s certificate: %w", policyServer.NameWithPrefix(), err)
			}

			policyServerSecret.Type = corev1.SecretTypeOpaque
			policyServerSecret.StringData = map[string]string{
				constants.PolicyServerTLSCert: string(cert),
				constants.PolicyServerTLSKey:  string(privateKey),
			}
		}

		return nil
	})
	if err != nil {
		setFalseConditionType(
			&policyServer.Status.Conditions,
			string(policiesv1.PolicyServerCertSecretReconciled),
			fmt.Sprintf("error reconciling secret: %v", err),
		)
		return errors.Join(errors.New("cannot fetch or initialize Policy Server CA secret"), err)
	}

	setTrueConditionType(
		&policyServer.Status.Conditions,
		string(policiesv1.PolicyServerCertSecretReconciled),
	)

	return nil
}

// Extract the CA certificate and private key from the secret storing the CA data
// used in the policy server certificate generation.
func extractCAFromSecret(caSecret *corev1.Secret) ([]byte, []byte, error) {
	caCert, ok := caSecret.Data[constants.CARootCert]
	if !ok {
		return nil, nil, fmt.Errorf("CA could not be extracted from secret %s", caSecret.Kind)
	}

	caPrivateKey, ok := caSecret.Data[constants.CARootPrivateKey]
	if !ok {
		return nil, nil, fmt.Errorf("CA private key bytes could not be extracted from secret %s", caSecret.Kind)
	}

	return caCert, caPrivateKey, nil
}

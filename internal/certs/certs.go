package certs

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/kubewarden/kubewarden-controller/internal/constants"
)

const (
	bitSize = 4096
	base    = 2
	exp     = 159
)

// GenerateCA generates a self-signed CA root certificate and private key in PEM format.
// The certificate is valid for 10 years.
func GenerateCA() ([]byte, []byte, error) {
	serialNumber, err := rand.Int(rand.Reader, (&big.Int{}).Exp(big.NewInt(base), big.NewInt(exp), nil))
	if err != nil {
		return nil, nil, fmt.Errorf("cannot init serial number: %w", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create private key: %w", err)
	}

	caCert := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:  []string{""},
			Country:       []string{""},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(constants.CertExpirationYears, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caCertBytes, err := x509.CreateCertificate(
		rand.Reader,
		&caCert,
		&caCert,
		&privateKey.PublicKey,
		privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create certificate: %w", err)
	}

	caCertPEM, err := pemEncodeCertificate(caCertBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot encode certificate: %w", err)
	}

	privateKeyPEM, err := pemEncodePrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot encode private key: %w", err)
	}

	return caCertPEM, privateKeyPEM, nil
}

// GenerateCert generates a certificate and private key signed by the provided CA in PEM format.
// The certificate is valid for 1 year.
func GenerateCert(caCertPEM []byte,
	caPrivateKeyPEM []byte,
	commonName string,
	extraSANs []string,
) ([]byte, []byte, error) {
	caCertBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing ca root certificate: %w", err)
	}

	caPrivateKeyBlock, _ := pem.Decode(caPrivateKeyPEM)
	caPrivateKey, err := x509.ParsePKCS1PrivateKey(caPrivateKeyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing ca root private key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, (&big.Int{}).Exp(big.NewInt(base), big.NewInt(exp), nil))
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate serialNumber for certificate: %w", err)
	}

	// key size must be higher than 1024, otherwise the PolicyServer
	// TLS acceptor will refuse to start
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot generate private key: %w", err)
	}

	sansHosts := []string{}
	sansIps := []net.IP{}
	for _, san := range extraSANs {
		sanIP := net.ParseIP(san)
		if sanIP == nil {
			sansHosts = append(sansHosts, san)
		} else {
			sansIps = append(sansIps, sanIP)
		}
	}

	cert := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:    commonName,
			Organization:  []string{""},
			Country:       []string{""},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		DNSNames:     sansHosts,
		IPAddresses:  sansIps,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(constants.CertExpirationYears, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		&cert,
		caCert,
		&privateKey.PublicKey,
		caPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create certificate: %w", err)
	}

	certPEM, err := pemEncodeCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot encode certificate: %w", err)
	}

	privateKeyPEM, err := pemEncodePrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot encode private key: %w", err)
	}

	return certPEM, privateKeyPEM, nil
}

// pemEncodeCertificate encodes a certificate to PEM format.
func pemEncodeCertificate(certificate []byte) ([]byte, error) {
	certificatePEM := new(bytes.Buffer)

	err := pem.Encode(certificatePEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate,
	})
	if err != nil {
		return []byte{}, fmt.Errorf("PEM encode failure: %w", err)
	}

	return certificatePEM.Bytes(), nil
}

// pemEncodePrivateKey encodes a private key to PEM format.
func pemEncodePrivateKey(privateKey *rsa.PrivateKey) ([]byte, error) {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := new(bytes.Buffer)

	err := pem.Encode(privateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	if err != nil {
		return []byte{}, fmt.Errorf("PEM encode failure: %w", err)
	}

	return privateKeyPEM.Bytes(), nil
}

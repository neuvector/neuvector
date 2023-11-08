package main

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
)

func GetInternalCACertTemplate(validDays int) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(5029),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Province:     []string{"California"},
			Organization: []string{"NeuVector Inc."},
			CommonName:   "NeuVector",
		},
		NotBefore:             time.Now().Add(time.Hour * -1), // Give it some room for timing skew.
		NotAfter:              time.Now().AddDate(0, 0, validDays),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
}

func GetInternalCertTemplate(validDays int) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(5030),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Province:     []string{"California"},
			Organization: []string{"NeuVector Inc."},
			CommonName:   "NeuVector",
		},
		NotBefore:    time.Now().Add(time.Hour * -1), // Give it some room for timing skew.
		NotAfter:     time.Now().AddDate(0, 0, validDays),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
}

func IsCertPresent(secret *corev1.Secret, prefix string) bool {
	if data, ok := secret.Data[prefix+CACERT_FILENAME]; !ok || len(data) == 0 {
		return false
	}
	if data, ok := secret.Data[prefix+CERT_FILENAME]; !ok || len(data) == 0 {
		return false
	}
	if data, ok := secret.Data[prefix+KEY_FILENAME]; !ok || len(data) == 0 {
		return false
	}
	return true
}

func IsSameCert(secret *corev1.Secret, prefix1 string, prefix2 string) bool {
	return reflect.DeepEqual(secret.Data[prefix1+CACERT_FILENAME], secret.Data[prefix2+CACERT_FILENAME]) &&
		reflect.DeepEqual(secret.Data[prefix1+CERT_FILENAME], secret.Data[prefix2+CERT_FILENAME]) &&
		reflect.DeepEqual(secret.Data[prefix1+KEY_FILENAME], secret.Data[prefix2+KEY_FILENAME])
}

// IsUpgradeInProgress verifies that if an upgrade is still in progress.
// This is determined by checking if newSecret, activeSecret and destSecret are consistent.
//
// This is because the upgrader will move newSecret to activeSecret and finally destSecret.
// That means, after upgrade, these three secrets should be the same.
// If they're the same, return false, otherwise, return true.
func IsUpgradeInProgress(ctx context.Context, secret *corev1.Secret) bool {
	if secret == nil {
		return false
	}
	return !IsSameCert(secret, NEW_SECRET_PREFIX, DEST_SECRET_PREFIX) || !IsSameCert(secret, NEW_SECRET_PREFIX, ACTIVE_SECRET_PREFIX)
}

package kv

import (
	"crypto/x509"
	"fmt"
	"testing"
	"time"

	"github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertManager(t *testing.T) {
	CN := "testcn"

	var mockCluster MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster

	cert_verified := false
	var olddata *share.CLUSX509Cert
	cm := NewCertManager(CertManagerConfig{
		ExpiryCheckPeriod: time.Second * 10,
	})
	require.NoError(t, cm.Register(CN, &CertManagerCallback{
		NewCert: func(*share.CLUSX509Cert) (*share.CLUSX509Cert, error) {
			cert, key, err := GenTlsKeyCert(CN, "", "", ValidityPeriod{}, x509.ExtKeyUsageAny)
			if err != nil {
				return nil, fmt.Errorf("failed to generate tls key/cert: %w", err)
			}
			return &share.CLUSX509Cert{
				CN:   CN,
				Key:  string(key),
				Cert: string(cert),
			}, nil
		},
		NotifyNewCert: func(oldcert *share.CLUSX509Cert, newcert *share.CLUSX509Cert) {
			if oldcert != nil {
				assert.Equal(t, oldcert.CN, newcert.CN)
				assert.NotEqual(t, oldcert.Cert, newcert.Cert)
				assert.NotEqual(t, oldcert.Key, newcert.Key)
			}
			assert.Equal(t, olddata, newcert.OldCert)
			cert_verified = true
		},
	}))

	// Should generate certificates
	err := cm.CheckAndRenewCerts()
	assert.Nil(t, err)
	assert.True(t, cert_verified)

	olddata, _, err = clusHelper.GetObjectCertRev(CN)
	assert.Nil(t, err)

	// Will regenerate certificates since validity period is 0 second.
	err = cm.CheckAndRenewCerts()
	assert.Nil(t, err)
	assert.True(t, cert_verified)

	newdata, _, err := clusHelper.GetObjectCertRev(CN)
	assert.Nil(t, err)

	assert.Equal(t, olddata.CN, newdata.CN)
	assert.NotEqual(t, olddata.Cert, newdata.Cert)
	assert.NotEqual(t, olddata.Key, newdata.Key)
	assert.Equal(t, olddata, newdata.OldCert)
}

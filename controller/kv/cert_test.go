package kv

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/assert"
)

func VerifyCert(t *testing.T, cn string, cacertfile string, certfile string, keyfile string) {
	// Load CA cert
	cacertdata, err := ioutil.ReadFile(cacertfile)
	assert.Nil(t, err)

	// Load CA cert
	certdata, err := ioutil.ReadFile(certfile)
	assert.Nil(t, err)

	block, _ := pem.Decode([]byte(certdata))
	assert.NotNil(t, block)

	x509Cert, err := x509.ParseCertificate(block.Bytes)
	assert.Nil(t, err)

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(cacertdata))
	assert.True(t, ok)

	opts := x509.VerifyOptions{
		DNSName: cn,
		Roots:   roots,
	}

	_, err = x509Cert.Verify(opts)
	assert.Nil(t, err)
}

func TestGenerateCA(t *testing.T) {
	cert, key, err := generateCAWithRSAKey(nil, 1024)
	assert.Nil(t, err)
	assert.NotNil(t, cert)
	assert.NotNil(t, key)

	// Check if it can be read.
	_, err = tls.X509KeyPair(cert, key)
	assert.Nil(t, err)

	// Verify it's self-signed certificate
	block, _ := pem.Decode(cert)
	assert.NotNil(t, block)

	x509Cert, err := x509.ParseCertificate(block.Bytes)
	assert.Nil(t, err)

	err = x509Cert.CheckSignatureFrom(x509Cert)
	assert.Nil(t, err)
}

func TestSavePrivKeyCert(t *testing.T) {
	// Self-signed certs
	cert, key, err := generateTLSCertWithRSAKey(nil, 1024, nil, nil)
	assert.Nil(t, err)
	assert.NotNil(t, cert)
	assert.NotNil(t, key)

	dir, err := ioutil.TempDir("", "test-cert")
	assert.Nil(t, err)
	defer os.RemoveAll(dir)

	certfile := filepath.Join(dir, "cert.pem")
	keyfile := filepath.Join(dir, "key.pem")

	err = savePrivKeyCert(cert, key, certfile, keyfile)
	assert.Nil(t, err)

	// Try to load certs
	_, err = tls.LoadX509KeyPair(certfile, keyfile)
	assert.Nil(t, err)
}

func TestCASignTLSCert(t *testing.T) {
	var mockCluster MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster

	// Generate CA
	dir, err := ioutil.TempDir("", "test-cert")
	assert.Nil(t, err)
	defer os.RemoveAll(dir)

	certfile := filepath.Join(dir, "cert.pem")
	keyfile := filepath.Join(dir, "key.pem")
	cacertfile := filepath.Join(dir, "cacert.pem")
	cakeyfile := filepath.Join(dir, "cakey.pem")

	err = CreateCAFilesAndStoreInKv(cacertfile, cakeyfile)
	assert.Nil(t, err)

	// Generate TLS key/cert using CA.
	err = GenTlsCertWithCaAndStoreInFiles("www.google.com", certfile, keyfile, cacertfile, cakeyfile, ValidityPeriod{Year: 1}, x509.ExtKeyUsageServerAuth)
	assert.Nil(t, err)

	_, err = tls.LoadX509KeyPair(certfile, keyfile)
	assert.Nil(t, err)

	VerifyCert(t, "www.google.com", cacertfile, certfile, keyfile)
}

func TestGenTlsCertWithCaAndStoreInKv_SelfSign(t *testing.T) {
	var mockCluster MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster

	dir, err := ioutil.TempDir("", "test-cert")
	assert.Nil(t, err)
	defer os.RemoveAll(dir)

	certfile := filepath.Join(dir, "cert.pem")
	keyfile := filepath.Join(dir, "key.pem")

	//
	// Self-sign
	//
	err = GenTlsCertWithCaAndStoreInKv("CN", certfile, keyfile, "", "", ValidityPeriod{Year: 1})
	assert.Nil(t, err)

	_, err = tls.LoadX509KeyPair(certfile, keyfile)
	assert.Nil(t, err)

	VerifyCert(t, "CN", certfile, certfile, keyfile)

	// Run again. The existing certs should be reused.
	keydata, err := ioutil.ReadFile(keyfile)
	assert.Nil(t, err)
	certdata, err := ioutil.ReadFile(certfile)
	assert.Nil(t, err)

	err = GenTlsCertWithCaAndStoreInKv("CN", certfile, keyfile, "", "", ValidityPeriod{Year: 1})
	assert.Nil(t, err)

	keydata2, err := ioutil.ReadFile(keyfile)
	assert.Nil(t, err)
	certdata2, err := ioutil.ReadFile(certfile)
	assert.Nil(t, err)

	assert.Equal(t, keydata, keydata2)
	assert.Equal(t, certdata, certdata2)
}

func TestGenTlsCertWithCaAndStoreInKv_WithCA(t *testing.T) {
	var mockCluster MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster

	dir, err := ioutil.TempDir("", "test-cert")
	assert.Nil(t, err)
	defer os.RemoveAll(dir)

	certfile := filepath.Join(dir, "cert.pem")
	keyfile := filepath.Join(dir, "key.pem")
	cacertfile := filepath.Join(dir, "cacert.pem")
	cakeyfile := filepath.Join(dir, "cakey.pem")

	// Create CA, cert and verify the cert is accepted by the CA.
	err = CreateCAFilesAndStoreInKv(cacertfile, cakeyfile)
	assert.Nil(t, err)

	err = GenTlsCertWithCaAndStoreInKv("CN", certfile, keyfile, cacertfile, cakeyfile, ValidityPeriod{Year: 1})
	assert.Nil(t, err)

	_, err = tls.LoadX509KeyPair(certfile, keyfile)
	assert.Nil(t, err)

	VerifyCert(t, "CN", cacertfile, certfile, keyfile)

	// Run again. The existing CA should be kept.
	cakeydata, err := ioutil.ReadFile(cakeyfile)
	assert.Nil(t, err)
	cacertdata, err := ioutil.ReadFile(cacertfile)
	assert.Nil(t, err)

	err = CreateCAFilesAndStoreInKv(cacertfile, cakeyfile)
	assert.Nil(t, err)

	cakeydata2, err := ioutil.ReadFile(cakeyfile)
	assert.Nil(t, err)
	cacertdata2, err := ioutil.ReadFile(cacertfile)
	assert.Nil(t, err)

	assert.Equal(t, cakeydata, cakeydata2)
	assert.Equal(t, cacertdata, cacertdata2)
}

func TestStoreKeyCertMemoryInKV(t *testing.T) {
	var mockCluster MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster

	// Verify that when the same key is stored, the original one should be honored.
	cert, key, err := GenTlsKeyCert("CN", "", "", ValidityPeriod{Year: 1}, x509.ExtKeyUsageServerAuth)
	assert.Nil(t, err)
	data, err := StoreKeyCertMemoryInKV("CN", string(cert), string(key))
	assert.Nil(t, err)

	expected := share.CLUSX509Cert{
		CN:   "CN",
		Key:  string(key),
		Cert: string(cert),
	}
	assert.Equal(t, &expected, data)

	// Verify that when the same key is stored, the original one should be honored.
	cert, key, err = GenTlsKeyCert("CN", "", "", ValidityPeriod{Year: 1}, x509.ExtKeyUsageServerAuth)
	assert.Nil(t, err)
	data, err = StoreKeyCertMemoryInKV("CN", string(cert), string(key))
	assert.Nil(t, err)

	assert.Equal(t, &expected, data)

	// Verify that when the same key is stored, the original one should be honored.
	data, index, err := clusHelper.GetObjectCertRev("CN")
	assert.Nil(t, err)
	assert.Greater(t, index, uint64(0))
	assert.Equal(t, &expected, data)
}

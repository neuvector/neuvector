package kv

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"strconv"
	"time"

	"errors"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
)

const (
	AdmCAKeyPath  = "/etc/neuvector/certs/internal/adm_ca.key"
	AdmCACertPath = "/etc/neuvector/certs/internal/adm_ca.cert"

	CertTypeAdmCtrl   = "adm_ctrl"
	CertTypeFed       = "federation"
	DefaultRSAKeySize = 2048
)

type ValidityPeriod struct {
	Year  int
	Month int
	Day   int
}

var (
	RSAKeySize int
)

func init() {
	// Provide overrides.
	RSAKeySize = DefaultRSAKeySize
	if keysize := os.Getenv("RSA_KEYSIZE"); keysize != "" {
		if v, err := strconv.Atoi(keysize); err == nil {
			RSAKeySize = v
		}
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Unable to marshal ECDSA private key")
			return nil
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

// Save PEM to disk.
func savePrivKeyCert(certPEM []byte, keyPEM []byte, certPath, keyPath string) error {
	var err error
	var keyOut, certOut *os.File

	os.Remove(keyPath)
	os.Remove(certPath)
	keyOut, err = os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "path": keyPath}).Error("failed to open file for writing")
		goto cleanup
	}

	if _, err := keyOut.Write(keyPEM); err != nil {
		log.WithFields(log.Fields{"error": err, "path": keyPath}).Error("failed to write data to file")
		goto cleanup
	}

	certOut, err = os.Create(certPath)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "path": certPath}).Error("failed to open file for writing")
		goto cleanup
	}

	if _, err := certOut.Write(certPEM); err != nil {
		log.WithFields(log.Fields{"error": err, "path": keyPath}).Error("failed to write data to file")
		goto cleanup
	}

cleanup:
	if keyOut != nil {
		if err = keyOut.Close(); err != nil {
			log.WithFields(log.Fields{"error": err, "path": keyPath}).Error("error closing file")
			return err
		}
	}
	if certOut != nil {
		if err = certOut.Close(); err != nil {
			log.WithFields(log.Fields{"error": err, "path": certPath}).Error("error closing file")
			return err
		}
	}

	return nil
}

// Store key cert in kv.
// If data is not consistent, the data in kv will be used and files in keyPath and certPath will be modified.
func StoreKeyCertFilesInKV(kvkey string, certPath string, keyPath string) error {
	log.Info("store key/cert in new kv")
	certData, err := ioutil.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read ca cert: %w", err)
	}
	keyData, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read ca key: %w", err)
	}

	if len(certData) <= 0 {
		return errors.New("invalid cert data")
	}

	if len(keyData) <= 0 {
		return fmt.Errorf("invalid key data")
	}

	cert := &share.CLUSX509Cert{
		CN:   kvkey,
		Key:  string(keyData),
		Cert: string(certData),
	}
	if err := clusHelper.PutObjectCert(kvkey, keyPath, certPath, cert); err != nil {
		return err
	}

	return nil
}

// Store key cert in kv.
// If data is not consistent, the data in kv will be used and files in keyPath and certPath will be modified.
func StoreKeyCertMemoryInKV(kvkey string, certData string, keyData string) (*share.CLUSX509Cert, error) {
	log.Info("store key/cert in new kv")

	if len(certData) <= 0 {
		return nil, errors.New("invalid cert data")
	}

	if len(keyData) <= 0 {
		return nil, fmt.Errorf("invalid key data")
	}

	cert := share.CLUSX509Cert{
		CN:   kvkey,
		Key:  string(keyData),
		Cert: string(certData),
	}
	if err := clusHelper.PutObjectCertMemory(kvkey, &cert, &cert, 0); err != nil {
		return nil, err
	}

	return &cert, nil
}

// Create CA files using default template and store in specified path.
// If cert file already exists, it should be loaded and stored in kv instead if creating a new one.
func CreateCAFilesAndStoreInKv(certpath, keypath string) error {
	notfound := false
	if _, err := os.Stat(certpath); err != nil && os.IsNotExist(err) {
		notfound = true
	}
	if _, err := os.Stat(keypath); err != nil && os.IsNotExist(err) {
		notfound = true
	}

	if !notfound {
		// adm_ca.key / adm_ca.cert could exist when createCA() is called. For example,
		// In fresh deployment, customer maps a folder to controller pod's /etc/neuvector/certs/internal/ and provide their own root CA.
		// Do nothing in this case.
		log.WithFields(log.Fields{
			"certpath": certpath,
			"keypath":  keypath,
		}).Debug("found existing CA files")
	} else {
		// Only RSA is supported for now.
		cert, key, err := generateCAWithRSAKey(nil, RSAKeySize)
		if err != nil {
			return fmt.Errorf("failed to create ca certificate: %w", err)
		}
		if err := savePrivKeyCert(cert, key, certpath, keypath); err != nil {
			return fmt.Errorf("failed to save key/cert: %w", err)
		}
	}

	// cert.IsEmpty() is checked in if condition above.
	if err := StoreKeyCertFilesInKV(share.CLUSRootCAKey, certpath, keypath); err != nil {
		return fmt.Errorf("failed to store key into KV: %w", err)
	}
	return nil
}

// Create a default certificate template for CA cert.
// Note: If you're modifying this too much, the certificate might get unrecognized by verifyWebServerCert().
func GetDefaultCACertTemplate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(2019), // 1653
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"Neuvector"},
			OrganizationalUnit: []string{"Neuvector"},
			Locality:           []string{"EN"},
			Province:           []string{"CA"},
		},
		NotBefore:             time.Now().Add(time.Hour * -1), // Give it some room for timing skew.
		NotAfter:              time.Now().AddDate(10, 0, 0),   // Default 10 years. Change it if it's necessary.
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
}

// Create a default certificate template for TLS server and JWT signing.
// Note: If you're modifying this too much, the certificate might get unrecognized by verifyWebServerCert().
func GetDefaultTLSCertTemplate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(2029), // 1658
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"Neuvector"},
			OrganizationalUnit: []string{"Neuvector"},
			Locality:           []string{"EN"},
			Province:           []string{"CA"},
			//CommonName:         cn,
		},
		NotBefore:    time.Now().Add(time.Hour * -1), // Give it some room for timing skew.
		NotAfter:     time.Now().AddDate(1, 0, 0),    // Default 1 years. Change it if it's necessary.
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
}

// Generate CA cert/key
// When succeeds, it returns cert (der) and key.
func generateCAWithRSAKey(template *x509.Certificate, keysize int) ([]byte, []byte, error) {
	// If user specifies one, use template provided.
	var certTemplate *x509.Certificate
	if template != nil {
		certTemplate = template
	} else {
		certTemplate = GetDefaultCACertTemplate()
	}

	return generateCertWithRSAKeyInternal(certTemplate, keysize, nil, nil)
}

// Generate TLS cert/key
// When parent == nil, it will be self-signed.
// When succeeds, it returns cert (der) and key.
func generateTLSCertWithRSAKey(template *x509.Certificate, keysize int, parent *x509.Certificate, parentPrivateKey interface{}) ([]byte, []byte, error) {
	// If user specifies one, use template provided.
	var certTemplate *x509.Certificate
	if template != nil {
		certTemplate = template
	} else {
		certTemplate = GetDefaultTLSCertTemplate()
	}

	return generateCertWithRSAKeyInternal(certTemplate, keysize, parent, parentPrivateKey)
}

// Generate PEM certificate and key.
// When parent is nil, this function will do self-sign.
func generateCertWithRSAKeyInternal(template *x509.Certificate, keysize int, parent *x509.Certificate, parentPrivateKey interface{}) ([]byte, []byte, error) {
	var privKey *rsa.PrivateKey
	var parentCert *x509.Certificate
	var err error
	var cert []byte
	var parentKey interface{}

	// Generate private key
	if privKey, err = rsa.GenerateKey(rand.Reader, keysize); err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	if parent == nil {
		// self sign. Use target template and private key we just generated.
		parentCert = template
		parentKey = privKey
	} else {
		parentCert = parent
		parentKey = parentPrivateKey
	}

	if cert, err = x509.CreateCertificate(rand.Reader, template, parentCert, &privKey.PublicKey, parentKey); err != nil {
		return nil, nil, fmt.Errorf("failed to create ca certificate: %w", err)
	}

	var certbuf bytes.Buffer
	var keybuf bytes.Buffer

	pemBlock := pemBlockForKey(privKey)
	if pemBlock == nil {
		return nil, nil, errors.New("failed to decode private key block")
	}
	if err = pem.Encode(&keybuf, pemBlock); err != nil {
		return nil, nil, fmt.Errorf("failed to encode pem file: %w", err)
	}

	if err = pem.Encode(&certbuf, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
		return nil, nil, fmt.Errorf("failed to encode pem file: %w", err)
	}

	return certbuf.Bytes(), keybuf.Bytes(), nil
}

// Generate a TLS cert and store it in kv.
func GenTlsCertWithCaAndStoreInKv(cn string, certPath string, keyPath string, caCertPath string, caKeyPath string, validityPeriod ValidityPeriod) error {
	if err := GenTlsCertWithCaAndStoreInFiles(cn, certPath, keyPath, caCertPath, caKeyPath, validityPeriod, x509.ExtKeyUsageServerAuth); err != nil {
		log.WithError(err).WithFields(log.Fields{"certPath": certPath, "keyPath": keyPath}).Error("wrong cert/key")
		return err
	}

	if err := StoreKeyCertFilesInKV(cn, certPath, keyPath); err != nil {
		log.WithError(err).WithFields(log.Fields{"certPath": certPath, "keyPath": keyPath}).Error("failed to write cert/key")
		return err
	}

	return nil
}

// Move cert kv keys from object/config/... to object/cert/... (outside upgrade phases) so no need to gen key/cert here
func genCrdWebhookResource() {
	CreateAdmCtrlStateByName(resource.NvCrdSvcName, true)
}

// TODO: Check certificate expiration day and key length so we can rotate it.
func verifyWebServerCert(cn string, certData []byte) bool {
	if orchPlatform != share.PlatformKubernetes {
		return true
	}
	if len(certData) > 0 {
		var customerCert bool // true means the cert is generated by customer, not neuvector
		var err error
		if block, _ := pem.Decode(certData); block == nil {
			err = fmt.Errorf("failed to decode PEM block")
		} else if block.Type != "CERTIFICATE" {
			err = fmt.Errorf("not a certificate: %s", block.Type)
		} else {
			cert, e := x509.ParseCertificate(block.Bytes)
			if e != nil {
				err = fmt.Errorf("failed to parse cert: %s", e.Error())
			} else {
				subj := cert.Subject
				if len(subj.Country) == 1 && len(subj.Organization) == 1 && len(subj.OrganizationalUnit) == 1 && len(subj.Province) == 1 &&
					subj.Country[0] == "US" && subj.Organization[0] == "Neuvector" && subj.OrganizationalUnit[0] == "Neuvector" && subj.Province[0] == "CA" {
					// this cert is generated by neuvector
				} else {
					customerCert = true
				}
				log.WithFields(log.Fields{"subject": cert.Subject, "san": cert.DNSNames, "cn": cn, "customerCert": customerCert}).Info()
				if cert.Subject.CommonName != cn {
					err = fmt.Errorf("mismatched cn")
				} else {
					// SANs is required in cert for k8s 1.19(+)
					if len(cert.DNSNames) == 1 && cert.DNSNames[0] == cn {
						// cert contains expected SANs
						return true
					} else {
						if k8sVerMajor, k8sVerMinor := resource.GetK8sVersion(); k8sVerMajor == 1 && k8sVerMinor < 19 {
							return true
						}
					}
				}
			}
		}
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error()
		}
	}

	return false
}

// Generate TLS key/cert pair using ca specified and store them in specified files.
// Return true if it succeeds to create key pair or the file already exists.
// If caCertPath and caKeyPath are both empty, this will create a self-signed certificate.
func GenTlsCertWithCaAndStoreInFiles(cn string, certPath string, privKeyPath string, caCertPath string, caKeyPath string, validityPeriod ValidityPeriod, usage x509.ExtKeyUsage) error {
	notfound := false
	if _, err := os.Stat(privKeyPath); err != nil && os.IsNotExist(err) {
		notfound = true
	}
	if _, err := os.Stat(certPath); err != nil && os.IsNotExist(err) {
		notfound = true
	}

	if !notfound {
		// cert/key already exists.  Do nothing in this case.
		log.WithFields(log.Fields{
			"certpath": certPath,
			"keypath":  privKeyPath,
			"cn":       cn,
		}).Debug("found existing key files")
	} else {
		cert, key, err := GenTlsKeyCert(cn, caCertPath, caKeyPath, validityPeriod, usage)
		if err != nil {
			return fmt.Errorf("failed to generate tls key/cert: %w", err)
		}

		if err := savePrivKeyCert(cert, key, certPath, privKeyPath); err != nil {
			return fmt.Errorf("failed to save key/cert: %w", err)
		}
	}

	return nil
}

// Generate TLS key/cert pair using ca specified.
// If caCertPath and caKeyPath are both empty, this will create a self-signed certificate.
func GenTlsKeyCert(cn string, caCertPath string, caKeyPath string, validityPeriod ValidityPeriod, usage x509.ExtKeyUsage) ([]byte, []byte, error) {
	var err error

	var cert []byte
	var key []byte

	// Customize template
	template := GetDefaultTLSCertTemplate()
	template.Subject.CommonName = cn
	template.DNSNames = []string{cn}
	template.ExtKeyUsage = []x509.ExtKeyUsage{usage}
	template.NotAfter = time.Now().AddDate(validityPeriod.Year, validityPeriod.Month, validityPeriod.Day)

	// As long as one of them is not empty, we assume it's creating a certificate using CA.
	if caCertPath != "" || caKeyPath != "" {
		catls, err := tls.LoadX509KeyPair(caCertPath, caKeyPath)
		if err != nil {
			log.WithError(err).Error("failed to load ca key pair")
			return nil, nil, fmt.Errorf("failed to load ca key pair: %w", err)
		}

		ca, err := x509.ParseCertificate(catls.Certificate[0])
		if err != nil {
			log.WithError(err).Error("failed to parse ca cert")
			return nil, nil, fmt.Errorf("failed to parse ca cert: %w", err)
		}
		// Only RSA is supported for now.
		cert, key, err = generateTLSCertWithRSAKey(template, RSAKeySize, ca, catls.PrivateKey)
		if err != nil {
			log.WithError(err).Error("Failed to create TLS certificate")
			return nil, nil, fmt.Errorf("failed to create TLS certificate: %w", err)
		}
	} else {
		// Only RSA is supported for now.
		// Self sign
		cert, key, err = generateTLSCertWithRSAKey(template, RSAKeySize, nil, nil)
		if err != nil {
			log.WithError(err).Error("Failed to create TLS certificate")
			return nil, nil, fmt.Errorf("failed to create TLS certificate: %w", err)
		}
	}

	return cert, key, nil
}

func GetFedTlsKeyCertPath(masterID, jointID string) (string, string, string) { // returns (caCertPath, privKeyPath, certPath)
	var caCertPath, privKeyPath, certPath string
	if masterID != "" {
		caCertPath = fmt.Sprintf("/etc/neuvector/certs/fed.master.%s.cert.pem", masterID)
	}
	if jointID != "" {
		privKeyPath = fmt.Sprintf("/etc/neuvector/certs/fed.client.%s.key.pem", jointID)
		certPath = fmt.Sprintf("/etc/neuvector/certs/fed.client.%s.cert.pem", jointID)
	}
	return caCertPath, privKeyPath, certPath
}

func GetFedCaCertPath(masterID string) (string, error) { // returns caCertPath
	var caCertData []byte
	var err error
	caCertPath := fmt.Sprintf("/etc/neuvector/certs/fed.master.%s.cert.pem", masterID)
	if caCertData, err = ioutil.ReadFile(AdmCACertPath); err == nil {
		if err = ioutil.WriteFile(caCertPath, caCertData, 0600); err == nil {
			return caCertPath, nil
		} else {
			log.WithFields(log.Fields{"error": err, "cert": caCertPath}).Error("failed to write")
		}
	} else {
		log.WithFields(log.Fields{"error": err, "cert": AdmCACertPath}).Error("failed to read")
	}
	return "", err
}

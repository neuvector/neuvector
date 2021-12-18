package kv

import (
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
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
)

const (
	AdmCAKeyPath  = "/etc/neuvector/certs/internal/adm_ca.key"
	AdmCACertPath = "/etc/neuvector/certs/internal/adm_ca.cert"

	CertTypeAdmCtrl = "adm_ctrl"
	CertTypeFed     = "federation"
)

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
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

func savePrivKeyCert(privKey *rsa.PrivateKey, derBytes []byte, keyPath, certPath string) bool {
	var err error
	var success bool
	var keyOut, certOut *os.File

	os.Remove(keyPath)
	os.Remove(certPath)
	keyOut, err = os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "path": keyPath}).Error("failed to open file for writing")
	} else {
		pemBlock := pemBlockForKey(privKey)
		if pemBlock != nil {
			if err = pem.Encode(keyOut, pemBlock); err != nil {
				log.WithFields(log.Fields{"error": err, "path": keyPath}).Error("failed to write data to file")
			} else {
				certOut, err = os.Create(certPath)
				if err != nil {
					log.WithFields(log.Fields{"error": err, "path": certPath}).Error("failed to open file for writing")
				} else if err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
					log.WithFields(log.Fields{"error": err, "path": certPath}).Error("failed to write data to file")
				} else {
					success = true
				}
			}
		}
	}
	if success {
		if keyOut != nil {
			if err = keyOut.Close(); err != nil {
				log.WithFields(log.Fields{"error": err, "path": keyPath}).Error("error closing file")
				success = false
			}
		}
		if certOut != nil {
			if err = certOut.Close(); err != nil {
				log.WithFields(log.Fields{"error": err, "path": certPath}).Error("error closing file")
				success = false
			}
		}
	}

	return success
}

func storeRootCAKeyCertInKV() bool {
	log.Info("store ca in new kv")
	keyData, _ := ioutil.ReadFile(AdmCAKeyPath)
	certData, _ := ioutil.ReadFile(AdmCACertPath)
	if len(keyData) > 0 && len(certData) > 0 {
		cert := &share.CLUSX509Cert{
			CN:   share.CLUSRootCAKey,
			Key:  string(keyData),
			Cert: string(certData),
		}
		if err := clusHelper.PutObjectCert(share.CLUSRootCAKey, AdmCAKeyPath, AdmCACertPath, cert); err == nil {
			return true
		}
	} else {
		log.WithFields(log.Fields{"len1": len(keyData), "len2": len(certData)}).Error("failed to read cert file")
	}

	return false
}

func createCA() bool {
	_, err1 := os.Stat(AdmCAKeyPath)
	_, err2 := os.Stat(AdmCACertPath)
	if (err1 != nil && os.IsNotExist(err1)) || (err2 != nil && os.IsNotExist(err2)) {
		if privKey, err := rsa.GenerateKey(rand.Reader, 2048); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("failed to create ca private key")
		} else {
			template := x509.Certificate{
				SerialNumber: big.NewInt(2019), // 1653
				Subject: pkix.Name{
					Country:            []string{"US"},
					Organization:       []string{"Neuvector"},
					OrganizationalUnit: []string{"Neuvector"},
					Locality:           []string{"EN"},
					Province:           []string{"CA"},
				},
				NotBefore:             time.Now(),
				NotAfter:              time.Now().AddDate(10, 0, 0),
				IsCA:                  true,
				ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
				KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
				BasicConstraintsValid: true,
			}
			if derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(privKey), privKey); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Failed to create ca certificate")
			} else {
				ret := savePrivKeyCert(privKey, derBytes, AdmCAKeyPath, AdmCACertPath)
				if ret {
					ret = storeRootCAKeyCertInKV()
				}
				return ret
			}
		}
		return false
	} else {
		// the cases that adm_ca.key / adm_ca.cert exist when createCA() is called
		// 1. in fresh deployment, customer maps a folder to controller pod's /etc/neuvector/certs/internal/ and provide their own root CA
		if cert, _, _ := clusHelper.GetObjectCertRev(share.CLUSRootCAKey); cert.IsEmpty() {
			// it means customer provides their own root CA
			storeRootCAKeyCertInKV()
		}
		return true
	}
}

func signWebhookTlsCert(svcName, ns, cn string) {
	tlsKeyPath, tlsCertPath := resource.GetTlsKeyCertPath(svcName, ns)
	if !GenTlsKeyCert(cn, tlsKeyPath, tlsCertPath, x509.ExtKeyUsageServerAuth) {
		log.WithFields(log.Fields{"keyPath": tlsKeyPath, "certPath": tlsCertPath}).Error("wrong cert/key")
	} else {
		// write key/cert to cluster
		keyData, _ := ioutil.ReadFile(tlsKeyPath)
		certData, _ := ioutil.ReadFile(tlsCertPath)
		if len(keyData) > 0 && len(certData) > 0 {
			cert := &share.CLUSX509Cert{
				CN:   cn,
				Key:  string(keyData),
				Cert: string(certData),
			}
			clusHelper.PutObjectCert(cn, tlsKeyPath, tlsCertPath, cert)
		}
	}
}

// Move cert kv keys from object/config/... to object/cert/... (outside upgrade phases) so no need to gen key/cert here
func genCrdWebhookResource() {
	CreateAdmCtrlStateByName(resource.NvCrdSvcName, true)
}

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

func GenTlsKeyCert(cn, privKeyPath, certPath string, usage x509.ExtKeyUsage) bool {
	extKeyUsage := []x509.ExtKeyUsage{usage}
	_, err1 := os.Stat(privKeyPath)
	_, err2 := os.Stat(certPath)
	if (err1 != nil && os.IsNotExist(err1)) || (err2 != nil && os.IsNotExist(err2)) {
		if catls, err := tls.LoadX509KeyPair(AdmCACertPath, AdmCAKeyPath); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("failed to load ca key pair")
		} else {
			if ca, err := x509.ParseCertificate(catls.Certificate[0]); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("ca key pair has some issue")
			} else {
				cert := &x509.Certificate{
					SerialNumber: big.NewInt(2029), // 1658
					Subject: pkix.Name{
						Country:            []string{"US"},
						Organization:       []string{"Neuvector"},
						OrganizationalUnit: []string{"Neuvector"},
						Locality:           []string{"EN"},
						Province:           []string{"CA"},
						CommonName:         cn,
					},
					NotBefore:    time.Now(),
					NotAfter:     time.Now().AddDate(10, 0, 0),
					SubjectKeyId: []byte{1, 2, 3, 4, 6},
					ExtKeyUsage:  extKeyUsage,
					KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
				}
				k8sVerMajor, k8sVerMinor := resource.GetK8sVersion()
				if k8sVerMajor > 1 || k8sVerMinor >= 19 {
					cert.DNSNames = []string{cn}
				}
				if privKey, err := rsa.GenerateKey(rand.Reader, 2048); err != nil {
					log.WithFields(log.Fields{"error": err}).Error("failed to create cert private key")
				} else {
					// Sign the certificate
					if derBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, publicKey(privKey), catls.PrivateKey); err != nil {
						log.WithFields(log.Fields{"cn": cn, "minor": k8sVerMinor, "error": err}).Error("failed to create certificate")
					} else {
						if savePrivKeyCert(privKey, derBytes, privKeyPath, certPath) {
							log.WithFields(log.Fields{"cn": cn, "minor": k8sVerMinor, "san": cert.DNSNames}).Info("wrote to tls files")
							return true
						}
					}
				}
			}
		}
		return false
	} else {
		log.WithFields(log.Fields{"cn": cn}).Debug("found existing file")
		return true
	}
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

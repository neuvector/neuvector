package kv

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	"errors"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	log "github.com/sirupsen/logrus"
)

// Due to consul's design, synchronization between clients using CAS() would easily make some clients starving.
// It's important to avoid this in the first place, but if you couldn't, change these variables when the scenario is too extreme.
const (
	DefaultRetryNumber   = 10
	DefaultSleepTime     = time.Millisecond * 10
	DefaultMaxSleepTime  = time.Second * 3
	DefaultBackoffFactor = 2.0
)

type CertManagerCallback struct {
	lastModifyIndex uint64
	NewCert         func(*share.CLUSX509Cert) (*share.CLUSX509Cert, error)
	NotifyNewCert   func(*share.CLUSX509Cert, *share.CLUSX509Cert)
	IsCertValid     func(*share.CLUSX509Cert) bool // optional
}

type CertManagerConfig struct {
	// How often the certificate will be checked.
	ExpiryCheckPeriod time.Duration

	// When NotAfter - now < RenewThreshold, renew will be triggered.
	RenewThreshold time.Duration
}

func isValidCallback(callback *CertManagerCallback) bool {
	if callback.NewCert == nil {
		return false
	}
	if callback.NotifyNewCert == nil {
		return false
	}
	return true
}

type CertManager struct {
	callbacks  map[string]*CertManagerCallback
	mutex      sync.Mutex // Protect callbacks and other shared configs.
	config     CertManagerConfig
	notifyChan chan string
}

func NewCertManager(config CertManagerConfig) *CertManager {
	return &CertManager{
		callbacks:  make(map[string]*CertManagerCallback),
		config:     config,
		notifyChan: make(chan string),
	}
}

// Main go routine of cert manager.
func (c *CertManager) Run(ctx context.Context) error {
	ticker := time.NewTicker(c.config.ExpiryCheckPeriod)
	for {
		select {
		case <-ticker.C:
			if err := c.CheckAndRenewCerts(); err != nil {
				log.WithError(err).Error("failed to check/renew certificate")
			}
		case cn := <-c.notifyChan:
			if err := c.UpdateCerts(cn); err != nil {
				log.WithError(err).Error("failed to update certificate")
			}
		case <-ctx.Done():
			goto end
		}
	}

end:
	return nil
}

// Utility function.  Retry consul API until it succeeds or retry number is reached.
func RetryOnCASError(retry int, fn func() error) error {
	steps := 0
	sleeptime := DefaultSleepTime
	for steps < retry {
		steps++
		if err := fn(); err != cluster.ErrPutCAS {
			return err
		}
		if sleeptime > DefaultMaxSleepTime {
			sleeptime = DefaultMaxSleepTime
		}
		time.Sleep(sleeptime)
		sleeptime *= DefaultBackoffFactor
	}
	return errors.New("RetryOnCASError timed out")
}

func (c *CertManager) checkAndRotateCert(cn string, callback *CertManagerCallback) error {
	// The flow here makes sure the data is consistent across cluster.
	// 1. Try to read certificate from consul.
	// 		KeyNotFound => The cert is not created yet.  Try to create it.
	// 		OtherError => Let it retry.
	// 2. Verify the certificate
	//      Not valid => Regenerate.  (IsCertValid callback is a good tool for testing and customize the logic here.)
	// 3. If the cert is not valid, CAS() will be called with the index we received as ModifyIndex.
	//      ModifyIndex: 0 (NotFound) => PutIfNotExist
	// 		other number => Overwrite.
	// 4. If CAS operation failed due to modifyIndex is not consistent, conflict happened with other nodes.
	//    We have to refresh modifyIndex and retry.
	//
	// For detail about how CAS works, see https://developer.hashicorp.com/consul/api-docs/kv
	return RetryOnCASError(DefaultRetryNumber, func() error {
		logctx := log.WithField("cn", cn)
		var block *pem.Block
		var x509Cert *x509.Certificate
		shouldrenew := false
		data, index, err := clusHelper.GetObjectCertRev(cn)
		if err != nil && err != cluster.ErrKeyNotFound {
			// This function assumes the previous certificate should be there.  If not, return an error.
			return fmt.Errorf("failed to get certificate: %w", err)
		}

		if data == nil {
			// Key not found.
			logctx.Info("certificate is not found.  Create it.")
			shouldrenew = true
			goto end
		}

		// Check if certificate is expired.  If it is, renew it with PutRev.
		block, _ = pem.Decode([]byte(data.Cert))
		if block == nil {
			logctx.WithError(err).Info("the certificate is ill-formatted. Try to create a new one.")
			shouldrenew = true
			goto end
		}
		x509Cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			logctx.WithError(err).Info("failed to parse certificate. Try to create a new one.")
			shouldrenew = true
			goto end
		}

		if time.Now().After(x509Cert.NotAfter.Add(-c.config.RenewThreshold)) {
			logctx.WithFields(log.Fields{
				"validity":  x509Cert.NotAfter.Format(time.RFC3339),
				"threshold": c.config.RenewThreshold.String(),
			}).Info("certificate is near expiration date.  Renewing it.")
			shouldrenew = true
			goto end
		}

		if callback.IsCertValid != nil {
			if !callback.IsCertValid(data) {
				logctx.WithFields(log.Fields{
					"validity":  x509Cert.NotAfter,
					"threshold": c.config.RenewThreshold.String(),
				}).Info("certificate is deemed invalid. Renewing.")
				shouldrenew = true
				goto end
			}
		}
	end:
		if !shouldrenew {
			logctx.WithFields(log.Fields{
				"validity": x509Cert.NotAfter.Format(time.RFC3339),
			}).Debug("certificate is up-to-date.")
			if callback.lastModifyIndex != index {
				callback.lastModifyIndex = index
				// Changed by others or initial start
				callback.NotifyNewCert(nil, data)
			}
			return nil
		}

		// CreateCert is confirmed not null during Register().
		newcert, err := callback.NewCert(data)
		if err != nil {
			logctx.WithError(err).Warn("failed to create new cert for rotation")
			return fmt.Errorf("failed to create new cert for rotation: %w", err)
		}

		tlscert, err := tls.X509KeyPair([]byte(newcert.Cert), []byte(newcert.Key))
		if err != nil {
			logctx.WithError(err).Error("failed to load key pair")
			return fmt.Errorf("failed to load ca key pair: %w", err)
		}

		if len(tlscert.Certificate) == 0 {
			logctx.Warn("no certificate generated found")
			return fmt.Errorf("no certificate generated found: %w", err)
		}

		x509cert, err := x509.ParseCertificate([]byte(tlscert.Certificate[0]))
		if err != nil {
			logctx.WithError(err).Warn("failed to parse certificate generated")
			return fmt.Errorf("failed to parse certificate generated: %w", err)
		}

		// We only want to keep one old cert, so remove data.OldCert.
		if data != nil {
			data.OldCert = nil
			newcert.OldCert = data
		}

		newcert.GeneratedTime = time.Now().Format(time.RFC3339)
		newcert.ExpiredTime = x509cert.NotAfter.Format(time.RFC3339)
		if err := clusHelper.PutObjectCertMemory(cn, newcert, newcert, index); err != nil {
			// While it's possible that it returns cluster.ErrPutCAS, we return all error for RetryOnCASError() to handle.
			logctx.WithError(err).Debug("failed to write certificate to consul kv")
			return err
		}

		// Notify caller
		callback.NotifyNewCert(data, newcert)

		logctx.WithFields(
			log.Fields{
				"generated_time": newcert.GeneratedTime,
				"validity":       x509cert.NotAfter.Format(time.RFC3339),
			},
		).Info("Certificate renewed.")
		return nil
	})
}

// Check and renew certificates.
// This is supposed to be called by one go routine.
func (c *CertManager) CheckAndRenewCerts() error {
	log.Debug("CheckAndRenewCerts() starts.")

	c.mutex.Lock()
	defer c.mutex.Unlock()

	for cn, callback := range c.callbacks {
		if err := c.checkAndRotateCert(cn, callback); err != nil {
			log.WithError(err).Error("failed to check/rotate cert")
		}
	}

	log.Debug("CheckAndRenewCerts() completes.")

	return nil
}

func (c *CertManager) Register(cn string, callback *CertManagerCallback) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if !isValidCallback(callback) {
		return errors.New("invalid callback")
	}
	c.callbacks[cn] = callback
	return nil
}

func (c *CertManager) Unregister(cn string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.callbacks, cn)
	return nil
}

// Notify cert manager that a change is detected.
func (c *CertManager) NotifyChanges(cn string) error {
	log.WithFields(log.Fields{
		"cn": cn,
	}).Debug("Changes detected in certificate")
	c.notifyChan <- cn
	return nil
}

// Update certificate based on data in consul
func (c *CertManager) UpdateCerts(cn string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	callback, ok := c.callbacks[cn]
	if !ok {
		return fmt.Errorf("no suitable callback for: %s", cn)
	}

	return RetryOnCASError(DefaultRetryNumber, func() error {
		data, index, err := clusHelper.GetObjectCertRev(cn)
		if err != nil && err != cluster.ErrKeyNotFound {
			// This function assumes the previous certificate should be there.  If not, return an error.
			return fmt.Errorf("failed to get certificate: %w", err)
		}

		if callback.lastModifyIndex != index {
			callback.lastModifyIndex = index
			// Changed by others or initial start
			callback.NotifyNewCert(nil, data)
		}
		return nil
	})
}

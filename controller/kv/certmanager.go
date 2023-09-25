package kv

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"sync"
	"time"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	DefaultRetryNumber   = 5
	DefaultSleepTime     = time.Millisecond * 10
	DefaultBackoffFactor = 5.0
)

type CertManagerCallback struct {
	lastModifyIndex uint64
	NewCert         func(*share.CLUSX509Cert) (*share.CLUSX509Cert, error)
	NotifyNewCert   func(*share.CLUSX509Cert, *share.CLUSX509Cert)
	IsCertValid     func(*share.CLUSX509Cert) bool // optional
}

type CertManagerConfig struct {
	CertCheckPeriod time.Duration
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
	callbacks map[string]*CertManagerCallback
	mutex     sync.RWMutex
	config    CertManagerConfig
}

func NewCertManager(config CertManagerConfig) *CertManager {
	return &CertManager{
		callbacks: make(map[string]*CertManagerCallback),
		config:    config,
	}
}

func (c *CertManager) Run(ctx context.Context) error {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	ticker := time.NewTicker(c.config.CertCheckPeriod)
	for {
		select {
		case <-ticker.C:
			c.CheckAndRenewCerts()
		case <-ctx.Done():
			goto end
		}
	}

end:
	return nil
}

func RetryOnCASError(retry int, fn func() error) error {
	steps := 0
	sleeptime := DefaultSleepTime
	for steps < retry {
		steps++
		if err := fn(); err != cluster.ErrPutCAS {
			return err
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
		var block *pem.Block
		var x509Cert *x509.Certificate
		shouldrenew := false
		data, index, err := clusHelper.GetObjectCertRev(cn)
		if err != nil && err != cluster.ErrKeyNotFound {
			// This function assumes the previous certificate should be there.  If not, return an error.
			return errors.Wrap(err, "failed to get certificate")
		}

		if data == nil {
			// Key not found.
			shouldrenew = true
			goto end
		}

		// Check if certificate is expired.  If it is, renew it with PutRev.
		block, _ = pem.Decode([]byte(data.Cert))
		x509Cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			// Invalid certificate.  Try to renew it...
			log.WithError(err).WithField("cn", cn).Info("failed to parse certificate")
			shouldrenew = true
			goto end
		}

		if x509Cert.NotAfter.After(time.Now().Add(time.Hour * 24 * -30)) {
			log.WithField("cn", cn).Info("certificate is near expiration date.  renew it.")
			shouldrenew = true
			goto end
		}

		if callback.IsCertValid != nil {
			if !callback.IsCertValid(data) {
				shouldrenew = true
				goto end
			}
		}
	end:
		if !shouldrenew {
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
			log.WithField("cn", cn).Warn("failed to create new cert for rotation")
			return err
		}

		newcert.OldCert = data
		if err := clusHelper.PutObjectCertMemory(cn, newcert, newcert, index); err != nil {
			return err
		}

		// Notify caller
		callback.NotifyNewCert(data, newcert)
		return nil
	})
}

func (c *CertManager) CheckAndRenewCerts() error {
	for cn, callback := range c.callbacks {
		c.checkAndRotateCert(cn, callback)
	}

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

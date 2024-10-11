package migration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"reflect"
	"sync/atomic"
	"time"

	"errors"

	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/healthz"
	"github.com/neuvector/neuvector/share/k8sutils"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	coreinformers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const (
	WaitSyncTimeout                     = time.Minute * 5
	INTERNAL_SECRET_ROTATION_ANNOTATION = "internal-cert-rotation"
)

type InternalSecretController struct {
	informerFactory informers.SharedInformerFactory
	secretInformer  coreinformers.SecretInformer
	namespace       string
	secretName      string
	lastRevision    string
	reloadFuncs     []func([]byte, []byte, []byte) error
	//	clientset       *kubernetes.Clientset
	initialized int32
}

func verifyCert(cacert []byte, cert []byte, key []byte) error {

	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(cacert)
	if !ok {
		return errors.New("failed to append cert")
	}

	block, _ := pem.Decode(cert)
	if block == nil {
		return errors.New("failed to decode cert")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		DNSName:       cluster.InternalCertCN,
		Intermediates: x509.NewCertPool(),
	}

	if _, err := crt.Verify(opts); err != nil {
		return fmt.Errorf("failed to verify certificate: %w", err)
	}

	if _, err := tls.X509KeyPair(cert, key); err != nil {
		return fmt.Errorf("invalid key cert pair: %w", err)
	}
	return nil
}

func GetCurrentInternalCerts() (cacert []byte, cert []byte, key []byte, err error) {
	if cacert, err = os.ReadFile(path.Join(cluster.InternalCertDir, cluster.InternalCACert)); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read cacert: %w", err)
	}
	if cert, err = os.ReadFile(path.Join(cluster.InternalCertDir, cluster.InternalCert)); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read cert: %w", err)
	}
	if key, err = os.ReadFile(path.Join(cluster.InternalCertDir, cluster.InternalCertKey)); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read key: %w", err)
	}
	return
}

func ReloadCert(cacert []byte, cert []byte, key []byte) error {
	if err := verifyCert(cacert, cert, key); err != nil {
		return fmt.Errorf("invalid key/cert: %w", err)
	}

	if err := os.WriteFile(path.Join(cluster.InternalCertDir, cluster.InternalCACert), []byte(cacert), 0600); err != nil {
		return fmt.Errorf("failed to write cacert: %w", err)
	}
	if err := os.WriteFile(path.Join(cluster.InternalCertDir, cluster.InternalCert), []byte(cert), 0600); err != nil {
		return fmt.Errorf("failed to write cert: %w", err)
	}
	if err := os.WriteFile(path.Join(cluster.InternalCertDir, cluster.InternalCertKey), []byte(key), 0600); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}
	return nil
}

// Reload using secret retrieved from k8s API server.
// The secret is created by helm and events will be received following this order:
// 1. The initial add.  It might have certs filled depending on timing, but no guarantee.
// 2. The following update.  This should have certs all the time.
func (c *InternalSecretController) ReloadSecret(secret *v1.Secret) (bool, error) {
	if secret.Annotations[INTERNAL_SECRET_ROTATION_ANNOTATION] == "" {
		log.Info("internal certificate is not ready yet.")
		return false, nil
	}

	if secret.Annotations[INTERNAL_SECRET_ROTATION_ANNOTATION] != "enabled" {
		log.Info("internal certificate rotation is disabled. Use built-in certs.")
		if c.initialized == 0 {
			atomic.SwapInt32(&c.initialized, 1)
		}
		return true, nil
	}

	cacert := secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME]
	cert := secret.Data[ACTIVE_SECRET_PREFIX+CERT_FILENAME]
	key := secret.Data[ACTIVE_SECRET_PREFIX+KEY_FILENAME]

	if cacert == nil || cert == nil || key == nil {
		return false, errors.New("active secret is not found, probably not initialized yet")
	}

	// Keep copy of existing certs, so we can rollback if something is wrong.
	oldcacert, oldcert, oldkey, err := GetCurrentInternalCerts()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("failed to read existing certs: %w", err)
		}
		// If file is not found, the container may have just been initialized.
	}

	// If internal certificate exists, and it's the same as the certificate defined in the secret,
	// it's possible that controller process restarts after cert is rolled out, so flip the flag in this case.
	if oldcacert != nil && oldcert != nil && oldkey != nil {
		if reflect.DeepEqual(oldcacert, cacert) && reflect.DeepEqual(oldcert, cert) && reflect.DeepEqual(oldkey, key) {
			atomic.SwapInt32(&c.initialized, 1)
			log.Debug("Internal certificate is not changed")
			return false, nil
		}
	}

	if err := ReloadCert(cacert, cert, key); err != nil {
		return false, fmt.Errorf("failed to reload certs: %w", err)
	}

	// At this point, cert has been replaced.
	// When initializing, all services haven't started yet, so skip the callback functions and flip the flag.
	// This go routine is the sole writer of c.initialized, so no lock is required.
	if c.initialized == 0 {
		atomic.SwapInt32(&c.initialized, 1)
		return true, nil
	}

	// If it was initialized before, reload the certificates.

	recoverCerts := func() {
		if err := ReloadCert(oldcacert, oldcert, oldkey); err != nil {
			log.WithError(err).Error("failed to recover internal certs")
		}
		for _, f := range c.reloadFuncs {
			err := f(cacert, cert, key)
			if err != nil {
				log.WithError(err).Error("failed to reload internal certs")
			}
		}
	}

	for _, f := range c.reloadFuncs {
		err := f(cacert, cert, key)
		if err != nil {
			log.WithError(err).Error("failed to reload internal certs")
			recoverCerts()
			return false, fmt.Errorf("failed to reload internal certs: %w", err)
		}
	}

	return true, nil
}

func (c *InternalSecretController) IsOfInterest(secret *v1.Secret) bool {
	if secret.Namespace != c.namespace || secret.Name != c.secretName {
		return false
	}
	if secret.ResourceVersion == c.lastRevision {
		// The same revision as last time.
		return false
	}
	return true
}

func (c *InternalSecretController) Run(stopCh <-chan struct{}) error {
	c.informerFactory.Start(stopCh)

	ctx, cancel := context.WithTimeout(context.Background(), WaitSyncTimeout)
	defer cancel()
	// wait for the initial synchronization of the local cache.
	if !cache.WaitForCacheSync(ctx.Done(), func() bool {
		if !c.secretInformer.Informer().HasSynced() {
			return false
		}
		return atomic.LoadInt32(&c.initialized) > 0
	}) {
		return errors.New("failed to sync with k8s for internal certs")
	}
	return nil
}

func (c *InternalSecretController) secretAdd(obj interface{}) {
	secret := obj.(*v1.Secret)
	if !c.IsOfInterest(secret) {
		return
	}

	log.WithFields(log.Fields{
		"namespace": secret.Namespace,
		"name":      secret.Name,
		"rev":       secret.ResourceVersion,
	}).Debug("internal secret is added")

	if reloaded, err := c.ReloadSecret(secret); err != nil {
		log.WithError(err).Warn("failed to reload secret")
	} else {
		if reloaded {
			log.WithField("rev", secret.ResourceVersion).Info("Internal secret is up-to-date")
		} else {
			log.WithField("rev", secret.ResourceVersion).Debug("Internal secret is up-to-date")
		}
		healthz.UpdateStatus("cert.revision", secret.ResourceVersion)
	}
}

func (c *InternalSecretController) secretUpdate(old, new interface{}) {
	oldSecret := old.(*v1.Secret)
	newSecret := new.(*v1.Secret)

	if !c.IsOfInterest(oldSecret) {
		return
	}

	log.WithFields(log.Fields{
		"namespace": newSecret.Namespace,
		"name":      newSecret.Name,
		"rev":       newSecret.ResourceVersion,
	}).Debug("Internal secret is updated")

	// Check if old secret is the same with new secret.
	// Note: There is no guarantee that oldSecret will be available, but for checking it's enough.
	if reflect.DeepEqual(oldSecret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME], newSecret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME]) &&
		reflect.DeepEqual(oldSecret.Data[ACTIVE_SECRET_PREFIX+CERT_FILENAME], newSecret.Data[ACTIVE_SECRET_PREFIX+CERT_FILENAME]) &&
		reflect.DeepEqual(oldSecret.Data[ACTIVE_SECRET_PREFIX+KEY_FILENAME], newSecret.Data[ACTIVE_SECRET_PREFIX+KEY_FILENAME]) &&
		reflect.DeepEqual(oldSecret.Annotations, newSecret.Annotations) {

		log.WithField("rev", newSecret.ResourceVersion).Debug("Internal certs has been applied before.")
		healthz.UpdateStatus("cert.revision", newSecret.ResourceVersion)
		return
	}

	log.WithFields(log.Fields{
		"namespace": newSecret.Namespace,
		"name":      newSecret.Name,
		"rev":       newSecret.ResourceVersion,
	}).Debug("New internal secret is detected")

	if reloaded, err := c.ReloadSecret(newSecret); err != nil {
		log.WithError(err).Error("failed to reload secret")
	} else {
		if reloaded {
			log.WithField("rev", newSecret.ResourceVersion).Info("Internal secret is up-to-date")
		} else {
			log.WithField("rev", newSecret.ResourceVersion).Debug("Internal secret is up-to-date")
		}
		healthz.UpdateStatus("cert.revision", newSecret.ResourceVersion)
	}
}

func (c *InternalSecretController) secretDelete(obj interface{}) {
	secret := obj.(*v1.Secret)
	if !c.IsOfInterest(secret) {
		return
	}
	log.WithFields(log.Fields{
		"namespace": secret.Namespace,
		"name":      secret.Name,
	}).Debug("internal secret is deleted")
}

func NewInternalSecretController(informerFactory informers.SharedInformerFactory, namespace string, secretName string,
	reloadFuncs []func([]byte, []byte, []byte) error) (*InternalSecretController, error) {

	secretInformer := informerFactory.Core().V1().Secrets()

	c := &InternalSecretController{
		informerFactory: informerFactory,
		secretInformer:  secretInformer,
		namespace:       namespace,
		secretName:      secretName,
		reloadFuncs:     reloadFuncs,
	}

	if _, err := secretInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			// Called on creation
			AddFunc: c.secretAdd,
			// Called on resource update and every resyncPeriod on existing resources.
			UpdateFunc: c.secretUpdate,
			// Called on resource deletion.
			DeleteFunc: c.secretDelete,
		},
		time.Minute*5, // re-enumerate cache every 5 minutes
	); err != nil {
		log.WithField("error", err).Error()
	}

	return c, nil
}

func InitializeInternalSecretController(ctx context.Context, reloadFuncs []func([]byte, []byte, []byte) error) (capable bool, err error) {
	var config *rest.Config

	var namespace string
	if data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		namespace = string(data)
	} else {
		log.WithError(err).Warn("failed to open namespace file.")
	}

	config, err = rest.InClusterConfig()
	if err != nil {
		return false, fmt.Errorf("failed to read in-cluster config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return false, fmt.Errorf("failed to get k8s config: %w", err)
	}

	for _, res := range k8sutils.SecretInformerRequiredPermissions {
		capable, err := k8sutils.CanI(clientset, res, namespace)
		if err != nil {
			return false, err
		}
		if !capable {
			return false, nil
		}
	}

	// Allow overriding via POD_NAMESPACE variable for testing
	if nsenv := os.Getenv("POD_NAMESPACE"); nsenv != "" {
		namespace = nsenv
	}

	factory := informers.NewSharedInformerFactoryWithOptions(clientset, time.Hour*24, informers.WithNamespace(namespace))

	controller, err := NewInternalSecretController(factory, namespace, "neuvector-internal-certs", reloadFuncs)
	if err != nil {
		return false, fmt.Errorf("failed to create internal secret controller: %w", err)
	}

	// This function will wait until the secret is synced.
	err = controller.Run(ctx.Done())
	if err != nil {
		return false, fmt.Errorf("failed to run internal secret controller: %w", err)
	}

	log.Info("cache is synced and internal cert is ready")

	return true, nil
}

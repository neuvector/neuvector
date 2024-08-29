package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"reflect"
	"time"

	"errors"

	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/share/k8sutils"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	appv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8sError "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	watchtools "k8s.io/client-go/tools/watch"
	"k8s.io/client-go/util/retry"
	"k8s.io/kubectl/pkg/polymorphichelpers"
)

const (
	UPGRADER_LEASE_NAME                 = "neuvector-cert-upgrader"
	INTERNAL_SECRET_ROTATION_ANNOTATION = "internal-cert-rotation"
)

type ContainerStatus map[string]string

func GetRemoteCert(host string, port string, config *tls.Config) (*x509.Certificate, error) {
	// #nosec G402 InsecureSkipVerify is required to get remote cert anonymously.
	addr := net.JoinHostPort(host, port)

	conn, err := tls.Dial("tcp", addr, config)
	if err != nil {
		return nil, fmt.Errorf("failed to dial host %s: %w", host, err)
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errors.New("no remote certificate is available")
	}
	return certs[0], nil
}

// Wait until a resource rolls out completely.
// See https://github.com/kubernetes/kubectl/blob/master/pkg/cmd/rollout/rollout_status.go
func WaitUntilRolledOut(ctx context.Context, gr schema.GroupVersionResource, client dynamic.Interface, namespace string, name string) error {
	// 1. Get controller deployment.
	item, err := client.Resource(gr).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		// something wrong to get the deployment.  Give up.
		return fmt.Errorf("failed to get deployment: %w", err)
	}
	var deployment appv1.Deployment
	err = runtime.DefaultUnstructuredConverter.
		FromUnstructured(item.UnstructuredContent(), &deployment)
	if err != nil {
		return fmt.Errorf("failed to convert deployment: %w", err)
	}

	fieldSelector := fields.OneTermEqualSelector("metadata.name", deployment.Name).String()
	lw := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			options.FieldSelector = fieldSelector
			return client.Resource(gr).Namespace(deployment.Namespace).List(ctx, options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			options.FieldSelector = fieldSelector
			return client.Resource(gr).Namespace(deployment.Namespace).Watch(ctx, options)
		},
	}

	statusViewer, err := polymorphichelpers.StatusViewerFor(deployment.GroupVersionKind().GroupKind())
	if err != nil {
		return fmt.Errorf("failed to find status viewer: %w", err)
	}

	// Wait until deployment finishes.  Note: this could last forever if some of pods can't be deployed.
	_, err = watchtools.UntilWithSync(ctx, lw, &unstructured.Unstructured{}, nil, func(e watch.Event) (bool, error) {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		default:
		}
		switch t := e.Type; t {
		case watch.Added, watch.Modified:
			status, done, err := statusViewer.Status(e.Object.(runtime.Unstructured), 0)
			if err != nil {
				return false, err
			}
			log.Println(status)

			// Quit waiting if the rollout is done
			if done {
				return true, nil
			}

			return false, nil

		case watch.Deleted:
			// We need to abort to avoid cases of recreation and not to silently watch the wrong (new) object
			return true, fmt.Errorf("object has been deleted")

		default:
			return true, fmt.Errorf("internal error: unexpected event %#v", e)
		}
	})
	return err
}

// WaitUntilRolledOut with timeout
func WaitUntilDeployed(ctx context.Context,
	resource schema.GroupVersionResource,
	client dynamic.Interface,
	namespace string,
	resourceName string,
	timeout time.Duration) error {

	timeoutCtx, cancel := watchtools.ContextWithOptionalTimeout(ctx, timeout)
	defer cancel()
	err := WaitUntilRolledOut(timeoutCtx,
		resource,
		client,
		namespace,
		resourceName,
	)
	if err != nil {
		if k8sError.IsNotFound(err) {
			log.WithError(err).
				WithField("resource", resourceName).
				Info("The resource is not found.  This is normal when the components are not deployed.")
			return nil
		}
		return fmt.Errorf("failed to wait controller to rollout: %w", err)
	}
	return nil
}

// Go through all NeuVector pods to see if they're all up-to-date by checking its healthz endpoint.
func IsCertRevisionUpToDate(ctx context.Context, client dynamic.Interface, namespace string, rev string, selector string) (bool, error) {
	// Get all running pods first.
	// Even if some pods are not in running status, e.g., ContainerStatusUnknown, they can catch up from neuvector-internal certs secret.
	//
	// NOTE: When a pod becomes running after we list the pods, it's supposed to get the new version of certificate we just update.
	// If for any reason the pod can't get newer certificate, it will be stuck in init phase and it will be caught in the next round.
	item, err := client.Resource(
		schema.GroupVersionResource{
			Resource: "pods",
			Version:  "v1",
		},
	).Namespace(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: selector,
		FieldSelector: fields.OneTermEqualSelector("status.phase", "Running").String(),
	})
	if err != nil {
		return false, fmt.Errorf("failed to find controller pods: %w", err)
	}

	var pods corev1.PodList
	err = runtime.DefaultUnstructuredConverter.
		FromUnstructured(item.UnstructuredContent(), &pods)
	if err != nil {
		return false, fmt.Errorf("failed to read pod list: %w", err)
	}

	num := len(pods.Items)

	for _, pod := range pods.Items {
		select {
		case <-ctx.Done():
			return false, context.Canceled
		default:
			// not canceled, continue
		}

		if pod.Status.PodIP == "" {
			// Still initializing.
			continue
		}

		log.WithFields(log.Fields{
			"podName": pod.Name,
			"pod":     pod.Status.PodIP,
		}).Info("Getting container status")

		var status ContainerStatus

		timeoutCtx, cancel := context.WithTimeout(ctx, time.Second*5)
		defer cancel()

		req, err := http.NewRequestWithContext(timeoutCtx, "GET", fmt.Sprintf("http://%s:%d/healthz", pod.Status.PodIP, 18500), nil)
		if err != nil {
			return false, fmt.Errorf("failed to create HTTP request for pod %s: %w", pod.Name, err)
		}

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return false, fmt.Errorf("failed to connect to healthz endpoint for pod %s: %w", pod.Name, err)
		}

		err = json.NewDecoder(res.Body).Decode(&status)
		if err != nil {
			return false, fmt.Errorf("failed to unmarshal healthz response for pod %s: %w", pod.Name, err)
		}

		if status["cert.revision"] != rev {
			log.WithFields(log.Fields{
				"rev":     rev,
				"pod":     pod.Status.PodIP,
				"podName": pod.Name,
			}).Info("Container is not ready yet")
			return false, nil
		}
	}
	log.WithFields(log.Fields{
		"rev":       rev,
		"podNum":    num,
		"namespace": namespace,
		"selector":  selector,
	}).Info("containers are up to date")
	return true, nil
}

// Going through controller, enforcer, scanner and registry-adapter to make sure their internal secret is up-to-date.
func IsAllCertRevisionUpToDate(ctx context.Context, client dynamic.Interface, namespace string, rev string) (bool, error) {
	if uptodate, err := IsCertRevisionUpToDate(ctx, client, namespace, rev, ControllerPodLabelSelector); err != nil {
		return false, fmt.Errorf("failed to check controller pods: %w", err)
	} else if !uptodate {
		return false, nil
	}

	if uptodate, err := IsCertRevisionUpToDate(ctx, client, namespace, rev, EnforcerPodLabelSelector); err != nil {
		return false, fmt.Errorf("failed to check enforcer pods: %w", err)
	} else if !uptodate {
		return false, nil
	}

	if uptodate, err := IsCertRevisionUpToDate(ctx, client, namespace, rev, ScannerPodLabelSelector); err != nil {
		return false, fmt.Errorf("failed to check scanner pods: %w", err)
	} else if !uptodate {
		return false, nil
	}

	if uptodate, err := IsCertRevisionUpToDate(ctx, client, namespace, rev, RegistryPodLabelSelector); err != nil {
		return false, fmt.Errorf("failed to check registry pods: %w", err)
	} else if !uptodate {
		return false, nil
	}

	return true, nil
}

// Wait until until containers being monitored has moved to new internal certificates.
func WaitContainerUpdate(ctx context.Context, client dynamic.Interface, namespace string, rev string) error {
	var err error

	// Wait until all containers have the right revision.
	log.WithField("revision", rev).Info("checking if all NV containers are using this revision of secret")

	uptodate := false
	var lastErr error
	err = wait.ExponentialBackoff(wait.Backoff{
		Duration: 5 * time.Second,
		Factor:   1.0,
		Steps:    20,
		Jitter:   0.1,
	},
		func() (bool, error) {
			uptodate, err = IsAllCertRevisionUpToDate(ctx, client, namespace, rev)
			switch {
			case err == nil && uptodate:
				// complete
				return true, nil
			case err == nil && !uptodate:
				// retry
				return false, nil
			default:
				// return error
				lastErr = err
				return false, nil
			}
		})
	if err != nil {
		log.WithError(err).WithField("lastErr", lastErr).Error("failed to wait for secret adopted. Please check container's log for more information.")
		return fmt.Errorf("failed to wait for secret adopted: %w", err)
	}
	return nil
}

// Utility function to generate a combined CA.
func GetCombinedCA(cacert1 []byte, cacert2 []byte) []byte {
	var combinedca []byte
	combinedca = append(combinedca, cacert1...)
	combinedca = append(combinedca, []byte("\n")...)
	combinedca = append(combinedca, cacert2...)
	return combinedca
}

// Determine migration steps, so cert-upgrader can continue.
func DetermineMigrationStep(secret *corev1.Secret) (int, bool, error) {

	if secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME] == nil ||
		secret.Data[ACTIVE_SECRET_PREFIX+CERT_FILENAME] == nil ||
		secret.Data[ACTIVE_SECRET_PREFIX+KEY_FILENAME] == nil ||
		secret.Data[DEST_SECRET_PREFIX+CACERT_FILENAME] == nil ||
		secret.Data[DEST_SECRET_PREFIX+CERT_FILENAME] == nil ||
		secret.Data[DEST_SECRET_PREFIX+KEY_FILENAME] == nil ||
		secret.Data[NEW_SECRET_PREFIX+CACERT_FILENAME] == nil ||
		secret.Data[NEW_SECRET_PREFIX+CERT_FILENAME] == nil ||
		secret.Data[NEW_SECRET_PREFIX+KEY_FILENAME] == nil {
		return 0, false, errors.New("invalid internal certs")
	}

	if IsSameCert(secret, ACTIVE_SECRET_PREFIX, DEST_SECRET_PREFIX) &&
		IsSameCert(secret, ACTIVE_SECRET_PREFIX, NEW_SECRET_PREFIX) {
		return 0, true, nil
	}

	combinedca := GetCombinedCA(secret.Data[DEST_SECRET_PREFIX+CACERT_FILENAME], secret.Data[NEW_SECRET_PREFIX+CACERT_FILENAME])

	if reflect.DeepEqual(secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME], secret.Data[DEST_SECRET_PREFIX+CACERT_FILENAME]) &&
		reflect.DeepEqual(secret.Data[ACTIVE_SECRET_PREFIX+CERT_FILENAME], secret.Data[DEST_SECRET_PREFIX+CERT_FILENAME]) &&
		reflect.DeepEqual(secret.Data[ACTIVE_SECRET_PREFIX+KEY_FILENAME], secret.Data[DEST_SECRET_PREFIX+KEY_FILENAME]) {
		return 0, false, nil
	}

	// Has combined CA, but not others
	if reflect.DeepEqual(secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME], combinedca) &&
		reflect.DeepEqual(secret.Data[ACTIVE_SECRET_PREFIX+CERT_FILENAME], secret.Data[DEST_SECRET_PREFIX+CERT_FILENAME]) &&
		reflect.DeepEqual(secret.Data[ACTIVE_SECRET_PREFIX+KEY_FILENAME], secret.Data[DEST_SECRET_PREFIX+KEY_FILENAME]) {
		return 1, false, nil
	}

	// Has combined CA and new key/cert.
	if reflect.DeepEqual(secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME], combinedca) &&
		reflect.DeepEqual(secret.Data[ACTIVE_SECRET_PREFIX+CERT_FILENAME], secret.Data[NEW_SECRET_PREFIX+CERT_FILENAME]) &&
		reflect.DeepEqual(secret.Data[ACTIVE_SECRET_PREFIX+KEY_FILENAME], secret.Data[NEW_SECRET_PREFIX+KEY_FILENAME]) {
		return 2, false, nil
	}

	// Migration has completed but failed before writing DEST cert.
	if reflect.DeepEqual(secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME], secret.Data[NEW_SECRET_PREFIX+CACERT_FILENAME]) &&
		reflect.DeepEqual(secret.Data[ACTIVE_SECRET_PREFIX+CERT_FILENAME], secret.Data[NEW_SECRET_PREFIX+CERT_FILENAME]) &&
		reflect.DeepEqual(secret.Data[ACTIVE_SECRET_PREFIX+KEY_FILENAME], secret.Data[NEW_SECRET_PREFIX+KEY_FILENAME]) {
		return 3, false, nil
	}

	return 0, false, errors.New("unexpected status of internal certs secret")
}

// The main function for cert migration.
func UpgradeInternalCerts(ctx context.Context, client dynamic.Interface, namespace string, secretName string, timeout time.Duration) error {
	var secret *corev1.Secret
	var err error

	if secret, err = GetK8sSecret(ctx, client, namespace, secretName); err != nil {
		return fmt.Errorf("failed to get secret: %w", err)
	}

	// Make sure all components are deployed
	err = WaitUntilDeployed(ctx,
		schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"},
		client,
		namespace,
		"neuvector-controller-pod",
		timeout)
	if err != nil {
		return fmt.Errorf("failed to wait controller to rollout: %w", err)
	}

	// 2. NOTE: we don't wait for enforcer and scanner because their certs don't have to be changed at the same time.

	// Flow:
	// src secret => target secret.  Eventually src and target will be the same.
	//
	// 0. When helm chart is installed, no secret will be created.
	// 		a. Retire cert-manager support?
	//		b. Or allow user/cert-manager to specify cert via src secret?
	//      c. Reconcile via controller? Or schedule job?
	// 1. When this job runs, it checks if either of below conditions is met.  If so, start migration.
	// 		a. cert is not present
	// 		b. a src secret is present
	// 2. Update target cert and call each component's reload.

	// Check if all containers are in sync first.
	if err := WaitContainerUpdate(ctx, client, namespace, secret.ResourceVersion); err != nil {
		return fmt.Errorf("some containers failed to adopt new version of secrets: %w", err)
	}

	step, completed, err := DetermineMigrationStep(secret)
	if err != nil {
		return fmt.Errorf("failed to determine the current migration step: %w", err)
	}
	if completed {
		log.Info("migration has completed since all certs are the same")
		return nil
	}
	log.WithField("step", step).Info("Start rollout certs")
	for ; step < 3; step++ {
		// state: 0
		// merged cacert + old cert + old key
		// state: 1
		// merged cacert + new cert + new key
		// state: 2
		// new cacert + new cert + new key
		switch step {
		case (0):
			// Combined CA
			secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME] = GetCombinedCA(secret.Data[DEST_SECRET_PREFIX+CACERT_FILENAME], secret.Data[NEW_SECRET_PREFIX+CACERT_FILENAME])

			// Old cert/key
			secret.Data[ACTIVE_SECRET_PREFIX+CERT_FILENAME] = secret.Data[DEST_SECRET_PREFIX+CERT_FILENAME]
			secret.Data[ACTIVE_SECRET_PREFIX+KEY_FILENAME] = secret.Data[DEST_SECRET_PREFIX+KEY_FILENAME]
		case (1):
			// Combined CA
			secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME] = nil
			secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME] = append(secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME], secret.Data[DEST_SECRET_PREFIX+CACERT_FILENAME]...)
			secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME] = append(secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME], []byte("\n")...)
			secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME] = append(secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME], secret.Data[NEW_SECRET_PREFIX+CACERT_FILENAME]...)

			// New cert/key
			secret.Data[ACTIVE_SECRET_PREFIX+CERT_FILENAME] = secret.Data[NEW_SECRET_PREFIX+CERT_FILENAME]
			secret.Data[ACTIVE_SECRET_PREFIX+KEY_FILENAME] = secret.Data[NEW_SECRET_PREFIX+KEY_FILENAME]
		case (2):
			// New CA/cert/key
			secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME] = secret.Data[NEW_SECRET_PREFIX+CACERT_FILENAME]
			secret.Data[ACTIVE_SECRET_PREFIX+CERT_FILENAME] = secret.Data[NEW_SECRET_PREFIX+CERT_FILENAME]
			secret.Data[ACTIVE_SECRET_PREFIX+KEY_FILENAME] = secret.Data[NEW_SECRET_PREFIX+KEY_FILENAME]
		}

		// Replace secret with what we got from API server.
		secret, err = UpdateSecret(ctx, client, namespace, secret)
		if err != nil {
			return fmt.Errorf("failed to create/update dst secret: %w", err)
		}

		// Wait until all containers have the right revision.
		log.WithField("revision", secret.ResourceVersion).Info("secret is created/updated")

		if err := WaitContainerUpdate(ctx, client, namespace, secret.ResourceVersion); err != nil {
			return fmt.Errorf("failed to wait for secret adopted: %w", err)
		}
	}

	// Write dest secret and finish the rollout
	secret.Data[DEST_SECRET_PREFIX+CACERT_FILENAME] = secret.Data[NEW_SECRET_PREFIX+CACERT_FILENAME]
	secret.Data[DEST_SECRET_PREFIX+CERT_FILENAME] = secret.Data[NEW_SECRET_PREFIX+CERT_FILENAME]
	secret.Data[DEST_SECRET_PREFIX+KEY_FILENAME] = secret.Data[NEW_SECRET_PREFIX+KEY_FILENAME]

	if _, err := UpdateSecret(ctx, client, namespace, secret); err != nil {
		return fmt.Errorf("failed to write dest secret: %w", err)
	}

	log.Info("Internal certificates are migrated")
	return nil
}

func IsCertNearExpired(data []byte, renewThreshold time.Duration) (bool, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return false, errors.New("failed to decode certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse x509 certificate: %w", err)
	}
	if time.Now().After(cert.NotAfter.Add(-renewThreshold)) {
		log.WithFields(log.Fields{
			"expiry":    cert.NotAfter,
			"threshold": renewThreshold,
		}).Info("Nearly expired certificate is detected")
		return true, nil
	}
	return false, nil
}

func (ic *InternalCertUpgrader) ShouldUpgradeInternalCert(ctx context.Context, secret *corev1.Secret) (bool, bool, error) {
	if secret == nil || len(secret.Data) == 0 {
		// No internal certificate.  We should upgrade it.
		return true, true, nil
	}
	log.WithFields(log.Fields{
		"threshold": ic.renewThreshold,
	}).Info("Checking CA certificate")

	// Check if the current certificate meets the criteria.
	caexpired, err := IsCertNearExpired(secret.Data[DEST_SECRET_PREFIX+CACERT_FILENAME], ic.renewThreshold)
	if err != nil {
		return false, false, err
	}

	log.WithFields(log.Fields{
		"threshold": ic.renewThreshold,
	}).Info("Checking certificate")

	certexpired, err := IsCertNearExpired(secret.Data[DEST_SECRET_PREFIX+CERT_FILENAME], ic.renewThreshold)
	if err != nil {
		return false, false, err
	}

	return caexpired, certexpired, nil
}

type CertConfig struct {
	CACertValidityDuration time.Duration
	CertValidityDuration   time.Duration
	RSAKeyLength           int
}

func (ic *InternalCertUpgrader) GenerateSecret() (cacert []byte, cert []byte, key []byte, err error) {

	// Note: We always upgrade cacert/cert/key together.
	// This is to reduce the attack surface, so after cert-upgrader creates these certs, ca key will be discarded and attacker can't initialize

	log.WithFields(log.Fields{
		"CACertValidityDuration": ic.CACertValidityDuration,
		"CertValidityDuration":   ic.CertValidityDuration,
		"RSAKeyLength":           ic.RSAKeyLength,
	}).Info("Creating new cert/key...")

	cacert, cakey, err := kv.GenerateCAWithRSAKey(
		&x509.Certificate{
			SerialNumber: big.NewInt(5029),
			Subject: pkix.Name{
				Country:      []string{"US"},
				Province:     []string{"California"},
				Organization: []string{"NeuVector Inc."},
				CommonName:   "NeuVector",
			},
			NotBefore:             time.Now().Add(time.Hour * -1), // Give it some room for timing skew.
			NotAfter:              time.Now().Add(ic.CACertValidityDuration),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}, ic.RSAKeyLength)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate ca cert: %w", err)
	}

	capair, err := tls.X509KeyPair(cacert, cakey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load ca key pair: %w", err)
	}

	log.WithFields(log.Fields{
		"cert":     string(cacert),
		"validity": ic.CACertValidityDuration,
	}).Debug("New cacert is created.")

	ca, err := x509.ParseCertificate(capair.Certificate[0])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse ca cert: %w", err)
	}

	cert, key, err = kv.GenerateTLSCertWithRSAKey(
		&x509.Certificate{
			SerialNumber: big.NewInt(5030),
			Subject: pkix.Name{
				Country:            []string{"US"},
				Locality:           []string{"San Jose"},
				Province:           []string{"California"},
				Organization:       []string{"NeuVector Inc."},
				OrganizationalUnit: []string{"NeuVector"},
				CommonName:         "NeuVector",
			},
			NotBefore:             time.Now().Add(time.Hour * -1), // Give it some room for timing skew.
			NotAfter:              time.Now().Add(ic.CertValidityDuration),
			SubjectKeyId:          []byte{1, 2, 3, 4, 6},
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
			IsCA:                  false,
			BasicConstraintsValid: true,
			DNSNames:              []string{"NeuVector"},
		}, ic.RSAKeyLength, ca, capair.PrivateKey)

	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate TLS certificate: %w", err)
	}

	log.WithFields(log.Fields{
		"cert":     string(cert),
		"validity": ic.CertValidityDuration,
	}).Debug("New cert is created.")

	return cacert, cert, key, nil
}

func (ic *InternalCertUpgrader) IsRotationEnabledOnSecret(secret *corev1.Secret) bool {
	if secret == nil {
		return false
	}
	if secret.Annotations[INTERNAL_SECRET_ROTATION_ANNOTATION] == "enabled" {
		return true
	}
	return false
}

// Generate certificate for fresh install
func (ic *InternalCertUpgrader) GenerateInitialSecretForFreshInstall(ctx context.Context, secret *corev1.Secret) (newSecret *corev1.Secret, needRotation bool, err error) {
	if secret != nil && len(secret.Data) > 0 {
		// Do not change the certificate.
		log.Info("All controller coming from the same replica set, but secret is already initialized.  Node failure or controllers are scaled to zero?")
		return nil, false, nil
	}

	cacert, cert, key, err := ic.GenerateSecret()
	if err != nil {
		return nil, false, fmt.Errorf("failed to generate certificate: %w", err)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				INTERNAL_SECRET_ROTATION_ANNOTATION: "enabled",
			},
		},
		Data: map[string][]byte{
			NEW_SECRET_PREFIX + CACERT_FILENAME: cacert,
			NEW_SECRET_PREFIX + CERT_FILENAME:   cert,
			NEW_SECRET_PREFIX + KEY_FILENAME:    key,

			DEST_SECRET_PREFIX + CACERT_FILENAME: cacert,
			DEST_SECRET_PREFIX + CERT_FILENAME:   cert,
			DEST_SECRET_PREFIX + KEY_FILENAME:    key,

			ACTIVE_SECRET_PREFIX + CACERT_FILENAME: cacert,
			ACTIVE_SECRET_PREFIX + CERT_FILENAME:   cert,
			ACTIVE_SECRET_PREFIX + KEY_FILENAME:    key,
		},
	}, false, nil
}

// Generate certificate for upgrade from previously generated cert in post-5.4
func (ic *InternalCertUpgrader) GenerateInitialSecretForUpgradeFromPost54WithRotationEnabled(ctx context.Context, secret *corev1.Secret) (newSecret *corev1.Secret, needRotation bool, err error) {
	cacert, cert, key, err := ic.GenerateSecret()
	if err != nil {
		return nil, false, fmt.Errorf("failed to generate certificate: %w", err)
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				INTERNAL_SECRET_ROTATION_ANNOTATION: "enabled",
			},
		},
		Data: map[string][]byte{
			NEW_SECRET_PREFIX + CACERT_FILENAME: cacert,
			NEW_SECRET_PREFIX + CERT_FILENAME:   cert,
			NEW_SECRET_PREFIX + KEY_FILENAME:    key,

			DEST_SECRET_PREFIX + CACERT_FILENAME: secret.Data[DEST_SECRET_PREFIX+CACERT_FILENAME],
			DEST_SECRET_PREFIX + CERT_FILENAME:   secret.Data[DEST_SECRET_PREFIX+CERT_FILENAME],
			DEST_SECRET_PREFIX + KEY_FILENAME:    secret.Data[DEST_SECRET_PREFIX+KEY_FILENAME],

			ACTIVE_SECRET_PREFIX + CACERT_FILENAME: secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME],
			ACTIVE_SECRET_PREFIX + CERT_FILENAME:   secret.Data[ACTIVE_SECRET_PREFIX+CERT_FILENAME],
			ACTIVE_SECRET_PREFIX + KEY_FILENAME:    secret.Data[ACTIVE_SECRET_PREFIX+KEY_FILENAME],
		},
	}, true, nil
}

// Generate certificate for upgrade from built-in cert in post-5.4
func (ic *InternalCertUpgrader) GenerateInitialSecretForUpgradeFromPost54WithRotationDisabled(ctx context.Context, secret *corev1.Secret) (newSecret *corev1.Secret, needRotation bool, err error) {
	cacert, cert, key, err := ic.GenerateSecret()
	if err != nil {
		return nil, false, fmt.Errorf("failed to generate certificate: %w", err)
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				INTERNAL_SECRET_ROTATION_ANNOTATION: "enabled",
			},
		},
		Data: map[string][]byte{
			NEW_SECRET_PREFIX + CACERT_FILENAME: cacert,
			NEW_SECRET_PREFIX + CERT_FILENAME:   cert,
			NEW_SECRET_PREFIX + KEY_FILENAME:    key,

			DEST_SECRET_PREFIX + CACERT_FILENAME: []byte(LegacyCaCert),
			DEST_SECRET_PREFIX + CERT_FILENAME:   []byte(LegacyCert),
			DEST_SECRET_PREFIX + KEY_FILENAME:    []byte(LegacyKey),

			ACTIVE_SECRET_PREFIX + CACERT_FILENAME: []byte(LegacyCaCert),
			ACTIVE_SECRET_PREFIX + CERT_FILENAME:   []byte(LegacyCert),
			ACTIVE_SECRET_PREFIX + KEY_FILENAME:    []byte(LegacyKey),
		},
	}, true, nil
}

// Generate initial secret for post-5.4.
func (ic *InternalCertUpgrader) GenerateInitialSecretForUpgradePost54(ctx context.Context, secret *corev1.Secret) (newSecret *corev1.Secret, needRotation bool, err error) {
	if !ic.enableRotation {
		// No upgrade path here.  Keep the secret intact.
		log.Info("Rotation is not enabled. Do not touch the existing certificate.")
		return nil, false, nil
	}

	if ic.IsRotationEnabledOnSecret(secret) {
		log.Info("the certificate exists.  Rotate from it.")
		// The certificate is generated before.  In this case we should rotate from the certificate to the one we just generated.
		return ic.GenerateInitialSecretForUpgradeFromPost54WithRotationEnabled(ctx, secret)
	} else {
		log.Info("the existing certificate is empty.  Rotate from built-in certificates.")
		// The certificate is not generated before.  We should rotate from the built-in one to the new one.
		return ic.GenerateInitialSecretForUpgradeFromPost54WithRotationDisabled(ctx, secret)
	}
}

// Generate initial secret for upgrade from pre-5.4, where the secret doesn't exist.
func (ic *InternalCertUpgrader) GenerateInitialSecretForUpgradePre54(ctx context.Context, secret *corev1.Secret) (newSecret *corev1.Secret, needRotation bool, err error) {
	if !ic.enableRotation {
		log.Info("Rotation is not enabled. Creating an empty secret.")
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Annotations: map[string]string{
					INTERNAL_SECRET_ROTATION_ANNOTATION: "disabled",
				},
			},
		}, false, nil
	}

	cacert, cert, key, err := ic.GenerateSecret()
	if err != nil {
		return nil, false, fmt.Errorf("failed to generate certificate: %w", err)
	}
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				INTERNAL_SECRET_ROTATION_ANNOTATION: "enabled",
			},
		},
		Data: map[string][]byte{
			NEW_SECRET_PREFIX + CACERT_FILENAME: cacert,
			NEW_SECRET_PREFIX + CERT_FILENAME:   cert,
			NEW_SECRET_PREFIX + KEY_FILENAME:    key,

			DEST_SECRET_PREFIX + CACERT_FILENAME: []byte(LegacyCaCert),
			DEST_SECRET_PREFIX + CERT_FILENAME:   []byte(LegacyCert),
			DEST_SECRET_PREFIX + KEY_FILENAME:    []byte(LegacyKey),

			ACTIVE_SECRET_PREFIX + CACERT_FILENAME: []byte(LegacyCaCert),
			ACTIVE_SECRET_PREFIX + CERT_FILENAME:   []byte(LegacyCert),
			ACTIVE_SECRET_PREFIX + KEY_FILENAME:    []byte(LegacyKey),
		},
	}, true, nil

}

// Generate initial secret based on below factors:
//
// 1. If it's a fresh install, which is determined in the init container of controllers, which creates this job.
//
// 2. If the secret already exists.
//
// 3. If the rotation is enabled.
//
// 4. If the rotation is marked as enabled before.
func (ic *InternalCertUpgrader) GenerateInitialSecret(ctx context.Context, secret *corev1.Secret) (newSecret *corev1.Secret, needRotation bool, err error) {
	if ic.freshInstall {
		log.Info("It's a fresh install.  Generate initial secret for fresh install")
		return ic.GenerateInitialSecretForFreshInstall(ctx, secret)
	}

	if secret != nil && secret.Annotations[INTERNAL_SECRET_ROTATION_ANNOTATION] != "" {
		log.Info("It's an upgrade from post-5.4.  Generate initial secret for it")
		return ic.GenerateInitialSecretForUpgradePost54(ctx, secret)
	} else {
		log.Info("It's an upgrade from pre-5.4.  Generate initial secret for it")
		return ic.GenerateInitialSecretForUpgradePre54(ctx, secret)
	}
}

func (ic *InternalCertUpgrader) UpdateInitialSecretIfRequired(ctx context.Context, secret *corev1.Secret) (newSecret *corev1.Secret, needRotation bool, err error) {

	// Check if cert-upgrader should still need to do its job.
	if inprogress := IsUpgradeInProgress(ctx, secret); inprogress {
		// There were interrupted jobs.  We should reuse the certificate created.
		// While we don't need to regenerate new certs, we should guide caller to resume rotation.
		log.Info("Cert rollout is still in progress.  Resuming.")
		return nil, true, nil
	}

	check, err := ic.ShouldCheckAndUpdateInitialSecret(ctx, secret)
	if err != nil {
		return nil, false, fmt.Errorf("failed to deterimine whether we should update secret: %w", err)
	}

	if !check {
		log.Info("No need to check secret")
		return nil, false, nil
	}
	newsecret, needRotation, err := ic.GenerateInitialSecret(ctx, secret)
	if err != nil {
		return nil, false, fmt.Errorf("failed to generate new secret: %w", err)
	}

	if newsecret == nil {
		// No change.  No need to update secret and perform rotation.
		log.Info("No need to update secret")
		return nil, false, nil
	}

	newsecret.Name = ic.secretName

	// If there is other instance running at the same time, this function is expected to cause conflict.
	var ret *corev1.Secret
	if ret, err = UpdateSecret(ctx, ic.client, ic.namespace, newsecret); err != nil {
		return nil, false, fmt.Errorf("failed to update initial secret: %w", err)
	}

	log.WithFields(log.Fields{
		"secret": ic.secretName,
	}).Info("Secret is updated")

	return ret, needRotation, nil
}

func (ic *InternalCertUpgrader) ShouldCheckAndUpdateInitialSecret(ctx context.Context, secret *corev1.Secret) (bool, error) {
	upgradeCA, upgradeCert, err := ic.ShouldUpgradeInternalCert(ctx, secret)
	if err != nil {
		return false, fmt.Errorf("failed to check if we should upgrade internal cert: %w", err)
	}

	if !upgradeCA && !upgradeCert {
		log.Info("Certificate is up-to-date")
		return false, nil
	}
	return true, nil
}

func (ic *InternalCertUpgrader) StartSecretWatcher(ctx context.Context, cancel context.CancelFunc) error {
	// Start watcher, so when `neuvector-internal-certs` secret is deleted, cert-upgrader will stop
	watcher, err := ic.client.Resource(schema.GroupVersionResource{
		Resource: "secrets",
		Version:  "v1",
	}).Namespace(ic.namespace).Watch(ctx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(metav1.ObjectNameField, ic.secretName).String(),
	})

	if err != nil {
		return fmt.Errorf("failed to watch secret (%s): %w", ic.secretName, err)
	}

	go func() {
		for event := range watcher.ResultChan() {
			switch event.Type {
			case watch.Deleted:
				log.Info("Internal cert is deleted. Upgrader should stop.")
				cancel()
				return
			default:
			}
		}
	}()
	return nil
}

func (ic *InternalCertUpgrader) TriggerRotation(ctx context.Context) (err error) {

	log.Info("Getting initial secret")

	var secret *corev1.Secret
	if secret, err = GetK8sSecret(ctx, ic.client, ic.namespace, ic.secretName); err != nil {
		if !k8sError.IsNotFound(err) {
			return fmt.Errorf("failed to find source secret: %w", err)
		}
	}

	log.Info("Updating initial secret if required")

	_, needRotation, err := ic.UpdateInitialSecretIfRequired(ctx, secret)
	if err != nil {
		return fmt.Errorf("failed to check/update initial secret: %w", err)
	}

	if !needRotation {
		log.Info("No need to perform rotation in stage.")
		return nil
	}

	log.WithFields(log.Fields{
		"needRotation": needRotation,
	}).Info("Starts certificate rotation")

	// Now we can create/update internal certs.
	log.Infof("Deploying internal secrets with retry: %+v", retry.DefaultRetry)
	err = retry.OnError(retry.DefaultRetry,
		func(error) bool {
			// Retry on all errors...returning error will make this job restart.
			return true
		},
		func() error {
			// The main logic.
			err = UpgradeInternalCerts(ctx, ic.client, ic.namespace, ic.secretName, ic.rolloutTimeout)
			if err != nil {
				return fmt.Errorf("failed to upgrade internal certs: %w", err)
			}

			return nil
		})
	if err != nil {
		return fmt.Errorf("failed to create internal certs: %w", err)
	}

	return nil
}

type InternalCertUpgrader struct {
	namespace              string
	secretName             string
	client                 dynamic.Interface
	rolloutTimeout         time.Duration
	renewThreshold         time.Duration
	CACertValidityDuration time.Duration
	CertValidityDuration   time.Duration
	RSAKeyLength           int
	enableRotation         bool
	freshInstall           bool
}

// Trigger the main logic of internal cert rotation.
func PostSyncHook(ctx *cli.Context) error {
	namespace := ctx.String("pod-namespace")
	kubeconfig := ctx.String("kube-config")
	timeout := ctx.Duration("timeout")

	// This flag is assigned by controller's init containers when all init containers coming from the same replica set.
	timeoutCtx, cancel := context.WithTimeout(ctx.Context, timeout)
	defer cancel()

	log.Info("Getting running namespace")

	if data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		namespace = string(data)
	} else {
		log.WithError(err).Warn("failed to open namespace file.")
	}

	log.Info("Creating k8s client")

	client, err := NewK8sClient(kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to create k8s client: %w", err)
	}

	log.Info("Checking k8s permissions")

	// Check if required permissions are there.
	config, err := rest.InClusterConfig()
	if err != nil {
		return fmt.Errorf("failed to read in-cluster config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to get k8s config: %w", err)
	}

	for _, res := range k8sutils.UpgraderPostsyncRequiredPermissions {
		capable, err := k8sutils.CanI(clientset, res, namespace)
		if err != nil {
			return err
		}
		if !capable {
			log.Error("required permission is missing...ending now")
			os.Exit(-2)
		}
	}

	log.Info("Initializing lock")

	// Make sure only one cert-upgrader will be running at the same time.
	lock, err := CreateLocker(client, namespace, UPGRADER_LEASE_NAME)
	if err != nil {
		log.Fatal("failed to acquire cluster-wide lock: %w", err)
	}

	lock.Lock()
	defer lock.Unlock()

	ic := InternalCertUpgrader{
		namespace:              namespace,
		secretName:             ctx.String("internal-secret-name"),
		client:                 client,
		rolloutTimeout:         ctx.Duration("rollout-timeout"),
		renewThreshold:         ctx.Duration("expiry-cert-threshold"),
		CACertValidityDuration: ctx.Duration("ca-cert-validity-period"),
		CertValidityDuration:   ctx.Duration("cert-validity-period"),
		RSAKeyLength:           ctx.Int("rsa-key-length"),
		enableRotation:         ctx.Bool("enable-rotation"),
		freshInstall:           ctx.Bool("fresh-install"),
	}

	log.WithFields(log.Fields{
		"upgrader": ic,
	}).Info("initial cert upgrader is initialized")

	log.Info("Setting up secret watcher")

	err = ic.StartSecretWatcher(timeoutCtx, cancel)
	if err != nil {
		return fmt.Errorf("failed to start secret watcher: %w", err)
	}

	log.Info("Starting handling cert rotation")

	if err := ic.TriggerRotation(timeoutCtx); err != nil {
		return fmt.Errorf("failed to trigger rotation: %w", err)
	}
	return nil
}

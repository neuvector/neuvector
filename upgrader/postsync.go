package main

import (
	"bytes"
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
	"reflect"
	"time"

	"errors"

	"github.com/neuvector/neuvector/controller/kv"
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
	"k8s.io/client-go/tools/cache"
	watchtools "k8s.io/client-go/tools/watch"
	"k8s.io/client-go/util/retry"
	"k8s.io/kubectl/pkg/polymorphichelpers"
)

const (
	UPGRADER_LEASE_NAME = "neuvector-cert-upgrader"
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

// Check if a legacy internal cert is still being used.
func containLegacyDefaultInternalCerts(ctx *cli.Context, client dynamic.Interface, namespace string) (bool, error) {
	item, err := client.Resource(
		schema.GroupVersionResource{
			Resource: "pods",
			Version:  "v1",
		},
	).Namespace(namespace).List(ctx.Context, metav1.ListOptions{
		LabelSelector: ControllerPodLabelSelector,
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

	for _, pod := range pods.Items {
		log.WithFields(log.Fields{
			"pod": pod.Status.PodIP,
		}).Info("Getting consul certs")

		// Check consul port to make sure consul is already up.
		cert, err := GetRemoteCert(pod.Status.PodIP, ControllerConsulPort, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return false, fmt.Errorf("failed to get remote certs from %s: %w", pod.Status.PodIP, err)
		}

		// Convert cert back to pem for comparison
		var b bytes.Buffer
		err = pem.Encode(&b, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		if err != nil {
			return false, fmt.Errorf("failed to convert remote cert to PEM: %w", err)
		}

		log.Infof("Issuer Name: %s\n", cert.Issuer)
		log.Infof("Expiry: %s \n", cert.NotAfter.Format("2006-January-02"))
		log.Infof("Common Name: %s \n", cert.Issuer.CommonName)
		if b.String() == LegacyCert {
			log.Info("It's legacy cert.")
			return true, nil
		}
	}
	return false, nil
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

// Check if we should upgrade internal certs. Currently the only criteria is:
// - If the certificate's expiry date + expiry-cert-threshold < now.
func ShouldUpgradeInternalCert(ctx context.Context, secret *corev1.Secret, renewThreshold time.Duration) (bool, bool, error) {
	if secret == nil || len(secret.Data) == 0 {
		// No internal certificate.  We should upgrade it.
		return true, true, nil
	}
	log.WithFields(log.Fields{
		"threshold": renewThreshold,
	}).Info("Checking CA certificate")

	// Check if the current certificate meets the criteria.
	caexpired, err := IsCertNearExpired(secret.Data[DEST_SECRET_PREFIX+CACERT_FILENAME], renewThreshold)
	if err != nil {
		return false, false, err
	}

	log.WithFields(log.Fields{
		"threshold": renewThreshold,
	}).Info("Checking certificate")

	certexpired, err := IsCertNearExpired(secret.Data[DEST_SECRET_PREFIX+CERT_FILENAME], renewThreshold)
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

// This function is meant to be called during pre-install/pre-upgrade/pre-sync hook.
// If it's a fresh-install, create an internal certificate that we can use directly.
// If it's a upgrade, leave it as it is.
// Post-upgrade/post-sync hook should deal with it.
func InitializeInternalSecret(ctx context.Context,
	client dynamic.Interface,
	namespace string,
	secretName string,
	freshInstall bool,
	certOnly bool,
	secret *corev1.Secret,
	config CertConfig) (*corev1.Secret, error) {
	var err error

	// Note: We always upgrade cacert/cert/key together.
	// This is to reduce the attack surface, so after cert-upgrader creates these certs, ca key will be discarded and attacker can't initialize

	if len(secret.Data) != 0 {
		log.Info("Updating internal secret.")
	} else {
		log.Info("Creating internal secret.")
		// Default secret is initialized using default certs. It will be updated later.
		secret.Data = map[string][]byte{
			NEW_SECRET_PREFIX + CACERT_FILENAME: []byte(LegacyCaCert),
			NEW_SECRET_PREFIX + CERT_FILENAME:   []byte(LegacyCert),
			NEW_SECRET_PREFIX + KEY_FILENAME:    []byte(LegacyKey),

			DEST_SECRET_PREFIX + CACERT_FILENAME: []byte(LegacyCaCert),
			DEST_SECRET_PREFIX + CERT_FILENAME:   []byte(LegacyCert),
			DEST_SECRET_PREFIX + KEY_FILENAME:    []byte(LegacyKey),

			ACTIVE_SECRET_PREFIX + CACERT_FILENAME: []byte(LegacyCaCert),
			ACTIVE_SECRET_PREFIX + CERT_FILENAME:   []byte(LegacyCert),
			ACTIVE_SECRET_PREFIX + KEY_FILENAME:    []byte(LegacyKey),
		}
	}

	log.WithFields(log.Fields{
		"CACertValidityDuration": config.CACertValidityDuration,
		"CertValidityDuration":   config.CertValidityDuration,
		"RSAKeyLength":           config.RSAKeyLength,
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
			NotAfter:              time.Now().Add(config.CACertValidityDuration),
			IsCA:                  true,
			BasicConstraintsValid: true,
		}, config.RSAKeyLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ca cert: %w", err)
	}
	capair, err := tls.X509KeyPair(cacert, cakey)
	if err != nil {
		return nil, fmt.Errorf("failed to load ca key pair: %w", err)
	}

	log.WithFields(log.Fields{
		"cert":     string(cacert),
		"validity": config.CACertValidityDuration,
	}).Debug("New cacert is created.")

	ca, err := x509.ParseCertificate(capair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse ca cert: %w", err)
	}

	cert, key, err := kv.GenerateTLSCertWithRSAKey(
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
			NotAfter:              time.Now().Add(config.CertValidityDuration),
			SubjectKeyId:          []byte{1, 2, 3, 4, 6},
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
			IsCA:                  false,
			BasicConstraintsValid: true,
			DNSNames:              []string{"NeuVector"},
		}, config.RSAKeyLength, ca, capair.PrivateKey)

	if err != nil {
		return nil, fmt.Errorf("failed to generate TLS certificate: %w", err)
	}

	log.WithFields(log.Fields{
		"cert":     string(cert),
		"validity": config.CertValidityDuration,
	}).Debug("New cert is created.")

	// At this point, we have these keys/certs in PEM format:
	// 1. cacert in cacert, cakey
	// 2. internal certs in cert/key.
	// Time to change the secret.
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}

	if freshInstall {
		// Fresh install case.  We should apply to NEW_SECRET_NAME, DEST_SECRET_NAME and ACTIVE_SECRET_NAME
		secret.Data[NEW_SECRET_PREFIX+CACERT_FILENAME] = cacert
		secret.Data[NEW_SECRET_PREFIX+CERT_FILENAME] = cert
		secret.Data[NEW_SECRET_PREFIX+KEY_FILENAME] = key

		secret.Data[DEST_SECRET_PREFIX+CACERT_FILENAME] = cacert
		secret.Data[DEST_SECRET_PREFIX+CERT_FILENAME] = cert
		secret.Data[DEST_SECRET_PREFIX+KEY_FILENAME] = key

		secret.Data[ACTIVE_SECRET_PREFIX+CACERT_FILENAME] = cacert
		secret.Data[ACTIVE_SECRET_PREFIX+CERT_FILENAME] = cert
		secret.Data[ACTIVE_SECRET_PREFIX+KEY_FILENAME] = key
	} else {
		// Upgrade case.  We should only provide NEW_SECRET and keep others intact
		secret.Data[NEW_SECRET_PREFIX+CACERT_FILENAME] = cacert
		secret.Data[NEW_SECRET_PREFIX+CERT_FILENAME] = cert
		secret.Data[NEW_SECRET_PREFIX+KEY_FILENAME] = key
	}

	// If there is other instance running at the same time, this function is expected to cause conflict.
	var ret *corev1.Secret
	if ret, err = UpdateSecret(ctx, client, namespace, secret); err != nil {
		return nil, fmt.Errorf("failed to write dst secret: %w", err)
	}
	log.WithFields(log.Fields{
		"secret": secretName,
	}).Info("Secret is updated")

	return ret, nil
}

// In post sync hook, we did a few things.
// 1. Check if the internal certs is already created.
// 2. Create it if it doesn't exist, trigger a rolling update on controller and exit. (fresh install case)
// 3. If it exists, examine the content.  If it's ok, just exit.  (upgrade from old, upgrade from new and reinstall)
// 4. If the cert is in the progress of upgrade, try to finish it. (Interrupted upgrade)
// 5. If the cert is not in progress, but its content is not ok, update it and trigger upgrade. (upgrade from old, upgrade from new and reinstall)
//
// Note: It's supposed to be only one cert-upgrader job (post sync job) running at all time.
//
// empty => create secret => if secret is created and this is for fresh install, trigger rolling update and exit.
// not empty => do rolling update per its state.
func PostSyncHook(ctx *cli.Context) error {
	namespace := ctx.String("pod-namespace")
	kubeconfig := ctx.String("kube-config")
	secretName := ctx.String("internal-secret-name")
	freshInstall := ctx.Bool("fresh-install")
	renewThreshold := ctx.Duration("expiry-cert-threshold")
	timeout := ctx.Duration("timeout")
	waitDeploymentTimeout := ctx.Duration("rollout-timeout")
	disableRotation := ctx.Bool("disable-rotation")

	timeoutCtx, cancel := context.WithTimeout(ctx.Context, timeout)
	defer cancel()

	log.Info("Initializing lock")

	// Make sure only one cert-upgrader will be running at the same time.
	lock, err := CreateLocker(namespace, UPGRADER_LEASE_NAME)
	if err != nil {
		log.Fatal("failed to acquire cluster-wide lock: %w", err)
	}

	lock.Lock()
	defer lock.Unlock()

	log.Info("Creating k8s client")

	client, err := NewK8sClient(kubeconfig)
	if err != nil {
		return fmt.Errorf("failed to create k8s client: %w", err)
	}

	// Start watcher, so when `neuvector-internal-certs` secret is deleted, cert-upgrader will stop
	watcher, err := client.Resource(schema.GroupVersionResource{
		Resource: "secrets",
		Version:  "v1",
	}).Namespace(namespace).Watch(timeoutCtx, metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(metav1.ObjectNameField, secretName).String(),
	})

	if err != nil {
		return fmt.Errorf("failed to watch secret (%s): %w", secretName, err)
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

	// Initialization phase.

	// 1. Check if internal cert exists.
	var secret *corev1.Secret
	var retSecret *corev1.Secret
	if secret, err = GetK8sSecret(timeoutCtx, client, namespace, secretName); err != nil {
		if !k8sError.IsNotFound(err) {
			return fmt.Errorf("failed to find source secret: %w", err)
		}
	}

	noInitialSecret := (secret == nil || len(secret.Data) == 0)

	// Check if we should update cert.  If not, exit

	// We create/update the secret in below scenario:
	// 1. Secret is not there.
	// 2. An option is given to force update the secret.
	// 3. Secret is not up-to-date, say it's expired, and no upgrade is in progress.

	// Check if cert-upgrader should still need to do its job.  If so, exit.
	if inprogress := IsUpgradeInProgress(timeoutCtx, secret); inprogress {
		// There was interrupted jobs.  We should reuse the certificate created.
		// Note: It's guaranteed in init containers that only one instance of Job will be running.
		log.Info("Cert rollout is still in progress.  This instance should take over.")
	} else {
		certOnly := false
		if upgradeCA, upgradeCert, err := ShouldUpgradeInternalCert(ctx.Context, secret, renewThreshold); err != nil {
			return fmt.Errorf("failed to check if we should upgrade internal cert: %w", err)
		} else if !upgradeCA && !upgradeCert {
			log.Info("Certificate is up-to-date")
			return nil
		} else {
			certOnly = !upgradeCA && upgradeCert
			log.Info("We should update internal certificate")
		}

		if retSecret, err = InitializeInternalSecret(timeoutCtx, client, namespace, secretName, freshInstall, certOnly, secret, CertConfig{
			CACertValidityDuration: ctx.Duration("ca-cert-validity-period"),
			CertValidityDuration:   ctx.Duration("cert-validity-period"),
			RSAKeyLength:           ctx.Int("rsa-key-length"),
		}); err != nil {
			return fmt.Errorf("failed to initialize internal secret: %w", err)
		}
	}

	// Fastpath if it's a fresh install and the secret is created.
	// We just trigger controller's rolling update and exit.
	// Otherwise, go through the full rolling update.

	// Here we check three conditions:
	// 1. No secret was created initially and we created a secret above.
	//    This is to support job resume. Only the first job can go through fash path.
	// 2. It's a fresh install because it's still doing rolling update.
	if noInitialSecret && retSecret != nil && freshInstall {
		log.Info("This is fresh install.  Everything is done.")
		// Everything is good now.  Exit.
		return nil
	}

	if disableRotation {
		log.Info("Rotation is disabled. Finishing.")
		return nil
	}

	log.WithFields(log.Fields{
		"noInitialSecret": noInitialSecret,
		"retSecret":       retSecret != nil,
		"freshInstall":    freshInstall,
	}).Info("Starts slowpath")

	// Now we can create/update internal certs.
	log.Infof("Deploying internal secrets with retry: %+v", retry.DefaultRetry)
	err = retry.OnError(retry.DefaultRetry,
		func(error) bool {
			// Retry on all errors...returning error will make this job restart, which will lead to a retry anyway.
			return true
		},
		func() error {
			// The main logic.

			// Now we have certs ready. It's time to do rolling update.
			err = UpgradeInternalCerts(timeoutCtx, client, namespace, secretName, waitDeploymentTimeout)
			if err != nil {
				return fmt.Errorf("failed to upgrade internal certs: %w", err)
			}

			return nil
		})
	if err != nil {
		if k8sError.IsAlreadyExists(err) {
			log.WithError(err).Debug("failed to create resource. Other init container created it. Can be safely ignored.")
		}
		return fmt.Errorf("failed to create internal certs: %w", err)
	}

	return nil
}

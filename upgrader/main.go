package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jrhouston/k8slock"
	log "github.com/sirupsen/logrus"

	"github.com/urfave/cli/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	TARGET_SECRET_SOURCE_NAME_CACERT = "target-cacert"
	TARGET_SECRET_SOURCE_NAME_CERT   = "target-cert"
	TARGET_SECRET_SOURCE_NAME_KEY    = "target-key"

	CACERT_FILENAME = "ca.crt"
	CERT_FILENAME   = "tls.crt"
	KEY_FILENAME    = "tls.key"

	NEW_SECRET_PREFIX    = "new-"
	DEST_SECRET_PREFIX   = "dest-"
	ACTIVE_SECRET_PREFIX = ""
)

// Go 1.14 + client-go  We had below options at design stage:
// 1. Use client-go + Go 1.16 => Need to patch build environment.
// 2. Use client-go + Go 1.14 => Works since we also include kubectl in this executable.
// 3. Use global.ORCH.StartWatchResource + Go 1.14 => should work too, but if we want cache support it will be getting complex.

var (
	ControllerPodLabelSelector = fields.OneTermEqualSelector("app", "neuvector-controller-pod").String()
	ScannerPodLabelSelector    = fields.OneTermEqualSelector("app", "neuvector-scanner-pod").String()
	EnforcerPodLabelSelector   = fields.OneTermEqualSelector("app", "neuvector-enforcer-pod").String()
	RegistryPodLabelSelector   = fields.OneTermEqualSelector("app", "neuvector-registry-adapter-pod").String()
)

var (
	ControllerConsulPort = "18300"
	ControllerGRPCPort   = "18400"
	EnforcerGRPCPort     = "18401"
	ScannerGRPCPort      = "18402"
)

func NewK8sClient(kubeconfig string) (dynamic.Interface, error) {
	var err error
	var config *rest.Config
	if len(kubeconfig) > 0 {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to build config from kubeconfig: %w", err)
		}
	} else {
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to read in-cluster config: %w", err)
		}
	}

	return dynamic.NewForConfig(config)
}

func CreateLocker(client dynamic.Interface, namespace string, lockName string) (*k8slock.Locker, error) {
	hostname, err := os.Hostname()
	if err != nil {
		log.Info("failed to get hostname: %w", err)
	}
	hostname += "_" + uuid.New().String()

	if _, err := client.Resource(
		schema.GroupVersionResource{
			Resource: "leases",
			Version:  "v1",
			Group:    "coordination.k8s.io",
		},
	).Namespace(namespace).Get(context.TODO(), lockName, metav1.GetOptions{}); err != nil {
		return nil, fmt.Errorf("failed to find lease object: %w", err)
	}

	return k8slock.NewLocker(
		lockName,
		k8slock.RetryWaitDuration(time.Second*30),
		k8slock.Namespace(namespace),
		k8slock.TTL(time.Hour*1),
		k8slock.ClientID(hostname),
		k8slock.CreateLease(true),
	)
}

func main() {
	app := cli.NewApp()

	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:  "kube-config",
			Value: "",
			Usage: "the active secret used by containers.  For testing only.",
		},
		&cli.StringFlag{
			Name:    "pod-namespace",
			Value:   "neuvector",
			Usage:   "The k8s namespace where NeuVector is running in",
			EnvVars: []string{"POD_NAMESPACE"},
		},
		&cli.StringFlag{
			Name:    "internal-secret-name",
			Value:   "neuvector-internal-certs",
			Usage:   "the new secret to be applied",
			EnvVars: []string{"INTERNAL_SECRET_NAME"},
		},
		&cli.DurationFlag{
			Name:    "timeout",
			Value:   time.Minute * 30,
			Usage:   "The timeout for this job to complete",
			EnvVars: []string{"TIMEOUT"},
		},
	}
	app.Commands = cli.Commands{
		&cli.Command{
			Name:   "create-upgrader-job",
			Usage:  "This command creates upgrader job from neuvector-upgrader-pod cron job in a not racey way.",
			Flags:  []cli.Flag{},
			Action: PreSyncHook,
		},
		&cli.Command{
			Name:  "upgrader-job",
			Usage: "Run neuvector upgrader",
			Flags: []cli.Flag{
				&cli.DurationFlag{
					Name:    "rollout-timeout",
					Value:   0,
					Usage:   "The timeout for waiting deployment to complete.  0: no timeout.",
					EnvVars: []string{"ROLLOUT_TIMEOUT"},
				},
				&cli.IntFlag{
					Name:    "rsa-key-length",
					Value:   4096,
					Usage:   "RSA key length when creating new internal key and certificate",
					EnvVars: []string{"RSA_KEY_LENGTH"},
				},
				&cli.DurationFlag{
					Name:    "expiry-cert-threshold",
					Value:   10 * 365 * 24 * time.Hour, // Will always rotate by default.
					Usage:   "The threshold to automatically upgrade an internal cert",
					EnvVars: []string{"EXPIRY_CERT_THRESHOLD"},
				},
				&cli.DurationFlag{
					Name:    "ca-cert-validity-period",
					Value:   5 * 365 * 24 * time.Hour,
					Usage:   "The ca cert's validity period",
					EnvVars: []string{"CA_CERT_VALIDITY_PERIOD"},
				},
				&cli.DurationFlag{
					Name:    "cert-validity-period",
					Value:   3 * 365 * 24 * time.Hour,
					Usage:   "The cert's validity period",
					EnvVars: []string{"CERT_VALIDITY_PERIOD"},
				},
				&cli.BoolFlag{
					Name:    "fresh-install",
					Value:   false,
					Usage:   "Whether it's a fresh install.  When in fresh install mode, upgrader will create certs and bypass the rolling update flow.",
					EnvVars: []string{"FRESH_INSTALL"},
				},
				&cli.BoolFlag{
					Name:    "enable-rotation",
					Value:   false,
					Usage:   "When this is specified, this program will rotate NV internal certificate.",
					EnvVars: []string{"ENABLE_ROTATION"},
				},
			},
			Action: PostSyncHook,
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.WithError(err).Fatal("Failed to run the command")
		os.Exit(1)
	}
}

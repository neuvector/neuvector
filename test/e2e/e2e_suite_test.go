package e2e_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/third_party/helm"
)

func createMinikubeCluster(profile, kubeconfigPath string) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		cmd := exec.CommandContext(ctx, "minikube", "start",
			"--driver=kvm2",
			"--profile", profile,
			"--cpus=4",
			"--memory=6144mb",
			"--container-runtime=containerd",
			"--wait=all",
		)
		cmd.Env = append(os.Environ(), "KUBECONFIG="+kubeconfigPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return ctx, fmt.Errorf("minikube start: %w", err)
		}
		cfg.WithKubeconfigFile(kubeconfigPath)
		return ctx, nil
	}
}

func loadImageToMinikube(profile, image string) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		cmd := exec.CommandContext(ctx, "minikube", "image", "load", image, "--profile", profile)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return ctx, fmt.Errorf("minikube image load %s: %w", image, err)
		}
		return ctx, nil
	}
}

func exportMinikubeLogs(profile, destDir string) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		if err := os.MkdirAll(destDir, 0755); err != nil {
			return ctx, err
		}
		logFile := filepath.Join(destDir, "minikube.log")
		f, err := os.Create(logFile)
		if err != nil {
			return ctx, err
		}
		defer f.Close()
		cmd := exec.CommandContext(ctx, "minikube", "logs", "--profile", profile)
		cmd.Stdout = f
		cmd.Stderr = f
		_ = cmd.Run()
		return ctx, nil
	}
}

func destroyMinikubeCluster(profile string) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		cmd := exec.CommandContext(ctx, "minikube", "delete", "--profile", profile)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return ctx, fmt.Errorf("minikube delete: %w", err)
		}
		return ctx, nil
	}
}

//nolint:gochecknoglobals // provided by e2e-framework
var testEnv env.Environment

//nolint:gochecknoglobals // generated once in TestMain, read by all test features
var nvAdminPassword string

const (
	helmRepoNotFoundString       = "no repo named"
	helmRepoReleaseNotFound      = "release: not found"
	helmNoRepositoriesConfigured = "no repositories configured"

	nvE2EPrefix    = "neuvector-e2e-"
	nvNamespace    = "neuvector"
	nvReleaseName  = "neuvector"
	nvHelmRepoName = nvE2EPrefix + "repo"
	nvHelmRepoURL  = "https://neuvector.github.io/neuvector-helm/"
	nvChartPath    = "/core"
)

var (
	controllerImage = "neuvector/controller:latest"
	enforcerImage   = "neuvector/enforcer:latest"
)

var defaultHelmTimeout = 10 * time.Minute

// generateAdminPassword returns a cryptographically random password.
// rand.Text() uses the base32 alphabet (A-Z, 2-7), so "Aa1" is appended to
// guarantee NeuVector's default profile (MinUpperCount=1, MinLowerCount=1, MinDigitCount=1).
func generateAdminPassword() string {
	return rand.Text() + "Aa1"
}

// writeValuesFile writes a temporary Helm values override file (mode 0600) that:
//   - Enables controller.secret so the admin password is stored in a Kubernetes Secret
//   - Sets the admin password via userinitcfg.yaml
//   - Exposes the controller REST API as a NodePort service
//
// The caller is responsible for removing the file when it is no longer needed.
func writeValuesFile(password string) (string, error) {
	content := fmt.Sprintf(`controller:
  secret:
    enabled: true
    data:
      userinitcfg.yaml:
        always_reload: false
        users:
          - Fullname: admin
            Password: %q
            Role: admin
`, password)

	f, err := os.CreateTemp("", "neuvector-e2e-values-*.yaml")
	if err != nil {
		return "", fmt.Errorf("create temp values file: %w", err)
	}
	name := f.Name()
	if err = os.Chmod(name, 0600); err != nil {
		f.Close()
		os.Remove(name)
		return "", fmt.Errorf("chmod temp values file: %w", err)
	}
	if _, err = f.WriteString(content); err != nil {
		f.Close()
		os.Remove(name)
		return "", fmt.Errorf("write temp values file: %w", err)
	}
	return name, f.Close()
}

type helmChart struct {
	name          string
	namespace     string
	repoLocalName string
	repoURL       string
	path          string
	helmOptions   []helm.Option
}

func getCharts(valuesFile string) []helmChart {
	return []helmChart{
		{
			name:          nvReleaseName,
			namespace:     nvNamespace,
			repoLocalName: nvHelmRepoName,
			repoURL:       nvHelmRepoURL,
			path:          nvChartPath,
			helmOptions: []helm.Option{
				helm.WithArgs("--set", "tag=latest"),
				helm.WithArgs("--set", "manager.enabled=false"),
				// Reduce replicas to 1 to limit memory usage in the test cluster.
				helm.WithArgs("--set", "controller.replicas=1"),
				helm.WithArgs("--set", "cve.scanner.replicas=1"),
				// Controller and enforcer are pre-loaded into the cluster; use
				// IfNotPresent so the kubelet picks up the local image instead of pulling.
				helm.WithArgs("--set", "controller.image.imagePullPolicy=IfNotPresent"),
				helm.WithArgs("--set", "enforcer.image.imagePullPolicy=IfNotPresent"),
				// Manager and scanner are not loaded locally; kubelet pulls them from DockerHub.
				// The chart's default global tag (nvChartTag) is used for manager.
				// Scanner uses its own cve.scanner.image.tag (independent of global tag).
				helm.WithVersion(os.Getenv("NV_CHART_VERSION")),
				// Inject the admin password and init config via a Kubernetes Secret.
				helm.WithArgs("--values", valuesFile),
				// Expose the controller REST API as a NodePort so tests can reach it.
				helm.WithArgs("--set", "controller.apisvc.type=NodePort"),
			},
		},
	}
}

func TestMain(m *testing.M) {
	if os.Getenv("NV_CHART_VERSION") == "" {
		fmt.Fprintf(os.Stderr, "NV_CHART_VERSION is not defined")
		os.Exit(1)
	}

	nvAdminPassword = generateAdminPassword()
	valuesFile, err := writeValuesFile(nvAdminPassword)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to write helm values file: %v\n", err)
		os.Exit(1)
	}

	charts := getCharts(valuesFile)
	commonSetupFuncs := []env.Func{
		uninstallHelmCharts(charts),
		installHelmCharts(charts),
		discoverAPIEndpoint(),
	}
	commonFinishFuncs := []env.Func{
		func(ctx context.Context, _ *envconf.Config) (context.Context, error) {
			os.Remove(valuesFile)
			return ctx, nil
		},
	}

	cfg, err := envconf.NewFromFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to process e2e config: %v\n", err)
		os.Exit(1)
	}
	testEnv = env.NewWithConfig(cfg)
	clusterProfile := envconf.RandomName(nvE2EPrefix, 32)
	kubeconfigPath := filepath.Join(os.TempDir(), clusterProfile+".kubeconfig")

	commonSetupFuncs = append([]env.Func{
		createMinikubeCluster(clusterProfile, kubeconfigPath),
		loadImageToMinikube(clusterProfile, controllerImage),
		loadImageToMinikube(clusterProfile, enforcerImage),
	}, commonSetupFuncs...)

	commonFinishFuncs = append([]env.Func{
		exportMinikubeLogs(clusterProfile, "./logs"),
	}, commonFinishFuncs...)
	commonFinishFuncs = append(commonFinishFuncs, destroyMinikubeCluster(clusterProfile))

	testEnv.Setup(commonSetupFuncs...)
	testEnv.Finish(commonFinishFuncs...)
	os.Exit(testEnv.Run(m))
}

func uninstallHelmCharts(charts []helmChart) env.Func {
	return func(ctx context.Context, config *envconf.Config) (context.Context, error) {
		manager := helm.New(config.KubeconfigFile())
		logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

		for _, chart := range slices.Backward(charts) {
			logger.InfoContext(ctx, "uninstall helm release if present",
				"name", chart.name, "namespace", chart.namespace)
			err := manager.RunUninstall(
				helm.WithName(chart.name),
				helm.WithNamespace(chart.namespace),
				helm.WithTimeout(defaultHelmTimeout.String()),
			)
			if err != nil && !strings.Contains(err.Error(), helmRepoReleaseNotFound) {
				logger.WarnContext(ctx, "failed to uninstall helm chart release",
					"name", chart.name, "namespace", chart.namespace, "error", err)
			}

			logger.InfoContext(ctx, "remove helm repo if present", "repo", chart.repoLocalName)
			err = manager.RunRepo(helm.WithArgs("remove", chart.repoLocalName))
			if err != nil &&
				!strings.Contains(err.Error(), helmRepoNotFoundString) &&
				!strings.Contains(err.Error(), helmNoRepositoriesConfigured) {
				logger.WarnContext(ctx, "failed to remove helm repo",
					"repo", chart.repoLocalName, "error", err)
			}
		}
		return ctx, nil
	}
}

func installHelmCharts(charts []helmChart) env.Func {
	return func(ctx context.Context, config *envconf.Config) (context.Context, error) {
		manager := helm.New(config.KubeconfigFile())
		logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

		for _, chart := range charts {
			var err error

			chartPath := chart.path
			if strings.HasPrefix(chartPath, "/") {
				if err = manager.RunRepo(helm.WithArgs("add", chart.repoLocalName, chart.repoURL)); err != nil {
					return ctx, fmt.Errorf("failed to add local repo '%s': %w", chart.repoLocalName, err)
				}
				if err = manager.RunRepo(helm.WithArgs("update")); err != nil {
					return ctx, fmt.Errorf("failed to update local repo '%s': %w", chart.repoLocalName, err)
				}
				chartPath = chart.repoLocalName + chartPath
			}

			opts := []helm.Option{
				helm.WithName(chart.name),
				helm.WithNamespace(chart.namespace),
				helm.WithArgs("--create-namespace"),
				helm.WithChart(chartPath),
				helm.WithWait(),
				helm.WithTimeout(defaultHelmTimeout.String()),
			}
			opts = append(opts, chart.helmOptions...)
			logger.InfoContext(ctx, "installing helm release",
				"path", chartPath, "name", chart.name, "namespace", chart.namespace)
			if err = manager.RunInstall(opts...); err != nil {
				return ctx, fmt.Errorf("failed to install release '%s': %w", chart.name, err)
			}
		}
		return ctx, nil
	}
}

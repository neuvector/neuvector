package e2e_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/e2e-framework/klient/conf"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/support/kind"
	"sigs.k8s.io/e2e-framework/third_party/helm"
)

//nolint:gochecknoglobals // provided by e2e-framework
var testEnv env.Environment

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

	controllerImage = "neuvector/controller:latest"
	enforcerImage   = "neuvector/enforcer:latest"
)

var defaultHelmTimeout = 10 * time.Minute

func useExistingCluster() bool {
	return os.Getenv("E2E_USE_EXISTING_CLUSTER") == "true"
}

type helmChart struct {
	name          string
	namespace     string
	repoLocalName string
	repoURL       string
	path          string
	helmOptions   []helm.Option
}

func getCharts() []helmChart {
	return []helmChart{
		{
			name:          nvReleaseName,
			namespace:     nvNamespace,
			repoLocalName: nvHelmRepoName,
			repoURL:       nvHelmRepoURL,
			path:          nvChartPath,
			helmOptions: []helm.Option{
				helm.WithArgs("--set", "tag=latest"),
				// Reduce replicas to 1 to limit memory usage in the test cluster.
				helm.WithArgs("--set", "controller.replicas=1"),
				helm.WithArgs("--set", "cve.scanner.replicas=1"),
				// Controller and enforcer use locally loaded images.
				helm.WithArgs("--set", "controller.image.imagePullPolicy=IfNotPresent"),
				helm.WithArgs("--set", "enforcer.image.imagePullPolicy=IfNotPresent"),
				// Manager pulls from DockerHub (no local build).
				helm.WithArgs("--set", "manager.image.imagePullPolicy=Always"),
				// Scanner lives under cve.scanner in the values hierarchy.
				helm.WithArgs("--set", "cve.scanner.image.imagePullPolicy=Always"),
			},
		},
	}
}

func TestMain(m *testing.M) {
	charts := getCharts()
	commonSetupFuncs := []env.Func{
		uninstallHelmCharts(charts),
		installHelmCharts(charts),
	}
	commonFinishFuncs := []env.Func{
		uninstallHelmCharts(charts),
	}

	if useExistingCluster() {
		path := conf.ResolveKubeConfigFile()
		cfg := envconf.NewWithKubeConfig(path)
		testEnv = env.NewWithConfig(cfg)
	} else {
		cfg, err := envconf.NewFromFlags()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to process e2e config: %v\n", err)
			os.Exit(1)
		}
		testEnv = env.NewWithConfig(cfg)
		kindClusterName := envconf.RandomName(nvE2EPrefix, 32)

		commonSetupFuncs = append([]env.Func{
			envfuncs.CreateCluster(kind.NewProvider(), kindClusterName),
			envfuncs.LoadImageToCluster(kindClusterName, controllerImage, "--verbose", "--mode", "direct"),
			envfuncs.LoadImageToCluster(kindClusterName, enforcerImage, "--verbose", "--mode", "direct"),
		}, commonSetupFuncs...)

		commonFinishFuncs = append([]env.Func{
			envfuncs.ExportClusterLogs(kindClusterName, "./logs"),
		}, commonFinishFuncs...)
		commonFinishFuncs = append(commonFinishFuncs, envfuncs.DestroyCluster(kindClusterName))
	}

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

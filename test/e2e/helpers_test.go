package e2e_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	api "github.com/neuvector/neuvector/controller/api"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

type contextKey struct{}

var k8sClientKey contextKey

const (
	controllerDeploymentName = "neuvector-controller-pod"
	enforcerDaemonSetName    = "neuvector-enforcer-pod"
	managerDeploymentName    = "neuvector-manager-pod"
	scannerDeploymentName    = "neuvector-scanner-pod"

	assessTimeout = 5 * time.Minute
)

func getNeuVectorDeploymentFeature() types.Feature {
	return features.New("NeuVector Core Deployment").
		Setup(setupSharedK8sClient).
		Assess("controller deployment is available", assessControllerDeployment).
		Assess("enforcer daemonset is ready", assessEnforcerDaemonSet).
		Assess("manager deployment is available", assessManagerDeployment).
		Assess("scanner deployment is available", assessScannerDeployment).
		Feature()
}

func setupSharedK8sClient(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
	t.Helper()
	client, err := cfg.NewClient()
	require.NoError(t, err, "create k8s client")
	return context.WithValue(ctx, k8sClientKey, client)
}

func getK8sClient(ctx context.Context) klient.Client {
	return ctx.Value(k8sClientKey).(klient.Client)
}

func assessControllerDeployment(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	client := getK8sClient(ctx)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: controllerDeploymentName, Namespace: nvNamespace},
	}
	err := wait.For(
		conditions.New(client.Resources()).DeploymentConditionMatch(dep, appsv1.DeploymentAvailable, corev1.ConditionTrue),
		wait.WithTimeout(assessTimeout),
	)
	require.NoError(t, err, "controller deployment not available")
	return ctx
}

func assessEnforcerDaemonSet(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	client := getK8sClient(ctx)
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: enforcerDaemonSetName, Namespace: nvNamespace},
	}
	err := wait.For(
		conditions.New(client.Resources()).ResourceMatch(ds, func(obj k8s.Object) bool {
			d := obj.(*appsv1.DaemonSet)
			return d.Status.DesiredNumberScheduled > 0 &&
				d.Status.DesiredNumberScheduled == d.Status.NumberReady
		}),
		wait.WithTimeout(assessTimeout),
	)
	require.NoError(t, err, "enforcer daemonset not ready")
	return ctx
}

func assessManagerDeployment(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	client := getK8sClient(ctx)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: managerDeploymentName, Namespace: nvNamespace},
	}
	err := wait.For(
		conditions.New(client.Resources()).DeploymentConditionMatch(dep, appsv1.DeploymentAvailable, corev1.ConditionTrue),
		wait.WithTimeout(assessTimeout),
	)
	require.NoError(t, err, "manager deployment not available")
	return ctx
}

func assessScannerDeployment(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	client := getK8sClient(ctx)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: scannerDeploymentName, Namespace: nvNamespace},
	}
	err := wait.For(
		conditions.New(client.Resources()).DeploymentConditionMatch(dep, appsv1.DeploymentAvailable, corev1.ConditionTrue),
		wait.WithTimeout(assessTimeout),
	)
	require.NoError(t, err, "scanner deployment not available")
	return ctx
}

// findWorkloadInNVAPI polls /v2/workload until a workload matching namespace and
// serviceGroup is found. If displayName is non-empty, it must also match. Returns
// the workload ID of the matched workload.
func findWorkloadInNVAPI(ctx context.Context, t *testing.T, namespace, serviceGroup, displayName string) string {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	httpClient := newNVHTTPClient()

	var workloadID string
	require.Eventually(t, func() bool {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v2/workload", nil)
		if err != nil {
			return false
		}
		req.Header.Set("X-Auth-Token", token)
		resp, err := httpClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			return false
		}
		defer resp.Body.Close()
		var list api.RESTWorkloadsDataV2
		if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
			return false
		}
		for _, w := range list.Workloads {
			if w.WlBrief.Domain == namespace &&
				w.WlBrief.ServiceGroup == serviceGroup &&
				(displayName == "" || w.WlBrief.DisplayName == displayName) {
				workloadID = w.WlBrief.ID
				return true
			}
		}
		return false
	}, assessTimeout, retryInterval,
		"workload in namespace %q with service_group %q not found in /v2/workload after %s",
		namespace, serviceGroup, assessTimeout)

	return workloadID
}

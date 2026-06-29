package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	api "github.com/neuvector/neuvector/controller/api"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

const (
	scanWorkloadNamespace    = "neuvector-e2e-scan"
	scanWorkloadDeployName   = "nginx"
	scanWorkloadServiceGroup = "nv." + scanWorkloadDeployName + "." + scanWorkloadNamespace
)

type workloadIDKey struct{}

func storeWorkloadID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, workloadIDKey{}, id)
}

func getWorkloadID(ctx context.Context) string {
	return ctx.Value(workloadIDKey{}).(string)
}

func getScannerCVEDBFeature() types.Feature {
	return features.New("NeuVector Scanner CVEDB Registration").
		Setup(setupSharedK8sClient).
		Setup(setupAPIEndpoint).
		Setup(setupAuthToken).
		Assess("scanner CVEDB version is populated in controller scan status", assessScannerCVEDBRegistered).
		Feature()
}

func assessScannerCVEDBRegistered(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	httpClient := newNVHTTPClient()

	require.Eventually(t, func() bool {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v1/scan/status", nil)
		if err != nil {
			return false
		}
		req.Header.Set("X-Auth-Token", token)
		resp, err := httpClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			return false
		}
		defer resp.Body.Close()
		var data api.RESTScanStatusData
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			return false
		}
		return data.Status != nil && data.Status.CVEDBVersion != ""
	}, assessTimeout, retryInterval, "scanner CVEDB version not populated in /v1/scan/status after %s", assessTimeout)

	return ctx
}

func getScannerWorkloadScanFeature() types.Feature {
	return features.New("NeuVector Workload Scan").
		Setup(setupSharedK8sClient).
		Setup(setupAPIEndpoint).
		Setup(setupScanWorkloadNamespace).
		Setup(deployScanTestWorkload).
		Setup(setupAuthToken).
		Assess("nginx workload is discovered by NeuVector", assessNginxWorkloadDiscovered).
		Assess("workload scan is triggered", assessWorkloadScanTriggered).
		Assess("workload scan completes with debian base OS", assessWorkloadScanFinished).
		Teardown(teardownScanTestWorkload).
		Teardown(teardownScanWorkloadNamespace).
		Feature()
}

func setupScanWorkloadNamespace(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	client := getK8sClient(ctx)
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: scanWorkloadNamespace},
	}
	err := client.Resources().Create(ctx, ns)
	require.NoError(t, err, "create workload namespace %s", scanWorkloadNamespace)
	return ctx
}

func deployScanTestWorkload(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	client := getK8sClient(ctx)
	replicas := int32(1)
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      scanWorkloadDeployName,
			Namespace: scanWorkloadNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": scanWorkloadDeployName},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": scanWorkloadDeployName},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "nginx", Image: "nginx:stable"},
					},
				},
			},
		},
	}
	err := client.Resources().Create(ctx, deploy)
	require.NoError(t, err, "create nginx deployment in %s", scanWorkloadNamespace)
	return ctx
}

func teardownScanTestWorkload(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	client := getK8sClient(ctx)
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: scanWorkloadDeployName, Namespace: scanWorkloadNamespace},
	}
	if err := client.Resources().Delete(ctx, deploy); err != nil {
		t.Logf("warning: failed to delete deployment %s/%s: %v", scanWorkloadNamespace, scanWorkloadDeployName, err)
	}
	return ctx
}

func teardownScanWorkloadNamespace(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	client := getK8sClient(ctx)
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: scanWorkloadNamespace},
	}
	if err := client.Resources().Delete(ctx, ns); err != nil {
		t.Logf("warning: failed to delete namespace %s: %v", scanWorkloadNamespace, err)
	}
	return ctx
}

func assessNginxWorkloadDiscovered(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	workloadID := findWorkloadInNVAPI(ctx, t, scanWorkloadNamespace, scanWorkloadServiceGroup, scanWorkloadDeployName)
	return storeWorkloadID(ctx, workloadID)
}

func assessWorkloadScanTriggered(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	httpClient := newNVHTTPClient()
	id := getWorkloadID(ctx)

	require.Eventually(t, func() bool {
		url := fmt.Sprintf("%s/v1/scan/workload/%s", endpoint, id)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
		if err != nil {
			return false
		}
		req.Header.Set("X-Auth-Token", token)
		resp, err := httpClient.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, assessTimeout, retryInterval, "POST /v1/scan/workload/%s did not return 200 after %s", id, assessTimeout)

	return ctx
}

func assessWorkloadScanFinished(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	httpClient := newNVHTTPClient()
	id := getWorkloadID(ctx)

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
			if w.WlBrief.ID != id {
				continue
			}
			s := w.WlSecurity.ScanSummary
			return s != nil && s.Status == "finished" && strings.HasPrefix(s.BaseOS, "debian")
		}
		return false
	}, assessTimeout, retryInterval,
		"workload %s scan not finished with debian base OS in /v2/workload after %s", id, assessTimeout)

	return ctx
}

package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	api "github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

const (
	workloadNamespace  = "neuvector-e2e-workload"
	workloadDeployName = "nginx"
	// NeuVector forms service groups as "nv.<app-label>.<namespace>"
	workloadServiceGroup = "nv." + workloadDeployName + "." + workloadNamespace
	// /v1/service and /v1/service/config expect the name without the "nv." prefix
	workloadServiceName = workloadDeployName + "." + workloadNamespace

	retryInterval = 10 * time.Second
)

func getProcessProfileFeature() types.Feature {
	return features.New("NeuVector Process Profile - Workload Visibility").
		Setup(setupSharedK8sClient).
		Setup(setupAPIEndpoint).
		Setup(setupWorkloadNamespace).
		Setup(deployTestWorkload).
		Setup(setupAuthToken).
		Assess("workload is visible in NeuVector API with correct service group", assessWorkloadInNVAPI).
		Assess("group is learned with nginx container member", assessGroupLearnedWithMember).
		Assess("process profile contains nginx entry", assessProcessProfileHasNginx).
		Assess("service exists in Discover mode",
			assessServiceHasState(workloadServiceName, serviceStateExpectation{ProfileMode: share.PolicyModeLearn})).
		Assess("PATCH service ProfileMode to Monitor",
			assessPatchServiceConfig(serviceBatchPatch{
				Services:    []string{workloadServiceName},
				ProfileMode: share.PolicyModeEvaluate,
			})).
		Assess("service ProfileMode is now Monitor",
			assessServiceHasState(workloadServiceName, serviceStateExpectation{ProfileMode: share.PolicyModeEvaluate})).
		Assess("exec unapproved bash in nginx pod", execBashInNginxPod).
		Assess("security event reports bash as incident", assessSecurityEventHasBashIncident).
		Teardown(teardownTestWorkload).
		Teardown(teardownWorkloadNamespace).
		Feature()
}

func setupWorkloadNamespace(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	client := getK8sClient(ctx)
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: workloadNamespace},
	}
	err := client.Resources().Create(ctx, ns)
	require.NoError(t, err, "create workload namespace %s", workloadNamespace)
	return ctx
}

func deployTestWorkload(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	client := getK8sClient(ctx)
	replicas := int32(1)
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      workloadDeployName,
			Namespace: workloadNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": workloadDeployName},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": workloadDeployName},
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
	require.NoError(t, err, "create nginx deployment in %s", workloadNamespace)
	return ctx
}

func assessWorkloadInNVAPI(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	findWorkloadInNVAPI(ctx, t, workloadNamespace, workloadServiceGroup, "")
	return ctx
}

func teardownTestWorkload(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	client := getK8sClient(ctx)
	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: workloadDeployName, Namespace: workloadNamespace},
	}
	if err := client.Resources().Delete(ctx, deploy); err != nil {
		t.Logf("warning: failed to delete deployment %s/%s: %v", workloadNamespace, workloadDeployName, err)
	}
	return ctx
}

func teardownWorkloadNamespace(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	client := getK8sClient(ctx)
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: workloadNamespace},
	}
	if err := client.Resources().Delete(ctx, ns); err != nil {
		t.Logf("warning: failed to delete namespace %s: %v", workloadNamespace, err)
	}
	return ctx
}

func assessGroupLearnedWithMember(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	httpClient := newNVHTTPClient()

	require.Eventually(t, func() bool {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v1/group", nil)
		if err != nil {
			return false
		}
		req.Header.Set("X-Auth-Token", token)
		resp, err := httpClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			return false
		}
		defer resp.Body.Close()
		var data api.RESTGroupsData
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			return false
		}
		for _, g := range data.Groups {
			if g.Name != workloadServiceGroup {
				continue
			}
			for _, m := range g.Members {
				if m.DisplayName == workloadDeployName {
					return true
				}
			}
		}
		return false
	}, assessTimeout, retryInterval,
		"group %q with member display_name=%q not found in /v1/group",
		workloadServiceGroup, workloadDeployName)

	return ctx
}

func execBashInNginxPod(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	// In Monitor mode NeuVector allows the process to run but generates an alert
	// incident. Tolerate a non-zero exit in case the container lacks bash or
	// the runtime returns an error for any other reason.
	tryExecCommandInPod(ctx, t,
		workloadNamespace,
		"app="+workloadDeployName,
		"nginx",
		[]string{"/usr/bin/bash", "-c", "sleep 5"},
	)
	return ctx
}

func assessSecurityEventHasBashIncident(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	httpClient := newNVHTTPClient()

	const bashPath = "/usr/bin/bash"

	require.Eventually(t, func() bool {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v1/log/security", nil)
		if err != nil {
			return false
		}
		req.Header.Set("X-Auth-Token", token)
		resp, err := httpClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			return false
		}
		defer resp.Body.Close()
		var data api.RESTSecurityData
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			return false
		}
		for _, incident := range data.Incidents {
			if incident.ProcPath == bashPath && incident.WorkloadService == workloadServiceName {
				return true
			}
		}
		return false
	}, assessTimeout, retryInterval,
		"security incident with proc_path=%q and workload_service=%q not found in /v1/log/security",
		bashPath, workloadServiceName)

	return ctx
}

func assessProcessProfileHasNginx(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	httpClient := newNVHTTPClient()

	const (
		expectedProcessName = "nginx"
		expectedProcessPath = "/usr/sbin/nginx"
	)

	require.Eventually(t, func() bool {
		url := fmt.Sprintf("%s/v1/process_profile/%s", endpoint, workloadServiceGroup)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return false
		}
		req.Header.Set("X-Auth-Token", token)
		resp, err := httpClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			return false
		}
		defer resp.Body.Close()
		var data api.RESTProcessProfileData
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			return false
		}
		if data.Profile == nil {
			return false
		}
		for _, p := range data.Profile.ProcessList {
			if p.Name == expectedProcessName && p.Path == expectedProcessPath {
				return true
			}
		}
		return false
	}, assessTimeout, retryInterval,
		"process profile for %q missing entry name=%q path=%q in /v1/process_profile/:name",
		workloadServiceGroup, expectedProcessName, expectedProcessPath)

	return ctx
}

// serviceStateExpectation holds the service fields to assert on GET /v1/service/:name.
// Any field left as "" is skipped during the check.
type serviceStateExpectation struct {
	ProfileMode     string
	PolicyMode      string
	BaselineProfile string
}

// assessServiceHasState returns an assess function that polls GET /v1/service/{serviceName}
// until all non-empty fields in want match the response. Reusable for any service name and
// any combination of ProfileMode, PolicyMode, and BaselineProfile.
func assessServiceHasState(serviceName string, want serviceStateExpectation) func(context.Context, *testing.T, *envconf.Config) context.Context {
	return func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
		t.Helper()
		endpoint := getAPIEndpoint(ctx)
		token := getNVToken(ctx)
		httpClient := newNVHTTPClient()

		require.Eventually(t, func() bool {
			url := fmt.Sprintf("%s/v1/service/%s", endpoint, serviceName)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return false
			}
			req.Header.Set("X-Auth-Token", token)
			resp, err := httpClient.Do(req)
			if err != nil || resp.StatusCode != http.StatusOK {
				return false
			}
			defer resp.Body.Close()
			var data api.RESTServiceData
			if err := json.NewDecoder(resp.Body).Decode(&data); err != nil || data.Service == nil {
				return false
			}
			svc := data.Service
			if want.ProfileMode != "" && svc.ProfileMode != want.ProfileMode {
				return false
			}
			if want.PolicyMode != "" && svc.PolicyMode != want.PolicyMode {
				return false
			}
			if want.BaselineProfile != "" && svc.BaselineProfile != want.BaselineProfile {
				return false
			}
			return true
		}, assessTimeout, retryInterval,
			"service %q did not reach expected state %+v within %s",
			serviceName, want, assessTimeout)

		return ctx
	}
}

// serviceBatchPatch holds the fields to update via PATCH /v1/service/config.
// Any field left as "" is omitted from the request body (sent as nil pointer).
type serviceBatchPatch struct {
	Services        []string
	PolicyMode      string
	ProfileMode     string
	BaselineProfile string
}

// assessPatchServiceConfig returns an assess function that sends a single PATCH /v1/service/config
// request and asserts HTTP 200. Reusable for any combination of services and mode fields.
func assessPatchServiceConfig(patch serviceBatchPatch) func(context.Context, *testing.T, *envconf.Config) context.Context {
	return func(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
		t.Helper()
		endpoint := getAPIEndpoint(ctx)
		token := getNVToken(ctx)
		httpClient := newNVHTTPClient()

		cfg := &api.RESTServiceBatchConfig{Services: patch.Services}
		if patch.PolicyMode != "" {
			cfg.PolicyMode = &patch.PolicyMode
		}
		if patch.ProfileMode != "" {
			cfg.ProfileMode = &patch.ProfileMode
		}
		if patch.BaselineProfile != "" {
			cfg.BaselineProfile = &patch.BaselineProfile
		}

		body, err := json.Marshal(api.RESTServiceBatchConfigData{Config: cfg})
		require.NoError(t, err)

		req, err := http.NewRequestWithContext(ctx, http.MethodPatch,
			endpoint+"/v1/service/config", bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("X-Auth-Token", token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode,
			"PATCH /v1/service/config for services %v failed", patch.Services)

		return ctx
	}
}

package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	api "github.com/neuvector/neuvector/controller/api"
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

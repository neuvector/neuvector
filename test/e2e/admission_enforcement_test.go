package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	api "github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

type nvAdmEnforceDenyIDKey struct{}
type nvAdmEnforceExceptIDKey struct{}

const (
	enforceTestNamespace = "default"
	enforceBlockedPod    = "test-enforce-blocked"
	enforceAllowedPod    = "test-enforce-allowed"

	// nvAdmCtrlValidateType matches admission.NvAdmValidateType used by the server.
	nvAdmCtrlValidateType = "validate"
)

func getAdmissionEnforcementFeature() types.Feature {
	return features.New("Admission Control Webhook Enforcement").
		Setup(setupSharedK8sClient).
		Setup(setupAPIEndpoint).
		Setup(setupAuthToken).
		Assess("enable admission control in protect mode", assessEnableAdmCtrlProtect).
		Assess("webhook is registered in cluster", assessWebhookRegistered).
		Assess("create deny rule for enforcement test", assessCreateEnforceDenyRule).
		Assess("pod with blocked image is rejected by webhook", assessPodRejectedByWebhook).
		Assess("create exception rule overriding the deny rule", assessCreateEnforceExceptRule).
		Assess("pod is admitted after exception rule is active", assessPodAllowedByExceptionWebhook).
		Teardown(teardownEnforcementPods).
		Teardown(teardownEnforcementRules).
		Teardown(teardownDisableAdmissionControl).
		Feature()
}

func assessWebhookRegistered(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	httpClient := newNVHTTPClient()

	require.Eventually(t, func() bool {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet,
			endpoint+"/v1/admission/state", nil)
		if err != nil {
			return false
		}
		req.Header.Set("X-Auth-Token", token)
		resp, err := httpClient.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return false
		}
		var data api.RESTAdmissionConfigData
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil || data.State == nil {
			return false
		}
		return data.State.CtrlStates != nil && data.State.CtrlStates[nvAdmCtrlValidateType]
	}, assessTimeout, retryInterval,
		"admission webhook ctrl_states.validate did not become enabled within %s", assessTimeout)

	return ctx
}

func assessCreateEnforceDenyRule(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	httpClient := newNVHTTPClient()

	category := "k8s"
	body, err := json.Marshal(api.RESTAdmissionRuleConfigData{
		Config: &api.RESTAdmissionRuleConfig{
			ID:       0,
			Category: &category,
			Comment:  strPtr("e2e enforcement deny rule"),
			Criteria: []*api.RESTAdmRuleCriterion{
				{
					Name:  share.CriteriaKeyImage,
					Op:    share.CriteriaOpContainsAny,
					Value: admAssessCriterionValue,
				},
			},
			CfgType:  api.CfgTypeUserCreated,
			RuleType: api.ValidatingDenyRuleType,
			RuleMode: strPtr(share.AdmCtrlModeProtect),
		},
	})
	require.NoError(t, err, "marshal create enforcement deny rule")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		endpoint+"/v1/admission/rule", bytes.NewReader(body))
	require.NoError(t, err, "build POST /v1/admission/rule request")
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	require.NoError(t, err, "POST /v1/admission/rule (enforcement deny)")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"POST /v1/admission/rule (enforcement deny) returned unexpected status")

	var data api.RESTAdmissionRuleData
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&data), "decode create enforcement deny rule response")
	require.NotNil(t, data.Rule, "created enforcement deny rule is nil in response")
	require.NotZero(t, data.Rule.ID, "created enforcement deny rule has zero ID")

	return context.WithValue(ctx, nvAdmEnforceDenyIDKey{}, data.Rule.ID)
}

func getEnforceDenyRuleID(ctx context.Context) uint32 {
	id, _ := ctx.Value(nvAdmEnforceDenyIDKey{}).(uint32)
	return id
}

func getEnforceExceptRuleID(ctx context.Context) uint32 {
	id, _ := ctx.Value(nvAdmEnforceExceptIDKey{}).(uint32)
	return id
}

// assessPodRejectedByWebhook waits until the deny rule is propagated (via assessment
// endpoint) then verifies that a real pod creation attempt is rejected by the webhook.
func assessPodRejectedByWebhook(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	denyID := getEnforceDenyRuleID(ctx)
	require.NotZero(t, denyID, "enforce deny rule ID must be set by previous step")

	// Wait for the deny rule to be active in the assessment engine before touching the webhook.
	require.Eventually(t, func() bool {
		results, err := postAssessmentYAML(ctx, endpoint, token, admAssessBlockedPodYAML)
		if err != nil || results == nil || len(results.Results) == 0 {
			return false
		}
		r := results.Results[0]
		if r.Allowed {
			return false
		}
		for _, mr := range r.MatchedRules {
			if mr.ID == denyID {
				return true
			}
		}
		return false
	}, assessTimeout, retryInterval,
		"deny rule ID %d not active in assessment engine within %s", denyID, assessTimeout)

	// Attempt real pod creation — the webhook must reject it.
	k8sClient := getK8sClient(ctx)
	pod := blockedTestPod(enforceBlockedPod, enforceTestNamespace)
	err := k8sClient.Resources(enforceTestNamespace).Create(ctx, pod)
	require.Error(t, err, "pod creation should be rejected by admission control webhook")
	require.Contains(t, err.Error(), "denied the request",
		"expected NeuVector admission webhook denial, got: %v", err)

	return ctx
}

func assessCreateEnforceExceptRule(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	httpClient := newNVHTTPClient()

	category := "k8s"
	body, err := json.Marshal(api.RESTAdmissionRuleConfigData{
		Config: &api.RESTAdmissionRuleConfig{
			ID:       0,
			Category: &category,
			Comment:  strPtr("e2e enforcement exception rule"),
			Criteria: []*api.RESTAdmRuleCriterion{
				{
					Name:  share.CriteriaKeyImage,
					Op:    share.CriteriaOpContainsAny,
					Value: admAssessCriterionValue,
				},
			},
			CfgType:  api.CfgTypeUserCreated,
			RuleType: api.ValidatingExceptRuleType,
		},
	})
	require.NoError(t, err, "marshal create enforcement exception rule")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		endpoint+"/v1/admission/rule", bytes.NewReader(body))
	require.NoError(t, err, "build POST /v1/admission/rule (exception) request")
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	require.NoError(t, err, "POST /v1/admission/rule (enforcement exception)")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"POST /v1/admission/rule (enforcement exception) returned unexpected status")

	var data api.RESTAdmissionRuleData
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&data), "decode create exception rule response")
	require.NotNil(t, data.Rule, "created enforcement exception rule is nil in response")
	require.NotZero(t, data.Rule.ID, "created enforcement exception rule has zero ID")

	return context.WithValue(ctx, nvAdmEnforceExceptIDKey{}, data.Rule.ID)
}

// assessPodAllowedByExceptionWebhook waits until the exception rule is active (via
// assessment endpoint) then verifies that a real pod creation is now admitted.
func assessPodAllowedByExceptionWebhook(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	exceptID := getEnforceExceptRuleID(ctx)
	require.NotZero(t, exceptID, "enforce exception rule ID must be set by previous step")

	// Wait for the exception rule to be active in the assessment engine.
	require.Eventually(t, func() bool {
		results, err := postAssessmentYAML(ctx, endpoint, token, admAssessBlockedPodYAML)
		if err != nil || results == nil || len(results.Results) == 0 {
			return false
		}
		r := results.Results[0]
		if !r.Allowed {
			return false
		}
		for _, mr := range r.MatchedRules {
			if mr.ID == exceptID {
				return true
			}
		}
		return false
	}, assessTimeout, retryInterval,
		"exception rule ID %d not active in assessment engine within %s", exceptID, assessTimeout)

	// Attempt real pod creation — the exception rule should allow it through.
	k8sClient := getK8sClient(ctx)
	pod := blockedTestPod(enforceAllowedPod, enforceTestNamespace)
	err := k8sClient.Resources(enforceTestNamespace).Create(ctx, pod)
	require.NoError(t, err, "pod creation should be admitted when exception rule is active")

	return ctx
}

// blockedTestPod returns a minimal pod spec using the blocked image for admission control testing.
func blockedTestPod(name, namespace string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:            "main",
					Image:           "bad-image:latest",
					ImagePullPolicy: corev1.PullNever,
				},
			},
			RestartPolicy: corev1.RestartPolicyNever,
		},
	}
}

func teardownEnforcementPods(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	k8sClient := getK8sClient(ctx)

	for _, name := range []string{enforceBlockedPod, enforceAllowedPod} {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: enforceTestNamespace,
			},
		}
		if err := k8sClient.Resources(enforceTestNamespace).Delete(ctx, pod); err != nil {
			if !apierrors.IsNotFound(err) {
				t.Logf("warning: delete pod %s: %v", name, err)
			}
		}
	}
	return ctx
}

func teardownEnforcementRules(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	httpClient := newNVHTTPClient()

	for _, id := range []uint32{getEnforceDenyRuleID(ctx), getEnforceExceptRuleID(ctx)} {
		if id == 0 {
			continue
		}
		url := fmt.Sprintf("%s/v1/admission/rule/%d", endpoint, id)
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
		if err != nil {
			t.Logf("warning: build DELETE /v1/admission/rule/%d: %v", id, err)
			continue
		}
		req.Header.Set("X-Auth-Token", token)
		resp, err := httpClient.Do(req)
		if err != nil {
			t.Logf("warning: DELETE /v1/admission/rule/%d: %v", id, err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Logf("warning: DELETE /v1/admission/rule/%d returned %d", id, resp.StatusCode)
		}
	}
	return ctx
}

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
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

type nvAdmAssessDenyIDKey struct{}
type nvAdmAssessExceptIDKey struct{}

// admAssessCriterionValue is the image criterion value used in the deny/except rules.
// NeuVector normalizes "bad-image:latest" to ImageRepo="library/bad-image" at match
// time (Docker Hub single-segment images get the "library/" prefix), so the criterion
// must include that prefix. Using a wildcard tag avoids a brittle exact-tag dependency.
const admAssessCriterionValue = "library/bad-image:*"

const admAssessBlockedPodYAML = `apiVersion: v1
kind: Pod
metadata:
  name: test-assess-blocked
  namespace: default
spec:
  containers:
  - name: main
    image: bad-image:latest
`

const admAssessCleanPodYAML = `apiVersion: v1
kind: Pod
metadata:
  name: test-assess-clean
  namespace: default
spec:
  containers:
  - name: main
    image: nginx:stable
`

func getAdmissionAssessmentFeature() types.Feature {
	return features.New("Admission Control Configuration Assessment").
		Setup(setupSharedK8sClient).
		Setup(setupAPIEndpoint).
		Setup(setupAuthToken).
		Assess("enable admission control in protect mode", assessEnableAdmCtrlProtect).
		Assess("create deny rule for assessment image", assessCreateAssessDenyRule).
		Assess("matching pod is denied by assessment", assessBlockedPodIsDenied).
		Assess("create exception rule overriding the deny rule", assessCreateAssessExceptRule).
		Assess("pod is now allowed with exception rule active", assessBlockedPodIsAllowedByException).
		Assess("non-matching pod is allowed by default", assessCleanPodIsAllowed).
		Teardown(teardownAssessmentRules).
		Teardown(teardownDisableAdmissionControl).
		Feature()
}

func assessEnableAdmCtrlProtect(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	httpClient := newNVHTTPClient()

	body, err := json.Marshal(api.RESTAdmissionConfigData{
		State: &api.RESTAdmissionState{
			Enable:        boolPtr(true),
			Mode:          strPtr(share.AdmCtrlModeProtect),
			DefaultAction: strPtr("allow"),
		},
	})
	require.NoError(t, err, "marshal admission state patch")

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch,
		endpoint+"/v1/admission/state", bytes.NewReader(body))
	require.NoError(t, err, "build PATCH /v1/admission/state request")
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	require.NoError(t, err, "PATCH /v1/admission/state")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"PATCH /v1/admission/state to enable in protect mode returned unexpected status")

	require.Eventually(t, func() bool {
		req2, err := http.NewRequestWithContext(ctx, http.MethodGet,
			endpoint+"/v1/admission/state", nil)
		if err != nil {
			return false
		}
		req2.Header.Set("X-Auth-Token", token)
		resp2, err := httpClient.Do(req2)
		if err != nil || resp2.StatusCode != http.StatusOK {
			return false
		}
		defer resp2.Body.Close()
		var data api.RESTAdmissionConfigData
		if err := json.NewDecoder(resp2.Body).Decode(&data); err != nil || data.State == nil {
			return false
		}
		return data.State.Enable != nil && *data.State.Enable &&
			data.State.Mode != nil && *data.State.Mode == share.AdmCtrlModeProtect
	}, assessTimeout, retryInterval,
		"admission state did not reflect enable=true mode=protect within %s", assessTimeout)

	return ctx
}

func assessCreateAssessDenyRule(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	httpClient := newNVHTTPClient()

	category := "k8s"
	body, err := json.Marshal(api.RESTAdmissionRuleConfigData{
		Config: &api.RESTAdmissionRuleConfig{
			ID:       0,
			Category: &category,
			Comment:  strPtr("e2e assessment deny rule"),
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
	require.NoError(t, err, "marshal create assessment deny rule")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		endpoint+"/v1/admission/rule", bytes.NewReader(body))
	require.NoError(t, err, "build POST /v1/admission/rule request")
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	require.NoError(t, err, "POST /v1/admission/rule (deny)")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "POST /v1/admission/rule (deny) returned unexpected status")

	var data api.RESTAdmissionRuleData
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&data), "decode create deny rule response")
	require.NotNil(t, data.Rule, "created deny rule is nil in response")
	require.NotZero(t, data.Rule.ID, "created deny rule has zero ID")

	return context.WithValue(ctx, nvAdmAssessDenyIDKey{}, data.Rule.ID)
}

func getAssessDenyRuleID(ctx context.Context) uint32 {
	id, _ := ctx.Value(nvAdmAssessDenyIDKey{}).(uint32)
	return id
}

func getAssessExceptRuleID(ctx context.Context) uint32 {
	id, _ := ctx.Value(nvAdmAssessExceptIDKey{}).(uint32)
	return id
}

// postAssessmentYAML submits raw YAML to POST /v1/assess/admission/rule and returns the results.
func postAssessmentYAML(ctx context.Context, endpoint, token, podYAML string) (*api.RESTAdmCtrlRulesTestResults, error) {
	httpClient := newNVHTTPClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		endpoint+"/v1/assess/admission/rule", bytes.NewReader([]byte(podYAML)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/yaml")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("POST /v1/assess/admission/rule returned %d", resp.StatusCode)
	}

	var results api.RESTAdmCtrlRulesTestResults
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return nil, err
	}
	return &results, nil
}

func assessBlockedPodIsDenied(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	denyID := getAssessDenyRuleID(ctx)
	require.NotZero(t, denyID, "deny rule ID must be set by previous step")

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
		"assessment did not return allowed=false with deny rule ID %d within %s", denyID, assessTimeout)

	return ctx
}

func assessCreateAssessExceptRule(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	httpClient := newNVHTTPClient()

	category := "k8s"
	body, err := json.Marshal(api.RESTAdmissionRuleConfigData{
		Config: &api.RESTAdmissionRuleConfig{
			ID:       0,
			Category: &category,
			Comment:  strPtr("e2e assessment exception rule"),
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
	require.NoError(t, err, "marshal create exception rule")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		endpoint+"/v1/admission/rule", bytes.NewReader(body))
	require.NoError(t, err, "build POST /v1/admission/rule (exception) request")
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	require.NoError(t, err, "POST /v1/admission/rule (exception)")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"POST /v1/admission/rule (exception) returned unexpected status")

	var data api.RESTAdmissionRuleData
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&data), "decode create exception rule response")
	require.NotNil(t, data.Rule, "created exception rule is nil in response")
	require.NotZero(t, data.Rule.ID, "created exception rule has zero ID")

	return context.WithValue(ctx, nvAdmAssessExceptIDKey{}, data.Rule.ID)
}

func assessBlockedPodIsAllowedByException(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	exceptID := getAssessExceptRuleID(ctx)
	require.NotZero(t, exceptID, "exception rule ID must be set by previous step")

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
		"assessment did not return allowed=true with exception rule ID %d within %s", exceptID, assessTimeout)

	return ctx
}

func assessCleanPodIsAllowed(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	denyID := getAssessDenyRuleID(ctx)

	results, err := postAssessmentYAML(ctx, endpoint, token, admAssessCleanPodYAML)
	require.NoError(t, err, "POST /v1/assess/admission/rule for clean pod")
	require.NotNil(t, results, "assessment results are nil for clean pod")
	require.NotEmpty(t, results.Results, "assessment returned no results for clean pod")

	r := results.Results[0]
	require.True(t, r.Allowed, "pod with non-matching image should be allowed by default")

	for _, mr := range r.MatchedRules {
		require.NotEqual(t, denyID, mr.ID,
			"deny rule ID %d should not match a pod using image %q", denyID, admAssessCriterionValue)
	}

	return ctx
}

func teardownAssessmentRules(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	httpClient := newNVHTTPClient()

	for _, id := range []uint32{getAssessDenyRuleID(ctx), getAssessExceptRuleID(ctx)} {
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

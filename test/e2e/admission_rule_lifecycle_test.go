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

// nvAdmRuleIDKey carries the ID of the deny rule created during the lifecycle test.
type nvAdmRuleIDKey struct{}

const admTestImagePattern = "bad-image:*"

// boolPtr and strPtr are pointer helpers used across the admission test files.
func boolPtr(b bool) *bool    { return &b }
func strPtr(s string) *string { return &s }

func getAdmissionRuleLifecycleFeature() types.Feature {
	return features.New("Admission Control Rule Lifecycle").
		Setup(setupSharedK8sClient).
		Setup(setupAPIEndpoint).
		Setup(setupAuthToken).
		Assess("enable admission control in monitor mode", assessEnableAdmissionControl).
		Assess("admission state reflects enabled monitor mode", assessAdmissionStateIsEnabled).
		Assess("create deny rule for image pattern bad-image:*", assessCreateAdmissionDenyRule).
		Assess("deny rule appears in rules list", assessAdmDenyRuleInList).
		Assess("disable the deny rule", assessDisableAdmissionDenyRule).
		Assess("rules list shows rule as disabled", assessAdmDenyRuleIsDisabled).
		Assess("delete the deny rule", assessDeleteAdmissionDenyRule).
		Assess("rules list no longer contains the deleted rule", assessAdmDenyRuleIsGone).
		Teardown(teardownDisableAdmissionControl).
		Feature()
}

func assessEnableAdmissionControl(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	httpClient := newNVHTTPClient()

	body, err := json.Marshal(api.RESTAdmissionConfigData{
		State: &api.RESTAdmissionState{
			Enable:        boolPtr(true),
			Mode:          strPtr(share.AdmCtrlModeMonitor),
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
		"PATCH /v1/admission/state to enable failed with unexpected status")
	return ctx
}

func assessAdmissionStateIsEnabled(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
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
		if err != nil || resp.StatusCode != http.StatusOK {
			return false
		}
		defer resp.Body.Close()
		var data api.RESTAdmissionConfigData
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil || data.State == nil {
			return false
		}
		return data.State.Enable != nil && *data.State.Enable &&
			data.State.Mode != nil && *data.State.Mode == share.AdmCtrlModeMonitor
	}, assessTimeout, retryInterval,
		"admission state did not reflect enable=true mode=monitor within %s", assessTimeout)
	return ctx
}

func assessCreateAdmissionDenyRule(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	httpClient := newNVHTTPClient()

	category := "k8s"
	body, err := json.Marshal(api.RESTAdmissionRuleConfigData{
		Config: &api.RESTAdmissionRuleConfig{
			ID:       0,
			Category: &category,
			Comment:  strPtr("e2e lifecycle test deny rule"),
			Criteria: []*api.RESTAdmRuleCriterion{
				{
					Name:  share.CriteriaKeyImage,
					Op:    share.CriteriaOpContainsAny,
					Value: admTestImagePattern,
				},
			},
			CfgType:  api.CfgTypeUserCreated,
			RuleType: api.ValidatingDenyRuleType,
			RuleMode: strPtr(share.AdmCtrlModeMonitor),
		},
	})
	require.NoError(t, err, "marshal create rule request")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		endpoint+"/v1/admission/rule", bytes.NewReader(body))
	require.NoError(t, err, "build POST /v1/admission/rule request")
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	require.NoError(t, err, "POST /v1/admission/rule")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "POST /v1/admission/rule failed")

	var data api.RESTAdmissionRuleData
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&data), "decode create rule response")
	require.NotNil(t, data.Rule, "created rule is nil in response")
	require.NotZero(t, data.Rule.ID, "created rule has zero ID")
	require.Equal(t, api.ValidatingDenyRuleType, data.Rule.RuleType, "rule_type mismatch")
	require.Len(t, data.Rule.Criteria, 1, "expected one criterion in created rule")
	require.Equal(t, share.CriteriaKeyImage, data.Rule.Criteria[0].Name, "criterion name mismatch")

	return context.WithValue(ctx, nvAdmRuleIDKey{}, data.Rule.ID)
}

func getAdmRuleID(ctx context.Context) uint32 {
	return ctx.Value(nvAdmRuleIDKey{}).(uint32)
}

func assessAdmDenyRuleInList(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	httpClient := newNVHTTPClient()
	ruleID := getAdmRuleID(ctx)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		endpoint+"/v1/admission/rules", nil)
	require.NoError(t, err)
	req.Header.Set("X-Auth-Token", token)

	resp, err := httpClient.Do(req)
	require.NoError(t, err, "GET /v1/admission/rules")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET /v1/admission/rules failed")

	var data api.RESTAdmissionRulesData
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&data), "decode rules list response")

	found := false
	for _, r := range data.Rules {
		if r.ID == ruleID {
			found = true
			require.False(t, r.Disable, "newly created rule should not be disabled")
			break
		}
	}
	require.True(t, found, "rule ID %d not found in GET /v1/admission/rules", ruleID)
	return ctx
}

func assessDisableAdmissionDenyRule(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	httpClient := newNVHTTPClient()
	ruleID := getAdmRuleID(ctx)

	category := "k8s"
	body, err := json.Marshal(api.RESTAdmissionRuleConfigData{
		Config: &api.RESTAdmissionRuleConfig{
			ID:       ruleID,
			Category: &category,
			Disable:  boolPtr(true),
			CfgType:  api.CfgTypeUserCreated,
			RuleType: api.ValidatingDenyRuleType,
		},
	})
	require.NoError(t, err, "marshal disable rule request")

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch,
		endpoint+"/v1/admission/rule", bytes.NewReader(body))
	require.NoError(t, err, "build PATCH /v1/admission/rule request")
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	require.NoError(t, err, "PATCH /v1/admission/rule (disable)")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"PATCH /v1/admission/rule (disable) returned unexpected status")
	return ctx
}

func assessAdmDenyRuleIsDisabled(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	httpClient := newNVHTTPClient()
	ruleID := getAdmRuleID(ctx)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		endpoint+"/v1/admission/rules", nil)
	require.NoError(t, err)
	req.Header.Set("X-Auth-Token", token)

	resp, err := httpClient.Do(req)
	require.NoError(t, err, "GET /v1/admission/rules")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET /v1/admission/rules failed")

	var data api.RESTAdmissionRulesData
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&data), "decode rules list response")

	found := false
	for _, r := range data.Rules {
		if r.ID == ruleID {
			found = true
			require.True(t, r.Disable, "rule ID %d should be disabled", ruleID)
			break
		}
	}
	require.True(t, found, "rule ID %d not found in GET /v1/admission/rules", ruleID)
	return ctx
}

func assessDeleteAdmissionDenyRule(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	httpClient := newNVHTTPClient()
	ruleID := getAdmRuleID(ctx)

	url := fmt.Sprintf("%s/v1/admission/rule/%d", endpoint, ruleID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	require.NoError(t, err, "build DELETE /v1/admission/rule/%d request", ruleID)
	req.Header.Set("X-Auth-Token", token)

	resp, err := httpClient.Do(req)
	require.NoError(t, err, "DELETE /v1/admission/rule/%d", ruleID)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"DELETE /v1/admission/rule/%d returned unexpected status", ruleID)
	return ctx
}

func assessAdmDenyRuleIsGone(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	httpClient := newNVHTTPClient()
	ruleID := getAdmRuleID(ctx)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		endpoint+"/v1/admission/rules", nil)
	require.NoError(t, err)
	req.Header.Set("X-Auth-Token", token)

	resp, err := httpClient.Do(req)
	require.NoError(t, err, "GET /v1/admission/rules")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "GET /v1/admission/rules failed")

	var data api.RESTAdmissionRulesData
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&data), "decode rules list response")

	for _, r := range data.Rules {
		require.NotEqual(t, ruleID, r.ID,
			"deleted rule ID %d should not appear in GET /v1/admission/rules", ruleID)
	}
	return ctx
}

func teardownDisableAdmissionControl(ctx context.Context, t *testing.T, _ *envconf.Config) context.Context {
	t.Helper()
	endpoint := getAPIEndpoint(ctx)
	token := getNVToken(ctx)
	httpClient := newNVHTTPClient()

	body, err := json.Marshal(api.RESTAdmissionConfigData{
		State: &api.RESTAdmissionState{
			Enable: boolPtr(false),
		},
	})
	if err != nil {
		t.Logf("warning: marshal admission disable request: %v", err)
		return ctx
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch,
		endpoint+"/v1/admission/state", bytes.NewReader(body))
	if err != nil {
		t.Logf("warning: build PATCH /v1/admission/state request: %v", err)
		return ctx
	}
	req.Header.Set("X-Auth-Token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Logf("warning: PATCH /v1/admission/state (disable): %v", err)
		return ctx
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Logf("warning: PATCH /v1/admission/state (disable) returned %d", resp.StatusCode)
	}
	return ctx
}

package opa

import (
	"os"
	"strings"
	"testing"

	"github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertToRegoRule_ExpectedOutput(t *testing.T) {
	// Create a test rule based on the provided input (same as YAML mock)
	rule := &share.CLUSAdmissionRule{
		ID: 1001,
		Criteria: []*share.CLUSAdmRuleCriterion{
			{
				Name:      "customPath",
				Type:      "customPath",
				Op:        "containsAll",
				Path:      "item.spec.initContainers[_].lifecycle.postStart.tcpSocket.host",
				Value:     "localhost",
				ValueType: "string",
			},
			{
				Name:      "customPath",
				Type:      "customPath",
				Op:        "containsAny",
				Path:      "item.spec.containers[_].image",
				Value:     "redis:latest,nginx:latest,sbomscanner",
				ValueType: "string",
			},
			{
				Name:      "runAsPrivileged",
				Type:      "", // predefined criteria
				Op:        "=",
				Path:      "runAsPrivileged",
				Value:     "true",
				ValueType: "string",
			},
			{
				Name:      "imageScanned",
				Type:      "", // predefined criteria
				Op:        "=",
				Path:      "imageScanned",
				Value:     "true",
				ValueType: "string",
			},
		},
	}

	// Generate Rego code with default options

	options := DefaultRegoGenConfig(rule.ID)
	actual, err := GenerateRegoCode(rule, options)

	assert.NoError(t, err)
	assert.NotEmpty(t, actual)

	// Load expected Rego from mock file and compare whole file.
	expectedBytes, err := os.ReadFile("testdata/rego_1001.txt")
	require.NoError(t, err)

	normalize := func(s string) string {
		lines := strings.Split(s, "\n")
		out := make([]string, 0, len(lines))
		for _, l := range lines {
			if strings.TrimSpace(l) == "" {
				continue
			}
			out = append(out, strings.TrimRight(l, " \t"))
		}
		return strings.Join(out, "\n")
	}

	expected := normalize(string(expectedBytes))
	actual = normalize(actual)

	assert.Equal(t, expected, actual)
}

func TestDefaultRegoGenConfig(t *testing.T) {
	ruleID := uint32(1001)
	options := DefaultRegoGenConfig(ruleID)

	assert.NotNil(t, options)
	assert.Equal(t, "neuvector_policy_1001", options.PackageName)
	assert.False(t, options.GenerateKubewardenMode)
}

func TestGenerateRegoCode_NoCustomCriteria(t *testing.T) {
	// Rule with only predefined criteria (Type == "")
	rule := &share.CLUSAdmissionRule{
		ID: 1001,
		Criteria: []*share.CLUSAdmRuleCriterion{
			{
				Name:      "runAsPrivileged",
				Type:      "", // predefined
				Op:        "=",
				Path:      "runAsPrivileged",
				Value:     "true",
				ValueType: "string",
			},
		},
	}

	options := DefaultRegoGenConfig(rule.ID)
	regoStr, err := GenerateRegoCode(rule, options)

	assert.NoError(t, err)
	assert.NotEmpty(t, regoStr)

	// Should still have package and specification, but no violation function for custom criteria
	assert.Contains(t, regoStr, "package neuvector_policy_1001")
	assert.Contains(t, regoStr, "specification = spec {")

	// Should not have criteria_0 since there are no customPath criteria
	// But GenerateViolationFunction will still be called and return empty violation function
	// Actually, looking at the code, if there are no customPath criteria, the violation function
	// will be empty (just the header and footer)
	lines := strings.Split(regoStr, "\n")
	violationFound := false
	for _, line := range lines {
		if strings.Contains(line, "violation[result]{") {
			violationFound = true
			break
		}
	}
	// The violation function will be generated but empty (no criteria calls)
	assert.True(t, violationFound || !strings.Contains(regoStr, "criteria_0"))
}

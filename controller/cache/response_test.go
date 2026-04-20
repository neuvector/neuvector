package cache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
)

func setupTestGroupCache(testWorkloadID string) {
	g := share.CLUSGroup{Name: api.AllContainerGroup, CfgType: share.UserCreated}
	groupCacheMap[api.AllContainerGroup] = &groupCache{
		group:               &g,
		usedByPolicy:        utils.NewSet(),
		usedByResponseRules: utils.NewSet(),
		members:             utils.NewSet(testWorkloadID),
	}
}

func cleanupTestPolicyGroupCache() {
	groupCacheMap = make(map[string]*groupCache)
	localResPolicyCache = resPolicyCacheType{
		ruleMap:      make(map[uint32]*share.CLUSResponseRule),
		ruleHeads:    make([]*share.CLUSRuleHead, 0),
		ruleOrderMap: make(map[uint32]int),
	}
}

func newEventRule(id uint32, evType, group string, conditions []share.CLUSEventCondition, actions []string) *share.CLUSResponseRule {
	rule := &share.CLUSResponseRule{
		ID:         id,
		Event:      evType,
		Group:      group,
		Conditions: conditions,
		Actions:    actions,
		CfgType:    share.UserCreated,
	}
	return rule
}

func buildResPolicyCache(rules []*share.CLUSResponseRule) resPolicyCacheType {
	resPolicyCache := resPolicyCacheType{
		ruleMap:      make(map[uint32]*share.CLUSResponseRule, len(rules)),
		ruleHeads:    make([]*share.CLUSRuleHead, len(rules)),
		ruleOrderMap: make(map[uint32]int, len(rules)),
	}
	for i, rule := range rules {
		resPolicyCache.ruleMap[rule.ID] = rule
		resPolicyCache.ruleHeads[i] = &share.CLUSRuleHead{ID: rule.ID, CfgType: share.UserCreated}
		resPolicyCache.ruleOrderMap[rule.ID] = i
	}
	return resPolicyCache
}

func newActivityDesc(activity, level, domain, testWorkloadID string) eventDesc {
	log := &api.Event{
		LogCommon: api.LogCommon{
			ClusterName:       "cluster-41",
			HostID:            "host-k8sworker41:GXTH:Z624:DIFT:72R6:OQXU:S7HD:2A6U:UZO5:HJU6:PWQC:BQSN:H2IR",
			HostName:          "host-k8sworker41",
			Level:             level,
			Name:              activity,
			ReportedAt:        "2026-03-11T13:20:39Z",
			ReportedTimeStamp: 1773235239,
			AgentID:           "b09358fe3dde086ff9a27fe78e19f598cdd2a70994620702fbcdec5192a035f8",
			AgentName:         "neuvector-enforcer-pod-4wq95",
		},
		Category:        "WORKLOAD",
		Msg:             activity,
		WorkloadDomain:  domain,
		WorkloadID:      testWorkloadID,
		WorkloadImage:   "rancher/mirrored-pause:3.6",
		WorkloadName:    "iperfserver-795d769cd9-wbxpq",
		WorkloadService: "iperfserver.demo",
	}
	return eventDesc{id: log.WorkloadID, event: share.EventActivity, name: log.Name, level: log.Level, arg: log}
}

func TestResponseRuleLookup(t *testing.T) {
	preTest()
	defer postTest()

	testWorkloadID := "bc40937a5ab126c1188a2e01f2a52833adfdc4b04f1d22134a4ca5967a64631d"
	testWorkloadDomain := "demo"

	setupTestGroupCache(testWorkloadID)
	defer cleanupTestPolicyGroupCache()

	t.Run("activity log matches one response rule by name", func(t *testing.T) {
		// Rule 10: matches Controller.Start (won't match)
		// Rule 9:  matches Container.Start but is disabled (won't match)
		// Rule 8:  matches Container.Start and is enabled (should match)
		actions := []string{share.EventActionSuppressLog}
		disabledRule := newEventRule(9, share.EventEvent, api.AllContainerGroup, []share.CLUSEventCondition{{CondType: share.EventCondTypeName, CondValue: api.EventNameContainerStart}}, actions)
		disabledRule.Disable = true

		localResPolicyCache = buildResPolicyCache([]*share.CLUSResponseRule{
			newEventRule(10, share.EventEvent, api.AllContainerGroup, []share.CLUSEventCondition{{CondType: share.EventCondTypeName, CondValue: api.EventNameControllerStart}}, actions),
			disabledRule,
			newEventRule(8, share.EventEvent, api.AllContainerGroup, []share.CLUSEventCondition{{CondType: share.EventCondTypeName, CondValue: api.EventNameContainerStart}}, actions),
		})

		desc := newActivityDesc(api.EventNameContainerStart, api.LogLevelINFO, testWorkloadDomain, testWorkloadID)
		matched := lookup(&desc)

		require.Len(t, matched, 1, "expected exactly one matched rule")
		assert.Equal(t, uint32(8), matched[0].id, "unexpected matched rule ID")
		assert.Len(t, matched[0].actions, 1, "expected exactly one action")
		assert.Equal(t, share.EventActionSuppressLog, matched[0].actions[0], "unexpected action")
	})

	t.Run("activity log matches 3 response rules, 2 by name and 1 by level", func(t *testing.T) {
		// Rule 10: matches Controller.Start (won't match)
		// Rule 9:  matches Container.Start but is disabled (won't match)
		// Rule 8:  matches Container.Start and is enabled (should match)
		// Rule 11: matches Info and is enabled (should match)
		// Rule 12: matches Container.Start and is enabled (should match)
		actions := []string{share.EventActionSuppressLog}
		disabledRule := newEventRule(9, share.EventEvent, api.AllContainerGroup, []share.CLUSEventCondition{{CondType: share.EventCondTypeName, CondValue: api.EventNameContainerStart}}, actions)
		disabledRule.Disable = true

		localResPolicyCache = buildResPolicyCache([]*share.CLUSResponseRule{
			newEventRule(10, share.EventEvent, api.AllContainerGroup, []share.CLUSEventCondition{{CondType: share.EventCondTypeName, CondValue: api.EventNameControllerStart}}, actions),
			disabledRule,
			newEventRule(8, share.EventEvent, api.AllContainerGroup, []share.CLUSEventCondition{{CondType: share.EventCondTypeName, CondValue: api.EventNameContainerStart}}, actions),
			newEventRule(11, share.EventEvent, api.AllContainerGroup, []share.CLUSEventCondition{{CondType: share.EventCondTypeLevel, CondValue: api.LogLevelINFO}}, actions),
			newEventRule(12, share.EventEvent, "", []share.CLUSEventCondition{{CondType: share.EventCondTypeName, CondValue: api.EventNameContainerStart}}, actions),
		})

		desc := newActivityDesc(api.EventNameContainerStart, api.LogLevelINFO, testWorkloadDomain, testWorkloadID)
		matched := lookup(&desc)

		require.Len(t, matched, 3, "expected 3 matched rules")
		assert.Equal(t, uint32(8), matched[0].id, "unexpected matched rule ID")
		assert.Equal(t, uint32(11), matched[1].id, "unexpected matched rule ID")
		assert.Equal(t, uint32(12), matched[2].id, "unexpected matched rule ID")
		for i := range 3 {
			assert.Len(t, matched[i].actions, 1, "expected exactly one action")
			assert.Equal(t, share.EventActionSuppressLog, matched[i].actions[0], "unexpected action")
		}
	})

	t.Run("activity log does not match any response rule", func(t *testing.T) {
		// Rule 12: matches Container.Suspicious.Process and is enabled (won't match)
		// Rule 10: matches Controller.Start (won't match)
		// Rule 9:  matches Container.Start but is disabled (won't match)
		// Rule 8:  matches Container.Start and is enabled (won't match)
		// Rule 11: matches Info and is enabled (won't match)
		actions := []string{share.EventActionSuppressLog}
		disabledRule := newEventRule(9, share.EventEvent, api.AllContainerGroup, []share.CLUSEventCondition{{CondType: share.EventCondTypeName, CondValue: api.EventNameContainerStart}}, actions)
		disabledRule.Disable = true

		localResPolicyCache = buildResPolicyCache([]*share.CLUSResponseRule{
			newEventRule(12, share.EventIncident, api.AllContainerGroup, []share.CLUSEventCondition{{CondType: share.EventCondTypeName, CondValue: api.EventNameHostSuspiciousProcess}}, actions),
			newEventRule(10, share.EventEvent, api.AllContainerGroup, []share.CLUSEventCondition{{CondType: share.EventCondTypeName, CondValue: api.EventNameControllerStart}}, actions),
			disabledRule,
			newEventRule(8, share.EventEvent, api.AllContainerGroup, []share.CLUSEventCondition{{CondType: share.EventCondTypeName, CondValue: api.EventNameContainerStart}}, actions),
			newEventRule(11, share.EventEvent, api.AllContainerGroup, []share.CLUSEventCondition{{CondType: share.EventCondTypeLevel, CondValue: api.LogLevelDEBUG}}, actions),
		})

		desc := newActivityDesc(api.EventNameContainerSecured, api.LogLevelINFO, testWorkloadDomain, testWorkloadID)
		matched := lookup(&desc)

		require.Len(t, matched, 0, "expected 0 matched rule")
	})
}

func TestResponseRuleCVEWithFixMatch(t *testing.T) {
	preTest()
	defer postTest()

	t.Run("CVE-report log matches 1 response rule for cve-high-with-fix count", func(t *testing.T) {
		// rule: # of high & critical vul(with fix) >= 3
		now := time.Now()
		actions := []string{share.EventActionSuppressLog}
		cveFixedInfo := []scanUtils.FixedVulInfo{
			{PubTS: now.AddDate(0, 0, -7).Unix()},
			{PubTS: now.AddDate(0, 0, -14).Unix()},
			{PubTS: now.AddDate(0, 0, -21).Unix()},
		}

		rule := newEventRule(9, share.EventCVEReport, api.AllContainerGroup, []share.CLUSEventCondition{{CondType: share.EventCondTypeCVEHighWithFix, CondValue: "3"}}, actions)
		localResPolicyCache = buildResPolicyCache([]*share.CLUSResponseRule{
			rule,
		})

		matched := matchCVEWithFixConditions(rule.Conditions[0].CondValue, cveFixedInfo)
		require.True(t, matched, "it should match cve-high-with-fix:3 rule")
	})

	t.Run("CVE-report log matches 0 response rule for cve-high-with-fix count with reported date", func(t *testing.T) {
		// rule: # of (high & critical vul that are reported 15 days ago AND have fix) >= 2
		now := time.Now()
		actions := []string{share.EventActionSuppressLog}
		cveFixedInfo := []scanUtils.FixedVulInfo{
			{PubTS: now.AddDate(0, 0, -7).Unix()},
			{PubTS: now.AddDate(0, 0, -14).Unix()},
			{PubTS: now.AddDate(0, 0, -21).Unix()},
		}

		rule := newEventRule(9, share.EventCVEReport, api.AllContainerGroup, []share.CLUSEventCondition{{CondType: share.EventCondTypeCVEHighWithFix, CondValue: "2/15"}}, actions)
		localResPolicyCache = buildResPolicyCache([]*share.CLUSResponseRule{
			rule,
		})

		matched := matchCVEWithFixConditions(rule.Conditions[0].CondValue, cveFixedInfo)
		require.False(t, matched, "it should not match cve-high-with-fix:2/15 rule")
	})

	t.Run("CVE-report log matches 1 response rule for cve-high-with-fix count with reported date", func(t *testing.T) {
		// rule: # of (high & critical vul that are reported 10 days ago AND have fix) >= 2
		now := time.Now()
		actions := []string{share.EventActionSuppressLog}
		cveFixedInfo := []scanUtils.FixedVulInfo{
			{PubTS: now.AddDate(0, 0, -7).Unix()},
			{PubTS: now.AddDate(0, 0, -14).Unix()},
			{PubTS: now.AddDate(0, 0, -21).Unix()},
		}

		rule := newEventRule(9, share.EventCVEReport, api.AllContainerGroup, []share.CLUSEventCondition{{CondType: share.EventCondTypeCVEHighWithFix, CondValue: "2/10"}}, actions)
		localResPolicyCache = buildResPolicyCache([]*share.CLUSResponseRule{
			rule,
		})

		matched := matchCVEWithFixConditions(rule.Conditions[0].CondValue, cveFixedInfo)
		require.True(t, matched, "it should match cve-high-with-fix:2/10 rule")
	})

	t.Run("CVE-report log does not match response rule for cve-high-with-fix count with reported date", func(t *testing.T) {
		// rule: # of (high & critical vul that are reported 30 days ago AND have fix) >= 1
		now := time.Now()
		actions := []string{share.EventActionSuppressLog}
		cveFixedInfo := []scanUtils.FixedVulInfo{
			{PubTS: now.AddDate(0, 0, -7).Unix()},
			{PubTS: now.AddDate(0, 0, -14).Unix()},
			{PubTS: now.AddDate(0, 0, -21).Unix()},
		}

		rule := newEventRule(9, share.EventCVEReport, api.AllContainerGroup, []share.CLUSEventCondition{{CondType: share.EventCondTypeCVEHighWithFix, CondValue: "1/30"}}, actions)
		localResPolicyCache = buildResPolicyCache([]*share.CLUSResponseRule{
			rule,
		})

		matched := matchCVEWithFixConditions(rule.Conditions[0].CondValue, cveFixedInfo)
		require.False(t, matched, "it should not match cve-high-with-fix:1/30 rule")
	})
}

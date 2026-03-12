package cache

import (
	"testing"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

func TestResponseRuleLookup(t *testing.T) {
	preTest()

	g1 := share.CLUSGroup{Name: api.AllContainerGroup, CfgType: share.UserCreated}
	groupCacheMap[api.AllContainerGroup] = &groupCache{
		group:               &g1,
		usedByPolicy:        utils.NewSet(),
		usedByResponseRules: utils.NewSet(),
		members:             utils.NewSet("bc40937a5ab126c1188a2e01f2a52833adfdc4b04f1d22134a4ca5967a64631d"),
	}

	localResPolicyCache = resPolicyCacheType{
		ruleMap: map[uint32]*share.CLUSResponseRule{
			10: {
				ID:    10,
				Event: share.EventEvent,
				Group: api.AllContainerGroup,
				Conditions: []share.CLUSEventCondition{
					{
						CondType:  share.EventCondTypeName,
						CondValue: api.EventNameControllerStart, // "Controller.Start"
					},
				},
				Actions: []string{share.EventActionSuppressLog},
				CfgType: share.UserCreated,
			},
			9: {
				ID:    9,
				Event: share.EventEvent,
				Group: api.AllContainerGroup,
				Conditions: []share.CLUSEventCondition{
					{
						CondType:  share.EventCondTypeName,
						CondValue: api.EventNameContainerStart, // "Container.Start",
					},
				},
				Actions: []string{share.EventActionSuppressLog},
				Disable: true,
				CfgType: share.UserCreated,
			},
			8: {
				ID:    8,
				Event: share.EventEvent,
				Group: api.AllContainerGroup,
				Conditions: []share.CLUSEventCondition{
					{
						CondType:  share.EventCondTypeName,
						CondValue: api.EventNameContainerStart, // "Container.Start",
					},
				},
				Actions: []string{share.EventActionSuppressLog},
				CfgType: share.UserCreated,
			},
		},
		ruleHeads: []*share.CLUSRuleHead{
			{ID: 10, CfgType: share.UserCreated},
			{ID: 9, CfgType: share.UserCreated},
			{ID: 8, CfgType: share.UserCreated},
		},
		ruleOrderMap: map[uint32]int{
			10: 0,
			9:  1,
			8:  2,
		},
	}

	log := &api.Event{
		LogCommon: api.LogCommon{
			ClusterName:       "cluster-41",
			HostID:            "host-k8sworker41:GXTH:Z624:DIFT:72R6:OQXU:S7HD:2A6U:UZO5:HJU6:PWQC:BQSN:H2IR",
			HostName:          "host-k8sworker41",
			Level:             "Info",
			Name:              "Container.Start",
			ReportedAt:        "2026-03-11T13:20:39Z",
			ReportedTimeStamp: 1773235239,
			AgentID:           "b09358fe3dde086ff9a27fe78e19f598cdd2a70994620702fbcdec5192a035f8",
			AgentName:         "neuvector-enforcer-pod-4wq95",
		},
		Category:        "WORKLOAD",
		Msg:             "Container.Start",
		WorkloadDomain:  "demo",
		WorkloadID:      "bc40937a5ab126c1188a2e01f2a52833adfdc4b04f1d22134a4ca5967a64631d",
		WorkloadImage:   "rancher/mirrored-pause:3.6",
		WorkloadName:    "iperfserver-795d769cd9-wbxpq",
		WorkloadService: "iperfserver.demo",
	}
	desc := eventDesc{id: log.WorkloadID, event: share.EventActivity, name: log.Name, level: log.Level, arg: log}

	//--- activity log matches 1 response rule(for Event)
	matched := lookup(&desc)
	if len(matched) != 1 || matched[0].id != 8 || len(matched[0].actions) != 1 || matched[0].actions[0] != share.EventActionSuppressLog {
		t.Errorf("Unexpected response rule match result [1]")
		t.Logf("  Expect: 1 rule matched\n")
		t.Logf("  Actual: rule(s) matched: %v\n", matched)
	}

	//--- activity log matches 2 response rules(for Event)
	localResPolicyCache.ruleMap[11] = &share.CLUSResponseRule{
		ID:    11,
		Event: share.EventEvent,
		Group: api.AllContainerGroup,
		Conditions: []share.CLUSEventCondition{
			{
				CondType:  share.EventCondTypeLevel,
				CondValue: api.LogLevelINFO,
			},
		},
		Actions: []string{share.EventActionSuppressLog},
		CfgType: share.UserCreated,
	}
	localResPolicyCache.ruleHeads = append(localResPolicyCache.ruleHeads, &share.CLUSRuleHead{ID: 11, CfgType: share.UserCreated})
	localResPolicyCache.ruleOrderMap[11] = 3

	matched = lookup(&desc)
	if len(matched) != 2 ||
		matched[0].id != 8 || len(matched[0].actions) != 1 || matched[0].actions[0] != share.EventActionSuppressLog ||
		matched[1].id != 11 || len(matched[1].actions) != 1 || matched[1].actions[0] != share.EventActionSuppressLog {
		t.Errorf("Unexpected response rule match result [2]")
		t.Logf("  Expect: 2 rule matched\n")
		t.Logf("  Actual: rule(s) matched: %v\n", matched)
	}

	//--- negative testing
	log.Name = "Container.Secured"
	log.Msg = "Container.Secured"
	log.Level = "Debug"
	desc = eventDesc{id: log.WorkloadID, event: share.EventActivity, name: log.Name, level: log.Level, arg: log}
	matched = lookup(&desc)
	if len(matched) != 0 {
		t.Errorf("Unexpected response rule match result [3]")
		t.Logf("  Expect: 0 rule matched\n")
		t.Logf("  Actual: %d rule(s) matched\n", len(matched))
	}

	groupCacheMap = make(map[string]*groupCache)
	localResPolicyCache = resPolicyCacheType{
		ruleMap:      make(map[uint32]*share.CLUSResponseRule),
		ruleHeads:    make([]*share.CLUSRuleHead, 0),
		ruleOrderMap: make(map[uint32]int, 0),
	}

	postTest()
}

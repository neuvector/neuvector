package rest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/share"
)

func initKvAndCache(mockCluster *kv.MockCluster, initRules []*share.CLUSPolicyRule, initGroups []*share.CLUSGroup) {
	mockCluster.Init(
		initRules,
		initGroups,
	)
	clusHelper = mockCluster

	mc := mockCache{
		groups:    make(map[string]*api.RESTGroup, len(initGroups)),
		rules:     make(map[uint32]*api.RESTPolicyRule, len(initRules)),
		ruleHeads: make([]*share.CLUSRuleHead, len(initRules)),
	}
	for _, g := range initGroups {
		mc.groups[g.Name] = mc.Group2REST(g)
	}
	for idx, r := range initRules {
		mc.rules[r.ID] = mc.PolicyRule2REST(r)
		mc.ruleHeads[idx] = mc.PolicyRule2RuleHead(r)
	}
	cacher = &mc
}

func TestPolicyRuleList(t *testing.T) {
	preTest()

	// Initial data
	rule1 := share.CLUSPolicyRule{
		ID: 100002, From: "fed.gFed1", To: "fed.gFed1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.FederalCfg,
	}
	rule11 := share.CLUSPolicyRule{
		ID: 110001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.GroundCfg,
	}
	rule21 := share.CLUSPolicyRule{
		ID: 10001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.Learned,
	}
	initRules := []*share.CLUSPolicyRule{&rule1, &rule11, &rule21}
	initGroups := []*share.CLUSGroup{
		{Name: "fed.gFed1", CfgType: share.FederalCfg},
		{Name: "g1", CfgType: share.UserCreated},
	}
	var mockCluster kv.MockCluster
	initKvAndCache(&mockCluster, initRules, initGroups)

	w := restCall("GET", "/v1/policy/rule?scope=fed", nil, api.UserRoleReader)
	if w.status == http.StatusOK {
		var resp api.RESTPolicyRulesData
		_ = json.Unmarshal(w.body, &resp)
		if len(resp.Rules) != 1 {
			t.Errorf("List policy rules positive: Status is OK.")
			t.Logf("  Expect len: 1\n")
			t.Logf("  Actual len: %d\n", len(resp.Rules))
		} else if resp.Rules[0].ID != 100002 {
			t.Errorf("List policy rules positive: Status is OK.")
			t.Logf("  Expect ID: %d\n", rule1.ID)
			t.Logf("  Actual ID: %d\n", resp.Rules[0].ID)
		}
	} else {
		t.Errorf("List policy rules positive: Status is not OK")
		t.Logf("  Expect status: %+v\n", http.StatusOK)
		t.Logf("  Actual status: %+v\n", w.status)
	}

	postTest()
}

func TestPolicyRuleShow(t *testing.T) {
	preTest()

	rule := api.RESTPolicyRule{
		ID: 10, From: "from", To: "to",
		Ports:        api.PolicyPortAny,
		Action:       share.PolicyActionAllow,
		Applications: []string{api.PolicyAppAny},
		CfgType:      api.CfgTypeUserCreated,
	}
	cacher = &mockCache{rules: map[uint32]*api.RESTPolicyRule{rule.ID: &rule}}

	// Read existing rule
	{
		w := restCall("GET", "/v1/policy/rule/10", nil, api.UserRoleAdmin)

		var resp api.RESTPolicyRuleData
		_ = json.Unmarshal(w.body, &resp)

		if !compareRESTRules(&rule, resp.Rule) {
			t.Errorf("Get existing rule: Not found.")
			t.Logf("  Expect: %+v\n", rule)
			t.Logf("  Actual: %+v\n", resp.Rule)
		}
	}

	// Read non-existing rule
	{
		w := restCall("GET", "/v1/policy/rule/20", nil, api.UserRoleReader)

		if w.status != http.StatusNotFound {
			t.Errorf("Get non-existing policy: Incorrect status.")
			t.Logf("  Expect status: %+v\n", http.StatusNotFound)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		var resp api.RESTError
		_ = json.Unmarshal(w.body, &resp)

		if resp.Code != api.RESTErrObjectNotFound {
			t.Errorf("Get non-existing policy: Incorrect error code.")
			t.Logf("  Expect error: %+v\n", api.RESTErrObjectNotFound)
			t.Logf("  Actual error: %+v\n", resp.Code)
		}
	}

	postTest()
}

func TestPolicyRuleConfigKeep(t *testing.T) {
	preTest()

	{
		// Initial data
		rule1 := share.CLUSPolicyRule{
			ID: 10, From: "g1", To: "g1", Action: share.PolicyActionDeny,
			Ports:        api.PolicyPortAny,
			Applications: []uint32{},
			CfgType:      share.UserCreated,
		}

		mc := mockCache{rules: make(map[uint32]*api.RESTPolicyRule, 0)}
		mc.rules[rule1.ID] = cacher.PolicyRule2REST(&rule1)
		cacher = &mc

		var mockCluster kv.MockCluster
		mockCluster.Init(
			[]*share.CLUSPolicyRule{&rule1},
			[]*share.CLUSGroup{
				{Name: "g1", CfgType: share.UserCreated},
			},
		)
		clusHelper = &mockCluster

		// Send REST
		action := share.PolicyActionAllow
		conf := api.RESTPolicyRuleConfig{ID: 10, Action: &action}
		data := api.RESTPolicyRuleConfigData{Config: &conf, Replicate: true}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule/10", body, api.UserRoleAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Overwrite policy positive: Status is not OK.")
		}

		// Compare result
		nrule1, _ := clusHelper.GetPolicyRule(10)
		if nrule1.Disable {
			t.Errorf("Overwritten policy should not be disabled")
		}

		nrh := clusHelper.GetPolicyRuleList()
		if len(nrh) != 2 || nrh[0].ID != 11 || nrh[1].ID != 10 {
			t.Errorf("Overwrite policy positive: Unexpected rule head")
			t.Errorf("  head: %+v %+v\n", nrh[0], nrh[1])
		}

		expect := share.CLUSPolicyRule{
			ID: 11, From: "g1", To: "g1", Action: action,
			Ports:        api.PolicyPortAny,
			Applications: []uint32{},
			CfgType:      share.UserCreated,
		}
		nr, _ := clusHelper.GetPolicyRule(expect.ID)
		if !compareCLUSRules(&expect, nr) {
			t.Errorf("Overwrite policy positive: Unexpected new rule")
			t.Logf("  Expect: %+v\n", expect)
			t.Logf("  Actual: %+v\n", *nr)
		}
	}

	{
		// Initial data
		rule1 := share.CLUSPolicyRule{
			ID: 10001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:        api.PolicyPortAny,
			Applications: []uint32{},
			CfgType:      share.Learned,
		}
		rule2 := share.CLUSPolicyRule{
			ID: 10002, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:        api.PolicyPortAny,
			Applications: []uint32{},
			CfgType:      share.Learned,
		}
		mc := mockCache{rules: make(map[uint32]*api.RESTPolicyRule, 0)}
		mc.rules[rule1.ID] = mc.PolicyRule2REST(&rule1)
		mc.rules[rule2.ID] = mc.PolicyRule2REST(&rule2)
		cacher = &mc

		var mockCluster kv.MockCluster
		mockCluster.Init(
			[]*share.CLUSPolicyRule{&rule1, &rule2},
			[]*share.CLUSGroup{
				{Name: "g1", CfgType: share.UserCreated},
			},
		)
		clusHelper = &mockCluster

		// Send REST
		action := share.PolicyActionDeny
		conf := api.RESTPolicyRuleConfig{ID: 10002, Action: &action}
		data := api.RESTPolicyRuleConfigData{Config: &conf, Replicate: true}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule/10002", body, api.UserRoleAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Overwrite policy positive: Status is not OK.")
		}

		// Compare result
		nrule2, _ := clusHelper.GetPolicyRule(10002)
		if nrule2.Disable {
			t.Errorf("Overwritten policy should not be disabled")
		}

		nrh := clusHelper.GetPolicyRuleList()
		if len(nrh) != 3 || nrh[0].ID != 10001 || nrh[1].ID != 1 || nrh[2].ID != 10002 {
			t.Errorf("Overwrite policy positive: Unexpected rule head")
			t.Errorf("  head: %+v %+v %+v\n", nrh[0], nrh[1], nrh[2])
		}

		expect := share.CLUSPolicyRule{
			ID: 1, From: "g1", To: "g1", Action: action,
			Ports:        api.PolicyPortAny,
			Applications: []uint32{},
			CfgType:      share.UserCreated,
		}
		nr, _ := clusHelper.GetPolicyRule(expect.ID)
		if !compareCLUSRules(&expect, nr) {
			t.Errorf("Overwrite policy positive: Unexpected new rule")
			t.Logf("  Expect: %+v\n", expect)
			t.Logf("  Actual: %+v\n", *nr)
		}
	}

	postTest()
}

func TestPolicyRuleConfig(t *testing.T) {
	preTest()

	// Initial data
	rule1 := share.CLUSPolicyRule{
		ID: 10, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.UserCreated,
	}
	mc := mockCache{rules: make(map[uint32]*api.RESTPolicyRule, 0)}
	mc.rules[rule1.ID] = mc.PolicyRule2REST(&rule1)
	cacher = &mc

	var mockCluster kv.MockCluster
	mockCluster.Init(
		[]*share.CLUSPolicyRule{&rule1},
		[]*share.CLUSGroup{
			{Name: "g1", CfgType: share.UserCreated},
		},
	)
	clusHelper = &mockCluster

	// Request without modification
	{
		conf := api.RESTPolicyRuleConfig{ID: 10}
		data := api.RESTPolicyRuleConfigData{Config: &conf}
		body, _ := json.Marshal(data)

		restCall("PATCH", "/v1/policy/rule/10", body, api.UserRoleAdmin)

		// Compare result
		nrule1, _ := clusHelper.GetPolicyRule(10)
		if !compareCLUSRules(&rule1, nrule1) {
			t.Errorf("No policy modification: Fail!")
			t.Logf("  Expect: %+v\n", rule1)
			t.Logf("  Actual: %+v\n", *nrule1)
		}
	}

	// Modify rule fields
	{
		action := share.PolicyActionDeny
		apps := []string{"http"}
		ports := "80"
		disable := true
		conf := api.RESTPolicyRuleConfig{
			ID: 10, Applications: &apps, Ports: &ports, Action: &action, Disable: &disable,
		}
		data := api.RESTPolicyRuleConfigData{Config: &conf}
		body, _ := json.Marshal(data)

		restCall("PATCH", "/v1/policy/rule/10", body, api.UserRoleAdmin)

		// Compare result
		rule1.Ports = "tcp/80"
		rule1.Applications = []uint32{1001}
		rule1.Action = share.PolicyActionDeny
		rule1.Disable = true
		nrule1, _ := clusHelper.GetPolicyRule(10)
		if !compareCLUSRules(&rule1, nrule1) {
			t.Errorf("Modify policy fields: Fail!")
			t.Logf("  Expect: %+v\n", rule1)
			t.Logf("  Actual: %+v\n", *nrule1)
		}
	}

	postTest()
}

func TestPolicyRuleConfigGroup(t *testing.T) {
	preTest()

	// Initial data
	rule1 := share.CLUSPolicyRule{
		ID: 10, From: "g1", To: "g2", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.UserCreated,
	}
	rule2 := share.CLUSPolicyRule{
		ID: 20, From: "g2", To: "g3", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.UserCreated,
	}
	mc := mockCache{rules: make(map[uint32]*api.RESTPolicyRule, 0)}
	mc.rules[rule1.ID] = mc.PolicyRule2REST(&rule1)
	mc.rules[rule2.ID] = mc.PolicyRule2REST(&rule2)
	cacher = &mc

	var mockCluster kv.MockCluster
	mockCluster.Init(
		[]*share.CLUSPolicyRule{&rule1, &rule2},
		[]*share.CLUSGroup{
			{Name: "g1", CfgType: share.UserCreated},
			{Name: "g2", CfgType: share.UserCreated},
			{Name: "g3", CfgType: share.UserCreated},
		},
	)
	clusHelper = &mockCluster

	// Modify policy group, rule1
	{
		to := "g1"
		conf := api.RESTPolicyRuleConfig{ID: 10, To: &to}
		data := api.RESTPolicyRuleConfigData{Config: &conf}
		body, _ := json.Marshal(data)

		restCall("PATCH", "/v1/policy/rule/10", body, api.UserRoleAdmin)

		// Compare result
		rule1.To = "g1"
		nrule1, _ := clusHelper.GetPolicyRule(10)
		if !compareCLUSRules(&rule1, nrule1) {
			t.Errorf("Modify policy 10 group: Incorrect policy group.")
			t.Logf("  Expect: %+v\n", rule1)
			t.Logf("  Actual: %+v\n", *nrule1)
		}
	}

	// Modify policy group, rule2
	{
		from := "g3"
		to := "g1"
		conf := api.RESTPolicyRuleConfig{ID: 20, From: &from, To: &to}
		data := api.RESTPolicyRuleConfigData{Config: &conf}
		body, _ := json.Marshal(data)

		restCall("PATCH", "/v1/policy/rule/20", body, api.UserRoleAdmin)

		// Compare result
		rule2.From = "g3"
		rule2.To = "g1"
		nrule2, _ := clusHelper.GetPolicyRule(20)
		if !compareCLUSRules(&rule2, nrule2) {
			t.Errorf("Modify policy group rule2: Incorrect policy group.")
			t.Logf("  Expect: %+v\n", rule2)
			t.Logf("  Actual: %+v\n", *nrule2)
		}
	}

	// Modify policy group, to external
	{
		to := api.LearnedExternal
		conf := api.RESTPolicyRuleConfig{ID: 20, To: &to}
		data := api.RESTPolicyRuleConfigData{Config: &conf}
		body, _ := json.Marshal(data)

		restCall("PATCH", "/v1/policy/rule/20", body, api.UserRoleAdmin)

		// Compare result
		rule2.To = to
		nrule2, _ := clusHelper.GetPolicyRule(20)
		if !compareCLUSRules(&rule2, nrule2) {
			t.Errorf("Modify policy 20 group to external: Incorrect policy group.")
			t.Logf("  Expect: %+v\n", rule2)
			t.Logf("  Actual: %+v\n", *nrule2)
		}
	}

	// Modify policy group, from external
	{
		from := api.LearnedExternal
		conf := api.RESTPolicyRuleConfig{ID: 20, From: &from}
		data := api.RESTPolicyRuleConfigData{Config: &conf}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule/20", body, api.UserRoleAdmin)

		if w.status != http.StatusBadRequest {
			t.Errorf("Modify both group to external: Incorrect status.")
			t.Logf("  Expect status: %+v\n", http.StatusBadRequest)
			t.Logf("  Actual status: %+v\n", w.status)
		}
	}

	postTest()
}

func TestPolicyRuleConfigPort(t *testing.T) {
	preTest()

	// Initial data
	rule := share.CLUSPolicyRule{
		ID: 10, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.UserCreated,
	}
	mc := mockCache{rules: make(map[uint32]*api.RESTPolicyRule, 0)}
	mc.rules[rule.ID] = mc.PolicyRule2REST(&rule)
	cacher = &mc

	var mockCluster kv.MockCluster
	mockCluster.Init(
		[]*share.CLUSPolicyRule{&rule},
		[]*share.CLUSGroup{
			{Name: "g1", CfgType: share.UserCreated},
		},
	)
	clusHelper = &mockCluster

	// Modify policy port, positive
	{
		portsPositive := map[string]string{
			"":                                    api.PolicyPortAny,
			"80":                                  "tcp/80",
			"8080,80":                             "tcp/80,tcp/8080",
			"2100-2200":                           "tcp/2100-2200",
			"100,101,102,UDP/80,udp/53-60":        "tcp/100,tcp/101,tcp/102,udp/53-60,udp/80",
			"100 , TCP/80  11153-11260,udp/60-60": "tcp/80,tcp/100,tcp/11153-11260,udp/60",
			"50, any, 100-200":                    api.PolicyPortAny,
		}

		for input, output := range portsPositive {
			conf := api.RESTPolicyRuleConfig{ID: 10, Ports: &input}
			data := api.RESTPolicyRuleConfigData{Config: &conf}
			body, _ := json.Marshal(data)

			w := restCall("PATCH", "/v1/policy/rule/10", body, api.UserRoleAdmin)

			if w.status != http.StatusOK {
				t.Errorf("Modify policy port positive: Status is not OK.")
			}

			// Compare result
			nrule, _ := clusHelper.GetPolicyRule(10)
			if nrule.Ports != output {
				t.Errorf("Modify policy port positive: Fail.")
				t.Logf("  Input : %+v\n", input)
				t.Logf("  Expect: %+v\n", output)
				t.Logf("  Actual: %+v\n", nrule.Ports)
			}
		}
	}

	// Modify policy port, positive
	{
		portsNegative := []string{
			"2100-2200,TCP/80,90-",
			"100- 200,80 -90",
			"icmp/8",
			"200-100",
		}

		for _, input := range portsNegative {
			conf := api.RESTPolicyRuleConfig{ID: 10, Ports: &input}
			data := api.RESTPolicyRuleConfigData{Config: &conf}
			body, _ := json.Marshal(data)

			w := restCall("PATCH", "/v1/policy/rule/10", body, api.UserRoleAdmin)

			if w.status != http.StatusBadRequest {
				t.Errorf("Modify policy port negative: Incorrect status.")
				t.Logf("  Expect status: %+v\n", http.StatusBadRequest)
				t.Logf("  Actual status: %+v\n", w.status)
			}
		}
	}

	postTest()
}

func TestPolicyRuleConfigApp(t *testing.T) {
	preTest()

	// Initial data
	rule := share.CLUSPolicyRule{
		ID: 10, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.UserCreated,
	}

	mc := mockCache{rules: make(map[uint32]*api.RESTPolicyRule, 0)}
	mc.rules[rule.ID] = mc.PolicyRule2REST(&rule)
	cacher = &mc

	var mockCluster kv.MockCluster
	mockCluster.Init(
		[]*share.CLUSPolicyRule{&rule},
		[]*share.CLUSGroup{
			{Name: "g1", CfgType: share.UserCreated},
		},
	)
	clusHelper = &mockCluster

	type appMap struct {
		input  []string
		output []uint32
	}

	{
		appsPositive := []appMap{
			{input: []string{}, output: []uint32{}},
			{input: []string{"http"}, output: []uint32{1001}},
			{input: []string{"http", "KafkA"}, output: []uint32{1001, 2007}},
			{input: []string{"http", "KafkA", "MySQL"}, output: []uint32{1001, 2007, 2001}},
			{input: []string{"http", "anY", "KafkA"}, output: []uint32{}},
		}
		for _, am := range appsPositive {
			conf := api.RESTPolicyRuleConfig{ID: 10, Applications: &am.input}
			data := api.RESTPolicyRuleConfigData{Config: &conf}
			body, _ := json.Marshal(data)

			w := restCall("PATCH", "/v1/policy/rule/10", body, api.UserRoleAdmin)

			if w.status != http.StatusOK {
				t.Errorf("Modify policy app positive: Status is not OK.")
				t.Logf("  Expect status: %+v\n", http.StatusOK)
				t.Logf("  Actual status: %+v\n", w.status)
			}

			nrule, _ := clusHelper.GetPolicyRule(10)
			if !reflect.DeepEqual(nrule.Applications, am.output) {
				t.Errorf("Modify policy app positive: Fail.")
				t.Logf("  Input : %+v\n", am.input)
				t.Logf("  Expect: %+v\n", am.output)
				t.Logf("  Actual: %+v\n", nrule.Applications)
			}
		}
	}

	{
		appsNegative := []appMap{
			{input: []string{""}, output: []uint32{}},
			{input: []string{" dummy"}, output: []uint32{}},
			{input: []string{"http", "KafkA "}, output: []uint32{}},
		}
		for _, am := range appsNegative {
			conf := api.RESTPolicyRuleConfig{ID: 10, Applications: &am.input}
			data := api.RESTPolicyRuleConfigData{Config: &conf}
			body, _ := json.Marshal(data)

			w := restCall("PATCH", "/v1/policy/rule/10", body, api.UserRoleAdmin)

			if w.status != http.StatusBadRequest {
				t.Errorf("Modify policy app negative: Incorrect status.")
				t.Logf("  Expect status: %+v\n", http.StatusOK)
				t.Logf("  Actual status: %+v\n", w.status)
			}
		}
	}

	postTest()
}

func TestPolicyRuleConfigNegative(t *testing.T) {
	preTest()

	// Initial data
	rule1 := share.CLUSPolicyRule{
		ID: 10, From: "g1", To: "g2", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.UserCreated,
	}
	rule2 := share.CLUSPolicyRule{
		ID: 10001, From: "g1", To: "g3", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.Learned,
	}
	mc := mockCache{rules: make(map[uint32]*api.RESTPolicyRule, 0)}
	mc.rules[rule1.ID] = mc.PolicyRule2REST(&rule1)
	mc.rules[rule2.ID] = mc.PolicyRule2REST(&rule2)
	cacher = &mc

	var mockCluster kv.MockCluster
	mockCluster.Init(
		[]*share.CLUSPolicyRule{&rule1, &rule2},
		[]*share.CLUSGroup{
			{Name: "g1", CfgType: share.UserCreated},
		},
	)
	clusHelper = &mockCluster

	// Reader cannot config policy
	{
		to := "g1"
		conf := api.RESTPolicyRuleConfig{ID: 10, To: &to}
		data := api.RESTPolicyRuleConfigData{Config: &conf}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule/10", body, api.UserRoleReader)

		if w.status != http.StatusForbidden {
			t.Errorf("Reader cannot modify policy: Incorrect status.")
			t.Logf("  Expect status: %+v\n", http.StatusForbidden)
			t.Logf("  Actual status: %+v\n", w.status)
		}
	}

	// Invalid request
	{
		body := []byte("{}")

		w := restCall("PATCH", "/v1/policy/rule/10", body, api.UserRoleAdmin)

		if w.status != http.StatusBadRequest {
			t.Errorf("Modify policy with malformed request: Incorrect status.")
			t.Logf("  Expect status: %+v\n", http.StatusBadRequest)
			t.Logf("  Actual status: %+v\n", w.status)
		}
	}

	// Invalid request
	{
		body := []byte("{\"config\": {}}")

		w := restCall("PATCH", "/v1/policy/rule/10", body, api.UserRoleAdmin)

		if w.status != http.StatusBadRequest {
			t.Errorf("Modify policy with malformed request: Incorrect status.")
			t.Logf("  Expect status: %+v\n", http.StatusBadRequest)
			t.Logf("  Actual status: %+v\n", w.status)
		}
	}

	// Modify learned policy
	{
		conf := api.RESTPolicyRuleConfig{ID: 10001}
		data := api.RESTPolicyRuleConfigData{Config: &conf}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule/10001", body, api.UserRoleAdmin)

		if w.status != http.StatusBadRequest {
			t.Errorf("Modify learned policy: Incorrect status.")
			t.Logf("  Expect status: %+v\n", http.StatusBadRequest)
			t.Logf("  Actual status: %+v\n", w.status)
		}
	}

	// Invalid nv. group rule
	{
		from := "Host:256.0.0.1"
		conf := api.RESTPolicyRuleConfig{ID: 10, From: &from}
		data := api.RESTPolicyRuleConfigData{Config: &conf}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule/10", body, api.UserRoleAdmin)

		if w.status != http.StatusBadRequest {
			t.Errorf("Invalid nv. group rule format: Incorrect status.")
			t.Logf("  Expect status: %+v\n", http.StatusBadRequest)
			t.Logf("  Actual status: %+v\n", w.status)
		}
	}

	// Invalid nv. group rule for both from and to
	{
		from := "Host:10.1.1.1"
		to := "nv.Workload:10.1.1.2"
		conf := api.RESTPolicyRuleConfig{ID: 10, From: &from, To: &to}
		data := api.RESTPolicyRuleConfigData{Config: &conf}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule/10", body, api.UserRoleAdmin)

		if w.status != http.StatusBadRequest {
			t.Errorf("Modify with nv. group rule as from and to: Incorrect status.")
			t.Logf("  Expect status: %+v\n", http.StatusBadRequest)
			t.Logf("  Actual status: %+v\n", w.status)
		}
	}

	postTest()
}

func TestFedPolicyRuleMove(t *testing.T) {
	preTest()

	{
		// Initial data
		rule1 := share.CLUSPolicyRule{
			ID: 100002, From: "fed.gFed1", To: "fed.gFed1", Action: share.PolicyActionAllow,
			Ports:        api.PolicyPortAny,
			Applications: []uint32{},
			CfgType:      share.FederalCfg,
		}
		rule2 := share.CLUSPolicyRule{
			ID: 100003, From: "fed.gFed1", To: "fed.gFed1", Action: share.PolicyActionAllow,
			Ports:        api.PolicyPortAny,
			Applications: []uint32{},
			CfgType:      share.FederalCfg,
		}
		rule11 := share.CLUSPolicyRule{
			ID: 110001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:        api.PolicyPortAny,
			Applications: []uint32{},
			CfgType:      share.GroundCfg,
		}
		rule21 := share.CLUSPolicyRule{
			ID: 10001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:        api.PolicyPortAny,
			Applications: []uint32{},
			CfgType:      share.Learned,
		}
		rule22 := share.CLUSPolicyRule{
			ID: 100, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:        api.PolicyPortAny,
			Applications: []uint32{},
		}
		mc := mockCache{rules: make(map[uint32]*api.RESTPolicyRule, 0)}
		mc.rules[rule1.ID] = mc.PolicyRule2REST(&rule1)
		mc.rules[rule2.ID] = mc.PolicyRule2REST(&rule2)
		mc.rules[rule11.ID] = mc.PolicyRule2REST(&rule11)
		mc.rules[rule21.ID] = mc.PolicyRule2REST(&rule21)
		mc.rules[rule22.ID] = mc.PolicyRule2REST(&rule22)
		cacher = &mc

		var mockCluster kv.MockCluster
		mockCluster.Init(
			[]*share.CLUSPolicyRule{&rule1, &rule2, &rule11, &rule21, &rule22},
			[]*share.CLUSGroup{
				{Name: "fed.gFed1", CfgType: share.FederalCfg},
				{Name: "g1", CfgType: share.UserCreated},
			},
		)
		clusHelper = &mockCluster

		// Move a rule
		var after int
		data := api.RESTPolicyRuleActionData{Move: &api.RESTPolicyRuleMove{
			After: &after,
		}}

		type TCase struct {
			NilAfter bool
			After    int
			ID       uint32
		}
		type TResult struct {
			IDs []uint32
		}

		testCases := []*TCase{
			{ID: 100003, After: 110001},
			{ID: 100002, NilAfter: true},
			{ID: 100003, After: -10001},
			{ID: 100003, After: 100002},
			{ID: 100003, After: -100002}, //
			{ID: 100002, After: 0},
			{ID: 10001, After: -100002},
			{ID: 10001, After: 110001},
			{ID: 10001, After: -10001},
			{ID: 10001, After: 100}, //
			{ID: 10001, NilAfter: true},
			{ID: 100, NilAfter: true},
			{ID: 100, After: -110001},
			{ID: 100, After: 100003},
			{ID: 100, After: 100}, //
			{ID: 10001, After: -100},
		}
		expected := []TResult{
			// initial:  []uint32{100002, 100003, 110001, 10001, 100}
			{IDs: []uint32{100002, 100003, 110001, 10001, 100}},
			{IDs: []uint32{100003, 100002, 110001, 10001, 100}},
			{IDs: []uint32{100002, 100003, 110001, 10001, 100}},
			{IDs: []uint32{100002, 100003, 110001, 10001, 100}},
			{IDs: []uint32{100003, 100002, 110001, 10001, 100}}, //
			{IDs: []uint32{100002, 100003, 110001, 10001, 100}},
			{IDs: []uint32{100002, 100003, 110001, 10001, 100}},
			{IDs: []uint32{100002, 100003, 110001, 10001, 100}},
			{IDs: []uint32{100002, 100003, 110001, 10001, 100}},
			{IDs: []uint32{100002, 100003, 110001, 100, 10001}}, //
			{IDs: []uint32{100002, 100003, 110001, 100, 10001}},
			{IDs: []uint32{100002, 100003, 110001, 10001, 100}},
			{IDs: []uint32{100002, 100003, 110001, 100, 10001}},
			{IDs: []uint32{100002, 100003, 110001, 100, 10001}},
			{IDs: []uint32{100002, 100003, 110001, 100, 10001}}, //
			{IDs: []uint32{100002, 100003, 110001, 10001, 100}},
		}

		for idx, testCase := range testCases {
			data.Move.ID = testCase.ID
			if testCase.NilAfter {
				data.Move.After = nil
			} else {
				after = testCase.After
				data.Move.After = &after
			}
			body, _ := json.Marshal(data)
			w := restCall("PATCH", "/v1/policy/rule", body, api.UserRoleFedAdmin)
			if w.status == http.StatusOK {
				crhs := clusHelper.GetPolicyRuleList()
				fail := false
				for i := 0; i < len(crhs); i++ {
					if crhs[i].ID != expected[idx].IDs[i] {
						fail = true
						break
					}
				}
				if fail {
					t.Errorf("Move fed policy rule(%d) positive: Status is OK.", idx)
					t.Logf("  Expect IDs: %d, %d, %d, %d, %d\n", expected[idx].IDs[0], expected[idx].IDs[1], expected[idx].IDs[2], expected[idx].IDs[3], expected[idx].IDs[4])
					t.Logf("  Actual IDs: %d, %d, %d, %d, %d\n", crhs[0].ID, crhs[1].ID, crhs[2].ID, crhs[3].ID, crhs[4].ID)
				}
			} else {
				t.Errorf("Move fed policy rule(%d) positive: Status is not OK", idx)
				t.Logf("  Expect status: %+v\n", http.StatusOK)
				t.Logf("  Actual status: %+v\n", w.status)
			}
		}
	}

	postTest()
}

func TestFedPolicyRuleInsert(t *testing.T) {
	preTest()

	{
		// Initial data
		rule1 := share.CLUSPolicyRule{
			ID: 110001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:        api.PolicyPortAny,
			Applications: []uint32{},
			CfgType:      share.GroundCfg,
		}
		rule2 := share.CLUSPolicyRule{
			ID: 10001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:        api.PolicyPortAny,
			Applications: []uint32{},
			CfgType:      share.Learned,
		}
		rule3 := share.CLUSPolicyRule{
			ID: 100, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:        api.PolicyPortAny,
			Applications: []uint32{},
		}
		mc := mockCache{rules: make(map[uint32]*api.RESTPolicyRule, 0)}
		mc.rules[rule1.ID] = mc.PolicyRule2REST(&rule1)
		mc.rules[rule2.ID] = mc.PolicyRule2REST(&rule2)
		mc.rules[rule3.ID] = mc.PolicyRule2REST(&rule3)
		cacher = &mc

		var mockCluster kv.MockCluster
		mockCluster.Init(
			[]*share.CLUSPolicyRule{&rule1, &rule2, &rule3},
			[]*share.CLUSGroup{
				{Name: "fed.gFed1", CfgType: share.FederalCfg},
				{Name: "g1", CfgType: share.UserCreated},
			},
		)
		clusHelper = &mockCluster

		type TCase struct {
			NilAfter bool
			After    int
			Rules    []*api.RESTPolicyRule
		}
		type TResult struct {
			Len int
			IDs []uint32
		}
		testCaseScopes := []string{
			"fed", "fed", "fed", "fed", "fed", "local", "local",
		}
		testCases := []TCase{
			{
				After: -110001, // inser before
				Rules: []*api.RESTPolicyRule{{ID: 100002, From: "fed.gFed1", To: "fed.gFed1", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny, CfgType: api.CfgTypeFederal, Comment: "fed1"}},
			},
			{
				After: 110001,
				Rules: []*api.RESTPolicyRule{{ID: 100003, From: "fed.gFed1", To: "fed.gFed1", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny, CfgType: api.CfgTypeFederal, Comment: "fed1"}},
			},
			{
				After: 0, // inser at the beginning
				Rules: []*api.RESTPolicyRule{
					{From: "fed.gFed1", To: "fed.gFed1", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny, CfgType: api.CfgTypeFederal, Comment: "fed1"},
					{From: "fed.gFed1", To: "fed.gFed1", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny, CfgType: api.CfgTypeFederal, Comment: "fed2"},
				},
			},
			{
				After: 100003, // inser after
				Rules: []*api.RESTPolicyRule{
					{From: "fed.gFed1", To: "fed.gFed1", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny, CfgType: api.CfgTypeFederal, Comment: "fed1"},
					{From: "fed.gFed1", To: "fed.gFed1", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny, CfgType: api.CfgTypeFederal, Comment: "fed2"},
				},
			},
			{
				NilAfter: true,
				Rules:    []*api.RESTPolicyRule{{From: "fed.gFed1", To: "fed.gFed1", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny, CfgType: api.CfgTypeFederal, Comment: "fed1"}},
			},
			{
				After: 100003, // inser after
				Rules: []*api.RESTPolicyRule{
					{From: "g1", To: "g1", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny, CfgType: api.CfgTypeUserCreated, Comment: "11"},
					{From: "g1", To: "g1", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny, CfgType: api.CfgTypeUserCreated, Comment: "12"},
				},
			},
			{
				After: 0, // inser after
				Rules: []*api.RESTPolicyRule{{From: "g1", To: "g1", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny, CfgType: api.CfgTypeUserCreated, Comment: "21"}},
			},
		}
		expected := []TResult{
			// initial:  []uint32{110001, 10001, 100}
			{IDs: []uint32{100002, 110001, 10001, 100}},
			{IDs: []uint32{100002, 100003, 110001, 10001, 100}},
			{IDs: []uint32{100004, 100005, 100002, 100003, 110001, 10001, 100}},
			{IDs: []uint32{100004, 100005, 100002, 100003, 100006, 100007, 110001, 10001, 100}},
			{IDs: []uint32{100004, 100005, 100002, 100003, 100006, 100007, 100008, 110001, 10001, 100}},
			{IDs: []uint32{100004, 100005, 100002, 100003, 100006, 100007, 100008, 110001, 101, 102, 10001, 100}},
			{IDs: []uint32{100004, 100005, 100002, 100003, 100006, 100007, 100008, 110001, 103, 101, 102, 10001, 100}},
		}

		var after int
		data := api.RESTPolicyRuleActionData{
			Insert: &api.RESTPolicyRuleInsert{
				After: &after,
			},
		}

		for idx, testCase := range testCases {
			data.Insert.Rules = testCase.Rules
			if testCase.NilAfter {
				data.Insert.After = nil
			} else {
				after = testCase.After
				data.Insert.After = &after
			}
			body, _ := json.Marshal(data)

			uri := fmt.Sprintf("/v1/policy/rule?scope=%s", testCaseScopes[idx])
			w := restCallFed("PATCH", uri, body, api.UserRoleFedAdmin, api.FedRoleMaster)
			if w.status == http.StatusOK {
				crhs := clusHelper.GetPolicyRuleList()
				crhsSlice := make([]uint32, len(crhs))
				for idx, rh := range crhs {
					crhsSlice[idx] = rh.ID
				}
				success := false
				if len(crhs) == len(expected[idx].IDs) {
					if reflect.DeepEqual(crhsSlice, expected[idx].IDs) {
						success = true
					}
				}
				if !success {
					t.Errorf("Insert fed policy rules(%d) positive: unexpected rule head.", idx)
					t.Logf("  Expect: %+v\n", expected[idx].IDs)
					t.Logf("  Actual: %+v\n", crhsSlice)
				} else {
					t.Logf("  Now IDs(%d): %+v\n", idx, crhsSlice) //->
				}
			} else {
				t.Errorf("Insert fed policy rules(%d) positive: Status is not OK", idx)
				t.Logf("  Expect status: %+v\n", http.StatusOK)
				t.Logf("  Actual status: %+v\n", w.status)
			}
		}
	}

	postTest()
}

func TestFedPolicyRuleInsertNegative(t *testing.T) {
	preTest()

	// Initial data
	rule1 := share.CLUSPolicyRule{
		ID: 100001, From: "fed.gFed1", To: "fed.gFed1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.FederalCfg,
	}
	rule2 := share.CLUSPolicyRule{
		ID: 110001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.GroundCfg,
	}
	rule3 := share.CLUSPolicyRule{
		ID: 10001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.Learned,
	}
	rule4 := share.CLUSPolicyRule{
		ID: 100, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
	}
	mc := mockCache{rules: make(map[uint32]*api.RESTPolicyRule, 0)}
	mc.rules[rule1.ID] = mc.PolicyRule2REST(&rule1)
	mc.rules[rule2.ID] = mc.PolicyRule2REST(&rule2)
	mc.rules[rule3.ID] = mc.PolicyRule2REST(&rule3)
	mc.rules[rule4.ID] = mc.PolicyRule2REST(&rule4)
	cacher = &mc

	var mockCluster kv.MockCluster
	mockCluster.Init(
		[]*share.CLUSPolicyRule{&rule1, &rule2, &rule3, &rule4},
		[]*share.CLUSGroup{
			{Name: "fed.gFed1", CfgType: share.FederalCfg},
			{Name: "g1", CfgType: share.UserCreated},
		},
	)
	clusHelper = &mockCluster

	type TCase struct {
		NilAfter bool
		After    int
		Rules    []*api.RESTPolicyRule
	}
	testCaseScopes := []string{"fed", "fed", "fed", "local", "local", "local", "fed", "local", "local"}
	testCases := []*TCase{
		{
			After: -100, // inser before
			Rules: []*api.RESTPolicyRule{ // duplicate id
				{ID: 100001, From: "fed.gFed1", To: "fed.gFed1", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny, CfgType: api.CfgTypeFederal, Comment: "fed1"},
			},
		},
		{
			After: 100009, // inser after
			Rules: []*api.RESTPolicyRule{ // duplicate id
				{ID: 100001, From: "fed.gFed1", To: "fed.gFed1", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny, CfgType: api.CfgTypeFederal, Comment: "fed1"},
			},
		},
		{
			After: 100, // inser after
			Rules: []*api.RESTPolicyRule{ // not same CfgType in slice
				{ID: 100003, From: "fed.gFed1", To: "fed.gFed1", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny, CfgType: api.CfgTypeFederal, Comment: "fed11"},
				{ID: 100004, From: "g1", To: "g1", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny, CfgType: api.CfgTypeUserCreated, Comment: "12"},
			},
		},
		{
			After: 100, // inser after
			Rules: []*api.RESTPolicyRule{ // not same CfgType in slice
				{ID: 100003, From: "fed.gFed1", To: "fed.gFed1", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny, CfgType: api.CfgTypeFederal, Comment: "fed11"},
				{ID: 100004, From: "g1", To: "g1", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny, CfgType: api.CfgTypeUserCreated, Comment: "12"},
			},
		},
		{
			After: 110001, // inser after
			Rules: []*api.RESTPolicyRule{ // FederalCfg policy with UserCreated group
				{ID: 100003, From: "g1", To: "g1", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny, CfgType: api.CfgTypeFederal, Comment: "11"},
			},
		},
		{
			After: 100, // inser after
			Rules: []*api.RESTPolicyRule{ // FederalCfg policy with UserCreated group
				{ID: 100003, From: "g1", To: "g1", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny, CfgType: api.CfgTypeFederal, Comment: "11"},
			},
		},
		{
			NilAfter: true, // inser at the end
			Rules: []*api.RESTPolicyRule{ // UserCreated policy with FederalCfg group
				{ID: 100003, From: "fed.gFed1", To: "fed.gFed1", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny, CfgType: api.CfgTypeUserCreated, Comment: "fed11"},
			},
		},
		{
			NilAfter: true, // inser at the end
			Rules: []*api.RESTPolicyRule{ // policy id in wrong range
				{ID: 100013, From: "g1", To: "g1", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny, CfgType: api.CfgTypeUserCreated, Comment: "11"},
			},
		},
		{
			NilAfter: true, // inser at the end
			Rules: []*api.RESTPolicyRule{ // policy id in wrong range
				{ID: 110013, From: "g1", To: "g1", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny, CfgType: api.CfgTypeUserCreated, Comment: "11"},
			},
		},
	}

	var after int
	data := api.RESTPolicyRuleActionData{
		Insert: &api.RESTPolicyRuleInsert{
			After: &after,
		},
	}

	for idx, testCase := range testCases {
		data.Insert.Rules = testCase.Rules
		if testCase.NilAfter {
			data.Insert.After = nil
		} else {
			after = testCase.After
			data.Insert.After = &after
		}
		body, _ := json.Marshal(data)

		uri := fmt.Sprintf("/v1/policy/rule?scope=%s", testCaseScopes[idx])
		w := restCallFed("PATCH", uri, body, api.UserRoleFedAdmin, api.FedRoleMaster)
		if w.status == http.StatusOK {
			t.Errorf("Insert fed policy rule(%d) negative: Status is OK", idx)
			t.Logf("  Expect status: %+v\n", http.StatusNotFound)
			t.Logf("  Actual status: %+v\n", w.status)
		} else {
			t.Logf("  w.status(%d): %+v(%s)\n", idx, w.status, string(w.body)) //->
		}
	}

	postTest()
}

func TestPolicyRuleInsert(t *testing.T) {
	preTest()

	{
		// Initial data
		rule1 := share.CLUSPolicyRule{
			ID: 10001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:        api.PolicyPortAny,
			Applications: []uint32{},
			CfgType:      share.Learned,
		}
		rule2 := share.CLUSPolicyRule{
			ID: 100, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:        api.PolicyPortAny,
			Applications: []uint32{},
		}
		mc := mockCache{rules: make(map[uint32]*api.RESTPolicyRule, 0)}
		mc.rules[rule1.ID] = mc.PolicyRule2REST(&rule1)
		mc.rules[rule2.ID] = mc.PolicyRule2REST(&rule2)
		cacher = &mc

		var mockCluster kv.MockCluster
		mockCluster.Init(
			[]*share.CLUSPolicyRule{&rule1, &rule2},
			[]*share.CLUSGroup{
				{Name: "g1", CfgType: share.UserCreated},
			},
		)
		clusHelper = &mockCluster

		// Insert before a rule
		ri1 := api.RESTPolicyRule{
			ID: 10, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		after := -100
		data := api.RESTPolicyRuleActionData{Insert: &api.RESTPolicyRuleInsert{
			After: &after, Rules: []*api.RESTPolicyRule{&ri1},
		}}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule", body, api.UserRoleAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Insert policy rules positive: Status is not OK.")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		expcrhs := []*share.CLUSRuleHead{
			{ID: rule1.ID, CfgType: rule1.CfgType},
			{ID: ri1.ID, CfgType: cfgTypeMapping[ri1.CfgType]},
			{ID: rule2.ID, CfgType: rule2.CfgType},
		}
		crhs := clusHelper.GetPolicyRuleList()
		if !reflect.DeepEqual(expcrhs, crhs) {
			t.Errorf("Insert policy rules positive: unexpected rule head.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %+v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %+v\n", crh)
			}
		}
	}

	{
		// Initial data
		rule1 := share.CLUSPolicyRule{
			ID: 10001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:        api.PolicyPortAny,
			Applications: []uint32{},
			CfgType:      share.Learned,
		}
		rule2 := share.CLUSPolicyRule{
			ID: 100, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:        api.PolicyPortAny,
			Applications: []uint32{},
			CfgType:      share.UserCreated,
		}
		mc := mockCache{rules: make(map[uint32]*api.RESTPolicyRule, 0)}
		mc.rules[rule1.ID] = mc.PolicyRule2REST(&rule1)
		mc.rules[rule2.ID] = mc.PolicyRule2REST(&rule2)
		cacher = &mc

		var mockCluster kv.MockCluster
		mockCluster.Init(
			[]*share.CLUSPolicyRule{&rule1, &rule2},
			[]*share.CLUSGroup{
				{Name: "g1", CfgType: share.Learned},
			},
		)
		clusHelper = &mockCluster

		// Insert to the last
		ri1 := api.RESTPolicyRule{
			ID: 20, From: "g1", To: "Workload:192.168.0.1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		data := api.RESTPolicyRuleActionData{Insert: &api.RESTPolicyRuleInsert{
			Rules: []*api.RESTPolicyRule{&ri1},
		}}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule", body, api.UserRoleAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Insert policy rules positive: Status is not OK.")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		expcrhs := []*share.CLUSRuleHead{
			{ID: rule1.ID, CfgType: rule1.CfgType},
			{ID: rule2.ID, CfgType: rule2.CfgType},
			{ID: ri1.ID, CfgType: cfgTypeMapping[ri1.CfgType]},
		}
		crhs := clusHelper.GetPolicyRuleList()
		if !reflect.DeepEqual(expcrhs, crhs) {
			t.Errorf("Insert policy rules positive: unexpected rule head.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %+v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %+v\n", crh)
			}
		}
	}

	postTest()
}

func TestPolicyRuleInsertNegative(t *testing.T) {
	preTest()

	// Initial data
	rule1 := share.CLUSPolicyRule{
		ID: 10001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.Learned,
	}
	rule2 := share.CLUSPolicyRule{
		ID: 100, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.UserCreated,
	}
	mc := mockCache{rules: make(map[uint32]*api.RESTPolicyRule, 0)}
	mc.rules[rule1.ID] = mc.PolicyRule2REST(&rule1)
	mc.rules[rule2.ID] = mc.PolicyRule2REST(&rule2)
	cacher = &mc

	var mockCluster kv.MockCluster
	mockCluster.Init(
		[]*share.CLUSPolicyRule{&rule1, &rule2},
		[]*share.CLUSGroup{
			{Name: "g1", CfgType: share.Learned},
		},
	)
	clusHelper = &mockCluster

	{
		// Insert a rule with duplicate ID
		ri1 := api.RESTPolicyRule{
			ID: 100, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		after := 10001
		data := api.RESTPolicyRuleActionData{Insert: &api.RESTPolicyRuleInsert{
			After: &after, Rules: []*api.RESTPolicyRule{&ri1},
		}}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule", body, api.UserRoleAdmin)

		if w.status != http.StatusBadRequest {
			t.Errorf("Insert policy rules negative: Status is not BadRequest.")
			t.Logf("  Expect status: %+v\n", http.StatusBadRequest)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		expcrhs := []*share.CLUSRuleHead{
			{ID: rule1.ID, CfgType: rule1.CfgType},
			{ID: rule2.ID, CfgType: rule2.CfgType},
		}
		crhs := clusHelper.GetPolicyRuleList()
		if !reflect.DeepEqual(expcrhs, crhs) {
			t.Errorf("Insert policy rules negative: policy rule changed.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %+v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %+v\n", crh)
			}
		}
	}

	postTest()
}

func TestPolicyRuleReplaceTime(t *testing.T) {
	preTest()

	createdAt := time.Unix(1552681342, 0)
	lastModAt := time.Unix(1552681600, 0)
	// Initial data
	rule1 := share.CLUSPolicyRule{
		ID: 10, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.UserCreated,
		CreatedAt:    createdAt,
		LastModAt:    lastModAt,
	}
	mc := mockCache{rules: make(map[uint32]*api.RESTPolicyRule, 0)}
	mc.rules[rule1.ID] = mc.PolicyRule2REST(&rule1)
	cacher = &mc

	var mockCluster kv.MockCluster
	mockCluster.Init(
		[]*share.CLUSPolicyRule{&rule1},
		[]*share.CLUSGroup{
			{Name: "g1", CfgType: share.Learned},
		},
	)
	clusHelper = &mockCluster

	{
		rr1 := api.RESTPolicyRule{
			ID: rule1.ID, From: rule1.From, To: rule1.To, Action: rule1.Action,
			Ports:        api.PolicyPortAny,
			Applications: []string{"HTTP"},
			CfgType:      cfgTypeMap2Api[rule1.CfgType],
		}
		data := api.RESTPolicyRuleActionData{Rules: &[]*api.RESTPolicyRule{&rr1}}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule?scope=local", body, api.UserRoleAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Replace policy rules positive: Status is not OK.")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		nrule, _ := clusHelper.GetPolicyRule(rule1.ID)
		if nrule == nil {
			t.Errorf("Replace policy rules positive: rule1 should not be removed.")
		} else {
			if nrule.CreatedAt != createdAt {
				t.Errorf("Replace policy rules positive: rule1 created time should not be changed. %+v", nrule)
			}
			if nrule.LastModAt == lastModAt {
				t.Errorf("Replace policy rules positive: rule1 last modify time should be updated. %+v", nrule)
			}
		}
	}

	postTest()
}

func TestFedPolicyRuleReplace(t *testing.T) {
	preTest()

	// Initial data
	rule1 := share.CLUSPolicyRule{
		ID: 100001, From: "fed.gFed1", To: "fed.gFed1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.FederalCfg,
	}
	rule2 := share.CLUSPolicyRule{
		ID: 10, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.UserCreated,
	}
	rule3 := share.CLUSPolicyRule{
		ID: 10001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.Learned,
	}
	rule4 := share.CLUSPolicyRule{
		ID: 110001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.GroundCfg,
	}
	mc := mockCache{rules: make(map[uint32]*api.RESTPolicyRule, 0)}
	mc.rules[rule1.ID] = mc.PolicyRule2REST(&rule1)
	mc.rules[rule2.ID] = mc.PolicyRule2REST(&rule2)
	mc.rules[rule3.ID] = mc.PolicyRule2REST(&rule3)
	cacher = &mc

	var mockCluster kv.MockCluster
	mockCluster.Init(
		[]*share.CLUSPolicyRule{&rule1, &rule4, &rule2, &rule3},
		[]*share.CLUSGroup{
			{Name: "fed.gFed1", CfgType: share.FederalCfg},
			{Name: "g1", CfgType: share.Learned},
			{Name: "external", Reserved: true, CfgType: share.Learned},
		},
	)
	clusHelper = &mockCluster

	{
		type TCase struct {
			Rules []*api.RESTPolicyRule
		}
		testCases := []*TCase{
			{
				Rules: []*api.RESTPolicyRule{
					{ID: 10, From: "g1", To: "g1", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny, CfgType: api.CfgTypeUserCreated},
				},
			},
			{
				Rules: []*api.RESTPolicyRule{
					{ID: 100002, From: "fed.gFed1", To: "external", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny},
				},
			},
			{
				Rules: []*api.RESTPolicyRule{
					{ID: 100002, From: "fed.gFed1", To: "nodes", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny},
				},
			},
		}
		{
			testCase := testCases[0]
			data := api.RESTPolicyRuleActionData{
				Rules:  &testCase.Rules,
				Delete: &[]uint32{10001},
			}
			body, _ := json.Marshal(data)

			w := restCallFed("PATCH", "/v1/policy/rule?scope=local", body, api.UserRoleFedAdmin, api.FedRoleMaster)

			if w.status != http.StatusOK {
				t.Errorf("Replace policy rules positive: Status is not OK.")
				t.Logf("  Expect status: %+v\n", http.StatusOK)
				t.Logf("  Actual status: %+v\n", w.status)
			}

			expcrhs := []*share.CLUSRuleHead{
				{ID: rule1.ID, CfgType: rule1.CfgType},
				{ID: rule4.ID, CfgType: rule4.CfgType},
				{ID: testCase.Rules[0].ID, CfgType: share.UserCreated},
			}
			crhs := clusHelper.GetPolicyRuleList()
			if !reflect.DeepEqual(expcrhs, crhs) {
				t.Errorf("Replace policy rules positive: unexpected rule head.")
				for _, crh := range expcrhs {
					t.Logf("  Expect: %+v\n", crh)
				}
				for _, crh := range crhs {
					t.Logf("  Actual: %+v\n", crh)
				}
			}

			nrule, _ := clusHelper.GetPolicyRule(rule3.ID)
			if nrule != nil {
				t.Errorf("Replace policy rules positive: rule3 should be removed.")
			}
		}

		for idx := 1; idx < 3; idx++ {
			testCase := testCases[idx]
			data := api.RESTPolicyRuleActionData{Rules: &testCase.Rules}
			body, _ := json.Marshal(data)

			w := restCallFed("PATCH", "/v1/policy/rule?scope=fed", body, api.UserRoleFedAdmin, api.FedRoleMaster)

			if w.status != http.StatusOK {
				t.Errorf("Replace policy rules positive: Status is not OK.")
				t.Logf("  Expect status: %+v\n", http.StatusOK)
				t.Logf("  Actual status: %+v\n", w.status)
			}

			expcrhs := []*share.CLUSRuleHead{
				{ID: testCase.Rules[0].ID, CfgType: share.FederalCfg},
				{ID: rule4.ID, CfgType: rule4.CfgType},
				{ID: rule2.ID, CfgType: rule2.CfgType},
			}
			crhs := clusHelper.GetPolicyRuleList()
			if !reflect.DeepEqual(expcrhs, crhs) {
				t.Errorf("Replace policy rules positive: unexpected rule head.")
				for _, crh := range expcrhs {
					t.Logf("  Expect: %+v\n", crh)
				}
				for _, crh := range crhs {
					t.Logf("  Actual: %+v\n", crh)
				}
			}

			nrule, _ := clusHelper.GetPolicyRule(rule1.ID)
			if nrule != nil {
				t.Errorf("Replace policy rules positive: rule1 should be removed.")
			}
		}

	}

	postTest()
}

func TestFedPolicyRuleReplaceNegative(t *testing.T) {
	preTest()

	// Initial data
	rule1 := share.CLUSPolicyRule{
		ID: 100001, From: "fed.gFed1", To: "fed.gFed1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.FederalCfg,
	}
	mc := mockCache{rules: make(map[uint32]*api.RESTPolicyRule, 0)}
	mc.rules[rule1.ID] = mc.PolicyRule2REST(&rule1)
	cacher = &mc

	var mockCluster kv.MockCluster
	mockCluster.Init(
		[]*share.CLUSPolicyRule{&rule1},
		[]*share.CLUSGroup{
			{Name: "fed.gFed1", CfgType: share.FederalCfg},
			{Name: "g1", CfgType: share.Learned},
		},
	)
	clusHelper = &mockCluster

	{
		type TCase struct {
			Rules []*api.RESTPolicyRule
		}
		testCases := []*TCase{
			{
				Rules: []*api.RESTPolicyRule{
					{ID: 10, From: "g1", To: "g1", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny},
				},
			},
			{
				Rules: []*api.RESTPolicyRule{
					{ID: 110001, From: "g1", To: "g1", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny, CfgType: api.CfgTypeGround},
				},
			},
			{
				Rules: []*api.RESTPolicyRule{
					{ID: 110002, From: "g1", To: "g1", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny},
				},
			},
			{
				Rules: []*api.RESTPolicyRule{
					{ID: 100002, From: "fed.gFed1", To: "containers", Action: share.PolicyActionAllow, Ports: api.PolicyPortAny},
				},
			},
		}
		for _, testCase := range testCases {
			data := api.RESTPolicyRuleActionData{Rules: &testCase.Rules}
			body, _ := json.Marshal(data)

			w := restCallFed("PATCH", "/v1/policy/rule?scope=fed", body, api.UserRoleAdmin, api.FedRoleMaster)

			if w.status == http.StatusOK {
				t.Errorf("Replace policy rules positive: Status is not OK.")
				t.Logf("  Expect status: %+v\n", http.StatusOK)
				t.Logf("  Actual status: %+v\n", w.status)
			}
		}

	}

	postTest()
}

func TestPolicyRuleReplace(t *testing.T) {
	preTest()

	// Initial data
	rule1 := share.CLUSPolicyRule{
		ID: 10001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.Learned,
	}
	mc := mockCache{rules: make(map[uint32]*api.RESTPolicyRule, 0)}
	mc.rules[rule1.ID] = mc.PolicyRule2REST(&rule1)
	cacher = &mc

	var mockCluster kv.MockCluster
	mockCluster.Init(
		[]*share.CLUSPolicyRule{&rule1},
		[]*share.CLUSGroup{
			{Name: "g1", CfgType: share.Learned},
		},
	)
	clusHelper = &mockCluster

	{
		// Replace with learned rule removed
		rr2 := api.RESTPolicyRule{
			ID: 10, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		data := api.RESTPolicyRuleActionData{
			Rules:  &[]*api.RESTPolicyRule{&rr2},
			Delete: &[]uint32{10001},
		}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule?scope=local", body, api.UserRoleAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Replace policy rules positive: Status is not OK.")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		expcrhs := []*share.CLUSRuleHead{
			{ID: rr2.ID, CfgType: cfgTypeMapping[rr2.CfgType]},
		}
		crhs := clusHelper.GetPolicyRuleList()
		if !reflect.DeepEqual(expcrhs, crhs) {
			t.Errorf("Replace policy rules positive: unexpected rule head.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %+v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %+v\n", crh)
			}
		}

		nrule, _ := clusHelper.GetPolicyRule(rule1.ID)
		if nrule != nil {
			t.Errorf("Replace policy rules positive: rule1 should be removed.")
		}
	}

	{
		// Replace with rule id 0
		rr2 := api.RESTPolicyRule{
			ID: 10, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		rr3 := api.RESTPolicyRule{
			ID: 0, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		data := api.RESTPolicyRuleActionData{Rules: &[]*api.RESTPolicyRule{&rr2, &rr3}}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule?scope=local", body, api.UserRoleAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Replace policy rules with ID 0: Status is not OK.")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		expcrhs := []*share.CLUSRuleHead{
			{ID: rr2.ID, CfgType: cfgTypeMapping[rr2.CfgType]},
			{ID: 11, CfgType: cfgTypeMapping[rr3.CfgType]},
		}
		crhs := clusHelper.GetPolicyRuleList()
		if !reflect.DeepEqual(expcrhs, crhs) {
			t.Errorf("Replace policy rules with ID 0: unexpected rule head.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %+v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %+v\n", crh)
			}
		}

		nrule, _ := clusHelper.GetPolicyRule(rule1.ID)
		if nrule != nil {
			t.Errorf("Replace policy rules with ID 0: rule1 should be removed.")
		}
		nrule, _ = clusHelper.GetPolicyRule(11)
		if nrule == nil {
			t.Errorf("Replace policy rules with ID 0: new rule is not added.")
		}
	}

	{
		// Replace with rule ID 0 with potential conflict
		rr2 := api.RESTPolicyRule{
			ID: 0, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		rr3 := api.RESTPolicyRule{
			ID: 1, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		data := api.RESTPolicyRuleActionData{Rules: &[]*api.RESTPolicyRule{&rr2, &rr3}}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule?scope=local", body, api.UserRoleAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Replace policy rules with ID 0 and 1: Status is not OK.")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		expcrhs := []*share.CLUSRuleHead{
			{ID: 2, CfgType: cfgTypeMapping[rr2.CfgType]},
			{ID: 1, CfgType: cfgTypeMapping[rr3.CfgType]},
		}
		crhs := clusHelper.GetPolicyRuleList()
		if !reflect.DeepEqual(expcrhs, crhs) {
			t.Errorf("Replace policy rules with ID 0 and 1: unexpected rule head.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %+v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %+v\n", crh)
			}
		}

		nrule, _ := clusHelper.GetPolicyRule(rule1.ID)
		if nrule != nil {
			t.Errorf("Replace policy rules with ID 0 and 1: rule1 should be removed.")
		}
		nrule, _ = clusHelper.GetPolicyRule(2)
		if nrule == nil {
			t.Errorf("Replace policy rules with ID 0 and 1: new rule is not added.")
		}
	}

	{
		// Replace with rule using Host and Workload groups
		rr2 := api.RESTPolicyRule{
			ID: 100, From: "g1", To: "Host:1.2.3.4", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		rr3 := api.RESTPolicyRule{
			ID: 101, From: "Workload:10.1.1.1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		data := api.RESTPolicyRuleActionData{Rules: &[]*api.RESTPolicyRule{&rr2, &rr3}}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule?scope=local", body, api.UserRoleAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Replace policy rules with nv. groups: Status is not OK.")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		expcrhs := []*share.CLUSRuleHead{
			{ID: rr2.ID, CfgType: cfgTypeMapping[rr2.CfgType]},
			{ID: rr3.ID, CfgType: cfgTypeMapping[rr3.CfgType]},
		}
		crhs := clusHelper.GetPolicyRuleList()
		if !reflect.DeepEqual(expcrhs, crhs) {
			t.Errorf("Replace policy rules with nv. group: unexpected rule head.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %+v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %+v\n", crh)
			}
		}

		nrule, _ := clusHelper.GetPolicyRule(rule1.ID)
		if nrule != nil {
			t.Errorf("Replace policy rules with nv. group: rule1 should be removed.")
		}
	}

	{
		// delete all non-fed rules
		data := api.RESTPolicyRuleActionData{Rules: &[]*api.RESTPolicyRule{}}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule?scope=local", body, api.UserRoleAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Replace policy rules positive: Status is not OK.")
			t.Logf("  len: %v\n", len(*data.Rules))
			t.Logf("  Expect status: %v\n", http.StatusOK)
			t.Logf("  Actual status: %v\n", w.status)
		}

		expcrhs := []*share.CLUSRuleHead{}
		crhs := clusHelper.GetPolicyRuleList()
		if len(crhs) > 0 {
			t.Errorf("Replace policy rules positive(delete all): unexpected rule head.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %v\n", crh)
			}
		}
	}

	postTest()
}

func TestFedPolicyRuleReplaceWithSmallerPayload(t *testing.T) { // for the improvement "unpatched rules in the payload have id field set only"
	preTest()

	// Initial data
	rule1 := share.CLUSPolicyRule{
		ID: 100001, From: "fed.gFed1", To: "fed.gFed1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.FederalCfg,
	}

	var mockCluster kv.MockCluster
	mockCluster.Init(
		[]*share.CLUSPolicyRule{&rule1},
		[]*share.CLUSGroup{
			{Name: "fed.gFed1", CfgType: share.FederalCfg},
			{Name: "fed.gFed2", CfgType: share.FederalCfg},
			{Name: "g1", CfgType: share.Learned},
		},
	)
	clusHelper = &mockCluster
	// now it has rules 10001

	{
		// Replace with invalid new fed rules
		rr2 := api.RESTPolicyRule{
			ID: 100002,
		}
		data := api.RESTPolicyRuleActionData{Rules: &[]*api.RESTPolicyRule{&rr2}}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule?scope=fed", body, api.UserRoleFedAdmin)

		if w.status == http.StatusOK {
			t.Errorf("Replace with invalid new fed rules: Status is OK.")
			t.Logf("  Expect status: %+v\n", http.StatusBadRequest)
			t.Logf("  Actual status: %+v\n", w.status)
		}
	}
	// now it has rules 100002, 10001

	{
		// Replace with original rule & create new fed rule after existing rule
		rr1 := api.RESTPolicyRule{
			ID: 100001,
		}
		rr2 := api.RESTPolicyRule{
			ID: 100002, From: "fed.gFed1", To: "fed.gFed2", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeFederal,
		}
		rr3 := api.RESTPolicyRule{
			ID: 100003, From: "fed.gFed2", To: "fed.gFed1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeFederal,
		}
		data := api.RESTPolicyRuleActionData{Rules: &[]*api.RESTPolicyRule{&rr2, &rr3, &rr1}}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule?scope=fed", body, api.UserRoleFedAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Replace with original rule & create new fed rule after existing rule: Status is not OK.")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		expcrhs := []*share.CLUSRuleHead{
			{ID: rr2.ID, CfgType: cfgTypeMapping[rr2.CfgType]},
			{ID: rr3.ID, CfgType: cfgTypeMapping[rr3.CfgType]},
			{ID: rule1.ID, CfgType: rule1.CfgType},
		}
		crhs := clusHelper.GetPolicyRuleList()
		if !reflect.DeepEqual(expcrhs, crhs) {
			t.Errorf("Replace with original rule & create new fed rule after existing rule: unexpected rule head.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %+v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %+v\n", crh)
			}
		}

		nrule, _ := clusHelper.GetPolicyRule(rule1.ID)
		if nrule == nil {
			t.Errorf("Replace with original rule & create new fed rule after existing rule: rule1 should not be removed.")
		}
	}
	// now it has rules 100002, 100003, 10001

	{
		// Admin tries to replace fed rules with rule-order changed and a fed rule deleted
		rr1 := api.RESTPolicyRule{
			ID: 100001,
		}
		rr2 := api.RESTPolicyRule{
			ID: 100002,
		}
		data := api.RESTPolicyRuleActionData{Rules: &[]*api.RESTPolicyRule{&rr1, &rr2}}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule?scope=fed", body, api.UserRoleAdmin)

		if w.status == http.StatusOK {
			t.Errorf("Admin tries to replace fed rules with rule-order changed and a fed rule deleted: Status is OK.")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}
	}
	// now it has rules 100002, 100003, 10001

	{
		// Replace fed rules with rule-order changed and a fed rule deleted
		rr1 := api.RESTPolicyRule{
			ID: 100001,
		}
		rr2 := api.RESTPolicyRule{
			ID: 100002,
		}
		data := api.RESTPolicyRuleActionData{Rules: &[]*api.RESTPolicyRule{&rr1, &rr2}}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule?scope=fed", body, api.UserRoleFedAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Replace fed rules with rule-order changed and a fed rule deleted: Status is not OK.")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		expcrhs := []*share.CLUSRuleHead{
			{ID: rr1.ID, CfgType: share.FederalCfg},
			{ID: rr2.ID, CfgType: share.FederalCfg},
		}
		crhs := clusHelper.GetPolicyRuleList()
		if !reflect.DeepEqual(expcrhs, crhs) {
			t.Errorf("Replace fed rules with rule-order changed and a fed rule deleted: unexpected rule head.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %+v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %+v\n", crh)
			}
		}

		nrule, _ := clusHelper.GetPolicyRule(rule1.ID)
		if nrule == nil {
			t.Errorf("Replace fed rules with rule-order changed and a fed rule deleted: rule1 should not be removed.")
		}
		nrule, _ = clusHelper.GetPolicyRule(100003)
		if nrule != nil {
			t.Errorf("Replace fed rules with rule-order changed and a fed rule deleted: rule3 should be removed.")
		}
	}
	// now it has rules 100001 & 100002

	{
		// Create a new rule before existing rule(controller assign new rule's id)
		rr1 := api.RESTPolicyRule{
			ID: 100001,
		}
		rr2 := api.RESTPolicyRule{
			ID: 100002,
		}
		rr3 := api.RESTPolicyRule{
			ID: 0, From: "fed.gFed2", To: "fed.gFed2", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeFederal,
		}
		data := api.RESTPolicyRuleActionData{Rules: &[]*api.RESTPolicyRule{&rr3, &rr1, &rr2}}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule?scope=fed", body, api.UserRoleFedAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Create a new rule before existing rule(controller assign new rule's id): Status is not OK.")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		expcrhs := []*share.CLUSRuleHead{
			{ID: 100003, CfgType: share.FederalCfg},
			{ID: rr1.ID, CfgType: share.FederalCfg},
			{ID: rr2.ID, CfgType: share.FederalCfg},
		}
		crhs := clusHelper.GetPolicyRuleList()
		if !reflect.DeepEqual(expcrhs, crhs) {
			t.Errorf("Create a new rule before existing rule(controller assign new rule's id): unexpected rule head.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %+v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %+v\n", crh)
			}
		}
	}
	// now it has rules 100003, 100001 & 100002

	{
		// Replace to add a new fed rule ID with conflict ID
		rr1 := api.RESTPolicyRule{
			ID: 100001,
		}
		rr2 := api.RESTPolicyRule{
			ID: 100002,
		}
		rr3 := api.RESTPolicyRule{
			ID: 100003,
		}
		rr4 := api.RESTPolicyRule{
			ID: 100003, From: "fed.gFed2", To: "fed.gFed2", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeFederal,
		}
		data := api.RESTPolicyRuleActionData{Rules: &[]*api.RESTPolicyRule{&rr2, &rr3, &rr4, &rr1}}
		body, _ := json.Marshal(data)

		restCall("PATCH", "/v1/policy/rule?scope=fed", body, api.UserRoleAdmin)

		expcrhs := []*share.CLUSRuleHead{
			{ID: 100003, CfgType: share.FederalCfg},
			{ID: 100001, CfgType: share.FederalCfg},
			{ID: 100002, CfgType: share.FederalCfg},
		}
		crhs := clusHelper.GetPolicyRuleList()
		if !reflect.DeepEqual(expcrhs, crhs) {
			t.Errorf("Replace to add a new fed rule ID with conflict ID: unexpected rule head.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %+v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %+v\n", crh)
			}
		}
	}
	// now it has rules 100003, 100001 & 100002

	{
		// Replace with same fed rules but in different order
		rr1 := api.RESTPolicyRule{
			ID: 100001,
		}
		rr2 := api.RESTPolicyRule{
			ID: 100002,
		}
		rr3 := api.RESTPolicyRule{
			ID: 100003,
		}
		data := api.RESTPolicyRuleActionData{Rules: &[]*api.RESTPolicyRule{&rr2, &rr1, &rr3}}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule?scope=fed", body, api.UserRoleFedAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Replace with same fed rules but in different order: Status is not OK.")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		expcrhs := []*share.CLUSRuleHead{
			{ID: 100002, CfgType: share.FederalCfg},
			{ID: 100001, CfgType: share.FederalCfg},
			{ID: 100003, CfgType: share.FederalCfg},
		}
		crhs := clusHelper.GetPolicyRuleList()
		if !reflect.DeepEqual(expcrhs, crhs) {
			t.Errorf("Replace policy rules with same rules but in different order.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %+v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %+v\n", crh)
			}
		}
	}
	// now it has rules 100002, 100001 & 100003

	{
		rule1 := share.CLUSPolicyRule{
			ID: 100001, From: "fed.gFed1", To: "fed.gFed1", Action: share.PolicyActionAllow,
			Ports:        api.PolicyPortAny,
			Applications: []uint32{},
			CfgType:      share.FederalCfg,
		}
		rule2 := share.CLUSPolicyRule{
			ID: 100002, From: "fed.gFed1", To: "fed.gFed2", Action: share.PolicyActionAllow,
			Ports:        api.PolicyPortAny,
			Applications: []uint32{},
			CfgType:      share.FederalCfg,
		}
		rule3 := share.CLUSPolicyRule{
			ID: 100003, From: "fed.gFed2", To: "fed.gFed2", Action: share.PolicyActionAllow,
			Ports:        api.PolicyPortAny,
			Applications: []uint32{},
			CfgType:      share.FederalCfg,
		}
		mc := mockCache{rules: make(map[uint32]*api.RESTPolicyRule, 3)}
		mc.rules[rule1.ID] = mc.PolicyRule2REST(&rule1)
		mc.rules[rule2.ID] = mc.PolicyRule2REST(&rule2)
		mc.rules[rule3.ID] = mc.PolicyRule2REST(&rule3)
		cacher = &mc

		// delete specified rules
		data := api.RESTPolicyRuleActionData{Delete: &[]uint32{10003}}
		body, _ := json.Marshal(data)
		w := restCall("PATCH", "/v1/policy/rule?scope=fed", body, api.UserRoleFedAdmin)

		if w.status == http.StatusOK {
			t.Errorf("delete specified fed rules: Status is OK.")
			t.Logf("  len: %v\n", len(*data.Delete))
			t.Logf("  Expect status: %v\n", http.StatusBadRequest)
			t.Logf("  Actual status: %v\n", w.status)
		}

		data = api.RESTPolicyRuleActionData{Delete: &[]uint32{100002, 100003, 100004}}
		body, _ = json.Marshal(data)
		w = restCall("PATCH", "/v1/policy/rule?scope=fed", body, api.UserRoleFedAdmin)

		if w.status != http.StatusOK {
			t.Errorf("delete specified fed rules: Status is not OK.")
			t.Logf("  len: %v\n", len(*data.Delete))
			t.Logf("  Expect status: %v\n", http.StatusOK)
			t.Logf("  Actual status: %v\n", w.status)
		}

		expcrhs := []*share.CLUSRuleHead{
			{ID: 100001, CfgType: share.FederalCfg},
		}
		crhs := clusHelper.GetPolicyRuleList()
		if !reflect.DeepEqual(expcrhs, crhs) {
			t.Errorf("Delete specified fed policy rules: unexpected rule head.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %+v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %+v\n", crh)
			}
		}
	}
	// now it has rules 100001

	{
		// delete all fed rules
		data := api.RESTPolicyRuleActionData{Rules: &[]*api.RESTPolicyRule{}}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule?scope=fed", body, api.UserRoleFedAdmin)

		if w.status != http.StatusOK {
			t.Errorf("delete all fed rules: Status is not OK.")
			t.Logf("  len: %v\n", len(*data.Rules))
			t.Logf("  Expect status: %v\n", http.StatusOK)
			t.Logf("  Actual status: %v\n", w.status)
		}

		expcrhs := []*share.CLUSRuleHead{}
		crhs := clusHelper.GetPolicyRuleList()
		if len(crhs) > 0 {
			t.Errorf("delete all fed rules: unexpected rule head.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %v\n", crh)
			}
		}
	}

	postTest()
}

func TestPolicyRuleReplaceWithSmallerPayload(t *testing.T) { // for the improvement "unpatched rules in the payload have id field set only"
	preTest()

	// Initial data
	rule1 := share.CLUSPolicyRule{
		ID: 10001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.Learned,
	}

	var mockCluster kv.MockCluster
	mockCluster.Init(
		[]*share.CLUSPolicyRule{&rule1},
		[]*share.CLUSGroup{
			{Name: "g1", CfgType: share.Learned},
		},
	)
	clusHelper = &mockCluster

	{
		// Replace with learned rule unchanged, plus an invalid new user-created rule
		rr1 := api.RESTPolicyRule{
			ID: 10001,
		}
		rr2 := api.RESTPolicyRule{
			ID: 10,
		}
		data := api.RESTPolicyRuleActionData{Rules: &[]*api.RESTPolicyRule{&rr1, &rr2}}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule?scope=local", body, api.UserRoleAdmin)

		if w.status == http.StatusOK {
			t.Errorf("Replace with learned rule unchanged, plus an invalid new user-created rule: Status is OK.")
			t.Logf("  Expect status: %+v\n", http.StatusBadRequest)
			t.Logf("  Actual status: %+v\n", w.status)
		}
	}
	// now it has rule 10001 only

	{
		// Replace with learned rule unchanged, plus a valid new user-created rule
		rr1 := api.RESTPolicyRule{
			ID: 10001,
		}
		rr2 := api.RESTPolicyRule{
			ID: 10, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		data := api.RESTPolicyRuleActionData{Rules: &[]*api.RESTPolicyRule{&rr1, &rr2}}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule?scope=local", body, api.UserRoleAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Replace with learned rule unchanged, plus a valid new user-created rule: Status is not OK.")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		expcrhs := []*share.CLUSRuleHead{
			{ID: rule1.ID, CfgType: rule1.CfgType},
			{ID: rr2.ID, CfgType: cfgTypeMapping[rr2.CfgType]},
		}
		crhs := clusHelper.GetPolicyRuleList()
		if !reflect.DeepEqual(expcrhs, crhs) {
			t.Errorf("Replace with learned rule unchanged, plus a valid new user-created rule: unexpected rule head.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %+v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %+v\n", crh)
			}
		}

		nrule, _ := clusHelper.GetPolicyRule(rule1.ID)
		if nrule == nil {
			t.Errorf("Replace with learned rule unchanged, plus a valid new user-created rule: rule1 should not be removed.")
		}
	}
	// now it has rules 10001 & 10

	{
		// Create a new rule after existing rule(controller assign new rule's id)
		rr2 := api.RESTPolicyRule{
			ID: 10,
		}
		rr3 := api.RESTPolicyRule{
			ID: 0, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		data := api.RESTPolicyRuleActionData{
			Rules:  &[]*api.RESTPolicyRule{&rr2, &rr3},
			Delete: &[]uint32{10001},
		}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule?scope=local", body, api.UserRoleAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Create a new rule after existing rule(controller assign new rule's id): Status is not OK.")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		expcrhs := []*share.CLUSRuleHead{
			{ID: rr2.ID, CfgType: cfgTypeMapping[api.CfgTypeUserCreated]},
			{ID: 11, CfgType: cfgTypeMapping[rr3.CfgType]},
		}
		crhs := clusHelper.GetPolicyRuleList()
		if !reflect.DeepEqual(expcrhs, crhs) {
			t.Errorf("Create a new rule after existing rule(controller assign new rule's id): unexpected rule head.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %+v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %+v\n", crh)
			}
		}

		nrule, _ := clusHelper.GetPolicyRule(rule1.ID)
		if nrule != nil {
			t.Errorf("Create a new rule after existing rule(controller assign new rule's id): rule1 should be removed.")
		}
		nrule, _ = clusHelper.GetPolicyRule(11)
		if nrule == nil {
			t.Errorf("Create a new rule after existing rule(controller assign new rule's id): new rule is not added.")
		}
	}
	// now it has rules 10, 11

	{
		// Replace with rule ID 0 with potential conflict
		rr2 := api.RESTPolicyRule{
			ID: 0, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		rr3 := api.RESTPolicyRule{
			ID: 1, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		rr4 := api.RESTPolicyRule{
			ID: 11,
		}
		rr5 := api.RESTPolicyRule{
			ID: 10,
		}
		data := api.RESTPolicyRuleActionData{Rules: &[]*api.RESTPolicyRule{&rr2, &rr3, &rr4, &rr5}}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule?scope=local", body, api.UserRoleAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Replace with rule ID 0 with potential conflict: Status is not OK.")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		expcrhs := []*share.CLUSRuleHead{
			{ID: 12, CfgType: cfgTypeMapping[rr2.CfgType]},
			{ID: 1, CfgType: cfgTypeMapping[rr3.CfgType]},
			{ID: rr4.ID, CfgType: cfgTypeMapping[api.CfgTypeUserCreated]},
			{ID: rr5.ID, CfgType: cfgTypeMapping[api.CfgTypeUserCreated]},
		}
		crhs := clusHelper.GetPolicyRuleList()
		if !reflect.DeepEqual(expcrhs, crhs) {
			t.Errorf("Replace with rule ID 0 with potential conflict: unexpected rule head.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %+v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %+v\n", crh)
			}
		}

		nrule, _ := clusHelper.GetPolicyRule(12)
		if nrule == nil {
			t.Errorf("Replace with rule ID 0 with potential conflict: new rule is not added.")
		}
	}
	// now it has rules 12, 1, 11, 10

	{
		// Replace with same rules but in different order
		rr2 := api.RESTPolicyRule{
			ID: 11,
		}
		rr3 := api.RESTPolicyRule{
			ID: 10,
		}
		rr4 := api.RESTPolicyRule{
			ID: 12,
		}
		rr5 := api.RESTPolicyRule{
			ID: 1,
		}
		data := api.RESTPolicyRuleActionData{Rules: &[]*api.RESTPolicyRule{&rr2, &rr3, &rr4, &rr5}}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule?scope=local", body, api.UserRoleAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Replace with same rules but in different order: Status is not OK.")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		expcrhs := []*share.CLUSRuleHead{
			{ID: 11, CfgType: cfgTypeMapping[api.CfgTypeUserCreated]},
			{ID: 10, CfgType: cfgTypeMapping[api.CfgTypeUserCreated]},
			{ID: 12, CfgType: cfgTypeMapping[api.CfgTypeUserCreated]},
			{ID: 1, CfgType: cfgTypeMapping[api.CfgTypeUserCreated]},
		}
		crhs := clusHelper.GetPolicyRuleList()
		if !reflect.DeepEqual(expcrhs, crhs) {
			t.Errorf("Replace with same rules but in different order.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %+v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %+v\n", crh)
			}
		}

		nrule, _ := clusHelper.GetPolicyRule(12)
		if nrule == nil {
			t.Errorf("Replace with same rules but in different order: new rule is not added.")
		}
	}
	// now it has rules 11, 10, 12, 1

	{
		// Replace with rule using Host and Workload groups
		rr1 := api.RESTPolicyRule{
			ID: 1,
		}
		rr2 := api.RESTPolicyRule{
			ID: 100, From: "g1", To: "Host:1.2.3.4", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		rr3 := api.RESTPolicyRule{
			ID: 101, From: "Workload:10.1.1.1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		rr4 := api.RESTPolicyRule{
			ID: 102, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		data := api.RESTPolicyRuleActionData{Rules: &[]*api.RESTPolicyRule{&rr1, &rr2, &rr3, &rr4}}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule?scope=local", body, api.UserRoleAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Replace with rule using Host and Workload groups: Status is not OK.")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		expcrhs := []*share.CLUSRuleHead{
			{ID: rr1.ID, CfgType: cfgTypeMapping[api.CfgTypeUserCreated]},
			{ID: rr2.ID, CfgType: cfgTypeMapping[rr2.CfgType]},
			{ID: rr3.ID, CfgType: cfgTypeMapping[rr3.CfgType]},
			{ID: rr4.ID, CfgType: cfgTypeMapping[rr4.CfgType]},
		}
		crhs := clusHelper.GetPolicyRuleList()
		if !reflect.DeepEqual(expcrhs, crhs) {
			t.Errorf("Replace with rule using Host and Workload groups: unexpected rule head.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %+v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %+v\n", crh)
			}
		}

		nrule, _ := clusHelper.GetPolicyRule(rule1.ID)
		if nrule != nil {
			t.Errorf("Replace with rule using Host and Workload groups: rule1 should be removed.")
		}
	}
	// now it has rules 1, 100, 101, 102

	{
		rule1 := api.RESTPolicyRule{
			ID: 1, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		rule2 := api.RESTPolicyRule{
			ID: 100, From: "g1", To: "Host:1.2.3.4", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		rule3 := api.RESTPolicyRule{
			ID: 101, From: "Workload:10.1.1.1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		rule4 := api.RESTPolicyRule{
			ID: 102, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		mc := mockCache{rules: make(map[uint32]*api.RESTPolicyRule, 4)}
		mc.rules[rule1.ID] = &rule1
		mc.rules[rule2.ID] = &rule2
		mc.rules[rule3.ID] = &rule3
		mc.rules[rule4.ID] = &rule4
		cacher = &mc

		// delete specified rules
		data := api.RESTPolicyRuleActionData{Delete: &[]uint32{110001}} // delete ground rule
		body, _ := json.Marshal(data)
		w := restCall("PATCH", "/v1/policy/rule", body, api.UserRoleAdmin)

		if w.status == http.StatusOK {
			t.Errorf("delete specified ground rules: Status is OK.")
			t.Logf("  len: %v\n", len(*data.Delete))
			t.Logf("  Expect status: %v\n", http.StatusBadRequest)
			t.Logf("  Actual status: %v\n", w.status)
		}

		data = api.RESTPolicyRuleActionData{Delete: &[]uint32{100003}} // delete fed rule
		body, _ = json.Marshal(data)
		w = restCall("PATCH", "/v1/policy/rule", body, api.UserRoleAdmin)

		if w.status == http.StatusOK {
			t.Errorf("delete specified fed rules: Status is OK.")
			t.Logf("  len: %v\n", len(*data.Delete))
			t.Logf("  Expect status: %v\n", http.StatusBadRequest)
			t.Logf("  Actual status: %v\n", w.status)
		}

		data = api.RESTPolicyRuleActionData{Delete: &[]uint32{1, 100, 10004}}
		body, _ = json.Marshal(data)
		w = restCall("PATCH", "/v1/policy/rule", body, api.UserRoleAdmin)

		if w.status != http.StatusOK {
			t.Errorf("delete specified fed rules: Status is not OK.")
			t.Logf("  len: %v\n", len(*data.Delete))
			t.Logf("  Expect status: %v\n", http.StatusOK)
			t.Logf("  Actual status: %v\n", w.status)
		}

		expcrhs := []*share.CLUSRuleHead{
			{ID: 101, CfgType: share.UserCreated},
			{ID: 102, CfgType: share.UserCreated},
		}
		crhs := clusHelper.GetPolicyRuleList()
		if !reflect.DeepEqual(expcrhs, crhs) {
			t.Errorf("Delete specified fed policy rules: unexpected rule head.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %+v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %+v\n", crh)
			}
		}
	}
	// now it has rule 101, 102

	{
		// delete all rules
		data := api.RESTPolicyRuleActionData{Rules: &[]*api.RESTPolicyRule{}}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule?scope=local", body, api.UserRoleAdmin)

		if w.status != http.StatusOK {
			t.Errorf("delete all rules: Status is not OK.")
			t.Logf("  len: %v\n", len(*data.Rules))
			t.Logf("  Expect status: %v\n", http.StatusOK)
			t.Logf("  Actual status: %v\n", w.status)
		}

		expcrhs := []*share.CLUSRuleHead{}
		crhs := clusHelper.GetPolicyRuleList()
		if len(crhs) > 0 {
			t.Errorf("delete all rules: unexpected rule head.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %v\n", crh)
			}
		}
	}

	postTest()
}

func TestPolicyRuleReplaceDeleteCount(t *testing.T) {
	preTest()

	// Initial data
	rule0 := share.CLUSPolicyRule{
		ID: 10, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.UserCreated,
	}
	rule1 := share.CLUSPolicyRule{
		ID: 11, From: "g1", To: "g2", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{1002},
		CfgType:      share.UserCreated,
	}
	rule2 := share.CLUSPolicyRule{
		ID: 12, From: "g1", To: "g2", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{1001, 1002},
		CfgType:      share.UserCreated,
	}
	rule3 := share.CLUSPolicyRule{
		ID: 13, From: "g1", To: "g2", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.UserCreated,
	}
	rule11 := share.CLUSPolicyRule{
		ID: 10001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.Learned,
	}
	rule12 := share.CLUSPolicyRule{
		ID: 10002, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.Learned,
	}

	var mockCluster kv.MockCluster
	mockCluster.Init(
		[]*share.CLUSPolicyRule{&rule0, &rule1, &rule2, &rule3, &rule11, &rule12},
		[]*share.CLUSGroup{
			{Name: "g1", CfgType: share.Learned},
			{Name: "g2", CfgType: share.UserCreated},
		},
	)
	clusHelper = &mockCluster

	{
		rr0 := api.RESTPolicyRule{
			ID: 10, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		rr1 := api.RESTPolicyRule{
			ID: 11, From: "g1", To: "g2", Action: share.PolicyActionAllow,
			Ports:        api.PolicyPortAny,
			Applications: []string{"HTTP"},
			CfgType:      api.CfgTypeUserCreated,
		}
		rr2 := api.RESTPolicyRule{
			ID: 12, From: "g1", To: "g2", Action: share.PolicyActionAllow,
			Ports:        api.PolicyPortAny,
			Applications: []string{"HTTP", "SSL"},
			CfgType:      api.CfgTypeUserCreated,
		}
		rr3 := api.RESTPolicyRule{
			ID: 13, From: "g1", To: "g2", Action: share.PolicyActionDeny,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		rr11 := api.RESTPolicyRule{
			ID: 10001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeLearned,
		}
		data := api.RESTPolicyRuleActionData{
			Rules:  &[]*api.RESTPolicyRule{&rr0, &rr1, &rr2, &rr3, &rr11},
			Delete: &[]uint32{10002},
		}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule?scope=local", body, api.UserRoleAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Replace policy rules delete count: Status is not OK.")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		expcrhs := []*share.CLUSRuleHead{
			{ID: rr0.ID, CfgType: cfgTypeMapping[rr0.CfgType]},
			{ID: rr1.ID, CfgType: cfgTypeMapping[rr1.CfgType]},
			{ID: rr2.ID, CfgType: cfgTypeMapping[rr2.CfgType]},
			{ID: rr3.ID, CfgType: cfgTypeMapping[rr3.CfgType]},
			{ID: rr11.ID, CfgType: cfgTypeMapping[rr11.CfgType]},
		}
		crhs := clusHelper.GetPolicyRuleList()
		if !reflect.DeepEqual(expcrhs, crhs) {
			t.Errorf("Replace policy rules delete count: unexpected rule head.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %+v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %+v\n", crh)
			}
		}

		if mockCluster.DeletePolicyRuleCount != 1 {
			t.Errorf("Replace policy rules delete count: unexpected delete count.")
			t.Logf("  Expect: %+v\n", 3)
			t.Logf("  Actual: %+v\n", mockCluster.DeletePolicyRuleCount)
		}
	}

	postTest()
}

func TestPolicyRuleReplaceOrder(t *testing.T) {
	preTest()

	// Initial data
	rule0 := share.CLUSPolicyRule{
		ID: 10, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.UserCreated,
	}
	rule1 := share.CLUSPolicyRule{
		ID: 10001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.Learned,
	}
	rule2 := share.CLUSPolicyRule{
		ID: 10002, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.Learned,
	}

	var mockCluster kv.MockCluster
	mockCluster.Init(
		[]*share.CLUSPolicyRule{&rule0, &rule1, &rule2},
		[]*share.CLUSGroup{
			{Name: "g1", CfgType: share.Learned},
			{Name: "g2", CfgType: share.UserCreated},
		},
	)
	clusHelper = &mockCluster

	{
		rr0 := api.RESTPolicyRule{
			ID: 10, From: "g1", To: "g2", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		rr1 := api.RESTPolicyRule{
			ID: 10001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeLearned,
		}
		rr2 := api.RESTPolicyRule{
			ID: 10002, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeLearned,
		}
		data := api.RESTPolicyRuleActionData{Rules: &[]*api.RESTPolicyRule{&rr2, &rr1, &rr0}}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule?scope=local", body, api.UserRoleAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Replace policy rules order: Status is not OK.")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		expcrhs := []*share.CLUSRuleHead{
			{ID: rr2.ID, CfgType: cfgTypeMapping[rr2.CfgType]},
			{ID: rr1.ID, CfgType: cfgTypeMapping[rr1.CfgType]},
			{ID: rr0.ID, CfgType: cfgTypeMapping[rr0.CfgType]},
		}
		crhs := clusHelper.GetPolicyRuleList()
		if !reflect.DeepEqual(expcrhs, crhs) {
			t.Errorf("Replace policy rules order: unexpected rule head.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %+v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %+v\n", crh)
			}
		}

		rule0.To = "g2"
		nrule, _ := clusHelper.GetPolicyRule(rule0.ID)
		if !compareCLUSRules(nrule, &rule0) {
			t.Errorf("Replace policy rules order: unexpected rule change.")
			t.Logf("  Expect status: %+v\n", nrule)
			t.Logf("  Actual status: %+v\n", rule0)
		}
	}

	postTest()
}

func TestPolicyRuleReplaceFedRuleOrder(t *testing.T) {
	preTest()

	// Initial data
	rule0 := share.CLUSPolicyRule{
		ID: 10, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.UserCreated,
	}
	rule1 := share.CLUSPolicyRule{
		ID: 10001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.Learned,
	}
	rule2 := share.CLUSPolicyRule{
		ID: 10002, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.Learned,
	}
	rule3 := share.CLUSPolicyRule{ // fed rule
		ID: 100001, From: "fed.gFed1", To: "fed.gFed1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.FederalCfg,
	}

	var mockCluster kv.MockCluster
	mockCluster.Init(
		[]*share.CLUSPolicyRule{&rule3, &rule0, &rule1, &rule2},
		[]*share.CLUSGroup{
			{Name: "g1", CfgType: share.Learned},
			{Name: "g2", CfgType: share.UserCreated},
			{Name: "fed.gFed1", CfgType: share.FederalCfg},
		},
	)
	clusHelper = &mockCluster

	{
		rr0 := api.RESTPolicyRule{
			ID: 10, From: "g1", To: "g2", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		rr1 := api.RESTPolicyRule{
			ID: 10001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeLearned,
		}
		rr2 := api.RESTPolicyRule{
			ID: 10002, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeLearned,
		}
		rr3 := api.RESTPolicyRule{
			ID: 100001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeFederal,
		}
		data := api.RESTPolicyRuleActionData{Rules: &[]*api.RESTPolicyRule{&rr2, &rr1, &rr0, &rr3}} // intentionally put fed policy at the end of the list
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule?scope=local", body, api.UserRoleAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Replace policy rules order: Status is not OK.")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		expcrhs := []*share.CLUSRuleHead{
			{ID: rr3.ID, CfgType: cfgTypeMapping[rr3.CfgType]}, // position of fed policy is not changed
			{ID: rr2.ID, CfgType: cfgTypeMapping[rr2.CfgType]},
			{ID: rr1.ID, CfgType: cfgTypeMapping[rr1.CfgType]},
			{ID: rr0.ID, CfgType: cfgTypeMapping[rr0.CfgType]},
		}
		crhs := clusHelper.GetPolicyRuleList()
		if !reflect.DeepEqual(expcrhs, crhs) {
			t.Errorf("Replace policy rules order: unexpected rule head.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %+v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %+v\n", crh)
			}
		}

		rule0.To = "g2"
		nrule, _ := clusHelper.GetPolicyRule(rule0.ID)
		if !compareCLUSRules(nrule, &rule0) {
			t.Errorf("Replace policy rules order: unexpected rule change.")
			t.Logf("  Expect status: %+v\n", nrule)
			t.Logf("  Actual status: %+v\n", rule0)
		}
	}

	postTest()
}

func TestPolicyRuleReplaceWrongID(t *testing.T) {
	preTest()

	// Initial data
	rule1 := share.CLUSPolicyRule{
		ID: 10001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.Learned,
	}

	var mockCluster kv.MockCluster
	mockCluster.Init(
		[]*share.CLUSPolicyRule{&rule1},
		[]*share.CLUSGroup{
			{Name: "g1", CfgType: share.Learned},
		},
	)
	clusHelper = &mockCluster

	{
		// Invalid ID
		rr1 := api.RESTPolicyRule{
			ID: 10005, From: "g1", To: "g1", Action: share.PolicyActionDeny,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		rr2 := api.RESTPolicyRule{
			ID: 10001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeLearned,
		}
		data := api.RESTPolicyRuleActionData{Rules: &[]*api.RESTPolicyRule{
			&rr1, &rr2,
		}}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule?scope=local", body, api.UserRoleAdmin)

		if w.status != http.StatusBadRequest {
			t.Errorf("Replace policy rules wrong ID: unexpected status.")
			t.Logf("  Expect status: %+v\n", http.StatusBadRequest)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		expcrhs := []*share.CLUSRuleHead{
			{ID: rr2.ID, CfgType: cfgTypeMapping[rr2.CfgType]},
		}
		crhs := clusHelper.GetPolicyRuleList()
		if !reflect.DeepEqual(expcrhs, crhs) {
			t.Errorf("Replace policy rules wrong ID: unexpected rule head.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %+v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %+v\n", crh)
			}
		}

		nrule, _ := clusHelper.GetPolicyRule(10001)
		if !compareCLUSRules(nrule, &rule1) {
			t.Errorf("Replace policy rules wrong ID: rule1 shouldn't be changed.")
			t.Logf("  Expect status: %+v\n", nrule)
			t.Logf("  Actual status: %+v\n", rule1)
		}
		nrule, _ = clusHelper.GetPolicyRule(10005)
		if nrule != nil {
			t.Errorf("Replace policy rules wrong ID: invalid rule shouldn't be added.")
		}
	}

	postTest()
}

func TestPolicyRuleReplaceWrongLearned(t *testing.T) {
	preTest()

	// Initial data
	rule1 := share.CLUSPolicyRule{
		ID: 10001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.Learned,
	}

	var mockCluster kv.MockCluster
	mockCluster.Init(
		[]*share.CLUSPolicyRule{&rule1},
		[]*share.CLUSGroup{
			{Name: "g1", CfgType: share.Learned},
		},
	)
	clusHelper = &mockCluster

	{
		// Invalid ID
		rr1 := api.RESTPolicyRule{
			ID: 10005, From: "g1", To: "g1", Action: share.PolicyActionDeny,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeLearned,
		}
		rr2 := api.RESTPolicyRule{
			ID: 10001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeLearned,
		}
		rr3 := api.RESTPolicyRule{
			ID: 1, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		data := api.RESTPolicyRuleActionData{Rules: &[]*api.RESTPolicyRule{
			&rr1, &rr2, &rr3,
		}}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule?scope=local", body, api.UserRoleAdmin)

		// 8/23/2018 we will ignore the added learned-rule instead of rejecting the request
		if w.status != http.StatusOK {
			t.Errorf("Replace policy rules wrong learned: unexpected status.")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		expcrhs := []*share.CLUSRuleHead{
			{ID: rr2.ID, CfgType: cfgTypeMapping[rr2.CfgType]},
			{ID: rr3.ID, CfgType: cfgTypeMapping[rr3.CfgType]},
		}
		crhs := clusHelper.GetPolicyRuleList()
		if !reflect.DeepEqual(expcrhs, crhs) {
			t.Errorf("Replace policy rules wrong learned: unexpected rule head.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %+v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %+v\n", crh)
			}
		}

		nrule, _ := clusHelper.GetPolicyRule(10001)
		if !compareCLUSRules(&rule1, nrule) {
			t.Errorf("Replace policy rules wrong learned: rule1 shouldn't be changed.")
			t.Logf("  Expect status: %+v\n", nrule)
			t.Logf("  Actual status: %+v\n", rule1)
		}
		nrule, _ = clusHelper.GetPolicyRule(10005)
		if nrule != nil {
			t.Errorf("Replace policy rules wrong learned: invalid rule shouldn't be added.")
		}
	}

	postTest()
}

func TestPolicyRuleNsUserDeleteRule(t *testing.T) {
	preTest()

	// Initial data
	rule10 := share.CLUSPolicyRule{ // namespace user cannot see this rule
		ID: 10, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.UserCreated,
	}
	rule11 := share.CLUSPolicyRule{ // namespace user can see & config it !!!!
		ID: 11, From: "g3", To: "g4", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{1002},
		CfgType:      share.UserCreated,
	}
	rule12 := share.CLUSPolicyRule{ // namespace user can see & config it !!!!
		ID: 12, From: "g4", To: "g3", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{1001, 1002},
		CfgType:      share.UserCreated,
	}
	rule13 := share.CLUSPolicyRule{ // namespace user cannot see this rule
		ID: 13, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.UserCreated,
	}
	rule14 := share.CLUSPolicyRule{ // namespace user can see but not modify this rule
		ID: 14, From: "g1", To: "g3", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.UserCreated,
	}
	rule15 := share.CLUSPolicyRule{ // namespace user can see but not modify this rule
		ID: 15, From: "g4", To: "g2", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.UserCreated,
	}
	rule10001 := share.CLUSPolicyRule{ // namespace user cannot see this rule
		ID: 10001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.Learned,
	}
	rule10002 := share.CLUSPolicyRule{ // namespace user cannot see this rule
		ID: 10002, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.Learned,
	}
	rule10003 := share.CLUSPolicyRule{ // namespace user can see & delete it !!!!
		ID: 10003, From: "g3", To: "g4", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.Learned,
	}
	rule10004 := share.CLUSPolicyRule{ // namespace user can see & delete it
		ID: 10004, From: "g4", To: "g3", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.Learned,
	}
	rule10005 := share.CLUSPolicyRule{ // namespace user can not see
		ID: 10005, From: "g1", To: "g2", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.Learned,
	}
	rule100001 := share.CLUSPolicyRule{ // namespace user cannot see this rule
		ID: 100001, From: "g5", To: "g6", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.FederalCfg,
	}
	rule100002 := share.CLUSPolicyRule{ // namespace user cannot see this rule
		ID: 100002, From: "g6", To: "g5", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.FederalCfg,
	}

	var mockCluster kv.MockCluster
	initRules := []*share.CLUSPolicyRule{&rule100001, &rule100002, &rule10, &rule11, &rule12, &rule13, &rule14, &rule15, &rule10001, &rule10002, &rule10003, &rule10004, &rule10005}
	initGroups := []*share.CLUSGroup{
		{Name: "g1", CfgType: share.Learned},
		{Name: "g2", CfgType: share.UserCreated},
		{Name: "g3", CfgType: share.UserCreated, CreaterDomains: []string{"domain1", "domain2"}},
		{Name: "g4", CfgType: share.UserCreated, CreaterDomains: []string{"domain1", "domain2"}},
		{Name: "g5", CfgType: share.FederalCfg},
		{Name: "g6", CfgType: share.FederalCfg},
	}
	initKvAndCache(&mockCluster, initRules, initGroups)

	{
		rNew10 := api.RESTPolicyRule{
			ID: 10, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		rNew11 := api.RESTPolicyRule{
			ID: 11, From: "g3", To: "g4", Action: share.PolicyActionAllow,
			Applications: []string{"SSL"},
			Ports:        api.PolicyPortAny,
			CfgType:      api.CfgTypeUserCreated,
		}
		// rule12 is deleted
		rNew13 := api.RESTPolicyRule{
			ID: 13, From: "g1", To: "g1", Action: share.PolicyActionDeny,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		rNew14 := api.RESTPolicyRule{
			ID: 14, From: "g1", To: "g3", Action: share.PolicyActionAllow,
			Applications: []string{"any"},
			Ports:        api.PolicyPortAny,
			CfgType:      api.CfgTypeUserCreated,
		}
		rNew15 := api.RESTPolicyRule{
			ID: 15, From: "g4", To: "g2", Action: share.PolicyActionAllow,
			Applications: []string{"any"},
			Ports:        api.PolicyPortAny,
			CfgType:      api.CfgTypeUserCreated,
		}
		rNew10001 := api.RESTPolicyRule{
			ID: 10001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeLearned,
		}
		rNew10002 := api.RESTPolicyRule{
			ID: 10002, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeLearned,
		}
		// r10003 is deleted
		rNew10004 := api.RESTPolicyRule{
			ID: 10004, From: "g4", To: "g3", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeLearned,
		}
		rNew10005 := api.RESTPolicyRule{
			ID: 10005, From: "g1", To: "g2", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeLearned,
		}
		rNew100001 := api.RESTPolicyRule{
			ID: 100001, From: "g5", To: "g6", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeFederal,
		}
		rNew100002 := api.RESTPolicyRule{
			ID: 100002, From: "g6", To: "g5", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeFederal,
		}

		rNew14Modified := rNew14
		rNew14Modified.Action = share.PolicyActionDeny

		user1 := makeLocalUserWithRole("user1", "111111", api.UserRoleNone,
			map[string][]string{api.UserRoleAdmin: {"domain1", "domain2"}},
		)
		_ = clusHelper.CreateUser(user1)

		w := login("user1", "111111")
		token1 := getLoginToken(w)

		// get initial policy rules
		w = restCallToken("GET", "/v1/policy/rule", nil, token1)
		if w.status != http.StatusOK {
			t.Errorf("Failed to get policy ruless: Status is not OK.")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v, body: %+v\n", w.status, string(w.body))
		}
		// can see rule11, rule12, rule14, rule15, rule10003, rule10004
		// but rule14, rule15, rule10006, rule10007 are read-only
		/*
			var resp api.RESTPolicyRulesData
			json.Unmarshal(w.body, &resp)
			for _, r := range resp.Rules {
				fmt.Printf("  Got rule=%d, cfgType=%v\n", r.ID, r.CfgType)
			}
			fmt.Printf("  Got rules=%d\n", len(resp.Rules))
		*/

		// replace with new rules, trying to delete rule12, rule14, rule15, rule10003
		data := api.RESTPolicyRuleActionData{
			Rules:  &[]*api.RESTPolicyRule{&rNew11, &rNew10004},
			Delete: &[]uint32{12, 14, 15, 10003},
		} // should fail because rule14, rule15 are read-only
		body, _ := json.Marshal(data)
		w = restCallToken("PATCH", "/v1/policy/rule?scope=local", body, token1)
		if w.status == http.StatusOK {
			t.Errorf("Surprised to replace policy rules successfully: Status is OK.")
		} else {
			var resp api.RESTErrorReadOnlyRules
			_ = json.Unmarshal(w.body, &resp)
			if len(resp.ReadOnlyRuleIDs) == 2 && ((resp.ReadOnlyRuleIDs[0] == 14 && resp.ReadOnlyRuleIDs[1] == 15) || (resp.ReadOnlyRuleIDs[0] == 15 && resp.ReadOnlyRuleIDs[1] == 14)) {
			} else {
				t.Errorf("Wrong error read-only rule IDs: %+v", resp.ReadOnlyRuleIDs)
			}
		}

		// replace with new rules, trying to delete rule12, rule10003 and modify rule14
		data = api.RESTPolicyRuleActionData{
			Rules:  &[]*api.RESTPolicyRule{&rNew11, &rNew14Modified, &rNew15, &rNew10004},
			Delete: &[]uint32{12, 10003},
		} // should fail because rule14, rule15 are read-only
		body, _ = json.Marshal(data)
		w = restCallToken("PATCH", "/v1/policy/rule?scope=local", body, token1)
		if w.status == http.StatusOK {
			t.Errorf("Surprised to replace policy rules successfully: Status is OK.")
		} else {
			var resp api.RESTErrorReadOnlyRules
			_ = json.Unmarshal(w.body, &resp)
			if len(resp.ReadOnlyRuleIDs) == 1 && (resp.ReadOnlyRuleIDs[0] == 14) {
			} else {
				t.Errorf("Wrong error read-only rule IDs: %+v", resp.ReadOnlyRuleIDs)
			}
		}

		// replace with new rules. try to delete rule12, rule10003 & switch order of rNew14 & rNew15
		data = api.RESTPolicyRuleActionData{
			Rules:  &[]*api.RESTPolicyRule{&rNew11, &rNew15, &rNew14, &rNew10004},
			Delete: &[]uint32{12, 10003},
		} // should succeed
		body, _ = json.Marshal(data)
		w = restCallToken("PATCH", "/v1/policy/rule?scope=local", body, token1)
		if w.status != http.StatusOK {
			t.Errorf("Replace policy rules delete count: Status is not OK.")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		expcrhs := []*share.CLUSRuleHead{
			{ID: rNew100001.ID, CfgType: cfgTypeMapping[rNew100001.CfgType]},
			{ID: rNew100002.ID, CfgType: cfgTypeMapping[rNew100002.CfgType]},
			{ID: rNew10.ID, CfgType: cfgTypeMapping[rNew10.CfgType]},
			{ID: rNew11.ID, CfgType: cfgTypeMapping[rNew11.CfgType]},
			{ID: rNew15.ID, CfgType: cfgTypeMapping[rNew15.CfgType]},
			// Because rule13 cannot be seen by this ns user, its position in the whole list is always the same !
			// Initially:
			//		whole list : 100001, 100002, 10, 11, 12, 13, 14, 15, ....
			// 		ns user see: 11, 12, 14, 15, ....
			// When ns user delete 12 & switch 14 and 15, first the whole list becomes:
			//		100001, 100002, 10, 11, [], 13, 14, 15, ....	// delete 12
			// ->   100001, 100002, 10, 11, [], 13, 15, 14, .... 	// switch 14 & 15
			// 		if we stop here, ns user see: 11, 15, 14, ....
			// Then controller move 15(the frist seenable entry after the empty entry) to the empty entry [] & do the same thing for the following rules
			// So the whole list becomes:
			//		100001, 100002, 10, 11, [15], 13, [  ], 14, ....
			// ->	100001, 100002, 10, 11, [15], 13, [14], [], ....
			// That's why the final expected order is:
			//		whole list : 100001, 100002, 10, 11, 15, 13, 14, ....
			{ID: rNew13.ID, CfgType: cfgTypeMapping[rNew13.CfgType]},
			{ID: rNew14.ID, CfgType: cfgTypeMapping[rNew14.CfgType]},
			{ID: rNew10001.ID, CfgType: cfgTypeMapping[rNew10001.CfgType]},
			{ID: rNew10002.ID, CfgType: cfgTypeMapping[rNew10002.CfgType]},
			{ID: rNew10004.ID, CfgType: cfgTypeMapping[rNew10004.CfgType]},
			{ID: rNew10005.ID, CfgType: cfgTypeMapping[rNew10005.CfgType]},
		}
		crhs := clusHelper.GetPolicyRuleList()
		if !reflect.DeepEqual(expcrhs, crhs) {
			t.Errorf("Replace policy rules delete count: unexpected rule head.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %+v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %+v\n", crh)
			}
		}
	}

	postTest()
}

func TestPolicyRuleAddRuleAssignID(t *testing.T) {
	preTest()

	// Initial data
	rule0 := share.CLUSPolicyRule{
		ID: 10, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.UserCreated,
	}
	rule1 := share.CLUSPolicyRule{ // namespace user can see & config it
		ID: 11, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{1002},
		CfgType:      share.UserCreated,
	}
	rule11 := share.CLUSPolicyRule{
		ID: 10001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.Learned,
	}
	rule12 := share.CLUSPolicyRule{
		ID: 10002, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.Learned,
	}
	rule21 := share.CLUSPolicyRule{
		ID: 100001, From: "g5", To: "g6", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.FederalCfg,
	}
	rule22 := share.CLUSPolicyRule{
		ID: 100002, From: "g6", To: "g5", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.FederalCfg,
	}

	mc := mockCache{rules: make(map[uint32]*api.RESTPolicyRule, 0)}
	mc.rules[rule21.ID] = mc.PolicyRule2REST(&rule21)
	mc.rules[rule22.ID] = mc.PolicyRule2REST(&rule22)
	mc.rules[rule11.ID] = mc.PolicyRule2REST(&rule11)
	mc.rules[rule12.ID] = mc.PolicyRule2REST(&rule12)
	mc.rules[rule0.ID] = mc.PolicyRule2REST(&rule0)
	mc.rules[rule1.ID] = mc.PolicyRule2REST(&rule1)
	cacher = &mc

	var mockCluster kv.MockCluster
	mockCluster.Init(
		[]*share.CLUSPolicyRule{&rule21, &rule22, &rule0, &rule1, &rule11, &rule12},
		[]*share.CLUSGroup{
			{Name: "g1", CfgType: share.Learned},
			{Name: "g2", CfgType: share.UserCreated},
			{Name: "g5", CfgType: share.FederalCfg},
			{Name: "g6", CfgType: share.FederalCfg},
		},
	)
	clusHelper = &mockCluster

	{
		rr0 := api.RESTPolicyRule{
			ID: 10, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		rr1 := api.RESTPolicyRule{
			ID: 11, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Applications: []string{"SSL"},
			Ports:        api.PolicyPortAny,
			CfgType:      api.CfgTypeUserCreated,
		}
		rr2 := api.RESTPolicyRule{
			ID: 12, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		rr3 := api.RESTPolicyRule{
			ID: 0, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		rr4 := api.RESTPolicyRule{
			ID: 0, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		rr11 := api.RESTPolicyRule{
			ID: 10001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeLearned,
		}
		rr12 := api.RESTPolicyRule{
			ID: 10002, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeLearned,
		}
		rr21 := api.RESTPolicyRule{
			ID: 100001, From: "g5", To: "g6", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeFederal,
		}
		rr22 := api.RESTPolicyRule{
			ID: 100002, From: "g6", To: "g5", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeFederal,
		}

		data := api.RESTPolicyRuleActionData{Rules: &[]*api.RESTPolicyRule{&rr0, &rr1, &rr2, &rr11, &rr3, &rr12, &rr4}} // add rr2(rule id=12), rr3(auth-gen id), rr4(auth-gen id)
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule?scope=local", body, api.UserRoleAdmin)
		if w.status != http.StatusOK {
			t.Errorf("Replace policy rules: Status is not OK.")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		rr3.ID = 13
		rr4.ID = 14
		expcrhs := []*share.CLUSRuleHead{
			{ID: rr21.ID, CfgType: cfgTypeMapping[rr21.CfgType]},
			{ID: rr22.ID, CfgType: cfgTypeMapping[rr22.CfgType]},
			{ID: rr0.ID, CfgType: cfgTypeMapping[rr0.CfgType]},
			{ID: rr1.ID, CfgType: cfgTypeMapping[rr1.CfgType]},
			{ID: rr2.ID, CfgType: cfgTypeMapping[rr2.CfgType]},
			{ID: rr11.ID, CfgType: cfgTypeMapping[rr11.CfgType]},
			{ID: rr3.ID, CfgType: cfgTypeMapping[rr3.CfgType]},
			{ID: rr12.ID, CfgType: cfgTypeMapping[rr12.CfgType]},
			{ID: rr4.ID, CfgType: cfgTypeMapping[rr4.CfgType]},
		}
		crhs := clusHelper.GetPolicyRuleList()
		if !reflect.DeepEqual(expcrhs, crhs) {
			t.Errorf("Replace policy rules delete count: unexpected rule head.")
			for _, crh := range expcrhs {
				t.Logf("  Expect: %+v\n", crh)
			}
			for _, crh := range crhs {
				t.Logf("  Actual: %+v\n", crh)
			}
		}
	}

	postTest()
}

func TestPolicyRuleReplaceRuleDuplicateID(t *testing.T) {
	preTest()

	// Initial data
	rule0 := share.CLUSPolicyRule{
		ID: 10, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.UserCreated,
	}
	rule1 := share.CLUSPolicyRule{ // namespace user can see & config it
		ID: 11, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{1002},
		CfgType:      share.UserCreated,
	}
	rule11 := share.CLUSPolicyRule{
		ID: 10001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.Learned,
	}
	rule12 := share.CLUSPolicyRule{
		ID: 10002, From: "g1", To: "g1", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.Learned,
	}
	rule21 := share.CLUSPolicyRule{
		ID: 100001, From: "g5", To: "g6", Action: share.PolicyActionAllow,
		Ports:        api.PolicyPortAny,
		Applications: []uint32{},
		CfgType:      share.FederalCfg,
	}

	mc := mockCache{rules: make(map[uint32]*api.RESTPolicyRule, 0)}
	mc.rules[rule21.ID] = mc.PolicyRule2REST(&rule21)
	mc.rules[rule11.ID] = mc.PolicyRule2REST(&rule11)
	mc.rules[rule12.ID] = mc.PolicyRule2REST(&rule12)
	mc.rules[rule0.ID] = mc.PolicyRule2REST(&rule0)
	mc.rules[rule1.ID] = mc.PolicyRule2REST(&rule1)
	cacher = &mc

	var mockCluster kv.MockCluster
	mockCluster.Init(
		[]*share.CLUSPolicyRule{&rule21, &rule0, &rule1, &rule11, &rule12},
		[]*share.CLUSGroup{
			{Name: "g1", CfgType: share.Learned},
			{Name: "g2", CfgType: share.UserCreated},
			{Name: "g5", CfgType: share.FederalCfg},
			{Name: "g6", CfgType: share.FederalCfg},
		},
	)
	clusHelper = &mockCluster

	{
		rr0 := api.RESTPolicyRule{
			ID: 10, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		rr1 := api.RESTPolicyRule{
			ID: 11, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Applications: []string{"SSL"},
			Ports:        api.PolicyPortAny,
			CfgType:      api.CfgTypeUserCreated,
		}
		rr2 := api.RESTPolicyRule{
			ID: 12, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		rr3 := api.RESTPolicyRule{
			ID: 12, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeUserCreated,
		}
		rr11 := api.RESTPolicyRule{
			ID: 10001, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeLearned,
		}
		rr12 := api.RESTPolicyRule{
			ID: 10002, From: "g1", To: "g1", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeLearned,
		}
		rr21 := api.RESTPolicyRule{
			ID: 100001, From: "g5", To: "g6", Action: share.PolicyActionAllow,
			Ports:   api.PolicyPortAny,
			CfgType: api.CfgTypeFederal,
		}

		data := api.RESTPolicyRuleActionData{Rules: &[]*api.RESTPolicyRule{&rr21, &rr0, &rr1, &rr2, &rr11, &rr3, &rr12}} // add rr2(rule id=12), rr3(rule id=12)
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/policy/rule?scope=local", body, api.UserRoleAdmin)
		if w.status != http.StatusBadRequest {
			t.Errorf("Replace policy rules duplicate id: Status is not 400.")
			t.Logf("  Expect status: %+v\n", http.StatusBadRequest)
			t.Logf("  Actual status: %+v\n", w.status)
		}
	}

	postTest()
}

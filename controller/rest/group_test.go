package rest

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/share"
)

func TestServiceCreate(t *testing.T) {
	preTest()

	{
		var mockCluster kv.MockCluster
		mockCluster.Init([]*share.CLUSPolicyRule{}, []*share.CLUSGroup{})
		clusHelper = &mockCluster

		mc := mockCache{
			rules:  make(map[uint32]*api.RESTPolicyRule, 0),
			groups: make(map[string]*api.RESTGroup, 0),
		}
		cacher = &mc

		modeEmpty := ""
		modeMonitor := "Monitor"
		modeWrong := "Wrong"

		notScored := false

		cases := map[string]api.RESTServiceConfig{
			"g1": {
				Name:            "g1",
				Domain:          "",
				Comment:         nil,
				PolicyMode:      nil,
				ProfileMode:     nil,
				BaselineProfile: nil,
				NotScored:       nil,
			},
			"g1.default": {
				Name:            "g1",
				Domain:          "default",
				Comment:         nil,
				PolicyMode:      nil,
				ProfileMode:     nil,
				BaselineProfile: nil,
				NotScored:       nil,
			},
			"external": {
				Name:            "external",
				Domain:          "",
				Comment:         nil,
				PolicyMode:      nil,
				ProfileMode:     nil,
				BaselineProfile: nil,
				NotScored:       nil,
			},
			"nodes": {
				Name:            "nodes",
				Domain:          "",
				Comment:         nil,
				PolicyMode:      nil,
				ProfileMode:     nil,
				BaselineProfile: nil,
				NotScored:       nil,
			},
			"nv.g2.default": {
				Name:            "nv.g2",
				Domain:          "default",
				Comment:         nil,
				PolicyMode:      nil,
				ProfileMode:     nil,
				BaselineProfile: nil,
				NotScored:       nil,
			},
			"g2.default": {
				Name:            "g2",
				Domain:          "default",
				Comment:         nil,
				PolicyMode:      &modeMonitor,
				ProfileMode:     &modeMonitor,
				BaselineProfile: nil,
				NotScored:       nil,
			},
			"sys.default": {
				Name:            "sys",
				Domain:          "default",
				Comment:         nil,
				PolicyMode:      nil,
				ProfileMode:     nil,
				BaselineProfile: nil,
				NotScored:       &notScored,
			},
		}

		for name, c := range cases {
			data := api.RESTServiceConfigData{Config: &c}
			body, _ := json.Marshal(data)
			w := restCall("POST", "/v1/service", body, api.UserRoleAdmin)
			if w.status != http.StatusOK {
				t.Errorf("Create service: %+v, Status %v is not OK.", c, w.status)
			}
			w = restCall("GET", "/v1/service/"+name, body, api.UserRoleAdmin)
			if w.status != http.StatusOK {
				t.Errorf("Get service: %+v, Status %v is not OK.", name, w.status)
			}
		}

		cases = map[string]api.RESTServiceConfig{
			"g1":         {Name: "g1", Domain: "", Comment: nil, PolicyMode: nil, ProfileMode: nil, BaselineProfile: nil, NotScored: nil},
			"g1.default": {Name: "g1", Domain: "default", Comment: nil, PolicyMode: nil, ProfileMode: nil, BaselineProfile: nil, NotScored: nil},
			".":          {Name: "", Domain: "", Comment: nil, PolicyMode: nil, ProfileMode: nil, BaselineProfile: nil, NotScored: nil},
			".default":   {Name: "", Domain: "default", Comment: nil, PolicyMode: nil, ProfileMode: nil, BaselineProfile: nil, NotScored: nil},
			"g2":         {Name: "g2", Domain: "", Comment: nil, PolicyMode: &modeEmpty, ProfileMode: &modeEmpty, BaselineProfile: nil, NotScored: nil},
			"g3.default": {Name: "g2", Domain: "default", Comment: nil, PolicyMode: &modeWrong, ProfileMode: &modeWrong, BaselineProfile: nil, NotScored: nil},
		}

		for _, c := range cases {
			data := api.RESTServiceConfigData{Config: &c}
			body, _ := json.Marshal(data)
			w := restCall("POST", "/v1/service", body, api.UserRoleAdmin)
			if w.status == http.StatusOK {
				t.Errorf("Create service - negative test: %+v, Status %v is not OK.", c, w.status)
			}
		}
	}

	postTest()
}

func TestGroupCreate(t *testing.T) {
	preTest()

	{
		var mockCluster kv.MockCluster
		mockCluster.Init([]*share.CLUSPolicyRule{}, []*share.CLUSGroup{})
		clusHelper = &mockCluster

		ct1 := api.RESTCriteriaEntry{Key: "image", Value: "redis", Op: share.CriteriaOpEqual}
		ct2 := api.RESTCriteriaEntry{Key: "label.key", Value: "label.value", Op: share.CriteriaOpContains}
		ct3 := api.RESTCriteriaEntry{Key: "node", Value: "B3D5", Op: share.CriteriaOpPrefix}
		ct4 := api.RESTCriteriaEntry{Key: "service", Value: "project:service", Op: share.CriteriaOpEqual}
		ct5 := api.RESTCriteriaEntry{Key: "service", Value: "", Op: share.CriteriaOpEqual}
		ct6 := api.RESTCriteriaEntry{Key: "label/key", Value: "label/value", Op: share.CriteriaOpEqual}
		conf := api.RESTGroupConfig{Name: "g1", Criteria: &[]api.RESTCriteriaEntry{ct1, ct2, ct3, ct4, ct5, ct6}}
		data := api.RESTGroupConfigData{Config: &conf}
		body, _ := json.Marshal(data)

		w := restCall("POST", "/v1/group", body, api.UserRoleAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Create group: Status %v is not OK.", w.status)
		}
	}

	{
		var mockCluster kv.MockCluster
		mockCluster.Init([]*share.CLUSPolicyRule{}, []*share.CLUSGroup{})
		clusHelper = &mockCluster

		ct1 := api.RESTCriteriaEntry{Key: "address", Value: "1.2.3.4", Op: share.CriteriaOpEqual}
		ct2 := api.RESTCriteriaEntry{Key: "address", Value: "1.2.3.4-1.2.4.5", Op: share.CriteriaOpEqual}
		ct3 := api.RESTCriteriaEntry{Key: "address", Value: "1.2.3.4/17", Op: share.CriteriaOpEqual}
		ct4 := api.RESTCriteriaEntry{Key: "address", Value: "abc", Op: share.CriteriaOpEqual}
		ct5 := api.RESTCriteriaEntry{Key: "address", Value: "abc-.xyz_", Op: share.CriteriaOpEqual}
		ct6 := api.RESTCriteriaEntry{Key: "address", Value: "abc.x.y.com", Op: share.CriteriaOpEqual}
		ct7 := api.RESTCriteriaEntry{Key: "address", Value: "8.us", Op: share.CriteriaOpEqual}
		ct8 := api.RESTCriteriaEntry{Key: "address", Value: "*.google.com", Op: share.CriteriaOpEqual}
		ct9 := api.RESTCriteriaEntry{Key: "address", Value: "*.docs.google.com", Op: share.CriteriaOpEqual}
		conf := api.RESTGroupConfig{Name: "g1", Criteria: &[]api.RESTCriteriaEntry{
			ct1, ct2, ct3, ct4, ct5, ct6, ct7, ct8, ct9,
		}}
		data := api.RESTGroupConfigData{Config: &conf}
		body, _ := json.Marshal(data)

		w := restCall("POST", "/v1/group", body, api.UserRoleAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Create group with address: Status %v is not OK.", w.status)
		}
	}

	postTest()
}

func TestGroupCreateNegative(t *testing.T) {
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init([]*share.CLUSPolicyRule{}, []*share.CLUSGroup{})
	clusHelper = &mockCluster

	{
		ct1 := api.RESTCriteriaEntry{Key: "label.key<", Value: "redis", Op: share.CriteriaOpEqual}
		conf := api.RESTGroupConfig{Name: "g1", Criteria: &[]api.RESTCriteriaEntry{ct1}}
		data := api.RESTGroupConfigData{Config: &conf}
		body, _ := json.Marshal(data)

		w := restCall("POST", "/v1/group", body, api.UserRoleAdmin)

		if w.status == http.StatusOK {
			t.Errorf("Create group negative: XSS should not be accepted.")
		}
	}

	{
		ct1 := api.RESTCriteriaEntry{Key: "", Value: "label.value", Op: share.CriteriaOpEqual}
		conf := api.RESTGroupConfig{Name: "g1", Criteria: &[]api.RESTCriteriaEntry{ct1}}
		data := api.RESTGroupConfigData{Config: &conf}
		body, _ := json.Marshal(data)

		w := restCall("POST", "/v1/group", body, api.UserRoleAdmin)

		if w.status == http.StatusOK {
			t.Errorf("Create group negative: Empty key should not be accepted.")
		}
	}

	{
		var mockCluster kv.MockCluster
		mockCluster.Init([]*share.CLUSPolicyRule{}, []*share.CLUSGroup{})
		clusHelper = &mockCluster

		ct1 := api.RESTCriteriaEntry{Key: "image", Value: "redis", Op: share.CriteriaOpEqual}
		ct2 := api.RESTCriteriaEntry{Key: "address", Value: "1.2.3.4", Op: share.CriteriaOpEqual}
		conf := api.RESTGroupConfig{Name: "g1", Criteria: &[]api.RESTCriteriaEntry{ct1, ct2}}
		data := api.RESTGroupConfigData{Config: &conf}
		body, _ := json.Marshal(data)

		w := restCall("POST", "/v1/group", body, api.UserRoleAdmin)

		if w.status == http.StatusOK {
			t.Errorf("Create group negative: mixed criteria is not allowed.")
		}
	}

	{
		addrs := []string{
			"",
			"1.2.3.789",
			"1.2.3.4,2.3.4.5",
			"1.2.3.4/33",
			"1.2.3.4/16-1.2.3.4/24",
			"1.2.3.4-1.2.3.3",
			"1.2.3,123",
			"123",
			"/",
			".",
			"a!z",
			"abc..xyz",
			"abc.xyz.",
			".abc",
			"abc.-xyz",
			"_abc.xyz",
			"abc/xyz",
			"*.google",
			"a*.google.com",
			"*ab.google.com",
			"ab.*.com",
		}
		for _, addr := range addrs {
			ct1 := api.RESTCriteriaEntry{Key: "address", Value: addr, Op: share.CriteriaOpEqual}
			conf := api.RESTGroupConfig{Name: "g1", Criteria: &[]api.RESTCriteriaEntry{ct1}}
			data := api.RESTGroupConfigData{Config: &conf}
			body, _ := json.Marshal(data)

			w := restCall("POST", "/v1/group", body, api.UserRoleAdmin)

			if w.status == http.StatusOK {
				t.Errorf("Create group negative: invalid address %v.", addr)
			}
		}
	}

	postTest()
}

func TestGroupDelete(t *testing.T) {
	preTest()

	accAdmin := access.NewAdminAccessControl()

	{
		var mockCluster kv.MockCluster
		mockCluster.Init(
			[]*share.CLUSPolicyRule{},
			[]*share.CLUSGroup{
				{Name: "g1", CfgType: share.UserCreated,
					Criteria: []share.CLUSCriteriaEntry{
						{Key: "image", Value: "redis", Op: share.CriteriaOpEqual},
					},
				},
			},
		)
		clusHelper = &mockCluster

		mc := mockCache{
			rules:  make(map[uint32]*api.RESTPolicyRule, 0),
			groups: make(map[string]*api.RESTGroup, 0),
		}
		mc.groups["g1"] = &api.RESTGroup{
			RESTGroupBrief: api.RESTGroupBrief{Name: "g1", CfgType: api.CfgTypeUserCreated},
		}
		cacher = &mc

		w := restCall("DELETE", "/v1/group/g1", nil, api.UserRoleAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Delete group: Incorrect status.")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		if g, _, _ := clusHelper.GetGroup("g1", accAdmin); g != nil {
			t.Errorf("Delete group: Group is not deleted.")
		}
	}

	{
		var mockCluster kv.MockCluster
		mockCluster.Init(
			[]*share.CLUSPolicyRule{},
			[]*share.CLUSGroup{
				{Name: "g1", CfgType: share.Learned,
					Criteria: []share.CLUSCriteriaEntry{
						{Key: "image", Value: "redis", Op: share.CriteriaOpEqual},
					},
				},
			},
		)
		clusHelper = &mockCluster

		mc := mockCache{
			rules:  make(map[uint32]*api.RESTPolicyRule, 0),
			groups: make(map[string]*api.RESTGroup, 0),
		}
		mc.groups["g1"] = &api.RESTGroup{
			RESTGroupBrief: api.RESTGroupBrief{Name: "g1", CfgType: api.CfgTypeLearned},
		}
		cacher = &mc

		w := restCall("DELETE", "/v1/group/g1", nil, api.UserRoleAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Delete group: Incorrect status.")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		if g, _, _ := clusHelper.GetGroup("g1", accAdmin); g != nil {
			t.Errorf("Delete group: Should allow to delete the learned group.")
		}
	}

	{
		rule := share.CLUSPolicyRule{
			ID: 10, From: "g1", To: "nv.external", CfgType: share.UserCreated,
		}

		var mockCluster kv.MockCluster
		mockCluster.Init(
			[]*share.CLUSPolicyRule{&rule},
			[]*share.CLUSGroup{
				{Name: "g1", CfgType: share.UserCreated,
					Criteria: []share.CLUSCriteriaEntry{
						{Key: "image", Value: "redis", Op: share.CriteriaOpEqual},
					},
				},
			},
		)
		clusHelper = &mockCluster

		mc := mockCache{
			rules:  make(map[uint32]*api.RESTPolicyRule, 0),
			groups: make(map[string]*api.RESTGroup, 0),
		}
		mc.groups["g1"] = &api.RESTGroup{
			RESTGroupBrief: api.RESTGroupBrief{Name: "g1", CfgType: api.CfgTypeUserCreated},
		}
		cacher = &mc

		w := restCall("DELETE", "/v1/group/g1", nil, api.UserRoleAdmin)

		if w.status != http.StatusOK {
			t.Errorf("Delete group: Incorrect status.")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}

		if g, _, _ := clusHelper.GetGroup("g1", accAdmin); g != nil {
			t.Errorf("Delete group: should allow to delete inused group.")
		}
	}

	postTest()
}

func TestParseGroupYamlFile(t *testing.T) {
	preTest()

	importData := []byte(`apiVersion: v1
items:
- apiVersion: neuvector.com/v1
  kind: NvGroupDefinition
  metadata:
    name: g-1
    namespace: neuvector
  spec:
    selector:
      comment: ""
      criteria:
      - key: container
        op: =
        value: myServer12
      name: g-1
- apiVersion: neuvector.com/v1
  kind: NvGroupDefinition
  metadata:
    name: g-2
    namespace: neuvector
  spec:
    selector:
      comment: ""
      criteria:
      - key: container
        op: =
        value: myServer2
      name: g-2
- apiVersion: neuvector.com/v1
  kind: NvGroupDefinition
  metadata:
    name: g-3
    namespace: neuvector
  spec:
    selector:
      comment: ""
      criteria:
      - key: container
        op: =
        value: myServer3
      name: g-3
kind: List
metadata: {}

---

apiVersion: neuvector.com/v1
kind: NvGroupDefinition
metadata:
  creationTimestamp: null
  name: nv.iperfserver.demo4
  namespace: neuvector
spec:
  selector:
    comment: ""
    criteria:
    - key: service
      op: =
      value: iperfserver.demo4
    - key: domain
      op: =
      value: demo4
    name: nv.iperfserver.demo4

---

apiVersion: v1
items:
- apiVersion: neuvector.com/v1
  kind: NvSecurityRule
  metadata:
    creationTimestamp: null
    name: nv.ip.kubernetes.default
    namespace: default
  spec:
    egress: []
    file: []
    ingress:
    - action: deny
      applications:
      - any
      name: nv.ip.kubernetes.default-ingress-0
      ports: any
      priority: 0
      selector:
        comment: ""
        criteria:
        - key: container
          op: =
          value: myServer
        name: g-1
        original_name: ""
    - action: deny
      applications:
      - any
      name: nv.ip.kubernetes.default-ingress-1
      ports: any
      priority: 0
      selector:
        comment: ""
        criteria:
        - key: container
          op: =
          value: myServer2
        name: g-1-192398063-2
        original_name: ""
    - action: deny
      applications:
      - any
      name: nv.ip.kubernetes.default-ingress-2
      ports: any
      priority: 0
      selector:
        comment: ""
        criteria:
        - key: container
          op: =
          value: myServer
        name: g-1
        original_name: ""
    process: []
    target:
      policymode: N/A
      selector:
        comment: ""
        criteria:
        - key: address
          op: =
          value: 10.43.0.1
        - key: domain
          op: =
          value: default
        name: nv.ip.kubernetes.default
        original_name: ""
- apiVersion: neuvector.com/v1
  kind: NvClusterSecurityRule
  metadata:
    name: g-1
  spec:
    dlp:
      settings: []
      status: true
    egress: []
    file: []
    ingress: []
    process: []
    target:
      policymode: N/A
      selector:
        comment: ""
        criteria:
        - key: container
          op: =
          value: myServer2
        name: g-1
        original_name: ""
    waf:
      settings: []
      status: true
kind: List
metadata: {}

---

apiVersion: neuvector.com/v1
kind: NvSecurityRule
metadata:
  name: nv.iperfserver.demo4
  namespace: demo4
spec:
  dlp:
    settings: []
    status: true
  egress:
  - action: deny
    applications:
    - MySQL
    name: containers-egress-0
    ports: any
    priority: 0
    selector:
      comment: ""
      name: containers
      original_name: ""
  - action: deny
    applications:
    - ZooKeeper
    name: nodes-egress-1
    ports: any
    priority: 0
    selector:
      comment: ""
      name: nodes
      original_name: ""
  file: []
  ingress:
  - action: deny
    applications:
    - Radius
    name: nv.iperfserver.demo4-ingress-0
    ports: any
    priority: 0
    selector:
      comment: ""
      name: g-1
      name_referral: true
      original_name: ""
  - action: deny
    applications:
    - ZooKeeper
    name: nv.iperfserver.demo4-ingress-1
    ports: any
    priority: 0
    selector:
      comment: ""
      name: nodes
      original_name: ""
  process: []
  process_profile:
    baseline: zero-drift
    mode: Discover
  target:
    policymode: Discover
    selector:
      comment: ""
      name: nv.iperfserver.demo4
      name_referral: true
      original_name: ""
  waf:
    settings: []
    status: true
`)

	if secRules, nvGrpDefs, err := parseGroupYamlFile(importData); err != nil {
		t.Errorf("parseGroupYamlFile failed: %s. Expect success", err)
	} else {
		if len(nvGrpDefs) != 4 {
			t.Errorf("parseGroupYamlFile: Incorrect number of valid NvGroupDefinition items parsed.")
			t.Logf("  Expect 4 group definitions\n")
			t.Logf("  Actual %d group definitions\n", len(nvGrpDefs))
		}

		nvSecurityRules := 0
		nvClusterSecurityRules := 0
		for _, r := range secRules {
			if r.Kind == "NvSecurityRule" {
				nvSecurityRules++
			} else if r.Kind == "NvClusterSecurityRule" {
				nvClusterSecurityRules++
			}
		}
		if nvSecurityRules != 2 {
			t.Errorf("parseGroupYamlFile: Incorrect number of valid NvSecurityRule items parsed.")
			t.Logf("  Expect 2 items\n")
			t.Logf("  Actual %d items\n", nvSecurityRules)
		}
		if nvClusterSecurityRules != 1 {
			t.Errorf("parseGroupYamlFile: Incorrect number of valid NvClusterSecurityRule items parsed.")
			t.Logf("  Expect 1 items\n")
			t.Logf("  Actual %d items\n", nvClusterSecurityRules)
		}
	}

	postTest()
}

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
			"g1":         {"g1", "", nil, nil, nil, nil, nil},
			"g1.default": {"g1", "default", nil, nil, nil, nil, nil},
			".":          {"", "", nil, nil, nil, nil, nil},
			".default":   {"", "default", nil, nil, nil, nil, nil},
			"g2":         {"g2", "", nil, &modeEmpty, &modeEmpty, nil, nil},
			"g3.default": {"g2", "default", nil, &modeWrong, &modeWrong, nil, nil},
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

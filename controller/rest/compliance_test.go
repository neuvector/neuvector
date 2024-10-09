package rest

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/kv"
)

func TestComplianceProfileConfig(t *testing.T) {
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	cacher = &mockCache{
		cps: map[string]*api.RESTComplianceProfile{
			"default": {
				Name:          "default",
				DisableSystem: false,
				Entries:       []api.RESTComplianceProfileEntry{},
			},
		},
	}

	disableSystem := false
	cfg := api.RESTComplianceProfileConfig{
		Name:          "default",
		DisableSystem: &disableSystem,
		Entries:       &[]*api.RESTComplianceProfileEntry{},
	}
	data := api.RESTComplianceProfileConfigData{Config: &cfg}
	body, _ := json.Marshal(data)

	w := restCall("PATCH", "/v1/compliance/profile/default", body, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Errorf("Configure compliance profile failed: %v", w.status)
	}

	// Modify disable system
	disableSystem = true
	cfg = api.RESTComplianceProfileConfig{
		Name:          "default",
		DisableSystem: &disableSystem,
	}
	data = api.RESTComplianceProfileConfigData{Config: &cfg}
	body, _ = json.Marshal(data)

	w = restCall("PATCH", "/v1/compliance/profile/default", body, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Errorf("Configure compliance profile failed: %v", w.status)
	}

	cp, _, _ := mockCluster.GetComplianceProfile("default", nil)
	v := cp.DisableSystem
	if v != true {
		t.Errorf("Compliance profile DisableSystem is not configured correctly: %v", v)
	}

	// Modify entries
	cfg = api.RESTComplianceProfileConfig{
		Name: "default",
		Entries: &[]*api.RESTComplianceProfileEntry{
			{TestNum: "D.1.1.1"},
			{TestNum: "D.1.2.1", Tags: []string{"PCI"}},
			{TestNum: "D.1.2.2", Tags: []string{"PCI", "HIPAA", "PCI"}},
		},
	}
	data = api.RESTComplianceProfileConfigData{Config: &cfg}
	body, _ = json.Marshal(data)

	w = restCall("PATCH", "/v1/compliance/profile/default", body, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Errorf("Configure compliance profile failed: %v", w.status)
	}

	cp, _, _ = mockCluster.GetComplianceProfile("default", nil)
	if len(cp.Entries) != 3 {
		t.Errorf("Compliance profile entries are not configured correctly: %v", len(cp.Entries))
	}

	// Reset
	cfg = api.RESTComplianceProfileConfig{
		Name:    "default",
		Entries: &[]*api.RESTComplianceProfileEntry{},
	}
	data = api.RESTComplianceProfileConfigData{Config: &cfg}
	body, _ = json.Marshal(data)

	w = restCall("PATCH", "/v1/compliance/profile/default", body, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Errorf("Configure compliance profile failed: %v", w.status)
	}

	cp, _, _ = mockCluster.GetComplianceProfile("default", nil)
	if len(cp.Entries) != 0 {
		t.Errorf("Compliance profile entries are not configured correctly: %v", len(cp.Entries))
	}

	// Modify entries with duplication
	cfg = api.RESTComplianceProfileConfig{
		Name: "default",
		Entries: &[]*api.RESTComplianceProfileEntry{
			{TestNum: "D.1.1.1", Tags: []string{"PCI"}},
			{TestNum: "D.1.2.1", Tags: []string{"PCI", "HIPAA"}},
			{TestNum: "D.1.1.1", Tags: []string{"NIST", "PCI"}},
			{TestNum: "D.1.2.1", Tags: []string{"GDPR"}},
		},
	}
	data = api.RESTComplianceProfileConfigData{Config: &cfg}
	body, _ = json.Marshal(data)

	w = restCall("PATCH", "/v1/compliance/profile/default", body, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Errorf("Configure compliance profile failed: %v", w.status)
	}

	cp, _, _ = mockCluster.GetComplianceProfile("default", nil)
	if len(cp.Entries) != 2 {
		t.Errorf("Compliance profile entries are not configured correctly: %v", len(cp.Entries))
	}
	if e, ok := cp.Entries["D.1.2.1"]; !ok {
		t.Errorf("Compliance profile entries missing: %v", cp.Entries)
	} else if len(e.Tags) != 1 {
		t.Errorf("Compliance profile entries are not configured correctly: %v", e)
	}

	// Add an entry
	e := api.RESTComplianceProfileEntry{TestNum: "K.1.2.1", Tags: []string{"NIST"}}
	edata := api.RESTComplianceProfileEntryConfigData{Config: &e}
	body, _ = json.Marshal(edata)

	w = restCall("PATCH", "/v1/compliance/profile/default/entry/K.1.2.1", body, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Errorf("Configure compliance profile failed: %v", w.status)
	}

	cp, _, _ = mockCluster.GetComplianceProfile("default", nil)
	if len(cp.Entries) != 3 {
		t.Errorf("Compliance profile entries are not configured correctly: %v", len(cp.Entries))
	}

	// Modify the entry
	e = api.RESTComplianceProfileEntry{TestNum: "K.1.2.1", Tags: []string{"PCI", "GDPR", "NIST"}}
	edata = api.RESTComplianceProfileEntryConfigData{Config: &e}
	body, _ = json.Marshal(edata)

	w = restCall("PATCH", "/v1/compliance/profile/default/entry/K.1.2.1", body, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Errorf("Configure compliance profile failed: %v", w.status)
	}

	cp, _, _ = mockCluster.GetComplianceProfile("default", nil)
	if len(cp.Entries) != 3 {
		t.Errorf("Compliance profile entries are not configured correctly: %v", len(cp.Entries))
	}
	if e, ok := cp.Entries["K.1.2.1"]; !ok {
		t.Errorf("Compliance profile entries missing: %v", cp.Entries)
	} else if len(e.Tags) != 3 {
		t.Errorf("Compliance profile entries are not configured correctly: %v", e)
	}

	// Make the entry empty
	e = api.RESTComplianceProfileEntry{TestNum: "K.1.2.1", Tags: []string{}}
	edata = api.RESTComplianceProfileEntryConfigData{Config: &e}
	body, _ = json.Marshal(edata)

	w = restCall("PATCH", "/v1/compliance/profile/default/entry/K.1.2.1", body, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Errorf("Configure compliance profile failed: %v", w.status)
	}

	cp, _, _ = mockCluster.GetComplianceProfile("default", nil)
	if len(cp.Entries) != 3 {
		t.Errorf("Compliance profile entries are not configured correctly: %v", len(cp.Entries))
	}
	if e, ok := cp.Entries["K.1.2.1"]; !ok {
		t.Errorf("Compliance profile entries missing: %v", cp.Entries)
	} else if len(e.Tags) != 0 {
		t.Errorf("Compliance profile entries are not configured correctly: %v", e)
	}

	// Delete an entry
	w = restCall("DELETE", "/v1/compliance/profile/default/entry/D.1.2.1", nil, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Errorf("Configure compliance profile failed: %v", w.status)
	}
	if len(cp.Entries) != 2 {
		t.Errorf("Compliance profile entries are not deleted correctly: %v", len(cp.Entries))
	}

	// Delete a non-existent entry
	w = restCall("DELETE", "/v1/compliance/profile/default/entry/none", nil, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Errorf("Configure compliance profile failed: %v", w.status)
	}
	if len(cp.Entries) != 2 {
		t.Errorf("Compliance profile entries are not deleted correctly: %v", len(cp.Entries))
	}

	postTest()
}

func TestComplianceProfileNegative(t *testing.T) {
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	cacher = &mockCache{
		cps: map[string]*api.RESTComplianceProfile{
			"default": {
				Name:          "default",
				DisableSystem: false,
				Entries:       []api.RESTComplianceProfileEntry{},
			},
		},
	}

	{
		cfg := api.RESTComplianceProfileConfig{
			Name: "default",
			Entries: &[]*api.RESTComplianceProfileEntry{
				{TestNum: "<abc>"},
			},
		}
		data := api.RESTComplianceProfileConfigData{Config: &cfg}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/compliance/profile/default", body, api.UserRoleAdmin)
		if w.status != http.StatusBadRequest {
			t.Errorf("Configure compliance profile should fail: %v", w.status)
		}
	}

	{
		cfg := api.RESTComplianceProfileConfig{
			Name: "default",
			Entries: &[]*api.RESTComplianceProfileEntry{
				{TestNum: "D.1.2.1", Tags: []string{"PCPI"}},
			},
		}
		data := api.RESTComplianceProfileConfigData{Config: &cfg}
		body, _ := json.Marshal(data)

		w := restCall("PATCH", "/v1/compliance/profile/default", body, api.UserRoleAdmin)
		if w.status != http.StatusBadRequest {
			t.Errorf("Configure compliance profile should fail: %v", w.status)
		}
	}

	{
		e := api.RESTComplianceProfileEntry{TestNum: "K.1.2.1", Tags: []string{"NISTY"}}
		edata := api.RESTComplianceProfileEntryConfigData{Config: &e}
		body, _ := json.Marshal(edata)

		w := restCall("PATCH", "/v1/compliance/profile/default/entry/K.1.2.1", body, api.UserRoleAdmin)
		if w.status != http.StatusBadRequest {
			t.Errorf("Configure compliance profile entry should fail: %v", w.status)
		}
	}

	postTest()
}

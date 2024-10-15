package rest

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/scan"
	"github.com/neuvector/neuvector/share"
	scanUtils "github.com/neuvector/neuvector/share/scan"
)

func TestFilterPositive(t *testing.T) {
	preTest()

	cases := map[string]share.CLUSRegistryFilter{
		"neuvector/image:latest": {
			Org:  "neuvector",
			Repo: "image",
			Tag:  "latest",
		},
		"neuvector/image:*": {
			Org:  "neuvector",
			Repo: "image",
			Tag:  ".*",
		},
		"neuvector/*:*": {
			Org:  "neuvector",
			Repo: ".*",
			Tag:  ".*",
		},
		"neuvector/*": {
			Org:  "neuvector",
			Repo: ".*",
			Tag:  ".*",
		},
		"*:*": {
			Org:  "",
			Repo: ".*",
			Tag:  ".*",
		},
		"neuvector/[image1|image2]:*": {
			Org:  "neuvector",
			Repo: "[image1|image2]",
			Tag:  ".*",
		},
		"neu*:*": {
			Org:  "",
			Repo: "neu.*",
			Tag:  ".*",
		},
		"neuvector/*:v2.1": {
			Org:  "neuvector",
			Repo: ".*",
			Tag:  "v2.1",
		},
		"neuvector/*:v2.*": {
			Org:  "neuvector",
			Repo: ".*",
			Tag:  "v2.*",
		},
		"neuvector/*:v2.[0]{1,2}": {
			Org:  "neuvector",
			Repo: ".*",
			Tag:  "v2.[0]{1,2}",
		},
		"neuvector/*:v2.[0]*": {
			Org:  "neuvector",
			Repo: ".*",
			Tag:  "v2.[0]*",
		},
		"neuvector/*_20201010_*:*": {
			Org:  "neuvector",
			Repo: ".*_20201010_.*",
			Tag:  ".*",
		},
		"neuvector/.*_20201010_*:*": {
			Org:  "neuvector",
			Repo: ".*_20201010_.*",
			Tag:  ".*",
		},
	}

	for k, v := range cases {
		if f, err := parseFilter([]string{k}, share.RegistryTypeDocker); err != nil {
			t.Errorf("Error: %v %v\n", k, err)
		} else if *f[0] != v {
			t.Errorf("Error: %v\n", k)
			t.Errorf("  Expect: %v\n", v)
			t.Errorf("  Actual: %v\n", *f[0])
		}
	}

	postTest()
}

func TestFilterNegative(t *testing.T) {
	preTest()

	cases := []string{
		"neu*/*:*",
		"*/*:*",
		"*/*",
		"*neuvector/*:*",
	}
	for _, v := range cases {
		if f, err := parseFilter([]string{v}, share.RegistryTypeDocker); err == nil {
			t.Errorf("Error: %v\n", v)
			t.Errorf("  Expect: invalid format\n")
			t.Errorf("  Actual: %v\n", *f[0])
		}
	}

	cases = []string{
		"iperf:*",
		"iperf",
	}
	for _, v := range cases {
		if f, err := parseFilter([]string{v}, share.RegistryTypeOpenShift); err == nil {
			t.Errorf("Error: %v\n", v)
			t.Errorf("  Expect: invalid format\n")
			t.Errorf("  Actual: %v\n", *f[0])
		}
	}

	postTest()
}

func TestRegistryURL(t *testing.T) {
	preTest()

	cases := []string{
		"http://examples.com/",
		"http://examples.com:5000/",
		"https://examples.com",
		"https://1.2.3.4",
		"https://examples.com/abc/",
		"https://examples.com/abc?k=v",
		"https://examples.com/abc#anchor",
	}
	for _, c := range cases {
		if _, err := scanUtils.ParseRegistryURI(c); err != nil {
			t.Errorf("Parsing registry URL should pass: %v\n", c)
		}
	}

	cases = []string{
		"proto://examples.com",
		"proto:/examples.com",
		"examples.com",
	}
	for _, c := range cases {
		if _, err := scanUtils.ParseRegistryURI(c); err == nil {
			t.Errorf("Parsing registry URL should false: %v\n", c)
		}
	}

	postTest()
}

func countRegistry(role string, roles map[string][]string) int {
	login := mockLoginUser("someuser", role, api.FedRoleNone, roles)
	r, _ := http.NewRequest(http.MethodGet, "https://10.1.1.1/v1/scan/registry", nil)
	acc := access.NewAccessControl(r, access.AccessOPRead, login.domainRoles, nil)

	var count int
	all := clusHelper.GetAllRegistry(share.ScopeLocal)
	for _, r := range all {
		if acc.Authorize(r, nil) {
			count++
		}
	}

	login._logout()
	return count
}

func TestRegistryCreateDelete(t *testing.T) {
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	cacher = &mockCache{}
	scanner = &mockScan{}

	dockerURL := "https://registry.hub.docker.com/"
	data := api.RESTRegistryConfigData{
		Config: &api.RESTRegistryConfig{
			Name:     "r1",
			Type:     share.RegistryTypeDocker,
			Registry: &dockerURL,
		},
	}
	body, _ := json.Marshal(&data)

	w := restCall("POST", "/v1/scan/registry", body, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Errorf("Error: status=%v registry=%v.", w.status, string(body[:]))
	}

	// -- reader cannot create
	data.Config.Name = "r2"
	body, _ = json.Marshal(&data)

	w = restCall("POST", "/v1/scan/registry", body, api.UserRoleReader)
	if w.status != http.StatusForbidden {
		t.Errorf("Error: status=%v registry=%v.", w.status, string(body[:]))
	}

	// -- allow admin user to set registry domain
	data.Config.Name = "r2"
	data.Config.Domains = &[]string{"ns1"}
	body, _ = json.Marshal(&data)

	w = restCall("POST", "/v1/scan/registry", body, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Errorf("Error: status=%v registry=%v.", w.status, string(body[:]))
	}

	// r1, r2
	if count := countRegistry(api.UserRoleReader, nil); count != 2 {
		t.Errorf("Wrong count: count=%v.", count)
	}

	// -- allow namespace user to create registry
	data.Config.Name = "r3"
	data.Config.Domains = nil
	body, _ = json.Marshal(&data)

	w = restCallWithRole("POST", "/v1/scan/registry", body, api.UserRoleNone, map[string][]string{api.UserRoleAdmin: {"ns1", "ns2"}})
	if w.status != http.StatusOK {
		t.Errorf("Error: status=%v registry=%v.", w.status, string(body[:]))
	}

	// r2, r3
	if count := countRegistry(api.UserRoleNone, map[string][]string{api.UserRoleAdmin: {"ns1", "ns2"}}); count != 2 {
		t.Errorf("Wrong count: count=%v.", count)
	}
	// r3
	if count := countRegistry(api.UserRoleNone, map[string][]string{api.UserRoleReader: {"ns2"}}); count != 1 {
		t.Errorf("Wrong count: count=%v.", count)
	}

	// -- allow namespace user to set registry domain
	data.Config.Name = "r4"
	data.Config.Domains = &[]string{"ns1"}
	body, _ = json.Marshal(&data)

	w = restCallWithRole("POST", "/v1/scan/registry", body, api.UserRoleNone, map[string][]string{api.UserRoleAdmin: {"ns1", "ns2"}})
	if w.status != http.StatusOK {
		t.Errorf("Error: status=%v registry=%v.", w.status, string(body[:]))
	}

	// r2, r3, r4
	if count := countRegistry(api.UserRoleNone, map[string][]string{api.UserRoleAdmin: {"ns1", "ns2"}}); count != 3 {
		t.Errorf("Wrong count: count=%v.", count)
	}

	// -- namespace user cannot create registry in namespace as reader
	data.Config.Name = "r5"
	data.Config.Domains = &[]string{"ns1", "ns2"}
	body, _ = json.Marshal(&data)

	w = restCallWithRole("POST", "/v1/scan/registry", body, api.UserRoleNone, map[string][]string{api.UserRoleAdmin: {"ns1"}, api.UserRoleReader: {"ns2"}})
	if w.status != http.StatusForbidden {
		t.Errorf("Error: status=%v registry=%v.", w.status, string(body[:]))
	}

	// -- namespace user cannot create registry in different namespace
	data.Config.Name = "r5"
	data.Config.Domains = &[]string{"ns1", "ns3"}
	body, _ = json.Marshal(&data)

	w = restCallWithRole("POST", "/v1/scan/registry", body, api.UserRoleNone, map[string][]string{api.UserRoleAdmin: {"ns1", "ns2"}})
	if w.status != http.StatusForbidden {
		t.Errorf("Error: status=%v registry=%v.", w.status, string(body[:]))
	}

	// -- treat empty domain array as nil
	data.Config.Name = "r5"
	data.Config.Domains = &[]string{}
	body, _ = json.Marshal(&data)

	w = restCallWithRole("POST", "/v1/scan/registry", body, api.UserRoleNone, map[string][]string{api.UserRoleAdmin: {"ns1", "ns2"}})
	if w.status != http.StatusOK {
		t.Errorf("Error: status=%v registry=%v.", w.status, string(body[:]))
	}

	// r1, r2, r3, r4, r5
	if count := countRegistry(api.UserRoleReader, nil); count != 5 {
		t.Errorf("Wrong count: count=%v.", count)
	}
	// r2, r3, r4, r5
	if count := countRegistry(api.UserRoleNone, map[string][]string{api.UserRoleAdmin: {"ns1", "ns2"}}); count != 4 {
		t.Errorf("Wrong count: count=%v.", count)
	}
	// r3, r5
	if count := countRegistry(api.UserRoleNone, map[string][]string{api.UserRoleReader: {"ns2"}}); count != 2 {
		t.Errorf("Wrong count: count=%v.", count)
	}

	// ---- Delete
	w = restCall("DELETE", "/v1/scan/registry/r1", body, api.UserRoleReader)
	if w.status != http.StatusForbidden {
		t.Errorf("Error: status=%v registry=%v.", w.status, string(body[:]))
	}

	w = restCall("DELETE", "/v1/scan/registry/r1", body, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Errorf("Error: status=%v registry=%v.", w.status, string(body[:]))
	}

	w = restCall("DELETE", "/v1/scan/registry/r5", body, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Errorf("Error: status=%v registry=%v.", w.status, string(body[:]))
	}

	w = restCallWithRole("DELETE", "/v1/scan/registry/r2", body, api.UserRoleNone, map[string][]string{api.UserRoleAdmin: {"ns1", "ns2"}})
	if w.status != http.StatusOK {
		t.Errorf("Error: status=%v registry=%v.", w.status, string(body[:]))
	}

	w = restCallWithRole("DELETE", "/v1/scan/registry/r3", body, api.UserRoleNone, map[string][]string{api.UserRoleAdmin: {"ns1"}})
	if w.status != http.StatusForbidden {
		t.Errorf("Error: status=%v registry=%v.", w.status, string(body[:]))
	}

	w = restCallWithRole("DELETE", "/v1/scan/registry/r3", body, api.UserRoleNone, map[string][]string{api.UserRoleAdmin: {"ns1", "ns2"}})
	if w.status != http.StatusOK {
		t.Errorf("Error: status=%v registry=%v.", w.status, string(body[:]))
	}

	w = restCallWithRole("DELETE", "/v1/scan/registry/r4", body, api.UserRoleNone, map[string][]string{api.UserRoleAdmin: {"ns1"}})
	if w.status != http.StatusOK {
		t.Errorf("Error: status=%v registry=%v.", w.status, string(body[:]))
	}

	postTest()
}

func TestFixRegRepo(t *testing.T) {
	cases := [][4]string{
		{"", "nv/node", "", "nv/node"},
		{"https://1.2.3.4:5000", "nv/node", "https://1.2.3.4:5000", "nv/node"},
		{"", "docker.io/nv/node", "https://docker.io/", "nv/node"},
		{"", "https://docker.io/nv/node", "https://docker.io/", "nv/node"},
		{"", "1.2.3.4:5000/nv/node", "https://1.2.3.4:5000/", "nv/node"},
		{"", "https://1.2.3.4:5000/nv/node", "https://1.2.3.4:5000/", "nv/node"},
		{"", "registry/nv/node", "", "registry/nv/node"},
		{"", "redis", "", "library/redis"},
	}

	for _, c := range cases {
		result := &share.ScanResult{Registry: c[0], Repository: c[1]}
		scan.FixRegRepoForAdmCtrl(result)
		if result.Registry != c[2] || result.Repository != c[3] {
			t.Errorf("Error: input:%s -- %s, expect:%s -- %s, output:%s -- %s", c[0], c[1], c[2], c[3], result.Registry, result.Repository)
		}
	}
}

func TestOpenshiftRegistryCreateDelete(t *testing.T) {
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster
	cacher = &mockCache{}
	scanner = &mockScan{}

	ocURL := "https://docker-registry.default.svc:5000"
	data := api.RESTRegistryConfigData{
		Config: &api.RESTRegistryConfig{
			Name:     "r1",
			Type:     share.RegistryTypeOpenShift,
			Registry: &ocURL,
			Filters:  &[]string{"ns1/image1:latest"},
		},
	}
	body, _ := json.Marshal(&data)

	w := restCall("POST", "/v1/scan/registry", body, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Errorf("Error: status=%v registry=%v.", w.status, string(body[:]))
	}

	data.Config.Name = "r2"
	data.Config.Filters = &[]string{"ns1/image1:latest", "ns2/image1:latest"}
	body, _ = json.Marshal(&data)
	w = restCall("POST", "/v1/scan/registry", body, api.UserRoleAdmin)
	if w.status != http.StatusOK {
		t.Errorf("Error: status=%v registry=%v.", w.status, string(body[:]))
	}

	// reader can see r1, r2
	if count := countRegistry(api.UserRoleReader, nil); count != 2 {
		t.Errorf("Wrong count: count=%v.", count)
	}

	// -- allow namespace user to create registry
	data.Config.Name = "r11"
	data.Config.Filters = &[]string{"ns1/image1:latest"}
	body, _ = json.Marshal(&data)
	w = restCallWithRole("POST", "/v1/scan/registry", body, api.UserRoleNone, map[string][]string{api.UserRoleAdmin: {"ns1", "ns2"}})
	if w.status != http.StatusOK {
		t.Errorf("Error: status=%v registry=%v.", w.status, string(body[:]))
	}

	// -- allow namespace user to see registry with any filter's namespace or any creator domain that is in the user's namespaces
	// r1(filter has ns1), r2(filter has ns1, ns2), r11(creatorDomains is ns1, ns2)
	if count := countRegistry(api.UserRoleNone, map[string][]string{api.UserRoleAdmin: {"ns1", "ns2"}}); count != 3 {
		t.Errorf("Wrong count: count=%v.", count)
	}
	// -- allow namespace user to see registry with any filter's namespace or any creator domain that is in the user's namespaces
	// r1(filter has ns1), r2(filter has ns1, ns2), r11(creatorDomains is ns1, ns2)
	if count := countRegistry(api.UserRoleNone, map[string][]string{api.UserRoleAdmin: {"ns1"}}); count != 3 {
		t.Errorf("Wrong count: count=%v.", count)
	}
	// -- allow namespace user to see registry with any filter's namespace or any creator domain that is in the user's namespaces
	// r2(filter has ns1, ns2), r11(creatorDomains is ns1, ns2)
	if count := countRegistry(api.UserRoleNone, map[string][]string{api.UserRoleReader: {"ns2"}}); count != 2 {
		t.Errorf("Wrong count: count=%v.", count)
	}
	// -- disallow namespace user to see registry when none of the user's namespaces is in registry's filter namespaces or creator domains
	if count := countRegistry(api.UserRoleNone, map[string][]string{api.UserRoleAdmin: {"nsA"}}); count != 0 {
		t.Errorf("Wrong count: count=%v.", count)
	}

	// -- allow namespace user to set registry with filter's namespace that is in the registry creator's namespaces
	// r11(creatorDomains is ns1, ns2)
	data.Config.Name = "r11"
	data.Config.Filters = &[]string{"ns1/image1:latest", "ns2/image2:latest"}
	body, _ = json.Marshal(&data)
	w = restCallWithRole("PATCH", "/v1/scan/registry/r11", body, api.UserRoleNone, map[string][]string{api.UserRoleAdmin: {"ns1", "ns2", "ns3"}})
	if w.status != http.StatusOK {
		t.Errorf("Error: status=%v registry=%v.", w.status, string(body[:]))
	}

	// -- disallow namespace user to set registry with any filter's namespace beyond the user's namespaces
	// r11(creatorDomains is ns1, ns2)
	data.Config.Name = "r11"
	data.Config.Filters = &[]string{"nsA/image1:latest"}
	body, _ = json.Marshal(&data)
	w = restCallWithRole("PATCH", "/v1/scan/registry/r11", body, api.UserRoleNone, map[string][]string{api.UserRoleAdmin: {"ns1", "ns2"}})
	if w.status == http.StatusOK {
		t.Errorf("Error: unexpected status=%v registry=%v.", w.status, string(body[:]))
	}

	// -- disallow namespace user to set registry that has any filter's namespace beyond the registry creator namespaces, even though the filter's namespace is in user's namespaces
	// r11(creatorDomains is ns1, ns2)
	data.Config.Name = "r11"
	data.Config.Filters = &[]string{"ns3/image3:latest"}
	body, _ = json.Marshal(&data)
	w = restCallWithRole("PATCH", "/v1/scan/registry/r11", body, api.UserRoleNone, map[string][]string{api.UserRoleAdmin: {"ns1", "ns2", "ns3"}})
	if w.status == http.StatusOK {
		t.Errorf("Error: unexpected status=%v registry=%v.", w.status, string(body[:]))
	}

	// -- disallow namespace user to create registry that has any filter's namespace beyond the user's namespaces
	data.Config.Name = "r12"
	data.Config.Filters = &[]string{"nsA/image1:latest"}
	body, _ = json.Marshal(&data)
	w = restCallWithRole("POST", "/v1/scan/registry", body, api.UserRoleNone, map[string][]string{api.UserRoleAdmin: {"ns1", "ns2"}})
	if w.status == http.StatusOK {
		t.Errorf("Error: unexpected status=%v registry=%v.", w.status, string(body[:]))
	}

	// -- disallow namespace user to delete a registry when any of the registry's creatorDomains is in user's namespaces
	// r11(creatorDomains is ns1, ns2)
	w = restCallWithRole("DELETE", "/v1/scan/registry/r11", body, api.UserRoleNone, map[string][]string{api.UserRoleAdmin: {"ns1"}})
	if w.status == http.StatusOK {
		t.Errorf("Error: status=%v registry=%v.", w.status, string(body[:]))
	}

	// -- allow namespace user to delete a registry when all the registry's creatorDomains are in user's namespaces
	// r11(creatorDomains is ns1, ns2)
	w = restCallWithRole("DELETE", "/v1/scan/registry/r11", body, api.UserRoleNone, map[string][]string{api.UserRoleAdmin: {"ns1", "ns2", "nsA"}})
	if w.status == http.StatusForbidden {
		t.Errorf("Error: status=%v registry=%v.", w.status, string(body[:]))
	}

	// -- disallow namespace user to delete a registry that has nil creator namespaces
	// r2(creatorDomains is nil)
	w = restCallWithRole("DELETE", "/v1/scan/registry/r2", body, api.UserRoleNone, map[string][]string{api.UserRoleAdmin: {"ns1", "ns2", "ns3"}})
	if w.status == http.StatusOK {
		t.Errorf("Error: status=%v registry=%v.", w.status, string(body[:]))
	}

	w = restCallWithRole("DELETE", "/v1/scan/registry/r1", body, api.UserRoleAdmin, map[string][]string{api.UserRoleAdmin: {"ns1", "ns2", "nsA"}})
	if w.status == http.StatusForbidden {
		t.Errorf("Error: status=%v registry=%v.", w.status, string(body[:]))
	}

	postTest()
}

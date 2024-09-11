package scan

import (
	"time"

	"testing"

	"github.com/neuvector/neuvector/controller/api"
)

func TestVulnerabilityProfile(t *testing.T) {
	p := api.RESTVulnerabilityProfile{
		Name: "default",
		Entries: []api.RESTVulnerabilityProfileEntry{
			{
				ID: 1, Name: api.VulnerabilityNameRecent, Days: 10, Images: []string{"nginx:*"},
			},
			{
				ID: 2, Name: "CVE-2021-*", Domains: []string{"dev-*", "prod-*"}, Images: []string{"alpine:3", "node-*:*"},
			},
			{
				ID: 3, Name: "CVE-2020-6789", Domains: []string{"dev-*"},
			},
			{
				ID: 4, Name: "CVE-2019-AAAA", Images: []string{"controller:4.0.1", "enforcer:*"},
			},
			{
				ID: 5, Name: "CVE-2018-*",
			},
		},
	}

	vpf := MakeVulnerabilityProfileFilter(&p)

	positives := []struct {
		v       api.RESTVulnerability
		domains []string
		image   string
	}{
		{api.RESTVulnerability{Name: "CVE-2021-YYYY", PublishedTS: time.Now().AddDate(0, 0, -5).Unix()}, nil, "nginx:3"},
		{api.RESTVulnerability{Name: "CVE-2021-1234"}, []string{"dev-1"}, "alpine:3"},
		{api.RESTVulnerability{Name: "CVE-2021-1234"}, []string{"dev-1"}, "node-10:latest"},
		{api.RESTVulnerability{Name: "CVE-2021-1234"}, []string{"prod-1"}, "alpine:3"},
		{api.RESTVulnerability{Name: "CVE-2020-6789"}, []string{"dev-1"}, ""},
		{api.RESTVulnerability{Name: "CVE-2020-6789"}, []string{"dev-1"}, "nginx:latest"},
		{api.RESTVulnerability{Name: "CVE-2019-AAAA"}, []string{""}, "enforcer:3"},
		{api.RESTVulnerability{Name: "CVE-2019-AAAA"}, nil, "enforcer:3"},
		{api.RESTVulnerability{Name: "CVE-2018-BBBB"}, []string{"stage-1"}, "enforcer:3"},
		{api.RESTVulnerability{Name: "CVE-2018-BBBB"}, nil, ""},
	}
	for _, p := range positives {
		if !vpf.filterOneVulREST(&p.v, p.domains, p.image) {
			t.Errorf("Vulnerability positive test fails: %v", p)
		}
	}

	negtives := []struct {
		v       api.RESTVulnerability
		domains []string
		image   string
	}{
		{api.RESTVulnerability{Name: "CVE-2021-YYYY", PublishedTS: time.Now().AddDate(0, 0, -11).Unix()}, nil, "nginx:3"},
		{api.RESTVulnerability{Name: "CVE-2021-YYYY", PublishedTS: time.Now().AddDate(0, 0, -5).Unix()}, nil, "alpine:3"},
		{api.RESTVulnerability{Name: "CVE-2021-1234"}, []string{""}, ""},
		{api.RESTVulnerability{Name: "CVE-2021-1234"}, []string{"dev-1"}, ""},
		{api.RESTVulnerability{Name: "CVE-2021-1234"}, []string{""}, "alpine:3"},
		{api.RESTVulnerability{Name: "CVE-2020-6789"}, []string{"prod-1"}, "alpine:3"},
		{api.RESTVulnerability{Name: "CVE-2019-XXXX"}, nil, "enforcer:3"},
		{api.RESTVulnerability{Name: "CVE-2017-BBBB"}, []string{"stage-1"}, "enforcer:3"},
	}
	for _, n := range negtives {
		if vpf.filterOneVulREST(&n.v, n.domains, n.image) {
			t.Errorf("Vulnerability negtive test fails: %v", n)
		}
	}

	tests := []struct {
		skip bool
		v    api.RESTVulnerability
		idns []api.RESTIDName
		tag  string
	}{
		{true, api.RESTVulnerability{Name: "CVE-2018-BBBB"}, []api.RESTIDName{}, ""},
		{true, api.RESTVulnerability{Name: "CVE-2018-BBBB"}, nil, ""},
		{true, api.RESTVulnerability{Name: "CVE-2018-BBBB"}, nil, "test"},
	}
	for _, s := range tests {
		r := vpf.FilterVulREST([]*api.RESTVulnerability{&s.v}, s.idns, s.tag)
		if !s.skip && len(r) == 0 {
			t.Errorf("Vulnerability negtive test fails: %v", s)
		} else if s.skip {
			if s.tag == "" && len(r) != 0 {
				t.Errorf("Vulnerability positive test fails: %v", s)
			} else if s.tag != "" && (len(r) == 0 || r[0].Tags[0] != s.tag) {
				t.Errorf("Vulnerability positive test fails: %v", s)
			}
		}
	}
}

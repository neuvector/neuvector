package rest

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
)

func TestNormalizeForURL(t *testing.T) {
	goodFilters := map[string]share.CLUSFileMonitorFilter{
		"/var/lib/dpkg/status":  share.CLUSFileMonitorFilter{Path: "/var/lib/dpkg/status", Regex: ""},
		"/var/lib/rpm/Packages": share.CLUSFileMonitorFilter{Path: "/var/lib/rpm/Packages", Regex: ""},
		"/lib/apk/db/installed": share.CLUSFileMonitorFilter{Path: "/lib/apk/db/installed", Regex: ""},
		"/etc/hosts":            share.CLUSFileMonitorFilter{Path: "/etc/hosts", Regex: ""},
		"/etc/passwd":           share.CLUSFileMonitorFilter{Path: "/etc/passwd", Regex: ""},
		"/etc/resolv.conf":      share.CLUSFileMonitorFilter{Path: "/etc/resolv\\.conf", Regex: ""},
		"/lib/ld-linux.*":       share.CLUSFileMonitorFilter{Path: "/lib", Regex: "ld-linux\\..*"},
		"/lib/libc.*":           share.CLUSFileMonitorFilter{Path: "/lib", Regex: "libc\\..*"},
		"/lib/libpthread*":      share.CLUSFileMonitorFilter{Path: "/lib", Regex: "libpthread.*"},
		"/lib64/ld-linux*":      share.CLUSFileMonitorFilter{Path: "/lib64", Regex: "ld-linux.*"},
		"/lib64/libc.*":         share.CLUSFileMonitorFilter{Path: "/lib64", Regex: "libc\\..*"},
		"/lib64/libpthread*":    share.CLUSFileMonitorFilter{Path: "/lib64", Regex: "libpthread.*"},
		"/bin/*":                share.CLUSFileMonitorFilter{Path: "/bin", Regex: ".*"},
		"/sbin/*":               share.CLUSFileMonitorFilter{Path: "/sbin", Regex: ".*"},
		"/usr/bin/*":            share.CLUSFileMonitorFilter{Path: "/usr/bin", Regex: ".*"},
		"/usr/sbin/*":           share.CLUSFileMonitorFilter{Path: "/usr/sbin", Regex: ".*"},
		"/usr/local/bin/*":      share.CLUSFileMonitorFilter{Path: "/usr/local/bin", Regex: ".*"},
		"/usr/local/sbin/*":     share.CLUSFileMonitorFilter{Path: "/usr/local/sbin", Regex: ".*"},
		"/home/*/.ssh/*":        share.CLUSFileMonitorFilter{Path: "/home/.*/\\.ssh", Regex: ".*"},
		"/*/*":                  share.CLUSFileMonitorFilter{Path: "/.*", Regex: ".*"},
		"/home/opt/*.php":       share.CLUSFileMonitorFilter{Path: "/home/opt", Regex: ".*\\.php"},
		"/home/opt/lib*.a":      share.CLUSFileMonitorFilter{Path: "/home/opt", Regex: "lib.*\\.a"},
		"/test":                 share.CLUSFileMonitorFilter{Path: "/test", Regex: ""},
		"/test/../ab/*":         share.CLUSFileMonitorFilter{Path: "/ab", Regex: ".*"},
		"/test/./ab/*":          share.CLUSFileMonitorFilter{Path: "/test/ab", Regex: ".*"},
		"/lib/":                 share.CLUSFileMonitorFilter{Path: "/lib", Regex: ".*"},
	}
	badFilters := map[string]share.CLUSFileMonitorFilter{
		"/test/./<ab>/*": share.CLUSFileMonitorFilter{Path: "", Regex: ""},
	}

	for k, v := range goodFilters {
		base, regex, ok := parseFileFilter(k)
		if !ok || base != v.Path || regex != v.Regex {
			t.Errorf("Error: %v,result: %v\n", k, ok)
			t.Errorf("  Expect: %v,%v\n", v.Path, v.Regex)
			t.Errorf("  Actual: %v,%v\n", base, regex)
		}
	}
	for k, v := range badFilters {
		base, regex, ok := parseFileFilter(k)
		if ok || base != v.Path || regex != v.Regex {
			t.Errorf("Error: %v,result: %v\n", k, ok)
			t.Errorf("  Expect: %v,%v\n", v.Path, v.Regex)
			t.Errorf("  Actual: %v,%v\n", base, regex)
		}
	}
}

func TestFileRuleShow(t *testing.T) {
	preTest()

	mc := mockCache{
		groups:  make(map[string]*api.RESTGroup),
		filters: make(map[string][]*api.RESTFileMonitorFilter),
	}

	mc.groups["external"] = &api.RESTGroup {
		RESTGroupBrief: api.RESTGroupBrief{
			Name: 	"external",
			Kind:	share.GroupKindExternal,
		},
	}

	mc.groups["containers"] = &api.RESTGroup {
		RESTGroupBrief: api.RESTGroupBrief{
			Name: 	"contrainers",
			Kind:	share.GroupKindContainer,
		},
	}

	mf := &api.RESTFileMonitorFilter{
		Filter:    "/etc/passwd",
		Recursive: false,
		Behavior:  share.FileAccessBehaviorMonitor,
		CfgType:   api.CfgTypeUserCreated,
		Apps:	   make([]string, 0),
	}
	ff := make([]*api.RESTFileMonitorFilter, 0)
	ff = append(ff, mf)
	mc.filters["external"] = ff
	mc.filters["containers"] = ff

	//
	cacher = &mc

	// Read existing group
	{
		w := restCall("GET", "/v1/file_monitor/containers", nil, api.UserRoleAdmin)
		if w.status == http.StatusOK {
			var resp api.RESTFileMonitorProfileData
			json.Unmarshal(w.body, &resp)
			if !reflect.DeepEqual(resp.Profile.Filters, ff) {
				t.Errorf("Status is OK but a wrong content")
				t.Logf("  Resp: %+v\n", ff)
			}
		} else {
			t.Errorf("Status is not OK")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}
	}

	// Read non-existing group
	{
		w := restCall("GET", "/v1/file_monitor/nv.nothing", nil, api.UserRoleAdmin)
		if w.status != http.StatusNotFound {
			t.Errorf("Read non-existing group: Status is OK")
			t.Logf("  Expect status: %+v\n", http.StatusOK)
			t.Logf("  Actual status: %+v\n", w.status)
		}
	}

	// Read an invalid-type group
	{
		w := restCall("GET", "/v1/file_monitor/external", nil, api.UserRoleAdmin)
		if w.status != http.StatusBadRequest {
			t.Errorf("Read an invalid-type group: Status is OK")
			t.Logf("  Expect status: %+v\n", http.StatusBadRequest)
			t.Logf("  Actual status: %+v\n", w.status)
		}
	}
	postTest()
}
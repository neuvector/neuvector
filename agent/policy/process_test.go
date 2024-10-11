package policy

import (
	"fmt"
	"testing"

	"github.com/neuvector/neuvector/share"
)

type appSample struct {
	name string
	path string
	good bool
}

// //// Utility
func printProfile(pp *share.CLUSProcessProfileEntry) {
	fmt.Printf("profile: %+v, %+v, %+v\n", pp.Name, pp.Path, pp.Action)
}

// //// Utility
func printApps(apps []appSample) {
	fmt.Printf("apps: count %d\n", len(apps))
	for i, app := range apps {
		fmt.Printf("[%d]: %+v, %+v, %+v\n", i, app.name, app.path, app.good)
	}
}

// //// Utility
func tester(pp *share.CLUSProcessProfileEntry, apps []appSample) bool {
	for _, app := range apps {
		ppe := &share.CLUSProcessProfileEntry{
			Name: app.name,
			Path: app.path,
		}

		//////// match policy
		matched := MatchProfileProcess(pp, ppe)
		if matched {
			if (pp.Action == share.PolicyActionAllow && !app.good) ||
				(pp.Action == share.PolicyActionDeny && app.good) {
				printProfile(pp) // optional
				printApps(apps)  // optional
				fmt.Printf("failed[%v:%v]: [%v, %v] [%v, %v]\n", app.good, pp.Action, app.name, app.path, pp.Name, pp.Path)
				return false
			}
		} else { // not matched
			if app.good {
				printProfile(pp) // optional
				printApps(apps)  // optional
				fmt.Printf("not matched: [%v, %v]\n", app.name, app.path)
				return false
			}
		}
	}
	return true
}

func TestWildcardPathEmptyPolicy(t *testing.T) {
	profile := &share.CLUSProcessProfileEntry{ // rule
		Name: "bash", Path: "", Action: share.PolicyActionAllow,
	}

	apps := []appSample{ // app
		{name: "dash", path: "/usr/bin"},
		{name: "dash", path: "bash"},
		{name: "bash", path: "/usr/bin/bash", good: true},
		{name: "bash", path: "/usr/bin/busybox", good: true},
	}

	if !tester(profile, apps) {
		t.Errorf("")
	}
}

func TestAllowAllPolicy(t *testing.T) {
	profile := &share.CLUSProcessProfileEntry{ // rule
		Name: "*", Path: "*", Action: share.PolicyActionAllow,
	}

	apps := []appSample{ // app
		{name: "dash", path: "/usr/bin", good: true},
		{name: "dash", path: "bash", good: true},
		{name: "bash", path: "/usr/bin/bash", good: true},
		{name: "bash", path: "/usr/bin/busybox", good: true},
	}

	if !tester(profile, apps) {
		t.Errorf("")
	}
}

func TestExactMatchedPolicy(t *testing.T) {
	profile := &share.CLUSProcessProfileEntry{ // rule
		Name: "bash", Path: "/usr/bin/bash", Action: share.PolicyActionAllow,
	}

	apps := []appSample{ // app
		{name: "dash", path: "/usr/bin"},
		{name: "bash", path: "/usr/bin/bash", good: true},
		{name: "bash", path: "/usr/bash"},
		{name: "bash", path: "/busybox"},
	}

	if !tester(profile, apps) {
		t.Errorf("")
	}
}

func TestRecursiveMatchedPolicy(t *testing.T) {
	profile := &share.CLUSProcessProfileEntry{ // rule
		Name: "bash", Path: "/usr/bin/*", Action: share.PolicyActionAllow,
	}

	apps := []appSample{ // app
		{name: "bash", path: "/usr/bin"},
		{name: "bash", path: "/usr/bin/bash", good: true},
		{name: "bash", path: "/usr/bin/local/bash", good: true},
		{name: "bash", path: "/usr/local/bash"},
		{name: "bash", path: "/busybox"},
		{name: "ps", path: "/usr/bin/local/bash", good: true}, // ????: TODO
	}

	if !tester(profile, apps) {
		t.Errorf("")
	}
}

func TestRecursiveMatchedPolicy2(t *testing.T) {
	profile := &share.CLUSProcessProfileEntry{ // rule
		Name: "bash", Path: "*", Action: share.PolicyActionAllow,
	}

	apps := []appSample{ // app
		{name: "bash", path: "/usr/bin", good: true},
		{name: "bash", path: "/usr/bin/bash", good: true},
		{name: "bash", path: "/usr/bin/local/bash", good: true},
		{name: "bash", path: "/usr/local/bash", good: true},
		{name: "bash", path: "/busybox", good: true},
	}

	if !tester(profile, apps) {
		t.Errorf("")
	}
}

func TestRecursiveMatchedPolicy3(t *testing.T) {
	profile := &share.CLUSProcessProfileEntry{ // rule
		Name: "bash", Path: "", Action: share.PolicyActionAllow,
	}

	apps := []appSample{ // app
		{name: "bash", path: "/usr/bin", good: true},
		{name: "bash", path: "/usr/bin/bash", good: true},
		{name: "bash", path: "/usr/bin/local/bash", good: true},
		{name: "bash", path: "/usr/local/bash", good: true},
		{name: "bash", path: "/busybox", good: true},
	}

	if !tester(profile, apps) {
		t.Errorf("")
	}
}

func TestRecursiveMatchedPolicy4(t *testing.T) {
	profile := &share.CLUSProcessProfileEntry{ // rule
		Name: "bash", Path: "/*", Action: share.PolicyActionAllow,
	}

	apps := []appSample{ // app
		{name: "bash", path: "/usr/bin", good: true},
		{name: "bash", path: "/usr/bin/bash", good: true},
		{name: "bash", path: "/usr/bin/local/bash", good: true},
		{name: "bash", path: "/usr/local/bash", good: true},
		{name: "bash", path: "/busybox", good: true},
	}

	if !tester(profile, apps) {
		t.Errorf("")
	}
}

func TestBusyboxPolicy(t *testing.T) {
	profile := &share.CLUSProcessProfileEntry{ // rule
		Name: "cat", Path: "/usr/bin/busybox", Action: share.PolicyActionAllow,
	}

	apps := []appSample{ // app
		{name: "ps", path: "/usr/bin/busybox"},
		{name: "cat", path: "/usr/bin/busybox", good: true},
		{name: "cat", path: "/usr/local/cat"},
		{name: "cat", path: "/busybox"},
	}

	if !tester(profile, apps) {
		t.Errorf("")
	}
}

func TestWildcardNameRecursivePathPolicy(t *testing.T) {
	profile := &share.CLUSProcessProfileEntry{ // rule
		Name: "*", Path: "/usr/bin/*", Action: share.PolicyActionAllow,
	}

	apps := []appSample{ // app
		{name: "bash", path: "/usr/bin"},
		{name: "bash", path: "/usr/bin/bash", good: true},
		{name: "bash", path: "/usr/bin/local/bash", good: true},
		{name: "bash", path: "/usr/local/bash"},
		{name: "bash", path: "/busybox"},
		{name: "ps", path: "/usr/bin/local/bash", good: true}, // ????
	}

	if !tester(profile, apps) {
		t.Errorf("")
	}
}

func TestWildcardNamePolicy(t *testing.T) {
	profile := &share.CLUSProcessProfileEntry{ // rule
		Name: "*", Path: "/bin/busybox", Action: share.PolicyActionAllow,
	}

	apps := []appSample{ // app
		{name: "bash", path: "/usr/bin"},
		{name: "sh", path: "/bin/busybox", good: true},
		{name: "ps", path: "/bin/busybox", good: true},
	}

	if !tester(profile, apps) {
		t.Errorf("")
	}
}

func TestWildcardNameDenyPolicy(t *testing.T) {
	profile := &share.CLUSProcessProfileEntry{ // deny rule
		Name: "*", Path: "/bin/busybox", Action: share.PolicyActionDeny,
	}

	apps := []appSample{ // app
		{name: "sh", path: "/bin/busybox"},
		{name: "ps", path: "/bin/busybox"},
	}

	if !tester(profile, apps) {
		t.Errorf("")
	}

	profile2 := &share.CLUSProcessProfileEntry{ // allow rule
		Name: "*", Path: "/bin/busybox", Action: share.PolicyActionAllow,
	}

	apps2 := []appSample{ // app
		{name: "sh", path: "/bin/busybox", good: true},
		{name: "ps", path: "/bin/busybox", good: true},
	}

	if !tester(profile2, apps2) {
		t.Errorf("")
	}
}

func TestRecursivePathDenyPolicy(t *testing.T) {
	profile := &share.CLUSProcessProfileEntry{ // deny rule
		Name: "ps", Path: "/bin/*", Action: share.PolicyActionDeny,
	}

	apps := []appSample{ // app
		{name: "sh", path: "/bin/busybox"},
		{name: "ps", path: "/bin/busybox"},
	}

	if !tester(profile, apps) {
		t.Errorf("")
	}

	profile2 := &share.CLUSProcessProfileEntry{ // allow rule
		Name: "ps", Path: "/bin/*", Action: share.PolicyActionAllow,
	}

	apps2 := []appSample{ // app
		{name: "sh", path: "/bin/busybox"},
		{name: "ps", path: "/bin/busybox", good: true},
	}

	if !tester(profile2, apps2) {
		t.Errorf("")
	}
}

func TestWildcardNameRecursivePathDenyPolicy(t *testing.T) {
	profile := &share.CLUSProcessProfileEntry{ // deny rule
		Name: "*", Path: "/bin/*", Action: share.PolicyActionDeny,
	}

	apps := []appSample{ // app
		{name: "sh", path: "/bin/busybox"},
		{name: "ps", path: "/bin/busybox"},
	}

	if !tester(profile, apps) {
		t.Errorf("")
	}

	profile2 := &share.CLUSProcessProfileEntry{ // allow rule
		Name: "*", Path: "/bin/*", Action: share.PolicyActionAllow,
	}

	apps2 := []appSample{ // app
		{name: "sh", path: "/bin/busybox", good: true},
		{name: "ps", path: "/bin/busybox", good: true},
	}

	if !tester(profile2, apps2) {
		t.Errorf("")
	}
}

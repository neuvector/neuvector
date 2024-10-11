package main

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/neuvector/neuvector/agent/policy"
	"github.com/neuvector/neuvector/share"
)

type appSample struct {
	name string
	path string
	good bool
}

// //// Utility
func printProfile(profile []*share.CLUSProcessProfileEntry) {
	fmt.Printf("profile: count %d\n", len(profile))
	for i, pp := range profile {
		fmt.Printf("[%d]: %+v, %+v, %+v\n", i, pp.Name, pp.Path, pp.Action)
	}
}

// //// Utility
func printApps(apps []appSample) {
	fmt.Printf("apps: count %d\n", len(apps))
	for i, app := range apps {
		fmt.Printf("[%d]: %+v, %+v, %+v\n", i, app.name, app.path, app.good)
	}
}

// //// Utility
func tester(profile []*share.CLUSProcessProfileEntry, apps []appSample) bool {
	for _, app := range apps {
		ppe := &share.CLUSProcessProfileEntry{
			Name: app.name,
			Path: app.path,
		}

		//////// match policy
		bFound := false
		for _, pp := range profile {
			matched := policy.MatchProfileProcess(pp, ppe)
			if matched {
				bFound = true
				if (pp.Action == share.PolicyActionAllow && !app.good) ||
					(pp.Action == share.PolicyActionDeny && app.good) {
					printProfile(profile) // optional
					printApps(apps)       // optional
					fmt.Printf("failed[%v:%v]: [%v, %v] [%v, %v]\n", app.good, pp.Action, app.name, app.path, pp.Name, pp.Path)
					return false
				}
				break
			}
		}

		/////
		if !bFound && app.good {
			printProfile(profile) // optional
			printApps(apps)       // optional
			fmt.Printf("not matched: [%v, %v]\n", app.name, app.path)
			return false
		}
	}
	return true
}

func TestWildcardPathEmptyPolicy(t *testing.T) {
	grp_rule1 := []*share.CLUSProcessProfileEntry{
		{Name: "ls", Path: "/usr/bin/busybox", Action: share.PolicyActionAllow},
	}

	grp_rule2 := []*share.CLUSProcessProfileEntry{
		{Name: "ps", Path: "", Action: share.PolicyActionAllow},
	}

	container_rule := []*share.CLUSProcessProfileEntry{
		{Name: "bash", Path: "/usr/bin/bash", Action: share.PolicyActionAllow},
		{Name: "cat", Path: "/usr/bin/cat", Action: share.PolicyActionDeny},
	}

	// merged rules
	profile := grp_rule1
	profile = append(profile, grp_rule2...)
	profile = append(profile, container_rule...)
	profile = mergeProcessProfiles(profile)

	// testing apps
	apps := []appSample{ // app
		{name: "sh", path: "/bin/busybox"},
		{name: "ps", path: "/bin/busybox", good: true},
		{name: "cat", path: "/usr/bin/cat"},
		{name: "bash", path: "/usr/bin/bash", good: true},
		{name: "ps", path: "/bin/ps", good: true},
	}

	//
	if !tester(profile, apps) {
		t.Errorf("")
	}
}

func TestAllowAllPolicy(t *testing.T) {
	grp_rule1 := []*share.CLUSProcessProfileEntry{
		{Name: "ls", Path: "/usr/bin/busybox", Action: share.PolicyActionAllow},
	}

	grp_rule2 := []*share.CLUSProcessProfileEntry{
		{Name: "*", Path: "*", Action: share.PolicyActionAllow},
	}

	container_rule := []*share.CLUSProcessProfileEntry{
		{Name: "bash", Path: "/usr/bin/bash", Action: share.PolicyActionAllow},
		{Name: "cat", Path: "/usr/bin/cat", Action: share.PolicyActionDeny},
	}

	// merged rules
	profile := grp_rule1
	profile = append(profile, grp_rule2...)
	profile = append(profile, container_rule...)
	profile = mergeProcessProfiles(profile)

	// testing apps
	apps := []appSample{ // app
		{name: "sh", path: "/bin/busybox", good: true},
		{name: "ps", path: "/bin/busybox", good: true},
		{name: "cat", path: "/usr/bin/cat", good: true},
	}

	//
	if !tester(profile, apps) {
		t.Errorf("")
	}
}

func TestExactMatchedPolicy(t *testing.T) {
	grp_rule1 := []*share.CLUSProcessProfileEntry{
		{Name: "ls", Path: "/usr/bin/busybox", Action: share.PolicyActionAllow},
	}

	grp_rule2 := []*share.CLUSProcessProfileEntry{
		{Name: "ps", Path: "/bin/ps", Action: share.PolicyActionAllow},
	}

	container_rule := []*share.CLUSProcessProfileEntry{
		{Name: "bash", Path: "/usr/bin/bash", Action: share.PolicyActionAllow},
		{Name: "cat", Path: "/usr/bin/cat", Action: share.PolicyActionDeny},
	}

	// merged rules
	profile := grp_rule1
	profile = append(profile, grp_rule2...)
	profile = append(profile, container_rule...)
	profile = mergeProcessProfiles(profile)

	// testing apps
	apps := []appSample{ // app
		{name: "sh", path: "/bin/busybox"},
		{name: "ps", path: "/bin/busybox"},
		{name: "cat", path: "/usr/bin/cat"},
		{name: "bash", path: "/usr/bin/bash", good: true},
		{name: "ps", path: "/bin/ps", good: true},
	}

	//
	if !tester(profile, apps) {
		t.Errorf("")
	}
}

func TestRecursiveMatchedPolicy(t *testing.T) {
	grp_rule1 := []*share.CLUSProcessProfileEntry{
		{Name: "ls", Path: "/usr/bin/*", Action: share.PolicyActionAllow},
	}

	grp_rule2 := []*share.CLUSProcessProfileEntry{
		{Name: "ps", Path: "/bin/ps", Action: share.PolicyActionAllow},
	}

	container_rule := []*share.CLUSProcessProfileEntry{
		{Name: "bash", Path: "/usr/bin/bash", Action: share.PolicyActionAllow},
		{Name: "cat", Path: "/usr/bin/cat", Action: share.PolicyActionDeny},
	}

	// merged rules
	profile := grp_rule1
	profile = append(profile, grp_rule2...)
	profile = append(profile, container_rule...)
	profile = mergeProcessProfiles(profile)

	// testing apps
	apps := []appSample{ // app
		{name: "sh", path: "/bin/busybox"},
		{name: "ls", path: "/bin/busybox"},
		{name: "ls", path: "/usr/ls"},
		{name: "ls", path: "/usr/bin/ls", good: true},
		{name: "ls", path: "/usr/bin/opt/ls", good: true},
		{name: "bash", path: "/usr/bin/bash", good: true},
		{name: "ps", path: "/bin/ps", good: true},
	}

	//
	if !tester(profile, apps) {
		t.Errorf("")
	}
}

func TestBusyboxPolicy(t *testing.T) {
	grp_rule1 := []*share.CLUSProcessProfileEntry{
		{Name: "ls", Path: "/usr/bin/busybox", Action: share.PolicyActionAllow},
	}

	grp_rule2 := []*share.CLUSProcessProfileEntry{
		{Name: "ps", Path: "/bin/ps", Action: share.PolicyActionAllow},
	}

	container_rule := []*share.CLUSProcessProfileEntry{
		{Name: "bash", Path: "/usr/bin/bash", Action: share.PolicyActionAllow},
		{Name: "cat", Path: "/usr/bin/cat", Action: share.PolicyActionDeny},
	}

	// merged rules
	profile := grp_rule1
	profile = append(profile, grp_rule2...)
	profile = append(profile, container_rule...)
	profile = mergeProcessProfiles(profile)

	// testing apps
	apps := []appSample{ // app
		{name: "ls", path: "/bin/my_busybox"},
		{name: "ls", path: "/usr/bin/busybox", good: true},
		{name: "ps", path: "/bin/busybox"},
		{name: "cat", path: "/usr/bin/cat"},
		{name: "bash", path: "/usr/bin/bash", good: true},
		{name: "ps", path: "/bin/ps", good: true},
	}

	//
	if !tester(profile, apps) {
		t.Errorf("")
	}
}

func TestRecursiveWildcardPolicy(t *testing.T) {
	grp_rule1 := []*share.CLUSProcessProfileEntry{
		{Name: "ls", Path: "/usr/bin/busybox", Action: share.PolicyActionAllow},
	}

	grp_rule2 := []*share.CLUSProcessProfileEntry{
		{Name: "*", Path: "/bin/*", Action: share.PolicyActionAllow},
	}

	container_rule := []*share.CLUSProcessProfileEntry{
		{Name: "bash", Path: "/usr/bin/bash", Action: share.PolicyActionAllow},
		{Name: "cat", Path: "/usr/bin/cat", Action: share.PolicyActionDeny},
	}

	// merged rules
	profile := grp_rule1
	profile = append(profile, grp_rule2...)
	profile = append(profile, container_rule...)
	profile = mergeProcessProfiles(profile)

	// testing apps
	apps := []appSample{ // app
		{name: "ls", path: "/bin/test/my_busybox", good: true},
		{name: "ls", path: "/usr/bin/busybox", good: true},
		{name: "ps", path: "/bin/busybox", good: true},
		{name: "cat", path: "/usr/bin/cat"},
		{name: "bash", path: "/usr/bin/bash", good: true},
		{name: "ps", path: "/bin/ps", good: true},
	}

	//
	if !tester(profile, apps) {
		t.Errorf("")
	}
}

func TestWildcardNamePolicy(t *testing.T) {
	grp_rule1 := []*share.CLUSProcessProfileEntry{
		{Name: "*", Path: "/usr/bin/busybox", Action: share.PolicyActionAllow},
	}

	grp_rule2 := []*share.CLUSProcessProfileEntry{
		{Name: "ps", Path: "/bin/ps", Action: share.PolicyActionAllow},
	}

	container_rule := []*share.CLUSProcessProfileEntry{
		{Name: "bash", Path: "/usr/bin/bash", Action: share.PolicyActionAllow},
		{Name: "cat", Path: "/usr/bin/cat", Action: share.PolicyActionDeny},
	}

	// merged rules
	profile := grp_rule1
	profile = append(profile, grp_rule2...)
	profile = append(profile, container_rule...)
	profile = mergeProcessProfiles(profile)

	// testing apps
	apps := []appSample{ // app
		{name: "ls", path: "/bin/my_busybox"},
		{name: "ls", path: "/usr/bin/busybox", good: true},
		{name: "ps", path: "/usr/bin/busybox", good: true},
		{name: "cat", path: "/usr/bin/busybox", good: true},
		{name: "cat", path: "/usr/bin/cat"},
		{name: "bash", path: "/usr/bin/bash", good: true},
		{name: "ps", path: "/bin/ps", good: true},
	}

	//
	if !tester(profile, apps) {
		t.Errorf("")
	}
}

func TestWildcardPathDenyPolicy(t *testing.T) {
	grp_rule1 := []*share.CLUSProcessProfileEntry{
		{Name: "*", Path: "/usr/bin/busybox", Action: share.PolicyActionAllow},
	}

	grp_rule2 := []*share.CLUSProcessProfileEntry{
		{Name: "ps", Path: "*", Action: share.PolicyActionDeny},
	}

	container_rule := []*share.CLUSProcessProfileEntry{
		{Name: "bash", Path: "/usr/bin/bash", Action: share.PolicyActionAllow},
		{Name: "cat", Path: "/usr/bin/cat", Action: share.PolicyActionDeny},
		{Name: "ps", Path: "/usr/bin/ps", Action: share.PolicyActionAllow}, // ignored
	}

	// merged rules
	profile := grp_rule1
	profile = append(profile, grp_rule2...)
	profile = append(profile, container_rule...)
	profile = mergeProcessProfiles(profile)

	// testing apps
	apps := []appSample{ // app
		{name: "ls", path: "/bin/my_busybox"},
		{name: "ls", path: "/usr/bin/busybox", good: true},
		{name: "ps", path: "/usr/bin/busybox"},
		{name: "cat", path: "/usr/bin/busybox", good: true},
		{name: "cat", path: "/usr/bin/cat"},
		{name: "bash", path: "/usr/bin/bash", good: true},
		{name: "ps", path: "/bin/ps"},
	}

	//
	if !tester(profile, apps) {
		t.Errorf("")
	}
}

func TestWildcardNameDenyPolicy(t *testing.T) {
	grp_rule1 := []*share.CLUSProcessProfileEntry{
		{Name: "*", Path: "/usr/bin/busybox", Action: share.PolicyActionDeny},
	}

	grp_rule2 := []*share.CLUSProcessProfileEntry{
		{Name: "ps", Path: "/usr/bin/busybox", Action: share.PolicyActionAllow},
	}

	container_rule := []*share.CLUSProcessProfileEntry{
		{Name: "bash", Path: "/usr/bin/bash", Action: share.PolicyActionAllow},
		{Name: "cat", Path: "/usr/bin/cat", Action: share.PolicyActionAllow},
		{Name: "ps", Path: "/usr/bin/ps", Action: share.PolicyActionAllow}, // ignored
	}

	// merged rules
	profile := grp_rule1
	profile = append(profile, grp_rule2...)
	profile = append(profile, container_rule...)
	profile = mergeProcessProfiles(profile)

	// testing apps
	apps := []appSample{ // app
		{name: "ls", path: "/bin/my_busybox"},
		{name: "ls", path: "/usr/bin/busybox"},
		{name: "ps", path: "/usr/bin/busybox"},
		{name: "cat", path: "/usr/bin/busybox"},
		{name: "cat", path: "/usr/bin/cat", good: true},
		{name: "bash", path: "/usr/bin/bash", good: true},
		{name: "ps", path: "/bin/ps"},
	}

	//
	if !tester(profile, apps) {
		t.Errorf("")
	}
}

func TestRecursivePathDenyPolicy(t *testing.T) {
	grp_rule1 := []*share.CLUSProcessProfileEntry{
		{Name: "*", Path: "/usr/bin/busybox", Action: share.PolicyActionAllow},
	}

	grp_rule2 := []*share.CLUSProcessProfileEntry{
		{Name: "ps", Path: "/usr/bin/*", Action: share.PolicyActionDeny},
	}

	container_rule := []*share.CLUSProcessProfileEntry{
		{Name: "bash", Path: "/usr/bin/bash", Action: share.PolicyActionAllow},
		{Name: "cat", Path: "/usr/bin/cat", Action: share.PolicyActionDeny},
		{Name: "ps", Path: "/usr/bin/ps", Action: share.PolicyActionAllow}, // ignored
	}

	// merged rules
	profile := grp_rule1
	profile = append(profile, grp_rule2...)
	profile = append(profile, container_rule...)
	profile = mergeProcessProfiles(profile)

	// testing apps
	apps := []appSample{ // app
		{name: "ls", path: "/usr/bin/busybox", good: true},
		{name: "ps", path: "/usr/bin/busybox"},
		{name: "cat", path: "/usr/bin/busybox", good: true},
		{name: "cat", path: "/usr/bin/cat"},
		{name: "bash", path: "/usr/bin/bash", good: true},
		{name: "ps", path: "/bin/ps"},
	}

	//
	if !tester(profile, apps) {
		t.Errorf("")
	}
}

func TestWildcardNameRecursivePathDenyPolicy(t *testing.T) {
	grp_rule1 := []*share.CLUSProcessProfileEntry{
		{Name: "*", Path: "/bin/busybox", Action: share.PolicyActionAllow},
	}

	grp_rule2 := []*share.CLUSProcessProfileEntry{
		{Name: "*", Path: "/usr/bin/*", Action: share.PolicyActionDeny},
	}

	container_rule := []*share.CLUSProcessProfileEntry{
		{Name: "bash", Path: "/usr/bin/bash", Action: share.PolicyActionAllow}, // ignored
		{Name: "cat", Path: "/usr/bin/cat", Action: share.PolicyActionDeny},
		{Name: "ps", Path: "/bin/ps", Action: share.PolicyActionAllow},
	}

	// merged rules
	profile := grp_rule1
	profile = append(profile, grp_rule2...)
	profile = append(profile, container_rule...)
	profile = mergeProcessProfiles(profile)

	// testing apps
	apps := []appSample{ // app
		{name: "ls", path: "/usr/bin/ls"},
		{name: "ps", path: "/usr/bin/ps"},
		{name: "cat", path: "/usr/bin/busybox"},
		{name: "cat", path: "/usr/bin/cat"},
		{name: "bash", path: "/usr/bin/bash"},
		{name: "ps", path: "/bin/ps", good: true},
		{name: "cat", path: "/bin/busybox", good: true},
	}

	//
	if !tester(profile, apps) {
		t.Errorf("")
	}
}

func TestBashDenyPolicy(t *testing.T) {
	grp_rule1 := []*share.CLUSProcessProfileEntry{
		{Name: "bash", Path: "", Action: share.PolicyActionDeny},
	}

	grp_rule2 := []*share.CLUSProcessProfileEntry{
		{Name: "*", Path: "/usr/bin/*", Action: share.PolicyActionAllow},
		{Name: "*", Path: "/usr/bin/busybox", Action: share.PolicyActionAllow},
	}

	container_rule := []*share.CLUSProcessProfileEntry{
		{Name: "bash", Path: "/usr/bin/bash", Action: share.PolicyActionAllow}, // ignored
		{Name: "cat", Path: "/usr/bin/cat", Action: share.PolicyActionDeny},
		{Name: "ps", Path: "/bin/ps", Action: share.PolicyActionAllow},
	}

	// merged rules
	profile := grp_rule1
	profile = append(profile, grp_rule2...)
	profile = append(profile, container_rule...)
	profile = mergeProcessProfiles(profile)

	// testing apps
	apps := []appSample{ // app
		{name: "ls", path: "/usr/bin/ls", good: true},
		{name: "cat", path: "/usr/bin/busybox", good: true},
		{name: "cat", path: "/usr/bin/cat"},
		{name: "bash", path: "/usr/bin/bash"},
	}

	//
	if !tester(profile, apps) {
		t.Errorf("")
	}
}

func TestShellhDenyPolicy(t *testing.T) {
	grp_rule1 := []*share.CLUSProcessProfileEntry{
		{Name: "bash", Path: "", Action: share.PolicyActionDeny},
		{Name: "dash", Path: "", Action: share.PolicyActionDeny},
		{Name: "ash", Path: "", Action: share.PolicyActionDeny},
		{Name: "sh", Path: "", Action: share.PolicyActionDeny},
	}

	grp_rule2 := []*share.CLUSProcessProfileEntry{
		{Name: "*", Path: "/bin/*", Action: share.PolicyActionAllow},
		{Name: "*", Path: "/usr/bin/busybox", Action: share.PolicyActionAllow},
	}

	container_rule := []*share.CLUSProcessProfileEntry{
		{Name: "bash", Path: "/bin/bash", Action: share.PolicyActionAllow}, // ignored
		{Name: "sh", Path: "/bin/sh", Action: share.PolicyActionAllow},     // ignored
		{Name: "ash", Path: "/bin/ash", Action: share.PolicyActionAllow},   // ignored
		{Name: "dash", Path: "/bin/dash", Action: share.PolicyActionAllow}, // ignored
		{Name: "cat", Path: "/usr/bin/cat", Action: share.PolicyActionDeny},
		{Name: "ps", Path: "/bin/ps", Action: share.PolicyActionAllow},
	}

	// merged rules
	profile := grp_rule1
	profile = append(profile, grp_rule2...)
	profile = append(profile, container_rule...)
	profile = mergeProcessProfiles(profile)

	// testing apps
	apps := []appSample{ // app
		{name: "ls", path: "/bin/ls", good: true},
		{name: "cat", path: "/usr/bin/busybox", good: true},
		{name: "sh", path: "/bin/sh"},
		{name: "bash", path: "/bin/bash"},
		{name: "ash", path: "/bin/ash"},
		{name: "dash", path: "/bin/dash"},
	}

	//
	if !tester(profile, apps) {
		t.Errorf("")
	}
}

// /////////////////////////////////////////////////////////
// /// File monitor tests	///////////////////////////////
// /////////////////////////////////////////////////////////
type fileSample struct {
	path     string
	behavior string
	good     bool
}

type monitorRule struct {
	prefix   string
	behavior string
}

/* removed by golint
////// Utility
func printFileMonitorProfile(profile []share.CLUSFileMonitorFilter) {
	fmt.Printf("monitor file profile: count %d\n", len(profile))
	for i, ff := range profile {
		fmt.Printf("[%d]: %+v, %+v, %+v, %+v, %+v, %+v\n", i, ff.Filter, ff.Path, ff.Regex, ff.Behavior, ff.Recursive, ff.CustomerAdd)
	}
}

////// Utility
func printFilePaths(files []fileSample) {
	fmt.Printf("files: count %d\n", len(files))
	for i, f := range files {
		fmt.Printf("[%d]: %+v, %+v, %+v\n", i, f.path, f.behavior, f.good)
	}
}
*/

// //// Utility
func printFileMonitorRules(rules []*monitorRule) {
	fmt.Printf("monitor file rules: count %d\n", len(rules))
	for i, v := range rules {
		fmt.Printf("[%d]: %+v, %+v\n", i, v.prefix, v.behavior)
	}
}

// //// Utility
func printFileAccessRules(rules map[string]*share.CLUSFileAccessFilterRule) {
	fmt.Printf("access file rules: count %d\n", len(rules))
	for filter, v := range rules {
		fmt.Printf("%+v, %+v, %+v\n", filter, v.Apps, v.Behavior)
	}
}

// //// Utility
func buildFileMonitorPrefixRules(profile []share.CLUSFileMonitorFilter) []*monitorRule {
	var rules []*monitorRule
	for _, ff := range profile {
		path := strings.TrimSuffix(ff.Filter, "*")
		path = strings.TrimSuffix(path, "/")
		if ff.Recursive {
			path += "/"
		}
		rules = append(rules, &monitorRule{prefix: path, behavior: ff.Behavior})
		// fmt.Printf("%+v[ %+v ]: %+v\n", path, ff.Filter, ff.Behavior)
	}
	return rules
}

// //// a simplified version to verify FileMonitor entries
func evalFileMonitor(profile []share.CLUSFileMonitorFilter, files []fileSample) bool {
	rules := buildFileMonitorPrefixRules(profile)
	for _, f := range files {
		good := false
		for _, r := range rules {
			if strings.HasPrefix(f.path, r.prefix) {
				good = (f.behavior == r.behavior)
				break
			}
		}

		if f.good != good {
			fmt.Printf("File: %+v, %+v\n", f.path, f.behavior)
			printFileMonitorRules(rules)
			return false
		}
	}
	return true
}

func TestFileMonitorPolicy(t *testing.T) {
	profile := &share.CLUSFileMonitorProfile{Filters: make([]share.CLUSFileMonitorFilter, 0)}

	// grp1
	grp_rule1 := []share.CLUSFileMonitorFilter{
		{Filter: "/etc/secret_block", Path: "/etc/secret_block", Regex: "", Recursive: false, Behavior: share.FileAccessBehaviorBlock, CustomerAdd: true},
	}

	// grp2
	grp_rule2 := []share.CLUSFileMonitorFilter{
		{Filter: "/etc/secret_monitor", Path: "/etc/secret_monitor", Regex: "", Recursive: false, Behavior: share.FileAccessBehaviorMonitor, CustomerAdd: true},
	}

	// workload
	workload_rule := []share.CLUSFileMonitorFilter{
		{Filter: "/usr/local/sbin/*", Path: "/usr/local/sbin", Regex: ".*", Recursive: true, Behavior: share.FileAccessBehaviorMonitor, CustomerAdd: false},
		{Filter: "/lib/libpthread*", Path: "/lib", Regex: "libpthread.*", Recursive: false, Behavior: share.FileAccessBehaviorMonitor, CustomerAdd: false},
		{Filter: "/tmp/secret_monitor", Path: "/etc/secret_monitor", Regex: "", Recursive: false, Behavior: share.FileAccessBehaviorMonitor, CustomerAdd: true},
		{Filter: "/tmp/secret_block", Path: "/tmp/secret_block", Regex: "", Recursive: false, Behavior: share.FileAccessBehaviorBlock, CustomerAdd: true},
	}

	// merged rules
	profile.Filters = append(profile.Filters, grp_rule1...)
	profile.Filters = append(profile.Filters, grp_rule2...)
	profile.Filters = append(profile.Filters, workload_rule...)
	profile.Filters = mergeFileMonitorProfile(profile.Filters)

	// testing files
	files := []fileSample{ // file
		{path: "/tmp/secret_monitor", behavior: share.FileAccessBehaviorMonitor, good: true},
		{path: "/tmp/secret_monitor", behavior: share.FileAccessBehaviorBlock},
		{path: "/tmp/secret_block", behavior: share.FileAccessBehaviorBlock, good: true},
		{path: "/tmp/secret_block", behavior: share.FileAccessBehaviorMonitor},
		{path: "/lib/libpthread4.4", behavior: share.FileAccessBehaviorMonitor, good: true},
		{path: "/lib/libpthread4.4", behavior: share.FileAccessBehaviorBlock},
		{path: "/usr/local/sbin/catlog", behavior: share.FileAccessBehaviorMonitor, good: true},
		{path: "/usr/local/sbin/catlog", behavior: share.FileAccessBehaviorBlock},
		{path: "/usr/local/catlog", behavior: share.FileAccessBehaviorMonitor},
		{path: "/usr/local/catlog", behavior: share.FileAccessBehaviorBlock},
	}

	if !evalFileMonitor(profile.Filters, files) {
		t.Errorf("")
	}
}

func TestFileAccessPolicy(t *testing.T) {
	profile := &share.CLUSFileAccessRule{Filters: make(map[string]*share.CLUSFileAccessFilterRule)}

	/// group 1
	grp_rule1 := &share.CLUSFileAccessRule{Filters: map[string]*share.CLUSFileAccessFilterRule{
		"/tmp/secret_monitor": {Apps: []string{"vi", "cat"}, Behavior: share.FileAccessBehaviorMonitor},
	}}

	/// group 2
	grp_rule2 := &share.CLUSFileAccessRule{Filters: map[string]*share.CLUSFileAccessFilterRule{
		"/tmp/secret_block": {Apps: []string{"cat"}, Behavior: share.FileAccessBehaviorBlock},
		"/tmp/myfile_m":     {Apps: []string{"open", "touch"}, Behavior: share.FileAccessBehaviorMonitor},
	}}

	/// workload
	workload_rule := &share.CLUSFileAccessRule{Filters: map[string]*share.CLUSFileAccessFilterRule{
		"/tmp/share":    {Apps: []string{"vi"}, Behavior: share.FileAccessBehaviorMonitor},
		"/tmp/myfile_b": {Apps: []string{""}, Behavior: share.FileAccessBehaviorBlock},
		"/tmp/myfile_m": {Apps: []string{"touch", "vi"}, Behavior: share.FileAccessBehaviorBlock},
	}}

	///
	mergeFileAccessProfile(profile, grp_rule1)
	mergeFileAccessProfile(profile, grp_rule2)
	mergeFileAccessProfile(profile, workload_rule)
	// printFileAccessRules(profile.Filters)

	var filter string
	var v *share.CLUSFileAccessFilterRule
	var apps []string   // correct
	var behavior string // correct
	for filter, v = range profile.Filters {
		switch filter {
		case "/tmp/secret_monitor":
			apps = []string{"vi", "cat"}
			behavior = share.FileAccessBehaviorMonitor
		case "/tmp/secret_block":
			apps = []string{"cat"}
			behavior = share.FileAccessBehaviorBlock
		case "/tmp/share":
			apps = []string{"vi"}
			behavior = share.FileAccessBehaviorMonitor
		case "/tmp/myfile_m":
			apps = []string{"open", "touch", "vi"}
			behavior = share.FileAccessBehaviorBlock
		case "/tmp/myfile_b":
			apps = []string{""}
			behavior = share.FileAccessBehaviorBlock
		default:
			apps = []string{""}
			behavior = "impossible behavior"
		}

		//
		pass := reflect.DeepEqual(v.Apps, apps) && v.Behavior == behavior
		if !pass {
			fmt.Printf("\nFailed at [%+v]: %+v, %+v, expected: %+v, %+v\n\n", filter, v.Apps, v.Behavior, apps, behavior)
			printFileAccessRules(profile.Filters)
			t.Errorf("wrong merged")
		}
	}
}

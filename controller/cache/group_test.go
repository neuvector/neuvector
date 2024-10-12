package cache

import (
	"testing"

	"net"

	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
)

func TestGroupPosMatch(t *testing.T) {
	preTest()

	cts := []share.CLUSCriteriaEntry{
		{Key: "image", Value: "redis", Op: share.CriteriaOpEqual},
		{Key: "image", Value: "mysql", Op: share.CriteriaOpEqual},
		{Key: "domain", Value: "billing", Op: share.CriteriaOpEqual},
	}
	wlc := workloadCache{
		workload: &share.CLUSWorkload{Image: "redis", Domain: "billing"},
	}
	if share.IsWorkloadSelected(wlc.workload, cts, nil) == false {
		t.Errorf("Workload %+v should be selected by %v.", *wlc.workload, cts)
	}

	wlc = workloadCache{
		workload: &share.CLUSWorkload{Image: "mysql", Domain: "billing"},
	}
	if share.IsWorkloadSelected(wlc.workload, cts, nil) == false {
		t.Errorf("Workload %+v should be selected by %v.", *wlc.workload, cts)
	}

	wlc = workloadCache{
		workload: &share.CLUSWorkload{Image: "oracle", Domain: "billing"},
	}
	if share.IsWorkloadSelected(wlc.workload, cts, nil) == true {
		t.Errorf("Workload %+v should not be selected by %v.", *wlc.workload, cts)
	}

	wlc = workloadCache{
		workload: &share.CLUSWorkload{Image: "mysql", Domain: "sales"},
	}
	if share.IsWorkloadSelected(wlc.workload, cts, nil) == true {
		t.Errorf("Workload %+v should not be selected by %v.", *wlc.workload, cts)
	}

	postTest()
}

func TestGroupNegMatch(t *testing.T) {
	preTest()

	cts := []share.CLUSCriteriaEntry{
		{Key: "image", Value: "redis", Op: share.CriteriaOpNotEqual},
		{Key: "image", Value: "mysql", Op: share.CriteriaOpNotEqual},
		{Key: "domain", Value: "billing", Op: share.CriteriaOpEqual},
	}
	wlc := workloadCache{
		workload: &share.CLUSWorkload{Image: "redis", Domain: "billing"},
	}
	if share.IsWorkloadSelected(wlc.workload, cts, nil) == true {
		t.Errorf("Workload %+v should not be selected by %v.", *wlc.workload, cts)
	}

	wlc = workloadCache{
		workload: &share.CLUSWorkload{Image: "mysql", Domain: "billing"},
	}
	if share.IsWorkloadSelected(wlc.workload, cts, nil) == true {
		t.Errorf("Workload %+v should not be selected by %v.", *wlc.workload, cts)
	}

	wlc = workloadCache{
		workload: &share.CLUSWorkload{Image: "oracle", Domain: "billing"},
	}
	if share.IsWorkloadSelected(wlc.workload, cts, nil) == false {
		t.Errorf("Workload %+v should be selected by %v.", *wlc.workload, cts)
	}

	wlc = workloadCache{
		workload: &share.CLUSWorkload{Image: "oracle", Domain: "sales"},
	}
	if share.IsWorkloadSelected(wlc.workload, cts, nil) == true {
		t.Errorf("Workload %+v should not be selected by %v.", *wlc.workload, cts)
	}

	postTest()
}

func TestGroupMixMatch(t *testing.T) {
	preTest()

	cts := []share.CLUSCriteriaEntry{
		{Key: "image", Value: "mysql", Op: share.CriteriaOpEqual},
		{Key: "image", Value: "redis", Op: share.CriteriaOpNotEqual},
		{Key: "domain", Value: "billing", Op: share.CriteriaOpEqual},
	}
	wlc := workloadCache{
		workload: &share.CLUSWorkload{Image: "redis", Domain: "billing"},
	}
	if share.IsWorkloadSelected(wlc.workload, cts, nil) == true {
		t.Errorf("Workload %+v should not be selected by %v.", *wlc.workload, cts)
	}

	wlc = workloadCache{
		workload: &share.CLUSWorkload{Image: "mysql", Domain: "billing"},
	}
	if share.IsWorkloadSelected(wlc.workload, cts, nil) == false {
		t.Errorf("Workload %+v should be selected by %v.", *wlc.workload, cts)
	}

	wlc = workloadCache{
		workload: &share.CLUSWorkload{Image: "oracle", Domain: "billing"},
	}
	if share.IsWorkloadSelected(wlc.workload, cts, nil) == false {
		t.Errorf("Workload %+v should be selected by %v.", *wlc.workload, cts)
	}

	wlc = workloadCache{
		workload: &share.CLUSWorkload{Image: "oracle", Domain: "sales"},
	}
	if share.IsWorkloadSelected(wlc.workload, cts, nil) == true {
		t.Errorf("Workload %+v should not be selected by %v.", *wlc.workload, cts)
	}

	postTest()
}

func TestGroupEqualMatch(t *testing.T) {
	preTest()

	cts := []share.CLUSCriteriaEntry{
		{Key: "image", Value: "redis*", Op: share.CriteriaOpEqual},
		{Key: "image", Value: "mysql", Op: share.CriteriaOpEqual},
		{Key: "domain", Value: "billing", Op: share.CriteriaOpEqual},
	}
	wlc := workloadCache{
		workload: &share.CLUSWorkload{Image: "redis", Domain: "billing"},
	}
	if share.IsWorkloadSelected(wlc.workload, cts, nil) == false {
		t.Errorf("Workload %+v should be selected by %v.", *wlc.workload, cts)
	}

	wlc = workloadCache{
		workload: &share.CLUSWorkload{Image: "redis.abc", Domain: "billing"},
	}
	if share.IsWorkloadSelected(wlc.workload, cts, nil) == false {
		t.Errorf("Workload %+v should be selected by %v.", *wlc.workload, cts)
	}

	cts = []share.CLUSCriteriaEntry{
		{Key: "image", Value: "redis*", Op: share.CriteriaOpNotEqual},
		{Key: "image", Value: "*mysql", Op: share.CriteriaOpNotEqual},
		{Key: "domain", Value: "billing", Op: share.CriteriaOpEqual},
	}
	wlc = workloadCache{
		workload: &share.CLUSWorkload{Image: "redis", Domain: "billing"},
	}
	if share.IsWorkloadSelected(wlc.workload, cts, nil) == true {
		t.Errorf("Workload %+v should not be selected by %v.", *wlc.workload, cts)
	}
	postTest()
}

func TestEqualMatch(t *testing.T) {
	poss := [][]string{
		{"*", "nginx"},
		{".*", ".nginx"},
		{"nginx", "nginx"},
		{"nginx.xyz", "nginx.xyz"},
		{"nginx*", "nginx"},
		{"nginx*", "nginx-123"},
		{"nginx.abc*", "nginx.abc-123"},
		{"nginx?", "nginx."},
		{"nginx*?", "nginxabc*"},
		{"nginx*xyz", "nginx.abc.xyz"},
		{"nginx?xyz", "nginx.xyz"},
		{"nginx??xyz", "nginx.-xyz"},
		{"*nginx*", "nginx"},
		{"*nginx*", "111nginx234"},
		{"*nginx", "111nginx"},
		{"**nginx", "111nginx"},
		{"?nginx", "1nginx"},
		{"?nginx", "?nginx"},
		{"?nginx.com", ".nginx.com"},
	}
	for _, kv := range poss {
		if !share.EqualMatch(kv[0], kv[1]) {
			t.Errorf("Pattern %v should match %v.", kv[0], kv[1])
		}
	}

	negs := [][]string{
		{"?", ""},
		{".*", "nginx"},
		{"nginx", "nginx1"},
		{"nginx.xyz", "nginx1xyz"},
		{"nginx*", "abc-nginx-123"},
		{"nginx*", "ngin-123"},
		{"nginx.abc*", "nginx-abc-123"},
		{"nginx?", "nginx.a"},
		{"nginx*?", "?nginxabc*"},
		{"nginx*xyz", "nginx.abc.yz"},
		{"nginx?xyz", "nginx..xyz"},
		{"*nginx*", "ngiinx"},
		{"*nginx", "111nginx-123"},
		{"?nginx", "12nginx"},
		{"?nginx", "?nginx1"},
		{"?nginx.com", ".?nginx-com"},
	}
	for _, kv := range negs {
		if share.EqualMatch(kv[0], kv[1]) {
			t.Errorf("Pattern %v should not match %v.", kv[0], kv[1])
		}
	}
}

func TestGroupPolicyMode(t *testing.T) {
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init(nil, nil)
	clusHelper = &mockCluster

	systemConfigCache.NewServicePolicyMode = share.PolicyModeEvaluate
	systemConfigCache.NewServiceProfileMode = share.PolicyModeEvaluate

	policyApplyIngress = true // k8s
	var extIPs []net.IP = make([]net.IP, 0)
	extIPs = append(extIPs, net.ParseIP("1.1.1.1"))
	extIPs = append(extIPs, net.ParseIP("2.2.2.2"))

	r := resource.Service{Domain: "default", Name: "web1", IPs: []net.IP{net.ParseIP("1.2.3.4")}, Selector: nil, ExternalIPs: extIPs}
	group := createServiceIPGroup(&r)
	if group != nil && group.PolicyMode != "" {
		t.Errorf("Invalid group policy-mode %+v", group)
	}

	r = resource.Service{Domain: "default", Name: "web2", IPs: []net.IP{net.ParseIP("1.2.3.4")}, Selector: map[string]string{"app": "web"}, ExternalIPs: extIPs}
	group = createServiceIPGroup(&r)
	if group != nil && group.PolicyMode != "" {
		t.Errorf("Invalid group policy-mode %+v", group)
	}

	policyApplyIngress = false // openshift

	r = resource.Service{Domain: "default", Name: "web3", IPs: []net.IP{net.ParseIP("1.2.3.4")}, Selector: nil, ExternalIPs: extIPs}
	group = createServiceIPGroup(&r)
	if group != nil && group.PolicyMode != "" {
		t.Errorf("Invalid group policy-mode %+v", group)
	}

	r = resource.Service{Domain: "default", Name: "web4", IPs: []net.IP{net.ParseIP("1.2.3.4")}, Selector: map[string]string{"app": "web"}, ExternalIPs: extIPs}
	group = createServiceIPGroup(&r)
	if group != nil && group.PolicyMode != "" {
		t.Errorf("Invalid group policy-mode %+v", group)
	}

	postTest()
}

package orchestration

import (
	"net"
	"testing"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/container"
)

func TestRancherIPScopeWithLabel(t *testing.T) {
	meta := container.ContainerMeta{
		Labels: map[string]string{
			"io.rancher.container.ip":   "1.2.3.5/16",
			"io.rancher.container.name": "test-container",
		},
	}

	ipnet01 := net.IPNet{IP: net.ParseIP("1.2.3.4"), Mask: net.CIDRMask(16, 32)}
	ipnet02 := net.IPNet{IP: net.ParseIP("1.2.3.5"), Mask: net.CIDRMask(16, 32)}
	ipnet11 := net.IPNet{IP: net.ParseIP("4.3.2.1"), Mask: net.CIDRMask(16, 32)}
	ports := map[string][]share.CLUSIPAddr{
		"eth0": {
			share.CLUSIPAddr{IPNet: ipnet01, Scope: share.CLUSIPAddrScopeLocalhost},
			share.CLUSIPAddr{IPNet: ipnet02, Scope: share.CLUSIPAddrScopeLocalhost},
		},
		"eth1": {
			share.CLUSIPAddr{IPNet: ipnet11, Scope: share.CLUSIPAddrScopeLocalhost},
		},
	}

	driver := &rancher{noop: noop{platform: share.PlatformRancher}}
	driver.SetIPAddrScope(ports, &meta, nil)

	eth0 := ports["eth0"]
	eth1 := ports["eth1"]
	if eth0[0].Scope != share.CLUSIPAddrScopeLocalhost ||
		eth0[1].Scope != share.CLUSIPAddrScopeGlobal ||
		eth1[0].Scope != share.CLUSIPAddrScopeLocalhost {
		t.Errorf("Wrong IP scope set, with container.ip label:\n")
		t.Errorf("    eth0=%v\n", eth0)
		t.Errorf("    eth1=%v\n", eth1)
	}
}

func TestRancherIPScopeWithoutLabel(t *testing.T) {
	meta := container.ContainerMeta{
		Labels: map[string]string{
			"io.rancher.container.name": "test-container",
		},
	}

	ipnet01 := net.IPNet{IP: net.ParseIP("1.2.3.4"), Mask: net.CIDRMask(16, 32)}
	ipnet11 := net.IPNet{IP: net.ParseIP("4.3.2.1"), Mask: net.CIDRMask(16, 32)}
	ports := map[string][]share.CLUSIPAddr{
		"eth0": {
			{IPNet: ipnet01, Scope: share.CLUSIPAddrScopeLocalhost},
		},
		"eth1": {
			{IPNet: ipnet11, Scope: share.CLUSIPAddrScopeLocalhost},
		},
	}

	driver := &rancher{noop: noop{platform: share.PlatformRancher}}
	driver.SetIPAddrScope(ports, &meta, nil)

	eth0 := ports["eth0"]
	eth1 := ports["eth1"]
	if eth0[0].Scope != share.CLUSIPAddrScopeGlobal ||
		eth1[0].Scope != share.CLUSIPAddrScopeLocalhost {
		t.Errorf("Wrong IP scope set, with container.ip label:\n")
		t.Errorf("    eth0=%v\n", eth0)
		t.Errorf("    eth1=%v\n", eth1)
	}

	ports = map[string][]share.CLUSIPAddr{
		"eth0": {
			{IPNet: ipnet01, Scope: share.CLUSIPAddrScopeLocalhost},
		},
	}
	driver.SetIPAddrScope(ports, &meta, nil)

	eth0 = ports["eth0"]
	if eth0[0].Scope != share.CLUSIPAddrScopeGlobal {
		t.Errorf("Wrong IP scope set, with container.ip label:\n")
		t.Errorf("    eth0=%v\n", eth0)
	}
}

func TestRancherIPScopeDefault(t *testing.T) {
	meta := container.ContainerMeta{
		NetMode: "default",
	}

	ipnet01 := net.IPNet{IP: net.ParseIP("172.17.0.2"), Mask: net.CIDRMask(16, 32)}
	ipnet02 := net.IPNet{IP: net.ParseIP("169.254.169.250"), Mask: net.CIDRMask(32, 32)}
	ports := map[string][]share.CLUSIPAddr{
		"eth0": {
			{IPNet: ipnet01, Scope: share.CLUSIPAddrScopeLocalhost},
			{IPNet: ipnet02, Scope: share.CLUSIPAddrScopeLocalhost},
		},
	}

	driver := &rancher{noop: noop{platform: share.PlatformRancher}}
	driver.SetIPAddrScope(ports, &meta, nil)

	eth0 := ports["eth0"]
	if eth0[0].Scope != share.CLUSIPAddrScopeLocalhost ||
		eth0[1].Scope != share.CLUSIPAddrScopeLocalhost {
		t.Errorf("Wrong IP scope set, default net mode:\n")
		t.Errorf("    eth0=%v\n", eth0)
	}
}

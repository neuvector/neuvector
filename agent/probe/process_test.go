package probe

import (
	"io"
	"testing"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/container"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/utils"
)

// a fake runtime driver
type dummyRTDriver struct {
	cmd string
}

func (d *dummyRTDriver) IsRuntimeProcess(proc string, cmds []string) bool {
	return proc == d.cmd
}

func (d *dummyRTDriver) String() string { return "mockRtDriver" }
func (d *dummyRTDriver) MonitorEvent(cb container.EventCallback, cpath bool) error {
	return container.ErrMethodNotSupported
}
func (d *dummyRTDriver) StopMonitorEvent()                 {}
func (d *dummyRTDriver) GetHost() (*share.CLUSHost, error) { return nil, nil }
func (d *dummyRTDriver) GetSelfID() string { return "a361929b15729277ed89f11da44b0882e82fe9cc9587f1f5f8ebed49802f8834" }
func (d *dummyRTDriver) GetDevice(id string) (*share.CLUSDevice, *container.ContainerMetaExtra, error) {
	return nil, nil, nil
}
func (d *dummyRTDriver) GetContainer(id string) (*container.ContainerMetaExtra, error) {
	return nil, nil
}
func (d *dummyRTDriver) ListContainers(runningOnly bool) ([]*container.ContainerMeta, error) {
	return nil, nil
}
func (d *dummyRTDriver) ListContainerIDs() (utils.Set, utils.Set) { return nil, nil }
func (d *dummyRTDriver) GetImageHistory(name string) ([]*container.ImageHistory, error) {
	return nil, nil
}
func (d *dummyRTDriver) GetImage(name string) (*container.ImageMeta, error) { return nil, nil }
func (d *dummyRTDriver) GetImageFile(id string) (io.ReadCloser, error)      { return nil, nil }
func (d *dummyRTDriver) GetNetworkEndpoint(netName, container, epName string) (*container.NetworkEndpoint, error) {
	return nil, nil
}
func (d *dummyRTDriver) ListNetworks() (map[string]*container.Network, error) { return nil, nil }
func (d *dummyRTDriver) GetParent(meta *container.ContainerMetaExtra, pidMap map[int]string) (bool, string) {
	return false, ""
}
func (d *dummyRTDriver) IsDaemonProcess(proc string, cmds []string) bool { return false }
func (d *dummyRTDriver) GetProxy() (string, string, string)              { return "", "", "" }
func (d *dummyRTDriver) GetDefaultRegistries() []string                  { return nil }
func (d *dummyRTDriver) GetStorageDriver() string                        { return "" }
func (d *dummyRTDriver) GetService(id string) (*container.Service, error) {
	return nil, container.ErrMethodNotSupported
}
func (d *dummyRTDriver) ListServices() ([]*container.Service, error) {
	return make([]*container.Service, 0), nil
}

/***************************  Basic idea:
	Host-only:

	echo $SHELL
	==> /bin/bash (not relaible because the script can assigne its shell command, like: "#!/bin/sh")

	Common (posix, unix) shell commands on modern Linux systems:
		/bin/ash
		/bin/dash
		/bin/bash
		/bin/sh
		/bin/csh

	## Matching 3 Criteria to exclude it from "learned" as an implicit whitelist entry (allowed).
	(1) Shell command-line from "/proc/<pid>/cmdline":
		(shell) (script)
		For example: "/bin/bash psloop.sh"
	(2) Exe Path: from "/proc/<pid>/exe":
		(Shell)
		For example: "/bin/bash"
	(3) Process name: from "/proc/<pid>/status" or "/proc/<pid>/comm"
		(script)
		For example: "psloop.sh"

	## Found two types of false-negative cases, but they are no-harm contributed to the excessive rules, for examples:
	(1) >> bash psloop.sh
		cmd=[bash psloop.sh ] name=bash path=/bin/bash
		It will be recorded as {"bash", "/bin/bash"}
	(2) >> sh psloops.sh
		cmd=[sh psloop.sh ] name=sh path=/bin/dash
		It will be recorded as {"sh", "/bin/dash"}
***************************/

func TestIsShellSCript(t *testing.T) {
	apps := map[uint32]*procInternal{
		// non-shell-script
		1: &procInternal{name: "name", path: "path", cmds: []string{"name", "param"}},
		2: &procInternal{name: "name", path: "/bin/bash", cmds: []string{"/bin/bash", "param"}},
		3: &procInternal{name: "name", path: "/bin/bash", cmds: []string{"name"}},
		4: &procInternal{name: "name", path: "/bin/bash", cmds: []string{"anotherName"}},
		5: &procInternal{name: "bash", path: "/bin/bash", cmds: []string{"bash"}},
		6: &procInternal{name: "cp", path: "/bin/busybox", cmds: []string{"cp"}},
		7: &procInternal{name: "cp", path: "/bin/busybox", cmds: []string{"/bin/busybox cp"}},

		11: &procInternal{name: "scxuPiwXl", path: "/usr/bin/bash", cmds: []string{"/usr/bin/ps", "server=$1", "if [ `systemctl list-unit-files | grep -i \"atomic-openshift-master-api.service\" | wc -l` -gt 0 ]", "then /etc/opt/microsoft/scx/conf/tmpdir/scxuPiwXl", "ocpmaster5102.rbgooe.at"}},
		12: &procInternal{name: "scxuPiwXl", path: "/usr/local/bin/bash", cmds: []string{"/usr/bin/ls", "server=$1", "if [ `systemctl list-unit-files | grep -i \"atomic-openshift-master-api.service\" | wc -l` -gt 0 ]", "then /etc/opt/microsoft/scx/conf/tmpdir/scxuPiwXl", "ocpmaster5102.rbgooe.at"}},

		// no-harm: false-negative
		50: &procInternal{name: "bash", path: "/bin/bash", cmds: []string{"/bin/bash", "psloop.sh"}},
		51: &procInternal{name: "dash", path: "/bin/dash", cmds: []string{"/bin/bash", "psloop.sh"}},

		// above: identified as not-shell-script
		// ------------------------------------------------------------------------------
		// below: shell scripts

		100: &procInternal{name: "psloop.sh", path: "/bin/bash", cmds: []string{"/bin/bash", "psloop.sh"}},
		101: &procInternal{name: "psloop.sh", path: "/bin/bash", cmds: []string{"/bin/sh", "psloop.sh"}},
		102: &procInternal{name: "name", path: "/bin/bash", cmds: []string{"/bin/bash", "name"}},
		103: &procInternal{name: "name", path: "/bin/dash", cmds: []string{"/bin/sh", "name"}},
		104: &procInternal{name: "1.sh", path: "/bin/dash", cmds: []string{"/bin/sh", "1.sh"}},

		// possible sample combinations from "Microsoft System Center - Operations Manager"
		110: &procInternal{name: "scxuPiwXl", path: "/bin/bash", cmds: []string{"/bin/bash", "server=$1 if [ `systemctl list-unit-files | grep -i \"atomic-openshift-master-api.service\" | wc -l` -gt 0 ] then /etc/opt/microsoft/scx/conf/tmpdir/scxuPiwXl ocpmaster5102.rbgooe.at"}},
		111: &procInternal{name: "scxuPiwXl", path: "/bin/bash", cmds: []string{"/bin/bash", "server=$1", "if [ `systemctl list-unit-files | grep -i \"atomic-openshift-master-api.service\" | wc -l` -gt 0 ] then /etc/opt/microsoft/scx/conf/tmpdir/scxuPiwXl ocpmaster5102.rbgooe.at"}},
		112: &procInternal{name: "scxuPiwXl", path: "/bin/bash", cmds: []string{"/bin/bash", "server=$1", "if [ `systemctl list-unit-files | grep -i \"atomic-openshift-master-api.service\" | wc -l` -gt 0 ]", "then /etc/opt/microsoft/scx/conf/tmpdir/scxuPiwXl ocpmaster5102.rbgooe.at"}},
		113: &procInternal{name: "scxuPiwXl", path: "/bin/bash", cmds: []string{"/bin/bash", "server=$1", "if [ `systemctl list-unit-files | grep -i \"atomic-openshift-master-api.service\" | wc -l` -gt 0 ]", "then", "/etc/opt/microsoft/scx/conf/tmpdir/scxuPiwXl ocpmaster5102.rbgooe.at"}},
		114: &procInternal{name: "scxuPiwXl", path: "/bin/bash", cmds: []string{"/bin/bash", "server=$1", "if [ `systemctl list-unit-files | grep -i \"atomic-openshift-master-api.service\" | wc -l` -gt 0 ]", "then /etc/opt/microsoft/scx/conf/tmpdir/scxuPiwXl", "ocpmaster5102.rbgooe.at"}},
		115: &procInternal{name: "scxuPiwXl", path: "/usr/bin/bash", cmds: []string{"/usr/bin/bash", "server=$1", "if [ `systemctl list-unit-files | grep -i \"atomic-openshift-master-api.service\" | wc -l` -gt 0 ]", "then /etc/opt/microsoft/scx/conf/tmpdir/scxuPiwXl", "ocpmaster5102.rbgooe.at"}},
		116: &procInternal{name: "scxuPiwXl", path: "/usr/local/bin/bash", cmds: []string{"/usr/bin/bash", "server=$1", "if [ `systemctl list-unit-files | grep -i \"atomic-openshift-master-api.service\" | wc -l` -gt 0 ]", "then /etc/opt/microsoft/scx/conf/tmpdir/scxuPiwXl", "ocpmaster5102.rbgooe.at"}},
	}

	p := &Probe{}
	cid := "" // host
	for k, v := range apps {
		res := p.isShellScript(cid, v)
		if k < 100 {
			if res == 1 {
				t.Errorf("Error[%v]: not a script: %v\n", k, v)
			}
		} else {
			if res == 0 {
				t.Errorf("Error[%v]: is a script: %v\n", k, v)
			}
		}
	}
}

/*
 "ip":
     Show / manipulate routing, devices, policy routing and tunnels

 ip [ OPTIONS ] OBJECT { COMMAND | help }
 ip link set DEVICE { up | down | arp { on | off } | ......
 ip link show [ DEVICE ]
 ip address { add | del } IFADDR dev STRING
 ip address { show | flush } [ dev STRING ] [ scope SCOPE-ID ] [ to PREFIX ] [ FLAG-LIST ] [ label PATTERN ]
 ip addrlabel { add | del } prefix PREFIX [ dev DEV ] [ label NUMBER ]
 ip addrlabel { list | flush }
 ip route get ADDRESS [ from ADDRESS iif STRING ] [ oif STRING ] [ tos TOS ]
 ip route { add | del | change | append | replace | monitor } ROUTE
 ip rule [ list | add | del | flush ] SELECTOR ACTION
 ip tunnel { add | change | del | show | prl } [ NAME ] [ mode MODE ] [ remote ADDR ]
 ip maddr [ add | del ] MULTIADDR dev STRING
 ip neighbour { add | del | change | replace } { ADDR [ lladdr LLADDR ]
 ip maddr [ add | del ] MULTIADDR dev STRING
 ip xfrm state { add | update } ID [ XFRM_OPT ] [ mode MODE ] [ reqid REQID ] [ seq SEQ ] [ replay-window SIZE ]
 ip monitor [ all | LISTofOBJECTS ]   ???

*/
func TestIpRuntimeReadOnlyCmd(t *testing.T) {
	apps := map[uint32]*procInternal{
		// positive
		1: &procInternal{cmds: []string{"ip", "-a", "-o", "link"}},
		2: &procInternal{cmds: []string{"ip", "address"}},
		3: &procInternal{cmds: []string{"ip", "address", "show"}},
		4: &procInternal{cmds: []string{"ip", "route", "get", "google.com"}},
		5: &procInternal{cmds: []string{"ip", "rule", "list", "selector"}},

		// negative
		10: &procInternal{cmds: []string{"cip", "address"}}, // wrong exec
		11: &procInternal{cmds: []string{"ip", "address", "flush", "eth1"}},
		12: &procInternal{cmds: []string{"ip", "route", "change", "toAbcRoute"}},
		13: &procInternal{cmds: []string{"ip", "route", "replace", "toAbcRoute"}},
		14: &procInternal{cmds: []string{"ip", "rule", "add", "selector"}},
		15: &procInternal{cmds: []string{"ip", "tunnel", "del", "myTunnel", "127.0.0.1"}},
		16: &procInternal{cmds: []string{"ip", "link", "set", "eth4", "down"}},
		17: &procInternal{cmds: []string{"ip", "link", "truncate", "eth4", "down"}}, // unknown operator
		18: &procInternal{cmds: []string{"ip", "link", "eth4", "down"}},             // missing object
	}

	p := &Probe{}
	for k, v := range apps {
		res := p.isAllowIpRuntimeCommand(v.cmds)
		if k < 10 {
			if !res {
				t.Errorf("Error[%v]: positive: %v\n", k, v.cmds)
			}
		} else {
			if res {
				t.Errorf("Error[%v]: negative: %v\n", k, v.cmds)
			}
		}
	}
}

func TestAzureCniCmd(t *testing.T) {
	apps := map[uint32]*procInternal{
		// positive
		1: &procInternal{name: "azure-vnet", pname: "runc", path: "/opt/cni/bin/azure-vnet"},
		2: &procInternal{name: "uptime", pname: "azure-vnet", ppath: "/opt/cni/bin/azure-vnet"},
		3: &procInternal{name: "tuning", pname: "azure-vnet", ppath: "/opt/cni/bin/azure-vnet", path: "/opt/cni/bin/tuning"},

		// negative
		10: &procInternal{name: "azure-vnet", pname: "bash", path: "/opt/cni/bin/azure-vnet"},
		11: &procInternal{name: "NotUptime", pname: "azure-vnet", ppath: "/opt/cni/bin/azure-vnet"},
		12: &procInternal{name: "tuning", pname: "azure-vnet", ppath: "/opt/cni/bin/attack/azure-vnet", path: "/opt/cni/bin/tuningX"},
	}

	global.RT = &dummyRTDriver{cmd: "runc"}
	p := &Probe{bKubePlatform: true}
	for k, v := range apps {
		res := p.isProcessException(v, share.GroupNVProtect, "1234567890", true, false)
		if k < 10 {
			if !res {
				t.Errorf("Error[%v]: positive: %v\n", k, v)
			}
		} else {
			if res {
				t.Errorf("Error[%v]: negative: %v\n", k, v)
			}
		}
	}
}

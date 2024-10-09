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
func (d *dummyRTDriver) GetSelfID() string {
	return "a361929b15729277ed89f11da44b0882e82fe9cc9587f1f5f8ebed49802f8834"
}
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
		1: {name: "name", path: "path", cmds: []string{"name", "param"}},
		2: {name: "name", path: "/bin/bash", cmds: []string{"/bin/bash", "param"}},
		3: {name: "name", path: "/bin/bash", cmds: []string{"name"}},
		4: {name: "name", path: "/bin/bash", cmds: []string{"anotherName"}},
		5: {name: "bash", path: "/bin/bash", cmds: []string{"bash"}},
		6: {name: "cp", path: "/bin/busybox", cmds: []string{"cp"}},
		7: {name: "cp", path: "/bin/busybox", cmds: []string{"/bin/busybox cp"}},

		11: {name: "scxuPiwXl", path: "/usr/bin/bash", cmds: []string{"/usr/bin/ps", "server=$1", "if [ `systemctl list-unit-files | grep -i \"atomic-openshift-master-api.service\" | wc -l` -gt 0 ]", "then /etc/opt/microsoft/scx/conf/tmpdir/scxuPiwXl", "ocpmaster5102.rbgooe.at"}},
		12: {name: "scxuPiwXl", path: "/usr/local/bin/bash", cmds: []string{"/usr/bin/ls", "server=$1", "if [ `systemctl list-unit-files | grep -i \"atomic-openshift-master-api.service\" | wc -l` -gt 0 ]", "then /etc/opt/microsoft/scx/conf/tmpdir/scxuPiwXl", "ocpmaster5102.rbgooe.at"}},

		// no-harm: false-negative
		50: {name: "bash", path: "/bin/bash", cmds: []string{"/bin/bash", "psloop.sh"}},
		51: {name: "dash", path: "/bin/dash", cmds: []string{"/bin/bash", "psloop.sh"}},

		// above: identified as not-shell-script
		// ------------------------------------------------------------------------------
		// below: shell scripts

		100: {name: "psloop.sh", path: "/bin/bash", cmds: []string{"/bin/bash", "psloop.sh"}},
		101: {name: "psloop.sh", path: "/bin/bash", cmds: []string{"/bin/sh", "psloop.sh"}},
		102: {name: "name", path: "/bin/bash", cmds: []string{"/bin/bash", "name"}},
		103: {name: "name", path: "/bin/dash", cmds: []string{"/bin/sh", "name"}},
		104: {name: "1.sh", path: "/bin/dash", cmds: []string{"/bin/sh", "1.sh"}},

		// possible sample combinations from "Microsoft System Center - Operations Manager"
		110: {name: "scxuPiwXl", path: "/bin/bash", cmds: []string{"/bin/bash", "server=$1 if [ `systemctl list-unit-files | grep -i \"atomic-openshift-master-api.service\" | wc -l` -gt 0 ] then /etc/opt/microsoft/scx/conf/tmpdir/scxuPiwXl ocpmaster5102.rbgooe.at"}},
		111: {name: "scxuPiwXl", path: "/bin/bash", cmds: []string{"/bin/bash", "server=$1", "if [ `systemctl list-unit-files | grep -i \"atomic-openshift-master-api.service\" | wc -l` -gt 0 ] then /etc/opt/microsoft/scx/conf/tmpdir/scxuPiwXl ocpmaster5102.rbgooe.at"}},
		112: {name: "scxuPiwXl", path: "/bin/bash", cmds: []string{"/bin/bash", "server=$1", "if [ `systemctl list-unit-files | grep -i \"atomic-openshift-master-api.service\" | wc -l` -gt 0 ]", "then /etc/opt/microsoft/scx/conf/tmpdir/scxuPiwXl ocpmaster5102.rbgooe.at"}},
		113: {name: "scxuPiwXl", path: "/bin/bash", cmds: []string{"/bin/bash", "server=$1", "if [ `systemctl list-unit-files | grep -i \"atomic-openshift-master-api.service\" | wc -l` -gt 0 ]", "then", "/etc/opt/microsoft/scx/conf/tmpdir/scxuPiwXl ocpmaster5102.rbgooe.at"}},
		114: {name: "scxuPiwXl", path: "/bin/bash", cmds: []string{"/bin/bash", "server=$1", "if [ `systemctl list-unit-files | grep -i \"atomic-openshift-master-api.service\" | wc -l` -gt 0 ]", "then /etc/opt/microsoft/scx/conf/tmpdir/scxuPiwXl", "ocpmaster5102.rbgooe.at"}},
		115: {name: "scxuPiwXl", path: "/usr/bin/bash", cmds: []string{"/usr/bin/bash", "server=$1", "if [ `systemctl list-unit-files | grep -i \"atomic-openshift-master-api.service\" | wc -l` -gt 0 ]", "then /etc/opt/microsoft/scx/conf/tmpdir/scxuPiwXl", "ocpmaster5102.rbgooe.at"}},
		116: {name: "scxuPiwXl", path: "/usr/local/bin/bash", cmds: []string{"/usr/bin/bash", "server=$1", "if [ `systemctl list-unit-files | grep -i \"atomic-openshift-master-api.service\" | wc -l` -gt 0 ]", "then /etc/opt/microsoft/scx/conf/tmpdir/scxuPiwXl", "ocpmaster5102.rbgooe.at"}},
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
		1: {cmds: []string{"ip", "-a", "-o", "link"}},
		2: {cmds: []string{"ip", "address"}},
		3: {cmds: []string{"ip", "address", "show"}},
		4: {cmds: []string{"ip", "route", "get", "google.com"}},
		5: {cmds: []string{"ip", "rule", "list", "selector"}},

		// negative
		10: {cmds: []string{"cip", "address"}}, // wrong exec
		11: {cmds: []string{"ip", "address", "flush", "eth1"}},
		12: {cmds: []string{"ip", "route", "change", "toAbcRoute"}},
		13: {cmds: []string{"ip", "route", "replace", "toAbcRoute"}},
		14: {cmds: []string{"ip", "rule", "add", "selector"}},
		15: {cmds: []string{"ip", "tunnel", "del", "myTunnel", "127.0.0.1"}},
		16: {cmds: []string{"ip", "link", "set", "eth4", "down"}},
		17: {cmds: []string{"ip", "link", "truncate", "eth4", "down"}}, // unknown operator
		18: {cmds: []string{"ip", "link", "eth4", "down"}},             // missing object
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
		1: {name: "azure-vnet", pname: "runc", path: "/opt/cni/bin/azure-vnet"},
		2: {name: "uptime", pname: "azure-vnet", ppath: "/opt/cni/bin/azure-vnet"},
		3: {name: "tuning", pname: "azure-vnet", ppath: "/opt/cni/bin/azure-vnet", path: "/opt/cni/bin/tuning"},

		// negative
		10: {name: "azure-vnet", pname: "bash", path: "/opt/cni/bin/azure-vnet"},
		11: {name: "NotUptime", pname: "azure-vnet", ppath: "/opt/cni/bin/azure-vnet"},
		12: {name: "tuning", pname: "azure-vnet", ppath: "/opt/cni/bin/attack/azure-vnet", path: "/opt/cni/bin/tuningX"},
	}

	global.RT = &dummyRTDriver{cmd: "runc"}
	p := &Probe{bKubePlatform: true, agentPid: 100}
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

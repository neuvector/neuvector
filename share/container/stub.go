package container

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/system/sysinfo"
	"github.com/neuvector/neuvector/share/utils"
)

// This is a virtual runtime device driver.
// It supports the limited device information when the runtime driver is not available.
const StubRtName = "stubRtDriver"

// a dummy static runtime driver
type stubRTDriver struct {
	sys     *system.SystemTools
	sysInfo *sysinfo.SysInfo

	rootPid  int
	initTime time.Time

	selfID       string
	podName      string
	nodeHostname string
	ipAddress    string
}

func (d *stubRTDriver) IsRuntimeProcess(proc string, cmds []string) bool          { return false }
func (d *stubRTDriver) String() string                                            { return StubRtName }
func (d *stubRTDriver) MonitorEvent(cb EventCallback, cpath bool) error           { return ErrMethodNotSupported }
func (d *stubRTDriver) StopMonitorEvent()                                         {}
func (d *stubRTDriver) GetContainer(id string) (*ContainerMetaExtra, error)       { return nil, nil }
func (d *stubRTDriver) ListContainers(runningOnly bool) ([]*ContainerMeta, error) { return nil, nil }
func (d *stubRTDriver) ListContainerIDs() (utils.Set, utils.Set)                  { return nil, nil }
func (d *stubRTDriver) GetImageHistory(name string) ([]*ImageHistory, error)      { return nil, nil }
func (d *stubRTDriver) GetImage(name string) (*ImageMeta, error)                  { return nil, nil }
func (d *stubRTDriver) GetImageFile(id string) (io.ReadCloser, error)             { return nil, nil }
func (d *stubRTDriver) GetNetworkEndpoint(netName, container, epName string) (*NetworkEndpoint, error) {
	return nil, nil
}
func (d *stubRTDriver) GetParent(meta *ContainerMetaExtra, pidMap map[int]string) (bool, string) {
	return false, ""
}
func (d *stubRTDriver) IsDaemonProcess(proc string, cmds []string) bool { return false }
func (d *stubRTDriver) GetDefaultRegistries() []string                  { return nil }
func (d *stubRTDriver) GetStorageDriver() string                        { return "" }
func (d *stubRTDriver) GetService(id string) (*Service, error)          { return nil, ErrMethodNotSupported }
func (d *stubRTDriver) ListServices() ([]*Service, error)               { return make([]*Service, 0), nil }

// ///////
func InitStubRtDriver(sys *system.SystemTools) (Runtime, error) {
	var id, podname, ipaddress string
	log.Info()
	ppid := os.Getppid()

	id, _, _, _ = sys.GetContainerIDByPID(ppid)
	if dat, err := os.ReadFile("/etc/hostname"); err == nil {
		podname = strings.TrimSpace(string(dat))
		if dat, err = os.ReadFile("/etc/hosts"); err == nil {
			for _, line := range strings.Split(strings.Trim(string(dat), " \t\r\n"), "\n") {
				line = strings.Replace(strings.Trim(line, " \t"), "\t", " ", -1)
				if len(line) == 0 || line[0] == ';' || line[0] == '#' {
					continue
				}
				slices := strings.SplitN(line, " ", 2)
				// log.WithFields(log.Fields{"slices": slices}).Debug()
				if len(slices) > 1 && strings.Contains(slices[1], podname) {
					ipaddress = slices[0]
					break
				}
			}
		}
	}

	if podname == "" && id == "" {
		return nil, fmt.Errorf("failed: id=%v, pod=%v", id, podname)
	}

	log.WithFields(log.Fields{"selfID": id, "podName": podname, "ipaddress": ipaddress}).Debug()
	return &stubRTDriver{sys: sys, sysInfo: sys.GetSystemInfo(), initTime: time.Now().UTC(),
		rootPid: ppid, selfID: id, podName: podname, nodeHostname: podname, ipAddress: ipaddress}, nil
}

// ///////
func (d *stubRTDriver) GetSelfID() string {
	return d.selfID
}

func (d *stubRTDriver) GetHost() (*share.CLUSHost, error) {
	var host share.CLUSHost

	host.Runtime = d.String()
	host.RuntimeVer = "1.0"
	host.RuntimeAPIVer = "1.0"

	if d.sysInfo != nil {
		host.Name = d.nodeHostname
		host.ID = fmt.Sprintf("%s:%s", d.nodeHostname, d.sysInfo.Product.UUID)
		host.OS = d.sysInfo.OS.Name
		host.Kernel = d.sysInfo.Kernel.Release
		host.CPUs = int64(d.sysInfo.CPU.Threads)
		host.Memory = int64(d.sysInfo.Memory.Size) * 1024 * 1024
	}

	return &host, nil
}

func (d *stubRTDriver) GetDevice(id string) (*share.CLUSDevice, *ContainerMetaExtra, error) {
	if id != d.selfID {
		return &share.CLUSDevice{}, nil, nil
	}

	dev := &share.CLUSDevice{
		ID:        d.selfID,
		Name:      d.podName,
		Labels:    make(map[string]string),
		Pid:       d.rootPid,
		CreatedAt: d.initTime,
		StartedAt: d.initTime,
	}

	// Read address
	ifaces := d.sys.GetGlobalAddrs(false)

	dev.Ifaces = make(map[string][]share.CLUSIPAddr)
	for name, addrs := range ifaces {
		log.WithFields(log.Fields{"name": name, "addrs": addrs}).Debug()
		dev.Ifaces[name] = make([]share.CLUSIPAddr, len(addrs))
		for i, addr := range addrs {
			dev.Ifaces[name][i] = share.CLUSIPAddr{
				IPNet: addr,
				Scope: share.CLUSIPAddrScopeLocalhost,
			}
		}
	}

	return dev, nil, nil
}

func (d *stubRTDriver) GetProxy() (string, string, string) {
	return "", "", ""
}

func (d *stubRTDriver) ListNetworks() (map[string]*Network, error) {
	return make(map[string]*Network), nil
}

package container

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/utils"
)

type Event string
type EventCallback func(event Event, id string, pid int)

type Runtime interface {
	String() string
	MonitorEvent(cb EventCallback, cpath bool) error
	StopMonitorEvent()
	GetHost() (*share.CLUSHost, error)
	GetSelfID() string
	GetDevice(id string) (*share.CLUSDevice, *ContainerMetaExtra, error)
	GetContainer(id string) (*ContainerMetaExtra, error)
	ListContainers(runningOnly bool) ([]*ContainerMeta, error)
	ListContainerIDs() (utils.Set, utils.Set)
	GetImageHistory(name string) ([]*ImageHistory, error)
	GetImage(name string) (*ImageMeta, error)
	GetImageFile(id string) (io.ReadCloser, error)
	GetNetworkEndpoint(netName, container, epName string) (*NetworkEndpoint, error)
	ListNetworks() (map[string]*Network, error)
	GetService(id string) (*Service, error)
	ListServices() ([]*Service, error)
	// Return if container is child and parent container id. If pidMap is nil, only return if it's child.
	GetParent(meta *ContainerMetaExtra, pidMap map[int]string) (bool, string)
	IsDaemonProcess(proc string, cmds []string) bool
	IsRuntimeProcess(proc string, cmds []string) bool
	GetProxy() (string, string, string)
	GetDefaultRegistries() []string
	GetStorageDriver() string
}

var (
	ErrUnknownRuntime     = errors.New("Unknown container runtime")
	ErrMethodNotSupported = errors.New("Method not supported")
	ErrNotFound           = errors.New("Not found")
)

const defaultUserSock = "/run/runtime.sock"

const (
	RuntimeDocker     = "docker"
	RuntimeContainerd = "containerd"
	RuntimeCriO       = "cri-o"
	RuntimeUnknown    = "unknown"
)

const (
	DockerNetworkGlobal = "global"
	DockerNetworkSwarm  = "swarm"
	DockerNetworkLocal  = "local"
)

const (
	EventContainerStart   = "start"
	EventContainerStop    = "stop"
	EventContainerDelete  = "delete"
	EventContainerCopyIn  = "copy-in"
	EventContainerCopyOut = "copy-out"
	EventSocketError      = "socket-err"
	EventServiceCreate    = "create-service"
	EventServiceUpdate    = "update-service"
	EventServiceDelete    = "delete-service"
	EventNetworkCreate    = "create-network"
	EventNetworkDelete    = "delete-network"
)

type Network struct {
	Name     string
	ID       string
	Scope    string
	Driver   string
	Subnets  []*net.IPNet
	Gateways []net.IP
}

type NetworkEndpoint struct {
	ID    string
	Name  string
	MAC   net.HardwareAddr
	IPNet *net.IPNet
}

type Service struct {
	ID     string
	Name   string
	Labels map[string]string
	VIPs   []net.IP
}

type ImageMeta struct {
	ID        string
	Digest    string
	CreatedAt time.Time
	Size      int64
	Env       []string
	Author    string
	Labels    map[string]string
	RepoTags  []string
	Layers    []string
}

type ImageHistory struct {
	ID   string
	Cmd  string
	Size int64
}

type ContainerMeta struct {
	ID       string
	Name     string
	Image    string
	Labels   map[string]string
	Hostname string
	Pid      int
	Envs     []string
	PidMode  string
	NetMode  string
	Sandbox  string
	isChild  bool
}

type ContainerMetaExtra struct {
	ContainerMeta
	ImageID     string
	ImageDigest string
	ImgCreateAt time.Time
	Author      string
	Privileged  bool
	ExitCode    int
	Running     bool
	CreatedAt   time.Time
	StartedAt   time.Time
	FinishedAt  time.Time
	MemoryLimit int64
	CPUs        string
	ProxyMesh   bool
	Sidecar     bool
	RunAsRoot   bool
	// network
	IPAddress   string
	IPPrefixLen int
	MappedPorts map[share.CLUSProtoPort]*share.CLUSMappedPort
	Networks    utils.Set
	LogPath     string
	Healthcheck []string
}

func ConnectDocker(endpoint string, sys *system.SystemTools) (Runtime, error) {
	log.WithFields(log.Fields{"endpoint": endpoint}).Info()
	if endpoint != "" {
		rt, err := dockerConnect(endpoint, sys)
		if err == nil {
			return rt, nil
		}
	} else {
		if isUnixSockFile(defaultDockerSocket) {
			rt, err := dockerConnect(defaultDockerSocket, sys)
			if err == nil {
				return rt, nil
			}
		}
	}

	return nil, ErrUnknownRuntime
}

func Connect(endpoint string, sys *system.SystemTools) (Runtime, error) {
	log.WithFields(log.Fields{"endpoint": endpoint}).Info()
	if endpoint != "" {
		if _, err := os.Stat(endpoint); err != nil {
			return nil, err
		}

		rt, err := dockerConnect(endpoint, sys)
		if err == nil {
			return rt, nil
		}

		rt, err = containerdConnect(endpoint, sys)
		if err == nil {
			return rt, nil
		}

		rt, err = crioConnect(endpoint, sys)
		if err == nil {
			return rt, nil
		}
	} else {
		// assigned "/run/runtime.sock"
		if rt, err := connectRt(defaultUserSock, RuntimeUnknown, sys); err == nil {
			return rt, nil
		}

		if IsPidHost() {
			if rtEndpoint, pause_img, ok := obtainRtEndpointFromKubelet(sys); ok {
				log.WithFields(log.Fields{"rtEndpoint": rtEndpoint, "pause_img": pause_img}).Info()
				edpt := filepath.Join("/proc/1/root", rtEndpoint)
				if rt, err := tryConnectRt(edpt, sys); err == nil {
					return rt, nil
				}

				if rt, err := connectRt(edpt, RuntimeUnknown, sys); err == nil {
					return rt, nil
				}
			}

			if rt, err := tryConnectDefaultRt("/proc/1/root", sys); err == nil {
				return rt, nil
			}
		}

		// backup: current approach
		if rt, err := tryConnectDefaultRt("", sys); err == nil {
			return rt, nil
		}
	}

	return nil, ErrUnknownRuntime
}

// Unlike named pipes which allow only unidirectional data flow, sockets are fully duplex-capable.
// A UNIX socket is marked with an s as the first letter of the mode string, e.g.
// srwxrwxrwx /tmp/.X11-unix/X0
func isUnixSockFile(filename string) bool {
	filename = strings.TrimPrefix(filename, "unix://")

	info, err := os.Stat(filename)
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeSocket) != 0
}

// // construct a json string from map[]
func buildJsonFromMap(info map[string]string) string {
	// sort all keys
	keys := []string{}
	for k := range info {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	jsonInfo := "{"
	for _, k := range keys {
		var res interface{}
		// We attempt to convert key into JSON if possible else use it directly
		if err := json.Unmarshal([]byte(info[k]), &res); err != nil {
			jsonInfo += "\"" + k + "\"" + ":" + "\"" + info[k] + "\","
		} else {
			jsonInfo += "\"" + k + "\"" + ":" + info[k] + ","
		}
	}
	jsonInfo = jsonInfo[:len(jsonInfo)-1]
	jsonInfo += "}"
	// log.WithFields(log.Fields{"info": jsonInfo}).Debug()
	return jsonInfo
}

func connectRt(rtPath, rtType string, sys *system.SystemTools) (Runtime, error) {
	if fpath, ok := justifyRuntimeSocketFile(rtPath); !ok {
		return nil, ErrUnknownRuntime
	} else {
		rtPath = fpath // updated
	}

	log.WithFields(log.Fields{"path": rtPath, "type": rtType}).Debug()

	switch rtType {
	case RuntimeDocker:
		if rt, err := dockerConnect(rtPath, sys); err == nil {
			return rt, nil
		}
	case RuntimeContainerd:
		if rt, err := containerdConnect(rtPath, sys); err == nil {
			return rt, nil
		}
	case RuntimeCriO:
		if rt, err := crioConnect(rtPath, sys); err == nil {
			return rt, nil
		}
	default:
		if rt, err := dockerConnect(rtPath, sys); err == nil { // prefer docker
			return rt, nil
		}
		if rt, err := containerdConnect(rtPath, sys); err == nil {
			return rt, nil
		}
		if rt, err := crioConnect(rtPath, sys); err == nil {
			return rt, nil
		}
	}
	log.WithFields(log.Fields{"path": rtPath, "type": rtType}).Debug("Failed")
	return nil, ErrUnknownRuntime
}

func tryConnectRt(rtPath string, sys *system.SystemTools) (Runtime, error) {
	log.WithFields(log.Fields{"rtPath": rtPath}).Info()

	// guessing RT from the socket name
	sock := filepath.Base(rtPath)
	if strings.Contains(sock, "crio") || strings.Contains(sock, "cri-") {
		if rt, err := connectRt(rtPath, RuntimeCriO, sys); err == nil {
			return rt, nil
		}
	}

	if strings.Contains(sock, "docker") {
		// prefer docker
		if rt, err := connectRt(rtPath, RuntimeDocker, sys); err == nil {
			return rt, nil
		}
	}

	if strings.Contains(sock, "containerd") {
		if rt, err := connectRt(rtPath, RuntimeContainerd, sys); err == nil {
			return rt, nil
		}
	}
	return nil, ErrUnknownRuntime
}

func tryConnectDefaultRt(rootPath string, sys *system.SystemTools) (Runtime, error) {
	// prefer docker
	if rt, err := connectRt(filepath.Join(rootPath, defaultDockerSocket), RuntimeDocker, sys); err == nil {
		return rt, nil
	}

	if rt, err := connectRt(filepath.Join(rootPath, defaultDockerShimSocket), RuntimeDocker, sys); err == nil {
		return rt, nil
	}

	// prefer k3s
	if rt, err := connectRt(filepath.Join(rootPath, defaultK3sContainerdSock), RuntimeContainerd, sys); err == nil {
		return rt, nil
	}

	if rt, err := connectRt(filepath.Join(rootPath, defaultContainerdSock), RuntimeContainerd, sys); err == nil {
		return rt, nil
	}

	if rt, err := connectRt(filepath.Join(rootPath, defaultCriOSock), RuntimeCriO, sys); err == nil {
		return rt, nil
	}

	if rt, err := connectRt(filepath.Join(rootPath, defaultCriDockerSock), RuntimeCriO, sys); err == nil {
		return rt, nil
	}
	return nil, ErrUnknownRuntime
}

func isKubeletLikely(cmds []string) bool {
	if strings.Contains(filepath.Base(cmds[0]), "kubelet") {
		return true
	}

	matchedCnt := 0
	for _, cmd := range cmds {
		// log.WithFields(log.Fields{"cmd": cmd}).Debug()
		if strings.HasPrefix(cmd, "--container-runtime-endpoint=") {
			matchedCnt++
		}

		if strings.HasPrefix(cmd, "--pod-infra-container-image=") {
			matchedCnt++
		}

		if strings.HasPrefix(cmd, "--kubeconfig=") {
			matchedCnt++
		}

		if strings.HasPrefix(cmd, "--kubelet-registration-path=") {
			matchedCnt++
		}

		if matchedCnt >= 2 {
			log.WithFields(log.Fields{"cmds": cmds}).Debug()
			return true
		}
	}
	return false
}

func isK3sLikely(cmds []string) (string, bool) {
	if strings.HasSuffix(filepath.Base(cmds[0]), "k3s") {
		// https://docs.k3s.io/cli/server
		pause_img := "docker.io/rancher/mirrored-pause:3.6" // default sandbox
		matched := false
		for i, cmd := range cmds {
			// log.WithFields(log.Fields{"cmd": cmd}).Debug()
			// node server
			if strings.HasPrefix(cmd, "server") {
				matched = true
			}

			// node agent
			if strings.HasPrefix(cmd, "agent") {
				matched = true
			}

			// only at agent
			if strings.HasPrefix(cmd, "--pause-image") {
				if (i + 1) < len(cmds) {
					pause_img = cmds[i+1]
				}
			}
		}
		return pause_img, matched
	}
	return "", false
}

func obtainRtEndpointFromKubelet(sys *system.SystemTools) (string, string, bool) {
	// (1) iterating proc paths to find the "kubelet"
	if d, err := os.Open("/proc"); err != nil {
		log.WithFields(log.Fields{"err": err}).Error("open")
	} else {
		defer d.Close()
		if files, err := d.Readdir(-1); err != nil {
			log.WithFields(log.Fields{"err": err}).Error("read")
		} else {
			var pid int
			for _, file := range files {
				if file.IsDir() {
					// get all the process
					pid, _ = strconv.Atoi(file.Name())
					if cmds, err := sys.ReadCmdLine(pid); err == nil && len(cmds) > 0 {
						if endpt, ok := isK3sLikely(cmds); ok {
							return defaultK3sContainerdSock, endpt, true
						}
						if !isKubeletLikely(cmds) {
							continue
						}
						// (2) cmdline: obtain token: "--container-runtime-endpoint="
						//     --container-runtime-endpoint=unix:///run/k3s/containerd/containerd.sock
						//     --container-runtime-endpoint=unix:///var/run/crio/crio.sock
						//     if not found, return "defaultDockerSocket"
						//     --pod-infra-container-image=registry.k8s.io/pause:3.8
						endpoint := ""
						pause_img := ""
						for _, cmd := range cmds {
							// log.WithFields(log.Fields{"cmd": cmd}).Debug()
							if strings.HasPrefix(cmd, "--container-runtime-endpoint=") {
								// log.WithFields(log.Fields{"cmd": cmd}).Debug("found")
								cmd = strings.TrimPrefix(cmd, "--container-runtime-endpoint=")
								cmd = strings.TrimPrefix(cmd, "unix://") // remove "unix://" if exist
								endpoint = cmd
							}

							if strings.HasPrefix(cmd, "--pod-infra-container-image=") {
								pause_img = strings.TrimPrefix(cmd, "--pod-infra-container-image=")
							}
						}

						if endpoint == "" {
							continue // find next process
						}
						// pre-k8s-1.24, docker is the default runtime
						return endpoint, pause_img, true
					}
				}
			}
		}
	}
	return "", "", false
}

func IsPidHost() bool { // pid host, pid-1 is the Linux bootup process
	name, _ := os.Readlink("/proc/1/exe")
	// nv containers: "monitor" is for the controller
	return name != "/usr/local/bin/monitor"
}

func justifyRuntimeSocketFile(rtPath string) (string, bool) {
	if !isUnixSockFile(rtPath) {
		if !strings.HasPrefix(rtPath, "/proc/") {
			// log.WithFields(log.Fields{"path": rtPath, "type": rtType}).Debug("not exist")
			return "", false
		}

		// The /run directory is the companion directory to /var/run.
		rtPath = strings.Replace(rtPath, "/var/", "/", 1) // remove "/var"
		if !isUnixSockFile(rtPath) {
			// log.WithFields(log.Fields{"path": rtPath, "type": rtType}).Debug("not exist")
			return "", false
		}
	}
	return rtPath, true
}

package container

import (
	"errors"
	"io"
	"net"
	"os"
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

const (
	RuntimeDocker     = "docker"
	RuntimeContainerd = "containerd"
	RuntimeCriO       = "cri-o"
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
		if isUnixSockFile(defaultDockerSocket) {
			rt, err := dockerConnect(defaultDockerSocket, sys)
			if err == nil {
				return rt, nil
			}
		}

		if isUnixSockFile(defaultContainerdSock) {
			rt, err := containerdConnect(defaultContainerdSock, sys)
			if err == nil {
				return rt, nil
			}
		}

		if isUnixSockFile(defaultCriOSock) {
			rt, err := crioConnect(defaultCriOSock, sys)
			if err == nil {
				return rt, nil
			}
		}
	}

	return nil, ErrUnknownRuntime
}

// Unlike named pipes which allow only unidirectional data flow, sockets are fully duplex-capable.
// A UNIX socket is marked with an s as the first letter of the mode string, e.g.
// srwxrwxrwx /tmp/.X11-unix/X0
func isUnixSockFile(filename string) bool {
	if strings.HasPrefix(filename, "unix://") {
		filename = filename[len("unix://"):]
	}

	info, err := os.Stat(filename)
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeSocket) != 0
}

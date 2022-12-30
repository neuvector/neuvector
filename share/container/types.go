package container

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	criRT "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"

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

//// construct a json string from map[]
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

func getCriImageMeta(client *grpc.ClientConn, name string) (*ImageMeta, error) {
	type criImageInfo struct {
		Info struct {
			ImageSpec struct {
				Author string `json:"author"`
				Config struct {
					Enrtrypoint []string          `json:"Entrypoint"`
					Labels      map[string]string `json:"Labels"`
				} `json:"config"`
			} `json:"imageSpec"`
		} `json:"info"`
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cimg := criRT.NewImageServiceClient(client)
	req := &criRT.ImageStatusRequest{Image: &criRT.ImageSpec{Image: name}, Verbose: true}
	resp, err := cimg.ImageStatus(ctx, req)
	if err == nil && resp != nil && resp.Image != nil {
		meta := &ImageMeta{
			ID:     resp.Image.Id,
			Size:   int64(resp.Image.Size_),
			Labels: make(map[string]string),
		}

		for _, tag := range resp.Image.RepoTags {
			meta.RepoTags = append(meta.RepoTags, tag)
		}

		if len(resp.Image.RepoDigests) > 0 {
			meta.Digest = resp.Image.RepoDigests[0]
		}

		jsonInfo := buildJsonFromMap(resp.GetInfo())
		var res criImageInfo
		if err := json.Unmarshal([]byte(jsonInfo), &res); err != nil {
			// log.WithFields(log.Fields{"error": err, "json": jsonInfo}).Error()
			return nil, err
		}

		meta.Author = res.Info.ImageSpec.Author
		if res.Info.ImageSpec.Config.Labels != nil {
			meta.Labels = res.Info.ImageSpec.Config.Labels
		}
		return meta, nil
	}

	log.WithFields(log.Fields{"error": err, "name": name}).Error("Failed to get image meta")
	return nil, errors.New("Failed to get image meta")
}

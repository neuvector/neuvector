package dockerclient

import (
	"fmt"
	"io"
	"time"

	"github.com/docker/go-units"
)

// docker: HealthConfig holds configuration settings for the HEALTHCHECK feature.
type HealthConfig struct {
	// Test is the test to perform to check that the container is healthy.
	// An empty slice means to inherit the default.
	// The options are:
	// {} : inherit healthcheck
	// {"NONE"} : disable healthcheck
	// {"CMD", args...} : exec arguments directly
	// {"CMD-SHELL", command} : run command with system's default shell
	Test []string `json:",omitempty"`

	// Zero means to inherit. Durations are expressed as integer nanoseconds.
	Interval    time.Duration `json:",omitempty"` // Interval is the time to wait between checks.
	Timeout     time.Duration `json:",omitempty"` // Timeout is the time to wait before considering the check to have hung.
	StartPeriod time.Duration `json:",omitempty"` // The start period for the container to initialize before the retries starts to count down.
	Retries     int           `json:",omitempty"`
}

type ContainerConfig struct {
	Hostname        string
	Domainname      string
	User            string
	AttachStdin     bool
	AttachStdout    bool
	AttachStderr    bool
	ExposedPorts    map[string]struct{}
	Tty             bool
	OpenStdin       bool
	StdinOnce       bool
	Env             []string
	Cmd             []string
	Image           string
	Volumes         map[string]struct{}
	WorkingDir      string
	Entrypoint      []string
	NetworkDisabled bool
	MacAddress      string
	OnBuild         []string
	Labels          map[string]string
	StopSignal      string

	// FIXME: VolumeDriver have been removed since docker 1.9
	VolumeDriver string

	// FIXME: The following fields have been removed since API v1.18
	Memory     int64
	MemorySwap int64
	CpuShares  int64
	Cpuset     string
	PortSpecs  []string

	// This is used only by the create command
	HostConfig HostConfig

	// Network configuration support
	NetworkingConfig NetworkingConfig
	Healthcheck      *HealthConfig
}

type HostConfig struct {
	Binds                []string
	ContainerIDFile      string
	LxcConf              []map[string]string
	Memory               int64
	MemoryReservation    int64
	MemorySwap           int64
	KernelMemory         int64
	CpuShares            int64
	CpuPeriod            int64
	CpusetCpus           string
	CpusetMems           string
	CpuQuota             int64
	BlkioWeight          int64
	OomKillDisable       bool
	MemorySwappiness     int64
	Privileged           bool
	PortBindings         map[string][]PortBinding
	Links                []string
	PublishAllPorts      bool
	Dns                  []string
	DNSOptions           []string
	DnsSearch            []string
	ExtraHosts           []string
	VolumesFrom          []string
	Devices              []DeviceMapping
	NetworkMode          string
	IpcMode              string
	PidMode              string
	UTSMode              string
	CapAdd               []string
	CapDrop              []string
	GroupAdd             []string
	RestartPolicy        RestartPolicy
	SecurityOpt          []string
	ReadonlyRootfs       bool
	Ulimits              []Ulimit
	LogConfig            LogConfig
	CgroupParent         string
	ConsoleSize          [2]int
	VolumeDriver         string
	OomScoreAdj          int
	Tmpfs                map[string]string
	ShmSize              int64 `json:"omitempty"`
	BlkioWeightDevice    []WeightDevice
	BlkioDeviceReadBps   []ThrottleDevice
	BlkioDeviceWriteBps  []ThrottleDevice
	BlkioDeviceReadIOps  []ThrottleDevice
	BlkioDeviceWriteIOps []ThrottleDevice
}

type WeightDevice struct {
	Path   string
	Weight uint16
}

type ThrottleDevice struct {
	Path string
	Rate uint64
}

type DeviceMapping struct {
	PathOnHost        string `json:"PathOnHost"`
	PathInContainer   string `json:"PathInContainer"`
	CgroupPermissions string `json:"CgroupPermissions"`
}

type ExecConfig struct {
	AttachStdin  bool
	AttachStdout bool
	AttachStderr bool
	Tty          bool
	Cmd          []string
	Container    string
	Detach       bool
}

type LogOptions struct {
	Follow     bool
	Stdout     bool
	Stderr     bool
	Timestamps bool
	Tail       int64
}

type AttachOptions struct {
	Logs   bool
	Stream bool
	Stdin  bool
	Stdout bool
	Stderr bool
}

type MonitorEventsFilters struct {
	Event      string   `json:",omitempty"`
	Events     []string `json:",omitempty"`
	Image      string   `json:",omitempty"`
	Images     []string `json:",omitempty"`
	Container  string   `json:",omitempty"`
	Containers []string `json:",omitempty"`
}

type MonitorEventsOptions struct {
	Since   int
	Until   int
	Filters *MonitorEventsFilters `json:",omitempty"`
}

type RestartPolicy struct {
	Name              string
	MaximumRetryCount int64
}

type PortBinding struct {
	HostIp   string
	HostPort string
}

type State struct {
	Running    bool
	Paused     bool
	Restarting bool
	OOMKilled  bool
	Dead       bool
	Pid        int
	ExitCode   int
	Error      string // contains last known error when starting the container
	StartedAt  time.Time
	FinishedAt time.Time
	Ghost      bool
}

// String returns a human-readable description of the state
// Stoken from docker/docker/daemon/state.go
func (s *State) String() string {
	if s.Running {
		if s.Paused {
			return fmt.Sprintf("Up %s (Paused)", units.HumanDuration(time.Now().UTC().Sub(s.StartedAt)))
		}
		if s.Restarting {
			return fmt.Sprintf("Restarting (%d) %s ago", s.ExitCode, units.HumanDuration(time.Now().UTC().Sub(s.FinishedAt)))
		}

		return fmt.Sprintf("Up %s", units.HumanDuration(time.Now().UTC().Sub(s.StartedAt)))
	}

	if s.Dead {
		return "Dead"
	}

	if s.StartedAt.IsZero() {
		return "Created"
	}

	if s.FinishedAt.IsZero() {
		return ""
	}

	return fmt.Sprintf("Exited (%d) %s ago", s.ExitCode, units.HumanDuration(time.Now().UTC().Sub(s.FinishedAt)))
}

// StateString returns a single string to describe state
// Stoken from docker/docker/daemon/state.go
func (s *State) StateString() string {
	if s.Running {
		if s.Paused {
			return "paused"
		}
		if s.Restarting {
			return "restarting"
		}
		return "running"
	}

	if s.Dead {
		return "dead"
	}

	if s.StartedAt.IsZero() {
		return "created"
	}

	return "exited"
}

type ImageRootFS struct {
	Type   string
	Layers []string
}

type ImageInfo struct {
	Architecture    string
	Author          string
	Comment         string
	Config          *ContainerConfig
	Container       string
	ContainerConfig *ContainerConfig
	Created         time.Time
	DockerVersion   string
	RepoDigests     []string
	RepoTags        []string
	Id              string
	Os              string
	Parent          string
	Size            int64
	VirtualSize     int64
	RootFS          *ImageRootFS
}

type ImageHistory struct {
	Id        string   `json:"Id"`
	Created   int64    `json:"Created"`
	CreatedBy string   `json:"CreatedBy"`
	Tags      []string `json:"Tags"`
	Size      int64    `json:"Size"`
	Comment   string   `json:"Comment"`
}

type ImageSearch struct {
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	IsOfficial  bool   `json:"is_official,omitempty" yaml:"is_official,omitempty"`
	IsAutomated bool   `json:"is_automated,omitempty" yaml:"is_automated,omitempty"`
	Name        string `json:"name,omitempty" yaml:"name,omitempty"`
	StarCount   int    `json:"star_count,omitempty" yaml:"star_count,omitempty"`
}

// Type represents the type of a mount.
type Type string

const (
	// TypeBind BIND
	TypeBind Type = "bind"
	// TypeVolume VOLUME
	TypeVolume Type = "volume"
)

// Mount represents a mount (volume).
type Mount struct {
	Type     Type   `json:",omitempty"`
	Source   string `json:",omitempty"`
	Target   string `json:",omitempty"`
	ReadOnly bool   `json:",omitempty"`

	BindOptions   *BindOptions   `json:",omitempty"`
	VolumeOptions *VolumeOptions `json:",omitempty"`
}

// Propagation represents the propagation of a mount.
type Propagation string

const (
	// PropagationRPrivate RPRIVATE
	PropagationRPrivate Propagation = "rprivate"
	// PropagationPrivate PRIVATE
	PropagationPrivate Propagation = "private"
	// PropagationRShared RSHARED
	PropagationRShared Propagation = "rshared"
	// PropagationShared SHARED
	PropagationShared Propagation = "shared"
	// PropagationRSlave RSLAVE
	PropagationRSlave Propagation = "rslave"
	// PropagationSlave SLAVE
	PropagationSlave Propagation = "slave"
)

// BindOptions defines options specific to mounts of type "bind".
type BindOptions struct {
	Propagation Propagation `json:",omitempty"`
}

// VolumeOptions represents the options for a mount of type volume.
type VolumeOptions struct {
	NoCopy       bool              `json:",omitempty"`
	Labels       map[string]string `json:",omitempty"`
	DriverConfig *Driver           `json:",omitempty"`
}

// Driver represents a volume driver.
type Driver struct {
	Name    string            `json:",omitempty"`
	Options map[string]string `json:",omitempty"`
}

// MountPoint represents a mount point configuration inside the container.
// This is used for reporting the mountpoints in use by a container.
type MountPoint struct {
	Type        Type   `json:",omitempty"`
	Name        string `json:",omitempty"`
	Source      string
	Destination string
	Driver      string `json:",omitempty"`
	Mode        string
	RW          bool
	Propagation Propagation
}

type ContainerInfo struct {
	Id              string
	Created         string
	Path            string
	Name            string
	Args            []string
	ExecIDs         []string
	Config          *ContainerConfig
	State           *State
	Image           string
	LogPath         string
	NetworkSettings struct {
		IPAddress   string `json:"IpAddress"`
		IPPrefixLen int    `json:"IpPrefixLen"`
		MacAddress  string `json:"MacAddress,omitempty" yaml:"MacAddress,omitempty"`
		Gateway     string
		Bridge      string
		Ports       map[string][]PortBinding
		Networks    map[string]*EndpointSettings
		NetworkID   string `json:"NetworkID,omitempty" yaml:"NetworkID,omitempty"`
		EndpointID  string `json:"EndpointID,omitempty" yaml:"EndpointID,omitempty"`
		SandboxKey  string `json:"SandboxKey,omitempty" yaml:"SandboxKey,omitempty"`
	}
	SysInitPath    string
	ResolvConfPath string
	Volumes        map[string]string
	HostConfig     *HostConfig
	Mounts         []MountPoint
}

type ContainerChanges struct {
	Path string
	Kind int
}

type Port struct {
	IP          string
	PrivatePort int
	PublicPort  int
	Type        string
}

// EndpointSettings stores the network endpoint details
type EndpointSettings struct {
	// Configurations
	IPAMConfig *EndpointIPAMConfig
	Links      []string
	Aliases    []string
	// Operational data
	NetworkID           string
	EndpointID          string
	Gateway             string
	IPAddress           string
	IPPrefixLen         int
	IPv6Gateway         string
	GlobalIPv6Address   string
	GlobalIPv6PrefixLen int
	MacAddress          string
}

// NetworkingConfig represents the container's networking configuration for each of its interfaces
// Carries the networink configs specified in the `docker run` and `docker network connect` commands
type NetworkingConfig struct {
	EndpointsConfig map[string]*EndpointSettings // Endpoint configs for each conencting network
}

type Container struct {
	Id              string
	Names           []string
	Image           string
	Command         string
	Created         int64
	Status          string
	Ports           []Port
	SizeRw          int64
	SizeRootFs      int64
	Labels          map[string]string
	NetworkSettings struct {
		Networks map[string]EndpointSettings
	}
}

type Actor struct {
	ID         string
	Attributes map[string]string
}

type Event struct {
	Status string `json:"status,omitempty"`
	ID     string `json:"id,omitempty"`
	From   string `json:"from,omitempty"`

	Type   string
	Action string
	Actor  Actor

	Time     int64 `json:"time,omitempty"`
	TimeNano int64 `json:"timeNano,omitempty"`
}

type Version struct {
	ApiVersion    string
	Arch          string
	GitCommit     string
	GoVersion     string
	KernelVersion string
	Os            string
	Version       string
}

type RespContainersCreate struct {
	Id       string
	Warnings []string
}

type Image struct {
	Created     int64
	Id          string
	Labels      map[string]string
	ParentId    string
	RepoDigests []string
	RepoTags    []string
	Size        int64
	VirtualSize int64
}

// Info is the struct returned by /info
// The API is currently in flux, so Debug, MemoryLimit, SwapLimit, and
// IPv4Forwarding are interfaces because in docker 1.6.1 they are 0 or 1 but in
// master they are bools.
type Info struct {
	ID                 string
	Containers         int64
	Driver             string
	DriverStatus       [][]string
	ExecutionDriver    string
	Images             int64
	KernelVersion      string
	OperatingSystem    string
	NCPU               int64
	MemTotal           int64
	Name               string
	Labels             []string
	Debug              interface{}
	NFd                int64
	NGoroutines        int64
	SystemTime         string
	NEventsListener    int64
	InitPath           string
	InitSha1           string
	IndexServerAddress string
	MemoryLimit        interface{}
	SwapLimit          interface{}
	IPv4Forwarding     interface{}
	BridgeNfIptables   bool
	BridgeNfIp6tables  bool
	DockerRootDir      string
	HttpProxy          string
	HttpsProxy         string
	NoProxy            string
	Registries         interface{}
}

type ImageDelete struct {
	Deleted  string
	Untagged string
}

type StatsOrError struct {
	Stats
	Error error
}

type EventOrError struct {
	Event
	Error error
}

type WaitResult struct {
	ExitCode int
	Error    error
}

type decodingResult struct {
	result interface{}
	err    error
}

// The following are types for the API stats endpoint
type ThrottlingData struct {
	// Number of periods with throttling active
	Periods uint64 `json:"periods"`
	// Number of periods when the container hit its throttling limit.
	ThrottledPeriods uint64 `json:"throttled_periods"`
	// Aggregate time the container was throttled for in nanoseconds.
	ThrottledTime uint64 `json:"throttled_time"`
}

// All CPU stats are aggregated since container inception.
type CpuUsage struct {
	// Total CPU time consumed.
	// Units: nanoseconds.
	TotalUsage uint64 `json:"total_usage"`
	// Total CPU time consumed per core.
	// Units: nanoseconds.
	PercpuUsage []uint64 `json:"percpu_usage"`
	// Time spent by tasks of the cgroup in kernel mode.
	// Units: nanoseconds.
	UsageInKernelmode uint64 `json:"usage_in_kernelmode"`
	// Time spent by tasks of the cgroup in user mode.
	// Units: nanoseconds.
	UsageInUsermode uint64 `json:"usage_in_usermode"`
}

type CpuStats struct {
	CpuUsage       CpuUsage       `json:"cpu_usage"`
	SystemUsage    uint64         `json:"system_cpu_usage"`
	ThrottlingData ThrottlingData `json:"throttling_data,omitempty"`
}

type NetworkStats struct {
	RxBytes   uint64 `json:"rx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	RxDropped uint64 `json:"rx_dropped"`
	TxBytes   uint64 `json:"tx_bytes"`
	TxPackets uint64 `json:"tx_packets"`
	TxErrors  uint64 `json:"tx_errors"`
	TxDropped uint64 `json:"tx_dropped"`
}

type MemoryStats struct {
	Usage    uint64            `json:"usage"`
	MaxUsage uint64            `json:"max_usage"`
	Stats    map[string]uint64 `json:"stats"`
	Failcnt  uint64            `json:"failcnt"`
	Limit    uint64            `json:"limit"`
}

type BlkioStatEntry struct {
	Major uint64 `json:"major"`
	Minor uint64 `json:"minor"`
	Op    string `json:"op"`
	Value uint64 `json:"value"`
}

type BlkioStats struct {
	// number of bytes tranferred to and from the block device
	IoServiceBytesRecursive []BlkioStatEntry `json:"io_service_bytes_recursive"`
	IoServicedRecursive     []BlkioStatEntry `json:"io_serviced_recursive"`
	IoQueuedRecursive       []BlkioStatEntry `json:"io_queue_recursive"`
	IoServiceTimeRecursive  []BlkioStatEntry `json:"io_service_time_recursive"`
	IoWaitTimeRecursive     []BlkioStatEntry `json:"io_wait_time_recursive"`
	IoMergedRecursive       []BlkioStatEntry `json:"io_merged_recursive"`
	IoTimeRecursive         []BlkioStatEntry `json:"io_time_recursive"`
	SectorsRecursive        []BlkioStatEntry `json:"sectors_recursive"`
}

type Stats struct {
	Read         time.Time    `json:"read"`
	NetworkStats NetworkStats `json:"network,omitempty"`
	CpuStats     CpuStats     `json:"cpu_stats,omitempty"`
	MemoryStats  MemoryStats  `json:"memory_stats,omitempty"`
	BlkioStats   BlkioStats   `json:"blkio_stats,omitempty"`
}

type Ulimit struct {
	Name string `json:"name"`
	Soft int64  `json:"soft"`
	Hard int64  `json:"hard"`
}

type LogConfig struct {
	Type   string            `json:"type"`
	Config map[string]string `json:"config"`
}

type BuildImage struct {
	Config         *ConfigFile
	DockerfileName string
	Context        io.Reader
	RemoteURL      string
	RepoName       string
	SuppressOutput bool
	NoCache        bool
	Remove         bool
	ForceRemove    bool
	Pull           bool
	Memory         int64
	MemorySwap     int64
	CpuShares      int64
	CpuPeriod      int64
	CpuQuota       int64
	CpuSetCpus     string
	CpuSetMems     string
	CgroupParent   string
	BuildArgs      map[string]string
	Labels         map[string]string // Labels hold metadata about the image
}

type Volume struct {
	Name       string            // Name is the name of the volume
	Driver     string            // Driver is the Driver name used to create the volume
	Mountpoint string            // Mountpoint is the location on disk of the volume
	Labels     map[string]string // Labels hold metadata about the volume
}

type VolumesListResponse struct {
	Volumes []*Volume // Volumes is the list of volumes being returned
}

type VolumeCreateRequest struct {
	Name       string            // Name is the requested name of the volume
	Driver     string            // Driver is the name of the driver that should be used to create the volume
	DriverOpts map[string]string // DriverOpts holds the driver specific options to use for when creating the volume.
	Labels     map[string]string // Labels hold metadata about the volume
}

// IPAM represents IP Address Management
type IPAM struct {
	Driver  string
	Options map[string]string //Per network IPAM driver options
	Config  []IPAMConfig
}

// IPAMConfig represents IPAM configurations
type IPAMConfig struct {
	Subnet     string            `json:",omitempty"`
	IPRange    string            `json:",omitempty"`
	Gateway    string            `json:",omitempty"`
	AuxAddress map[string]string `json:"AuxiliaryAddresses,omitempty"`
}

// EndpointIPAMConfig represents IPAM configurations for the endpoint
type EndpointIPAMConfig struct {
	IPv4Address string `json:",omitempty"`
	IPv6Address string `json:",omitempty"`
}

// NetworkResource is the body of the "get network" http response message
type NetworkResource struct {
	Name   string
	ID     string `json:"Id"`
	Scope  string
	Driver string
	IPAM   IPAM
	//Internal   bool
	Containers map[string]EndpointResource
	Options    map[string]string
	Labels     map[string]string // Labels hold metadata about the network
}

// EndpointResource contains network resources allocated and used for a container in a network
type EndpointResource struct {
	Name        string
	EndpointID  string
	MacAddress  string
	IPv4Address string
	IPv6Address string
}

// NetworkCreate is the expected body of the "create network" http request message
type NetworkCreate struct {
	Name           string
	CheckDuplicate bool
	Driver         string
	IPAM           IPAM
	Internal       bool
	Options        map[string]string
	Labels         map[string]string // Labels hold metadata about the network
}

// NetworkCreateResponse is the response message sent by the server for network create call
type NetworkCreateResponse struct {
	ID      string `json:"Id"`
	Warning string
}

// NetworkConnect represents the data to be used to connect a container to the network
type NetworkConnect struct {
	Container string
}

// NetworkDisconnect represents the data to be used to disconnect a container from the network
type NetworkDisconnect struct {
	Container string
	Force     bool
}

type ServiceVirtualIP struct {
	NetworkID string
	Addr      string
}

type ServiceResource struct {
	ID   string
	Spec struct {
		Name   string
		Labels map[string]string
	}
	Endpoint struct {
		Spec struct {
			Mode string
		}
		VirtualIPs []ServiceVirtualIP
	}
}

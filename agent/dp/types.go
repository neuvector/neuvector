package dp

import (
	"net"

	"github.com/neuvector/neuvector/share"
)

type DPCallback func(buf []byte, param interface{}) bool
type DPTaskCallback func(task *DPTask)

const (
	DP_TASK_THREAT_LOG = iota
	DP_TASK_CONNECTION
	DP_TASK_HOST_CONNECTION
	DP_TASK_APPLICATION
	DP_TASK_FQDN_IP
	DP_TASK_IP_FQDN_STORAGE_UPDATE
	DP_TASK_IP_FQDN_STORAGE_RELEASE
)

type Connection struct {
	AgentID      string
	HostID       string
	ClientWL     string
	ServerWL     string
	ClientIP     net.IP
	ServerIP     net.IP
	Scope        string
	Network      string
	ServerPort   uint16
	ClientPort   uint16
	IPProto      uint8
	Application  uint32
	Bytes        uint64
	Sessions     uint32
	FirstSeenAt  uint32
	LastSeenAt   uint32
	ThreatID     uint32
	Severity     uint8
	PolicyAction uint8
	Ingress      bool
	ExternalPeer bool
	LocalPeer    bool
	PolicyId     uint32
	Violates     uint32
	Xff          bool
	SvcExtIP     bool
	ToSidecar    bool
	MeshToSvr    bool
	LinkLocal    bool
	TmpOpen      bool
	UwlIp        bool
	EpSessCurIn  uint32
	EpSessIn12   uint32
	EpByteIn12   uint64
	Nbe          bool
	NbeSns       bool
}

type ConnectionData struct {
	EPMAC net.HardwareAddr
	Conn  *Connection
}

type IpFqdnStorageUpdate struct {
	IP   net.IP
	Name string
}

type DPTask struct {
	Task               int
	MAC                net.HardwareAddr
	SecLog             *share.CLUSThreatLog
	Connects           []*ConnectionData
	Apps               map[share.CLUSProtoPort]*share.CLUSApp
	Fqdns              *share.CLUSFqdnIp
	FqdnStorageUpdate  *IpFqdnStorageUpdate
	FqdnStorageRelease net.IP
}

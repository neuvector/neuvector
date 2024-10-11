package probe

import (
	"github.com/neuvector/neuvector/agent/dp"
	"github.com/neuvector/neuvector/agent/workerlet"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/fsmon"
	"github.com/neuvector/neuvector/share/osutil"
	"github.com/neuvector/neuvector/share/utils"
	"time"
)

type ProbeConfig struct {
	ProfileEnable        bool
	Pid                  int
	PidMode              string
	DpTaskCallback       dp.DPTaskCallback
	NotifyTaskChan       chan *ProbeMessage
	NotifyFsTaskChan     chan *fsmon.MonitorMessage
	PolicyLookupFunc     func(conn *dp.Connection) (uint32, uint8, bool)
	ProcPolicyLookupFunc func(id, riskType, pname, ppath string, pid, pgid, shellCmd int, proc *share.CLUSProcessProfileEntry) (string, string, string, string, bool, error)
	IsK8sGroupWithProbe  func(svcGroup string) bool
	ReportLearnProc      func(svcGroup string, proc *share.CLUSProcessProfileEntry)
	IsNeuvectorContainer func(id string) (string, bool)
	ContainerInContainer bool
	GetContainerPid      func(id string) int
	GetAllContainerList  func() utils.Set
	RerunKubeBench       func(string, string)
	GetEstimateProcGroup func(id, name, path string) (string, string)
	GetServiceGroupName  func(id string) (string, bool, bool)
	CapKubeBench         bool
	FAEndChan            chan bool
	EnableTrace          bool
	DeferContStartRpt    bool
	KubePlatform         bool
	KubeFlavor           string
	WalkHelper           *workerlet.Tasker
}

const (
	PROBE_PROCESS_CHANGE = iota
	PROBE_CONTAINER_START
	PROBE_CONTAINER_STOP
	PROBE_CONTAINER_NEW_IP
	PROBE_REPORT_ESCALATION
	PROBE_REPORT_SUSPICIOUS
	PROBE_REPORT_TUNNEL
	PROBE_REPORT_FILE_MODIFIED
	PROBE_REPORT_PROCESS_VIOLATION
	PROBE_REPORT_PROCESS_DENIED
	PROBE_HOST_NEW_IP // obsolete
)

var ProbeMsgName = []string{
	PROBE_PROCESS_CHANGE:           "process_change",
	PROBE_CONTAINER_START:          "container_start",
	PROBE_CONTAINER_STOP:           "container_stop",
	PROBE_CONTAINER_NEW_IP:         "container_new_ip",
	PROBE_REPORT_ESCALATION:        "escalation",
	PROBE_REPORT_SUSPICIOUS:        "suspicious_process",
	PROBE_REPORT_TUNNEL:            "tunnel_connection",
	PROBE_REPORT_FILE_MODIFIED:     "file_modified",
	PROBE_REPORT_PROCESS_VIOLATION: "process_profile_violation",
	PROBE_REPORT_PROCESS_DENIED:    "process_profile_denied",
	PROBE_HOST_NEW_IP:              "host_new_ip", // obsolete
}

type ProbeMessage struct {
	Type         int
	Count        int
	StartAt      time.Time
	Connections  []*dp.Connection
	ContainerIDs utils.Set
	Escalation   *ProbeEscalation
	Process      *ProbeProcess
}

type ProbeEscalation struct {
	ID       string
	Pid      int
	Name     string
	Path     string
	Cmds     []string
	RUid     int
	EUid     int
	RealUser string
	EffUser  string

	// parent info
	ParentPid  int
	ParentName string
	ParentPath string
	ParentCmds []string

	Msg string
}

type ProbeProcess struct {
	ID          string
	Name        string
	Path        string
	Cmds        []string
	Pid         int
	EUid        int
	EUser       string
	PPid        int
	PName       string
	PPath       string
	Connection  *osutil.Connection
	ConnIngress bool
	RuleID      string
	Group       string
	Msg         string
}

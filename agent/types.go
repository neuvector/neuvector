package main

import (
	"net"
	"time"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/container"
)

type AgentEnvInfo struct {
	startsAt             time.Time
	runInContainer       bool
	runWithController    bool
	containerInContainer bool
	containerShieldMode  bool
	cgroupMemory         string
	cgroupCPUAcct        string
	kvCongestCtrl        bool
	scanSecrets          bool
	autoBenchmark        bool
	systemProfiles       bool
	customBenchmark      bool
	netPolicyPuller      int
	autoProfieCapture    uint64
	memoryLimit          uint64
	peakMemoryUsage      uint64
	snapshotMemStep      uint64
}

const (
	EV_ADD_CONTAINER = iota
	EV_STOP_CONTAINER
	EV_DEL_CONTAINER
	EV_REFRESH_CONTAINERS
	EV_UPDATE_CONTAINER
	EV_CLUSTER_EXIT
)

var ClusterEventName = []string{
	EV_ADD_CONTAINER:      "add_container",
	EV_STOP_CONTAINER:     "stop_container",
	EV_DEL_CONTAINER:      "del_container",
	EV_REFRESH_CONTAINERS: "refresh_containers",
	EV_UPDATE_CONTAINER:   "update_container",
	EV_CLUSTER_EXIT:       "cluster_exit",
}

type ClusterEvent struct {
	event int
	id    string
	info  *container.ContainerMetaExtra

	// applications map[share.CLUSProtoPort]*share.CLUSApp
	apps        map[string]share.CLUSApp
	ports       map[string]share.CLUSMappedPort
	ifaces      map[string][]share.CLUSIPAddr
	role        *string
	service     *string
	domain      *string
	shareNetNS  *string
	inline      *bool
	quar        *bool
	quarReason  *string
	capIntcp    *bool
	capSniff    *bool
	hasDatapath *bool
}

const (
	TASK_ADD_CONTAINER = iota
	TASK_STOP_CONTAINER
	TASK_DEL_CONTAINER
	TASK_CONFIG_CONTAINER
	TASK_CONFIG_AGENT
	TASK_CONFIG_SYSTEM
	TASK_REEXAM_PROC_CONTAINER
	TASK_REEXAM_INTF_CONTAINER
	TASK_APP_UPDATE_FROM_DP
	TASK_INTERCEPT_CONTAINER
	TASK_EXIT
)

var ContainerTaskName = []string{
	TASK_ADD_CONTAINER:         "add_container",
	TASK_STOP_CONTAINER:        "stop_container",
	TASK_DEL_CONTAINER:         "del_container",
	TASK_CONFIG_CONTAINER:      "config_container",
	TASK_CONFIG_AGENT:          "config_agent",
	TASK_CONFIG_SYSTEM:         "config_system",
	TASK_REEXAM_PROC_CONTAINER: "reexam_proc_container",
	TASK_REEXAM_INTF_CONTAINER: "reexam_intf_container",
	TASK_APP_UPDATE_FROM_DP:    "app_update_from_dp",
	TASK_INTERCEPT_CONTAINER:   "intercept_container",
	TASK_EXIT:                  "exit",
}

type taskHandler interface {
	handler()
}

type ContainerTask struct {
	task int
	id   string
	pid  int
	info *container.ContainerMetaExtra
	//	expect string

	// APP update
	mac  net.HardwareAddr
	apps map[share.CLUSProtoPort]*share.CLUSApp

	macConf   *share.CLUSWorkloadConfig
	agentConf *share.CLUSAgentConfig

	taskData taskHandler
}

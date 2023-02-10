package api

const (
	ProfilingCPU         string = "cpu"
	ProfilingMemory      string = "memory"
	ProfilingDurationMax uint32 = 60
)

type RESTDerivedPolicyRule struct {
	ID          uint32 `json:"policy_id"`
	SrcIP       string `json:"from"`
	DstIP       string `json:"to"`
	Port        string `json:"port"`
	Action      string `json:"action"`
	Ingress     bool   `json:"ingress"`
	Application string `json:"application"`
	Domain      string `json:"domain,omitempty"`
}

type RESTDerivedWorkloadPolicyRule struct {
	Workload *RESTWorkloadBrief       `json:"workload"`
	Rules    []*RESTDerivedPolicyRule `json:"rules"`
}

type RESTDerivedPolicyRuleData struct {
	WorkloadRules []*RESTDerivedWorkloadPolicyRule `json:"workload_rules"`
}

type RESTDebugIP2Workload struct {
	IP       string             `json:"ip"`
	Workload *RESTWorkloadBrief `json:"workload"`
}

type RESTDebugIP2WorkloadData struct {
	IP2Workloads []*RESTDebugIP2Workload `json:"ip_2_workloads"`
}

type RESTDebugSyncInfo struct {
	ClusterIP      string                `json:"cluster_ip"`
	Leader         bool                  `json:"leader"`
	SyncErrorFound bool                  `json:"sync_error_found"`
	LearnedRuleMax uint32                `json:"learned_rule_max"`
	GraphNodeCount uint32                `json:"graph_node_count"`
	PolicyError    []*RESTPolicyMismatch `json:"policy_error,omitempty"`
}

type RESTDebugSyncInfoData struct {
	Sync []*RESTDebugSyncInfo `json:"sync"`
}

type RESTProbeSummary struct {
	ContainerMap    uint32 `json:"containers"`
	PidContainerMap uint32 `json:"pid_containers"`
	PidProcMap      uint32 `json:"pid_procs"`
	NewProcesses    uint32 `json:"new_procs"`
	NewSuspicProc   uint32 `json:"new_suspicious_procs"`
	ContainerStops  uint32 `json:"stopped_container"`
	PidSet          uint32 `json:"pids"`
	SessionTable    uint32 `json:"host_sessions"`
}

type RESTProbeSummaryData struct {
	Summary *RESTProbeSummary `json:"summary"`
}

type RESTProbeProcess struct {
	Pid       int32  `json:"pid"`
	Ppid      int32  `json:"ppid"`
	Name      string `json:"name"`
	Ruid      uint32 `json:"ruid"`
	Euid      uint32 `json:"euid"`
	ScanTimes uint32 `json:"scan_times"`
	StartTime uint64 `json:"start_times"`
	Reported  uint32 `json:"reported"`
	Container string `json:"container"`
}

type RESTProbeProcessesData struct {
	Processes []*RESTProbeProcess `json:"processes"`
}

type RESTProbeContainer struct {
	Id       string  `json:"id"`
	Pid      int32   `json:"pid"`
	Children []int32 `json:"children"`
	PortsMap string  `json:"port_map"`
}

type RESTProbeContainersData struct {
	Containers []*RESTProbeContainer `json:"containers"`
}

type RESTRegistryDebugImageTag struct {
	Tag    string `json:"tag"`
	Serial string `json:"serial"`
}

type RESTRegistryDebugImage struct {
	Domain     string                       `json:"domain"`
	Repository string                       `json:"repository"`
	Tags       []*RESTRegistryDebugImageTag `json:"tags"`
}

type RESTRegistryDebugImageData struct {
	Images []*RESTRegistryDebugImage `json:"images"`
}

type RESTRegistryTestData struct {
	Config *RESTRegistry `json:"config"`
}

const (
	HTTPTestStepStage    = "stage"
	HTTPTestStepImage    = "images"
	HTTPTestStepURL      = "url"
	HTTPTestStepResponse = "response"
	HTTPTestStepError    = "error"
)

type RESTRegistryTestStep struct {
	Step    string `json:"step_type"`
	Content string `json:"step_content"`
}

type RESTRegistryTestStepData struct {
	Steps []*RESTRegistryTestStep `json:"steps"`
}

type RESTProfiling struct {
	Methods  []string `json:"methods"`
	Duration uint32   `json:"duration"`
}

type RESTProfilingData struct {
	Profiling *RESTProfiling `json:"profiling"`
}

type RESTRiskScoreMetricsWL struct {
	RunningPods    int `json:"running_pods"`
	PrivilegedWLs  int `json:"privileged_wls"`
	RootWLs        int `json:"root_wls"`
	DiscoverExtEPs int `json:"discover_ext_eps"`
	MonitorExtEPs  int `json:"monitor_ext_eps"`
	ProtectExtEPs  int `json:"protect_ext_eps"`
	ThrtExtEPs     int `json:"threat_ext_eps"`
	VioExtEPs      int `json:"violate_ext_eps"`
}

type RESTRiskScoreMetricsGroup struct {
	Groups           int `json:"groups"`
	DiscoverGroups   int `json:"discover_groups"`
	MonitorGroups    int `json:"monitor_groups"`
	ProtectGroups    int `json:"protect_groups"`
	DiscoverGroupsZD int `json:"discover_groups_zero_drift"`
	MonitorGroupsZD  int `json:"monitor_groups_zero_drift"`
	ProtectGroupsZD  int `json:"protect_groups_zero_drift"`
}

type RESTRiskScoreMetricsCVE struct {
	DiscoverCVEs int `json:"discover_cves"`
	MonitorCVEs  int `json:"monitor_cves"`
	ProtectCVEs  int `json:"protect_cves"`
	PlatformCVEs int `json:"platform_cves"`
	HostCVEs     int `json:"host_cves"`
}

type RESTRiskScoreMetrics struct {
	Platform         string                    `json:"platform"`
	K8sVersion       string                    `json:"kube_version"`
	OCVersion        string                    `json:"openshift_version"`
	NewServiceMode   string                    `json:"new_service_policy_mode"`
	DenyAdmCtrlRules int                       `json:"deny_adm_ctrl_rules"`
	Hosts            int                       `json:"hosts"`
	WLs              RESTRiskScoreMetricsWL    `json:"workloads"`
	Groups           RESTRiskScoreMetricsGroup `json:"groups"`
	CVEs             RESTRiskScoreMetricsCVE   `json:"cves"`
}

type RESTExposedEndpoint struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	DisplayName  string   `json:"display_name"`
	PodName      string   `json:"pod_name"`
	Service      string   `json:"service"`
	Severity     string   `json:"severity"`
	PolicyMode   string   `json:"policy_mode"`
	PolicyAction string   `json:"policy_action"`
	Protos       []string `json:"protocols,omitempty"`
	Apps         []string `json:"applications,omitempty"`
	Ports        []string `json:"ports,omitempty"`
}

type RESTInternalSystemData struct {
	Metrics *RESTRiskScoreMetrics  `json:"metrics"`
	Ingress []*RESTExposedEndpoint `json:"ingress"`
	Egress  []*RESTExposedEndpoint `json:"egress"`
}

type RESTK8sNvRbacStatus struct {
	ClusterRoleErrors        []string              `json:"clusterrole_errors"`
	ClusterRoleBindingErrors []string              `json:"clusterrolebinding_errors"`
	RoleBindingErrors        []string              `json:"rolebinding_errors"`
	NvUpgradeInfo            *RESTCheckUpgradeInfo `json:"neuvector_upgrade_info"`
}

// telemetry
type RESTUpgradeInfo struct {
	Version     string // must be in semantic versioning, like v5.0.0
	ReleaseDate string
	Tag         string
}

type RESTCheckUpgradeInfo struct {
	MinUpgradeVersion *RESTUpgradeInfo `json:"min_upgrade_version"`
	MaxUpgradeVersion *RESTUpgradeInfo `json:"max_upgrade_version"`
}

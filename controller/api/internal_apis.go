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

type RESTRegistryTestDataV2 struct {
	Config *RESTRegistryV2 `json:"config"`
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
	Groups                int `json:"groups"`
	DiscoverGroups        int `json:"discover_groups"`
	MonitorGroups         int `json:"monitor_groups"`
	ProtectGroups         int `json:"protect_groups"`
	ProfileDiscoverGroups int `json:"profile_discover_groups"`
	ProfileMonitorGroups  int `json:"profile_monitor_groups"`
	ProfileProtectGroups  int `json:"profile_protect_groups"`
	DiscoverGroupsZD      int `json:"discover_groups_zero_drift"`
	MonitorGroupsZD       int `json:"monitor_groups_zero_drift"`
	ProtectGroupsZD       int `json:"protect_groups_zero_drift"`
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
	NewProfileMode   string                    `json:"new_service_profile_mode"`
	DenyAdmCtrlRules int                       `json:"deny_adm_ctrl_rules"`
	Hosts            int                       `json:"hosts"`
	WLs              RESTRiskScoreMetricsWL    `json:"workloads"`
	Groups           RESTRiskScoreMetricsGroup `json:"groups"`
	CVEs             RESTRiskScoreMetricsCVE   `json:"cves"`
}

type RESTExposedEndpoint struct {
	ID             string                         `json:"id"`
	Name           string                         `json:"name"`
	DisplayName    string                         `json:"display_name"`
	PodName        string                         `json:"pod_name"`
	Service        string                         `json:"service"`
	ThreatSeverity string                         `json:"severity"`
	CriticalVuls   int                            `json:"critical"`
	HighVuls       int                            `json:"high"`
	MedVuls        int                            `json:"medium"`
	PolicyMode     string                         `json:"policy_mode"`
	PolicyAction   string                         `json:"policy_action"`
	Protos         []string                       `json:"protocols,omitempty"`
	Apps           []string                       `json:"applications,omitempty"`
	Ports          []string                       `json:"ports,omitempty"`
	Entries        []*RESTConversationReportEntry `json:"entries"`
}

type RESTInternalSystemData struct {
	Metrics *RESTRiskScoreMetrics  `json:"metrics"`
	Ingress []*RESTExposedEndpoint `json:"ingress"`
	Egress  []*RESTExposedEndpoint `json:"egress"`
}

type RESTK8sNvRbacStatus struct {
	ClusterRoleErrors        []string                   `json:"clusterrole_errors,omitempty"`        // obsolete
	ClusterRoleBindingErrors []string                   `json:"clusterrolebinding_errors,omitempty"` // obsolete
	RoleErrors               []string                   `json:"role_errors,omitempty"`               // obsolete
	RoleBindingErrors        []string                   `json:"rolebinding_errors,omitempty"`        // obsolete
	NvCrdSchemaErrors        []string                   `json:"neuvector_crd_errors,omitempty"`      // obsolete
	NvUpgradeInfo            *RESTCheckUpgradeInfo      `json:"neuvector_upgrade_info"`
	AcceptableAlerts         *RESTK8sNvAcceptableAlerts `json:"acceptable_alerts,omitempty"` // acceptable controller-generated alerts
	AcceptedAlerts           []string                   `json:"accepted_alerts,omitempty"`   // keys of accepted manager-generated/user alerts
}

type RESTK8sNvAcceptableAlerts struct {
	ClusterRoleErrors        map[string]string `json:"clusterrole_errors"`        // key is md5 of the English message
	ClusterRoleBindingErrors map[string]string `json:"clusterrolebinding_errors"` // key is md5 of the English message
	RoleErrors               map[string]string `json:"role_errors"`               // key is md5 of the English message
	RoleBindingErrors        map[string]string `json:"rolebinding_errors"`        // key is md5 of the English message
	NvCrdSchemaErrors        map[string]string `json:"neuvector_crd_errors"`      // key is md5 of the English message
	OtherAlerts              map[string]string `json:"other_alerts"`              // key is md5 of the English message
}

type RESTNvAlerts struct {
	NvUpgradeInfo    *RESTCheckUpgradeInfo   `json:"neuvector_upgrade_info"`
	AcceptableAlerts *RESTNvAcceptableAlerts `json:"acceptable_alerts,omitempty"` // acceptable controller-generated alerts
	AcceptedAlerts   []string                `json:"accepted_alerts,omitempty"`   // keys of accepted manager-generated/user alerts
}

type RESTNvAcceptableAlerts struct {
	ClusterRoleAlerts        *RESTNvAlertGroup `json:"clusterrole_alerts,omitempty"`
	ClusterRoleBindingAlerts *RESTNvAlertGroup `json:"clusterrolebinding_alerts,omitempty"`
	RoleAlerts               *RESTNvAlertGroup `json:"role_alerts,omitempty"`
	RoleBindingAlerts        *RESTNvAlertGroup `json:"rolebinding_alerts,omitempty"`
	NvCrdSchemaAlerts        *RESTNvAlertGroup `json:"neuvector_crd_alerts,omitempty"`
	CertificateAlerts        *RESTNvAlertGroup `json:"certificate_alerts,omitempty"`
	OtherAlerts              *RESTNvAlertGroup `json:"other_alerts,omitempty"`
}

type AlertType string

const (
	AlertTypeRBAC           AlertType = "RBAC"
	AlertTypeTlsCertificate AlertType = "TLS_CERTIFICATE"
)

type RESTNvAlertGroup struct {
	Type AlertType      `json:"type"`
	Data []*RESTNvAlert `json:"data,omitempty"`
}

type RESTNvAlert struct {
	ID      string `json:"id"` // ID is md5 of the English message
	Message string `json:"message"`
}

type RESTAcceptedAlerts struct {
	ManagerAlerts    []string `json:"manager_alerts"`    // message key slice of manager-generated alerts
	ControllerAlerts []string `json:"controller_alerts"` // message key slice of controller-generated alerts
	UserAlerts       []string `json:"user_alerts"`       // message key slice of current login user alerts
}

// telemetry
type RESTUpgradeInfo struct {
	Version     string `json:"version"` // must be in semantic versioning, like v5.0.0
	ReleaseDate string `json:"release_date"`
	Tag         string `json:"tag"`
}

type RESTCheckUpgradeInfo struct {
	MinUpgradeVersion *RESTUpgradeInfo `json:"min_upgrade_version"`
	MaxUpgradeVersion *RESTUpgradeInfo `json:"max_upgrade_version"`
}

package api

import (
	"github.com/neuvector/neuvector/share"
)

const (
	FedRoleNone   = ""
	FedRoleMaster = "master"
	FedRoleJoint  = "joint"
)

const (
	FedClusterStatusNone           = "active"
	FedClusterStatusCmdUnknown     = "unknown_cmd"
	FedClusterStatusCmdReceived    = "notified"
	FedClusterStatusCmdReqError    = "req_error"
	FedStatusMasterUpgradeRequired = "master_upgrade_required" // for describing master cluster only
	FedStatusJointUpgradeRequired  = "joint_upgrade_required"  // for describing joint cluster only
	FedStatusClusterUpgradeOngoing = "cluster_upgrade_ongoing" // could get this status only when rolling upgrade & polling fed rules on joint cluster are happenging
	FedStatusJointVersionTooNew    = "joint_version_too_new"   // for describing joint cluster only
	FedStatusClusterConnected      = "connected"               // for describing master cluster only
	FedStatusClusterDisconnected   = "disconnected"            // for describing master cluster only
	FedStatusClusterJoined         = "joined"                  // for describing joint cluster only. short-lived (between joining and the first polling)
	FedStatusClusterOutOfSync      = "out_of_sync"             // for describing joint cluster only
	FedStatusClusterSynced         = "synced"                  // for describing joint cluster only
	FedStatusClusterKicked         = "kicked"                  // for describing self on joint cluster only
	FedStatusClusterLeft           = "left"                    // for describing joint cluster only
	FedStatusLicenseDisallowed     = "license_disallow"        // for describing clusters in fed
	FedStatusClusterPinging        = "pinging"                 // for describing joint cluster only. short-lived (between license update and the immediate ping)
	FedStatusClusterSyncing        = "syncing"                 // for describing joint cluster only. short-lived (when joint cluster is applying fed rules)
	FedStatusClusterPending        = "pending"                 // for describing joint cluster only. when master cluster is not sure joint cluster has finished the joining fed operation
)

// master cluster: a promoted cluster. One per-federation
// joint cluster: the other non-master clusters that join the federation
// 1. A cluster becomes master cluster after it's promoted (providing the ip/port for other clusters to join)
// 2. A cluster can join one federation at most
// 3. A master cluster with joint cluster(s) cannot join other federation
// 4. A master cluster without any joint cluster can join another federation. At the same time it becomes joint cluster of another federation.
type RESTFedMasterClusterInfo struct {
	Disabled    bool                     `json:"disabled"`
	Name        string                   `json:"name"` // cluster name
	ID          string                   `json:"id"`
	Secret      string                   `json:"secret"`       // used for encryoting/decrypting join_ticket issued by the master cluster. never export
	User        string                   `json:"user"`         // the user who promoets this cluster to master cluster in federation
	Status      string                   `json:"status"`       // ex: FedStatusClusterSynced/FedStatusClusterOutOfSync (see above)
	RestVersion string                   `json:"rest_version"` // from kv.GetRestVer()
	RestInfo    share.CLUSRestServerInfo `json:"rest_info"`
}

type RESTFedJointClusterInfo struct {
	Disabled      bool                     `json:"disabled"`
	Name          string                   `json:"name"` // cluster name
	ID            string                   `json:"id"`
	Secret        string                   `json:"secret"`
	User          string                   `json:"user"`         // the user who joins this cluster to federation
	Status        string                   `json:"status"`       // ex: FedStatusClusterSynced/FedStatusClusterOutOfSync (see above)
	RestVersion   string                   `json:"rest_version"` // joint cluster's kv.GetRestVer()
	RestInfo      share.CLUSRestServerInfo `json:"rest_info"`
	ProxyRequired bool                     `json:"proxy_required"` // a joint cluster may be reachable without proxy even master cluster is configured to use proxy. decided when it joins fed.
}

type RESTFedMembereshipData struct { // including all clusters in the federation
	FedRole            string                     `json:"fed_role"`                 // FedRoleMaster / FedRoleJoint / FedRoleNone (see above)
	LocalRestInfo      share.CLUSRestServerInfo   `json:"local_rest_info"`          //
	MasterCluster      *RESTFedMasterClusterInfo  `json:"master_cluster,omitempty"` // master cluster
	JointClusters      []*RESTFedJointClusterInfo `json:"joint_clusters"`           // all non-master clusters in the federation
	UseProxy           string                     `json:"use_proxy"`                // "" / https
	DeployRepoScanData bool                       `json:"deploy_repo_scan_data"`    // whether fed repo scan data deployment is enabled
}

type RESTFedConfigData struct { // including all clusters in the federation
	PingInterval       *uint32                   `json:"ping_interval,omitempty"` // in minute
	PollInterval       *uint32                   `json:"poll_interval,omitempty"` // in minute
	Name               *string                   `json:"name,omitempty"`          // cluster name
	RestInfo           *share.CLUSRestServerInfo `json:"rest_info,omitempty"`
	UseProxy           *string                   `json:"use_proxy,omitempty"`   // "" / https
	DeployRepoScanData *bool                     `json:"deploy_repo_scan_data"` // whether fed repo scan data deployment is enabled
}

type RESTFedPromoteReqData struct {
	Name               string                    `json:"name,omitempty"`             // cluster name
	PingInterval       uint32                    `json:"ping_interval"`              // in minute
	PollInterval       uint32                    `json:"poll_interval"`              // in minute
	MasterRestInfo     *share.CLUSRestServerInfo `json:"master_rest_info,omitempty"` // rest info about this master cluster
	UseProxy           *string                   `json:"use_proxy,omitempty"`        // "" / https
	DeployRepoScanData *bool                     `json:"deploy_repo_scan_data"`      // whether fed repo scan data deployment is enabled
}

type RESTFedPromoteRespData struct {
	FedRole            string                   `json:"fed_role"`
	MasterCluster      RESTFedMasterClusterInfo `json:"master_cluster"`        // info about this master cluster
	UseProxy           string                   `json:"use_proxy,omitempty"`   // "" / https
	DeployRepoScanData bool                     `json:"deploy_repo_scan_data"` // whether fed repo scan data deployment is enabled
}

type RESTFedJoinToken struct { // json of the join token that contains master cluster server/port & encrypted join_ticket
	JoinToken string `json:"join_token"`
}

type RESTFedJoinReq struct { // from manager to local cluster
	Name          string                    `json:"name"`                      // cluster name
	Server        string                    `json:"server"`                    // server of master cluster
	Port          uint                      `json:"port"`                      // port of master cluster
	JoinToken     string                    `json:"join_token"`                // generated by the master cluster, i.e. RESTFedJoinToken.JoinToken
	JointRestInfo *share.CLUSRestServerInfo `json:"joint_rest_info,omitempty"` // rest info about this joint cluster
	UseProxy      *string                   `json:"use_proxy,omitempty"`       // "" / https
}

type RESTFedJoinReqInternal struct { // from joining cluster to master cluster for joining federation.
	User         string                  `json:"user"`                   // current operating user
	Remote       string                  `json:"remote"`                 // current operating user's remote info
	UserRoles    map[string]string       `json:"user_roles"`             // current operating user's roles
	FedKvVersion string                  `json:"fed_kv_version"`         // kv version in the code of the joining cluster
	RestVersion  string                  `json:"rest_version,omitempty"` // rest version in the code of joining cluster
	JoinTicket   string                  `json:"join_ticket"`            // generated by the master cluster, not containing master's server/port
	JointCluster RESTFedJointClusterInfo `json:"joint_cluster"`          // info about joint cluster
	CspType      string                  `json:"csp_type"`
	Nodes        int                     `json:"nodes"`
}

type RESTFedJoinRespInternal struct { // from master cluster to joining cluster for response of joining federation.
	PollInterval  uint32                    `json:"poll_interval"`  // in minute
	CACert        string                    `json:"ca_cert"`        // ca cert for the federated rest server in master cluster
	ClientKey     string                    `json:"client_key"`     // client key for the joint cluster
	ClientCert    string                    `json:"client_cert"`    // client cert for the joint cluster
	MasterCluster *RESTFedMasterClusterInfo `json:"master_cluster"` // info about the master cluster
	CspType       string                    `json:"csp_type"`       // master's billing csp type
}

type RESTFedLeaveReq struct { // from manager to joint cluster
	Force bool `json:"force"` // true means leave federation no matter master cluster succeeds or not
}

// for leaving federation request from joint clusters to master cluster
type RESTFedLeaveReqInternal struct { // from joint cluster to master cluster for leaving federation.
	ID          string            `json:"id"`           // id of the joint cluster to leave federation
	JointTicket string            `json:"joint_ticket"` // generated using joint cluster's secret
	User        string            `json:"user"`         // current operating user
	Remote      string            `json:"remote"`       // current operating user's remote info
	UserRoles   map[string]string `json:"user_roles"`   // current operating user's roles
}

type RESTFedRemovedReqInternal struct { // from master cluster to joint cluster for being removed from federation.
	User string `json:"user"` // current operating user
}

type RESTFedTokenResp struct {
	Token string `json:"token"` // for issued by remote joint cluster
}

type RESTFedDataCfgMap struct {
	ClusterName        string                    `json:"cluster_name"`                    // this cluster's unique name in federation
	PrimaryRestInfo    share.CLUSRestServerInfo  `json:"primary_rest_info"`               // rest info about primary cluster
	ManagedRestInfo    *share.CLUSRestServerInfo `json:"managed_rest_info,omitempty"`     // rest info about managed cluster (for managed clusters only)
	UseProxy           string                    `json:"use_proxy"`                       // "" / https
	JoinToken          string                    `json:"join_token"`                      // must be in a format that is 36 characters long, i.e., 32 hexadecimal characters grouped as 8-4-4-4-12 and separated by four hyphens
	DeployRepoScanData *bool                     `json:"deploy_repo_scan_data,omitempty"` // whether fed repo scan data deployment is enabled (for master cluster only)
}

// for deploying fed settings to joint clusters
type RESTDeployFedRulesReq struct {
	Force bool     `json:"force"` // true means deploying all federal rules. false means only deploying the newly changed federal rules.
	IDs   []string `json:"ids"`   // empty means deploy to all clusters
}

type RESTDeployFedRulesResp struct {
	Results map[string]int `json:"results"` // value: _fedSuccess/....
}

type RESTFedRulesSettings struct {
	AdmCtrlRulesData    *share.CLUSFedAdmCtrlRulesData   `json:"admctrl_rules_data,omitempty"`
	NetworkRulesData    *share.CLUSFedNetworkRulesData   `json:"network_rules_data,omitempty"`
	ResponseRulesData   *share.CLUSFedResponseRulesData  `json:"response_rules_data,omitempty"`
	GroupsData          *share.CLUSFedGroupsData         `json:"groups_data,omitempty"`
	FileMonitorData     *share.CLUSFedFileMonitorData    `json:"file_monitor_data,omitempty"`
	ProcessProfilesData *share.CLUSFedProcessProfileData `json:"process_profiles_data,omitempty"`
	SystemConfigData    *share.CLUSFedSystemConfigData   `json:"system_config_data,omitempty"`
}

type RESTFedImageScanResult struct {
	MD5     string                          `json:"md5"` // it's md5 of json.marshal(gob(regImageSummaryReport))
	Summary *share.CLUSRegistryImageSummary `json:"summary,omitempty"`
	Report  *share.CLUSScanReport           `json:"report,omitempty"`
}

type RESTFedScanResultData struct {
	UpdatedScanResults map[string]map[string]*RESTFedImageScanResult `json:"updated_scan_result,omitempty"` // registry name : image id : scan result; it contains only new/updated scan results
	DeletedScanResults map[string][]string                           `json:"deleted_scan_result,omitempty"` // registry name : []image id. map value being nil means the registry is deleted
	UpToDateRegs       []string                                      `json:"up_to_date_regs,omitempty"`     // registries whose images scan result in managed cluster is already up-to-date
}

type RESTFedInternalCommandReq struct {
	FedKvVersion string            `json:"fed_kv_version"` // kv version in the code of master cluster
	Command      string            `json:"command"`        // currently supported commands: _cmdPollFedRules / _cmdForcePullFedRules
	User         string            `json:"user"`           // current operating user
	Revisions    map[string]uint64 `json:"revisions"`      // key is fed rules type, value is the revision of current fed rules
}

type RESTFedInternalCommandResp struct {
	Result int `json:"result"` // value: _fedCmdReceived/....
}

type RESTFedPingReq struct { // from manager to joint cluster
	Token        string `json:"token"`
	FedKvVersion string `json:"fed_kv_version"` // kv version in the code of the master cluster
}

type RESTFedPingResp struct { // from manager to joint cluster
	Result int `json:"result"` // value: _fedSuccess/....
}

// for polling fed rules/settings from joint clusters to master cluster
type RESTPollFedRulesReq struct {
	ID           string            `json:"id"`                     // id of joint cluster
	Name         string            `json:"name"`                   // name of joint cluster
	JointTicket  string            `json:"joint_ticket"`           // generated using joint cluster's secret
	FedKvVersion string            `json:"fed_kv_version"`         // kv version in the code of joint cluster
	RestVersion  string            `json:"rest_version,omitempty"` // rest version in the code of joint cluster
	Revisions    map[string]uint64 `json:"revisions"`              // key is fed rules type, value is the revision
	CspType      string            `json:"csp_type"`               // joint cluster's billing csp type
	Nodes        int               `json:"nodes"`
}

type RESTFedScanDataRevs struct {
	RegConfigRev   uint64            `json:"reg_config_rev"`   // fed registry revision
	ScannedRegRevs map[string]uint64 `json:"scanned_reg_revs"` // revisions of all fed registry scan data (registry name : revision)
	ScannedRepoRev uint64            `json:"scanned_repo_rev"` // revision of fed repo scan data on master cluster
}

type RESTPollFedRulesResp struct {
	Result             int                 `json:"result"`                // value: _fedSuccess/....
	PollInterval       uint32              `json:"poll_interval"`         // in minute
	Settings           []byte              `json:"settings,omitempty"`    // marshall of RESTFedRulesSettings, which contains only modified settings (for ~5.0.x)
	Revisions          map[string]uint64   `json:"revisions"`             // key is fed rules type, value is the revision. It contains only revisions of modified settings
	ScanDataRevs       RESTFedScanDataRevs `json:"scan_data_revs"`        // the latest revisions of all the fed registry/repo scan data on master cluster
	DeployRepoScanData bool                `json:"deploy_repo_scan_data"` // for informing whether master cluster deploys repo scan data to managed clusters
	CspType            string              `json:"csp_type"`              // master's billing csp type
}

type RESTPollFedScanDataReq struct {
	ID            string                       `json:"id"`                        // id of joint cluster
	Name          string                       `json:"name"`                      // name of joint cluster
	JointTicket   string                       `json:"joint_ticket"`              // generated using joint cluster's secret
	FedKvVersion  string                       `json:"fed_kv_version"`            // kv version in the code of joint cluster
	RestVersion   string                       `json:"rest_version"`              // rest version in the code of joint cluster
	RegConfigRev  uint64                       `json:"reg_config_rev"`            // revision of fed registry setting that the managed cluster remembers
	UpToDateRegs  []string                     `json:"up_to_date_regs,omitempty"` // fed registry/repo whose images scan result in managed cluster is already up-to-date
	ScanResultMD5 map[string]map[string]string `json:"scan_result_md5"`           // all scan result md5 of the scanned images in fed registry/repo that have different scan data revision from master (registry name : image id : scan result md5)
	IgnoreRegs    []string                     `json:"ignore_regs,omitempty"`     // the other fed registry/repo that have different scan data revision from master
}

type RESTPollFedScanDataResp struct {
	Result             int                          `json:"result"`                 // value: _fedSuccess/....
	PollInterval       uint32                       `json:"poll_interval"`          // in minute
	RegistryCfg        *share.CLUSFedRegistriesData `json:"registry_cfg,omitempty"` // all fed registry' settings if there is any change since last polling
	ScanResultData     RESTFedScanResultData        `json:"scan_result_data"`       // (partial) updated/deleted scan result of the requested fed registry/repo
	HasMoreScanResult  bool                         `json:"has_more_scan_reresult"` // (bandwidth consideration) true when master cluster returns partial scan result in ScanResultData for instructing managed clusters to keep polling.
	ThrottleTime       int64                        `json:"throttle_time"`          // in ms. decided by master cluster
	DeployRepoScanData bool                         `json:"deploy_repo_scan_data"`  // for informing whether master cluster deploys repo scan data to managed clusters
}

type RESTFedView struct {
	Compatible bool `json:"compatible"`
}

// csp-adapter billing integration
type RESTClusterCspUsage struct {
	CspType string `json:"csp_type"`
	Nodes   int    `json:"nodes"` // total nodes count in this cluster
}

type RESTCspAdapterInfo struct {
	AdapterVersions string `json:"adapter_versions"`
}

type RESTFedCspSupportReq struct { // for joint clusters to request csp-config data from master cluster
	ID           string `json:"id"`                     // id of joint cluster
	JointTicket  string `json:"joint_ticket"`           // generated using joint cluster's secret
	FedKvVersion string `json:"fed_kv_version"`         // kv version in the code of joint cluster
	RestVersion  string `json:"rest_version,omitempty"` // rest version in the code of joint cluster
}

type RESTFedCspSupportResp struct { // csp-config data returned from master cluster
	Compliant           bool     `json:"compliant"`
	ExpireTime          int64    `json:"expire_time"`     // the last billing "compliant" state's expiration time in seconds
	CspErrors           []string `json:"csp_errors"`      // internal errors from csp-adapter
	NvError             string   `json:"nv_error"`        // error message for nv to check csp-config
	CspConfigData       string   `json:"csp_config_data"` // raw csp-config data
	CspConfigFrom       string   `json:"csp_config_from"` // "master"/"joint"/ "": where is csp-config data from
	JointReportUsage    bool     `json:"joint_report_usage"`
	AdapterVersions     string   `json:"adapter_versions"`
	MeteringArchiveData string   `json:"metering_archive_data"` // raw metering-archive data
}

type RESTFedCspUsage struct {
	TotalNodes   int                    `json:"total_nodes"`             // nodes of all reachable cluster(s) in the nv setup
	Unreachable  int                    `json:"unreachable_downstreams"` // unreachable downstream clusters
	CspUsages    map[string]int         `json:"csp_usages"`              // key: cspType, value: nodes of all reachable cluster(s) with the same cspType
	MemberUsages []*RESTClusterCspUsage `json:"member_usages"`           // list of all reachable clusters' usages, only available on master cluster
}

type RESTNvUsage struct {
	LocalClusterRole  string              `json:"local_clusterd_role"` // "primary", "downstream", "standalone"
	FedUsage          *RESTFedCspUsage    `json:"fed_usage,omitempty"` // list of all reachable clusters' usages, only available on master cluster
	LocalClusterUsage RESTClusterCspUsage `json:"local_cluster_usage"` // local cluster' cspType & usage
	CspConfigFrom     string              `json:"csp_config_from"`     // "master"/"joint"/ "": where is csp-config data from when collecting support config
}

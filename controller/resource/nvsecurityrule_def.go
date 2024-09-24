package resource

import (
	//	"github.com/neuvector/k8s"
	"github.com/neuvector/neuvector/controller/api"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const constApiGroupNV = "neuvector.com"
const NvCrdV1 = "v1"

const NvSecurityRuleName = "nvsecurityrules.neuvector.com"
const NvSecurityRuleVersion = "v1"
const NvSecurityRulePlural = "nvsecurityrules"
const NvSecurityRuleKind = "NvSecurityRule"
const NvSecurityRuleListKind = "NvSecurityRuleList"
const NvSecurityRuleSingular = "nvsecurityrule"
const NvSecurityRuleScope = "Namespaced"

const NvClusterSecurityRuleScope = "Cluster"
const NvClusterSecurityRuleName = "nvclustersecurityrules.neuvector.com"
const NvClusterSecurityRuleVersion = "v1"
const NvClusterSecurityRulePlural = "nvclustersecurityrules"
const NvClusterSecurityRuleKind = "NvClusterSecurityRule"
const NvClusterSecurityRuleListKind = "NvClusterSecurityRuleList"
const NvClusterSecurityRuleSingular = "nvclustersecurityrule"

const NvAdmCtrlSecurityRuleName = "nvadmissioncontrolsecurityrules.neuvector.com"
const NvAdmCtrlSecurityRuleVersion = "v1"
const NvAdmCtrlSecurityRulePlural = "nvadmissioncontrolsecurityrules"
const NvAdmCtrlSecurityRuleKind = "NvAdmissionControlSecurityRule"
const NvAdmCtrlSecurityRuleListKind = "NvAdmissionControlSecurityRuleList"
const NvAdmCtrlSecurityRuleSingular = "nvadmissioncontrolsecurityrule"

const NvDlpSecurityRuleName = "nvdlpsecurityrules.neuvector.com"
const NvDlpSecurityRuleVersion = "v1"
const NvDlpSecurityRulePlural = "nvdlpsecurityrules"
const NvDlpSecurityRuleKind = "NvDlpSecurityRule"
const NvDlpSecurityRuleListKind = "NvDlpSecurityRuleList"
const NvDlpSecurityRuleSingular = "nvdlpsecurityrule"

const NvWafSecurityRuleName = "nvwafsecurityrules.neuvector.com"
const NvWafSecurityRuleVersion = "v1"
const NvWafSecurityRulePlural = "nvwafsecurityrules"
const NvWafSecurityRuleKind = "NvWafSecurityRule"
const NvWafSecurityRuleListKind = "NvWafSecurityRuleList"
const NvWafSecurityRuleSingular = "nvwafsecurityrule"

const NvVulnProfileSecurityRuleName = "nvvulnerabilityprofiles.neuvector.com"
const NvVulnProfileSecurityRuleVersion = "v1"
const NvVulnProfileSecurityRulePlural = "nvvulnerabilityprofiles"
const NvVulnProfileSecurityRuleKind = "NvVulnerabilityProfile"
const NvVulnProfileSecurityRuleListKind = "NvVulnerabilityProfileList"
const NvVulnProfileSecurityRuleSingular = "nvvulnerabilityprofile"

const NvCompProfileSecurityRuleName = "nvcomplianceprofiles.neuvector.com"
const NvCompProfileSecurityRuleVersion = "v1"
const NvCompProfileSecurityRulePlural = "nvcomplianceprofiles"
const NvCompProfileSecurityRuleKind = "NvComplianceProfile"
const NvCompProfileSecurityRuleListKind = "NvComplianceProfileList"
const NvCompProfileSecurityRuleSingular = "nvcomplianceprofile"

// csp billing adapter
const NvCspUsageName = "cspadapterusagerecords.susecloud.net"
const NvCspUsagePlural = "cspadapterusagerecords"
const NvCspUsageKind = "CspAdapterUsageRecord" // CR kind
const NvCspUsageListKind = "CspAdapterUsageRecordList"
const NvCspUsageSingular = "cspadapterusagerecord"

type NvCrdAdmCtrlRule struct {
	ID         uint32                      `json:"id"`        // only set for default rules
	RuleType   string                      `json:"rule_type"` // ValidatingExceptRuleType / ValidatingDenyRuleType (see above)
	RuleMode   string                      `json:"rule_mode"` // "" / share.AdmCtrlModeMonitor / share.AdmCtrlModeProtect
	Comment    string                      `json:"comment"`
	Criteria   []*api.RESTAdmRuleCriterion `json:"criteria,omitempty"`
	Disabled   bool                        `json:"disabled"`
	Containers uint8                       `json:"containers,omitempty"`
}

type NvCrdAdmCtrlConfig struct {
	Enable        bool   `json:"enable"`
	Mode          string `json:"mode"`
	AdmClientMode string `json:"adm_client_mode"`
}

type NvCrdVulnProfileConfig struct {
	Profile *api.RESTVulnerabilityProfileConfig `json:"profile"`
}

type NvCrdCompProfileConfig struct {
	Templates *api.RESTComplianceProfileConfig `json:"profile"`
}

type NvSecurityParse struct {
	TargetName        string
	PolicyModeCfg     *api.RESTServiceConfig
	ProcessProfileCfg *api.RESTProcessProfile
	FileProfileCfg    *api.RESTFileMonitorProfile
	GroupCfgs         []api.RESTCrdGroupConfig
	RuleCfgs          []api.RESTPolicyRuleConfig
	DlpGroupCfg       *api.RESTCrdDlpGroupConfig // per-group's dlp sensor configuration
	WafGroupCfg       *api.RESTCrdWafGroupConfig // per-group's waf sensor configuration
	AdmCtrlCfg        *NvCrdAdmCtrlConfig
	AdmCtrlRulesCfg   map[string][]*NvCrdAdmCtrlRule // map key is "deny" / "exception"
	DlpSensorCfg      *api.RESTDlpSensorConfig       // dlp sensor defined by this crd object
	WafSensorCfg      *api.RESTWafSensorConfig       // waf sensor defined by this crd object
	VulnProfileCfg    *NvCrdVulnProfileConfig        // vulerability profile defined by this crd object
	CompProfileCfg    *NvCrdCompProfileConfig        // compliance profile defined by this crd object
	Uid               string                         // Metadata.Uid from AdmissionReview request
}

type NvSecurityTarget struct {
	PolicyMode *string                `json:"policymode,omitempty"`
	Selector   api.RESTCrdGroupConfig `json:"selector"`
}

type NvSecurityRuleDetail struct {
	Selector     api.RESTCrdGroupConfig `json:"selector"`
	Applications []string               `json:"applications"`
	Ports        string                 `json:"ports"`
	Action       string                 `json:"action"`
	Name         string                 `json:"name"`
	Priority     uint32                 `json:"priority"`
}

type NvSecurityProcessProfile struct {
	Baseline *string `json:"baseline"`
	Mode     *string `json:"mode"` // added in 5.4.1 for process/file profiles
}

type NvSecurityProcessRule struct {
	Name            string `json:"name"`
	Path            string `json:"path"`
	Action          string `json:"action"`
	AllowFileUpdate bool   `json:"allow_update"`
}

type NvSecurityFileRule struct {
	Filter    string   `json:"filter"`
	Recursive bool     `json:"recursive"`
	Behavior  string   `json:"behavior"`
	App       []string `json:"app"`
}

type NvSecurityDlpGroup struct {
	Status   bool                         `json:"status"`
	Settings []api.RESTCrdDlpGroupSetting `json:"settings"`
}

type NvSecurityWafGroup struct {
	Status   bool                         `json:"status"`
	Settings []api.RESTCrdWafGroupSetting `json:"settings"`
}

type NvSecurityRuleSpec struct {
	Target         NvSecurityTarget          `json:"target"`
	IngressRule    []NvSecurityRuleDetail    `json:"ingress"`
	EgressRule     []NvSecurityRuleDetail    `json:"egress"`
	ProcessProfile *NvSecurityProcessProfile `json:"process_profile,omitempty"`
	ProcessRule    []NvSecurityProcessRule   `json:"process"`
	FileRule       []NvSecurityFileRule      `json:"file"`
	DlpGroup       *NvSecurityDlpGroup       `json:"dlp,omitempty"` // per-group's dlp sensor mapping data
	WafGroup       *NvSecurityWafGroup       `json:"waf,omitempty"` // per-group's waf sensor mapping data
}

type NvSecurityRulePartial struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	XXX_unrecognized  []byte `json:"-"`
}

type NvSecurityRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Spec              NvSecurityRuleSpec `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
}

type NvSecurityRuleList struct {
	metav1.TypeMeta  `json:",inline"`
	metav1.ListMeta  `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Items            []NvSecurityRule `json:"items" protobuf:"bytes,2,rep,name=items"`
	XXX_unrecognized []byte           `json:"-"`
}

type NvClusterSecurityRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Spec              NvSecurityRuleSpec `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
}

type NvClusterSecurityRuleList struct {
	metav1.TypeMeta  `json:",inline"`
	metav1.ListMeta  `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Items            []NvClusterSecurityRule `json:"items" protobuf:"bytes,2,rep,name=items"`
	XXX_unrecognized []byte                  `json:"-"`
}

/*
func init() {
	// Register resources with the k8s package.
	k8s.Register("neuvector.com", "v1", "nvsecurityrules", true, &NvSecurityRule{})
	k8s.RegisterList("neuvector.com", "v1", "nvsecurityrules", true, &NvSecurityRuleList{})
	k8s.Register("neuvector.com", "v1", "nvclustersecurityrules", true, &NvClusterSecurityRule{})
	k8s.RegisterList("neuvector.com", "v1", "nvclustersecurityrules", true, &NvClusterSecurityRuleList{})
}
*/

// admission control CRD resourced are non-namespaced
type NvSecurityAdmCtrlConfig struct {
	Enable        *bool   `json:"enable,omitempty"`
	Mode          *string `json:"mode,omitempty"`
	AdmClientMode *string `json:"client_mode" validate:"required"`
}

type NvSecurityAdmCtrlRule struct {
	ID         *uint32                     `json:"id,omitempty"`
	Action     *string                     `json:"action,omitempty"`    // api.ValidatingAllowRuleType / api.ValidatingDenyRuleType
	RuleMode   *string                     `json:"rule_mode,omitempty"` // "" / share.AdmCtrlModeMonitor / share.AdmCtrlModeProtect
	Comment    *string                     `json:"comment,omitempty"`
	Disabled   *bool                       `json:"disabled,omitempty"`
	Containers []string                    `json:"containers,omitempty"`
	Criteria   []*api.RESTAdmRuleCriterion `json:"criteria,omitempty"`
}

type NvSecurityAdmCtrlRules struct {
	Rules []*NvSecurityAdmCtrlRule `json:"rules,omitempty"`
}

type NvSecurityAdmCtrlSpec struct {
	Config *NvSecurityAdmCtrlConfig `json:"config,omitempty"`
	Rules  []*NvSecurityAdmCtrlRule `json:"rules,omitempty"`
}

/*
	type NvAdmCtrlSecurityRule struct {
		metav1.TypeMeta   `json:",inline"`
		metav1.ObjectMeta `json:"metadata,omitempty"`
		Spec              NvSecurityAdmCtrlSpec `json:"spec"`
	}

	type NvAdmCtrlSecurityRuleList struct {
		metav1.TypeMeta  `json:",inline"`
		metav1.ListMeta  `json:"metadata,omitempty"`
		Items            []*NvAdmCtrlSecurityRule `json:"items"`
		XXX_unrecognized []byte                   `json:"-"`
	}
*/
type NvAdmCtrlSecurityRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Spec              NvSecurityAdmCtrlSpec `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
}

type NvAdmCtrlSecurityRuleList struct {
	metav1.TypeMeta  `json:",inline"`
	metav1.ListMeta  `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Items            []NvAdmCtrlSecurityRule `json:"items" protobuf:"bytes,2,rep,name=items"`
	XXX_unrecognized []byte                  `json:"-"`
}

// DLP
type NvSecurityDlpRule struct {
	Name     *string                    `json:"name"`
	Patterns []api.RESTDlpCriteriaEntry `json:"patterns"`
}

type NvSecurityDlpSensor struct {
	Name     string               `json:"name"`
	Comment  *string              `json:"comment"`
	RuleList []*NvSecurityDlpRule `json:"rules"`
}

type NvSecurityDlpSpec struct {
	Sensor *NvSecurityDlpSensor `json:"sensor"`
}

type NvDlpSecurityRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Spec              NvSecurityDlpSpec `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
}

type NvDlpSecurityRuleList struct {
	metav1.TypeMeta  `json:",inline"`
	metav1.ListMeta  `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Items            []NvDlpSecurityRule `json:"items" protobuf:"bytes,2,rep,name=items"`
	XXX_unrecognized []byte              `json:"-"`
}

// WAF
type NvSecurityWafRule struct {
	Name     *string                    `json:"name"`
	Patterns []api.RESTWafCriteriaEntry `json:"patterns"`
}

type NvSecurityWafSensor struct {
	Name     string               `json:"name"`
	Comment  *string              `json:"comment"`
	RuleList []*NvSecurityWafRule `json:"rules"`
}

type NvSecurityWafSpec struct {
	Sensor *NvSecurityWafSensor `json:"sensor"`
}

type NvWafSecurityRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Spec              NvSecurityWafSpec `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
}

type NvWafSecurityRuleList struct {
	metav1.TypeMeta  `json:",inline"`
	metav1.ListMeta  `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Items            []NvWafSecurityRule `json:"items" protobuf:"bytes,2,rep,name=items"`
	XXX_unrecognized []byte              `json:"-"`
}

// vulnerability profile
type NvSecurityVulnProfileEntry struct {
	Name    string   `json:"name"`
	Comment *string  `json:"comment"`
	Days    *uint    `json:"days"` // Only used for 'recent' vuln entries
	Domains []string `json:"domains"`
	Images  []string `json:"images"`
}

type NvSecurityVulnProfile struct {
	Entries []*NvSecurityVulnProfileEntry `json:"entries"`
}

type NvSecurityVulnProfileSpec struct {
	Profile *NvSecurityVulnProfile `json:"profile"`
}

type NvVulnProfileSecurityRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Spec              NvSecurityVulnProfileSpec `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
}

type NvVulnProfileSecurityRuleList struct {
	metav1.TypeMeta  `json:",inline"`
	metav1.ListMeta  `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Items            []NvVulnProfileSecurityRule `json:"items" protobuf:"bytes,2,rep,name=items"`
	XXX_unrecognized []byte                      `json:"-"`
}

// compliance profile
type NvSecurityCompTemplates struct {
	DisableSystem bool                              `json:"disable_system"`
	Entries       []*api.RESTComplianceProfileEntry `json:"entries"`
}

type NvSecurityCompProfileSpec struct {
	Templates *NvSecurityCompTemplates `json:"templates,omitempty"`
}

type NvCompProfileSecurityRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Spec              NvSecurityCompProfileSpec `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
}

type NvCompProfileSecurityRuleList struct {
	metav1.TypeMeta  `json:",inline"`
	metav1.ListMeta  `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Items            []NvCompProfileSecurityRule `json:"items" protobuf:"bytes,2,rep,name=items"`
	XXX_unrecognized []byte                      `json:"-"`
}

// csp billing adapter integration
type NvCspUsage struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	ManagedNodeCount  int    `json:"managed_node_count"` // sum of all reachable clusters' nodes count. 0 means "do not report to CSP API"
	ReportingTime     string `json:"reporting_time"`
	BaseProduct       string `json:"base_product"`
	XXX_unrecognized  []byte `json:"-"`
}

type NvCspUsageList struct {
	metav1.TypeMeta  `json:",inline"`
	metav1.ListMeta  `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Items            []NvCspUsage `json:"items" protobuf:"bytes,2,rep,name=items"`
	XXX_unrecognized []byte       `json:"-"`
}

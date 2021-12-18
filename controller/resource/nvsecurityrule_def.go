package resource

import (
	//	"github.com/ericchiang/k8s"
	metav1 "github.com/ericchiang/k8s/apis/meta/v1"
	"github.com/neuvector/neuvector/controller/api"
)

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

const NvWafSecurityRuleName = "nvwafsecurityrules.neuvector.com"
const NvWafSecurityRuleVersion = "v1"
const NvWafSecurityRulePlural = "nvwafsecurityrules"
const NvWafSecurityRuleKind = "NvWafSecurityRule"
const NvWafSecurityRuleListKind = "NvWafSecurityRuleList"
const NvWafSecurityRuleSingular = "nvwafsecurityrule"

type NvCrdAdmCtrlRule struct {
	ID       uint32                      `json:"id"`        // only set for default rules
	RuleType string                      `json:"rule_type"` // ValidatingExceptRuleType / ValidatingDenyRuleType (see above)
	Comment  string                      `json:"comment"`
	Criteria []*api.RESTAdmRuleCriterion `json:"criteria,omitempty"`
	Disabled bool                        `json:"disabled"`
}

type NvCrdAdmCtrlConfig struct {
	Enable        bool   `json:"enable"`
	Mode          string `json:"mode"`
	AdmClientMode string `json:"adm_client_mode"`
}

type NvSecurityParse struct {
	TargetName        string
	PolicyModeCfg     *api.RESTServiceConfig
	ProcessProfileCfg *api.RESTProcessProfile
	FileProfileCfg    *api.RESTFileMonitorProfile
	GroupCfgs         []api.RESTCrdGroupConfig
	RuleCfgs          []api.RESTPolicyRuleConfig
	WafGroupCfg       *api.RESTCrdWafGroupConfig // per-group's waf sensor configuration
	AdmCtrlCfg        *NvCrdAdmCtrlConfig
	AdmCtrlRulesCfg   map[string][]*NvCrdAdmCtrlRule // map key is "deny" / "exception"
	WafSensorCfg      *api.RESTWafSensorConfig       // waf sensor defined by this crd object
}

type NvSecurityTarget struct {
	PolicyMode *string                `json:"policymode, omitempty"`
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

type NvSecurityWafGroup struct {
	Status   bool                         `json:"status"`
	Settings []api.RESTCrdWafGroupSetting `json:"settings"`
}

type NvSecurityRuleSpec struct {
	Target         NvSecurityTarget          `json:"target"`
	IngressRule    []NvSecurityRuleDetail    `json:"ingress"`
	EgressRule     []NvSecurityRuleDetail    `json:"egress"`
	ProcessProfile *NvSecurityProcessProfile `json:"process_profile"`
	ProcessRule    []NvSecurityProcessRule   `json:"process"`
	FileRule       []NvSecurityFileRule      `json:"file"`
	WafGroup       *NvSecurityWafGroup       `json:"waf"` // per-group's waf sensor mapping data
}

type NvSecurityRulePartial struct {
	Kind             *string            `json:"kind,omitempty"`
	ApiVersion       *string            `json:"apiVersion,omitempty"`
	Metadata         *metav1.ObjectMeta `json:"metadata"`
	XXX_unrecognized []byte             `json:"-"`
}

type NvSecurityRule struct {
	Kind       *string            `json:"kind,omitempty"`
	ApiVersion *string            `json:"apiVersion,omitempty"`
	Metadata   *metav1.ObjectMeta `json:"metadata"`
	Spec       NvSecurityRuleSpec `json:"spec"`
}

type NvSecurityRuleList struct {
	Kind             *string           `json:"kind,omitempty"`
	ApiVersion       *string           `json:"apiVersion,omitempty"`
	Metadata         *metav1.ListMeta  `json:"metadata"`
	Items            []*NvSecurityRule `json:"items"`
	XXX_unrecognized []byte            `json:"-"`
}

type NvClusterSecurityRule struct {
	Kind       *string            `json:"kind,omitempty"`
	ApiVersion *string            `json:"apiVersion,omitempty"`
	Metadata   *metav1.ObjectMeta `json:"metadata"`
	Spec       NvSecurityRuleSpec `json:"spec"`
}

type NvClusterSecurityRuleList struct {
	Kind             *string                  `json:"kind,omitempty"`
	ApiVersion       *string                  `json:"apiVersion,omitempty"`
	Metadata         *metav1.ListMeta         `json:"metadata"`
	Items            []*NvClusterSecurityRule `json:"items"`
	XXX_unrecognized []byte                   `json:"-"`
}

func (m *NvSecurityRule) GetMetadata() *metav1.ObjectMeta {
	return m.Metadata
}

func (m *NvSecurityRuleList) GetMetadata() *metav1.ListMeta {
	return m.Metadata
}

func (m *NvClusterSecurityRule) GetMetadata() *metav1.ObjectMeta {
	return m.Metadata
}

func (m *NvClusterSecurityRuleList) GetMetadata() *metav1.ListMeta {
	return m.Metadata
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
	ID       *uint32                     `json:"id,omitempty"`
	Action   *string                     `json:"action,omitempty"` // api.ValidatingAllowRuleType / api.ValidatingDenyRuleType
	Comment  *string                     `json:"comment,omitempty"`
	Disabled *bool                       `json:"disabled,omitempty"`
	Criteria []*api.RESTAdmRuleCriterion `json:"criteria,omitempty"`
}

type NvSecurityAdmCtrlRules struct {
	Rules []*NvSecurityAdmCtrlRule `json:"rules,omitempty"`
}

type NvSecurityAdmCtrlSpec struct {
	Config *NvSecurityAdmCtrlConfig `json:"config,omitempty"`
	Rules  []*NvSecurityAdmCtrlRule `json:"rules,omitempty"`
}

type NvAdmCtrlSecurityRule struct {
	Kind       *string               `json:"kind,omitempty"`
	ApiVersion *string               `json:"apiVersion,omitempty"`
	Metadata   *metav1.ObjectMeta    `json:"metadata"`
	Spec       NvSecurityAdmCtrlSpec `json:"spec"`
}

type NvAdmCtrlSecurityRuleList struct {
	Kind             *string                  `json:"kind,omitempty"`
	ApiVersion       *string                  `json:"apiVersion,omitempty"`
	Metadata         *metav1.ListMeta         `json:"metadata"`
	Items            []*NvAdmCtrlSecurityRule `json:"items"`
	XXX_unrecognized []byte                   `json:"-"`
}

func (m *NvAdmCtrlSecurityRule) GetMetadata() *metav1.ObjectMeta {
	return m.Metadata
}

func (m *NvAdmCtrlSecurityRuleList) GetMetadata() *metav1.ListMeta {
	return m.Metadata
}

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
	Kind       *string            `json:"kind,omitempty"`
	ApiVersion *string            `json:"apiVersion,omitempty"`
	Metadata   *metav1.ObjectMeta `json:"metadata"`
	Spec       NvSecurityWafSpec  `json:"spec"`
}

type NvWafSecurityRuleList struct {
	Kind             *string              `json:"kind,omitempty"`
	ApiVersion       *string              `json:"apiVersion,omitempty"`
	Metadata         *metav1.ListMeta     `json:"metadata"`
	Items            []*NvWafSecurityRule `json:"items"`
	XXX_unrecognized []byte               `json:"-"`
}

func (m *NvWafSecurityRule) GetMetadata() *metav1.ObjectMeta {
	return m.Metadata
}

func (m *NvWafSecurityRuleList) GetMetadata() *metav1.ListMeta {
	return m.Metadata
}

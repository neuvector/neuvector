package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// response rule

type EventCondition struct {
	CondType  string `json:"type,omitempty"`
	CondValue string `json:"value,omitempty"`
}

// Group-related definition

type DlpGroupSetting struct {
	Name   string `json:"name"`
	Action string `json:"action"`
}

type WafGroupSetting struct {
	Name   string `json:"name"`
	Action string `json:"action"`
}

type CriteriaEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Op    string `json:"op"`
}

type GroupConfig struct {
	OriginalName string          `json:"original_name"`
	Name         string          `json:"name"`
	Comment      string          `json:"comment"`
	NameReferral bool            `json:"name_referral,omitempty"`
	Criteria     []CriteriaEntry `json:"criteria,omitempty"`
	MonMetric    *bool           `json:"mon_metric,omitempty"`
	GrpSessCur   *uint32         `json:"grp_sess_cur,omitempty"`
	GrpSessRate  *uint32         `json:"grp_sess_rate,omitempty"`
	GrpBandWidth *uint32         `json:"grp_band_width,omitempty"`
}

type NvCrdResponseRule struct {
	PolicyName string           `json:"policy_name"`
	Event      string           `json:"event"`
	Group      string           `json:"group,omitempty"`
	Actions    []string         `json:"actions"` // "quarantine" / "suppress-log" / "webhook"
	Comment    string           `json:"comment,omitempty"`
	Disable    bool             `json:"disable,omitempty"`
	Webhooks   []string         `json:"webhooks,omitempty"`
	Conditions []EventCondition `json:"conditions,omitempty"`
}

// NvSecurityRule CRD
type NvSecurityTarget struct {
	PolicyMode *string     `json:"policymode,omitempty"`
	Selector   GroupConfig `json:"selector"`
}

type NvSecurityRuleDetail struct {
	Selector     GroupConfig `json:"selector"`
	Applications []string    `json:"applications"`
	Ports        string      `json:"ports"`
	Action       string      `json:"action"`
	Name         string      `json:"name"`
	Priority     uint32      `json:"priority"`
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
	Status   bool              `json:"status"`
	Settings []DlpGroupSetting `json:"settings"`
}

type NvSecurityWafGroup struct {
	Status   bool              `json:"status"`
	Settings []WafGroupSetting `json:"settings"`
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
	ResponseRule   []*NvCrdResponseRule      `json:"response"`      // response rules for the group
}

// For parsing with NV custom client.
type NvSecurityRulePartial struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	XXX_unrecognized  []byte `json:"-"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:singular="nvsecurityrule",path="nvsecurityrules",scope="Namespaced"
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type NvSecurityRule struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Spec              NvSecurityRuleSpec `json:"spec,omitempty" protobuf:"bytes,2,opt,name=spec"`
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type NvSecurityRuleList struct {
	metav1.TypeMeta  `json:",inline"`
	metav1.ListMeta  `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
	Items            []NvSecurityRule `json:"items" protobuf:"bytes,2,rep,name=items"`
	XXX_unrecognized []byte           `json:"-"`
}

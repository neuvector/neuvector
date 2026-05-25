package v1

import (
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type NvCrdResponseRule struct {
	PolicyName string                     `json:"policy_name"`
	Event      string                     `json:"event"`
	Group      string                     `json:"group,omitempty"`
	Actions    []string                   `json:"actions"` // share.EventActionQuarantine / share.EventActionSuppressLog / share.EventActionWebhook
	Comment    string                     `json:"comment,omitempty"`
	Disable    bool                       `json:"disable,omitempty"`
	Webhooks   []string                   `json:"webhooks,omitempty"`
	Conditions []share.CLUSEventCondition `json:"conditions,omitempty"`
}

// NvSecurityRule CRD
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
	ResponseRule   []*NvCrdResponseRule      `json:"response"`      // response rules for the group
}

// TODO: do we need this?
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

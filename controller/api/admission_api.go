package api

type NvSecurityAdmCtrlRule struct {
	ID              *uint32                 `json:"id,omitempty" yaml:"id,omitempty"`
	ConversionIdRef *uint32                 `json:"conversion_id_ref,omitempty" yaml:"conversion_id_ref,omitempty"` // for KW conversion tool only. ignored in NV rest/crd import
	Action          *string                 `json:"action,omitempty" yaml:"action,omitempty"`                       // api.ValidatingAllowRuleType / api.ValidatingDenyRuleType
	RuleMode        *string                 `json:"rule_mode,omitempty" yaml:"rule_mode,omitempty"`                 // "" / share.AdmCtrlModeMonitor / share.AdmCtrlModeProtect
	Comment         *string                 `json:"comment,omitempty" yaml:"comment,omitempty"`
	Disabled        *bool                   `json:"disabled,omitempty" yaml:"disabled,omitempty"`
	Containers      []string                `json:"containers,omitempty" yaml:"containers,omitempty"`
	Criteria        []*RESTAdmRuleCriterion `json:"criteria,omitempty" yaml:"criteria,omitempty"`
}

type NvSecurityAdmCtrlRules struct {
	Rules []*NvSecurityAdmCtrlRule `json:"rules,omitempty"`
}

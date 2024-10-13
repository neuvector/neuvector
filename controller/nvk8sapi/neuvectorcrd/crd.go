package nvcrd

import (
	"github.com/neuvector/k8s"
	log "github.com/sirupsen/logrus"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextv1b1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1" // apiextensions.k8s.io/v1beta1 API version of CustomResourceDefinition is no longer served as of k8s v1.22
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/cache"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	admission "github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/controller/rest"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/utils"
)

type nvCrdSchmaBuilder struct {
	schemaTypeArray   string
	schemaTypeBoolean string
	schemaTypeInteger string
	schemaTypeObject  string
	schemaTypeString  string
	enumMap           map[string][]byte // all constant allowed by schema
}

func (b *nvCrdSchmaBuilder) Init() {
	b.schemaTypeArray = "array"
	b.schemaTypeBoolean = "boolean"
	b.schemaTypeInteger = "integer"
	b.schemaTypeObject = "object"
	b.schemaTypeString = "string"
	enums := []string{
		share.AdmCtrlModeMonitor, share.AdmCtrlModeProtect, "",
		share.AdmClientModeSvc, share.AdmClientModeUrl,
		share.AdmCtrlActionAllow, share.AdmCtrlActionDeny,
		share.PolicyModeLearn, share.PolicyModeEvaluate, share.PolicyModeEnforce, share.PolicyModeUnavailable,
		share.ProfileBasic, share.ProfileZeroDrift, share.ProfileDefault_UNUSED, share.ProfileShield_UNUSED,
		share.FileAccessBehaviorMonitor, share.FileAccessBehaviorBlock,
		share.DlpPatternContextURI, share.DlpPatternContextHEAD, share.DlpPatternContextBODY, share.DlpPatternContextPACKET,
		share.CriteriaOpRegex, share.CriteriaOpNotRegex, share.DlpRuleKeyPattern,
		share.AdmCtrlRuleInitContainers, share.AdmCtrlRuleContainers, share.AdmCtrlRuleEphemeralContainers,
	}
	b.enumMap = make(map[string][]byte, len(enums))
	for _, k := range enums {
		b.enumMap[k], _ = json.Marshal(k)
	}
}

func (b *nvCrdSchmaBuilder) buildNvSeurityCrdAppV1B1Schema() apiextv1b1.JSONSchemaProps {
	schema := apiextv1b1.JSONSchemaProps{
		Type: b.schemaTypeArray,
		Items: &apiextv1b1.JSONSchemaPropsOrArray{
			Schema: &apiextv1b1.JSONSchemaProps{
				Type: b.schemaTypeString,
			},
		},
	}

	return schema
}

func (b *nvCrdSchmaBuilder) buildNvSeurityCrdAppV1Schema() apiextv1.JSONSchemaProps {
	schema := apiextv1.JSONSchemaProps{
		Type: b.schemaTypeArray,
		Items: &apiextv1.JSONSchemaPropsOrArray{
			Schema: &apiextv1.JSONSchemaProps{
				Type: b.schemaTypeString,
			},
		},
	}

	return schema
}

func (b *nvCrdSchmaBuilder) buildNvSeurityCrdSelectorV1Schema(owner string) apiextv1.JSONSchemaProps {
	schema := apiextv1.JSONSchemaProps{
		Type:     b.schemaTypeObject,
		Required: []string{"name"},
		Properties: map[string]apiextv1.JSONSchemaProps{
			"name": {
				Type: b.schemaTypeString,
			},
			"original_name": {
				Type: b.schemaTypeString,
			},
			"comment": {
				Type: b.schemaTypeString,
			},
			"criteria": {
				Type: b.schemaTypeArray,
				Items: &apiextv1.JSONSchemaPropsOrArray{
					Schema: &apiextv1.JSONSchemaProps{
						Type:     b.schemaTypeObject,
						Required: []string{"key", "op", "value"},
						Properties: map[string]apiextv1.JSONSchemaProps{
							"key": {
								Type: b.schemaTypeString,
							},
							"op": {
								Type: b.schemaTypeString,
							},
							"value": {
								Type: b.schemaTypeString,
							},
						},
					},
				},
			},
		},
	}
	if owner == "target" {
		schema.Properties["mon_metric"] = apiextv1.JSONSchemaProps{
			Type: b.schemaTypeBoolean,
		}
		intJsonSchemaProps := apiextv1.JSONSchemaProps{
			Type: b.schemaTypeInteger,
		}
		schema.Properties["grp_sess_cur"] = intJsonSchemaProps
		schema.Properties["grp_sess_rate"] = intJsonSchemaProps
		schema.Properties["grp_band_width"] = intJsonSchemaProps
	}

	return schema
}

func (b *nvCrdSchmaBuilder) buildNvSeurityCrdSelectorV1B1Schema(owner string) apiextv1b1.JSONSchemaProps {
	schema := apiextv1b1.JSONSchemaProps{
		Type:     b.schemaTypeObject,
		Required: []string{"name"},
		Properties: map[string]apiextv1b1.JSONSchemaProps{
			"name": {
				Type: b.schemaTypeString,
			},
			"original_name": {
				Type: b.schemaTypeString,
			},
			"comment": {
				Type: b.schemaTypeString,
			},
			"criteria": {
				Type: b.schemaTypeArray,
				Items: &apiextv1b1.JSONSchemaPropsOrArray{
					Schema: &apiextv1b1.JSONSchemaProps{
						Type:     b.schemaTypeObject,
						Required: []string{"key", "op", "value"},
						Properties: map[string]apiextv1b1.JSONSchemaProps{
							"key": {
								Type: b.schemaTypeString,
							},
							"op": {
								Type: b.schemaTypeString,
							},
							"value": {
								Type: b.schemaTypeString,
							},
						},
					},
				},
			},
		},
	}
	if owner == "target" {
		schema.Properties["mon_metric"] = apiextv1b1.JSONSchemaProps{
			Type: b.schemaTypeBoolean,
		}
		intJsonSchemaProps := apiextv1b1.JSONSchemaProps{
			Type: b.schemaTypeInteger,
		}
		schema.Properties["grp_sess_cur"] = intJsonSchemaProps
		schema.Properties["grp_sess_rate"] = intJsonSchemaProps
		schema.Properties["grp_band_width"] = intJsonSchemaProps
	}

	return schema
}

func (b *nvCrdSchmaBuilder) buildNvSeurityCrdPolicyV1Schema(owner string) apiextv1.JSONSchemaProps {
	schema := apiextv1.JSONSchemaProps{
		Type: b.schemaTypeArray,
		Items: &apiextv1.JSONSchemaPropsOrArray{
			Schema: &apiextv1.JSONSchemaProps{
				Type:     b.schemaTypeObject,
				Required: []string{"action", "name", "selector"},
				Properties: map[string]apiextv1.JSONSchemaProps{
					"ports": {
						Type: b.schemaTypeString,
					},
					"priority": {
						Type: b.schemaTypeInteger,
					},
					"action": {
						Type: b.schemaTypeString,
						Enum: []apiextv1.JSON{
							{Raw: b.enumMap[share.PolicyActionAllow]},
							{Raw: b.enumMap[share.PolicyActionDeny]},
						},
					},
					"name": {
						Type: b.schemaTypeString,
					},
					"selector":     b.buildNvSeurityCrdSelectorV1Schema(owner),
					"applications": b.buildNvSeurityCrdAppV1Schema(),
				},
			},
		},
	}

	return schema
}

func (b *nvCrdSchmaBuilder) buildNvSeurityCrdPolicyV1B1Schema(owner string) apiextv1b1.JSONSchemaProps {
	schema := apiextv1b1.JSONSchemaProps{
		Type: b.schemaTypeArray,
		Items: &apiextv1b1.JSONSchemaPropsOrArray{
			Schema: &apiextv1b1.JSONSchemaProps{
				Type:     b.schemaTypeObject,
				Required: []string{"action", "name", "selector"},
				Properties: map[string]apiextv1b1.JSONSchemaProps{
					"ports": {
						Type: b.schemaTypeString,
					},
					"priority": {
						Type: b.schemaTypeInteger,
					},
					"action": {
						Type: b.schemaTypeString,
						Enum: []apiextv1b1.JSON{
							{Raw: b.enumMap[share.PolicyActionAllow]},
							{Raw: b.enumMap[share.PolicyActionDeny]},
						},
					},
					"name": {
						Type: b.schemaTypeString,
					},
					"selector":     b.buildNvSeurityCrdSelectorV1B1Schema(owner),
					"applications": b.buildNvSeurityCrdAppV1B1Schema(),
				},
			},
		},
	}

	return schema
}

func (b *nvCrdSchmaBuilder) buildNvSeurityCrdDlpWafV1B1Schema() apiextv1b1.JSONSchemaProps {
	schema := apiextv1b1.JSONSchemaProps{
		Type: b.schemaTypeObject,
		Properties: map[string]apiextv1b1.JSONSchemaProps{
			"status": {
				Type: b.schemaTypeBoolean,
			},
			"settings": {
				Type: b.schemaTypeArray,
				Items: &apiextv1b1.JSONSchemaPropsOrArray{
					Schema: &apiextv1b1.JSONSchemaProps{
						Type:     b.schemaTypeObject,
						Required: []string{"name", "action"},
						Properties: map[string]apiextv1b1.JSONSchemaProps{
							"name": {
								Type: b.schemaTypeString,
							},
							"action": {
								Type: b.schemaTypeString,
								Enum: []apiextv1b1.JSON{
									{Raw: b.enumMap[share.PolicyActionAllow]},
									{Raw: b.enumMap[share.PolicyActionDeny]},
								},
							},
						},
					},
				},
			},
		},
	}

	return schema
}

func (b *nvCrdSchmaBuilder) buildNvSeurityCrdDlpWafV1Schema() apiextv1.JSONSchemaProps {
	schema := apiextv1.JSONSchemaProps{
		Type: b.schemaTypeObject,
		Properties: map[string]apiextv1.JSONSchemaProps{
			"status": {
				Type: b.schemaTypeBoolean,
			},
			"settings": {
				Type: b.schemaTypeArray,
				Items: &apiextv1.JSONSchemaPropsOrArray{
					Schema: &apiextv1.JSONSchemaProps{
						Type:     b.schemaTypeObject,
						Required: []string{"name", "action"},
						Properties: map[string]apiextv1.JSONSchemaProps{
							"name": {
								Type: b.schemaTypeString,
							},
							"action": {
								Type: b.schemaTypeString,
								Enum: []apiextv1.JSON{
									{Raw: b.enumMap[share.PolicyActionAllow]},
									{Raw: b.enumMap[share.PolicyActionDeny]},
								},
							},
						},
					},
				},
			},
		},
	}

	return schema
}

func (b *nvCrdSchmaBuilder) buildNvSeurityCrdNwPolicyV1Schema() *apiextv1.JSONSchemaProps {
	schema := apiextv1.JSONSchemaProps{
		Type: b.schemaTypeObject,
		Properties: map[string]apiextv1.JSONSchemaProps{
			"spec": {
				Type:     b.schemaTypeObject,
				Required: []string{"target"},
				Properties: map[string]apiextv1.JSONSchemaProps{
					"target": {
						Type:     b.schemaTypeObject,
						Required: []string{"selector"},
						Properties: map[string]apiextv1.JSONSchemaProps{
							"policymode": {
								Type: b.schemaTypeString,
								Enum: []apiextv1.JSON{
									{Raw: b.enumMap[share.PolicyModeLearn]},
									{Raw: b.enumMap[share.PolicyModeEvaluate]},
									{Raw: b.enumMap[share.PolicyModeEnforce]},
									{Raw: b.enumMap[share.PolicyModeUnavailable]},
								},
							},
							"selector": b.buildNvSeurityCrdSelectorV1Schema("target"),
						},
					},
					"ingress": b.buildNvSeurityCrdPolicyV1Schema("ingress"),
					"egress":  b.buildNvSeurityCrdPolicyV1Schema("egress"),
					"process": {
						Type: b.schemaTypeArray,
						Items: &apiextv1.JSONSchemaPropsOrArray{
							Schema: &apiextv1.JSONSchemaProps{
								Type:     b.schemaTypeObject,
								Required: []string{"action"},
								Properties: map[string]apiextv1.JSONSchemaProps{
									"path": {
										Type: b.schemaTypeString,
									},
									"action": {
										Type: b.schemaTypeString,
										Enum: []apiextv1.JSON{
											{Raw: b.enumMap[share.PolicyActionAllow]},
											{Raw: b.enumMap[share.PolicyActionDeny]},
										},
									},
									"name": {
										Type: b.schemaTypeString,
									},
									"allow_update": {
										Type: b.schemaTypeBoolean,
									},
								},
							},
						},
					},
					"process_profile": {
						Type: b.schemaTypeObject,
						Properties: map[string]apiextv1.JSONSchemaProps{
							"baseline": {
								Type: b.schemaTypeString,
								Enum: []apiextv1.JSON{
									{Raw: b.enumMap[share.ProfileBasic]},
									{Raw: b.enumMap[share.ProfileZeroDrift]},
									{Raw: b.enumMap[share.ProfileDefault_UNUSED]},
									{Raw: b.enumMap[share.ProfileShield_UNUSED]},
								},
							},
							"mode": {
								Type: b.schemaTypeString,
								Enum: []apiextv1.JSON{
									{Raw: b.enumMap[share.PolicyModeLearn]},
									{Raw: b.enumMap[share.PolicyModeEvaluate]},
									{Raw: b.enumMap[share.PolicyModeEnforce]},
								},
							},
						},
					},
					"file": {
						Type: b.schemaTypeArray,
						Items: &apiextv1.JSONSchemaPropsOrArray{
							Schema: &apiextv1.JSONSchemaProps{
								Type:     b.schemaTypeObject,
								Required: []string{"behavior", "filter"},
								Properties: map[string]apiextv1.JSONSchemaProps{
									"behavior": {
										Type: b.schemaTypeString,
										Enum: []apiextv1.JSON{
											{Raw: b.enumMap[share.FileAccessBehaviorMonitor]},
											{Raw: b.enumMap[share.FileAccessBehaviorBlock]},
										},
									},
									"filter": {
										Type: b.schemaTypeString,
									},
									"recursive": {
										Type: b.schemaTypeBoolean,
									},
									"app": b.buildNvSeurityCrdAppV1Schema(),
								},
							},
						},
					},
					"dlp": b.buildNvSeurityCrdDlpWafV1Schema(),
					"waf": b.buildNvSeurityCrdDlpWafV1Schema(),
				},
			},
		},
	}

	return &schema
}

func (b *nvCrdSchmaBuilder) buildNvSeurityCrdNwPolicyV1B1Schema() *apiextv1b1.JSONSchemaProps {
	schema := apiextv1b1.JSONSchemaProps{
		Type: b.schemaTypeObject,
		Properties: map[string]apiextv1b1.JSONSchemaProps{
			"spec": {
				Type:     b.schemaTypeObject,
				Required: []string{"target"},
				Properties: map[string]apiextv1b1.JSONSchemaProps{
					"target": {
						Type:     b.schemaTypeObject,
						Required: []string{"selector"},
						Properties: map[string]apiextv1b1.JSONSchemaProps{
							"policymode": {
								Type: b.schemaTypeString,
								Enum: []apiextv1b1.JSON{
									{Raw: b.enumMap[share.PolicyModeLearn]},
									{Raw: b.enumMap[share.PolicyModeEvaluate]},
									{Raw: b.enumMap[share.PolicyModeEnforce]},
									{Raw: b.enumMap[share.PolicyModeUnavailable]},
								},
							},
							"selector": b.buildNvSeurityCrdSelectorV1B1Schema("target"),
						},
					},
					"ingress": b.buildNvSeurityCrdPolicyV1B1Schema("ingress"),
					"egress":  b.buildNvSeurityCrdPolicyV1B1Schema("egress"),
					"process": {
						Type: b.schemaTypeArray,
						Items: &apiextv1b1.JSONSchemaPropsOrArray{
							Schema: &apiextv1b1.JSONSchemaProps{
								Type:     b.schemaTypeObject,
								Required: []string{"action"},
								Properties: map[string]apiextv1b1.JSONSchemaProps{
									"path": {
										Type: b.schemaTypeString,
									},
									"action": {
										Type: b.schemaTypeString,
										Enum: []apiextv1b1.JSON{
											{Raw: b.enumMap[share.PolicyActionAllow]},
											{Raw: b.enumMap[share.PolicyActionDeny]},
										},
									},
									"name": {
										Type: b.schemaTypeString,
									},
									"allow_update": {
										Type: b.schemaTypeBoolean,
									},
								},
							},
						},
					},
					"process_profile": {
						Type: b.schemaTypeObject,
						Properties: map[string]apiextv1b1.JSONSchemaProps{
							"baseline": {
								Type: b.schemaTypeString,
								Enum: []apiextv1b1.JSON{
									{Raw: b.enumMap[share.ProfileBasic]},
									{Raw: b.enumMap[share.ProfileZeroDrift]},
									{Raw: b.enumMap[share.ProfileDefault_UNUSED]},
									{Raw: b.enumMap[share.ProfileShield_UNUSED]},
								},
							},
							"mode": {
								Type: b.schemaTypeString,
								Enum: []apiextv1b1.JSON{
									{Raw: b.enumMap[share.PolicyModeLearn]},
									{Raw: b.enumMap[share.PolicyModeEvaluate]},
									{Raw: b.enumMap[share.PolicyModeEnforce]},
								},
							},
						},
					},
					"file": {
						Type: b.schemaTypeArray,
						Items: &apiextv1b1.JSONSchemaPropsOrArray{
							Schema: &apiextv1b1.JSONSchemaProps{
								Type:     b.schemaTypeObject,
								Required: []string{"behavior", "filter"},
								Properties: map[string]apiextv1b1.JSONSchemaProps{
									"behavior": {
										Type: b.schemaTypeString,
										Enum: []apiextv1b1.JSON{
											{Raw: b.enumMap[share.FileAccessBehaviorMonitor]},
											{Raw: b.enumMap[share.FileAccessBehaviorBlock]},
										},
									},
									"filter": {
										Type: b.schemaTypeString,
									},
									"recursive": {
										Type: b.schemaTypeBoolean,
									},
									"app": b.buildNvSeurityCrdAppV1B1Schema(),
								},
							},
						},
					},
					"dlp": b.buildNvSeurityCrdDlpWafV1B1Schema(),
					"waf": b.buildNvSeurityCrdDlpWafV1B1Schema(),
				},
			},
		},
	}

	return &schema
}

// for k8a 1.19(+)
func (b *nvCrdSchmaBuilder) buildNvSecurityCrdAdmCtrlV1Schema() *apiextv1.JSONSchemaProps {
	schema := apiextv1.JSONSchemaProps{
		Type: b.schemaTypeObject,
		Properties: map[string]apiextv1.JSONSchemaProps{
			"spec": {
				Type:     b.schemaTypeObject,
				Required: []string{},
				Properties: map[string]apiextv1.JSONSchemaProps{
					"config": {
						Type:     b.schemaTypeObject,
						Required: []string{"enable", "mode", "client_mode"},
						Properties: map[string]apiextv1.JSONSchemaProps{
							"enable": {
								Type: b.schemaTypeBoolean,
							},
							"mode": {
								Type: b.schemaTypeString,
								Enum: []apiextv1.JSON{
									{Raw: b.enumMap[share.AdmCtrlModeMonitor]},
									{Raw: b.enumMap[share.AdmCtrlModeProtect]},
								},
							},
							"client_mode": {
								Type: b.schemaTypeString,
								Enum: []apiextv1.JSON{
									{Raw: b.enumMap[share.AdmClientModeSvc]},
									{Raw: b.enumMap[share.AdmClientModeUrl]},
								},
							},
						},
					},
					"rules": {
						Type: b.schemaTypeArray,
						Items: &apiextv1.JSONSchemaPropsOrArray{
							Schema: &apiextv1.JSONSchemaProps{
								Type:     b.schemaTypeObject,
								Required: []string{"action", "criteria"},
								Properties: map[string]apiextv1.JSONSchemaProps{
									"id": {
										Type: b.schemaTypeInteger,
									},
									"action": {
										Type: b.schemaTypeString,
										Enum: []apiextv1.JSON{
											{Raw: b.enumMap[share.AdmCtrlActionAllow]},
											{Raw: b.enumMap[share.AdmCtrlActionDeny]},
										},
									},
									"comment": {
										Type: b.schemaTypeString,
									},
									"disabled": {
										Type: b.schemaTypeBoolean,
									},
									"rule_mode": {
										Type: b.schemaTypeString,
										Enum: []apiextv1.JSON{
											{Raw: b.enumMap[""]},
											{Raw: b.enumMap[share.AdmCtrlModeMonitor]},
											{Raw: b.enumMap[share.AdmCtrlModeProtect]},
										},
									},
									"containers": {
										Type: b.schemaTypeArray,
										Items: &apiextv1.JSONSchemaPropsOrArray{
											Schema: &apiextv1.JSONSchemaProps{
												Type: b.schemaTypeString,
												Enum: []apiextv1.JSON{
													{Raw: b.enumMap[share.AdmCtrlRuleInitContainers]},
													{Raw: b.enumMap[share.AdmCtrlRuleContainers]},
													{Raw: b.enumMap[share.AdmCtrlRuleEphemeralContainers]},
												},
											},
										},
									},
									"criteria": {
										Type: b.schemaTypeArray,
										Items: &apiextv1.JSONSchemaPropsOrArray{
											Schema: &apiextv1.JSONSchemaProps{
												Type:     b.schemaTypeObject,
												Required: []string{"name", "op", "value"},
												Properties: map[string]apiextv1.JSONSchemaProps{
													"name": {
														Type: b.schemaTypeString,
													},
													"op": {
														Type: b.schemaTypeString,
													},
													"value": {
														Type: b.schemaTypeString,
													},
													"type": {
														Type: b.schemaTypeString,
													},
													"template_kind": {
														Type: b.schemaTypeString,
													},
													"path": {
														Type: b.schemaTypeString,
													},
													"value_type": {
														Type: b.schemaTypeString,
													},
													"sub_criteria": {
														Type: b.schemaTypeArray,
														Items: &apiextv1.JSONSchemaPropsOrArray{
															Schema: &apiextv1.JSONSchemaProps{
																Type:     b.schemaTypeObject,
																Required: []string{"name", "op", "value"},
																Properties: map[string]apiextv1.JSONSchemaProps{
																	"name": {
																		Type: b.schemaTypeString,
																	},
																	"op": {
																		Type: b.schemaTypeString,
																	},
																	"value": {
																		Type: b.schemaTypeString,
																	},
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	return &schema
}

// for k8a 1.18(-)
func (b *nvCrdSchmaBuilder) buildNvSecurityCrdAdmCtrlV1B1Schema() *apiextv1b1.JSONSchemaProps {
	schema := apiextv1b1.JSONSchemaProps{
		Type: b.schemaTypeObject,
		Properties: map[string]apiextv1b1.JSONSchemaProps{
			"spec": {
				Type:     b.schemaTypeObject,
				Required: []string{},
				Properties: map[string]apiextv1b1.JSONSchemaProps{
					"config": {
						Type:     b.schemaTypeObject,
						Required: []string{"enable", "mode", "client_mode"},
						Properties: map[string]apiextv1b1.JSONSchemaProps{
							"enable": {
								Type: b.schemaTypeBoolean,
							},
							"mode": {
								Type: b.schemaTypeString,
								Enum: []apiextv1b1.JSON{
									{Raw: b.enumMap[share.AdmCtrlModeMonitor]},
									{Raw: b.enumMap[share.AdmCtrlModeProtect]},
								},
							},
							"client_mode": {
								Type: b.schemaTypeString,
								Enum: []apiextv1b1.JSON{
									{Raw: b.enumMap[share.AdmClientModeSvc]},
									{Raw: b.enumMap[share.AdmClientModeUrl]},
								},
							},
						},
					},
					"rules": {
						Type: b.schemaTypeArray,
						Items: &apiextv1b1.JSONSchemaPropsOrArray{
							Schema: &apiextv1b1.JSONSchemaProps{
								Type:     b.schemaTypeObject,
								Required: []string{"action", "criteria"},
								Properties: map[string]apiextv1b1.JSONSchemaProps{
									"id": {
										Type: b.schemaTypeInteger,
									},
									"action": {
										Type: b.schemaTypeString,
										Enum: []apiextv1b1.JSON{
											{Raw: b.enumMap[share.AdmCtrlActionAllow]},
											{Raw: b.enumMap[share.AdmCtrlActionDeny]},
										},
									},
									"comment": {
										Type: b.schemaTypeString,
									},
									"disabled": {
										Type: b.schemaTypeBoolean,
									},
									"rule_mode": {
										Type: b.schemaTypeString,
										Enum: []apiextv1b1.JSON{
											{Raw: b.enumMap[""]},
											{Raw: b.enumMap[share.AdmCtrlModeMonitor]},
											{Raw: b.enumMap[share.AdmCtrlModeProtect]},
										},
									},
									"containers": {
										Type: b.schemaTypeArray,
										Items: &apiextv1b1.JSONSchemaPropsOrArray{
											Schema: &apiextv1b1.JSONSchemaProps{
												Type: b.schemaTypeString,
												Enum: []apiextv1b1.JSON{
													{Raw: b.enumMap[share.AdmCtrlRuleInitContainers]},
													{Raw: b.enumMap[share.AdmCtrlRuleContainers]},
													{Raw: b.enumMap[share.AdmCtrlRuleEphemeralContainers]},
												},
											},
										},
									},
									"criteria": {
										Type: b.schemaTypeArray,
										Items: &apiextv1b1.JSONSchemaPropsOrArray{
											Schema: &apiextv1b1.JSONSchemaProps{
												Type:     b.schemaTypeObject,
												Required: []string{"name", "op", "value"},
												Properties: map[string]apiextv1b1.JSONSchemaProps{
													"name": {
														Type: b.schemaTypeString,
													},
													"op": {
														Type: b.schemaTypeString,
													},
													"value": {
														Type: b.schemaTypeString,
													},
													"type": {
														Type: b.schemaTypeString,
													},
													"template_kind": {
														Type: b.schemaTypeString,
													},
													"path": {
														Type: b.schemaTypeString,
													},
													"value_type": {
														Type: b.schemaTypeString,
													},
													"sub_criteria": {
														Type: b.schemaTypeArray,
														Items: &apiextv1b1.JSONSchemaPropsOrArray{
															Schema: &apiextv1b1.JSONSchemaProps{
																Type:     b.schemaTypeObject,
																Required: []string{"name", "op", "value"},
																Properties: map[string]apiextv1b1.JSONSchemaProps{
																	"name": {
																		Type: b.schemaTypeString,
																	},
																	"op": {
																		Type: b.schemaTypeString,
																	},
																	"value": {
																		Type: b.schemaTypeString,
																	},
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	return &schema
}

func (b *nvCrdSchmaBuilder) buildNvSecurityCrdDlpWafV1Schema() *apiextv1.JSONSchemaProps {
	schema := apiextv1.JSONSchemaProps{
		Type: b.schemaTypeObject,
		Properties: map[string]apiextv1.JSONSchemaProps{
			"spec": {
				Type:     b.schemaTypeObject,
				Required: []string{"sensor"},
				Properties: map[string]apiextv1.JSONSchemaProps{
					"sensor": {
						Type:     b.schemaTypeObject,
						Required: []string{"name"},
						Properties: map[string]apiextv1.JSONSchemaProps{
							"name": {
								Type: b.schemaTypeString,
							},
							"comment": {
								Type: b.schemaTypeString,
							},
							"rules": {
								Type: b.schemaTypeArray,
								Items: &apiextv1.JSONSchemaPropsOrArray{
									Schema: &apiextv1.JSONSchemaProps{
										Type:     b.schemaTypeObject,
										Required: []string{"name", "patterns"},
										Properties: map[string]apiextv1.JSONSchemaProps{
											"name": {
												Type: b.schemaTypeString,
											},
											"patterns": {
												Type: b.schemaTypeArray,
												Items: &apiextv1.JSONSchemaPropsOrArray{
													Schema: &apiextv1.JSONSchemaProps{
														Type:     b.schemaTypeObject,
														Required: []string{"key", "op", "value", "context"},
														Properties: map[string]apiextv1.JSONSchemaProps{
															"key": {
																Type: b.schemaTypeString,
																Enum: []apiextv1.JSON{
																	{Raw: b.enumMap[share.DlpRuleKeyPattern]},
																},
															},
															"op": {
																Type: b.schemaTypeString,
																Enum: []apiextv1.JSON{
																	{Raw: b.enumMap[share.CriteriaOpRegex]},
																	{Raw: b.enumMap[share.CriteriaOpNotRegex]},
																},
															},
															"value": {
																Type: b.schemaTypeString,
															},
															"context": {
																Type: b.schemaTypeString,
																Enum: []apiextv1.JSON{
																	{Raw: b.enumMap[share.DlpPatternContextURI]},
																	{Raw: b.enumMap[share.DlpPatternContextHEAD]},
																	{Raw: b.enumMap[share.DlpPatternContextBODY]},
																	{Raw: b.enumMap[share.DlpPatternContextPACKET]},
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	return &schema
}

func (b *nvCrdSchmaBuilder) buildNvSecurityCrdVulnProfileV1Schema() *apiextv1.JSONSchemaProps {
	schema := apiextv1.JSONSchemaProps{
		Type: b.schemaTypeObject,
		Properties: map[string]apiextv1.JSONSchemaProps{
			"spec": {
				Type:     b.schemaTypeObject,
				Required: []string{"profile"},
				Properties: map[string]apiextv1.JSONSchemaProps{
					"profile": {
						Type:     b.schemaTypeObject,
						Required: []string{"entries"},
						Properties: map[string]apiextv1.JSONSchemaProps{
							"entries": {
								Type: b.schemaTypeArray,
								Items: &apiextv1.JSONSchemaPropsOrArray{
									Schema: &apiextv1.JSONSchemaProps{
										Type:     b.schemaTypeObject,
										Required: []string{"name"},
										Properties: map[string]apiextv1.JSONSchemaProps{
											"name": {
												Type: b.schemaTypeString,
											},
											"comment": {
												Type: b.schemaTypeString,
											},
											"days": {
												Type: b.schemaTypeInteger,
											},
											"domains": {
												Type: b.schemaTypeArray,
												Items: &apiextv1.JSONSchemaPropsOrArray{
													Schema: &apiextv1.JSONSchemaProps{
														Type: b.schemaTypeString,
													},
												},
											},
											"images": {
												Type: b.schemaTypeArray,
												Items: &apiextv1.JSONSchemaPropsOrArray{
													Schema: &apiextv1.JSONSchemaProps{
														Type: b.schemaTypeString,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	return &schema
}

/*
	func (b *nvCrdSchmaBuilder) buildNvSeurityCrdCompAssetV1Schema() *apiextv1.JSONSchemaProps {
		schema := apiextv1.JSONSchemaProps{
			Type:     b.schemaTypeObject,
			Required: []string{"name"},
			Properties: map[string]apiextv1.JSONSchemaProps{
				"name": apiextv1.JSONSchemaProps{
					Type: b.schemaTypeString,
				},
				"disable": apiextv1.JSONSchemaProps{
					Type: b.schemaTypeBoolean,
				},
				"dummy": apiextv1.JSONSchemaProps{
					Type: b.schemaTypeBoolean,
				},
				"labels": apiextv1.JSONSchemaProps{
					Type: b.schemaTypeObject,
					AdditionalProperties: &apiextv1.JSONSchemaPropsOrBool{
						Schema: &apiextv1.JSONSchemaProps{
							Type: b.schemaTypeString,
						},
					},
				},
				"tags": apiextv1.JSONSchemaProps{
					Type: b.schemaTypeArray,
					Items: &apiextv1.JSONSchemaPropsOrArray{
						Schema: &apiextv1.JSONSchemaProps{
							Type: b.schemaTypeString,
						},
					},
				},
			},
		}

		return &schema
	}
*/
func (b *nvCrdSchmaBuilder) buildNvSecurityCrdCompProfileV1Schema() *apiextv1.JSONSchemaProps {
	schema := apiextv1.JSONSchemaProps{
		Type: b.schemaTypeObject,
		Properties: map[string]apiextv1.JSONSchemaProps{
			"spec": {
				Type: b.schemaTypeObject,
				Properties: map[string]apiextv1.JSONSchemaProps{
					"templates": {
						Type:     b.schemaTypeObject,
						Required: []string{"entries"},
						Properties: map[string]apiextv1.JSONSchemaProps{
							"disable_system": {
								Type: b.schemaTypeBoolean,
							},
							"entries": {
								Type: b.schemaTypeArray,
								Items: &apiextv1.JSONSchemaPropsOrArray{
									Schema: &apiextv1.JSONSchemaProps{
										Type:     b.schemaTypeObject,
										Required: []string{"test_number"},
										Properties: map[string]apiextv1.JSONSchemaProps{
											"test_number": {
												Type: b.schemaTypeString,
											},
											"tags": {
												Type: b.schemaTypeArray,
												Items: &apiextv1.JSONSchemaPropsOrArray{
													Schema: &apiextv1.JSONSchemaProps{
														Type: b.schemaTypeString,
													},
												},
											},
										},
									},
								},
							},
						},
					},
					/*
						"assets": apiextv1.JSONSchemaProps{
							Type: b.schemaTypeObject,
							Properties: map[string]apiextv1.JSONSchemaProps{
								"built-in":   b.buildNvSeurityCrdCompAssetV1Schema(),
								"namespaces": b.buildNvSeurityCrdCompAssetV1Schema(),
							},
						},
					*/
				},
			},
		},
	}
	return &schema
}

func (b *nvCrdSchmaBuilder) buildNvCspUsageV1Schema() *apiextv1.JSONSchemaProps {
	schema := apiextv1.JSONSchemaProps{
		Type:     b.schemaTypeObject,
		Required: []string{"managed_node_count", "reporting_time", "base_product"},
		Properties: map[string]apiextv1.JSONSchemaProps{
			"reporting_time": {
				Type: b.schemaTypeString,
			},
			"managed_node_count": {
				Type: b.schemaTypeInteger,
			},
			"base_product": {
				Type: b.schemaTypeString,
			},
		},
	}
	return &schema
}

// for k8a 1.18(-)
func (b *nvCrdSchmaBuilder) buildNvSecurityCrdDlpWafV1B1Schema() *apiextv1b1.JSONSchemaProps {
	schema := apiextv1b1.JSONSchemaProps{
		Type: b.schemaTypeObject,
		Properties: map[string]apiextv1b1.JSONSchemaProps{
			"spec": {
				Type:     b.schemaTypeObject,
				Required: []string{"sensor"},
				Properties: map[string]apiextv1b1.JSONSchemaProps{
					"sensor": {
						Type:     b.schemaTypeObject,
						Required: []string{"name"},
						Properties: map[string]apiextv1b1.JSONSchemaProps{
							"name": {
								Type: b.schemaTypeString,
							},
							"comment": {
								Type: b.schemaTypeString,
							},
							"rules": {
								Type: b.schemaTypeArray,
								Items: &apiextv1b1.JSONSchemaPropsOrArray{
									Schema: &apiextv1b1.JSONSchemaProps{
										Type:     b.schemaTypeObject,
										Required: []string{"name", "patterns"},
										Properties: map[string]apiextv1b1.JSONSchemaProps{
											"name": {
												Type: b.schemaTypeString,
											},
											"patterns": {
												Type: b.schemaTypeArray,
												Items: &apiextv1b1.JSONSchemaPropsOrArray{
													Schema: &apiextv1b1.JSONSchemaProps{
														Type:     b.schemaTypeObject,
														Required: []string{"key", "op", "value", "context"},
														Properties: map[string]apiextv1b1.JSONSchemaProps{
															"key": {
																Type: b.schemaTypeString,
																Enum: []apiextv1b1.JSON{
																	{Raw: b.enumMap[share.DlpRuleKeyPattern]},
																},
															},
															"op": {
																Type: b.schemaTypeString,
																Enum: []apiextv1b1.JSON{
																	{Raw: b.enumMap[share.CriteriaOpRegex]},
																	{Raw: b.enumMap[share.CriteriaOpNotRegex]},
																},
															},
															"value": {
																Type: b.schemaTypeString,
															},
															"context": {
																Type: b.schemaTypeString,
																Enum: []apiextv1b1.JSON{
																	{Raw: b.enumMap[share.DlpPatternContextURI]},
																	{Raw: b.enumMap[share.DlpPatternContextHEAD]},
																	{Raw: b.enumMap[share.DlpPatternContextBODY]},
																	{Raw: b.enumMap[share.DlpPatternContextPACKET]},
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	return &schema
}

func (b *nvCrdSchmaBuilder) buildNvSecurityCrdVulnProfileV1B1Schema() *apiextv1b1.JSONSchemaProps {
	schema := apiextv1b1.JSONSchemaProps{
		Type: b.schemaTypeObject,
		Properties: map[string]apiextv1b1.JSONSchemaProps{
			"spec": {
				Type:     b.schemaTypeObject,
				Required: []string{"profile"},
				Properties: map[string]apiextv1b1.JSONSchemaProps{
					"profile": {
						Type:     b.schemaTypeObject,
						Required: []string{"entries"},
						Properties: map[string]apiextv1b1.JSONSchemaProps{
							"entries": {
								Type: b.schemaTypeArray,
								Items: &apiextv1b1.JSONSchemaPropsOrArray{
									Schema: &apiextv1b1.JSONSchemaProps{
										Type:     b.schemaTypeObject,
										Required: []string{"name"},
										Properties: map[string]apiextv1b1.JSONSchemaProps{
											"name": {
												Type: b.schemaTypeString,
											},
											"comment": {
												Type: b.schemaTypeString,
											},
											"days": {
												Type: b.schemaTypeInteger,
											},
											"domains": {
												Type: b.schemaTypeArray,
												Items: &apiextv1b1.JSONSchemaPropsOrArray{
													Schema: &apiextv1b1.JSONSchemaProps{
														Type: b.schemaTypeString,
													},
												},
											},
											"images": {
												Type: b.schemaTypeArray,
												Items: &apiextv1b1.JSONSchemaPropsOrArray{
													Schema: &apiextv1b1.JSONSchemaProps{
														Type: b.schemaTypeString,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	return &schema
}

/*
	func (b *nvCrdSchmaBuilder) buildNvSeurityCrdCompAssetV1B1Schema() apiextv1b1.JSONSchemaProps {
		schema := apiextv1b1.JSONSchemaProps{
			Type:     b.schemaTypeObject,
			Required: []string{"name"},
			Properties: map[string]*apiextv1b1.JSONSchemaProps{
				"name": apiextv1b1.JSONSchemaProps{
					Type: b.schemaTypeString,
				},
				"disable": apiextv1b1.JSONSchemaProps{
					Type: b.schemaTypeBoolean,
				},
				"dummy": apiextv1b1.JSONSchemaProps{
					Type: b.schemaTypeBoolean,
				},
				"labels": apiextv1b1.JSONSchemaProps{
					Type: b.schemaTypeObject,
					AdditionalProperties: apiextv1b1.JSONSchemaPropsOrBool{
						Schema: &apiextv1b1.JSONSchemaProps{
							Type: b.schemaTypeString,
						},
					},
				},
				"tags": apiextv1b1.JSONSchemaProps{
					Type: b.schemaTypeArray,
					Items: &apiextv1b1.JSONSchemaPropsOrArray{
						Schema: &apiextv1b1.JSONSchemaProps{
							Type: b.schemaTypeString,
						},
					},
				},
			},
		}

		return &schema
	}
*/
func (b *nvCrdSchmaBuilder) buildNvSecurityCrdCompProfileV1B1Schema() *apiextv1b1.JSONSchemaProps {
	schema := apiextv1b1.JSONSchemaProps{
		Type: b.schemaTypeObject,
		Properties: map[string]apiextv1b1.JSONSchemaProps{
			"spec": {
				Type: b.schemaTypeObject,
				Properties: map[string]apiextv1b1.JSONSchemaProps{
					"templates": {
						Type:     b.schemaTypeObject,
						Required: []string{"entries"},
						Properties: map[string]apiextv1b1.JSONSchemaProps{
							"disable_system": {
								Type: b.schemaTypeBoolean,
							},
							"entries": {
								Type: b.schemaTypeArray,
								Items: &apiextv1b1.JSONSchemaPropsOrArray{
									Schema: &apiextv1b1.JSONSchemaProps{
										Type:     b.schemaTypeObject,
										Required: []string{"test_number"},
										Properties: map[string]apiextv1b1.JSONSchemaProps{
											"test_number": {
												Type: b.schemaTypeString,
											},
											"tags": {
												Type: b.schemaTypeArray,
												Items: &apiextv1b1.JSONSchemaPropsOrArray{
													Schema: &apiextv1b1.JSONSchemaProps{
														Type: b.schemaTypeString,
													},
												},
											},
										},
									},
								},
							},
						},
					},
					/*
						"assets": apiextv1b1.JSONSchemaProps{
							Type: b.schemaTypeObject,
							Properties: map[string]*apiextv1b1.JSONSchemaProps{
								"built-in":   b.buildNvSeurityCrdCompAssetV1B1Schema(),
								"namespaces": b.buildNvSeurityCrdCompAssetV1B1Schema(),
							},
						},
					*/
				},
			},
		},
	}
	return &schema
}

func (b *nvCrdSchmaBuilder) buildNvCspUsageV1B1Schema() *apiextv1b1.JSONSchemaProps {
	schema := apiextv1b1.JSONSchemaProps{
		Type:     b.schemaTypeObject,
		Required: []string{"managed_node_count", "reporting_time", "base_product"},
		Properties: map[string]apiextv1b1.JSONSchemaProps{
			"reporting_time": {
				Type: b.schemaTypeString,
			},
			"managed_node_count": {
				Type: b.schemaTypeInteger,
			},
			"base_product": {
				Type: b.schemaTypeString,
			},
		},
	}
	return &schema
}

func (b *nvCrdSchmaBuilder) buildNvSecurityCrdByApiExtV1(nvCrdMetaName string, version string) apiextv1.CustomResourceDefinitionVersion {

	v1 := apiextv1.CustomResourceDefinitionVersion{
		Name:    version,
		Served:  true,
		Storage: true,
		Schema:  &apiextv1.CustomResourceValidation{},
	}
	switch nvCrdMetaName {
	case resource.NvSecurityRuleName, resource.NvClusterSecurityRuleName:
		v1.Schema.OpenAPIV3Schema = b.buildNvSeurityCrdNwPolicyV1Schema()
	case resource.NvAdmCtrlSecurityRuleName:
		v1.Schema.OpenAPIV3Schema = b.buildNvSecurityCrdAdmCtrlV1Schema()
	case resource.NvDlpSecurityRuleName, resource.NvWafSecurityRuleName:
		v1.Schema.OpenAPIV3Schema = b.buildNvSecurityCrdDlpWafV1Schema()
	case resource.NvVulnProfileSecurityRuleName:
		v1.Schema.OpenAPIV3Schema = b.buildNvSecurityCrdVulnProfileV1Schema()
	case resource.NvCompProfileSecurityRuleName:
		v1.Schema.OpenAPIV3Schema = b.buildNvSecurityCrdCompProfileV1Schema()
	case resource.NvCspUsageName:
		v1.Schema.OpenAPIV3Schema = b.buildNvCspUsageV1Schema()
	}
	return v1
}

func (b *nvCrdSchmaBuilder) buildNvSecurityCrdByApiExtV1B1(nvCrdMetaName string, version string) apiextv1b1.CustomResourceDefinitionVersion {

	v1 := apiextv1b1.CustomResourceDefinitionVersion{
		Name:    version,
		Served:  true,
		Storage: true,
		Schema:  &apiextv1b1.CustomResourceValidation{},
	}
	switch nvCrdMetaName {
	case resource.NvSecurityRuleName, resource.NvClusterSecurityRuleName:
		v1.Schema.OpenAPIV3Schema = b.buildNvSeurityCrdNwPolicyV1B1Schema()
	case resource.NvAdmCtrlSecurityRuleName:
		v1.Schema.OpenAPIV3Schema = b.buildNvSecurityCrdAdmCtrlV1B1Schema()
	case resource.NvDlpSecurityRuleName, resource.NvWafSecurityRuleName:
		v1.Schema.OpenAPIV3Schema = b.buildNvSecurityCrdDlpWafV1B1Schema()
	case resource.NvVulnProfileSecurityRuleName:
		v1.Schema.OpenAPIV3Schema = b.buildNvSecurityCrdVulnProfileV1B1Schema()
	case resource.NvCompProfileSecurityRuleName:
		v1.Schema.OpenAPIV3Schema = b.buildNvSecurityCrdCompProfileV1B1Schema()
	case resource.NvCspUsageName:
		v1.Schema.OpenAPIV3Schema = b.buildNvCspUsageV1B1Schema()
	}
	return v1
}

// create the CustomResourceDefinition resource(schema) that is listed by "kubectl get CustomResourceDefinition"
func createK8sCrdSchema(crdInfo *resource.NvCrdInfo) error {
	var err error
	var verRead string
	var builder nvCrdSchmaBuilder

	k8sVersionMajor, k8sVersionMinor := resource.GetK8sVersion()
	builder.Init()
	if k8sVersionMajor == 1 && k8sVersionMinor < 19 {
		res := &apiextv1b1.CustomResourceDefinition{
			ObjectMeta: metav1.ObjectMeta{
				Name:            crdInfo.MetaName,
				ResourceVersion: verRead,
			},
			Spec: apiextv1b1.CustomResourceDefinitionSpec{
				Group:   crdInfo.SpecGroup,
				Version: crdInfo.SpecVersion,
				Names: apiextv1b1.CustomResourceDefinitionNames{
					Plural:   crdInfo.SpecNamesPlural,
					Kind:     crdInfo.SpecNamesKind,
					Singular: crdInfo.SpecNamesSingular,
					ListKind: crdInfo.SpecNamesListKind,
				},
				Scope: apiextv1b1.ResourceScope(crdInfo.SpecScope),
			},
		}
		v := builder.buildNvSecurityCrdByApiExtV1B1(crdInfo.MetaName, crdInfo.SpecVersion)
		res.Spec.Validation = v.Schema
		err = global.ORCH.AddResource(resource.RscTypeCrd, res)
	} else {
		res := &apiextv1.CustomResourceDefinition{
			ObjectMeta: metav1.ObjectMeta{
				Name:            crdInfo.MetaName,
				ResourceVersion: verRead,
			},
			Spec: apiextv1.CustomResourceDefinitionSpec{
				Group: crdInfo.SpecGroup,
				Names: apiextv1.CustomResourceDefinitionNames{
					Plural:   crdInfo.SpecNamesPlural,
					Kind:     crdInfo.SpecNamesKind,
					Singular: crdInfo.SpecNamesSingular,
					ListKind: crdInfo.SpecNamesListKind,
				},
				Scope: apiextv1.ResourceScope(crdInfo.SpecScope),
			},
		}
		if len(crdInfo.ShortNames) > 0 {
			res.Spec.Names.ShortNames = crdInfo.ShortNames
		}
		v := builder.buildNvSecurityCrdByApiExtV1(crdInfo.MetaName, crdInfo.SpecVersion)
		res.Spec.Versions = append(res.Spec.Versions, v)
		err = global.ORCH.AddResource(resource.RscTypeCrd, res)
	}

	return err
}

func (b *nvCrdSchmaBuilder) compJSONSchemaV1(srcSchema, destSchema *apiextv1.JSONSchemaProps) bool {
	if srcSchema == nil && destSchema == nil {
		return true
	}
	if srcSchema == nil || destSchema == nil || srcSchema.Type != destSchema.Type ||
		len(srcSchema.Required) != len(destSchema.Required) ||
		len(srcSchema.Enum) != len(destSchema.Enum) ||
		len(srcSchema.Properties) != len(destSchema.Properties) {
		return false
	}

	if srcSchema.Type == b.schemaTypeArray {
		srcItems := srcSchema.Items
		destItems := destSchema.Items
		if !b.compJSONSchemaV1(srcItems.Schema, destItems.Schema) || len(srcItems.JSONSchemas) != len(destItems.JSONSchemas) {
			return false
		}
		for _, srcItem := range srcItems.JSONSchemas {
			found := false
			for _, destItem := range destItems.JSONSchemas {
				if b.compJSONSchemaV1(&srcItem, &destItem) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}

		return true
	}

	srcRequired := srcSchema.Required
	destRequired := destSchema.Required
	sort.Strings(srcRequired)
	sort.Strings(destRequired)
	for i, r := range srcRequired {
		if r != destRequired[i] {
			return false
		}
	}

	for _, srcEnum := range srcSchema.Enum {
		found := false
		for _, destEnum := range destSchema.Enum {
			if len(srcEnum.Raw) == len(destEnum.Raw) && string(srcEnum.Raw) == string(destEnum.Raw) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	srcProps := srcSchema.Properties
	destProps := destSchema.Properties
	for srcName, srcProp := range srcProps {
		if destProp, ok := destProps[srcName]; !ok {
			return false
		} else {
			if same := b.compJSONSchemaV1(&srcProp, &destProp); !same {
				return false
			}
		}
	}

	return true
}

func (b *nvCrdSchmaBuilder) compJSONSchemaV1B1(srcSchema, destSchema *apiextv1b1.JSONSchemaProps) bool {
	if srcSchema == nil && destSchema == nil {
		return true
	}
	if srcSchema == nil || destSchema == nil || srcSchema.Type != destSchema.Type ||
		len(srcSchema.Required) != len(destSchema.Required) ||
		len(srcSchema.Enum) != len(destSchema.Enum) ||
		len(srcSchema.Properties) != len(destSchema.Properties) {
		return false
	}

	if srcSchema.Type == b.schemaTypeArray {
		srcItems := srcSchema.Items
		destItems := destSchema.Items
		if !b.compJSONSchemaV1B1(srcItems.Schema, destItems.Schema) || len(srcItems.JSONSchemas) != len(destItems.JSONSchemas) {
			return false
		}
		for _, srcItem := range srcItems.JSONSchemas {
			found := false
			for _, destItem := range destItems.JSONSchemas {
				if b.compJSONSchemaV1B1(&srcItem, &destItem) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}

		return true
	}

	srcRequired := srcSchema.Required
	destRequired := destSchema.Required
	sort.Strings(srcRequired)
	sort.Strings(destRequired)
	for i, r := range srcRequired {
		if r != destRequired[i] {
			return false
		}
	}

	for _, srcEnum := range srcSchema.Enum {
		found := false
		for _, destEnum := range destSchema.Enum {
			if len(srcEnum.Raw) == len(destEnum.Raw) && string(srcEnum.Raw) == string(destEnum.Raw) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	srcProps := srcSchema.Properties
	destProps := destSchema.Properties
	for srcName, srcProp := range srcProps {
		if destProp, ok := destProps[srcName]; !ok {
			return false
		} else {
			if same := b.compJSONSchemaV1B1(&srcProp, &destProp); !same {
				return false
			}
		}
	}

	return true
}

func isCrdUpToDate(leader bool, crdInfo *resource.NvCrdInfo) (bool, bool, error) {
	crdConfigured := false // crd schema is configured or not
	crdUpToDate := false   // whether the configured crd schema is up-to-date

	obj, err := global.ORCH.GetResource(resource.RscTypeCrd, k8s.AllNamespaces, crdInfo.MetaName)
	if err == nil {
		crdConfigured = true
		if crdRes, ok := obj.(*apiextv1.CustomResourceDefinition); ok {
			crdSpec := crdRes.Spec
			if crdRes.Name == crdInfo.MetaName && len(crdSpec.Versions) > 0 {
				if crdSpec.Group == crdInfo.SpecGroup && string(crdSpec.Scope) == crdInfo.SpecScope {
					shortNames := crdSpec.Names.ShortNames
					if utils.CompareSliceWithoutOrder(shortNames, crdInfo.ShortNames) &&
						crdSpec.Names.Plural == crdInfo.SpecNamesPlural &&
						crdSpec.Names.Singular == crdInfo.SpecNamesSingular &&
						crdSpec.Names.Kind == crdInfo.SpecNamesKind &&
						crdSpec.Names.ListKind == crdInfo.SpecNamesListKind {
						v0 := crdSpec.Versions[0]
						schema := v0.Schema
						if schema != nil && schema.OpenAPIV3Schema != nil && schema.OpenAPIV3Schema.Properties != nil {
							if _, ok := schema.OpenAPIV3Schema.Properties["spec"]; crdInfo.RscType == resource.RscTypeCrdNvCspUsage || ok {
								var builder nvCrdSchmaBuilder
								builder.Init()
								if expected := builder.buildNvSecurityCrdByApiExtV1(crdInfo.MetaName, crdInfo.SpecVersion); expected.Schema != nil {
									if v0.Served == expected.Served && v0.Storage == expected.Storage && v0.Name == expected.Name {
										crdUpToDate = builder.compJSONSchemaV1(expected.Schema.OpenAPIV3Schema, schema.OpenAPIV3Schema)
									}
								}
							}
						}
					}
				}
			}
		} else if crdRes, ok := obj.(*apiextv1b1.CustomResourceDefinition); ok && len(crdRes.Spec.Versions) > 0 {
			crdSpec := crdRes.Spec
			if crdRes.Name == crdInfo.MetaName && len(crdSpec.Versions) > 0 {
				if crdSpec.Group == crdInfo.SpecGroup && string(crdSpec.Scope) == crdInfo.SpecScope {
					if crdSpec.Names.Plural == crdInfo.SpecNamesPlural &&
						crdSpec.Names.Singular == crdInfo.SpecNamesSingular &&
						crdSpec.Names.Kind == crdInfo.SpecNamesKind &&
						crdSpec.Names.ListKind == crdInfo.SpecNamesListKind {
						v0 := crdSpec.Versions[0]
						if v0.Served && v0.Storage {
							schema := crdRes.Spec.Versions[0].Schema
							if schema != nil && schema.OpenAPIV3Schema != nil && schema.OpenAPIV3Schema.Properties != nil {
								if _, ok := schema.OpenAPIV3Schema.Properties["spec"]; crdInfo.RscType == resource.RscTypeCrdNvCspUsage || ok {
									var builder nvCrdSchmaBuilder
									builder.Init()
									if expected := builder.buildNvSecurityCrdByApiExtV1B1(crdInfo.MetaName, crdInfo.SpecVersion); expected.Schema != nil {
										crdUpToDate = builder.compJSONSchemaV1B1(expected.Schema.OpenAPIV3Schema, schema.OpenAPIV3Schema)
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return crdConfigured, crdUpToDate, err
}

// do not update CustomResourceDefinition resource(schema) anymore
func CheckCrdSchema(leader, init, crossCheck bool, cspType share.TCspType) []string {
	var nvCrdInfo []*resource.NvCrdInfo
	nvCrdInfoBasic := []*resource.NvCrdInfo{
		{
			RscType:           resource.RscTypeCrdSecurityRule,
			MetaName:          resource.NvSecurityRuleName,
			SpecScope:         resource.NvSecurityRuleScope,
			SpecGroup:         common.OEMSecurityRuleGroup,
			SpecVersion:       resource.NvSecurityRuleVersion,
			SpecNamesPlural:   resource.NvSecurityRulePlural,
			SpecNamesKind:     resource.NvSecurityRuleKind,
			SpecNamesSingular: resource.NvSecurityRuleSingular,
			SpecNamesListKind: resource.NvSecurityRuleListKind,
			LockKey:           share.CLUSLockPolicyKey,
			KvCrdKind:         resource.NvSecurityRuleKind,
		},
		{
			RscType:           resource.RscTypeCrdClusterSecurityRule,
			MetaName:          resource.NvClusterSecurityRuleName,
			SpecScope:         resource.NvClusterSecurityRuleScope,
			SpecGroup:         common.OEMClusterSecurityRuleGroup,
			SpecVersion:       resource.NvClusterSecurityRuleVersion,
			SpecNamesPlural:   resource.NvClusterSecurityRulePlural,
			SpecNamesKind:     resource.NvClusterSecurityRuleKind,
			SpecNamesSingular: resource.NvClusterSecurityRuleSingular,
			SpecNamesListKind: resource.NvClusterSecurityRuleListKind,
			LockKey:           share.CLUSLockPolicyKey,
			KvCrdKind:         resource.NvSecurityRuleKind,
		},
		{
			RscType:           resource.RscTypeCrdAdmCtrlSecurityRule,
			MetaName:          resource.NvAdmCtrlSecurityRuleName,
			SpecScope:         resource.NvClusterSecurityRuleScope,
			SpecGroup:         common.OEMClusterSecurityRuleGroup,
			SpecVersion:       resource.NvAdmCtrlSecurityRuleVersion,
			SpecNamesPlural:   resource.NvAdmCtrlSecurityRulePlural,
			SpecNamesKind:     resource.NvAdmCtrlSecurityRuleKind,
			SpecNamesSingular: resource.NvAdmCtrlSecurityRuleSingular,
			SpecNamesListKind: resource.NvAdmCtrlSecurityRuleListKind,
			LockKey:           share.CLUSLockAdmCtrlKey,
			KvCrdKind:         resource.NvAdmCtrlSecurityRuleKind,
		},
		{
			RscType:           resource.RscTypeCrdDlpSecurityRule,
			MetaName:          resource.NvDlpSecurityRuleName,
			SpecScope:         resource.NvClusterSecurityRuleScope,
			SpecGroup:         common.OEMClusterSecurityRuleGroup,
			SpecVersion:       resource.NvDlpSecurityRuleVersion,
			SpecNamesPlural:   resource.NvDlpSecurityRulePlural,
			SpecNamesKind:     resource.NvDlpSecurityRuleKind,
			SpecNamesSingular: resource.NvDlpSecurityRuleSingular,
			SpecNamesListKind: resource.NvDlpSecurityRuleListKind,
			LockKey:           share.CLUSLockPolicyKey,
			KvCrdKind:         resource.NvDlpSecurityRuleKind,
		},
		{
			RscType:           resource.RscTypeCrdWafSecurityRule,
			MetaName:          resource.NvWafSecurityRuleName,
			SpecScope:         resource.NvClusterSecurityRuleScope,
			SpecGroup:         common.OEMClusterSecurityRuleGroup,
			SpecVersion:       resource.NvWafSecurityRuleVersion,
			SpecNamesPlural:   resource.NvWafSecurityRulePlural,
			SpecNamesKind:     resource.NvWafSecurityRuleKind,
			SpecNamesSingular: resource.NvWafSecurityRuleSingular,
			SpecNamesListKind: resource.NvWafSecurityRuleListKind,
			LockKey:           share.CLUSLockPolicyKey,
			KvCrdKind:         resource.NvWafSecurityRuleKind,
		},
		{
			RscType:           resource.RscTypeCrdVulnProfile,
			MetaName:          resource.NvVulnProfileSecurityRuleName,
			SpecScope:         resource.NvClusterSecurityRuleScope,
			SpecGroup:         common.OEMClusterSecurityRuleGroup,
			SpecVersion:       resource.NvVulnProfileSecurityRuleVersion,
			SpecNamesPlural:   resource.NvVulnProfileSecurityRulePlural,
			SpecNamesKind:     resource.NvVulnProfileSecurityRuleKind,
			SpecNamesSingular: resource.NvVulnProfileSecurityRuleSingular,
			SpecNamesListKind: resource.NvVulnProfileSecurityRuleListKind,
			LockKey:           share.CLUSLockVulnKey,
			KvCrdKind:         resource.NvVulnProfileSecurityRuleKind,
		},
		{
			RscType:           resource.RscTypeCrdCompProfile,
			MetaName:          resource.NvCompProfileSecurityRuleName,
			SpecScope:         resource.NvClusterSecurityRuleScope,
			SpecGroup:         common.OEMClusterSecurityRuleGroup,
			SpecVersion:       resource.NvCompProfileSecurityRuleVersion,
			SpecNamesPlural:   resource.NvCompProfileSecurityRulePlural,
			SpecNamesKind:     resource.NvCompProfileSecurityRuleKind,
			SpecNamesSingular: resource.NvCompProfileSecurityRuleSingular,
			SpecNamesListKind: resource.NvCompProfileSecurityRuleListKind,
			LockKey:           share.CLUSLockCompKey,
			KvCrdKind:         resource.NvCompProfileSecurityRuleKind,
		},
	}
	if cspType != share.CSP_NONE {
		nvCrdInfo = []*resource.NvCrdInfo{
			{
				RscType:           resource.RscTypeCrdNvCspUsage,
				MetaName:          resource.NvCspUsageName,
				SpecScope:         resource.NvClusterSecurityRuleScope,
				SpecGroup:         "susecloud.net",
				SpecVersion:       "v1",
				SpecNamesPlural:   resource.NvCspUsagePlural,
				SpecNamesKind:     resource.NvCspUsageKind,
				SpecNamesSingular: resource.NvCspUsageSingular,
				SpecNamesListKind: resource.NvCspUsageListKind,
				LockKey:           "",
				KvCrdKind:         resource.NvCspUsageKind,
				ShortNames:        []string{"caur"},
			},
		}
		nvCrdInfo = append(nvCrdInfo, nvCrdInfoBasic...)
	} else {
		nvCrdInfo = nvCrdInfoBasic
	}

	crdOutOfDate := make([]string, 0, len(nvCrdInfo))
	errors := make([]string, 0, len(nvCrdInfo))
	for _, crdInfo := range nvCrdInfo {
		// [2023/04] no more crd schema upgrade.
		crdConfigured, crdUpToDate, err := isCrdUpToDate(leader, crdInfo)
		if crdConfigured {
			if crossCheck && crdInfo.RscType != resource.RscTypeCrdNvCspUsage {
				rest.CrossCheckCrd(crdInfo.SpecNamesKind, crdInfo.RscType, crdInfo.KvCrdKind, crdInfo.LockKey, false)
			}

			if !crdUpToDate {
				crdOutOfDate = append(crdOutOfDate, crdInfo.MetaName)
				continue
			}
		} else if init {
			for retry := 0; retry < 3; retry++ {
				if err = createK8sCrdSchema(crdInfo); err == nil {
					log.WithFields(log.Fields{"crd": crdInfo.MetaName}).Info("configured crd schema in k8s")
					break
				}
			}
		}

		if crdInfo.RscType == resource.RscTypeCrdNvCspUsage {
			clusHelper := kv.GetClusterHelper()
			var fedRole string = api.FedRoleNone
			var masterClusterID string
			if m := clusHelper.GetFedMembership(); m != nil {
				fedRole = m.FedRole
				masterClusterID = m.MasterCluster.ID
			}
			cache.ConfigCspUsages(true, false, fedRole, masterClusterID)
		}

		if err != nil {
			log.WithFields(log.Fields{"crd": crdInfo.MetaName, "init": init, "err": err}).Error("crd schema")
			errors = append(errors, err.Error())
		}
	}
	if len(crdOutOfDate) > 0 {
		err := fmt.Errorf("CRD schema of %s is out of date.", strings.Join(crdOutOfDate, ", "))
		log.WithFields(log.Fields{"err": err}).Warning("crd schema")
		errors = append(errors, err.Error())
	}

	return errors
}

func Init(leader, crossCheck bool, cspType share.TCspType) {
	var crdconf *share.CLUSAdmissionState
	clusHelper := kv.GetClusterHelper()
	crdconf, _ = clusHelper.GetAdmissionStateRev(resource.NvCrdSvcName)
	if crdconf == nil {
		return
	}
	crdconf.CtrlStates[admission.NvAdmValidateType].Enable = true // always enable NV CRD feature

	CheckCrdSchema(leader, true, crossCheck, cspType)

	// register crd admission control(ValidatingWebhookConfiguration neuvector-validating-crd-webhook) to k8s
	k8sResInfo := admission.ValidatingWebhookConfigInfo{
		Name: resource.NvCrdValidatingName,
		WebhooksInfo: []*admission.WebhookInfo{
			{
				Name: resource.NvCrdValidatingWebhookName,
				ClientConfig: admission.ClientConfig{
					ClientMode:  crdconf.AdmClientMode,
					ServiceName: resource.NvCrdSvcName,
					Path:        crdconf.CtrlStates[admission.NvAdmValidateType].Uri,
				},
				FailurePolicy:  resource.Ignore,
				TimeoutSeconds: resource.DefTimeoutSeconds,
			},
		},
	}
	admission.ConfigK8sAdmissionControl(&k8sResInfo, crdconf.CtrlStates[admission.NvAdmValidateType])
}

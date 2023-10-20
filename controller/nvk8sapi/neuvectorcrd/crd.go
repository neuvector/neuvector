package nvcrd

import (
	"github.com/neuvector/k8s"
	apiextv1 "github.com/neuvector/k8s/apis/apiextensions/v1"
	apiextv1b1 "github.com/neuvector/k8s/apis/apiextensions/v1beta1"
	metav1 "github.com/neuvector/k8s/apis/meta/v1"
	log "github.com/sirupsen/logrus"

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
	}
	b.enumMap = make(map[string][]byte, len(enums))
	for _, k := range enums {
		b.enumMap[k], _ = json.Marshal(k)
	}
}

func (b *nvCrdSchmaBuilder) buildNvSeurityCrdAppV1B1Schema() *apiextv1b1.JSONSchemaProps {
	schema := &apiextv1b1.JSONSchemaProps{
		Type: &b.schemaTypeArray,
		Items: &apiextv1b1.JSONSchemaPropsOrArray{
			Schema: &apiextv1b1.JSONSchemaProps{
				Type: &b.schemaTypeString,
			},
		},
	}

	return schema
}

func (b *nvCrdSchmaBuilder) buildNvSeurityCrdAppV1Schema() *apiextv1.JSONSchemaProps {
	schema := &apiextv1.JSONSchemaProps{
		Type: &b.schemaTypeArray,
		Items: &apiextv1.JSONSchemaPropsOrArray{
			Schema: &apiextv1.JSONSchemaProps{
				Type: &b.schemaTypeString,
			},
		},
	}

	return schema
}

func (b *nvCrdSchmaBuilder) buildNvSeurityCrdSelectorV1Schema() *apiextv1.JSONSchemaProps {
	schema := &apiextv1.JSONSchemaProps{
		Type:     &b.schemaTypeObject,
		Required: []string{"name"},
		Properties: map[string]*apiextv1.JSONSchemaProps{
			"name": &apiextv1.JSONSchemaProps{
				Type: &b.schemaTypeString,
			},
			"original_name": &apiextv1.JSONSchemaProps{
				Type: &b.schemaTypeString,
			},
			"comment": &apiextv1.JSONSchemaProps{
				Type: &b.schemaTypeString,
			},
			"criteria": &apiextv1.JSONSchemaProps{
				Type: &b.schemaTypeArray,
				Items: &apiextv1.JSONSchemaPropsOrArray{
					Schema: &apiextv1.JSONSchemaProps{
						Type:     &b.schemaTypeObject,
						Required: []string{"key", "op", "value"},
						Properties: map[string]*apiextv1.JSONSchemaProps{
							"key": &apiextv1.JSONSchemaProps{
								Type: &b.schemaTypeString,
							},
							"op": &apiextv1.JSONSchemaProps{
								Type: &b.schemaTypeString,
							},
							"value": &apiextv1.JSONSchemaProps{
								Type: &b.schemaTypeString,
							},
						},
					},
				},
			},
		},
	}

	return schema
}

func (b *nvCrdSchmaBuilder) buildNvSeurityCrdSelectorV1B1Schema() *apiextv1b1.JSONSchemaProps {
	schema := &apiextv1b1.JSONSchemaProps{
		Type:     &b.schemaTypeObject,
		Required: []string{"name"},
		Properties: map[string]*apiextv1b1.JSONSchemaProps{
			"name": &apiextv1b1.JSONSchemaProps{
				Type: &b.schemaTypeString,
			},
			"original_name": &apiextv1b1.JSONSchemaProps{
				Type: &b.schemaTypeString,
			},
			"comment": &apiextv1b1.JSONSchemaProps{
				Type: &b.schemaTypeString,
			},
			"criteria": &apiextv1b1.JSONSchemaProps{
				Type: &b.schemaTypeArray,
				Items: &apiextv1b1.JSONSchemaPropsOrArray{
					Schema: &apiextv1b1.JSONSchemaProps{
						Type:     &b.schemaTypeObject,
						Required: []string{"key", "op", "value"},
						Properties: map[string]*apiextv1b1.JSONSchemaProps{
							"key": &apiextv1b1.JSONSchemaProps{
								Type: &b.schemaTypeString,
							},
							"op": &apiextv1b1.JSONSchemaProps{
								Type: &b.schemaTypeString,
							},
							"value": &apiextv1b1.JSONSchemaProps{
								Type: &b.schemaTypeString,
							},
						},
					},
				},
			},
		},
	}

	return schema
}

func (b *nvCrdSchmaBuilder) buildNvSeurityCrdPolicyV1Schema() *apiextv1.JSONSchemaProps {
	schema := &apiextv1.JSONSchemaProps{
		Type: &b.schemaTypeArray,
		Items: &apiextv1.JSONSchemaPropsOrArray{
			Schema: &apiextv1.JSONSchemaProps{
				Type:     &b.schemaTypeObject,
				Required: []string{"action", "name", "selector"},
				Properties: map[string]*apiextv1.JSONSchemaProps{
					"ports": &apiextv1.JSONSchemaProps{
						Type: &b.schemaTypeString,
					},
					"priority": &apiextv1.JSONSchemaProps{
						Type: &b.schemaTypeInteger,
					},
					"action": &apiextv1.JSONSchemaProps{
						Type: &b.schemaTypeString,
						Enum: []*apiextv1.JSON{
							&apiextv1.JSON{Raw: b.enumMap[share.PolicyActionAllow]},
							&apiextv1.JSON{Raw: b.enumMap[share.PolicyActionDeny]},
						},
					},
					"name": &apiextv1.JSONSchemaProps{
						Type: &b.schemaTypeString,
					},
					"selector":     b.buildNvSeurityCrdSelectorV1Schema(),
					"applications": b.buildNvSeurityCrdAppV1Schema(),
				},
			},
		},
	}

	return schema
}

func (b *nvCrdSchmaBuilder) buildNvSeurityCrdPolicyV1B1Schema() *apiextv1b1.JSONSchemaProps {
	schema := &apiextv1b1.JSONSchemaProps{
		Type: &b.schemaTypeArray,
		Items: &apiextv1b1.JSONSchemaPropsOrArray{
			Schema: &apiextv1b1.JSONSchemaProps{
				Type:     &b.schemaTypeObject,
				Required: []string{"action", "name", "selector"},
				Properties: map[string]*apiextv1b1.JSONSchemaProps{
					"ports": &apiextv1b1.JSONSchemaProps{
						Type: &b.schemaTypeString,
					},
					"priority": &apiextv1b1.JSONSchemaProps{
						Type: &b.schemaTypeInteger,
					},
					"action": &apiextv1b1.JSONSchemaProps{
						Type: &b.schemaTypeString,
						Enum: []*apiextv1b1.JSON{
							&apiextv1b1.JSON{Raw: b.enumMap[share.PolicyActionAllow]},
							&apiextv1b1.JSON{Raw: b.enumMap[share.PolicyActionDeny]},
						},
					},
					"name": &apiextv1b1.JSONSchemaProps{
						Type: &b.schemaTypeString,
					},
					"selector":     b.buildNvSeurityCrdSelectorV1B1Schema(),
					"applications": b.buildNvSeurityCrdAppV1B1Schema(),
				},
			},
		},
	}

	return schema
}

func (b *nvCrdSchmaBuilder) buildNvSeurityCrdDlpWafV1B1Schema() *apiextv1b1.JSONSchemaProps {
	schema := &apiextv1b1.JSONSchemaProps{
		Type: &b.schemaTypeObject,
		Properties: map[string]*apiextv1b1.JSONSchemaProps{
			"status": &apiextv1b1.JSONSchemaProps{
				Type: &b.schemaTypeBoolean,
			},
			"settings": &apiextv1b1.JSONSchemaProps{
				Type: &b.schemaTypeArray,
				Items: &apiextv1b1.JSONSchemaPropsOrArray{
					Schema: &apiextv1b1.JSONSchemaProps{
						Type:     &b.schemaTypeObject,
						Required: []string{"name", "action"},
						Properties: map[string]*apiextv1b1.JSONSchemaProps{
							"name": &apiextv1b1.JSONSchemaProps{
								Type: &b.schemaTypeString,
							},
							"action": &apiextv1b1.JSONSchemaProps{
								Type: &b.schemaTypeString,
								Enum: []*apiextv1b1.JSON{
									&apiextv1b1.JSON{Raw: b.enumMap[share.PolicyActionAllow]},
									&apiextv1b1.JSON{Raw: b.enumMap[share.PolicyActionDeny]},
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

func (b *nvCrdSchmaBuilder) buildNvSeurityCrdDlpWafV1Schema() *apiextv1.JSONSchemaProps {
	schema := &apiextv1.JSONSchemaProps{
		Type: &b.schemaTypeObject,
		Properties: map[string]*apiextv1.JSONSchemaProps{
			"status": &apiextv1.JSONSchemaProps{
				Type: &b.schemaTypeBoolean,
			},
			"settings": &apiextv1.JSONSchemaProps{
				Type: &b.schemaTypeArray,
				Items: &apiextv1.JSONSchemaPropsOrArray{
					Schema: &apiextv1.JSONSchemaProps{
						Type:     &b.schemaTypeObject,
						Required: []string{"name", "action"},
						Properties: map[string]*apiextv1.JSONSchemaProps{
							"name": &apiextv1.JSONSchemaProps{
								Type: &b.schemaTypeString,
							},
							"action": &apiextv1.JSONSchemaProps{
								Type: &b.schemaTypeString,
								Enum: []*apiextv1.JSON{
									&apiextv1.JSON{Raw: b.enumMap[share.PolicyActionAllow]},
									&apiextv1.JSON{Raw: b.enumMap[share.PolicyActionDeny]},
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
	schema := &apiextv1.JSONSchemaProps{
		Type: &b.schemaTypeObject,
		Properties: map[string]*apiextv1.JSONSchemaProps{
			"spec": &apiextv1.JSONSchemaProps{
				Type:     &b.schemaTypeObject,
				Required: []string{"target"},
				Properties: map[string]*apiextv1.JSONSchemaProps{
					"target": &apiextv1.JSONSchemaProps{
						Type:     &b.schemaTypeObject,
						Required: []string{"selector"},
						Properties: map[string]*apiextv1.JSONSchemaProps{
							"policymode": &apiextv1.JSONSchemaProps{
								Type: &b.schemaTypeString,
								Enum: []*apiextv1.JSON{
									&apiextv1.JSON{Raw: b.enumMap[share.PolicyModeLearn]},
									&apiextv1.JSON{Raw: b.enumMap[share.PolicyModeEvaluate]},
									&apiextv1.JSON{Raw: b.enumMap[share.PolicyModeEnforce]},
									&apiextv1.JSON{Raw: b.enumMap[share.PolicyModeUnavailable]},
								},
							},
							"selector": b.buildNvSeurityCrdSelectorV1Schema(),
						},
					},
					"ingress": b.buildNvSeurityCrdPolicyV1Schema(),
					"egress":  b.buildNvSeurityCrdPolicyV1Schema(),
					"process": &apiextv1.JSONSchemaProps{
						Type: &b.schemaTypeArray,
						Items: &apiextv1.JSONSchemaPropsOrArray{
							Schema: &apiextv1.JSONSchemaProps{
								Type:     &b.schemaTypeObject,
								Required: []string{"action"},
								Properties: map[string]*apiextv1.JSONSchemaProps{
									"path": &apiextv1.JSONSchemaProps{
										Type: &b.schemaTypeString,
									},
									"action": &apiextv1.JSONSchemaProps{
										Type: &b.schemaTypeString,
										Enum: []*apiextv1.JSON{
											&apiextv1.JSON{Raw: b.enumMap[share.PolicyActionAllow]},
											&apiextv1.JSON{Raw: b.enumMap[share.PolicyActionDeny]},
										},
									},
									"name": &apiextv1.JSONSchemaProps{
										Type: &b.schemaTypeString,
									},
									"allow_update": &apiextv1.JSONSchemaProps{
										Type: &b.schemaTypeBoolean,
									},
								},
							},
						},
					},
					"process_profile": &apiextv1.JSONSchemaProps{
						Type: &b.schemaTypeObject,
						Properties: map[string]*apiextv1.JSONSchemaProps{
							"baseline": &apiextv1.JSONSchemaProps{
								Type: &b.schemaTypeString,
								Enum: []*apiextv1.JSON{
									&apiextv1.JSON{Raw: b.enumMap[share.ProfileBasic]},
									&apiextv1.JSON{Raw: b.enumMap[share.ProfileZeroDrift]},
									&apiextv1.JSON{Raw: b.enumMap[share.ProfileDefault_UNUSED]},
									&apiextv1.JSON{Raw: b.enumMap[share.ProfileShield_UNUSED]},
								},
							},
						},
					},
					"file": &apiextv1.JSONSchemaProps{
						Type: &b.schemaTypeArray,
						Items: &apiextv1.JSONSchemaPropsOrArray{
							Schema: &apiextv1.JSONSchemaProps{
								Type:     &b.schemaTypeObject,
								Required: []string{"behavior", "filter"},
								Properties: map[string]*apiextv1.JSONSchemaProps{
									"behavior": &apiextv1.JSONSchemaProps{
										Type: &b.schemaTypeString,
										Enum: []*apiextv1.JSON{
											&apiextv1.JSON{Raw: b.enumMap[share.FileAccessBehaviorMonitor]},
											&apiextv1.JSON{Raw: b.enumMap[share.FileAccessBehaviorBlock]},
										},
									},
									"filter": &apiextv1.JSONSchemaProps{
										Type: &b.schemaTypeString,
									},
									"recursive": &apiextv1.JSONSchemaProps{
										Type: &b.schemaTypeBoolean,
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

	return schema
}

func (b *nvCrdSchmaBuilder) buildNvSeurityCrdNwPolicyV1B1Schema() *apiextv1b1.JSONSchemaProps {
	schema := &apiextv1b1.JSONSchemaProps{
		Type: &b.schemaTypeObject,
		Properties: map[string]*apiextv1b1.JSONSchemaProps{
			"spec": &apiextv1b1.JSONSchemaProps{
				Type:     &b.schemaTypeObject,
				Required: []string{"target"},
				Properties: map[string]*apiextv1b1.JSONSchemaProps{
					"target": &apiextv1b1.JSONSchemaProps{
						Type:     &b.schemaTypeObject,
						Required: []string{"selector"},
						Properties: map[string]*apiextv1b1.JSONSchemaProps{
							"policymode": &apiextv1b1.JSONSchemaProps{
								Type: &b.schemaTypeString,
								Enum: []*apiextv1b1.JSON{
									&apiextv1b1.JSON{Raw: b.enumMap[share.PolicyModeLearn]},
									&apiextv1b1.JSON{Raw: b.enumMap[share.PolicyModeEvaluate]},
									&apiextv1b1.JSON{Raw: b.enumMap[share.PolicyModeEnforce]},
									&apiextv1b1.JSON{Raw: b.enumMap[share.PolicyModeUnavailable]},
								},
							},
							"selector": b.buildNvSeurityCrdSelectorV1B1Schema(),
						},
					},
					"ingress": b.buildNvSeurityCrdPolicyV1B1Schema(),
					"egress":  b.buildNvSeurityCrdPolicyV1B1Schema(),
					"process": &apiextv1b1.JSONSchemaProps{
						Type: &b.schemaTypeArray,
						Items: &apiextv1b1.JSONSchemaPropsOrArray{
							Schema: &apiextv1b1.JSONSchemaProps{
								Type:     &b.schemaTypeObject,
								Required: []string{"action"},
								Properties: map[string]*apiextv1b1.JSONSchemaProps{
									"path": &apiextv1b1.JSONSchemaProps{
										Type: &b.schemaTypeString,
									},
									"action": &apiextv1b1.JSONSchemaProps{
										Type: &b.schemaTypeString,
										Enum: []*apiextv1b1.JSON{
											&apiextv1b1.JSON{Raw: b.enumMap[share.PolicyActionAllow]},
											&apiextv1b1.JSON{Raw: b.enumMap[share.PolicyActionDeny]},
										},
									},
									"name": &apiextv1b1.JSONSchemaProps{
										Type: &b.schemaTypeString,
									},
									"allow_update": &apiextv1b1.JSONSchemaProps{
										Type: &b.schemaTypeBoolean,
									},
								},
							},
						},
					},
					"process_profile": &apiextv1b1.JSONSchemaProps{
						Type: &b.schemaTypeObject,
						Properties: map[string]*apiextv1b1.JSONSchemaProps{
							"baseline": &apiextv1b1.JSONSchemaProps{
								Type: &b.schemaTypeString,
								Enum: []*apiextv1b1.JSON{
									&apiextv1b1.JSON{Raw: b.enumMap[share.ProfileBasic]},
									&apiextv1b1.JSON{Raw: b.enumMap[share.ProfileZeroDrift]},
									&apiextv1b1.JSON{Raw: b.enumMap[share.ProfileDefault_UNUSED]},
									&apiextv1b1.JSON{Raw: b.enumMap[share.ProfileShield_UNUSED]},
								},
							},
						},
					},
					"file": &apiextv1b1.JSONSchemaProps{
						Type: &b.schemaTypeArray,
						Items: &apiextv1b1.JSONSchemaPropsOrArray{
							Schema: &apiextv1b1.JSONSchemaProps{
								Type:     &b.schemaTypeObject,
								Required: []string{"behavior", "filter"},
								Properties: map[string]*apiextv1b1.JSONSchemaProps{
									"behavior": &apiextv1b1.JSONSchemaProps{
										Type: &b.schemaTypeString,
										Enum: []*apiextv1b1.JSON{
											&apiextv1b1.JSON{Raw: b.enumMap[share.FileAccessBehaviorMonitor]},
											&apiextv1b1.JSON{Raw: b.enumMap[share.FileAccessBehaviorBlock]},
										},
									},
									"filter": &apiextv1b1.JSONSchemaProps{
										Type: &b.schemaTypeString,
									},
									"recursive": &apiextv1b1.JSONSchemaProps{
										Type: &b.schemaTypeBoolean,
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

	return schema
}

// for k8a 1.19(+)
func (b *nvCrdSchmaBuilder) buildNvSecurityCrdAdmCtrlV1Schema() *apiextv1.JSONSchemaProps {
	schema := &apiextv1.JSONSchemaProps{
		Type: &b.schemaTypeObject,
		Properties: map[string]*apiextv1.JSONSchemaProps{
			"spec": &apiextv1.JSONSchemaProps{
				Type:     &b.schemaTypeObject,
				Required: []string{},
				Properties: map[string]*apiextv1.JSONSchemaProps{
					"config": &apiextv1.JSONSchemaProps{
						Type:     &b.schemaTypeObject,
						Required: []string{"enable", "mode", "client_mode"},
						Properties: map[string]*apiextv1.JSONSchemaProps{
							"enable": &apiextv1.JSONSchemaProps{
								Type: &b.schemaTypeBoolean,
							},
							"mode": &apiextv1.JSONSchemaProps{
								Type: &b.schemaTypeString,
								Enum: []*apiextv1.JSON{
									&apiextv1.JSON{Raw: b.enumMap[share.AdmCtrlModeMonitor]},
									&apiextv1.JSON{Raw: b.enumMap[share.AdmCtrlModeProtect]},
								},
							},
							"client_mode": &apiextv1.JSONSchemaProps{
								Type: &b.schemaTypeString,
								Enum: []*apiextv1.JSON{
									&apiextv1.JSON{Raw: b.enumMap[share.AdmClientModeSvc]},
									&apiextv1.JSON{Raw: b.enumMap[share.AdmClientModeUrl]},
								},
							},
						},
					},
					"rules": &apiextv1.JSONSchemaProps{
						Type: &b.schemaTypeArray,
						Items: &apiextv1.JSONSchemaPropsOrArray{
							Schema: &apiextv1.JSONSchemaProps{
								Type:     &b.schemaTypeObject,
								Required: []string{"action", "criteria"},
								Properties: map[string]*apiextv1.JSONSchemaProps{
									"id": &apiextv1.JSONSchemaProps{
										Type: &b.schemaTypeInteger,
									},
									"action": &apiextv1.JSONSchemaProps{
										Type: &b.schemaTypeString,
										Enum: []*apiextv1.JSON{
											&apiextv1.JSON{Raw: b.enumMap[share.AdmCtrlActionAllow]},
											&apiextv1.JSON{Raw: b.enumMap[share.AdmCtrlActionDeny]},
										},
									},
									"comment": &apiextv1.JSONSchemaProps{
										Type: &b.schemaTypeString,
									},
									"disabled": &apiextv1.JSONSchemaProps{
										Type: &b.schemaTypeBoolean,
									},
									"rule_mode": &apiextv1.JSONSchemaProps{
										Type: &b.schemaTypeString,
										Enum: []*apiextv1.JSON{
											&apiextv1.JSON{Raw: b.enumMap[""]},
											&apiextv1.JSON{Raw: b.enumMap[share.AdmCtrlModeMonitor]},
											&apiextv1.JSON{Raw: b.enumMap[share.AdmCtrlModeProtect]},
										},
									},
									"criteria": &apiextv1.JSONSchemaProps{
										Type: &b.schemaTypeArray,
										Items: &apiextv1.JSONSchemaPropsOrArray{
											Schema: &apiextv1.JSONSchemaProps{
												Type:     &b.schemaTypeObject,
												Required: []string{"name", "op", "value"},
												Properties: map[string]*apiextv1.JSONSchemaProps{
													"name": &apiextv1.JSONSchemaProps{
														Type: &b.schemaTypeString,
													},
													"op": &apiextv1.JSONSchemaProps{
														Type: &b.schemaTypeString,
													},
													"value": &apiextv1.JSONSchemaProps{
														Type: &b.schemaTypeString,
													},
													"type": &apiextv1.JSONSchemaProps{
														Type: &b.schemaTypeString,
													},
													"template_kind": &apiextv1.JSONSchemaProps{
														Type: &b.schemaTypeString,
													},
													"path": &apiextv1.JSONSchemaProps{
														Type: &b.schemaTypeString,
													},
													"value_type": &apiextv1.JSONSchemaProps{
														Type: &b.schemaTypeString,
													},
													"sub_criteria": &apiextv1.JSONSchemaProps{
														Type: &b.schemaTypeArray,
														Items: &apiextv1.JSONSchemaPropsOrArray{
															Schema: &apiextv1.JSONSchemaProps{
																Type:     &b.schemaTypeObject,
																Required: []string{"name", "op", "value"},
																Properties: map[string]*apiextv1.JSONSchemaProps{
																	"name": &apiextv1.JSONSchemaProps{
																		Type: &b.schemaTypeString,
																	},
																	"op": &apiextv1.JSONSchemaProps{
																		Type: &b.schemaTypeString,
																	},
																	"value": &apiextv1.JSONSchemaProps{
																		Type: &b.schemaTypeString,
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
	return schema
}

// for k8a 1.18(-)
func (b *nvCrdSchmaBuilder) buildNvSecurityCrdAdmCtrlV1B1Schema() *apiextv1b1.JSONSchemaProps {
	schema := &apiextv1b1.JSONSchemaProps{
		Type: &b.schemaTypeObject,
		Properties: map[string]*apiextv1b1.JSONSchemaProps{
			"spec": &apiextv1b1.JSONSchemaProps{
				Type:     &b.schemaTypeObject,
				Required: []string{},
				Properties: map[string]*apiextv1b1.JSONSchemaProps{
					"config": &apiextv1b1.JSONSchemaProps{
						Type:     &b.schemaTypeObject,
						Required: []string{"enable", "mode", "client_mode"},
						Properties: map[string]*apiextv1b1.JSONSchemaProps{
							"enable": &apiextv1b1.JSONSchemaProps{
								Type: &b.schemaTypeBoolean,
							},
							"mode": &apiextv1b1.JSONSchemaProps{
								Type: &b.schemaTypeString,
								Enum: []*apiextv1b1.JSON{
									&apiextv1b1.JSON{Raw: b.enumMap[share.AdmCtrlModeMonitor]},
									&apiextv1b1.JSON{Raw: b.enumMap[share.AdmCtrlModeProtect]},
								},
							},
							"client_mode": &apiextv1b1.JSONSchemaProps{
								Type: &b.schemaTypeString,
								Enum: []*apiextv1b1.JSON{
									&apiextv1b1.JSON{Raw: b.enumMap[share.AdmClientModeSvc]},
									&apiextv1b1.JSON{Raw: b.enumMap[share.AdmClientModeUrl]},
								},
							},
						},
					},
					"rules": &apiextv1b1.JSONSchemaProps{
						Type: &b.schemaTypeArray,
						Items: &apiextv1b1.JSONSchemaPropsOrArray{
							Schema: &apiextv1b1.JSONSchemaProps{
								Type:     &b.schemaTypeObject,
								Required: []string{"action", "criteria"},
								Properties: map[string]*apiextv1b1.JSONSchemaProps{
									"id": &apiextv1b1.JSONSchemaProps{
										Type: &b.schemaTypeInteger,
									},
									"action": &apiextv1b1.JSONSchemaProps{
										Type: &b.schemaTypeString,
										Enum: []*apiextv1b1.JSON{
											&apiextv1b1.JSON{Raw: b.enumMap[share.AdmCtrlActionAllow]},
											&apiextv1b1.JSON{Raw: b.enumMap[share.AdmCtrlActionDeny]},
										},
									},
									"comment": &apiextv1b1.JSONSchemaProps{
										Type: &b.schemaTypeString,
									},
									"disabled": &apiextv1b1.JSONSchemaProps{
										Type: &b.schemaTypeBoolean,
									},
									"rule_mode": &apiextv1b1.JSONSchemaProps{
										Type: &b.schemaTypeString,
										Enum: []*apiextv1b1.JSON{
											&apiextv1b1.JSON{Raw: b.enumMap[""]},
											&apiextv1b1.JSON{Raw: b.enumMap[share.AdmCtrlModeMonitor]},
											&apiextv1b1.JSON{Raw: b.enumMap[share.AdmCtrlModeProtect]},
										},
									},
									"criteria": &apiextv1b1.JSONSchemaProps{
										Type: &b.schemaTypeArray,
										Items: &apiextv1b1.JSONSchemaPropsOrArray{
											Schema: &apiextv1b1.JSONSchemaProps{
												Type:     &b.schemaTypeObject,
												Required: []string{"name", "op", "value"},
												Properties: map[string]*apiextv1b1.JSONSchemaProps{
													"name": &apiextv1b1.JSONSchemaProps{
														Type: &b.schemaTypeString,
													},
													"op": &apiextv1b1.JSONSchemaProps{
														Type: &b.schemaTypeString,
													},
													"value": &apiextv1b1.JSONSchemaProps{
														Type: &b.schemaTypeString,
													},
													"type": &apiextv1b1.JSONSchemaProps{
														Type: &b.schemaTypeString,
													},
													"template_kind": &apiextv1b1.JSONSchemaProps{
														Type: &b.schemaTypeString,
													},
													"path": &apiextv1b1.JSONSchemaProps{
														Type: &b.schemaTypeString,
													},
													"value_type": &apiextv1b1.JSONSchemaProps{
														Type: &b.schemaTypeString,
													},
													"sub_criteria": &apiextv1b1.JSONSchemaProps{
														Type: &b.schemaTypeArray,
														Items: &apiextv1b1.JSONSchemaPropsOrArray{
															Schema: &apiextv1b1.JSONSchemaProps{
																Type:     &b.schemaTypeObject,
																Required: []string{"name", "op", "value"},
																Properties: map[string]*apiextv1b1.JSONSchemaProps{
																	"name": &apiextv1b1.JSONSchemaProps{
																		Type: &b.schemaTypeString,
																	},
																	"op": &apiextv1b1.JSONSchemaProps{
																		Type: &b.schemaTypeString,
																	},
																	"value": &apiextv1b1.JSONSchemaProps{
																		Type: &b.schemaTypeString,
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
	return schema
}

func (b *nvCrdSchmaBuilder) buildNvSecurityCrdDlpWafV1Schema() *apiextv1.JSONSchemaProps {
	schema := &apiextv1.JSONSchemaProps{
		Type: &b.schemaTypeObject,
		Properties: map[string]*apiextv1.JSONSchemaProps{
			"spec": &apiextv1.JSONSchemaProps{
				Type:     &b.schemaTypeObject,
				Required: []string{"sensor"},
				Properties: map[string]*apiextv1.JSONSchemaProps{
					"sensor": &apiextv1.JSONSchemaProps{
						Type:     &b.schemaTypeObject,
						Required: []string{"name"},
						Properties: map[string]*apiextv1.JSONSchemaProps{
							"name": &apiextv1.JSONSchemaProps{
								Type: &b.schemaTypeString,
							},
							"comment": &apiextv1.JSONSchemaProps{
								Type: &b.schemaTypeString,
							},
							"rules": &apiextv1.JSONSchemaProps{
								Type: &b.schemaTypeArray,
								Items: &apiextv1.JSONSchemaPropsOrArray{
									Schema: &apiextv1.JSONSchemaProps{
										Type:     &b.schemaTypeObject,
										Required: []string{"name", "patterns"},
										Properties: map[string]*apiextv1.JSONSchemaProps{
											"name": &apiextv1.JSONSchemaProps{
												Type: &b.schemaTypeString,
											},
											"patterns": &apiextv1.JSONSchemaProps{
												Type: &b.schemaTypeArray,
												Items: &apiextv1.JSONSchemaPropsOrArray{
													Schema: &apiextv1.JSONSchemaProps{
														Type:     &b.schemaTypeObject,
														Required: []string{"key", "op", "value", "context"},
														Properties: map[string]*apiextv1.JSONSchemaProps{
															"key": &apiextv1.JSONSchemaProps{
																Type: &b.schemaTypeString,
																Enum: []*apiextv1.JSON{
																	&apiextv1.JSON{Raw: b.enumMap[share.DlpRuleKeyPattern]},
																},
															},
															"op": &apiextv1.JSONSchemaProps{
																Type: &b.schemaTypeString,
																Enum: []*apiextv1.JSON{
																	&apiextv1.JSON{Raw: b.enumMap[share.CriteriaOpRegex]},
																	&apiextv1.JSON{Raw: b.enumMap[share.CriteriaOpNotRegex]},
																},
															},
															"value": &apiextv1.JSONSchemaProps{
																Type: &b.schemaTypeString,
															},
															"context": &apiextv1.JSONSchemaProps{
																Type: &b.schemaTypeString,
																Enum: []*apiextv1.JSON{
																	&apiextv1.JSON{Raw: b.enumMap[share.DlpPatternContextURI]},
																	&apiextv1.JSON{Raw: b.enumMap[share.DlpPatternContextHEAD]},
																	&apiextv1.JSON{Raw: b.enumMap[share.DlpPatternContextBODY]},
																	&apiextv1.JSON{Raw: b.enumMap[share.DlpPatternContextPACKET]},
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
	return schema
}

func (b *nvCrdSchmaBuilder) buildNvCspUsageV1Schema() *apiextv1.JSONSchemaProps {
	schema := &apiextv1.JSONSchemaProps{
		Type:     &b.schemaTypeObject,
		Required: []string{"managed_node_count", "reporting_time", "base_product"},
		Properties: map[string]*apiextv1.JSONSchemaProps{
			"reporting_time": &apiextv1.JSONSchemaProps{
				Type: &b.schemaTypeString,
			},
			"managed_node_count": &apiextv1.JSONSchemaProps{
				Type: &b.schemaTypeInteger,
			},
			"base_product": &apiextv1.JSONSchemaProps{
				Type: &b.schemaTypeString,
			},
		},
	}
	return schema
}

// for k8a 1.18(-)
func (b *nvCrdSchmaBuilder) buildNvSecurityCrdDlpWafV1B1Schema() *apiextv1b1.JSONSchemaProps {
	schema := &apiextv1b1.JSONSchemaProps{
		Type: &b.schemaTypeObject,
		Properties: map[string]*apiextv1b1.JSONSchemaProps{
			"spec": &apiextv1b1.JSONSchemaProps{
				Type:     &b.schemaTypeObject,
				Required: []string{"sensor"},
				Properties: map[string]*apiextv1b1.JSONSchemaProps{
					"sensor": &apiextv1b1.JSONSchemaProps{
						Type:     &b.schemaTypeObject,
						Required: []string{"name"},
						Properties: map[string]*apiextv1b1.JSONSchemaProps{
							"name": &apiextv1b1.JSONSchemaProps{
								Type: &b.schemaTypeString,
							},
							"comment": &apiextv1b1.JSONSchemaProps{
								Type: &b.schemaTypeString,
							},
							"rules": &apiextv1b1.JSONSchemaProps{
								Type: &b.schemaTypeArray,
								Items: &apiextv1b1.JSONSchemaPropsOrArray{
									Schema: &apiextv1b1.JSONSchemaProps{
										Type:     &b.schemaTypeObject,
										Required: []string{"name", "patterns"},
										Properties: map[string]*apiextv1b1.JSONSchemaProps{
											"name": &apiextv1b1.JSONSchemaProps{
												Type: &b.schemaTypeString,
											},
											"patterns": &apiextv1b1.JSONSchemaProps{
												Type: &b.schemaTypeArray,
												Items: &apiextv1b1.JSONSchemaPropsOrArray{
													Schema: &apiextv1b1.JSONSchemaProps{
														Type:     &b.schemaTypeObject,
														Required: []string{"key", "op", "value", "context"},
														Properties: map[string]*apiextv1b1.JSONSchemaProps{
															"key": &apiextv1b1.JSONSchemaProps{
																Type: &b.schemaTypeString,
																Enum: []*apiextv1b1.JSON{
																	&apiextv1b1.JSON{Raw: b.enumMap[share.DlpRuleKeyPattern]},
																},
															},
															"op": &apiextv1b1.JSONSchemaProps{
																Type: &b.schemaTypeString,
																Enum: []*apiextv1b1.JSON{
																	&apiextv1b1.JSON{Raw: b.enumMap[share.CriteriaOpRegex]},
																	&apiextv1b1.JSON{Raw: b.enumMap[share.CriteriaOpNotRegex]},
																},
															},
															"value": &apiextv1b1.JSONSchemaProps{
																Type: &b.schemaTypeString,
															},
															"context": &apiextv1b1.JSONSchemaProps{
																Type: &b.schemaTypeString,
																Enum: []*apiextv1b1.JSON{
																	&apiextv1b1.JSON{Raw: b.enumMap[share.DlpPatternContextURI]},
																	&apiextv1b1.JSON{Raw: b.enumMap[share.DlpPatternContextHEAD]},
																	&apiextv1b1.JSON{Raw: b.enumMap[share.DlpPatternContextBODY]},
																	&apiextv1b1.JSON{Raw: b.enumMap[share.DlpPatternContextPACKET]},
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
	return schema
}

func (b *nvCrdSchmaBuilder) buildNvCspUsageV1B1Schema() *apiextv1b1.JSONSchemaProps {
	schema := &apiextv1b1.JSONSchemaProps{
		Type:     &b.schemaTypeObject,
		Required: []string{"managed_node_count", "reporting_time", "base_product"},
		Properties: map[string]*apiextv1b1.JSONSchemaProps{
			"reporting_time": &apiextv1b1.JSONSchemaProps{
				Type: &b.schemaTypeString,
			},
			"managed_node_count": &apiextv1b1.JSONSchemaProps{
				Type: &b.schemaTypeInteger,
			},
			"base_product": &apiextv1b1.JSONSchemaProps{
				Type: &b.schemaTypeString,
			},
		},
	}
	return schema
}

func (b *nvCrdSchmaBuilder) buildNvSecurityCrdByApiExtV1(nvCrdMetaName string, version *string) *apiextv1.CustomResourceDefinitionVersion {

	v1 := &apiextv1.CustomResourceDefinitionVersion{
		Name:    version,
		Served:  func() *bool { b := true; return &b }(),
		Storage: func() *bool { b := true; return &b }(),
		Schema:  &apiextv1.CustomResourceValidation{},
	}
	switch nvCrdMetaName {
	case resource.NvSecurityRuleName, resource.NvClusterSecurityRuleName:
		v1.Schema.OpenAPIV3Schema = b.buildNvSeurityCrdNwPolicyV1Schema()
	case resource.NvAdmCtrlSecurityRuleName:
		v1.Schema.OpenAPIV3Schema = b.buildNvSecurityCrdAdmCtrlV1Schema()
	case resource.NvDlpSecurityRuleName, resource.NvWafSecurityRuleName:
		v1.Schema.OpenAPIV3Schema = b.buildNvSecurityCrdDlpWafV1Schema()
	case resource.NvCspUsageName:
		v1.Schema.OpenAPIV3Schema = b.buildNvCspUsageV1Schema()
	}
	return v1
}

func (b *nvCrdSchmaBuilder) buildNvSecurityCrdByApiExtV1B1(nvCrdMetaName string, version *string) *apiextv1b1.CustomResourceDefinitionVersion {

	v1 := &apiextv1b1.CustomResourceDefinitionVersion{
		Name:    version,
		Served:  func() *bool { b := true; return &b }(),
		Storage: func() *bool { b := true; return &b }(),
		Schema:  &apiextv1b1.CustomResourceValidation{},
	}
	switch nvCrdMetaName {
	case resource.NvSecurityRuleName, resource.NvClusterSecurityRuleName:
		v1.Schema.OpenAPIV3Schema = b.buildNvSeurityCrdNwPolicyV1B1Schema()
	case resource.NvAdmCtrlSecurityRuleName:
		v1.Schema.OpenAPIV3Schema = b.buildNvSecurityCrdAdmCtrlV1B1Schema()
	case resource.NvDlpSecurityRuleName, resource.NvWafSecurityRuleName:
		v1.Schema.OpenAPIV3Schema = b.buildNvSecurityCrdDlpWafV1B1Schema()
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
			Metadata: &metav1.ObjectMeta{
				Name:            &crdInfo.MetaName,
				ResourceVersion: &verRead,
			},
			Spec: &apiextv1b1.CustomResourceDefinitionSpec{
				Group:   &crdInfo.SpecGroup,
				Version: &crdInfo.SpecVersion,
				Names: &apiextv1b1.CustomResourceDefinitionNames{
					Plural:   &crdInfo.SpecNamesPlural,
					Kind:     &crdInfo.SpecNamesKind,
					Singular: &crdInfo.SpecNamesSingular,
					ListKind: &crdInfo.SpecNamesListKind,
				},
				Scope: &crdInfo.SpecScope,
			},
		}
		v := builder.buildNvSecurityCrdByApiExtV1B1(crdInfo.MetaName, &crdInfo.SpecVersion)
		res.Spec.Validation = v.Schema
		err = global.ORCH.AddResource(resource.RscTypeCrd, res)
	} else {
		res := &apiextv1.CustomResourceDefinition{
			Metadata: &metav1.ObjectMeta{
				Name:            &crdInfo.MetaName,
				ResourceVersion: &verRead,
			},
			Spec: &apiextv1.CustomResourceDefinitionSpec{
				Group: &crdInfo.SpecGroup,
				Names: &apiextv1.CustomResourceDefinitionNames{
					Plural:   &crdInfo.SpecNamesPlural,
					Kind:     &crdInfo.SpecNamesKind,
					Singular: &crdInfo.SpecNamesSingular,
					ListKind: &crdInfo.SpecNamesListKind,
				},
				Scope: &crdInfo.SpecScope,
			},
		}
		if len(crdInfo.ShortNames) > 0 {
			res.Spec.Names.ShortNames = crdInfo.ShortNames
		}
		v := builder.buildNvSecurityCrdByApiExtV1(crdInfo.MetaName, &crdInfo.SpecVersion)
		res.Spec.Versions = append(res.Spec.Versions, v)
		err = global.ORCH.AddResource(resource.RscTypeCrd, res)
	}

	return err
}

func (b *nvCrdSchmaBuilder) compJSONSchemaV1(srcSchema, destSchema *apiextv1.JSONSchemaProps) bool {
	if srcSchema == nil && destSchema == nil {
		return true
	}
	if srcSchema == nil || destSchema == nil || srcSchema.GetType() != destSchema.GetType() ||
		len(srcSchema.GetRequired()) != len(destSchema.GetRequired()) ||
		len(srcSchema.GetEnum()) != len(destSchema.GetEnum()) ||
		len(srcSchema.GetProperties()) != len(destSchema.GetProperties()) {
		return false
	}

	if srcSchema.GetType() == b.schemaTypeArray {
		srcItems := srcSchema.GetItems()
		destItems := destSchema.GetItems()
		if !b.compJSONSchemaV1(srcItems.Schema, destItems.Schema) || len(srcItems.JSONSchemas) != len(destItems.JSONSchemas) {
			return false
		}
		for _, srcItem := range srcItems.JSONSchemas {
			found := false
			for _, destItem := range destItems.JSONSchemas {
				if b.compJSONSchemaV1(srcItem, destItem) {
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

	srcRequired := srcSchema.GetRequired()
	destRequired := destSchema.GetRequired()
	sort.Strings(srcRequired)
	sort.Strings(destRequired)
	for i, r := range srcRequired {
		if r != destRequired[i] {
			return false
		}
	}

	for _, srcEnum := range srcSchema.GetEnum() {
		found := false
		for _, destEnum := range destSchema.GetEnum() {
			if srcEnum == nil && destEnum == nil {
				found = true
				break
			} else if srcEnum == nil || destEnum == nil {
				continue
			} else if len(srcEnum.Raw) == len(destEnum.Raw) && string(srcEnum.Raw) == string(destEnum.Raw) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	srcProps := srcSchema.GetProperties()
	destProps := destSchema.GetProperties()
	for srcName, srcProp := range srcProps {
		if destProp, ok := destProps[srcName]; !ok || destProp == nil {
			return false
		} else {
			if same := b.compJSONSchemaV1(srcProp, destProp); !same {
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
	if srcSchema == nil || destSchema == nil || srcSchema.GetType() != destSchema.GetType() ||
		len(srcSchema.GetRequired()) != len(destSchema.GetRequired()) ||
		len(srcSchema.GetEnum()) != len(destSchema.GetEnum()) ||
		len(srcSchema.GetProperties()) != len(destSchema.GetProperties()) {
		return false
	}

	if srcSchema.GetType() == b.schemaTypeArray {
		srcItems := srcSchema.GetItems()
		destItems := destSchema.GetItems()
		if !b.compJSONSchemaV1B1(srcItems.Schema, destItems.Schema) || len(srcItems.JSONSchemas) != len(destItems.JSONSchemas) {
			return false
		}
		for _, srcItem := range srcItems.JSONSchemas {
			found := false
			for _, destItem := range destItems.JSONSchemas {
				if b.compJSONSchemaV1B1(srcItem, destItem) {
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

	srcRequired := srcSchema.GetRequired()
	destRequired := destSchema.GetRequired()
	sort.Strings(srcRequired)
	sort.Strings(destRequired)
	for i, r := range srcRequired {
		if r != destRequired[i] {
			return false
		}
	}

	for _, srcEnum := range srcSchema.GetEnum() {
		found := false
		for _, destEnum := range destSchema.GetEnum() {
			if srcEnum == nil && destEnum == nil {
				found = true
				break
			} else if srcEnum == nil || destEnum == nil {
				continue
			} else if len(srcEnum.Raw) == len(destEnum.Raw) && string(srcEnum.Raw) == string(destEnum.Raw) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	srcProps := srcSchema.GetProperties()
	destProps := destSchema.GetProperties()
	for srcName, srcProp := range srcProps {
		if destProp, ok := destProps[srcName]; !ok || destProp == nil {
			return false
		} else {
			if same := b.compJSONSchemaV1B1(srcProp, destProp); !same {
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
		if crdRes, ok := obj.(*apiextv1.CustomResourceDefinition); ok && crdRes.Metadata != nil && crdRes.Spec != nil {
			crdSpec := crdRes.Spec
			if crdRes.Metadata.GetName() == crdInfo.MetaName && len(crdSpec.Versions) > 0 {
				if crdSpec.GetGroup() == crdInfo.SpecGroup && crdSpec.GetScope() == crdInfo.SpecScope && crdSpec.Names != nil {
					shortNames := crdSpec.Names.GetShortNames()
					if utils.CompareSliceWithoutOrder(shortNames, crdInfo.ShortNames) &&
						crdSpec.Names.GetPlural() == crdInfo.SpecNamesPlural &&
						crdSpec.Names.GetSingular() == crdInfo.SpecNamesSingular &&
						crdSpec.Names.GetKind() == crdInfo.SpecNamesKind &&
						crdSpec.Names.GetListKind() == crdInfo.SpecNamesListKind {
						v0 := crdSpec.Versions[0]
						schema := v0.Schema
						if schema != nil && schema.OpenAPIV3Schema != nil && schema.OpenAPIV3Schema.Properties != nil {
							if spec, ok := schema.OpenAPIV3Schema.Properties["spec"]; crdInfo.RscType == resource.RscTypeCrdNvCspUsage || (ok && spec != nil) {
								var builder nvCrdSchmaBuilder
								builder.Init()
								if expected := builder.buildNvSecurityCrdByApiExtV1(crdInfo.MetaName, &crdInfo.SpecVersion); expected != nil && expected.Schema != nil {
									if v0.GetServed() == expected.GetServed() && v0.GetStorage() == expected.GetStorage() && v0.GetName() == expected.GetName() {
										crdUpToDate = builder.compJSONSchemaV1(expected.Schema.OpenAPIV3Schema, schema.OpenAPIV3Schema)
									}
								}
							}
						}
					}
				}
			}
		} else if crdRes, ok := obj.(*apiextv1b1.CustomResourceDefinition); ok && crdRes.Metadata != nil && crdRes.Spec != nil && len(crdRes.Spec.Versions) > 0 {
			crdSpec := crdRes.Spec
			if crdRes.Metadata.GetName() == crdInfo.MetaName && len(crdSpec.Versions) > 0 {
				if crdSpec.GetGroup() == crdInfo.SpecGroup && crdSpec.GetScope() == crdInfo.SpecScope && crdSpec.Names != nil {
					if crdSpec.Names.GetPlural() == crdInfo.SpecNamesPlural &&
						crdSpec.Names.GetSingular() == crdInfo.SpecNamesSingular &&
						crdSpec.Names.GetKind() == crdInfo.SpecNamesKind &&
						crdSpec.Names.GetListKind() == crdInfo.SpecNamesListKind {
						v0 := crdSpec.Versions[0]
						if v0.Served != nil && *v0.Served && v0.Storage != nil && *v0.Storage {
							schema := crdRes.Spec.Versions[0].Schema
							if schema != nil && schema.OpenAPIV3Schema != nil && schema.OpenAPIV3Schema.Properties != nil {
								if spec, ok := schema.OpenAPIV3Schema.Properties["spec"]; crdInfo.RscType == resource.RscTypeCrdNvCspUsage || (ok && spec != nil) {
									var builder nvCrdSchmaBuilder
									builder.Init()
									if expected := builder.buildNvSecurityCrdByApiExtV1B1(crdInfo.MetaName, &crdInfo.SpecVersion); expected != nil && expected.Schema != nil {
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
func CheckCrdSchema(leader, create bool, cspType share.TCspType) []string {

	nvCrdInfo := []*resource.NvCrdInfo{}
	nvCrdInfoBasic := []*resource.NvCrdInfo{
		&resource.NvCrdInfo{
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
		&resource.NvCrdInfo{
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
		&resource.NvCrdInfo{
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
		&resource.NvCrdInfo{
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
		&resource.NvCrdInfo{
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
	}
	if cspType != share.CSP_NONE {
		nvCrdInfo = []*resource.NvCrdInfo{
			&resource.NvCrdInfo{
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
			if leader && create {
				if crdInfo.RscType != resource.RscTypeCrdNvCspUsage {
					rest.CrossCheckCrd(crdInfo.SpecNamesKind, crdInfo.RscType, crdInfo.KvCrdKind, crdInfo.LockKey, false)
				}
			}

			if !crdUpToDate {
				crdOutOfDate = append(crdOutOfDate, crdInfo.MetaName)
				continue
			}
		} else if create {
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
			log.WithFields(log.Fields{"crd": crdInfo.MetaName, "create": create, "err": err}).Error("crd schema")
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

func Init(leader bool, cspType share.TCspType) {
	var crdconf *share.CLUSAdmissionState
	clusHelper := kv.GetClusterHelper()
	crdconf, _ = clusHelper.GetAdmissionStateRev(resource.NvCrdSvcName)
	if crdconf == nil {
		return
	}
	crdconf.CtrlStates[admission.NvAdmValidateType].Enable = true // always enable NV CRD feature

	CheckCrdSchema(leader, true, cspType)

	// register crd admission control(ValidatingWebhookConfiguration neuvector-validating-crd-webhook) to k8s
	k8sResInfo := admission.ValidatingWebhookConfigInfo{
		Name: resource.NvCrdValidatingName,
		WebhooksInfo: []*admission.WebhookInfo{
			&admission.WebhookInfo{
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

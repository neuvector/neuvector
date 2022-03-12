package nvcrd

import (
	"github.com/neuvector/k8s"
	apiextv1 "github.com/neuvector/k8s/apis/apiextensions/v1"
	apiextv1b1 "github.com/neuvector/k8s/apis/apiextensions/v1beta1"
	metav1 "github.com/neuvector/k8s/apis/meta/v1"
	log "github.com/sirupsen/logrus"

	"encoding/json"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/controller/rest"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/global"
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
		share.AdmCtrlModeMonitor, share.AdmCtrlModeProtect,
		share.AdmClientModeSvc, share.AdmClientModeUrl,
		share.AdmCtrlActionAllow, share.AdmCtrlActionDeny,
		share.PolicyModeLearn, share.PolicyModeEvaluate, share.PolicyModeEnforce, share.PolicyModeUnavailable,
		share.ProfileBasic, share.ProfileZeroDrift, share.ProfileDefault, share.ProfileShield,
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
									&apiextv1.JSON{Raw: b.enumMap[share.ProfileDefault]},
									&apiextv1.JSON{Raw: b.enumMap[share.ProfileShield]},
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
					"waf": &apiextv1.JSONSchemaProps{
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
					},
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
									&apiextv1b1.JSON{Raw: b.enumMap[share.ProfileDefault]},
									&apiextv1b1.JSON{Raw: b.enumMap[share.ProfileShield]},
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
					"waf": &apiextv1b1.JSONSchemaProps{
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
					},
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

func (b *nvCrdSchmaBuilder) buildNvSecurityCrdWafV1Schema() *apiextv1.JSONSchemaProps {
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

// for k8a 1.18(-)
func (b *nvCrdSchmaBuilder) buildNvSecurityCrdWafV1B1Schema() *apiextv1b1.JSONSchemaProps {
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
	case resource.NvWafSecurityRuleName:
		v1.Schema.OpenAPIV3Schema = b.buildNvSecurityCrdWafV1Schema()
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
	case resource.NvWafSecurityRuleName:
		v1.Schema.OpenAPIV3Schema = b.buildNvSecurityCrdWafV1B1Schema()
	}
	return v1
}

func configK8sCrdSchema(op, verRead string, crdInfo *resource.NvCrdInfo) error {
	var err error
	k8sVersionMajor, k8sVersionMinor := resource.GetK8sVersion()
	if op == resource.Delete {
		if k8sVersionMajor == 1 && k8sVersionMinor < 19 {
			res := &apiextv1b1.CustomResourceDefinition{
				Metadata: &metav1.ObjectMeta{
					Name: &crdInfo.MetaName,
				},
			}
			err = global.ORCH.DeleteResource(resource.RscTypeCrd, res)
		} else {
			res := &apiextv1.CustomResourceDefinition{
				Metadata: &metav1.ObjectMeta{
					Name: &crdInfo.MetaName,
				},
			}
			err = global.ORCH.DeleteResource(resource.RscTypeCrd, res)
		}
	} else {
		var builder nvCrdSchmaBuilder
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
			if op == resource.Create {
				err = global.ORCH.AddResource(resource.RscTypeCrd, res)
			} else if op == resource.Update {
				err = global.ORCH.UpdateResource(resource.RscTypeCrd, res)
			}
		} else {
			res := &apiextv1.CustomResourceDefinition{
				Metadata: &metav1.ObjectMeta{
					Name:            &crdInfo.MetaName,
					ResourceVersion: &verRead,
				},
				Spec: &apiextv1.CustomResourceDefinitionSpec{
					Group: &crdInfo.SpecGroup,
					//Version: &version, // Deprecated: specify `Versions`
					Names: &apiextv1.CustomResourceDefinitionNames{
						Plural:   &crdInfo.SpecNamesPlural,
						Kind:     &crdInfo.SpecNamesKind,
						Singular: &crdInfo.SpecNamesSingular,
						ListKind: &crdInfo.SpecNamesListKind,
					},
					Scope: &crdInfo.SpecScope,
				},
			}
			v := builder.buildNvSecurityCrdByApiExtV1(crdInfo.MetaName, &crdInfo.SpecVersion)
			res.Spec.Versions = append(res.Spec.Versions, v)
			if op == resource.Create {
				err = global.ORCH.AddResource(resource.RscTypeCrd, res)
			} else if op == resource.Update {
				err = global.ORCH.UpdateResource(resource.RscTypeCrd, res)
			}
		}
	}
	return err
}

// create the CustomResourceDefinition resource(schema) that is listed by "kubectl get CustomResourceDefinition"
func initK8sCrdSchema(leader bool, crdInfo *resource.NvCrdInfo, ctrlState *share.CLUSAdmCtrlState) (bool, error) {
	crdConfigured := false // crd schema is configured or not
	crdExpected := false   // whether the configured crd schema is up-to-date

	var verRead string
	obj, err := global.ORCH.GetResource(resource.RscTypeCrd, k8s.AllNamespaces, crdInfo.MetaName)
	if err == nil {
		crdConfigured = true
		if crdInfo.MetaName == resource.NvAdmCtrlSecurityRuleName || crdInfo.MetaName == resource.NvWafSecurityRuleName {
			crdExpected = true
		} else {
			if res, ok := obj.(*apiextv1.CustomResourceDefinition); ok && res.Spec != nil {
				verRead = *res.Metadata.ResourceVersion
				if len(res.Spec.Versions) > 0 {
					schema := res.Spec.Versions[0].Schema
					if schema != nil && schema.OpenAPIV3Schema != nil && schema.OpenAPIV3Schema.Properties != nil {
						if spec, ok := schema.OpenAPIV3Schema.Properties["spec"]; ok && spec != nil {
							if pp, ok := spec.Properties["process_profile"]; ok {
								if bl, ok := pp.Properties["baseline"]; ok && len(bl.Enum) == 4 {
									if _, ok := spec.Properties["waf"]; ok {
										crdExpected = true
									}
								}
							}
						}
					}
				}
			} else if res, ok := obj.(*apiextv1b1.CustomResourceDefinition); ok && res.Spec != nil {
				verRead = *res.Metadata.ResourceVersion
				if len(res.Spec.Versions) > 0 {
					schema := res.Spec.Versions[0].Schema
					if schema != nil && schema.OpenAPIV3Schema != nil && schema.OpenAPIV3Schema.Properties != nil {
						if spec, ok := schema.OpenAPIV3Schema.Properties["spec"]; ok && spec != nil {
							if pp, ok := spec.Properties["process_profile"]; ok {
								if bl, ok := pp.Properties["baseline"]; ok && len(bl.Enum) == 4 {
									if _, ok := spec.Properties["waf"]; ok {
										crdExpected = true
									}
								}
							}
						}
					}
				}
			}
		}
		if leader {
			rest.CrossCheckCrd(crdInfo.SpecNamesKind, crdInfo.RscType, crdInfo.KvCrdKind, crdInfo.LockKey, false)
		}
	}

	if !crdConfigured && !ctrlState.Enable {
		return true, err
	} else if crdConfigured && crdExpected && ctrlState.Enable {
		log.WithFields(log.Fields{"enable": ctrlState.Enable, "CrdConfigured": crdConfigured, "crd": crdInfo.MetaName}).
			Debug("skip because crd schema is already defined")
		return true, err
	}

	var op string
	if !ctrlState.Enable {
		op = resource.Delete
	} else {
		if !crdConfigured {
			op = resource.Create
		} else if !crdExpected {
			op = resource.Update
		}
	}
	retry := 0
	for retry < 3 {
		if err = configK8sCrdSchema(op, verRead, crdInfo); err == nil {
			log.WithFields(log.Fields{"op": op, "crd": crdInfo.MetaName}).Info("configured crd in k8s")
			return false, nil
		}
		retry++
	}
	log.WithFields(log.Fields{"op": op, "crd": crdInfo.MetaName, "error": err}).Error("failed to configure crd in k8s")

	return true, err
}

func Init(leader bool) {
	var crdconf *share.CLUSAdmissionState
	clusHelper := kv.GetClusterHelper()
	crdconf, _ = clusHelper.GetAdmissionStateRev(resource.NvCrdSvcName)
	if crdconf == nil {
		return
	}

	nvCrdInfo := []*resource.NvCrdInfo{
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
	crdconf.CtrlStates[admission.NvAdmValidateType].Enable = true // always enable NV CRD feature
	for _, crdInfo := range nvCrdInfo {
		initK8sCrdSchema(leader, crdInfo, crdconf.CtrlStates[admission.NvAdmValidateType])
	}

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
	admission.ConfigK8sAdmissionControl(k8sResInfo, crdconf.CtrlStates[admission.NvAdmValidateType])
}

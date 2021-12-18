package admission

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/ericchiang/k8s"
	apiv1 "github.com/ericchiang/k8s/apis/admissionregistration/v1"
	apiv1beta1 "github.com/ericchiang/k8s/apis/admissionregistration/v1beta1"
	corev1 "github.com/ericchiang/k8s/apis/core/v1"
	metav1 "github.com/ericchiang/k8s/apis/meta/v1"
	rbacv1 "github.com/ericchiang/k8s/apis/rbac/v1"
	rbacv1b1 "github.com/ericchiang/k8s/apis/rbac/v1beta1"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/utils"
)

type ValidateWebhookSvcInfo struct {
	Status      int
	SvcNodePort int32
	SvcType     string
	LabelTag    string
	LabelEcho   string
}

type WebhookSvcLabelKey struct {
	TagKey  string
	EchoKey string
}

type ClientConfig struct {
	ClientMode  string // "service" or "url"
	ServiceName string
	Path        string // uri
	Port        int32
}

type WebhookInfo struct {
	Name           string
	ClientConfig   ClientConfig
	FailurePolicy  string
	TimeoutSeconds int32
}

type ValidatingWebhookConfigInfo struct {
	Name         string
	WebhooksInfo []*WebhookInfo
}

const (
	UriAdmCtrlPrefix   = "/v1"
	UriAdmCtrlNvStatus = "nvstatus"
)

const (
	//NvAdmMutateType   = "mutate" // for Kubernetes
	NvAdmValidateType = "validate" // for Kubernetes
)

const (
	AdmRuleCatK8s = "Kubernetes"
)

const (
	K8sResOpCreate = "create"
	K8sResOpUpdate = "update"
	K8sResOpDelete = "delete"
)

const (
	TestSucceeded = iota
	TestFailedAtRead
	TestFailedAtWrite
	TestFailed
	TestAborted
)

var admCaBundle = make(map[string]string)               // key is service name
var svcLabelKeys = make(map[string]*WebhookSvcLabelKey) // key is service name

var admCtrlTypes []string

var allowedNamespaces utils.Set     // all effectively allowed namespaces that do no contain wildcard character
var allowedNamespacesWild utils.Set // all effectively allowed namespaces that contain wildcard character
var nsSelectorValue string

var allSetOps = []string{share.CriteriaOpContainsAll, share.CriteriaOpContainsAny, share.CriteriaOpNotContainsAny, share.CriteriaOpContainsOtherThan}

func InitK8sNsSelectorInfo(allowedNS, allowedNsWild utils.Set, selectorValue string, admCtrlEnabled bool) {
	nsSelectorValue = selectorValue
	allowedNamespaces = allowedNS
	allowedNamespacesWild = allowedNsWild
	if objs, err := global.ORCH.ListResource(resource.RscTypeNamespace); len(objs) > 0 {
		for _, obj := range objs {
			if nsObj := obj.(*resource.Namespace); nsObj != nil {
				VerifyK8sNs(admCtrlEnabled, nsObj.Name, nsObj.Labels)
			}
		}
	} else {
		log.WithFields(log.Fields{"enabled": admCtrlEnabled, "err": err}).Error()
	}
}

func UpdateAllowedK8sNs(isLead, admCtrlEnabled bool, newAllowedNS, newAllowedNsWild utils.Set) {
	if isLead {
		allowedNamespaces = newAllowedNS
		allowedNamespacesWild = newAllowedNsWild
		if objs, err := global.ORCH.ListResource(resource.RscTypeNamespace); len(objs) > 0 {
			for _, obj := range objs {
				if nsObj := obj.(*resource.Namespace); nsObj != nil {
					VerifyK8sNs(admCtrlEnabled, nsObj.Name, nsObj.Labels)
				}
			}
		} else {
			log.WithFields(log.Fields{"enabled": admCtrlEnabled, "err": err}).Error()
		}
	} else {
		allowedNamespaces = newAllowedNS
		allowedNamespacesWild = newAllowedNsWild
	}
}

func VerifyK8sNs(admCtrlEnabled bool, nsName string, nsLabels map[string]string) {
	keys := map[string]bool{ // map key is label key, map value is the label key should exist in k8s resource metadata or not
		resource.NsSelectorKeySkipNV:   false,
		resource.NsSelectorKeyStatusNV: false,
	}
	addLabelSkip := false
	addLabelStatus := false
	if admCtrlEnabled {
		if allowedNamespaces.Contains(nsName) {
			keys[resource.NsSelectorKeySkipNV] = true
			addLabelSkip = true
		} else {
			for allowedNsWild := range allowedNamespacesWild.Iter() {
				if share.EqualMatch(allowedNsWild.(string), nsName) {
					keys[resource.NsSelectorKeySkipNV] = true
					addLabelSkip = true
					break
				}
			}
		}
		if resource.NvAdmSvcNamespace == nsName {
			// as long as admission control is enabled, even 'namespace=neuvector' critical allow rule is disabled, label 'statusNeuvector' still exists in neuvector namespace
			keys[resource.NsSelectorKeyStatusNV] = true
			addLabelStatus = true
		}
	}
	needUpdate := false
	for key, labelShouldExist := range keys {
		if labelShouldExist {
			if nsLabels != nil {
				if _, exists := nsLabels[key]; exists {
					continue
				} else {
					needUpdate = true
					break
				}
			} else {
				needUpdate = true
				break
			}
		} else {
			if nsLabels != nil {
				if _, exists := nsLabels[key]; exists {
					needUpdate = true
					break
				}
			}
		}
	}
	if needUpdate {
		workSingleK8sNsLabels(addLabelSkip, addLabelStatus, nsName)
	}
}

func SetCABundle(svcName string, caBundle []byte) {
	admCaBundle[svcName] = string(caBundle)
	svcLabelKeys[svcName] = &WebhookSvcLabelKey{
		TagKey:  fmt.Sprintf("tag-%s", svcName),
		EchoKey: fmt.Sprintf("echo-%s", svcName),
	}
	b := md5.Sum(caBundle)
	log.WithFields(log.Fields{"svcName": svcName, "cert": hex.EncodeToString(b[:])}).Info("md5")

	resource.GetK8sVersion()
}

func ResetCABundle(svcName string, caBundle []byte) bool { // return true if reset
	newCert := string(caBundle)
	oldCert := admCaBundle[svcName]
	if len(newCert) > 0 && oldCert != newCert {
		b := md5.Sum([]byte(oldCert))
		log.WithFields(log.Fields{"svcName": svcName, "old": hex.EncodeToString(b[:])}).Info("md5")
		admCaBundle[svcName] = newCert
		return true
	}
	return false
}

func GetAdmissionCtrlTypes(platform string) []string {
	if admCtrlTypes == nil {
		admCtrlTypes = []string{NvAdmValidateType}
	}
	return admCtrlTypes
}

func isK8sConfiguredAsExpected(k8sResInfo ValidatingWebhookConfigInfo) (bool, bool, string, error) { // returns (found, matchedCfg, verRead, error)
	var rt string
	if k8sResInfo.Name == resource.NvAdmValidatingName || k8sResInfo.Name == resource.NvCrdValidatingName {
		rt = resource.RscTypeValidatingWebhookConfiguration
	} else {
		err := fmt.Errorf("Unsupported admission control type")
		log.WithFields(log.Fields{"name": k8sResInfo.Name, "err": err}).Error()
		return false, false, "", err
	}
	obj, err := global.ORCH.GetResource(rt, k8s.AllNamespaces, k8sResInfo.Name)
	if err != nil {
		return false, false, "", err
	}

	useApiV1 := false
	k8sVersionMajor, k8sVersionMinor := resource.GetK8sVersion()
	if _, ok := obj.(*apiv1.ValidatingWebhookConfiguration); ok {
		useApiV1 = true
	} else if _, ok := obj.(*apiv1beta1.ValidatingWebhookConfiguration); !ok {
		err := fmt.Errorf("type assertion failed(%d.%d)", k8sVersionMajor, k8sVersionMinor)
		log.WithFields(log.Fields{"name": k8sResInfo.Name}).Error(err.Error())
		return true, false, "", err
	}

	var verRead string
	var config *resource.K8sAdmRegValidatingWebhookConfiguration
	if useApiV1 {
		k8sConfig := obj.(*apiv1.ValidatingWebhookConfiguration)
		verRead = *k8sConfig.Metadata.ResourceVersion
		if len(k8sConfig.Webhooks) != len(k8sResInfo.WebhooksInfo) {
			return true, false, verRead, nil
		}
		config = &resource.K8sAdmRegValidatingWebhookConfiguration{
			Metadata: k8sConfig.Metadata,
			Webhooks: make([]*resource.K8sAdmRegWebhook, len(k8sConfig.Webhooks)),
		}
		for idx, wh := range k8sConfig.Webhooks {
			config.Webhooks[idx] = &resource.K8sAdmRegWebhook{
				Name:                    wh.Name,
				AdmissionReviewVersions: wh.AdmissionReviewVersions,
				ClientConfig: &resource.K8sAdmRegWebhookClientConfig{
					Url:      wh.ClientConfig.Url,
					CaBundle: wh.ClientConfig.CaBundle,
				},
				Rules:             make([]*resource.K8sAdmRegRuleWithOperations, len(wh.Rules)),
				FailurePolicy:     wh.FailurePolicy,
				NamespaceSelector: wh.NamespaceSelector,
				SideEffects:       wh.SideEffects,
			}
			if wh.ClientConfig.Service != nil {
				config.Webhooks[idx].ClientConfig.Service = &resource.K8sAdmRegServiceReference{
					Namespace: wh.ClientConfig.Service.Namespace,
					Name:      wh.ClientConfig.Service.Name,
					Path:      wh.ClientConfig.Service.Path,
				}
			}
			for j, rops := range wh.Rules {
				config.Webhooks[idx].Rules[j] = &resource.K8sAdmRegRuleWithOperations{
					Operations: rops.Operations,
					Rule: &resource.K8sAdmRegRule{
						ApiGroups:   rops.Rule.ApiGroups,
						ApiVersions: rops.Rule.ApiVersions,
						Resources:   rops.Rule.Resources,
						Scope:       rops.Rule.Scope,
					},
				}
			}
		}
	} else {
		k8sConfig := obj.(*apiv1beta1.ValidatingWebhookConfiguration)
		verRead = *k8sConfig.Metadata.ResourceVersion
		if len(k8sConfig.Webhooks) != len(k8sResInfo.WebhooksInfo) {
			return true, false, verRead, nil
		}
		config = &resource.K8sAdmRegValidatingWebhookConfiguration{
			Metadata: k8sConfig.Metadata,
			Webhooks: make([]*resource.K8sAdmRegWebhook, len(k8sConfig.Webhooks)),
		}
		for idx, wh := range k8sConfig.Webhooks {
			config.Webhooks[idx] = &resource.K8sAdmRegWebhook{
				Name: wh.Name,
				ClientConfig: &resource.K8sAdmRegWebhookClientConfig{
					Url:      wh.ClientConfig.Url,
					CaBundle: wh.ClientConfig.CaBundle,
				},
				Rules:             make([]*resource.K8sAdmRegRuleWithOperations, len(wh.Rules)),
				FailurePolicy:     wh.FailurePolicy,
				NamespaceSelector: wh.NamespaceSelector,
				SideEffects:       wh.SideEffects,
			}
			if wh.ClientConfig.Service != nil {
				config.Webhooks[idx].ClientConfig.Service = &resource.K8sAdmRegServiceReference{
					Namespace: wh.ClientConfig.Service.Namespace,
					Name:      wh.ClientConfig.Service.Name,
					Path:      wh.ClientConfig.Service.Path,
				}
			}
			for j, rops := range wh.Rules {
				config.Webhooks[idx].Rules[j] = &resource.K8sAdmRegRuleWithOperations{
					Operations: rops.Operations,
					Rule: &resource.K8sAdmRegRule{
						ApiGroups:   rops.Rule.ApiGroups,
						ApiVersions: rops.Rule.ApiVersions,
						Resources:   rops.Rule.Resources,
						Scope:       rops.Rule.Scope,
					},
				}
			}
		}
	}
	nsSelectorSupported := IsNsSelectorSupported()

	// config.Webhooks is from k8s, k8sResInfo.WebhooksInfo is what nv expects
	for _, wh := range config.Webhooks {
		whFound := false
		for _, whInfo := range k8sResInfo.WebhooksInfo {
			if wh.Name == nil || *wh.Name != whInfo.Name {
				continue
			}
			whFound = true // found a webhook with the same name
			clientInUrlMode := false
			if whInfo.ClientConfig.ClientMode == share.AdmClientModeUrl {
				clientInUrlMode = true
			}
			whMatched := false
			// check whether the webhook has expected configuration
			if !useApiV1 || reflect.DeepEqual(wh.AdmissionReviewVersions, []string{resource.K8sApiVersionV1Beta1}) {
				// we don't support k8s.io/api/admission/v1 yet
				clientCfg := wh.ClientConfig
				if (!clientInUrlMode && clientCfg.Service != nil) || (clientInUrlMode && clientCfg.Url != nil) {
					// ClientConfig has the same mode as what should be for neuvector-svc-admission-webhook's type
					// SideEffects is supported starting from K8s 1.12. In admissionregistration/v1, sideEffects must be None or NoneOnDryRun
					var sideEffects string = resource.SideEffectNone
					if k8sResInfo.Name == resource.NvCrdValidatingName {
						if k8sVersionMajor == 1 && k8sVersionMinor >= 22 {
							sideEffects = resource.SideEffectNoneOnDryRun
						} else {
							sideEffects = resource.SideEffectSome
						}
					}
					if k8sVersionMinor <= 11 || (k8sVersionMinor > 11 && wh.SideEffects != nil && *wh.SideEffects == sideEffects) {
						svcName := whInfo.ClientConfig.ServiceName
						// if controller doesn't have caBundle value yet, do not compare caBundle value
						if len(admCaBundle[svcName]) == 0 || admCaBundle[svcName] == string(clientCfg.CaBundle) {
							if clientInUrlMode {
								expectedUrl := fmt.Sprintf("https://%s.%s.svc:%d%s", svcName, resource.NvAdmSvcNamespace, whInfo.ClientConfig.Port, whInfo.ClientConfig.Path)
								if clientCfg.Url != nil && strings.EqualFold(*clientCfg.Url, expectedUrl) {
									if resource.IsK8sNvWebhookConfigured(whInfo.Name, whInfo.FailurePolicy, wh, nsSelectorSupported) {
										whMatched = true
									}
								}
							} else {
								if clientCfg.Service.Namespace != nil && *clientCfg.Service.Namespace == resource.NvAdmSvcNamespace &&
									clientCfg.Service.Name != nil && *clientCfg.Service.Name == svcName {
									if clientCfg.Service.Path != nil && strings.EqualFold(*clientCfg.Service.Path, whInfo.ClientConfig.Path) {
										if resource.IsK8sNvWebhookConfigured(whInfo.Name, whInfo.FailurePolicy, wh, nsSelectorSupported) {
											whMatched = true
										}
									}
								}
							}
						}
					}
				} else {
					log.WithFields(log.Fields{"clientInUrlMode": clientInUrlMode}).Warn()
				}
			}
			whFound = whMatched
			break
		}
		if !whFound {
			return true, false, verRead, nil
		}
	}

	return true, true, verRead, nil
}

func configK8sAdmCtrlValidateResource(op, resVersion string, k8sResInfo ValidatingWebhookConfigInfo) error {
	var err error
	k8sVersionMajor, k8sVersionMinor := resource.GetK8sVersion()
	if op == K8sResOpDelete {
		// delete resource when admission control is configured in k8s & we are asked to disable admission control
		if k8sVersionMajor == 1 && k8sVersionMinor >= 22 {
			res := &apiv1.ValidatingWebhookConfiguration{
				Metadata: &metav1.ObjectMeta{
					Name: &k8sResInfo.Name,
				},
			}
			err = global.ORCH.DeleteResource(resource.RscTypeValidatingWebhookConfiguration, res)
		} else {
			res := &apiv1beta1.ValidatingWebhookConfiguration{
				Metadata: &metav1.ObjectMeta{
					Name: &k8sResInfo.Name,
				},
			}
			err = global.ORCH.DeleteResource(resource.RscTypeValidatingWebhookConfiguration, res)
		}
	} else if (op == K8sResOpCreate) || (op == K8sResOpUpdate) {
		allApiGroups := []string{resource.K8sAllApiGroup}
		v1b1b2ApiVersions := []string{resource.K8sApiVersionV1, resource.K8sApiVersionV1Beta1, resource.K8sApiVersionV1Beta2}
		if k8sVersionMajor == 1 && k8sVersionMinor >= 22 {
			// https://kubernetes.io/docs/reference/using-api/deprecation-guide/
			// admissionregistration.k8s.io/v1beta1 ValidatingWebhookConfiguration is deprecated in v1.16+, unavailable in v1.22+
			// k8s stops serving the admissionregistration.k8s.io/v1beta1 API by default in v1.19.
			matchPolicyExact := "Exact"
			webhooks := make([]*apiv1.ValidatingWebhook, len(k8sResInfo.WebhooksInfo)) // only for RscTypeValidatingWebhookConfiguration
			for i, whInfo := range k8sResInfo.WebhooksInfo {
				svcName := whInfo.ClientConfig.ServiceName
				if len(admCaBundle[svcName]) == 0 {
					// if controller doesn't have caBundle value, do not config k8s
					return errors.New("empty caBundle")
				}
				var nvOpResources []resource.NvAdmRegRuleSetting
				var sideEffects string = resource.SideEffectNone
				var nsSelectorKey, nsSelectorOp, failurePolicy string

				switch whInfo.Name {
				case resource.NvAdmValidatingWebhookName:
					nvOpResources = resource.AdmResForOpsSettings
					nsSelectorKey = resource.NsSelectorKeySkipNV
					nsSelectorOp = resource.NsSelectorOpNotExist
					failurePolicy = whInfo.FailurePolicy

				case resource.NvCrdValidatingWebhookName:
					nvOpResources = resource.CrdResForOpsSettings
					sideEffects = resource.SideEffectNoneOnDryRun
					failurePolicy = resource.Ignore

				case resource.NvStatusValidatingWebhookName:
					nvOpResources = resource.StatusResForOpsSettings
					nsSelectorKey = resource.NsSelectorKeyStatusNV
					nsSelectorOp = resource.NsSelectorOpExists
					failurePolicy = resource.Ignore
				}
				webhooks[i] = &apiv1.ValidatingWebhook{
					Name: &whInfo.Name,
					ClientConfig: &apiv1.WebhookClientConfig{
						CaBundle: []byte(admCaBundle[svcName]),
					},
					Rules:                   make([]*apiv1.RuleWithOperations, 0, len(nvOpResources)),
					FailurePolicy:           &failurePolicy,
					AdmissionReviewVersions: []string{resource.K8sApiVersionV1Beta1}, // we don't support k8s.io/api/admission/v1 yet
					MatchPolicy:             &matchPolicyExact,
					SideEffects:             &sideEffects, // SideEffects is supported starting from K8s 1.12
					TimeoutSeconds:          &whInfo.TimeoutSeconds,
				}
				for _, opRes := range nvOpResources {
					ro := &apiv1.RuleWithOperations{
						Operations: opRes.Operations.ToStringSlice(),
						Rule: &apiv1.Rule{
							ApiGroups:   allApiGroups,
							ApiVersions: v1b1b2ApiVersions,
							Resources:   opRes.Resources.ToStringSlice(),
							Scope:       &opRes.Scope, // Scope is supported starting from K8s 1.14
						},
					}
					sort.Strings(ro.Operations)
					sort.Strings(ro.Rule.Resources)
					webhooks[i].Rules = append(webhooks[i].Rules, ro)
				}
				// NamespaceSelector is supported starting from K8s 1.14
				if nsSelectorKey != "" && nsSelectorOp != "" {
					webhooks[i].NamespaceSelector = &metav1.LabelSelector{
						MatchExpressions: []*metav1.LabelSelectorRequirement{
							&metav1.LabelSelectorRequirement{
								Key:      &nsSelectorKey,
								Operator: &nsSelectorOp,
							},
						},
					}
				}
				if whInfo.ClientConfig.ClientMode == share.AdmClientModeUrl {
					expectedUrl := fmt.Sprintf("https://%s.%s.svc:%d%s", svcName, resource.NvAdmSvcNamespace, whInfo.ClientConfig.Port, whInfo.ClientConfig.Path)
					webhooks[i].ClientConfig.Url = &expectedUrl
				} else {
					webhooks[i].ClientConfig.Service = &apiv1.ServiceReference{
						Namespace: &resource.NvAdmSvcNamespace,
						Name:      &svcName,
						Path:      &whInfo.ClientConfig.Path,
					}
				}
			}
			res := &apiv1.ValidatingWebhookConfiguration{
				Metadata: &metav1.ObjectMeta{
					Name: &k8sResInfo.Name,
				},
				Webhooks: webhooks,
			}
			if op == K8sResOpCreate {
				// add resource when admission control is not configured in k8s  & we are asked to enable admission control
				err = global.ORCH.AddResource(resource.RscTypeValidatingWebhookConfiguration, res)
			} else if op == K8sResOpUpdate {
				// update resource when admission control is configured in k8s with different setting & admission control is enabled in NV
				res.Metadata.ResourceVersion = &resVersion
				err = global.ORCH.UpdateResource(resource.RscTypeValidatingWebhookConfiguration, res)
			}
		} else {
			webhooks := make([]*apiv1beta1.Webhook, len(k8sResInfo.WebhooksInfo))
			for i, whInfo := range k8sResInfo.WebhooksInfo {
				svcName := whInfo.ClientConfig.ServiceName
				if len(admCaBundle[svcName]) == 0 {
					// if controller doesn't have caBundle value, do not config k8s
					return errors.New("empty caBundle")
				}
				var nvOpResources []resource.NvAdmRegRuleSetting
				var sideEffects string = resource.SideEffectNone
				var nsSelectorKey, nsSelectorOp, failurePolicy string

				switch whInfo.Name {
				case resource.NvAdmValidatingWebhookName:
					nvOpResources = resource.AdmResForOpsSettings
					nsSelectorKey = resource.NsSelectorKeySkipNV
					nsSelectorOp = resource.NsSelectorOpNotExist
					failurePolicy = whInfo.FailurePolicy

				case resource.NvCrdValidatingWebhookName:
					nvOpResources = resource.CrdResForOpsSettings
					sideEffects = resource.SideEffectSome
					failurePolicy = resource.Ignore

				case resource.NvStatusValidatingWebhookName:
					nvOpResources = resource.StatusResForOpsSettings
					nsSelectorKey = resource.NsSelectorKeyStatusNV
					nsSelectorOp = resource.NsSelectorOpExists
					failurePolicy = resource.Ignore
				}
				webhooks[i] = &apiv1beta1.Webhook{
					Name: &whInfo.Name,
					ClientConfig: &apiv1beta1.WebhookClientConfig{
						CaBundle: []byte(admCaBundle[svcName]),
					},
					Rules:         make([]*apiv1beta1.RuleWithOperations, 0, len(nvOpResources)),
					FailurePolicy: &failurePolicy,
				}
				for _, opRes := range nvOpResources {
					ro := &apiv1beta1.RuleWithOperations{
						Operations: opRes.Operations.ToStringSlice(),
						Rule: &apiv1beta1.Rule{
							ApiGroups:   allApiGroups,
							ApiVersions: v1b1b2ApiVersions,
							Resources:   opRes.Resources.ToStringSlice(),
						},
					}
					sort.Strings(ro.Operations)
					sort.Strings(ro.Rule.Resources)
					if IsNsSelectorSupported() {
						// Scope is supported starting from K8s 1.14
						ro.Rule.Scope = &opRes.Scope
					}
					webhooks[i].Rules = append(webhooks[i].Rules, ro)
				}
				if IsNsSelectorSupported() {
					// NamespaceSelector is supported starting from K8s 1.14
					if nsSelectorKey != "" && nsSelectorOp != "" {
						webhooks[i].NamespaceSelector = &metav1.LabelSelector{
							MatchExpressions: []*metav1.LabelSelectorRequirement{
								&metav1.LabelSelectorRequirement{
									Key:      &nsSelectorKey,
									Operator: &nsSelectorOp,
								},
							},
						}
					}
				}
				if whInfo.ClientConfig.ClientMode == share.AdmClientModeUrl {
					expectedUrl := fmt.Sprintf("https://%s.%s.svc:%d%s", svcName, resource.NvAdmSvcNamespace, whInfo.ClientConfig.Port, whInfo.ClientConfig.Path)
					webhooks[i].ClientConfig.Url = &expectedUrl
				} else {
					webhooks[i].ClientConfig.Service = &apiv1beta1.ServiceReference{
						Namespace: &resource.NvAdmSvcNamespace,
						Name:      &svcName,
						Path:      &whInfo.ClientConfig.Path,
					}
				}
				if k8sVersionMajor == 1 {
					if k8sVersionMinor > 11 {
						// SideEffects is supported starting from K8s 1.12
						webhooks[i].SideEffects = &sideEffects
					}
				}
			}
			res := &apiv1beta1.ValidatingWebhookConfiguration{
				Metadata: &metav1.ObjectMeta{
					Name: &k8sResInfo.Name,
				},
				Webhooks: webhooks,
			}
			if op == K8sResOpCreate {
				// add resource when admission control is not configured in k8s  & we are asked to enable admission control
				err = global.ORCH.AddResource(resource.RscTypeValidatingWebhookConfiguration, res)
			} else if op == K8sResOpUpdate {
				// update resource when admission control is configured in k8s with different setting & admission control is enabled in NV
				res.Metadata.ResourceVersion = &resVersion
				err = global.ORCH.UpdateResource(resource.RscTypeValidatingWebhookConfiguration, res)
			}
		}
	} else {
		err = errors.New("unsupported k8s resource operation")
	}

	return err
}

func ConfigK8sAdmissionControl(k8sResInfo ValidatingWebhookConfigInfo, ctrlState *share.CLUSAdmCtrlState) (bool, error) { // returns (skip, err)
	if ctrlState == nil || ctrlState.Uri == "" {
		log.WithFields(log.Fields{"name": k8sResInfo.Name}).Error("Empty ctrlState") // should never reach here
		return true, nil
	}

	var k8sConfigured, matchedCfg bool
	var verRead, op string
	var err error
	retry := 0
	for _, whInfo := range k8sResInfo.WebhooksInfo {
		if whInfo.ClientConfig.ClientMode == share.AdmClientModeUrl {
			_, svcInfo := GetValidateWebhookSvcInfo(whInfo.ClientConfig.ServiceName)
			whInfo.ClientConfig.Port = svcInfo.SvcNodePort
		}
	}
	for retry < 3 {
		op = ""
		k8sConfigured, matchedCfg, verRead, err = isK8sConfiguredAsExpected(k8sResInfo)
		if !k8sConfigured && !matchedCfg && !ctrlState.Enable && err != nil {
			return true, nil
		} else if (!k8sConfigured && !ctrlState.Enable) || (matchedCfg && k8sConfigured && ctrlState.Enable) {
			log.WithFields(log.Fields{"name": k8sResInfo.Name, "enable": ctrlState.Enable, "k8sConfigured": k8sConfigured, "matchedCfg": matchedCfg}).
				Debug("skip because of no change")
			return true, nil
		}
		if k8sConfigured && !ctrlState.Enable {
			// admssion control config(NV) is in K8s and caller wants to disable NV admission control
			op = K8sResOpDelete
		} else if ctrlState.Enable {
			if !k8sConfigured {
				// admssion control config(NV) is not in K8s and caller wants to enable NV admission control
				op = K8sResOpCreate
			} else if !matchedCfg {
				// unusual case: admssion control config(NV) has unexpected settings in K8s and caller wants to enable NV admission control. Update it
				op = K8sResOpUpdate
			}
		}
		if op != "" {
			err = configK8sAdmCtrlValidateResource(op, verRead, k8sResInfo)
			if err == nil {
				log.WithFields(log.Fields{"name": k8sResInfo.Name, "op": op, "enable": ctrlState.Enable}).Info("Configured admission control in k8s")
				return false, nil
			}
		}
		retry++
	}

	log.WithFields(log.Fields{"name": k8sResInfo.Name, "op": op, "enable": ctrlState.Enable, "error": err}).Error("Failed to configure admission control in k8s")

	return true, err
}

func UnregK8sAdmissionControl(admType, nvAdmName string) error {
	k8sResInfo := ValidatingWebhookConfigInfo{Name: nvAdmName}
	return configK8sAdmCtrlValidateResource(K8sResOpDelete, "", k8sResInfo)
}

func ValidateK8sSetting(k8sResInfo ValidatingWebhookConfigInfo) bool {
	for _, whInfo := range k8sResInfo.WebhooksInfo {
		if whInfo.ClientConfig.ClientMode == share.AdmClientModeUrl {
			_, svcInfo := GetValidateWebhookSvcInfo(whInfo.ClientConfig.ServiceName)
			whInfo.ClientConfig.Port = svcInfo.SvcNodePort
		}
	}
	k8sConfigured, matchedCfg, _, err := isK8sConfiguredAsExpected(k8sResInfo)

	return err == nil && k8sConfigured && matchedCfg
}

func GetValidateWebhookSvcInfo(svcname string) (error, *ValidateWebhookSvcInfo) {
	svcInfo := &ValidateWebhookSvcInfo{
		SvcNodePort: 443,
		Status:      api.RESTErrWebhookSvcForAdmCtrl,
		SvcType:     resource.ServiceTypeClusterIP,
	}
	obj, err := global.ORCH.GetResource(resource.RscTypeService, resource.NvAdmSvcNamespace, svcname)
	if err != nil {
		log.WithFields(log.Fields{"namespace": resource.NvAdmSvcNamespace, "service": svcname, "err": err}).Error("resource no found")
		if strings.Index(err.Error(), " 403 ") > 0 && strings.Index(err.Error(), "forbidden") > 0 {
			svcInfo.Status = api.RESTErrNvPermission
		}
	} else {
		if svc, ok := obj.(*corev1.Service); ok && svc != nil {
			if keys, exist := svcLabelKeys[svcname]; exist {
				if tag, ok := svc.Metadata.Labels[keys.TagKey]; ok {
					svcInfo.LabelTag = tag
				}
				if echo, ok := svc.Metadata.Labels[keys.EchoKey]; ok {
					svcInfo.LabelEcho = echo
				}
			}
			if svc.Spec != nil && svc.Spec.Type != nil && *svc.Spec.Type == resource.ServiceTypeNodePort {
				for _, ports := range svc.Spec.Ports {
					if ports != nil && ports.NodePort != nil {
						svcInfo.SvcNodePort = *ports.NodePort
						svcInfo.SvcType = resource.ServiceTypeNodePort
						return nil, svcInfo
					}
				}
			}
		} else {
			log.WithFields(log.Fields{"service": svcname}).Error("unknown type")
		}
	}
	log.WithFields(log.Fields{"namespace": resource.NvAdmSvcNamespace, "service": svcname}).Debug("NodePort not found")

	return err, svcInfo
}

// https://kubernetes.io/docs/reference/using-api/deprecation-guide/
// The rbac.authorization.k8s.io/v1beta1 API version of ClusterRole, ClusterRoleBinding, Role, and RoleBinding is no longer served as of v1.22.
func VerifyAdmClusterRole() (bool, error) {
	roles := map[string]utils.Set{ // k8s clusterrole to resources mapping
		resource.NvAdmCtrlRole: utils.NewSet(resource.RscNameMutatingWebhookConfigurations, resource.RscNameValidatingWebhookConfigurations),
		resource.NvAppRole:     utils.NewSet(resource.RscNamespaces, resource.RscServices),
	}

	for role, rscsToCheck := range roles {
		obj, err := global.ORCH.GetResource(resource.K8sRscTypeClusRole, k8s.AllNamespaces, role)
		if err != nil {
			log.WithFields(log.Fields{"role": role, "err": err}).Error("resource no found")
			return false, fmt.Errorf("Cannot find clusterrole %s(%s). ", role, err.Error())
		} else {
			var err error
			if r, ok := obj.(*rbacv1.ClusterRole); ok && r != nil {
				err = resource.DeduceAdmCtrlRoleRules(rscsToCheck, r.GetRules())
			} else if r, ok := obj.(*rbacv1b1.ClusterRole); ok && r != nil {
				err = resource.DeduceAdmCtrlRoleRules(rscsToCheck, r.GetRules())
			} else {
				err = fmt.Errorf("Unknown object type for clusterrole %s. ", role)
			}
			if err != nil {
				log.WithFields(log.Fields{"role": role, "error": err}).Error()
				return false, err
			}
		}
	}

	return true, nil
}

func verifyAdmClusterRoleBinding(rolename, rolebindingname string) (bool, error) {
	obj, err := global.ORCH.GetResource(resource.K8sRscTypeClusRoleBinding, k8s.AllNamespaces, rolebindingname)
	if err != nil {
		err = fmt.Errorf("Cannot find clusterrolebinding %s(%s). ", rolebindingname, err.Error())
	} else {
		if rb, ok := obj.(*rbacv1.ClusterRoleBinding); ok && rb != nil {
			role := rb.GetRoleRef()
			if role != nil && role.Name != nil && *role.Name == rolename {
				for _, s := range rb.GetSubjects() {
					// do not check serviceAccountName in case customer changes it to value other than "default"
					if s.GetKind() == "ServiceAccount" && s.GetNamespace() == resource.NvAdmSvcNamespace {
						return true, nil
					}
				}
			}
		} else if rb, ok := obj.(*rbacv1b1.ClusterRoleBinding); ok && rb != nil {
			role := rb.GetRoleRef()
			if role != nil && role.Name != nil && *role.Name == rolename {
				for _, s := range rb.GetSubjects() {
					// do not check serviceAccountName in case customer changes it to value other than "default"
					if s.GetKind() == "ServiceAccount" && s.GetNamespace() == resource.NvAdmSvcNamespace {
						return true, nil
					}
				}
			}
		} else {
			err = fmt.Errorf("Unknown object type for clusterrolebinding %s. ", rolebindingname)
		}
	}
	log.WithFields(log.Fields{"rolebinding": rolebindingname, "err": err}).Error()

	return false, err
}

func VerifyAdmClusterRoleBinding() (bool, error) {
	roleBindingMapping := map[string]string{
		resource.NvAdmCtrlRole: resource.NvAdmCtrlRoleBinding,
		resource.NvAppRole:     resource.NvAppRoleBinding,
	}
	for rolename, rolebindingname := range roleBindingMapping {
		if ok, err := verifyAdmClusterRoleBinding(rolename, rolebindingname); !ok {
			return false, err
		}
	}
	return true, nil
}

func TestAdmWebhookConnection(svcname string) (int, error) {
	obj, err := global.ORCH.GetResource(resource.RscTypeService, resource.NvAdmSvcNamespace, svcname)
	if err != nil {
		log.WithFields(log.Fields{"namespace": resource.NvAdmSvcNamespace, "service": svcname, "err": err}).Error("resource no found")
		return TestFailedAtRead, err
	} else {
		keys, exist := svcLabelKeys[svcname]
		if !exist {
			log.WithFields(log.Fields{"service": svcname}).Error("svc labels unknown")
			return TestFailedAtRead, errors.New("svc labels unknown")
		}
		svc := obj.(*corev1.Service)
		if svc != nil && svc.Metadata != nil && svc.Metadata.ResourceVersion != nil {
			if svc.Metadata.Labels == nil {
				svc.Metadata.Labels = make(map[string]string)
			}
			tag := fmt.Sprintf("%d", time.Now().Unix())
			svc.Metadata.Labels[keys.TagKey] = tag
			if _, ok := svc.Metadata.Labels[keys.EchoKey]; ok {
				delete(svc.Metadata.Labels, keys.EchoKey)
				// we need adm webhook server to add 'echo' label later
			}
			err = global.ORCH.UpdateResource(resource.RscTypeService, svc)
			if err != nil {
				log.WithFields(log.Fields{"service": svcname, "svc": svc, "err": err}).Error("update resource failed")
				return TestFailedAtWrite, err
			} else {
				c_sig := make(chan os.Signal, 1)
				signal.Notify(c_sig, os.Interrupt, syscall.SIGTERM)
				ticker := time.Tick(time.Second)
				for i := 0; i < 10; i++ {
					select {
					case <-ticker:
						if err, svcInfo := GetValidateWebhookSvcInfo(svcname); err == nil {
							if svcInfo.LabelTag == tag && svcInfo.LabelEcho == tag {
								// one nv controller processed our UPDATE svc request
								log.WithFields(log.Fields{"tag": tag}).Debug("detected test result")
								return TestSucceeded, nil
							}
						}
					case <-c_sig:
						return TestAborted, nil
					}
				}
			}
		}
	}

	return TestFailed, nil
}

func workSingleK8sNsLabels(addLabelSkip, addLabelStatus bool, nsName string) error {
	obj, err := global.ORCH.GetResource(resource.RscTypeNamespace, "", nsName)
	if err != nil {
		log.WithFields(log.Fields{"addLabelSkip": addLabelSkip, "addLabelStatus": addLabelStatus, "namespace": nsName, "err": err}).Error("resource no found")
		return err
	} else {
		keys := map[string]bool{ // map key is label key, map value is the label key should exist in k8s resource metadata or not
			resource.NsSelectorKeySkipNV:   false,
			resource.NsSelectorKeyStatusNV: false,
		}
		if addLabelSkip {
			keys[resource.NsSelectorKeySkipNV] = true
		}
		if addLabelStatus && resource.NvAdmSvcNamespace == nsName {
			// as long as admission control is enabled, even 'namespace=neuvector' critical allow rule is disabled, label 'statusNeuvector' still exists in neuvector namespace
			keys[resource.NsSelectorKeyStatusNV] = true
		}
		nsObj := obj.(*corev1.Namespace)
		if nsObj != nil && nsObj.Metadata != nil {
			updated := false
			for key, labelShouldExist := range keys {
				if labelShouldExist {
					if nsObj.Metadata.Labels == nil {
						nsObj.Metadata.Labels = make(map[string]string)
					}
					if _, exists := nsObj.Metadata.Labels[key]; exists {
						continue
					}
					nsObj.Metadata.Labels[key] = nsSelectorValue
					updated = true
				} else {
					if nsObj.Metadata.Labels != nil {
						if _, exists := nsObj.Metadata.Labels[key]; exists {
							delete(nsObj.Metadata.Labels, key)
							updated = true
						}
					}
				}
			}
			if updated {
				err = global.ORCH.UpdateResource(resource.RscTypeNamespace, nsObj)
				if err != nil {
					log.WithFields(log.Fields{"nsName": nsName, "err": err}).Error("update resource failed")
					return err
				}
			}
		} else {
			err = fmt.Errorf("ns/metadata is nil")
			log.WithFields(log.Fields{"nsName": nsName}).Error(err)
			return err
		}
	}

	return nil
}

func IsNsSelectorSupported() bool {
	k8sVersionMajor, k8sVersionMinor := resource.GetK8sVersion()
	return k8sVersionMajor == 1 && k8sVersionMinor >= 14
}

func EchoAdmWebhookConnection(tagExpected, svcname string) {
	keys, exist := svcLabelKeys[svcname]
	if !exist {
		log.WithFields(log.Fields{"service": svcname}).Error("svc labels unknown")
		return
	}
	c_sig := make(chan os.Signal, 1)
	signal.Notify(c_sig, os.Interrupt, syscall.SIGTERM)
	ticker := time.Tick(time.Second)
	for i := 0; i < 4; i++ {
		select {
		case <-ticker:
			obj, err := global.ORCH.GetResource(resource.RscTypeService, resource.NvAdmSvcNamespace, svcname)
			if err != nil {
				log.WithFields(log.Fields{"namespace": resource.NvAdmSvcNamespace, "service": svcname, "err": err}).Error("resource no found")
			} else {
				svc, ok := obj.(*corev1.Service)
				if ok && svc != nil && svc.Metadata != nil && svc.Metadata.ResourceVersion != nil && len(svc.Metadata.Labels) > 0 {
					if tag, ok := svc.Metadata.Labels[keys.TagKey]; ok && tag == tagExpected {
						svc.Metadata.Labels[keys.EchoKey] = tag
						err = global.ORCH.UpdateResource(resource.RscTypeService, svc)
						if err != nil {
							log.WithFields(log.Fields{"service": svcname, "svc": svc, "err": err}).Error("update resource failed")
						} else {
							log.WithFields(log.Fields{"tag": tag}).Info("echo test result")
							return
						}
					}
				} else {
					log.WithFields(log.Fields{"svcname": svcname}).Error("unknown type")
				}
			}
		case <-c_sig:
			return
		}
	}
}

func GetSvcLabelKeysForTest(svcname string) (string, string) {
	if keys, exist := svcLabelKeys[svcname]; exist {
		return keys.TagKey, keys.EchoKey
	}
	return "", ""
}

/*[2019/Apr.] do not enable ConfigMap support for env vars yet
func GetK8sConfigMap(cfgMapName, ns string) (*corev1.ConfigMap, error) {
	obj, err := global.ORCH.GetResource(resource.RscTypeConfigMap, ns, cfgMapName)
	if err != nil {
		log.WithFields(log.Fields{"ns": ns, "cfgMapName": cfgMapName, "err": err}).Error("resource no found")
		return nil, err
	}

	cm, ok := obj.(*corev1.ConfigMap)
	if !ok {
		log.WithFields(log.Fields{"cfgMapName": cfgMapName, "ns": ns}).Error("unknown type")
	}

	return cm, nil
}

func VerifyConfigMapPermission() bool {
	objs, err := global.ORCH.ListResource(resource.RscTypeConfigMap)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("resource no found")
		return false
	}
	if len(objs) > 0 {
		resCfgMap := objs[0].(*resource.ConfigMap)
		if resCfgMap != nil {
			if _, err := GetK8sConfigMap(resCfgMap.Name, resCfgMap.Domain); err == nil {
				return true
			} else {
				log.WithFields(log.Fields{"name": resCfgMap.Name, "namespace": resCfgMap.Domain, "err": err}).Error("get resource failed")
			}
		}
		return false
	}

	return true
}*/

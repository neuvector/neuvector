package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	admission "github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg"
	nvsysadmission "github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg/admission"
	"github.com/neuvector/neuvector/controller/opa"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/controller/scan"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/utils"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	appsv1 "k8s.io/api/apps/v1"
	k8sCorev1 "k8s.io/api/core/v1"
)

const (
	retryClusterMax = 3

	andDelim = " and "
	orDelim  = " or "

	setDelim = ","

	_criticalRulesOnly = 0
)

const (
	_matchedSrcImageLabels     = "image labels"
	_matchedSrcResourceLabels  = "resource labels"
	_matchedSrcBothLabels      = "resource and image labels"
	_matchedSrcImageEnvVars    = "image environment variables"
	_matchedSrcResourceEnvVars = "resource environment variables"
	_matchedSrcBothEnvVars     = "resource and image environment variables"

	_matchedSrcResourceAnnotations = "resource annotations"
)

var admUriStates map[string]*nvsysadmission.AdmUriState // key is uri for admission request
var admStats share.CLUSAdmissionStats
var admLocalStats share.CLUSAdmissionStats // local processed allowed/denied requests count. flushed after written to cluster
var admStateCache share.CLUSAdmissionState
var admValidateDenyCache share.CLUSAdmissionRules
var admValidateExceptCache share.CLUSAdmissionRules
var admFedValidateExceptionCache share.CLUSAdmissionRules
var admFedValidateDenyCache share.CLUSAdmissionRules
var admCacheMutex sync.RWMutex // only for setting/getting admission control 'enable' state. Notice: cacheMutex could already be held when admCacheMutex.Lock() is called
var nvDeployStatus map[string]bool
var nvDeployDeleted uint32 // non-zero means nv deployment is being deleted
var whRevertCount uint32   // ValidatingWebhookConfiguration neuvector-validating-admission-webhook revert count (because of unknown matchExpressions keys)
var initFedRole string

var reservedRegs = make(map[string][]string)

var critDisplayName map[string]string = map[string]string{
	share.CriteriaKeyImageRegistry:                 "image registry",
	share.CriteriaKeyK8sGroups:                     "user groups",
	share.CriteriaKeyMountVolumes:                  "mount volumes",
	share.CriteriaKeyEnvVars:                       "environment variables",
	share.CriteriaKeyCVENames:                      "CVE names",
	share.CriteriaKeyCVECriticalCount:              "count of critical severity CVE",
	share.CriteriaKeyCVEHighCount:                  "count of high and critical severity CVE",
	share.CriteriaKeyCVEHighCountNoCritical:        "count of high severity CVE, not including critical severity CVE",
	share.CriteriaKeyCVEMediumCount:                "count of medium severity CVE",
	share.CriteriaKeyCVECriticalWithFixCount:       "count of critical severity CVE with fix",
	share.CriteriaKeyCVEHighWithFixCount:           "count of high and critical severity CVE with fix",
	share.CriteriaKeyCVEHighWithFixCountNoCritical: "count of high severity CVE with fix, not including critical severity CVE with fix",
	share.CriteriaKeyCVEScoreCount:                 "CVE score",
	share.CriteriaKeyImageScanned:                  "image scanned",
	share.CriteriaKeyRunAsPrivileged:               "run as privileged",
	share.CriteriaKeyRunAsRoot:                     "run as root",
	share.CriteriaKeyImageCompliance:               "image compliance violations",
	share.CriteriaKeyEnvVarSecrets:                 "environment variables with secrets",
	share.CriteriaKeyImageNoOS:                     "image without OS information",
	share.CriteriaKeySharePidWithHost:              "share host's PID namespaces",
	share.CriteriaKeyShareIpcWithHost:              "share host's IPC namespaces",
	share.CriteriaKeyShareNetWithHost:              "share host's network",
	share.CriteriaKeyAllowPrivEscalation:           "allow privilege escalation",
	share.CriteriaKeyPspCompliance:                 "PSP best practice violation",
	share.CriteriaKeyRequestLimit:                  "resource limitation",
	share.CriteriaKeyCustomPath:                    "custom path violation",
	share.CriteriaKeySaBindRiskyRole:               "service account bounds high risk role violation",
	share.CriteriaKeyImageVerifiers:                "image verifiers",
	share.CriteriaKeyStorageClassName:              "StorageClass name",
}

var critDisplayName2 map[string]string = map[string]string{ // for criteria that have sub-criteria
	share.CriteriaKeyCVECriticalCount:              "more than %s critical severity CVEs that were reported before %s days ago",
	share.CriteriaKeyCVEHighCount:                  "more than %s high and critical severity CVEs that were reported before %s days ago",
	share.CriteriaKeyCVEHighCountNoCritical:        "more than %s high severity CVEs that were reported before %s days ago",
	share.CriteriaKeyCVEMediumCount:                "more than %s medium severity CVEs that were reported before %s days ago",
	share.CriteriaKeyCVECriticalWithFixCount:       "more than %s critical severity CVEs with fix that were reported before %s days ago",
	share.CriteriaKeyCVEHighWithFixCount:           "more than %s high and critical severity CVEs with fix that were reported before %s days ago",
	share.CriteriaKeyCVEHighWithFixCountNoCritical: "more than %s high severity CVEs with fix that were reported before %s days ago",
	share.CriteriaKeyCVEScoreCount:                 "more than %s CVEs whose score >= %s",
}

var predefinedRiskyRoles map[string]string = map[string]string{
	"risky_role_view_secret":         "view secret",
	"risky_role_any_action_workload": "do any action on workload resources",
	"risky_role_any_action_rbac":     "do any action on rbac resources",
	"risky_role_create_pod":          "create workload resources",
	"risky_role_exec_into_container": "execute into container",
}

func initStateCache(svcName string, stateCache *share.CLUSAdmissionState) {
	state, _ := clusHelper.GetAdmissionStateRev(svcName)
	if state != nil {
		*stateCache = *state
	}
	stateCache.CtrlStates = make(map[string]*share.CLUSAdmCtrlState) // key is admType
	for _, admType := range admission.GetAdmissionCtrlTypes(localDev.Host.Platform) {
		stateCache.CtrlStates[admType] = &share.CLUSAdmCtrlState{}
		if state != nil && state.CtrlStates != nil {
			ctrlState := state.CtrlStates[admType]
			if ctrlState != nil && ctrlState.Uri != "" {
				stateCache.CtrlStates[admType].Uri = ctrlState.Uri
				if svcName == resource.NvCrdSvcName {
					stateCache.Enable = state.Enable
					stateCache.CtrlStates[admType].Enable = ctrlState.Enable
				}
			}
		}
	}
}

func initCache() {
	admUriStates = make(map[string]*nvsysadmission.AdmUriState) // key is uri for admission request

	initStateCache(resource.NvAdmSvcName, &admStateCache)

	cacheMutexLock()
	defer cacheMutexUnlock()

	var checkAllowNsRuleCfgType share.TCfgType
	m := clusHelper.GetFedMembership()
	if m != nil {
		fedMembershipCache.FedRole = m.FedRole
		if fedMembershipCache.FedRole != api.FedRoleNone {
			checkAllowNsRuleCfgType = share.FederalCfg
		} else {
			checkAllowNsRuleCfgType = share.UserCreated
			ruleTypes := [2]string{api.ValidatingExceptRuleType, api.ValidatingDenyRuleType}
		Exit:
			for _, ruleType := range ruleTypes {
				if arhs, err := clusHelper.GetAdmissionRuleList(admission.NvAdmValidateType, ruleType); err == nil {
					for _, arh := range arhs {
						if arh.CfgType == share.GroundCfg {
							checkAllowNsRuleCfgType = share.GroundCfg
							continue Exit
						}
					}
				}
			}
		}
	}

	defAllowedNS := utils.NewSet()     // namespaces in critical(default) allow rules, enabled or not
	allAllowedNS := utils.NewSet()     // all effectively allowed namespaces that do no contain wildcard character
	allAllowedNsWild := utils.NewSet() // all effectively allowed namespaces that contain wildcard character
	ruleTypes := [4]string{api.ValidatingExceptRuleType, api.ValidatingDenyRuleType, share.FedAdmCtrlExceptRulesType, share.FedAdmCtrlDenyRulesType}
	ruleCaches := [4]*share.CLUSAdmissionRules{&admValidateExceptCache, &admValidateDenyCache, &admFedValidateExceptionCache, &admFedValidateDenyCache}
	for idx, ruleType := range ruleTypes {
		arhs, err := clusHelper.GetAdmissionRuleList(admission.NvAdmValidateType, ruleType)
		if err != nil && err.Error() == cluster.ErrKeyNotFound.Error() {
			clusHelper.PutAdmissionRuleList(admission.NvAdmValidateType, ruleType, arhs)
		}
		ruleCaches[idx].RuleMap = make(map[uint32]*share.CLUSAdmissionRule, len(arhs)) // key is ruleID
		ruleCaches[idx].RuleHeads = make([]*share.CLUSRuleHead, 0, len(arhs))
		for _, arh := range arhs {
			r := clusHelper.GetAdmissionRule(admission.NvAdmValidateType, ruleType, arh.ID)
			if r != nil {
				rh := &share.CLUSRuleHead{
					ID: r.ID,
				}
				for _, crt := range r.Criteria {
					switch crt.Op {
					case share.CriteriaOpContainsAll, share.CriteriaOpContainsAny, share.CriteriaOpNotContainsAny, share.CriteriaOpContainsOtherThan,
						share.CriteriaOpRegexContainsAny, share.CriteriaOpRegexNotContainsAny:
						crt.ValueSlice = strings.Split(crt.Value, setDelim)
						for i, value := range crt.ValueSlice {
							crt.ValueSlice[i] = strings.TrimSpace(value)
						}
					}
				}
				ruleCaches[idx].RuleMap[arh.ID] = r
				ruleCaches[idx].RuleHeads = append(ruleCaches[idx].RuleHeads, rh)

				if r.RuleType == api.ValidatingExceptRuleType {
					if qualifiedRule := (r.Critical || r.CfgType == checkAllowNsRuleCfgType); qualifiedRule {
						for _, crt := range r.Criteria {
							if crt.Name != share.CriteriaKeyNamespace || crt.Op != share.CriteriaOpContainsAny {
								qualifiedRule = false
								break
							}
						}
						if qualifiedRule {
							// reaching here means this critical/fed allow rule contains {namespace is in <namespaces>}-only criteria
							for _, crt := range r.Criteria {
								for _, ns := range strings.Split(crt.Value, setDelim) {
									if !r.Disable {
										if strings.Contains(ns, "*") {
											allAllowedNsWild.Add(ns)
										} else {
											allAllowedNS.Add(ns)
										}
									}
									if r.Critical {
										defAllowedNS.Add(ns)
									}
								}
							}
						}
					}
				}
			}
		}
	}
	if localDev.Host.Platform == share.PlatformKubernetes {
		if admission.IsNsSelectorSupported() {
			installID, _ := clusHelper.GetInstallationID()
			admission.InitK8sNsSelectorInfo(allAllowedNS, allAllowedNsWild, defAllowedNS, installID, admStateCache.Enable)
		}

		var svcAvailable bool
		if _, err := global.ORCH.GetResource(resource.RscTypeService, resource.NvAdmSvcNamespace, resource.NvAdmSvcName); err == nil {
			svcAvailable = true
		}
		setAdmCtrlStateInCluster(admission.NvAdmValidateType, resource.NvAdmSvcName, admStateCache.Enable, &svcAvailable)
	}
	updateNvDeployStatus(nil)

	reservedRegs["dockerhub"] = []string{"https://index.docker.io/", "https://registry.hub.docker.com/", "https://registry-1.docker.io/"}
	reservedRegs["docker.io"] = reservedRegs["dockerhub"]
}

// Notice: cacheMutex could already be held when admCacheMutex.Lock() is called
func admCacheMutexLock() {
	cctx.MutexLog.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("Acquire ...")
	admCacheMutex.Lock()
}

func admCacheMutexUnlock() {
	admCacheMutex.Unlock()
	cctx.MutexLog.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("Released")
}

func admCacheMutexRLock() {
	cctx.MutexLog.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("Acquire ...")
	admCacheMutex.RLock()
}

func admCacheMutexRUnlock() {
	admCacheMutex.RUnlock()
	cctx.MutexLog.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("Released")
}

func selectAdminPolicyCache(admType, ruleType string) *share.CLUSAdmissionRules {
	if admType == admission.NvAdmValidateType {
		if ruleType == api.ValidatingDenyRuleType {
			return &admValidateDenyCache
		} else if ruleType == api.ValidatingExceptRuleType {
			return &admValidateExceptCache
		} else if ruleType == share.FedAdmCtrlExceptRulesType {
			return &admFedValidateExceptionCache
		} else if ruleType == share.FedAdmCtrlDenyRulesType {
			return &admFedValidateDenyCache
		}
	}
	log.WithFields(log.Fields{"admType": admType, "ruleType": ruleType}).Error("Admission policy cache not found")
	return nil
}

func admissionRule2REST(rule *share.CLUSAdmissionRule) *api.RESTAdmissionRule {
	criteria := make([]*api.RESTAdmRuleCriterion, 0, len(rule.Criteria))
	for _, crit := range rule.Criteria {
		c := &api.RESTAdmRuleCriterion{
			Name:      crit.Name,
			Op:        crit.Op,
			Value:     crit.Value,
			Type:      crit.Type,
			Kind:      crit.Kind,
			Path:      crit.Path,
			ValueType: crit.ValueType,
		}
		if len(crit.SubCriteria) > 0 {
			c.SubCriteria = make([]*api.RESTAdmRuleCriterion, 0, len(crit.SubCriteria))
			for _, subCrt := range crit.SubCriteria {
				c2 := &api.RESTAdmRuleCriterion{
					Name:  subCrt.Name,
					Op:    subCrt.Op,
					Value: subCrt.Value,
				}
				c.SubCriteria = append(c.SubCriteria, c2)
			}
		}
		criteria = append(criteria, c)
	}
	r := api.RESTAdmissionRule{
		ID:       rule.ID,
		Category: rule.Category,
		Comment:  rule.Comment,
		Criteria: criteria,
		Disable:  rule.Disable,
		Critical: rule.Critical,
		RuleType: rule.RuleType,
		RuleMode: rule.RuleMode,
	}
	r.CfgType, _ = cfgTypeMapping[rule.CfgType]
	if rule.CfgType == share.FederalCfg {
		if r.RuleType == share.FedAdmCtrlExceptRulesType {
			r.RuleType = api.ValidatingExceptRuleType
		} else if r.RuleType == share.FedAdmCtrlDenyRulesType {
			r.RuleType = api.ValidatingDenyRuleType
		}
	}
	if rule.Containers&share.AdmCtrlRuleContainersN > 0 {
		r.Containers = append(r.Containers, share.AdmCtrlRuleContainers)
	}
	if rule.Containers&share.AdmCtrlRuleInitContainersN > 0 {
		r.Containers = append(r.Containers, share.AdmCtrlRuleInitContainers)
	}
	if rule.Containers&share.AdmCtrlRuleEphemeralContainersN > 0 {
		r.Containers = append(r.Containers, share.AdmCtrlRuleEphemeralContainers)
	}
	if len(r.Containers) == 0 {
		r.Containers = []string{share.AdmCtrlRuleContainers}
	}

	return &r
}

func setAdmCtrlStateInCluster(admType, svcName string, enable bool, svcAvailable *bool) {
	retry := 0
	for retry < retryClusterMax {
		if state, rev := clusHelper.GetAdmissionStateRev(svcName); state != nil {
			updated := false
			if svcName == resource.NvCrdSvcName {
				if state.FailurePolicy != resource.IgnoreLower || state.TimeoutSeconds != resource.DefTimeoutSeconds {
					state.FailurePolicy = resource.IgnoreLower
					state.TimeoutSeconds = resource.DefTimeoutSeconds
					updated = true
				}
			}
			if state.Enable != enable || state.CtrlStates[admType].Enable != enable {
				state.Enable = enable
				state.CtrlStates[admType].Enable = enable
				updated = true
			}
			if svcAvailable != nil && *svcAvailable != state.NvDeployStatus[svcName] {
				state.NvDeployStatus[svcName] = *svcAvailable
				updated = true
			}
			if updated {
				if err := clusHelper.PutAdmissionStateRev(svcName, state, rev); err == nil {
					break
				}
			} else {
				return
			}
		} else {
			kv.CreateAdmCtrlStateByName(svcName, enable)
		}
		retry++
	}
}

// cache mutex is owned by caller
func updateNvDeployStatus(status map[string]bool) (updated, nvInstalled bool) {
	updated = false
	nvInstalled = true
	if localDev.Host.Platform != share.PlatformKubernetes {
		return
	}

	nvInstalled = false
	if len(nvDeployStatus) == 0 {
		nvDeployStatus = map[string]bool{
			resource.NvDeploymentName: true,
			resource.NvAdmSvcName:     false,
			resource.NvCrdSvcName:     false,
		}
	}

	if len(status) > 0 {
		for k, v := range nvDeployStatus {
			if value, exist := status[k]; exist && v != value {
				nvDeployStatus[k] = value
				updated = true
			}
			// we assume NV is being uninstalled when the required resources
			// (neuvector-controller-pod/neuvector-allinone-pod & neuvector-svc-admission-webhook) are all gone,
			nvInstalled = nvInstalled || nvDeployStatus[k]
		}
	}

	return
}

func evalAdmCtrlRulesForAllowedNS(admCtrlEnabled bool) {
	if localDev.Host.Platform != share.PlatformKubernetes || !admission.IsNsSelectorSupported() {
		return
	}

	newAllowedNS := utils.NewSet()     // namespaces(without wildcard char) in critical/fed allow rules only
	newAllowedNsWild := utils.NewSet() // namespaces(with wildcard char) in critical/fed allow rules only
	if admCtrlEnabled {
		var checkAllowNsRuleCfgType share.TCfgType
		fedRole := fedMembershipCache.FedRole
		if fedRole != api.FedRoleNone {
			checkAllowNsRuleCfgType = share.FederalCfg
		} else {
			checkAllowNsRuleCfgType = share.UserCreated
			ruleCaches := [2]*share.CLUSAdmissionRules{&admValidateExceptCache, &admValidateDenyCache}
		Exit:
			for _, ruleCache := range ruleCaches {
				for _, r := range ruleCache.RuleMap {
					if r.CfgType == share.GroundCfg {
						checkAllowNsRuleCfgType = share.GroundCfg
						continue Exit
					}
				}
			}
		}

		for _, allowedRulesCache := range []*share.CLUSAdmissionRules{&admFedValidateExceptionCache, &admValidateExceptCache} {
			for _, r := range allowedRulesCache.RuleMap {
				if !r.Disable && r.RuleType == api.ValidatingExceptRuleType && len(r.Criteria) > 0 {
					if qualifiedRule := (r.Critical || r.CfgType == checkAllowNsRuleCfgType); qualifiedRule {
						for _, crt := range r.Criteria {
							if crt.Name != share.CriteriaKeyNamespace || crt.Op != share.CriteriaOpContainsAny {
								qualifiedRule = false
								break
							}
						}
						if qualifiedRule {
							// reaching here means this critical/fed allow rule contains {namespace is in <namespaces>}-only criteria
							for _, crt := range r.Criteria {
								for _, ns := range strings.Split(crt.Value, setDelim) {
									if strings.Contains(ns, "*") {
										newAllowedNsWild.Add(ns)
									} else {
										newAllowedNS.Add(ns)
									}
								}
							}
						}
					}
				}
			}
		}
	}
	admission.UpdateAllowedK8sNs(isLeader(), admCtrlEnabled, newAllowedNS, newAllowedNsWild)
}

// Do not call admission.ConfigK8sAdmissionControl() in admissionConfigUpdate()
// Currently there are 3 ways to call admission.ConfigK8sAdmissionControl():
// 1. k8s resource watcher's handler
// 2. resp server
// 3. configuration import
func admissionConfigUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	log.Debug("")

	var admType, ruleType string
	var admPolicyCache *share.CLUSAdmissionRules
	cfgType := share.CLUSPolicyKey2AdmCfgSubkey(key)
	if cfgType == share.CLUSAdmissionCfgRule || cfgType == share.CLUSAdmissionCfgRuleList {
		admType, ruleType = share.CLUSPolicyRuleKey2AdmRuleType(key, cfgType)
		admPolicyCache = selectAdminPolicyCache(admType, ruleType)
		if admPolicyCache == nil {
			return
		}
	}

	cacheMutexLock()
	defer cacheMutexUnlock()

	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		switch cfgType {
		case share.CLUSAdmissionCfgState:
			var state share.CLUSAdmissionState
			json.Unmarshal(value, &state)
			updated, nvInstalled := updateNvDeployStatus(state.NvDeployStatus)
			if updated && !nvInstalled {
				atomic.StoreUint32(&nvDeployDeleted, 1)
			}
			if isLeader() && updated && !nvInstalled {
				// if it reaches here, it means cluster is updated about nv deployment being deleted
				for _, nvAdmName := range []string{resource.NvAdmValidatingName, resource.NvCrdValidatingName} {
					if admission.UnregK8sAdmissionControl(admission.NvAdmValidateType, nvAdmName) == nil {
						log.WithFields(log.Fields{"name": nvAdmName}).Info("Unregister admission control in k8s")
					}
				}
				evalAdmCtrlRulesForAllowedNS(false)
				setAdmCtrlStateInCluster(admission.NvAdmValidateType, resource.NvAdmSvcName, false, nil)
				setAdmCtrlStateInCluster(admission.NvAdmValidateType, resource.NvCrdSvcName, false, nil)
			} else {
				evalAllowedNS := (admStateCache.Enable != state.Enable)
				for admType, ctrlState := range state.CtrlStates {
					var category string
					switch admType {
					case admission.NvAdmValidateType:
						category = admission.AdmRuleCatK8s
						if oldState, _ := admStateCache.CtrlStates[admType]; oldState != nil {
							if oldState.Uri != ctrlState.Uri || oldState.NvStatusUri != ctrlState.NvStatusUri {
								var param interface{} = &resource.NvAdmSvcName
								cctx.StartStopFedPingPollFunc(share.RestartWebhookServer, 0, param)
							}
						}
					}
					setAdmCtrlStateCache(admType, category, &state, ctrlState.Uri, ctrlState.NvStatusUri)
				}
				if admStateCache.Enable && !state.Enable {
					whRevertCount = 0
				}
				admStateCache.Enable = state.Enable
				admStateCache.Mode = state.Mode
				admStateCache.DefaultAction = state.DefaultAction
				admStateCache.AdmClientMode = state.AdmClientMode
				admStateCache.FailurePolicy = state.FailurePolicy
				admStateCache.CfgType = state.CfgType
				if evalAllowedNS {
					evalAdmCtrlRulesForAllowedNS(admStateCache.Enable)
				}
			}
		case share.CLUSAdmissionCfgRule:
			var rule share.CLUSAdmissionRule
			json.Unmarshal(value, &rule)
			for _, crt := range rule.Criteria {
				switch crt.Op {
				case share.CriteriaOpContainsAll, share.CriteriaOpContainsAny, share.CriteriaOpNotContainsAny, share.CriteriaOpContainsOtherThan,
					share.CriteriaOpRegexContainsAny, share.CriteriaOpRegexNotContainsAny:
					crt.ValueSlice = strings.Split(crt.Value, setDelim)
					for i, value := range crt.ValueSlice {
						crt.ValueSlice[i] = strings.TrimSpace(value)
					}
				}
			}
			if rule.RuleType == "" {
				rule.RuleType = ruleType
			}
			admPolicyCache.RuleMap[rule.ID] = &rule
			if rule.RuleType == api.ValidatingExceptRuleType || rule.RuleType == share.FedAdmCtrlExceptRulesType {
				evalAdmCtrlRulesForAllowedNS(admStateCache.Enable)
			}

			opa.ConvertToRegoRule(&rule)
			log.WithFields(log.Fields{"nType": nType, "cfgType": cfgType, "rule.ID": rule.ID}).Debug("admissionConfigUpdate, add/modify to opa")
		case share.CLUSAdmissionCfgRuleList:
			var heads []*share.CLUSRuleHead
			json.Unmarshal(value, &heads)
			admPolicyCache.RuleHeads = heads
			ids := utils.NewSet()
			for _, rh := range heads {
				ids.Add(rh.ID)
			}
			evalAllowedNS := false
			for id, r := range admPolicyCache.RuleMap {
				if !ids.Contains(id) {
					delete(admPolicyCache.RuleMap, id)
					opa.DeletePolicy(id)
					log.WithFields(log.Fields{"nType": nType, "cfgType": cfgType, "id": id}).Debug("admissionConfigUpdate, delete OPA")
					if r.RuleType == api.ValidatingExceptRuleType || r.RuleType == share.FedAdmCtrlExceptRulesType {
						evalAllowedNS = true
					}
				}
			}
			if evalAllowedNS {
				evalAdmCtrlRulesForAllowedNS(admStateCache.Enable)
			}
		case share.CLUSAdmissionStatistics:
			var stats share.CLUSAdmissionStats
			json.Unmarshal(value, &stats)
			atomic.StoreUint64(&admStats.K8sAllowedRequests, stats.K8sAllowedRequests)
			atomic.StoreUint64(&admStats.K8sDeniedRequests, stats.K8sDeniedRequests)
			atomic.StoreUint64(&admStats.K8sErroneousRequests, stats.K8sErroneousRequests)
			atomic.StoreUint64(&admStats.K8sIgnoredRequests, stats.K8sIgnoredRequests)
			atomic.StoreInt64(&admStats.K8sProcessingRequests, stats.K8sProcessingRequests)
		}
	case cluster.ClusterNotifyDelete:
		switch cfgType {
		case share.CLUSAdmissionCfgRule:
			id := share.CLUSPolicyRuleKey2ID(key)
			if _, ok := admPolicyCache.RuleMap[id]; ok {
				delete(admPolicyCache.RuleMap, id)
				opa.DeletePolicy(id)
			}
		case share.CLUSAdmissionCfgRuleList:
			heads := make([]*share.CLUSRuleHead, 0)
			admPolicyCache.RuleHeads = heads
			admPolicyCache.RuleMap = make(map[uint32]*share.CLUSAdmissionRule, 0)
		}
	}
}

func admissionRuleInit() {
	if localDev.Host.Platform == share.PlatformKubernetes {
		if localDev.Host.Flavor == share.FlavorOpenShift {
			resource.AdjustAdmResForOC()
		}
	}

	initCache()
	nvsysadmission.GetAdmRuleTypeOptions(api.ValidatingDenyRuleType)
}

func isStringCriterionMet(crt *share.CLUSAdmRuleCriterion, value string) (bool, bool) {
	switch crt.Op {
	case share.CriteriaOpEqual:
		return share.EqualMatch(crt.Value, value), true
	case share.CriteriaOpNotEqual:
		return !share.EqualMatch(crt.Value, value), false
	case share.CriteriaOpContains:
		return strings.Contains(value, crt.Value), true
	case share.CriteriaOpPrefix:
		return strings.HasPrefix(value, crt.Value), true
	case share.CriteriaOpRegex, share.CriteriaOpRegex_Deprecated:
		matched, _ := regexp.MatchString(crt.Value, value)
		return matched, true
	case share.CriteriaOpNotRegex, share.CriteriaOpNotRegex_Deprecated:
		matched, _ := regexp.MatchString(crt.Value, value)
		return !matched, false
	case share.CriteriaOpContainsAll, share.CriteriaOpContainsAny, share.CriteriaOpNotContainsAny, share.CriteriaOpContainsOtherThan,
		share.CriteriaOpRegexContainsAny, share.CriteriaOpRegexNotContainsAny:
		valueSet := utils.NewSet(value)
		return isSetCriterionMet(crt, valueSet)
	default:
		log.WithFields(log.Fields{"name": crt.Name, "op": crt.Op}).Error("unsupported op")
	}

	return false, true
}

func isNumericCriterionMet(crt *share.CLUSAdmRuleCriterion, v1 interface{}, v2 interface{}) (bool, bool) {
	var number1, number2 float64
	var err1, err2 error

	switch v := v1.(type) {
	case *int:
		number1 = float64(*v)
	case *int64:
		number1 = float64(*v)
	case *float32:
		number1 = float64(*v)
	case *float64:
		number1 = float64(*v)
	case *string:
		number1, err1 = strconv.ParseFloat(*v, 64)
	default:
		err1 = errors.New("unsupported type")
		log.WithFields(log.Fields{"name": crt.Name}).Error(err1.Error())
	}
	switch v := v2.(type) {
	case *int:
		number2 = float64(*v)
	case *int64:
		number2 = float64(*v)
	case *float32:
		number2 = float64(*v)
	case *float64:
		number2 = float64(*v)
	case *string:
		number2, err2 = strconv.ParseFloat(*v, 64)
	default:
		err2 = errors.New("unsupported type")
		log.WithFields(log.Fields{"name": crt.Name}).Error(err2.Error())
	}

	if err1 == nil && err2 == nil {
		switch crt.Op {
		case share.CriteriaOpBiggerEqualThan:
			return number1 >= number2, true
		case share.CriteriaOpBiggerThan:
			return number1 > number2, true
		case share.CriteriaOpLessEqualThan:
			return number1 <= number2, true
		default:
			log.WithFields(log.Fields{"name": crt.Name, "op": crt.Op}).Error("unsupported op")
		}
	}

	return false, true
}

func isCveCountCriterionMet(crt *share.CLUSAdmRuleCriterion, checkWithFix bool, vulsWithFix int, vulInfo map[string]share.CLUSScannedVulInfo) (bool, bool) {
	cveCount := 0
	if len(crt.SubCriteria) > 0 {
		for _, sc := range crt.SubCriteria {
			if sc.Name == share.SubCriteriaPublishDays {
				crtPublishDays, _ := strconv.ParseFloat(crt.SubCriteria[0].Value, 32)
				hoursValue := 24 * crtPublishDays // because criterion value is in days
				if vulInfo != nil {
					for _, vi := range vulInfo {
						if !checkWithFix || (checkWithFix && vi.WithFix) {
							dur := time.Since(time.Unix(vi.PublishDate, 0))
							switch crt.Op {
							case share.CriteriaOpBiggerEqualThan:
								if dur.Hours() >= hoursValue { // found cve that is reported before <days>
									cveCount++
								}
							default:
								log.WithFields(log.Fields{"name": crt.Name, "op": crt.Op}).Error("unsupported op")
							}
						}
					}
				} else {
					// if scan summary is from pre-3.2.2 that doesn't contain HighVulInfo/MediumVulInfo, treat it as always met for SubCriteriaPublishDays criterion
					cveCount++
				}
				return isNumericCriterionMet(crt, &cveCount, &crt.Value)
			} else {
				log.WithFields(log.Fields{"name": sc.Name, "op": sc.Op}).Error("unsupported op")
			}
		}
	} else if checkWithFix { // for cveHighWithFixCount, cveHighWithFixCountNoCritical, cveCriticalWithFixCount
		cveCount = vulsWithFix
	} else { // for cveHighCount, cveMediumCount
		cveCount = len(vulInfo)
	}
	return isNumericCriterionMet(crt, &cveCount, &crt.Value)
}

func isCveScoreCountCriterionMet(crt *share.CLUSAdmRuleCriterion, highVulInfo, mediumVulInfo map[string]share.CLUSScannedVulInfo,
	lowVulInfo []share.CLUSScannedVulInfoSimple) (bool, bool) {
	cveCount := 0
	if len(crt.SubCriteria) > 0 {
		crtSub := crt.SubCriteria[0]
		if crt.Name != share.CriteriaKeyCVEScoreCount || crt.Op != share.CriteriaOpBiggerEqualThan ||
			crtSub.Name != share.SubCriteriaCount || crtSub.Op != share.CriteriaOpBiggerEqualThan {
			log.WithFields(log.Fields{"name": crt.Name, "op": crt.Op, "nameSub": crtSub.Name, "opSub": crtSub.Op}).Error("unsupported op")
		} else {
			if score, err := strconv.ParseFloat(crt.Value, 32); err == nil {
				cveScore := float32(score)
				vulInfos := []map[string]share.CLUSScannedVulInfo{highVulInfo, mediumVulInfo}
				for _, vulInfo := range vulInfos {
					for _, vi := range vulInfo {
						if vi.Score >= cveScore { // found a cve that has score matched the criterion value
							cveCount++
						}
					}
				}
				for _, vi := range lowVulInfo {
					if vi.Score >= cveScore { // found a cve that has score matched the criterion value
						cveCount++
					}
				}
				return isNumericCriterionMet(crtSub, &cveCount, &crtSub.Value)
			}
		}
	}
	return false, true
}

func isSetCriterionMet(crt *share.CLUSAdmRuleCriterion, valueSet utils.Set) (bool, bool) {
	if valueSet.Cardinality() > 0 {
		switch crt.Op {
		case share.CriteriaOpRegex, share.CriteriaOpNotRegex:
			if regex, err := regexp.Compile(crt.Value); err == nil {
				for value := range valueSet.Iter() {
					if regex.MatchString(value.(string)) {
						if crt.Op == share.CriteriaOpRegex {
							return true, true
						} else {
							return false, false
						}
					}
				}
			}
		case share.CriteriaOpContainsAll, share.CriteriaOpContainsAny, share.CriteriaOpNotContainsAny,
			share.CriteriaOpRegexContainsAny, share.CriteriaOpRegexNotContainsAny:
			for _, crtValue := range crt.ValueSlice {
				switch crt.Op {
				case share.CriteriaOpContainsAll:
					found := false
					for value := range valueSet.Iter() {
						if share.EqualMatch(crtValue, value.(string)) {
							found = true
							break
						}
					}
					if !found {
						return false, true
					}
				case share.CriteriaOpContainsAny:
					for value := range valueSet.Iter() {
						if share.EqualMatch(crtValue, value.(string)) {
							return true, true
						}
					}
				case share.CriteriaOpNotContainsAny:
					for value := range valueSet.Iter() {
						if share.EqualMatch(crtValue, value.(string)) {
							return false, false
						}
					}
				case share.CriteriaOpRegexContainsAny, share.CriteriaOpRegexNotContainsAny:
					if regex, err := regexp.Compile(crtValue); err == nil {
						for value := range valueSet.Iter() {
							if regex.MatchString(value.(string)) {
								if crt.Op == share.CriteriaOpRegexContainsAny {
									return true, true
								} else {
									return false, false
								}
							}
						}
					}
				}
			}
		case share.CriteriaOpContainsOtherThan:
			for value := range valueSet.Iter() {
				found := false
				for _, crtValue := range crt.ValueSlice {
					if share.EqualMatch(crtValue, value.(string)) {
						found = true
						break
					}
				}
				if !found {
					return true, true
				}
			}
		default:
			log.WithFields(log.Fields{"name": crt.Name, "op": crt.Op}).Error("unsupported op")
		}
	}
	switch crt.Op {
	case share.CriteriaOpContainsAll:
		if valueSet.Cardinality() > 0 {
			return true, true
		} else {
			return false, true
		}
	case share.CriteriaOpContainsAny, share.CriteriaOpRegexContainsAny, share.CriteriaOpRegex:
		return false, true
	case share.CriteriaOpNotContainsAny, share.CriteriaOpRegexNotContainsAny, share.CriteriaOpNotRegex:
		return true, false
	case share.CriteriaOpContainsOtherThan:
		return false, true
	default:
		return false, true
	}
}

type criterionValue struct {
	Value    string
	Operator string
	Test     func(string, string) bool
}

func doesCrtContainProp(propKey, propValue string, kvMap map[string][]criterionValue) bool {
	if crtValues, exist := kvMap[propKey]; exist {
		// kvMap contains propKey
		for _, crtValue := range crtValues {
			if crtValue.Test(crtValue.Value, propValue) {
				return true
			}
		}
	}
	return false
}

// does propMap contain key=value(when value is not "") or key(when value is "")
func doesPropMapMatchCrtValue(key string, crtVal criterionValue, propMap map[string][]string) bool {
	if propValues, exist := propMap[key]; exist {
		for _, propValue := range propValues {
			if crtVal.Test(crtVal.Value, propValue) {
				return true
			}
		}
	}
	return false
}

func getValidMapOperators(crt *share.CLUSAdmRuleCriterion) []string {
	validOperators := []string{"="}

	if crt.Name == share.CriteriaKeyModules {
		validOperators = append(validOperators, []string{">", "<", ">=", "<="}...)
	}

	return validOperators
}

func getCrtValOperator(crtValString string, validOperators []string) (string, int) {
	for _, operator := range validOperators {
		if operatorIndex := strings.Index(crtValString, operator); operatorIndex >= 0 {
			// The following checks ensure that something like the ">=" operator
			// doesn't get interpreted as the "=" or ">" operator
			if operator == "=" && operatorIndex != 0 {
				prevChar := string(crtValString[operatorIndex-1])
				if prevChar == ">" || prevChar == "<" {
					continue
				}
			}
			if (operator == ">" || operator == "<") && operatorIndex != len(crtValString)-1 {
				nextChar := string(crtValString[operatorIndex+1])
				if nextChar == "=" {
					continue
				}
			}
			return operator, operatorIndex
		}
	}
	return "", -1
}

func getCrtTestFunction(crt *share.CLUSAdmRuleCriterion, comparisonOp string) func(string, string) bool {
	if comparisonOp == "EXISTS" {
		return func(crtVal string, propVal string) bool {
			// if this function is being run, its because the same key exists in a propMap
			// and a crtValueMap, thus return true
			return true
		}
	}

	if crt.Name == share.CriteriaKeyModules {
		switch comparisonOp {
		case ">":
			return func(crtVal string, propVal string) bool {
				propVersion, propErr := utils.NewVersion(propVal)
				crtVersion, crtErr := utils.NewVersion(crtVal)

				if propErr != nil || crtErr != nil {
					// when a semantic version isn't provided in the criteria or propMap
					// fail comparison by default by returning false
					return false
				}

				return propVersion.Compare(crtVersion) == 1
			}
		case "<":
			return func(crtVal string, propVal string) bool {
				propVersion, propErr := utils.NewVersion(propVal)
				crtVersion, crtErr := utils.NewVersion(crtVal)

				if propErr != nil || crtErr != nil {
					return false
				}

				return propVersion.Compare(crtVersion) == -1
			}
		case ">=":
			return func(crtVal string, propVal string) bool {
				propVersion, propErr := utils.NewVersion(propVal)
				crtVersion, crtErr := utils.NewVersion(crtVal)

				if propErr != nil || crtErr != nil {
					return false
				}

				return propVersion.Compare(crtVersion) >= 0
			}
		case "<=":
			return func(crtVal string, propVal string) bool {
				propVersion, propErr := utils.NewVersion(propVal)
				crtVersion, crtErr := utils.NewVersion(crtVal)

				if propErr != nil || crtErr != nil {
					return false
				}

				return propVersion.Compare(crtVersion) <= 0
			}
		}
	}

	return func(crtVal string, propVal string) bool {
		return share.EqualMatch(crtVal, propVal)
	}
}

func isComplexMapCriterionMet(crt *share.CLUSAdmRuleCriterion, propMap map[string][]string) (bool, bool) {
	if len(propMap) > 0 {
		crtValMap := map[string][]criterionValue{}
		for _, crtValString := range crt.ValueSlice {
			var key string
			var val criterionValue
			if operator, operatorIndex := getCrtValOperator(crtValString, getValidMapOperators(crt)); operator != "" {
				key = strings.TrimSpace(crtValString[:operatorIndex])
				val = criterionValue{
					Value:    strings.TrimSpace(crtValString[operatorIndex+len(operator):]),
					Operator: operator,
				}
			} else {
				key = strings.TrimSpace(crtValString)
				val = criterionValue{
					Operator: "EXISTS",
				}
			}
			val.Test = getCrtTestFunction(crt, val.Operator)
			crtValMap[key] = append(crtValMap[key], val)
		}

		switch crt.Op {
		case share.CriteriaOpContainsAll, share.CriteriaOpContainsAny, share.CriteriaOpNotContainsAny:
			for key, values := range crtValMap {
				for _, value := range values {
					switch crt.Op {
					case share.CriteriaOpContainsAll:
						if !doesPropMapMatchCrtValue(key, value, propMap) {
							return false, true
						}
					case share.CriteriaOpContainsAny:
						if doesPropMapMatchCrtValue(key, value, propMap) {
							return true, true
						}
					case share.CriteriaOpNotContainsAny:
						if doesPropMapMatchCrtValue(key, value, propMap) {
							return false, false
						}
					default:
						log.WithFields(log.Fields{"name": crt.Name, "op": crt.Op}).Error("unsupported op")
					}
				}
			}
		case share.CriteriaOpContainsOtherThan:
			for propKey, propValues := range propMap {
				for _, propValue := range propValues {
					if !doesCrtContainProp(propKey, propValue, crtValMap) {
						// in propMap there is an entry that doesn't match crtValue
						return true, true
					}
				}
			}
		default:
			log.WithFields(log.Fields{"name": crt.Name, "op": crt.Op}).Error("unsupported op")
		}
	}
	switch crt.Op {
	case share.CriteriaOpContainsAll:
		if len(propMap) > 0 {
			return true, true
		} else {
			return false, true
		}
	case share.CriteriaOpContainsAny:
		return false, true
	case share.CriteriaOpNotContainsAny:
		return true, false
	case share.CriteriaOpContainsOtherThan:
		return false, true
	default:
		return false, true
	}
}

func isMapCriterionMet(crt *share.CLUSAdmRuleCriterion, propMap map[string]string) (bool, bool) {
	complexPropMap := map[string][]string{}
	for key, value := range propMap {
		complexPropMap[key] = []string{value}
	}
	return isComplexMapCriterionMet(crt, complexPropMap)
}

func isResourceLimitCriterionMet(crt *share.CLUSAdmRuleCriterion, c *nvsysadmission.AdmContainerInfo) (bool, bool) {
	if len(crt.SubCriteria) > 0 {
		cpuCfgInYaml := map[string]float64{
			share.SubCriteriaCpuLimit:   c.CpuLimits,
			share.SubCriteriaCpuRequest: c.CpuRequests,
		}
		memoryCfgInYaml := map[string]int64{
			share.SubCriteriaMemoryLimit:   c.MemoryLimits,
			share.SubCriteriaMemoryRequest: c.MemoryRequests,
		}
		for _, sc := range crt.SubCriteria {
			if sc != nil && sc.Value != "" {
				if value, ok := cpuCfgInYaml[sc.Name]; ok && value >= 0 {
					met, positive := isNumericCriterionMet(sc, &value, &sc.Value)
					if met {
						return met, positive
					}
				} else if value, ok := memoryCfgInYaml[sc.Name]; ok && value >= 0 {
					met, positive := isNumericCriterionMet(sc, &value, &sc.Value)
					if met {
						return met, positive
					}
				}
			}
		}
	}
	return false, true
}

func normalizeImageValue(value string, registryOnly bool) string {
	var crtValue string
	var normalized string
	var crtRegistry, crtRepo, crtTag string

	idxProtocol := strings.Index(value, "https://")
	if idxProtocol == 0 {
		crtValue = value[len("https://"):]
	} else {
		crtValue = value
	}
	ss := strings.Split(crtValue, "/")
	if len(ss) > 0 {
		sss := strings.Split(ss[0], ":")
		if len(sss) > 0 && (strings.ContainsAny(sss[0], ".") || sss[0] == "localhost") { // ex: 10.1.127.3:5000/...... or localhost:8080/........
			crtRegistry = strings.ToLower(ss[0])
		}
	}
	if !registryOnly {
		if crtRegistry != "" {
			if len(ss) > 1 {
				crtValue = strings.Join(ss[1:], "/")
			} else {
				crtValue = ""
			}
		}
		if idxTag := strings.LastIndex(crtValue, ":"); idxTag > 0 { // ex: 10.1.127.3:5000/nvlab/iperf:latest or nvlab/iperf:latest
			crtRepo = crtValue[:idxTag]
			crtTag = crtValue[idxTag+1:]
		} else { // ex: 10.1.127.3:5000/nvlab/iperf or nvlab/iperf
			crtRepo = crtValue
		}
		if crtRepo != "" {
			crtRepo = strings.ToLower(crtRepo)
		}
	}

	if crtRegistry != "" {
		if crtRepo != "" && crtTag != "" {
			normalized = fmt.Sprintf("https://%s/%s:%s", crtRegistry, crtRepo, crtTag)
		} else if crtRepo != "" {
			normalized = fmt.Sprintf("https://%s/%s", crtRegistry, crtRepo)
		} else if crtTag != "" {
			normalized = fmt.Sprintf("https://%s/:%s", crtRegistry, crtTag)
		} else {
			normalized = fmt.Sprintf("https://%s/", crtRegistry)
		}
	} else {
		if crtRepo != "" && crtTag != "" {
			normalized = fmt.Sprintf("%s:%s", crtRepo, crtTag)
		} else if crtRepo != "" {
			normalized = crtRepo
		} else if crtTag != "" {
			normalized = fmt.Sprintf(":%s", crtTag)
		}
	}
	return normalized
}

func matchImageValue(crtOp, crtValue string, c *nvsysadmission.AdmContainerInfo) bool {
	var value string
	matched := false
	crtHasRegistry, crtHasTag := false, false

	idxProtocol := strings.Index(crtValue, "https://")
	if idxProtocol == 0 {
		value = crtValue[len("https://"):]
	} else {
		value = crtValue
	}
	idxRegistry := strings.Index(value, "/")
	if idxRegistry > 0 {
		ss := strings.Split(value[:idxRegistry], ":")
		if len(ss) > 0 && (strings.ContainsAny(ss[0], ".") || ss[0] == "localhost") {
			crtHasRegistry = true
		}
	}
	if idxTag := strings.LastIndex(value, ":"); idxTag > 0 {
		if crtHasRegistry && idxTag > idxRegistry {
			crtHasTag = true // ex: 10.1.127.3:5000/nvlab/iperf:latest
		} else if !crtHasRegistry && idxProtocol != 0 {
			crtHasTag = true // ex: nvlab/iperf:latest
		}
	}
	if crtHasRegistry && idxProtocol != 0 {
		// If crtValue contains registry but not protocol, like index.docker.io/nvlab/iperf, normalize it to https://index.docker.io/nvlab/iperf for comparison
		crtValue = fmt.Sprintf("https://%s", crtValue)
	}
	var fullName string
	for ctnerReg := range c.ImageRegistry.Iter() {
		if crtHasRegistry {
			if crtHasTag {
				if strings.Index(c.ImageTag, "sha") == 0 && strings.Index(c.ImageTag, ":") != -1 {
					fullName = fmt.Sprintf("%s%s@%s", ctnerReg, c.ImageRepo, c.ImageTag) // ex: https://index.docker.io/nvlab/iperf@sha256:6f8ee848131d2fe7fb7fc5c96dab9adba619b55b7f0d87f6c4dbfaf77f7936f5
				} else {
					fullName = fmt.Sprintf("%s%s:%s", ctnerReg, c.ImageRepo, c.ImageTag) // ex: https://index.docker.io/nvlab/iperf:latest
				}
			} else {
				fullName = fmt.Sprintf("%s%s", ctnerReg, c.ImageRepo) // ex: https://index.docker.io/nvlab/iperf
			}
		} else {
			if crtHasTag {
				if strings.Index(c.ImageTag, "sha") == 0 && strings.Index(c.ImageTag, ":") != -1 {
					fullName = fmt.Sprintf("%s@%s", c.ImageRepo, c.ImageTag) // ex: nvlab/iperf@sha256:6f8ee848131d2fe7fb7fc5c96dab9adba619b55b7f0d87f6c4dbfaf77f7936f5
				} else {
					fullName = fmt.Sprintf("%s:%s", c.ImageRepo, c.ImageTag) // ex: nvlab/iperf:latest
				}
			} else {
				fullName = c.ImageRepo // ex: nvlab/iperf
			}
		}
		switch crtOp {
		case share.CriteriaOpRegex:
			matched, _ = regexp.MatchString(crtValue, fullName)
		default:
			matched = share.EqualMatch(crtValue, fullName)
		}
		if !crtHasRegistry || matched {
			break
		}
	}

	return matched
}

// special handling for image criterion because the criterion value could contain both formats like "https://index.docker.io/nvlab/iperf" & "nvlab/iperf"
func isImageCriterionMet(crt *share.CLUSAdmRuleCriterion, c *nvsysadmission.AdmContainerInfo) (bool, bool) {
	switch crt.Op {
	case share.CriteriaOpRegex:
		return matchImageValue(crt.Op, crt.Value, c), true
	case share.CriteriaOpContainsAll, share.CriteriaOpContainsAny, share.CriteriaOpNotContainsAny, share.CriteriaOpContainsOtherThan:
		var matchedFinal, positive bool
		switch crt.Op {
		case share.CriteriaOpContainsAll:
			matchedFinal, positive = true, true
		case share.CriteriaOpContainsAny:
			matchedFinal, positive = false, true
		case share.CriteriaOpNotContainsAny:
			matchedFinal, positive = true, false
		case share.CriteriaOpContainsOtherThan:
			matchedFinal, positive = false, true
		}
		for _, crtValue := range crt.ValueSlice {
			matched := matchImageValue(crt.Op, crtValue, c)
			switch crt.Op {
			case share.CriteriaOpContainsAll:
				matchedFinal = matchedFinal && matched
			case share.CriteriaOpContainsAny:
				matchedFinal = matchedFinal || matched
				if matchedFinal {
					return matchedFinal, true
				}
			case share.CriteriaOpNotContainsAny:
				matchedFinal = matchedFinal && !matched
			case share.CriteriaOpContainsOtherThan:
				matchedFinal = matchedFinal || !matched
				if matchedFinal {
					return matchedFinal, true
				}
			}
		}
		return matchedFinal, positive
	default:
		log.WithFields(log.Fields{"name": crt.Name, "op": crt.Op}).Error("unsupported op")
	}

	return false, true
}

func isModulesCriterionMet(crt *share.CLUSAdmRuleCriterion, modules []*share.ScanModule) (bool, bool) {
	var nameVersionMap map[string][]string = make(map[string][]string)
	for _, module := range modules {
		nameVersionMap[module.Name] = append(nameVersionMap[module.Name], module.Version)
	}

	return isComplexMapCriterionMet(crt, nameVersionMap)
}

func mergeStringMaps(propFromYaml map[string]string, propFromImage map[string]string) map[string][]string {
	size := len(propFromYaml)
	if len(propFromImage) > size {
		size = len(propFromImage)
	}
	union := make(map[string][]string, size)
	for k, v := range propFromYaml {
		slice := []string{v}
		union[k] = slice
	}
	for k2, v2 := range propFromImage {
		if v, ok := propFromYaml[k2]; ok {
			if v2 != v {
				// a key exists in both propFromYaml & propFromImage with different values
				slice, _ := union[k2]
				union[k2] = append(slice, v2)
			}
		} else {
			// a key exists in propFromImage but not propFromYaml
			slice := []string{v2}
			union[k2] = slice
		}
	}

	return union
}

func pssViolations(crt *share.CLUSAdmRuleCriterion, c *nvsysadmission.AdmContainerInfo, imageRunsAsRoot bool) []string {
	selectedPolicy := strings.TrimSpace(strings.ToLower(crt.Value))

	switch selectedPolicy {
	case share.PssPolicyBaseline:
		return baselinePolicyViolations(c)
	case share.PssPolicyRestricted:
		return restrictedPolicyViolations(c, imageRunsAsRoot)
	}

	return []string{} // invalid policy
}

// to recollect critical and high vulnerabilities to use in legacy admission control rules
func mergeVulnMaps(highVulns, criticalVulns map[string]share.CLUSScannedVulInfo) map[string]share.CLUSScannedVulInfo {
	mergedVulns := make(map[string]share.CLUSScannedVulInfo)

	for k, v := range highVulns {
		mergedVulns[k] = v
	}

	for k, v := range criticalVulns {
		mergedVulns[k] = v
	}

	return mergedVulns
}

// For criteria of same type, apply 'and' for all negative matches until the first positive match;
//
//	apply 'or' after the first positive match;
//
// For different criteria type, apply 'and'
func isAdmissionRuleMet(admResObject *nvsysadmission.AdmResObject, c *nvsysadmission.AdmContainerInfo, scannedImage *nvsysadmission.ScannedImageSummary,
	criteria []*share.CLUSAdmRuleCriterion, rootAvail bool, ar *admissionv1beta1.AdmissionReview, ruleID uint32) (bool, string) { // return (matched, matched data source)
	var met, positive bool
	var matchedSource string
	var mets map[string]bool = make(map[string]bool)
	var poss map[string]bool = make(map[string]bool)
	var hasCustomCriteria bool
	var kind string

	statefuleSetVCT := make([]string, 0)
	if ar != nil {
		req := ar.Request
		if req.Kind.Kind == "StatefulSet" {
			var statefulSet appsv1.StatefulSet
			if err := json.Unmarshal(req.Object.Raw, &statefulSet); err == nil {
				for _, vct := range statefulSet.Spec.VolumeClaimTemplates {
					if vct.Spec.StorageClassName != nil {
						statefuleSetVCT = append(statefuleSetVCT, *vct.Spec.StorageClassName)
					}
				}
			}
			kind = "StatefulSet"
		}
	}

	for _, crt := range criteria {
		if c.Type == nvsysadmission.K8SEphemeralContainer || c.Type == nvsysadmission.K8sInitContainer {
			if crt.Name != share.CriteriaKeyHasPssViolation {
				// don't check non-pss criteria for ephemeral or init containers
				continue
			}
		}

		// only handle predefined criteria
		if crt.Type != "" && crt.Type != share.CriteriaKeySaBindRiskyRole {
			hasCustomCriteria = true
			continue
		}

		key := crt.Name
		switch crt.Name {
		case share.CriteriaKeyUser:
			if rootAvail {
				met, positive = isStringCriterionMet(crt, admResObject.UserName)
			} else {
				met, positive = false, true
			}
		case share.CriteriaKeyK8sGroups:
			if rootAvail {
				met, positive = isSetCriterionMet(crt, admResObject.Groups)
			} else {
				met, positive = false, true
			}
		case share.CriteriaKeyNamespace:
			met, positive = isStringCriterionMet(crt, admResObject.Namespace)
		case share.CriteriaKeyLabels:
			// for Labels criterion, crt.Value is in the format "key[=value][;key[=value]]"
			var dataSrc string
			if len(admResObject.Labels) > 0 && len(scannedImage.Labels) > 0 {
				met, positive = isComplexMapCriterionMet(crt, mergeStringMaps(admResObject.Labels, scannedImage.Labels))
				dataSrc = _matchedSrcBothLabels
			} else if len(admResObject.Labels) > 0 {
				met, positive = isMapCriterionMet(crt, admResObject.Labels)
				dataSrc = _matchedSrcResourceLabels
			} else {
				met, positive = isMapCriterionMet(crt, scannedImage.Labels)
				dataSrc = _matchedSrcImageLabels
			}
			if met {
				matchedSource = dataSrc
			}
		case share.CriteriaKeyAnnotations:
			met, positive = isMapCriterionMet(crt, admResObject.Annotations)
		case share.CriteriaKeyImage:
			met, positive = isImageCriterionMet(crt, c)
		case share.CriteriaKeyImageRegistry:
			met, positive = isSetCriterionMet(crt, c.ImageRegistry)
		//case share.CriteriaKeyBaseImage: //-> is base image available?
		//	met, positive = isStringCriterionMet(crt, scannedImage.BaseName)
		case share.CriteriaKeyCVECriticalCount:
			met, positive = isCveCountCriterionMet(crt, false, 0, scannedImage.CriticalVulInfo)
		case share.CriteriaKeyCVEHighCountNoCritical:
			met, positive = isCveCountCriterionMet(crt, false, 0, scannedImage.HighVulInfo)
		case share.CriteriaKeyCVEHighCount:
			met, positive = isCveCountCriterionMet(crt, false, 0, mergeVulnMaps(scannedImage.HighVulInfo, scannedImage.CriticalVulInfo))
		case share.CriteriaKeyCVEMediumCount:
			met, positive = isCveCountCriterionMet(crt, false, 0, scannedImage.MediumVulInfo)
		case share.CriteriaKeyCVECriticalWithFixCount:
			met, positive = isCveCountCriterionMet(crt, true, scannedImage.CriticalVulsWithFix, scannedImage.CriticalVulInfo)
		case share.CriteriaKeyCVEHighWithFixCountNoCritical:
			met, positive = isCveCountCriterionMet(crt, true, scannedImage.HighVulsWithFix, scannedImage.HighVulInfo)
		case share.CriteriaKeyCVEHighWithFixCount:
			met, positive = isCveCountCriterionMet(crt, true, scannedImage.HighVulsWithFix+scannedImage.CriticalVulsWithFix, mergeVulnMaps(scannedImage.HighVulInfo, scannedImage.CriticalVulInfo))
		case share.CriteriaKeyCVEScoreCount:
			met, positive = isCveScoreCountCriterionMet(crt, mergeVulnMaps(scannedImage.HighVulInfo, scannedImage.CriticalVulInfo), scannedImage.MediumVulInfo, scannedImage.LowVulInfo)
		case share.CriteriaKeyCVEScore:
			met, positive = isNumericCriterionMet(crt, &scannedImage.VulScore, &crt.Value)
		case share.CriteriaKeyImageScanned:
			met, positive = isStringCriterionMet(crt, strconv.FormatBool(scannedImage.Scanned))
		case share.CriteriaKeyImageSigned:
			imageSigned := false
			if len(scannedImage.Verifiers) > 0 {
				imageSigned = true
			}
			met, positive = isStringCriterionMet(crt, strconv.FormatBool(imageSigned))
		case share.CriteriaKeyRunAsPrivileged:
			met, positive = isStringCriterionMet(crt, strconv.FormatBool(c.Privileged))
		case share.CriteriaKeyRunAsRoot:
			met, positive = isStringCriterionMet(crt, strconv.FormatBool((c.RunAsUser == 0) || (c.RunAsUser == -1 && scannedImage.RunAsRoot)))
		case share.CriteriaKeyAllowPrivEscalation:
			met, positive = isStringCriterionMet(crt, strconv.FormatBool(c.AllowPrivilegeEscalation))
		case share.CriteriaKeyMountVolumes:
			met, positive = isSetCriterionMet(crt, c.VolMounts)
		case share.CriteriaKeyEnvVars:
			// for EnvVars criterion, crt.Value is in the format "key[=value][;key[=value]]"
			var dataSrc string
			if len(c.EnvVars) > 0 && len(scannedImage.EnvVars) > 0 {
				met, positive = isComplexMapCriterionMet(crt, mergeStringMaps(c.EnvVars, scannedImage.EnvVars))
				dataSrc = _matchedSrcBothEnvVars
			} else if len(c.EnvVars) > 0 {
				met, positive = isMapCriterionMet(crt, c.EnvVars)
				dataSrc = _matchedSrcResourceEnvVars
			} else {
				met, positive = isMapCriterionMet(crt, scannedImage.EnvVars)
				dataSrc = _matchedSrcImageEnvVars
			}
			if met {
				matchedSource = dataSrc
			}
		case share.CriteriaKeyCVENames:
			met, positive = isSetCriterionMet(crt, scannedImage.VulNames)
		case share.CriteriaKeyImageCompliance:
			found := scannedImage.SecretsCnt > 0 || scannedImage.SetIDPermCnt > 0
			met, positive = isStringCriterionMet(crt, strconv.FormatBool(found))
		case share.CriteriaKeyEnvVarSecrets:
			found := len(c.EnvSecrets) > 0
			met, positive = isStringCriterionMet(crt, strconv.FormatBool(found))
		case share.CriteriaKeyImageNoOS:
			var value bool
			if scannedImage.BaseOS == "" {
				value = true
			}
			met, positive = isStringCriterionMet(crt, strconv.FormatBool(value))
		case share.CriteriaKeySharePidWithHost:
			met, positive = isStringCriterionMet(crt, strconv.FormatBool(c.HostPID))
		case share.CriteriaKeyShareIpcWithHost:
			met, positive = isStringCriterionMet(crt, strconv.FormatBool(c.HostIPC))
		case share.CriteriaKeyShareNetWithHost:
			met, positive = isStringCriterionMet(crt, strconv.FormatBool(c.HostNetwork))
		case share.CriteriaKeyPspCompliance:
			props := []bool{c.Privileged, ((c.RunAsUser == 0) || (c.RunAsUser == -1 && scannedImage.RunAsRoot)), c.AllowPrivilegeEscalation, c.HostIPC, c.HostNetwork, c.HostPID}
			for _, prop := range props {
				if metAny, _ := isStringCriterionMet(crt, strconv.FormatBool(prop)); metAny {
					met, positive = true, true
					break
				}
			}
		case share.CriteriaKeyRequestLimit:
			met, positive = isResourceLimitCriterionMet(crt, c)
		case share.CriteriaKeyModules:
			met, positive = isModulesCriterionMet(crt, scannedImage.Modules)
		case share.CriteriaKeyHasPssViolation:
			met = len(pssViolations(crt, c, scannedImage.RunAsRoot)) > 0
			positive = true
		case share.CriteriaKeyImageVerifiers:
			met, positive = isSetCriterionMet(crt, utils.NewSetFromStringSlice(scannedImage.Verifiers))
		case share.CriteriaKeyStorageClassName:
			if kind == "StatefulSet" {
				for _, scName := range statefuleSetVCT {
					met, positive = isStringCriterionMet(crt, scName)
					if met {
						break
					}
				}
			} else {
				met, positive = isStorageClassNameCriterionMet(crt, admResObject.Namespace, c)
			}
		case share.CriteriaKeySaBindRiskyRole:
			met, positive = isRiskyServiceAccountRuleMet(crt, admResObject.ServiceAccountName, admResObject.Namespace)
		default:
			met, positive = false, true
		}

		if v, ok := mets[key]; !ok {
			mets[key] = met
			poss[key] = positive
		} else {
			p, _ := poss[key]
			if !positive && !p {
				mets[key] = v && met
			} else {
				mets[key] = v || met
			}
			poss[key] = p || positive
		}
	}

	if hasCustomCriteria {
		// handle custom criteria,
		// OPA requres the data wrapped under "input" key
		type AdmissionReviewWrapper struct {
			Review *admissionv1beta1.AdmissionReview `json:"input"`
		}

		ar2 := AdmissionReviewWrapper{Review: ar}
		jsonData, _ := json.Marshal(ar2)

		policyUrl := fmt.Sprintf("/v1/data/neuvector_policy_%d", ruleID)

		statusCode, body, err := opa.OpaEvalByString(policyUrl, string(jsonData))

		if err != nil {
			log.WithFields(log.Fields{"err": err, "policyUrl": policyUrl, "ar.RequestID": ar.Request.UID}).Error("opa.OpaEvalByString() failed")
		} else {
			log.WithFields(log.Fields{"policyUrl": policyUrl, "statusCode": statusCode, "body": body, "ar.RequestID": ar.Request.UID}).Debug("opa.OpaEvalByString() success")

			met, err := opa.AnalyzeResult(body)
			if err != nil {
				log.WithFields(log.Fields{"err": err, "policyUrl": policyUrl, "body": body}).Error("opa.AnalyzeResult() failed")
			}

			mets["custom_criteria"] = met
			poss["custom_criteria"] = true
		}
	}

	if len(mets) == 0 {
		return false, ""
	}
	for _, met = range mets {
		if !met {
			return false, ""
		}
	}

	return true, matchedSource
}

// cache lock is owned by caller
func setAdmCtrlStateCache(admType, category string, state *share.CLUSAdmissionState, validateUri, nvStatusUri string) error {
	ctrlState, exist := admStateCache.CtrlStates[admType]
	if ctrlState == nil || !exist {
		var strErr = "Cannot set unsupported admission control state"
		log.WithFields(log.Fields{"admType": admType, "validateUri": validateUri, "nvStatusUri": nvStatusUri}).Error(strErr)
		return errors.New(strErr)
	}
	ctrlState.Enable = state.Enable
	ctrlState.Uri = validateUri
	ctrlState.NvStatusUri = nvStatusUri

	if ctrlState.Uri != "" {
		defaultAction := nvsysadmission.AdmCtrlActionAllow
		if state.DefaultAction == share.AdmCtrlActionDeny {
			defaultAction = nvsysadmission.AdmCtrlActionDeny
		}
		admCacheMutexLock()
		for _, uri := range []string{ctrlState.Uri, ctrlState.NvStatusUri} {
			uriState, exist := admUriStates[uri]
			if !exist {
				uriState = &nvsysadmission.AdmUriState{
					AdmType:  admType,
					Category: category,
				}
				admUriStates[uri] = uriState
			}
			uriState.Enabled = state.Enable
			uriState.Mode = state.Mode
			uriState.DefaultAction = defaultAction
		}
		admCacheMutexUnlock()
		log.WithFields(log.Fields{"admType": admType, "state": *state}).Debug("admission control state")
	}

	return nil
}

func getOpDisplay(crt *share.CLUSAdmRuleCriterion) string {
	switch crt.Op {
	case share.CriteriaOpEqual, share.CriteriaOpNotEqual, share.CriteriaOpBiggerEqualThan, share.CriteriaOpBiggerThan, share.CriteriaOpLessEqualThan, "":
		return crt.Op
	case share.CriteriaOpRegex, share.CriteriaOpRegex_Deprecated:
		return "matches"
	case share.CriteriaOpNotRegex, share.CriteriaOpNotRegex_Deprecated:
		return "does not match"
	case share.CriteriaOpContainsAll:
		return "contains all in"
	case share.CriteriaOpContainsAny:
		return "contains any in"
	case share.CriteriaOpNotContainsAny:
		return "does not contain any in"
	case share.CriteriaOpRegexContainsAny:
		return "contains any in regex"
	case share.CriteriaOpRegexNotContainsAny:
		return "does not contain any in regex"
	case share.CriteriaOpContainsOtherThan:
		return "contains value other than"
	case share.CriteriaOpExist:
		return "exist"
	case share.CriteriaOpNotExist:
		return "does not exist"
	case share.CriteriaOpContainsTagAny:
		return "bounds to a high risk role"
	default:
		return "unknown"
	}
}

func sameNameCriteriaToString(ruleType string, criteria []*share.CLUSAdmRuleCriterion) string {
	if len(criteria) == 0 {
		return ""
	}

	var firstCriterion = true
	var sb strings.Builder
	var positive bool
	var displayName string
	var ok bool

	if len(criteria) > 1 {
		sb.WriteString("(")
	}
	for _, crt := range criteria {
		var str, strSub string
		if len(crt.SubCriteria) > 0 {
			if format, ok := critDisplayName2[crt.Name]; ok && len(crt.SubCriteria) == 1 && ruleType == api.ValidatingDenyRuleType {
				if crt.Name == share.CriteriaKeyCVEScoreCount {
					str = fmt.Sprintf(format, crt.SubCriteria[0].Value, crt.Value)
				} else {
					str = fmt.Sprintf(format, crt.Value, crt.SubCriteria[0].Value)
				}
			} else {
				strSub = sameNameCriteriaToString(ruleType, crt.SubCriteria)
			}
		}
		if str == "" {
			opDsiplay := getOpDisplay(crt)
			displayName = ""

			if crt.Type != "" {
				crt.Name = crt.Type
			}

			if displayName, ok = critDisplayName[crt.Name]; !ok {
				displayName = crt.Name
			}
			if crt.Op == "" {
				str = fmt.Sprintf("(%s)", displayName)
			} else {
				switch crt.Op {
				case share.CriteriaOpContainsAll, share.CriteriaOpContainsAny, share.CriteriaOpNotContainsAny, share.CriteriaOpContainsOtherThan,
					share.CriteriaOpRegexContainsAny, share.CriteriaOpRegexNotContainsAny:
					if crt.Type == "customPath" {
						str = fmt.Sprintf("(%s, %s %s {%s})", displayName, crt.Path, opDsiplay, crt.Value)
					} else {
						str = fmt.Sprintf("(%s %s {%s})", displayName, opDsiplay, crt.Value)
					}
				case share.CriteriaOpRegex, share.CriteriaOpRegex_Deprecated:
					str = fmt.Sprintf("(%s %s regex(%s) )", displayName, opDsiplay, crt.Value)
				case share.CriteriaOpExist, share.CriteriaOpNotExist:
					str = fmt.Sprintf("(%s, path %s %s)", displayName, crt.Path, opDsiplay)
				case share.CriteriaOpContainsTagAny:
					str = fmt.Sprintf("(the service account is bound to one of high risk role {%s})", formatRiskyRoleCriteriaMsg(crt.Value))
				default:
					if crt.Type == "customPath" {
						str = fmt.Sprintf("(%s, value in %s %s %s)", displayName, crt.Path, opDsiplay, crt.Value)
					} else {
						str = fmt.Sprintf("(%s %s %s)", displayName, opDsiplay, crt.Value)
					}
				}
			}
			if len(strSub) > 0 {
				str = fmt.Sprintf("(%s that %s)", str, strSub)
			}
		} else {
			str = fmt.Sprintf("(%s)", str)
		}
		if !firstCriterion {
			if !positive && (crt.Op == share.CriteriaOpNotContainsAny || crt.Op == share.CriteriaOpNotEqual ||
				crt.Op == share.CriteriaOpNotRegex || crt.Op == share.CriteriaOpNotRegex_Deprecated) {
				sb.WriteString(andDelim)
			} else {
				sb.WriteString(orDelim)
				positive = true
			}
		} else {
			if crt.Op != share.CriteriaOpNotContainsAny && crt.Op != share.CriteriaOpNotEqual &&
				crt.Op != share.CriteriaOpNotRegex && crt.Op != share.CriteriaOpNotRegex_Deprecated {
				positive = true
			}
		}
		sb.WriteString(str)
		firstCriterion = false
	}
	if len(criteria) > 1 {
		sb.WriteString(")")
	}
	return sb.String()
}

func ruleToString(rule *share.CLUSAdmissionRule) string {
	var firstCriterion = true
	var sb strings.Builder

	critNameMap := make(map[string][]*share.CLUSAdmRuleCriterion)
	for _, crt := range rule.Criteria {
		if arr, exist := critNameMap[crt.Name]; !exist {
			critNameMap[crt.Name] = []*share.CLUSAdmRuleCriterion{crt}
		} else {
			critNameMap[crt.Name] = append(arr, crt)
		}
	}
	if len(critNameMap) > 1 {
		sb.WriteString("(")
	}
	for _, arr := range critNameMap {
		str := sameNameCriteriaToString(rule.RuleType, arr)
		if !firstCriterion {
			sb.WriteString(andDelim)
		}
		sb.WriteString(str)
		firstCriterion = false
	}
	if len(critNameMap) > 1 {
		sb.WriteString(")")
	}
	return sb.String()
}

func isApiPathAvailable(ctrlStates map[string]*share.CLUSAdmCtrlState) bool {
	for _, ctrlState := range ctrlStates {
		if ctrlState.Uri == "" {
			return false
		}
	}
	return true
}

// return true means the match is a critical match that decides the action of the admission control request
func collectMatchedResult(rule *share.CLUSAdmissionRule, evalContext *nvsysadmission.AdmCtrlEvalContext,
	imageSummary *nvsysadmission.ScannedImageSummary, result *nvsysadmission.AdmCtrlAssessResult,
	ruleType, image, matchedSource, extraDenyRuleMsg string) bool {

	// 1. for assessment, disabled rules' matched results are collected as well.
	//    however, disabled rules' matched results are ignored in the calc of the final webhook request result.
	// 2. for non-assessment, disabled rules are not evaluated at all.

	isDenyRuleType := false
	isCriticalMatch := false // meaning the matched rule gets allow/deny action(not including deny/monitor)
	matchedAction := ""

	if ruleType == share.FedAdmCtrlDenyRulesType || ruleType == api.ValidatingDenyRuleType {
		isDenyRuleType = true
	}

	ruleDetails := fmt.Sprintf("%s%s.", ruleToString(rule), matchedSource)
	if len(extraDenyRuleMsg) > 0 {
		ruleDetails += " " + extraDenyRuleMsg
	}
	if len(ruleDetails) > 0 && ruleDetails[len(ruleDetails)-1] == '.' {
		ruleDetails = ruleDetails[0 : len(ruleDetails)-1]
	}

	if !isDenyRuleType {
		matchedAction = share.PolicyActionAllow
	} else if rule.RuleMode == share.AdmCtrlModeProtect || (rule.RuleMode == "" && evalContext.GlobalMode == share.AdmCtrlModeProtect) {
		matchedAction = share.AdmCtrlActionDeny
	}

	if result.AssessAction == "" && !rule.Disable && matchedAction != "" {
		isCriticalMatch = true
	}
	matchedResult := &nvsysadmission.AdmCtrlMatchedResult{
		ContainerImage:  image,
		RuleID:          rule.ID,
		IsFedRule:       ruleType == share.FedAdmCtrlDenyRulesType || ruleType == share.FedAdmCtrlExceptRulesType,
		IsDenyRuleType:  isDenyRuleType,
		Disabled:        rule.Disable,
		IsCriticalMatch: isCriticalMatch,
		RuleDetails:     ruleDetails,
		RuleMode:        rule.RuleMode, // matched rule's per-rule mode. for deny rules only
		RuleCfgType:     rule.CfgType,
	}
	if imageSummary != nil {
		matchedResult.ImageInfo = nvsysadmission.AdmCtrlMatchedImageInfo{
			ImageScanned:    imageSummary.Scanned,
			ImageID:         imageSummary.ImageID,
			Registry:        imageSummary.Registry,
			BaseOS:          imageSummary.BaseOS,
			CriticalVulsCnt: imageSummary.CriticalVuls,
			HighVulsCnt:     imageSummary.HighVuls,
			MedVulsCnt:      imageSummary.MedVuls,
		}
	}
	result.MatchedResults = append(result.MatchedResults, matchedResult)
	if isCriticalMatch {
		result.AssessAction = matchedAction
		result.CriticalMatch = matchedResult
	}

	return isCriticalMatch
}

// matchCfgType being 0 means to compare with default(critical) rules only
// result is per-container-image's result. (a pod could have multiple containers)
// return true means an enabled rule is matched with allow/deny action
func matchK8sAdmissionRules(ruleType string, matchCfgType int, admResObject *nvsysadmission.AdmResObject, c *nvsysadmission.AdmContainerInfo,
	evalContext *nvsysadmission.AdmCtrlEvalContext, scannedImages []*nvsysadmission.ScannedImageSummary, result *nvsysadmission.AdmCtrlAssessResult,
	ar *admissionv1beta1.AdmissionReview, containerType string) bool {

	forTesting := evalContext.ForTesting
	hasActionMatched := false
	admPolicyCache := selectAdminPolicyCache(evalContext.AdmCtrlType, ruleType)
	if admPolicyCache != nil {
		cacheMutexRLock()
		defer cacheMutexRUnlock()

		for _, head := range admPolicyCache.RuleHeads {
			if rule, ok := admPolicyCache.RuleMap[head.ID]; ok && (forTesting || !rule.Disable) && rule.Category == admission.AdmRuleCatK8s {
				if ((matchCfgType == _criticalRulesOnly) && rule.Critical) || (!rule.Critical && (matchCfgType == int(rule.CfgType))) {
					// check whether this rule should be evaluated for the container
					var evaluate bool
					if rule.Containers == 0 {
						if containerType == share.AdmCtrlRuleContainers {
							evaluate = true
						}
					} else {
						switch containerType {
						case share.AdmCtrlRuleContainers:
							if (rule.Containers & share.AdmCtrlRuleContainersN) > 0 {
								evaluate = true
							}
						case share.AdmCtrlRuleInitContainers:
							if (rule.Containers & share.AdmCtrlRuleInitContainersN) > 0 {
								evaluate = true
							}
						case share.AdmCtrlRuleEphemeralContainers:
							if (rule.Containers & share.AdmCtrlRuleEphemeralContainersN) > 0 {
								evaluate = true
							}
						}
					}
					if !evaluate {
						continue
					}

					for _, scannedImage := range scannedImages {
						if matched, matchedSource := isAdmissionRuleMet(admResObject, c, scannedImage, rule.Criteria, evalContext.RootAvail, ar, rule.ID); matched {
							extraDenyRuleMsg := ""
							if ruleType == share.FedAdmCtrlDenyRulesType || ruleType == api.ValidatingDenyRuleType {
								if matchedSource != "" {
									matchedSource = fmt.Sprintf(" and matched data from %s", matchedSource)
								}
								extraDenyRuleMsg = fillDenyMessageFromRule(c, rule, scannedImage)
							}
							isActionMatched := collectMatchedResult(rule, evalContext, scannedImage, result, ruleType, c.Image, matchedSource, extraDenyRuleMsg)
							// for assessment, disabled rule could be matched even though it's ignored in the calc of final request result
							if !forTesting {
								log.WithFields(log.Fields{"id": head.ID, "image": c.Image, "type": ruleType, "isActionMatched": isActionMatched}).Debug("matched a rule")
							}

							if isActionMatched {
								if forTesting {
									hasActionMatched = true
								} else {
									return true
								}
							}
						}
					}
				}
			}
		}
	}

	return hasActionMatched
}

// Admission control - non-UI
func (m CacheMethod) SyncAdmCtrlStateToK8s(svcName, nvAdmName string, updateDetected bool) (bool, error) { // (skip, err)
	// Configure K8s based on settings in consul in case they are different
	state, _ := clusHelper.GetAdmissionStateRev(svcName)
	if state == nil {
		msg := "no admission state in cluster!"
		log.Error(msg)
		return true, errors.New(msg)
	}
	failurePolicy := resource.Ignore
	if state.FailurePolicy == resource.FailLower {
		failurePolicy = resource.Fail
	}
	for admType, ctrlState := range state.CtrlStates { // admType is ctrlType
		log.WithFields(log.Fields{"admType": admType, "enable": ctrlState.Enable, "name": nvAdmName,
			"uri": ctrlState.Uri, "nvstatusuri": ctrlState.NvStatusUri}).Debug("sync admission control state to k8s")
		if admType == admission.NvAdmValidateType {
			var k8sResInfo admission.ValidatingWebhookConfigInfo
			switch nvAdmName {
			case resource.NvAdmValidatingName:
				k8sResInfo = admission.ValidatingWebhookConfigInfo{
					WebhooksInfo: []*admission.WebhookInfo{
						&admission.WebhookInfo{
							Name: resource.NvAdmValidatingWebhookName,
							ClientConfig: admission.ClientConfig{
								ClientMode:  state.AdmClientMode,
								ServiceName: resource.NvAdmSvcName,
								Path:        ctrlState.Uri,
							},
							FailurePolicy:  failurePolicy,
							TimeoutSeconds: state.TimeoutSeconds,
						},
						&admission.WebhookInfo{
							Name: resource.NvStatusValidatingWebhookName,
							ClientConfig: admission.ClientConfig{
								ClientMode:  state.AdmClientMode,
								ServiceName: resource.NvAdmSvcName,
								Path:        ctrlState.NvStatusUri,
							},
							FailurePolicy:  resource.Ignore,
							TimeoutSeconds: state.TimeoutSeconds,
						},
					},
				}
				if updateDetected {
					k8sResInfo.RevertCount = &whRevertCount
				}
			case resource.NvCrdValidatingName:
				k8sResInfo = admission.ValidatingWebhookConfigInfo{
					WebhooksInfo: []*admission.WebhookInfo{
						&admission.WebhookInfo{
							Name: resource.NvCrdValidatingWebhookName,
							ClientConfig: admission.ClientConfig{
								ClientMode:  state.AdmClientMode,
								ServiceName: resource.NvCrdSvcName,
								Path:        ctrlState.Uri,
							},
							FailurePolicy:  resource.Ignore,
							TimeoutSeconds: resource.DefTimeoutSeconds,
						},
					},
				}
			}
			k8sResInfo.Name = nvAdmName
			skip, err := admission.ConfigK8sAdmissionControl(&k8sResInfo, ctrlState)
			if !skip && err == nil && k8sResInfo.UnexpectedMatchExpr != "" {
				msg := fmt.Sprintf("Kubernetes %s %s is modified with unexpected key(s) %s", resource.RscKindValidatingWebhookConfiguration,
					resource.NvAdmValidatingName, k8sResInfo.UnexpectedMatchExpr)
				alog := share.CLUSEventLog{
					Event:      share.CLUSEvK8sAdmissionWebhookCChange,
					Msg:        msg,
					ReportedAt: time.Now().UTC(),
				}
				cctx.EvQueue.Append(&alog)
			}
			return skip, err
		}
	}
	return true, nil
}

func (m CacheMethod) WaitUntilApiPathReady() bool {
	ticker := time.Tick(time.Second)
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	for i := 1; i <= 10; i++ {
		state, _ := clusHelper.GetAdmissionStateRev(resource.NvAdmSvcName)
		if state != nil && isApiPathAvailable(state.CtrlStates) {
			return true
		}
		select {
		case <-ticker:
			log.Debug("wait until admission api path is ready")
		case <-signalChan:
			return false
		}
	}

	return false
}

func (m CacheMethod) IsImageScanned(c *nvsysadmission.AdmContainerInfo) (bool, int, int) {
	vpf := cacher.GetVulnerabilityProfileInterface(share.DefaultVulnerabilityProfileName)
	scannedImages := scan.GetScannedImageSummary(c.ImageRegistry, c.ImageRepo, c.ImageTag, vpf)
	if len(scannedImages) == 1 {
		if !scannedImages[0].Scanned {
			log.WithFields(log.Fields{"ImageRegistry": c.ImageRegistry.Any(), "ImageRepo": c.ImageRepo, "ImageTag": c.ImageTag}).Info("requested image not scanned")
			return false, 0, 0
		} else {
			return true, scannedImages[0].HighVuls, scannedImages[0].MedVuls
		}
	} else {
		scanned, highVuls, medVuls := false, 0, 0
		for _, scannedImage := range scannedImages {
			if scannedImage.Scanned {
				scanned = true
				if scannedImage.HighVuls > highVuls {
					highVuls = scannedImage.HighVuls
				}
				if scannedImage.MedVuls > medVuls {
					medVuls = scannedImage.MedVuls
				}
			}
		}
		return scanned, highVuls, medVuls
	}
}

// it's for a container/image's evaluation only
func (m CacheMethod) MatchK8sAdmissionRules(admResObject *nvsysadmission.AdmResObject, c *nvsysadmission.AdmContainerInfo,
	evalContext *nvsysadmission.AdmCtrlEvalContext, stamps *api.AdmCtlTimeStamps, ar *admissionv1beta1.AdmissionReview,
	containerType string) (*nvsysadmission.AdmCtrlAssessResult, bool) {

	forTesting := evalContext.ForTesting
	result := &nvsysadmission.AdmCtrlAssessResult{} // match result for the container-image
	vpf := cacher.GetVulnerabilityProfileInterface(share.DefaultVulnerabilityProfileName)
	stamps.GonnaFetch = time.Now()
	scannedImages := scan.GetScannedImageSummary(c.ImageRegistry, c.ImageRepo, c.ImageTag, vpf)
	stamps.Fetched = time.Now()

	// criticalVuls, highVuls, medVuls are the max vulns found for the image
	scanned, criticalVuls, highVuls, medVuls := false, 0, 0, 0
	if len(scannedImages) > 0 {
		imageSummaryCount := 1
		firstScannedImage := scannedImages[0]

		for i, scannedImage := range scannedImages {
			if scannedImage.Scanned {
				scanned = true
				if scannedImage.CriticalVuls > criticalVuls {
					criticalVuls = scannedImage.CriticalVuls
				}
				if scannedImage.HighVuls > highVuls {
					highVuls = scannedImage.HighVuls
				}
				if scannedImage.MedVuls > medVuls {
					medVuls = scannedImage.MedVuls
				}
			}

			if i > 0 && (scannedImage.ImageID != firstScannedImage.ImageID || scannedImage.Digest != firstScannedImage.Digest) {
				imageSummaryCount++
				log.WithFields(log.Fields{"Image": c.Image, "imageID": scannedImage.ImageID, "digest": scannedImage.ImageID}).Info("multiple image summary")
			}

			// As specified in https://kubernetes.io/docs/tasks/inject-data-application/define-environment-variable-container/,
			// the environment variables set using the env or envFrom field will override any environment variables specified in the container image.
			// So environment variables set in yaml will override any environment variables specified in the scanned result.
			for k, _ := range c.EnvVars {
				if _, exist := scannedImage.EnvVars[k]; exist {
					delete(scannedImage.EnvVars, k)
				}
			}
		}

		if imageSummaryCount > 0 {
			log.WithFields(log.Fields{"Image": c.Image, "imageID": firstScannedImage.ImageID, "digest": firstScannedImage.Digest}).Info("first image summary")
		}
	}
	if !scanned {
		log.WithFields(log.Fields{"ImageRegistry": c.ImageRegistry.Any(), "ImageRepo": c.ImageRepo, "ImageTag": c.ImageTag}).Info("requested image not scanned")
	}

	result.ContainerImageInfo.Name = c.Name
	result.ContainerImageInfo.Image = c.Image
	result.ContainerImageInfo.Repository = c.ImageRepo
	result.ContainerImageInfo.Tag = c.ImageTag
	result.ContainerImageInfo.ImageScanned = scanned
	result.ContainerImageInfo.CriticalVulsCnt = criticalVuls
	result.ContainerImageInfo.HighVulsCnt = highVuls
	result.ContainerImageInfo.MedVulsCnt = medVuls

	if !forTesting && evalContext.ReqActionSoFar == share.AdmCtrlActionDeny {
		return result, false
	}

	// we compare with default allow rules first when this container doesn't match any rule yet
	if isActionMatched := matchK8sAdmissionRules(api.ValidatingExceptRuleType, _criticalRulesOnly,
		admResObject, c, evalContext, scannedImages, result, ar, containerType); isActionMatched && !forTesting {
		return result, true
	}

	// if we are in federation, compare with fed admission rules(i.e. fed_admctrl_exception/fed_admctrl_deny rules) before crd/local user-defined rules
	if fedRole := cacher.GetFedMembershipRoleNoAuth(); fedRole == api.FedRoleJoint || fedRole == api.FedRoleMaster {
		if isActionMatched := matchK8sAdmissionRules(share.FedAdmCtrlExceptRulesType, share.FederalCfg,
			admResObject, c, evalContext, scannedImages, result, ar, containerType); isActionMatched && !forTesting {
			return result, true
		}

		if isActionMatched := matchK8sAdmissionRules(share.FedAdmCtrlDenyRulesType, share.FederalCfg,
			admResObject, c, evalContext, scannedImages, result, ar, containerType); isActionMatched && !forTesting {
			// it's not assessment. the matched deny rule will trigger protect-deny action
			return result, true
		}
	}

	// if this container doesn't match any rule yet, we compare in the following order:
	// 1. CRD allow rules
	// 2. CRD deny rules
	// 3. user-defined allow rules
	// 4. user-defined deny rules
	for _, matchScope := range []int{share.GroundCfg, share.UserCreated} {
		if isActionMatched := matchK8sAdmissionRules(api.ValidatingExceptRuleType, matchScope,
			admResObject, c, evalContext, scannedImages, result, ar, containerType); isActionMatched && !forTesting {
			return result, true
		}

		if isActionMatched := matchK8sAdmissionRules(api.ValidatingDenyRuleType, matchScope,
			admResObject, c, evalContext, scannedImages, result, ar, containerType); isActionMatched && !forTesting {
			// it's not assessment. the matched deny rule will trigger protect-deny action
			return result, true
		}
	}

	return result, false
}

func (m CacheMethod) IsAdmControlEnabled(uri *string) (bool, string, int, string, string) {
	admCacheMutexRLock()
	defer admCacheMutexRUnlock()

	if state, exist := admUriStates[*uri]; exist {
		return state.Enabled, state.Mode, state.DefaultAction, state.AdmType, state.Category
	}
	return false, share.AdmCtrlModeMonitor, nvsysadmission.AdmCtrlActionAllow, "", ""
}

func (m CacheMethod) UpdateLocalAdmCtrlStats(category string, stats int) error {
	if category == admission.AdmRuleCatK8s {
		switch stats {
		case nvsysadmission.ReqAllowed:
			atomic.AddUint64(&admLocalStats.K8sAllowedRequests, 1)
		case nvsysadmission.ReqDenied:
			atomic.AddUint64(&admLocalStats.K8sDeniedRequests, 1)
		case nvsysadmission.ReqErrored:
			atomic.AddUint64(&admLocalStats.K8sErroneousRequests, 1)
		case nvsysadmission.ReqIgnored:
			atomic.AddUint64(&admLocalStats.K8sIgnoredRequests, 1)
		}
	}
	atomic.AddInt64(&admLocalStats.K8sProcessingRequests, -1)

	return nil
}

func (m CacheMethod) IncrementAdmCtrlProcessing() {
	atomic.AddInt64(&admLocalStats.K8sProcessingRequests, 1)
}

func (m CacheMethod) FlushAdmCtrlStats() error {
	retry := 0
	var needUpdate bool
	const COUNTERS = 4
	var counts [COUNTERS]uint64
	var processing int64
	var fromAddrs = [COUNTERS]*uint64{&admLocalStats.K8sAllowedRequests, &admLocalStats.K8sDeniedRequests, &admLocalStats.K8sErroneousRequests,
		&admLocalStats.K8sIgnoredRequests}

	if processing = atomic.SwapInt64(&admLocalStats.K8sProcessingRequests, 0); processing != 0 {
		needUpdate = true
	} else {
		for i, addr := range fromAddrs {
			counts[i] = atomic.SwapUint64(addr, 0)
			if counts[i] > 0 {
				needUpdate = true
				break
			}
		}
	}
	if needUpdate {
		for retry < retryClusterMax {
			stats, rev := clusHelper.GetAdmissionStatsRev()
			if stats == nil {
				return errors.New("Admission stats doesn't exist")
			}
			statsAddrs := [COUNTERS]*uint64{&stats.K8sAllowedRequests, &stats.K8sDeniedRequests, &stats.K8sErroneousRequests, &stats.K8sIgnoredRequests}
			for i, addr := range statsAddrs {
				*addr += counts[i]
			}
			stats.K8sProcessingRequests += processing
			if err := clusHelper.PutAdmissionStatsRev(stats, rev); err != nil {
				retry++
			} else {
				break
			}
		}
		if retry >= retryClusterMax {
			for i, count := range counts {
				if count > 0 {
					atomic.AddUint64(fromAddrs[i], count)
				}
			}
			atomic.AddInt64(&admLocalStats.K8sProcessingRequests, processing)
			return errors.New("Failed to put admission stats")
		}
	}

	return nil
}

func AdmCriteria2CLUS(criteria []*api.RESTAdmRuleCriterion) ([]*share.CLUSAdmRuleCriterion, error) {
	if criteria == nil {
		return make([]*share.CLUSAdmRuleCriterion, 0), nil
	}
	var err error
	clus := make([]*share.CLUSAdmRuleCriterion, 0, len(criteria))
	for _, crit := range criteria {
		c := &share.CLUSAdmRuleCriterion{
			Name:      crit.Name,
			Op:        crit.Op,
			Type:      crit.Type,
			Kind:      crit.Kind,
			Path:      crit.Path,
			ValueType: crit.ValueType,
		}
		var critValues []string
		if c.Op == share.CriteriaOpContainsAll || c.Op == share.CriteriaOpContainsAny || c.Op == share.CriteriaOpNotContainsAny || c.Op == share.CriteriaOpContainsOtherThan ||
			c.Op == share.CriteriaOpRegexContainsAny || c.Op == share.CriteriaOpRegexNotContainsAny {
			critValues = strings.Split(crit.Value, setDelim)
			idx := 0
			for _, crtValue := range critValues {
				critValues[idx] = strings.TrimSpace(crtValue)
				if critValues[idx] != "" {
					idx++
				}
			}
			if len(critValues) > idx { // found empty string element in critValues
				critValues = critValues[:idx]
			}
		} else if c.Op == share.CriteriaOpExist || c.Op == share.CriteriaOpNotExist {
			clus = append(clus, c)
			continue
		} else {
			critValues = []string{strings.TrimSpace(crit.Value)}
		}

		if c.Type == "customPath" || c.Type == "saBindRiskyRole" {
			c.Name = c.Type
		}

		set := utils.NewSet()
		for _, crtValue := range critValues {
			if c.Name == share.CriteriaKeyCVENames {
				value := strings.ToUpper(crtValue)
				if !set.Contains(value) {
					set.Add(value)
				}
			} else if c.Name == share.CriteriaKeyImageRegistry {
				if regs, exist := reservedRegs[crtValue]; exist {
					for _, reg := range regs {
						if !set.Contains(reg) {
							set.Add(reg)
						}
					}
				} else {
					value := normalizeImageValue(crtValue, true)
					if value != "" && !set.Contains(value) {
						set.Add(value)
					}
				}
			} else if c.Name == share.CriteriaKeyImage {
				if c.Op == share.CriteriaOpRegex {
					set.Add(crtValue)
				} else {
					value := normalizeImageValue(crtValue, false)
					if value != "" && !set.Contains(value) {
						set.Add(value)
					}
				}
			} else if c.Name == share.CriteriaKeyRequestLimit {
				set.Add("")
			} else {
				if crtValue != "" && !set.Contains(crtValue) {
					set.Add(crtValue)
				}
			}
		}
		if set.Cardinality() > 0 {
			c.Value = strings.Join(set.ToStringSlice(), setDelim)
			if crit.SubCriteria != nil && len(crit.SubCriteria) > 0 {
				if c.SubCriteria, err = AdmCriteria2CLUS(crit.SubCriteria); err != nil {
					return nil, fmt.Errorf("Invalid criterion value")
				}
			}
			clus = append(clus, c)
		}
	}
	if len(clus) == 0 {
		return nil, fmt.Errorf("Invalid criterion value")
	}

	return clus, nil
}

func (m CacheMethod) SetNvDeployStatusInCluster(resName string, value bool) {
	if localDev.Host.Platform != share.PlatformKubernetes {
		return
	}

	// resName, like "neuvector-controller-pod"/"neuvector-svc-admission-webhook"/"neuvector-svc-crd-webhook", is used as key in status map
	retry := 0
	for retry < retryClusterMax {
		state, rev := clusHelper.GetAdmissionStateRev(resource.NvAdmSvcName)
		if state == nil {
			return
		}
		if v, exist := state.NvDeployStatus[resName]; !exist || v != value {
			state.NvDeployStatus[resName] = value
			// we should be notified by consul watcher and update cache in the handler function
			if err := clusHelper.PutAdmissionStateRev(resource.NvAdmSvcName, state, rev); err == nil {
				return
			}
		}
		retry++
	}
	log.WithFields(log.Fields{"resName": resName, "value": value}).Error("Failed to write cluster")
}

// Admission control - UI
func (m CacheMethod) GetAdmissionRuleCount(admType, ruleType string, acc *access.AccessControl) int {
	admPolicyCache := selectAdminPolicyCache(admType, ruleType)
	if admPolicyCache == nil {
		return 0
	}

	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if acc.HasGlobalPermissions(share.PERM_ADM_CONTROL, 0) {
		return len(admPolicyCache.RuleMap)
	} else {
		var count int
		for _, r := range admPolicyCache.RuleMap {
			if !acc.Authorize(r, nil) {
				continue
			}
			count++
		}
		return count
	}
}

func (m CacheMethod) GetAdmissionRule(admType, ruleType string, id uint32, acc *access.AccessControl) (*api.RESTAdmissionRule, error) {
	admPolicyCache := selectAdminPolicyCache(admType, ruleType)
	if admPolicyCache == nil {
		return nil, common.ErrObjectNotFound
	}

	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if rule, ok := admPolicyCache.RuleMap[id]; ok {
		if !acc.Authorize(rule, nil) {
			return nil, common.ErrObjectAccessDenied
		}
		return admissionRule2REST(rule), nil
	}
	return nil, common.ErrObjectNotFound
}

func (m CacheMethod) GetAdmissionRules(admType, ruleType string, acc *access.AccessControl) []*api.RESTAdmissionRule {
	admPolicyCache := selectAdminPolicyCache(admType, ruleType)
	if admPolicyCache == nil {
		rules := make([]*api.RESTAdmissionRule, 0)
		return rules
	}

	cacheMutexRLock()
	defer cacheMutexRUnlock()

	rules := make([]*api.RESTAdmissionRule, 0, len(admPolicyCache.RuleHeads))
	for _, head := range admPolicyCache.RuleHeads {
		if rule, ok := admPolicyCache.RuleMap[head.ID]; ok {
			if !acc.Authorize(rule, nil) {
				continue
			}
			rules = append(rules, admissionRule2REST(rule))
		}
	}
	return rules
}

// caller owns cacheMutexRLock & has readAll right
func (m CacheMethod) GetFedAdmissionRulesCache(admType, ruleType string) (*share.CLUSAdmissionRules, error) {
	admPolicyCache := selectAdminPolicyCache(admType, ruleType)
	if admPolicyCache == nil {
		return nil, nil
	}

	rules := &share.CLUSAdmissionRules{
		RuleHeads: admPolicyCache.RuleHeads,
		RuleMap:   admPolicyCache.RuleMap,
	}

	return rules, nil
}

func (m CacheMethod) GetAdmissionState(acc *access.AccessControl) (*api.RESTAdmissionState, error) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if !acc.Authorize(&admStateCache, nil) {
		return nil, common.ErrObjectAccessDenied
	}

	enable := admStateCache.Enable
	mode := admStateCache.Mode
	defaultAction := admStateCache.DefaultAction
	admClientMode := admStateCache.AdmClientMode
	failurePolicy := admStateCache.FailurePolicy
	if failurePolicy == "" {
		failurePolicy = resource.IgnoreLower
	}
	state := &api.RESTAdmissionState{
		Enable:        &enable,
		Mode:          &mode,
		DefaultAction: &defaultAction,
		AdmClientMode: &admClientMode,
		FailurePolicy: &failurePolicy,
		CtrlStates:    make(map[string]bool),
		CfgType:       api.CfgTypeUserCreated,
	}
	for admType, ctrlState := range admStateCache.CtrlStates {
		state.CtrlStates[admType] = ctrlState.Enable
	}
	if admStateCache.CfgType == share.GroundCfg {
		state.CfgType = api.CfgTypeGround
	}

	return state, nil
}

func (m CacheMethod) GetAdmissionStats(acc *access.AccessControl) (*api.RESTAdmissionStats, error) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	if !acc.Authorize(&admStats, nil) {
		return nil, common.ErrObjectAccessDenied
	}

	stats := &api.RESTAdmissionStats{
		K8sAllowedRequests:    atomic.LoadUint64(&admStats.K8sAllowedRequests),
		K8sDeniedRequests:     atomic.LoadUint64(&admStats.K8sDeniedRequests),
		K8sErroneousRequests:  atomic.LoadUint64(&admStats.K8sErroneousRequests),
		K8sIgnoredRequests:    atomic.LoadUint64(&admStats.K8sIgnoredRequests),
		K8sProcessingRequests: atomic.LoadInt64(&admStats.K8sProcessingRequests),
	}

	return stats, nil
}

func (m CacheMethod) GetAdmissionPssDesc() map[string][]string {
	baselineDesc := make([]string, len(baselinePolicyConditions))
	for idx, cond := range baselinePolicyConditions {
		baselineDesc[idx] = cond.ViolationReason
	}
	restrictedDesc := make([]string, len(restrictedConditions))
	for idx, cond := range restrictedConditions {
		restrictedDesc[idx] = cond.ViolationReason
	}
	desc := map[string][]string{
		share.PssPolicyBaseline:   baselineDesc,
		share.PssPolicyRestricted: restrictedDesc,
	}

	return desc
}

func fillDenyMessageFromRule(c *nvsysadmission.AdmContainerInfo, rule *share.CLUSAdmissionRule, scannedImage *nvsysadmission.ScannedImageSummary) string {
	var message string

	for _, crt := range rule.Criteria {
		switch crt.Name {
		case share.CriteriaKeyImageCompliance:
			found := scannedImage.SecretsCnt > 0 || scannedImage.SetIDPermCnt > 0
			if found {
				message = fmt.Sprintf("Found I.4.8[setuid/setgid: %d], I.4.10[secrets: %d]. Please review your image compliance report.", scannedImage.SetIDPermCnt, scannedImage.SecretsCnt)
			}
		case share.CriteriaKeyEnvVarSecrets:
			found := len(c.EnvSecrets) > 0
			if found {
				message = "Found environment secrets in your YAML resources: \n"
				for _, log := range c.EnvSecrets {
					message += fmt.Sprintf("Type[%s]: %s\n", log.RuleDesc, log.Text)
				}
			}
		case share.CriteriaKeySharePidWithHost, share.CriteriaKeyShareIpcWithHost, share.CriteriaKeyShareNetWithHost,
			share.CriteriaKeyRunAsPrivileged, share.CriteriaKeyRunAsRoot, share.CriteriaKeyPspCompliance:
			var messages []string
			props := []bool{c.Privileged, c.RunAsUser == 0, c.HostIPC, c.HostNetwork, c.HostPID, c.AllowPrivilegeEscalation}
			propNames := []string{"privileged=true", "runAsUser=0", "hostIPC=true", "hostNetwork=true", "hostPID=true", "(allowPrivilegeEscalation=true or capabilities:add:SYS_ADMIN is enabled)"}
			for i, prop := range props {
				if prop {
					messages = append(messages, propNames[i])
				}
			}
			if len(messages) > 0 {
				temp := fmt.Sprintf("%s in your YAML resources", strings.Join(messages, ", "))
				messages = nil
				messages = append(messages, temp)
			}
			if c.RunAsUser == -1 && scannedImage.RunAsRoot {
				messages = append(messages, fmt.Sprintf("runAsRoot in the image"))
			}
			if len(messages) > 0 {
				message = fmt.Sprintf("Found %s.", strings.Join(messages, " or "))
			}
		case share.CriteriaKeyHasPssViolation:
			selectedPolicyViolations := pssViolations(crt, c, scannedImage.RunAsRoot)
			if len(selectedPolicyViolations) > 0 {
				message = fmt.Sprintf("Deployment has PSS/PSA Violations: %s.", strings.Join(selectedPolicyViolations, " "))
			}
		}
		if message != "" {
			break
		}
	}
	return message
}

func PopulateRulesToOpa() {
	ruleTypes := make([]string, 0, 4)
	ruleTypes = append(ruleTypes, share.FedAdmCtrlExceptRulesType, share.FedAdmCtrlDenyRulesType, api.ValidatingExceptRuleType, api.ValidatingDenyRuleType)

	cacheMutexRLock()
	defer cacheMutexRUnlock()

	for _, ruleType := range ruleTypes {
		admPolicyCache := selectAdminPolicyCache(admission.NvAdmValidateType, ruleType)
		if admPolicyCache == nil {
			continue
		}

		for _, head := range admPolicyCache.RuleHeads {
			if rule, ok := admPolicyCache.RuleMap[head.ID]; ok {
				opa.ConvertToRegoRule(rule)
			}
		}
	}
}

func GetPredefinedRiskyRoles() []string {
	keys := make([]string, 0, len(predefinedRiskyRoles))
	for k := range predefinedRiskyRoles {
		keys = append(keys, k)
	}
	return keys
}

func formatRiskyRoleCriteriaMsg(critValue string) string {
	results := []string{}
	items := strings.Split(critValue, ",")
	for _, k := range items {
		k = strings.TrimSpace(k)
		if _, ok := predefinedRiskyRoles[k]; ok {
			results = append(results, predefinedRiskyRoles[k])
		}
	}

	return strings.Join(results, ",")
}

func isStorageClassNameCriterionMet(crt *share.CLUSAdmRuleCriterion, namespace string, c *nvsysadmission.AdmContainerInfo) (bool, bool) {
	claimeNames := make([]string, 0)
	for _, v := range c.Volumes {
		if v.VolumeSource.PersistentVolumeClaim != nil {
			claimName := v.VolumeSource.PersistentVolumeClaim.ClaimName
			claimeNames = append(claimeNames, claimName)
		}
	}

	for _, claimName := range claimeNames {
		scName, err := getStorageClassNameFromK8s(namespace, claimName)
		if err == nil {
			met, positive := isStringCriterionMet(crt, scName)
			if met {
				return met, positive
			}
		} else {
			log.WithFields(log.Fields{"claimeNames": claimeNames, "namespace": namespace, "claimName": claimName}).Debug("get sc name in PVC failed")
		}
	}

	return false, true
}

func getStorageClassNameFromK8s(ns, name string) (string, error) {
	// for assessment
	if ns == "" {
		ns = "default"
	}

	if obj, err := global.ORCH.GetResource(resource.RscTypePersistentVolumeClaim, ns, name); err == nil {
		if pvcObj := obj.(*k8sCorev1.PersistentVolumeClaim); pvcObj != nil {
			return *pvcObj.Spec.StorageClassName, nil
		}
	}
	return "", errors.New("PVC not found")
}

func (m CacheMethod) MatchK8sAdmissionRulesForPVC(ns, name, scName string, evalContext *nvsysadmission.AdmCtrlEvalContext) (
	*nvsysadmission.AdmCtrlAssessResult, bool) {

	forTesting := evalContext.ForTesting
	result := &nvsysadmission.AdmCtrlAssessResult{}

	// if we are in federation, compare with fed admission rules(i.e. fed_admctrl_exception/fed_admctrl_deny rules) before crd/local user-defined rules
	if fedRole := cacher.GetFedMembershipRoleNoAuth(); fedRole == api.FedRoleJoint || fedRole == api.FedRoleMaster {
		if isActionMatched := matchK8sAdmissionRulesForPVC(evalContext.AdmCtrlType, share.FedAdmCtrlDenyRulesType, share.FederalCfg,
			ns, name, scName, evalContext, result); isActionMatched && !forTesting {
			return result, true
		}
	}

	// 1. CRD deny rules
	// 2. user-defined deny rules
	for _, matchScope := range []int{share.GroundCfg, share.UserCreated} {
		if isActionMatched := matchK8sAdmissionRulesForPVC(evalContext.AdmCtrlType, api.ValidatingDenyRuleType, matchScope,
			ns, name, scName, evalContext, result); isActionMatched && !forTesting {
			return result, true
		}
	}

	return result, false
}

// matchCfgType being 0 means to compare with default(critical) rules only
// return true means an enabled rule is matched with allow/deny action
func matchK8sAdmissionRulesForPVC(admType, ruleType string, matchCfgType int, ns, name, scName string,
	evalContext *nvsysadmission.AdmCtrlEvalContext, result *nvsysadmission.AdmCtrlAssessResult) bool {

	var hasActionMatched bool

	forTesting := evalContext.ForTesting
	admPolicyCache := selectAdminPolicyCache(admType, ruleType)
	if admPolicyCache != nil {
		cacheMutexRLock()
		defer cacheMutexRUnlock()

		for _, head := range admPolicyCache.RuleHeads {
			if rule, ok := admPolicyCache.RuleMap[head.ID]; ok && (forTesting || !rule.Disable) && rule.Category == admission.AdmRuleCatK8s {
				if ((matchCfgType == _criticalRulesOnly) && rule.Critical) || (!rule.Critical && (matchCfgType == int(rule.CfgType))) {
					if matched := isAdmissionPVCRuleMet(rule.Criteria, ns, name, scName); matched {
						// for assessment, disabled rule could be matched even though it's ignored in the calc of final request result
						isActionMatched := collectMatchedResult(rule, evalContext, nil, result, ruleType, "", "", "")
						if !forTesting {
							log.WithFields(log.Fields{"id": head.ID, "namespace": ns, "StorageClassName": scName, "type": ruleType}).Debug("matched a rule")
						}

						if isActionMatched {
							if forTesting {
								hasActionMatched = true
							} else {
								return true
							}
						}
					}
				}
			}
		}
	}

	return hasActionMatched
}

func isAdmissionPVCRuleMet(criteria []*share.CLUSAdmRuleCriterion, ns, name, scName string) bool {
	var met, positive bool
	var mets map[string]bool = make(map[string]bool)
	var poss map[string]bool = make(map[string]bool)

	for _, crt := range criteria {
		key := crt.Name

		switch crt.Name {
		case share.CriteriaKeyNamespace:
			met, positive = isStringCriterionMet(crt, ns)
		case share.CriteriaKeyStorageClassName:
			met, positive = isStringCriterionMet(crt, scName)
		default:
			met, positive = false, true
		}

		if v, ok := mets[key]; !ok {
			mets[key] = met
			poss[key] = positive
		} else {
			p, _ := poss[key]
			if !positive && !p {
				mets[key] = v && met
			} else {
				mets[key] = v || met
			}
			poss[key] = p || positive
		}
	}

	if len(mets) == 0 {
		return false
	}
	for _, met = range mets {
		if !met {
			return false
		}
	}

	return true
}

func isRiskyServiceAccountRuleMet(crt *share.CLUSAdmRuleCriterion, saName, namespace string) (bool, bool) {
	if saName == "" {
		saName = "default"
	}

	if namespace == "" {
		namespace = "default"
	}

	allBoundRiksRoles, err := resource.GetAllRiskyRolesByServiceAccount(saName, namespace)

	if err != nil {
		log.WithFields(log.Fields{"err": err, "crt.Value": crt.Value, "namespace": namespace, "saName": saName}).Error("GetAllRiskyRolesByServiceAccount fail")
		return false, true
	}

	log.WithFields(log.Fields{"crt.Value": crt.Value, "allBoundRiksRoles": allBoundRiksRoles, "namespace": namespace, "saName": saName}).Debug("isRiskyServiceAccountRuleMet")

	if len(allBoundRiksRoles) > 0 {
		checks := strings.Split(crt.Value, ",")
		for _, check := range checks {
			checkTag := 0
			switch check {
			case "risky_role_view_secret":
				checkTag = resource.RiskyRole_ViewSecret
			case "risky_role_any_action_workload":
				checkTag = resource.RiskyRole_AnyActionWorkload
			case "risky_role_any_action_rbac":
				checkTag = resource.RiskyRole_AnyActionRBAC
			case "risky_role_create_pod":
				checkTag = resource.RiskyRole_CreatePod
			case "risky_role_exec_into_container":
				checkTag = resource.RiskyRole_ExecContainer
			default:
			}

			for _, riskyTags := range allBoundRiksRoles {
				if (riskyTags & checkTag) > 0 {
					return true, true // found
				}
			}
		}
	}

	return false, true
}

package rest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/cache"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	admission "github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg"
	nvsysadmission "github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg/admission"
	"github.com/neuvector/neuvector/controller/opa"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

// const (
// 	_writeHeader   = true
// 	_noWriteHeader = false
// )

type admissionRequestObject struct {
	ApiVersion string            `json:"apiVersion,omitempty"`
	Kind       string            `json:"kind,omitempty"`
	ObjectMeta metav1.ObjectMeta `json:"metadata,omitempty"`
}

func getAdmCtrlRuleTypes(query *restQuery, defScope string) ([]string, string) {
	var ok bool
	var scope string
	ruleTypes := make([]string, 0, 4)
	if query == nil {
		scope = defScope
	} else if scope, ok = query.pairs[api.QueryScope]; !ok { // if not specified, use default value
		scope = defScope
	}
	if scope == share.ScopeLocal {
		ruleTypes = append(ruleTypes, api.ValidatingExceptRuleType, api.ValidatingDenyRuleType)
	} else if scope == share.ScopeFed {
		ruleTypes = append(ruleTypes, share.FedAdmCtrlExceptRulesType, share.FedAdmCtrlDenyRulesType)
	} else if scope == share.ScopeAll {
		ruleTypes = append(ruleTypes, share.FedAdmCtrlExceptRulesType, share.FedAdmCtrlDenyRulesType, api.ValidatingExceptRuleType, api.ValidatingDenyRuleType)
	}

	return ruleTypes, scope
}

func getRuleId(w http.ResponseWriter, ps httprouter.Params) (uint32, error) {
	id, err := strconv.Atoi(ps.ByName("id"))
	if err != nil || id <= 0 || id > 4294967295 {
		log.WithFields(log.Fields{"id": id}).Error("Invalid ID")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return 0, common.ErrObjectNotFound
	}
	return uint32(id), nil
}

func validateAdmCtrlCriteria(criteria []*share.CLUSAdmRuleCriterion, options map[string]*api.RESTAdmissionRuleOption, ruleType string) error {
	if criteria != nil && options == nil {
		return fmt.Errorf("Invalid criteria options")
	}

	numOps := utils.NewSet(share.CriteriaOpLessEqualThan, share.CriteriaOpBiggerEqualThan, share.CriteriaOpBiggerThan)
	hasStorageClassCriteria := false

	for _, crt := range criteria {
		var allowedOp, allowedValue bool

		if crt.Type == "customPath" {
			allowedOp, allowedValue = validateCustomPathCriteria(crt)
		}

		if crt.Type == "saBindRiskyRole" {
			allowedOp, allowedValue = validateSaBindRiskyRoleCriteria(crt, options)
		}

		if crt.Type == "customPath" || crt.Type == "saBindRiskyRole" {
			if ruleType != api.ValidatingDenyRuleType {
				return fmt.Errorf("Unsupported criterion name: %s", crt.Name)
			}

			if !allowedOp {
				return fmt.Errorf("Invalid criterion operator: %s", crt.Op)
			}
			if !allowedValue {
				return fmt.Errorf("Invalid criterion value: %s", crt.Value)
			}
			continue
		}

		if crt.Op == share.CriteriaOpRegexContainsAny || crt.Op == share.CriteriaOpRegexNotContainsAny {
			for _, value := range strings.Split(crt.Value, ",") {
				value = strings.TrimSpace(value)
				if _, err := regexp.Compile(value); err != nil {
					return fmt.Errorf("Invalid criterion value for regex operator: %s", crt.Value)
				}
			}
		}

		if option, exist := options[crt.Name]; exist {
			if len(option.Ops) == 0 {
				allowedOp = true
			} else {
				for _, op := range option.Ops {
					if op == crt.Op {
						allowedOp = true
						break
					}
				}
			}
			if len(option.Values) > 0 {
				for _, value := range option.Values {
					if value == crt.Value {
						allowedValue = true
						break
					}
				}
			} else {
				numberVal := false
				for _, opOption := range option.Ops {
					if numOps.Contains(opOption) {
						numberVal = true
						break
					}
				}
				if numberVal {
					if _, err := strconv.ParseFloat(crt.Value, 64); err == nil {
						allowedValue = true // meaning any valid float value is allowed
					}
				} else {
					allowedValue = true // meaning any valid float value is allowed
				}
			}
			if !allowedOp {
				return fmt.Errorf("Invalid criterion operator: %s", crt.Op)
			}
			if !allowedValue {
				return fmt.Errorf("Invalid criterion value: %s", crt.Value)
			}
			if crt.Name == share.CriteriaKeyCVEScoreCount && len(crt.SubCriteria) == 0 {
				crt.SubCriteria = []*share.CLUSAdmRuleCriterion{
					{
						Name:  share.SubCriteriaCount,
						Op:    share.CriteriaOpBiggerEqualThan,
						Value: "1",
					},
				}
			}
			if len(crt.SubCriteria) > 0 {
				if err := validateAdmCtrlCriteria(crt.SubCriteria, option.SubOptions, ruleType); err != nil {
					return err
				}
			}
		} else {
			return fmt.Errorf("Unsupported criterion name: %s", crt.Name)
		}

		if crt.Name == share.CriteriaKeyStorageClassName {
			hasStorageClassCriteria = true
		}
	}

	if hasStorageClassCriteria {
		for _, crt := range criteria {
			if crt.Name != share.CriteriaKeyStorageClassName && crt.Name != share.CriteriaKeyNamespace {
				return fmt.Errorf("The StorageClass Name criteria can only be used in conjunction with namespace criteria. Criterion name: %s", crt.Name)
			}
		}
	}

	return nil
}

// cluster lock is owned by caller
func setAdmCtrlStateInCluster(enable *bool, mode, defaultAction, admClientMode, failurePolicy *string,
	cfgType share.TCfgType) (int, int, *share.CLUSAdmissionState, *share.CLUSAdmissionState) {

	var cconf *share.CLUSAdmissionState
	var rev uint64
	var origConf *share.CLUSAdmissionState

	retry := 0
	for retry < retryClusterMax {
		cconf, rev = clusHelper.GetAdmissionStateRev(resource.NvAdmSvcName)
		if cconf == nil {
			return http.StatusNotFound, api.RESTErrObjectNotFound, nil, nil
		}

		origConf = &share.CLUSAdmissionState{
			Enable:         cconf.Enable,
			Mode:           cconf.Mode,
			DefaultAction:  cconf.DefaultAction,
			AdmClientMode:  cconf.AdmClientMode,
			FailurePolicy:  cconf.FailurePolicy,
			NvDeployStatus: cconf.NvDeployStatus,
			CfgType:        cconf.CfgType,
		}
		// we should be notified by consul watcher and update cache in the handler function
		if enable != nil {
			cconf.Enable = *enable
			if ctrlState, exist := cconf.CtrlStates[admission.NvAdmValidateType]; exist {
				ctrlState.Enable = *enable
			}
		}
		if mode != nil {
			cconf.Mode = *mode
		}
		if defaultAction != nil {
			cconf.DefaultAction = *defaultAction
		}
		if admClientMode != nil {
			cconf.AdmClientMode = *admClientMode
		}
		/* do not allow admission control webhook's FailurePolicy to be configurable yet
		if failurePolicy != nil {
			cconf.FailurePolicy = *failurePolicy
		}
		*/
		cconf.CfgType = cfgType
		if err := clusHelper.PutAdmissionStateRev(resource.NvAdmSvcName, cconf, rev); err == nil {
			break
		}
		retry++
	}
	if retry >= retryClusterMax {
		return http.StatusInternalServerError, api.RESTErrFailWriteCluster, nil, nil
	}

	return http.StatusOK, 0, origConf, cconf
}

func sameRuleSettings(ruleCfg *api.RESTAdmissionRuleConfig, clusConf *share.CLUSAdmissionRule) bool { // return true means same settings
	if (ruleCfg.Category != nil && *ruleCfg.Category != clusConf.Category) || (ruleCfg.Comment != nil && *ruleCfg.Comment != clusConf.Comment) {
		return false
	} else if ruleCfg.Criteria != nil {
		if len(ruleCfg.Criteria) != len(clusConf.Criteria) {
			return false
		}
		for idx, ruleCrt := range ruleCfg.Criteria {
			clusCrt := clusConf.Criteria[idx]
			if ruleCrt.Name != clusCrt.Name || ruleCrt.Op != clusCrt.Op || ruleCrt.Value != clusCrt.Value {
				return false
			}
		}
	}
	return true
}

func getAdmissionRule(id uint32, acc *access.AccessControl) (*api.RESTAdmissionRule, error) {
	var rule *api.RESTAdmissionRule
	err := common.ErrObjectNotFound
	var ruleType string
	var ruleTypes []string
	if id > api.StartingFedAdmRespRuleID && id < api.MaxFedAdmRespRuleID {
		ruleTypes = []string{share.FedAdmCtrlExceptRulesType, share.FedAdmCtrlDenyRulesType}
	} else {
		ruleTypes = []string{api.ValidatingExceptRuleType, api.ValidatingDenyRuleType}
	}
	for _, ruleType = range ruleTypes {
		if rule, err = cacher.GetAdmissionRule(admission.NvAdmValidateType, ruleType, id, acc); err == nil {
			break
		}
	}
	if err != nil {
		log.WithFields(log.Fields{"id": id, "ruleType": ruleType, "error": err}).Error()
	}

	return rule, err
}

func applyTransact(w http.ResponseWriter, txn *cluster.ClusterTransact) error {
	if ok, err := txn.Apply(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		if w != nil {
			restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		}
		return err
	} else if !ok {
		e := "Atomic write to the cluster failed"
		log.Error(e)
		if w != nil {
			restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster, e)
		}
		return fmt.Errorf("%s", e)
	}
	return nil
}

func getAdmCtrlRuleContainers(targets []string) (uint8, error) {
	var ruleContainers uint8

	for _, t := range targets {
		switch t {
		case share.AdmCtrlRuleContainers:
			ruleContainers = ruleContainers | share.AdmCtrlRuleContainersN
		case share.AdmCtrlRuleInitContainers:
			ruleContainers = ruleContainers | share.AdmCtrlRuleInitContainersN
		case share.AdmCtrlRuleEphemeralContainers:
			ruleContainers = ruleContainers | share.AdmCtrlRuleEphemeralContainersN
		default:
			return 0, fmt.Errorf("Invalid containers value")
		}
	}
	if ruleContainers == 0 {
		ruleContainers = share.AdmCtrlRuleContainersN
	}

	return ruleContainers, nil
}

func handlerAdmissionStatistics(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	if !k8sPlatform {
		restRespError(w, http.StatusPreconditionFailed, api.RESTErrAdmCtrlUnSupported)
		return
	}
	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	stats, err := cacher.GetAdmissionStats(acc)
	if err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	resp := api.RESTAdmissionStatsData{Stats: stats}
	restRespSuccess(w, r, &resp, acc, login, nil, "Get admission control statistics")
}

func handlerGetAdmissionState(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}
	state, err := cacher.GetAdmissionState(acc)
	if err != nil {
		if login.hasFedPermission() {
			resp := api.RESTAdmissionConfigData{
				K8sEnv: k8sPlatform,
			}
			restRespSuccess(w, r, &resp, acc, login, nil, "")
		} else {
			restRespNotFoundLogAccessDenied(w, login, err)
		}
		return
	}

	if k8sPlatform {
		var errs []string
		k8sClusterRoles := []string{resource.NvRbacRole, resource.NvAdmCtrlRole, resource.NvAppRole}
		if errs, _ = resource.VerifyNvRbacRoles(k8sClusterRoles, false); len(errs) == 0 {
			errs, _ = resource.VerifyNvRbacRoleBindings(k8sClusterRoles, false, true)
		}
		if len(errs) > 0 {
			msg := strings.Join(errs, "<p>")
			restRespErrorMessage(w, http.StatusNotFound, api.RESTErrK8sNvRBAC, msg)
			return
		}
	}
	/*[2019/Apr.] do not enable ConfigMap support for env vars yet
	if !admission.VerifyConfigMapPermission() {
		restRespError(w, http.StatusNotFound, api.RESTErrNvPermission)
		return
	}*/
	if k8sPlatform {
		var svcInfo *admission.ValidateWebhookSvcInfo
		err, svcInfo = admission.GetValidateWebhookSvcInfo(resource.NvAdmSvcName)
		if err != nil {
			restRespError(w, http.StatusNotFound, svcInfo.Status)
			return
		}
		state.AdmSvcType = &svcInfo.SvcType
		state.FailurePolicy = state.FailurePolicy
		/* do not allow admission control webhook's FailurePolicy to be configurable yet
		if admission.IsNsSelectorSupported() {
			state.FailurePolicyChangable = true
		}
		*/
		state.AdmClientModeOptions = map[string]string{
			share.AdmClientModeSvc: fmt.Sprintf("%s.%s.svc", resource.NvAdmSvcName, resource.NvAdmSvcNamespace),
			share.AdmClientModeUrl: fmt.Sprintf("https://%s.%s.svc:%d", resource.NvAdmSvcName, resource.NvAdmSvcNamespace, svcInfo.SvcNodePort),
		}
	} else {
		enable := false
		mode := share.AdmCtrlModeProtect
		defaultAction := share.AdmCtrlActionAllow
		state = &api.RESTAdmissionState{
			Enable:        &enable,
			Mode:          &mode,
			DefaultAction: &defaultAction,
		}
	}
	var resp = api.RESTAdmissionConfigData{
		State:  state,
		K8sEnv: k8sPlatform,
	}
	restRespSuccess(w, r, &resp, acc, login, nil, "Get admission control state")
}

func handlerPatchAdmissionState(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	if !k8sPlatform {
		restRespError(w, http.StatusPreconditionFailed, api.RESTErrAdmCtrlUnSupported)
		return
	}
	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}
	currState, err := cacher.GetAdmissionState(acc)
	if err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	} else {
		if currState.CfgType == api.CfgTypeGround {
			restRespError(w, http.StatusBadRequest, api.RESTErrOpNotAllowed)
			return
		}
	}

	var errs []string
	k8sClusterRoles := []string{resource.NvRbacRole, resource.NvAdmCtrlRole, resource.NvAppRole}
	if errs, _ = resource.VerifyNvRbacRoles(k8sClusterRoles, false); len(errs) == 0 {
		errs, _ = resource.VerifyNvRbacRoleBindings(k8sClusterRoles, false, true)
	}
	if len(errs) > 0 {
		msg := strings.Join(errs, "<p>")
		restRespErrorMessage(w, http.StatusNotFound, api.RESTErrK8sNvRBAC, msg)
		return
	}
	if err, svcInfo := admission.GetValidateWebhookSvcInfo(resource.NvAdmSvcName); err != nil {
		restRespError(w, http.StatusNotFound, svcInfo.Status)
		return
	}

	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTAdmissionConfigData
	err = json.Unmarshal(body, &rconf)
	if err != nil || rconf.State == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	state := rconf.State
	if state == nil || (state.Mode != nil && *state.Mode != share.AdmCtrlModeMonitor && *state.Mode != share.AdmCtrlModeProtect) ||
		(state.DefaultAction != nil && *state.DefaultAction != share.AdmCtrlActionAllow && *state.DefaultAction != share.AdmCtrlActionDeny) ||
		(state.AdmClientMode != nil && *state.AdmClientMode != share.AdmClientModeSvc && *state.AdmClientMode != share.AdmClientModeUrl) {
		log.Error("Request contains invalid data")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}
	if state.Mode != nil && *state.Mode == share.AdmCtrlModeProtect {
		if !licenseAllowEnforce() {
			e := "The policy mode is not enabled in the license"
			log.WithFields(log.Fields{"mode": *state.Mode}).Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrLicenseFail, e)
		}
	}

	if !*currState.Enable && (state.Enable == nil || !*state.Enable) && (state.Mode != nil || state.DefaultAction != nil || state.AdmClientMode != nil || state.FailurePolicy != nil) {
		restRespError(w, http.StatusBadRequest, api.RESTErrWebhookIsDisabled)
		return
	}

	var lock cluster.LockInterface
	if lock, err = lockClusKey(w, share.CLUSLockAdmCtrlKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	status, code, origConf, cconf := setAdmCtrlStateInCluster(state.Enable, state.Mode, state.DefaultAction, state.AdmClientMode, state.FailurePolicy, share.UserCreated)
	if status != http.StatusOK {
		restRespError(w, status, code)
		return
	}
	time.Sleep(time.Second)

	const msg = "Patch admission control state"
	var msgState string
	msgFinal := msg
	if cconf.Enable {
		msgState = "enabled"
	} else {
		msgState = "disabled"
	}
	if ctrlState, exist := cconf.CtrlStates[admission.NvAdmValidateType]; exist {
		admClientMode := origConf.AdmClientMode
		if state.AdmClientMode != nil {
			admClientMode = *state.AdmClientMode
		}
		/* do not allow admission control webhook's FailurePolicy to be configurable yet
		failurePolicy := origConf.FailurePolicy
		if state.FailurePolicy != nil {
			failurePolicy = *state.FailurePolicy
		}
		if failurePolicy == resource.FailLower {
			failurePolicy = resource.Fail
		} else {
			failurePolicy = resource.Ignore
		}
		*/
		failurePolicy := resource.Ignore
		k8sResInfo := admission.ValidatingWebhookConfigInfo{
			Name: resource.NvAdmValidatingName,
			WebhooksInfo: []*admission.WebhookInfo{
				{
					Name: resource.NvAdmValidatingWebhookName,
					ClientConfig: admission.ClientConfig{
						ClientMode:  admClientMode,
						ServiceName: resource.NvAdmSvcName,
						Path:        ctrlState.Uri,
					},
					FailurePolicy:  failurePolicy,
					TimeoutSeconds: resource.DefTimeoutSeconds,
				},
				{
					Name: resource.NvStatusValidatingWebhookName,
					ClientConfig: admission.ClientConfig{
						ClientMode:  admClientMode,
						ServiceName: resource.NvAdmSvcName,
						Path:        ctrlState.NvStatusUri,
					},
					FailurePolicy:  resource.Ignore,
					TimeoutSeconds: resource.DefTimeoutSeconds,
				},
			},
		}
		skip, err := admission.ConfigK8sAdmissionControl(&k8sResInfo, ctrlState)
		if !skip {
			alog := share.CLUSEventLog{ReportedAt: time.Now().UTC()}
			if err == nil {
				alog.Event = share.CLUSEvAdmCtrlK8sConfigured
				alog.Msg = fmt.Sprintf("Admission control is %s.", msgState)
			} else {
				alog.Event = share.CLUSEvAdmCtrlK8sConfigFailed
				alog.Msg = "Failed to configure admission control state."
			}
			evqueue.Append(&alog)
		}
		if err == nil {
			messages := make([]string, 0, 3)
			if cconf.Enable != origConf.Enable {
				messages = append(messages, fmt.Sprintf("state: %s", msgState))
			}
			if len(cconf.Mode) > 0 && cconf.Mode != origConf.Mode {
				messages = append(messages, fmt.Sprintf("mode: %s", *state.Mode))
			}
			if len(cconf.DefaultAction) > 0 && cconf.DefaultAction != origConf.DefaultAction {
				messages = append(messages, fmt.Sprintf("default action: %s", *state.DefaultAction))
			}
			if len(cconf.AdmClientMode) > 0 && cconf.AdmClientMode != origConf.AdmClientMode {
				messages = append(messages, fmt.Sprintf("client mode: %s", *state.AdmClientMode))
			}
			/* do not allow admission control webhook's FailurePolicy to be configurable yet
			if len(cconf.FailurePolicy) > 0 && cconf.FailurePolicy != origConf.FailurePolicy {
				messages = append(messages, fmt.Sprintf("failure policy: %s", *state.FailurePolicy))
			}
			*/
			if len(messages) > 0 {
				msgFinal = fmt.Sprintf("%s (%s)", msgFinal, strings.Join(messages, ", "))
			}
		} else {
			log.WithFields(log.Fields{"origConf": origConf, "err": err}).Info("Gonna revert admission control state in cluster")
			status, code, _, _ := setAdmCtrlStateInCluster(&origConf.Enable, &origConf.Mode, &origConf.DefaultAction, &origConf.AdmClientMode, &origConf.FailurePolicy, share.UserCreated)
			if status != http.StatusOK {
				log.WithFields(log.Fields{"status": status, "code": code}).Info("Failed to revert admission control state in cluster")
			}
			restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailKubernetesApi, err.Error())
			return
		}
	}

	restRespSuccess(w, r, nil, acc, login, &rconf, msgFinal)
}

func handlerGetAdmissionOptions(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSAdmissionState{}, nil) {
		if login.hasFedPermission() {
			resp := &api.RESTAdmissionConfigData{
				K8sEnv: k8sPlatform,
			}
			restRespSuccess(w, r, &resp, acc, login, nil, "Get admission control rule options")
		} else {
			restRespAccessDenied(w, login)
		}
		return
	}

	resp := &api.RESTAdmissionConfigData{
		Options: &api.RESTAdmRuleTypeOptions{
			DenyOptions:      nvsysadmission.GetAdmRuleTypeOptions(api.ValidatingDenyRuleType),
			ExceptionOptions: nvsysadmission.GetAdmRuleTypeOptions(api.ValidatingExceptRuleType),
		},
		K8sEnv:                  k8sPlatform,
		CustomCriteriaOptions:   nvsysadmission.GetCustomCriteriaOptions(),
		CustomCriteriaTemplates: nvsysadmission.GetCustomCriteriaTemplates(),
		PredefinedRiskyRoles:    cache.GetPredefinedRiskyRoles(),
	}
	keys := []string{share.CriteriaKeyRunAsPrivileged, share.CriteriaKeyRunAsRoot, share.CriteriaKeySharePidWithHost,
		share.CriteriaKeyShareIpcWithHost, share.CriteriaKeyShareNetWithHost, share.CriteriaKeyAllowPrivEscalation}
	pspCollection := make([]*api.RESTAdmRuleCriterion, 0, 6)
	for _, key := range keys {
		crit := &api.RESTAdmRuleCriterion{
			Name:  key,
			Op:    share.CriteriaOpEqual,
			Value: "true",
		}
		pspCollection = append(pspCollection, crit)
	}
	resp.Options.PspCollection = pspCollection
	resp.Options.PssCollections = cacher.GetAdmissionPssDesc()
	sigstoreVerifiers := []string{}
	if keys, _ := cluster.GetStoreKeys(share.CLUSConfigSigstoreRootsOfTrust); len(keys) > 0 {
		sigstoreVerifiers = make([]string, 0, len(keys))
		for _, key := range keys {
			if ss := strings.Split(key, "/"); len(ss) != 5 {
				continue
			} else {
				sigstoreVerifiers = append(sigstoreVerifiers, fmt.Sprintf("%s/%s", ss[3], ss[4]))
			}
		}
	}
	resp.Options.SigstoreVerifiers = sigstoreVerifiers

	restRespSuccess(w, r, resp, acc, login, nil, "Get admission control rule options")
}

// caller has been verified for federal admin access right
func replaceFedAdmissionRules(ruleType string, rulesNew *share.CLUSAdmissionRules) bool {
	if ruleType != share.FedAdmCtrlExceptRulesType && ruleType != share.FedAdmCtrlDenyRulesType {
		return false
	}

	var err error
	var lock cluster.LockInterface
	if lock, err = lockClusKey(nil, share.CLUSLockAdmCtrlKey); err != nil {
		return false
	}
	defer clusHelper.ReleaseLock(lock)

	// get current rules header list first
	rhsExisting, _ := clusHelper.GetAdmissionRuleList(admission.NvAdmValidateType, ruleType)

	// count total modified keys because of transaction's 64 keys limit
	modKeysCount := 0
	rhlChanged := false
	delRules := make([]uint32, 0, len(rhsExisting))
	patchedRules := make(map[uint32]*share.CLUSAdmissionRule, len(rulesNew.RuleMap))
	for _, rhExisting := range rhsExisting {
		if _, ok := rulesNew.RuleMap[rhExisting.ID]; !ok {
			delRules = append(delRules, rhExisting.ID)
		}
	}
	for _, ruleNew := range rulesNew.RuleMap {
		if ruleNew != nil {
			ruleExisting := clusHelper.GetAdmissionRule(admission.NvAdmValidateType, ruleType, ruleNew.ID)
			if ruleExisting == nil || !reflect.DeepEqual(*ruleNew, *ruleExisting) {
				patchedRules[ruleNew.ID] = ruleNew
			}
		}
	}
	if !reflect.DeepEqual(rulesNew.RuleHeads, rhsExisting) {
		rhlChanged = true
		modKeysCount++
	}
	modKeysCount += len(delRules)
	modKeysCount += len(patchedRules)

	if modKeysCount < _maxTransacKeys { // less then 64 keys modified. use transaction
		txn := cluster.Transact()
		defer txn.Close()
		// delete obsolete id keys
		for _, id := range delRules {
			clusHelper.DeleteAdmissionRuleTxn(txn, admission.NvAdmValidateType, ruleType, id)
		}
		// write updated id keys
		for _, ruleNew := range patchedRules {
			clusHelper.PutAdmissionRuleTxn(txn, admission.NvAdmValidateType, ruleType, ruleNew)
		}
		// overwrite rule headers list
		if rhlChanged {
			clusHelper.PutAdmissionRuleListTxn(txn, admission.NvAdmValidateType, ruleType, rulesNew.RuleHeads)
		}
		return applyTransact(nil, txn) == nil
	} else {
		// delete obsolete id keys
		for _, id := range delRules {
			clusHelper.DeleteAdmissionRule(admission.NvAdmValidateType, ruleType, id)
		}
		// write updated  id keys
		for _, ruleNew := range patchedRules {
			clusHelper.PutAdmissionRule(admission.NvAdmValidateType, ruleType, ruleNew)
		}
		// overwrite rule headers list
		if rhlChanged {
			if err := clusHelper.PutAdmissionRuleList(admission.NvAdmValidateType, ruleType, rulesNew.RuleHeads); err != nil {
				return false
			}
		}
	}

	return true
}

func handlerGetAdmissionRules(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}
	query := restParseQuery(r)
	ruleTypes, _ := getAdmCtrlRuleTypes(query, share.ScopeAll) // internal rule types: "exception", "deny", "fed_admctrl_exception" or "fed_admctrl_deny"
	if len(ruleTypes) == 0 {
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	allRules := make(map[string][]*api.RESTAdmissionRule, 7)
	for _, ruleType := range ruleTypes {
		rules := cacher.GetAdmissionRules(admission.NvAdmValidateType, ruleType, acc)
		switch ruleType {
		case share.FedAdmCtrlExceptRulesType, share.FedAdmCtrlDenyRulesType:
			allRules[ruleType] = rules
		case api.ValidatingExceptRuleType, api.ValidatingDenyRuleType:
			critRules := make([]*api.RESTAdmissionRule, 0, 4)
			crdRules := make([]*api.RESTAdmissionRule, 0, len(rules))
			userRules := make([]*api.RESTAdmissionRule, 0, len(rules))
			for _, rule := range rules {
				if rule.Critical {
					critRules = append(critRules, rule)
				} else if rule.CfgType == api.CfgTypeGround {
					crdRules = append(crdRules, rule)
				} else {
					userRules = append(userRules, rule)
				}
			}
			if ruleType == api.ValidatingExceptRuleType {
				allRules[share.CriticalAdmCtrlExceptRulesType] = critRules
				allRules[share.CrdAdmCtrlExceptRulesType] = crdRules
			} else {
				allRules[share.CrdAdmCtrlDenyRulesType] = crdRules
			}
			allRules[ruleType] = userRules
		}
	}

	totalCount := 0
	for _, rules := range allRules {
		totalCount += len(rules)
	}
	// query.start: start idx(inclusive) of the rule to get in the union of all admission rules
	end := totalCount // end idx(exclusive) of the rule to get in the union of all admission rules
	if query.limit > 0 && query.limit < totalCount {
		end = query.start + query.limit
	}

	// ruleTypes is in display order
	ruleTypes = []string{share.CriticalAdmCtrlExceptRulesType, share.FedAdmCtrlExceptRulesType, share.FedAdmCtrlDenyRulesType,
		share.CrdAdmCtrlExceptRulesType, share.CrdAdmCtrlDenyRulesType, api.ValidatingExceptRuleType, api.ValidatingDenyRuleType}
	resp := api.RESTAdmissionRulesData{Rules: make([]*api.RESTAdmissionRule, 0, end-query.start)}
	startIdxTotal := 0 // current idx in the union of all admission rules
	for _, ruleType := range ruleTypes {
		if rules, ok := allRules[ruleType]; ok && len(rules) > 0 {
			endIdxTotal := startIdxTotal + len(rules) // idx of the last rule(for this rule type) in the union of all admission rules
			if (endIdxTotal < query.start) || (startIdxTotal >= end) {
				startIdxTotal += len(rules)
				continue
			}

			endIdxTotal = startIdxTotal + len(rules)
			collectStartIdx := 0        // start idx(inclusive) of the rule to collect in this rule type
			collectEndIdx := len(rules) // end idx(exclusive) of the rule to collect in this rule type
			if startIdxTotal < query.start {
				collectStartIdx = query.start - startIdxTotal
			}
			if endIdxTotal > end {
				collectEndIdx = len(rules) - (endIdxTotal - end)
			}
			target := rules[collectStartIdx:collectEndIdx]
			resp.Rules = append(resp.Rules, target...)
			startIdxTotal += len(rules)
		}
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get admission control rules list")
}

// caller must own CLUSLockAdmCtrlKey lock
func deleteAdmissionRules(w http.ResponseWriter, scope string, ruleTypeKeys []string, acc *access.AccessControl) (error, []string) {
	type delRulesMetadata struct {
		delRules     utils.Set             // id of rules to delete
		keepRuleList []*share.CLUSRuleHead // new rule head list after deletion
	}

	delRuleTypes := make(map[string]*delRulesMetadata, len(ruleTypeKeys))
	for _, ruleTypeKey := range ruleTypeKeys {
		cachedRules := cacher.GetAdmissionRules(admission.NvAdmValidateType, ruleTypeKey, acc)
		if len(cachedRules) == 0 {
			continue
		}

		keepRules := make([]*share.CLUSRuleHead, 0)
		delRules := utils.NewSet()
		for _, cr := range cachedRules {
			if cr.Critical || (scope == share.ScopeLocal && cr.CfgType != api.CfgTypeUserCreated) ||
				(scope == share.ScopeFed && cr.CfgType != api.CfgTypeFederal) {
				continue
			}
			delRules.Add(cr.ID)
		}
		delRuleType := &delRulesMetadata{delRules: utils.NewSet()}
		delRuleTypes[ruleTypeKey] = delRuleType
		arhs, _ := clusHelper.GetAdmissionRuleList(admission.NvAdmValidateType, ruleTypeKey)
		for _, arh := range arhs {
			if delRules.Contains(arh.ID) {
				delRuleType.delRules.Add(arh.ID)
			} else {
				keepRules = append(keepRules, arh)
			}
		}
		delRuleType.keepRuleList = keepRules
	}

	modKeysCount := 0
	for _, delRuleType := range delRuleTypes {
		modKeysCount += delRuleType.delRules.Cardinality()
		modKeysCount++
	}

	delFedRuleTypes := make([]string, 0, 2)
	if modKeysCount < _maxTransacKeys {
		txn := cluster.Transact()
		txn.Close()

		for ruleTypeKey, delRuleType := range delRuleTypes {
			clusHelper.PutAdmissionRuleListTxn(txn, admission.NvAdmValidateType, ruleTypeKey, delRuleType.keepRuleList)
			for id := range delRuleType.delRules.Iter() {
				clusHelper.DeleteAdmissionRuleTxn(txn, admission.NvAdmValidateType, ruleTypeKey, id.(uint32))
				opa.DeletePolicy(id.(uint32))
			}
			if ruleTypeKey == share.FedAdmCtrlExceptRulesType || ruleTypeKey == share.FedAdmCtrlDenyRulesType {
				delFedRuleTypes = append(delFedRuleTypes, ruleTypeKey)
			}
		}
		if err := applyTransact(w, txn); err != nil {
			return err, nil
		}
	} else {
		for ruleTypeKey, delRuleType := range delRuleTypes {
			if err := clusHelper.PutAdmissionRuleList(admission.NvAdmValidateType, ruleTypeKey, delRuleType.keepRuleList); err != nil {
				break
			} else {
				for id := range delRuleType.delRules.Iter() {
					clusHelper.DeleteAdmissionRule(admission.NvAdmValidateType, ruleTypeKey, id.(uint32))
					opa.DeletePolicy(id.(uint32))
				}
				if ruleTypeKey == share.FedAdmCtrlExceptRulesType || ruleTypeKey == share.FedAdmCtrlDenyRulesType {
					delFedRuleTypes = append(delFedRuleTypes, ruleTypeKey)
				}
			}
		}
	}

	return nil, delFedRuleTypes
}

func handlerDeleteAdmissionRules(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasGlobalPermissions(0, share.PERM_ADM_CONTROL) {
		restRespAccessDenied(w, login)
		return
	}
	query := restParseQuery(r)
	ruleTypeKeys, scope := getAdmCtrlRuleTypes(query, share.ScopeLocal) // internal rule types: "exception", "deny", "fed_admctrl_exception" or "fed_admctrl_deny"
	if scope != share.ScopeFed && scope != share.ScopeLocal {
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	var err error
	var lock cluster.LockInterface
	if lock, err = lockClusKey(w, share.CLUSLockAdmCtrlKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	err, delFedRuleTypes := deleteAdmissionRules(w, scope, ruleTypeKeys, acc)
	if len(delFedRuleTypes) > 0 {
		updateFedRulesRevision(delFedRuleTypes, acc, login)
	}
	if err == nil {
		restRespSuccess(w, r, nil, acc, login, nil, "Delete all admission control rules")
	}
}

func handlerGetAdmissionRule(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}
	id, err := getRuleId(w, ps)
	if err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	rule, err := getAdmissionRule(id, acc)
	if err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}
	resp := api.RESTAdmissionRuleData{Rule: rule}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get admission control rule")
}

func handlerAddAdmissionRule(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	var confData api.RESTAdmissionRuleConfigData
	body, _ := io.ReadAll(r.Body)
	err := json.Unmarshal(body, &confData)
	if err != nil || confData.Config == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}
	ruleCfg := confData.Config
	cfgType := cfgTypeMapping[ruleCfg.CfgType]
	modes := utils.NewSet("", share.AdmCtrlModeMonitor, share.AdmCtrlModeProtect)
	if (cfgType != share.UserCreated && cfgType != share.FederalCfg) ||
		(ruleCfg.RuleType != api.ValidatingExceptRuleType && ruleCfg.RuleType != api.ValidatingDenyRuleType) ||
		(ruleCfg.RuleType == api.ValidatingExceptRuleType && ruleCfg.RuleMode != nil) ||
		(ruleCfg.RuleType == api.ValidatingDenyRuleType && ruleCfg.RuleMode != nil && !modes.Contains(*ruleCfg.RuleMode)) {
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	var applyTarget uint8
	if ruleCfg.Containers != nil {
		if v, err := getAdmCtrlRuleContainers(ruleCfg.Containers); err != nil {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
			return
		} else {
			applyTarget = v
		}
	}

	if !acc.Authorize(&share.CLUSAdmissionRule{CfgType: cfgType}, nil) {
		restRespAccessDenied(w, login)
		return
	}
	var ruleTypeKey string // "exception", "deny", "fed_admctrl_exception" or "fed_admctrl_deny"
	if cfgType == share.FederalCfg {
		if ruleCfg.RuleType == api.ValidatingExceptRuleType {
			ruleTypeKey = share.FedAdmCtrlExceptRulesType
		} else if ruleCfg.RuleType == api.ValidatingDenyRuleType {
			ruleTypeKey = share.FedAdmCtrlDenyRulesType
		}
	} else {
		ruleTypeKey = ruleCfg.RuleType
	}

	if ruleCfg.ID != 0 {
		if _, err := getAdmissionRule(ruleCfg.ID, acc); err == nil {
			restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
			return
		}
	}

	var lock cluster.LockInterface
	if lock, err = lockClusKey(w, share.CLUSLockAdmCtrlKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	ids := utils.NewSet()
	var arhsAll [2][]*share.CLUSRuleHead
	if cfgType == share.FederalCfg {
		arhsAll[0], _ = clusHelper.GetAdmissionRuleList(admission.NvAdmValidateType, share.FedAdmCtrlExceptRulesType)
		arhsAll[1], _ = clusHelper.GetAdmissionRuleList(admission.NvAdmValidateType, share.FedAdmCtrlDenyRulesType)
	} else {
		arhsAll[0], _ = clusHelper.GetAdmissionRuleList(admission.NvAdmValidateType, api.ValidatingExceptRuleType)
		arhsAll[1], _ = clusHelper.GetAdmissionRuleList(admission.NvAdmValidateType, api.ValidatingDenyRuleType)
	}
	for _, arhs := range arhsAll {
		for _, arh := range arhs {
			ids.Add(arh.ID)
		}
	}
	ruleCfg.ID = getAvailableRuleID(ruleTypeAdmCtrl, ids, cfgType)
	if ruleCfg.ID == 0 {
		// if the POST request specifies a rule ID that alreadys exists, return error
		restRespError(w, http.StatusInternalServerError, api.RESTErrClusterWrongData)
		return
	}

	clusConf := &share.CLUSAdmissionRule{ID: ruleCfg.ID, CfgType: cfgType, RuleType: ruleCfg.RuleType}
	clusConf.Category = admission.AdmRuleCatK8s
	if ruleCfg.Comment != nil {
		clusConf.Comment = *ruleCfg.Comment
	}
	if ruleCfg.Criteria != nil {
		clusConf.Criteria, err = cache.AdmCriteria2CLUS(ruleCfg.Criteria)
		if err != nil {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
			return
		}
	}
	if ruleCfg.Disable != nil {
		clusConf.Disable = *ruleCfg.Disable
	}
	if ruleCfg.RuleMode != nil {
		clusConf.RuleMode = *ruleCfg.RuleMode
	}
	if ruleCfg.Containers != nil {
		clusConf.Containers = applyTarget
	}
	ruleOptions := nvsysadmission.GetAdmRuleTypeOptions(ruleCfg.RuleType)
	if err := validateAdmCtrlCriteria(clusConf.Criteria, ruleOptions.K8sOptions.RuleOptions, ruleCfg.RuleType); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Admission rule validation failed")
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
		return
	}

	txn := cluster.Transact()
	defer txn.Close()

	clusHelper.PutAdmissionRuleTxn(txn, admission.NvAdmValidateType, ruleTypeKey, clusConf)
	arhs, _ := clusHelper.GetAdmissionRuleList(admission.NvAdmValidateType, ruleTypeKey)
	rh := &share.CLUSRuleHead{
		ID:      ruleCfg.ID,
		CfgType: cfgType,
	}
	arhs = append(arhs, rh)
	clusHelper.PutAdmissionRuleListTxn(txn, admission.NvAdmValidateType, ruleTypeKey, arhs)

	if applyTransact(w, txn) != nil {
		return
	}

	if cfgType == share.FederalCfg {
		updateFedRulesRevision([]string{ruleTypeKey}, acc, login)
	}
	// returns the final rule ID that is created in response payload
	resp := api.RESTAdmissionRuleData{
		Rule: &api.RESTAdmissionRule{
			ID:         ruleCfg.ID,
			Category:   clusConf.Category,
			Comment:    clusConf.Comment,
			Disable:    clusConf.Disable,
			Critical:   clusConf.Critical,
			CfgType:    ruleCfg.CfgType,
			RuleType:   clusConf.RuleType,
			RuleMode:   clusConf.RuleMode,
			Containers: ruleCfg.Containers,
		},
	}
	if ruleCfg.Criteria != nil {
		resp.Rule.Criteria = make([]*api.RESTAdmRuleCriterion, len(ruleCfg.Criteria))
		copy(resp.Rule.Criteria, ruleCfg.Criteria)
	}

	opa.ConvertToRegoRule(clusConf)

	restRespSuccess(w, r, &resp, acc, login, &confData, "Add admission control rule")
}

func handlerPatchAdmissionRule(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	code := 0
	var confData api.RESTAdmissionRuleConfigData
	body, _ := io.ReadAll(r.Body)
	err := json.Unmarshal(body, &confData)
	ruleCfg := confData.Config
	if err != nil || confData.Config == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		code = api.RESTErrInvalidRequest
	} else {
		modes := utils.NewSet("", share.AdmCtrlModeMonitor, share.AdmCtrlModeProtect)
		if (ruleCfg.ID <= api.AdmCtrlCrdRuleIDMax) && (ruleCfg.ID >= api.AdmCtrlCrdRuleIDBase) {
			code = api.RESTErrOpNotAllowed
		} else if (ruleCfg.CfgType != api.CfgTypeUserCreated && ruleCfg.CfgType != api.CfgTypeFederal) ||
			(ruleCfg.RuleType != api.ValidatingExceptRuleType && ruleCfg.RuleType != api.ValidatingDenyRuleType) ||
			(ruleCfg.RuleType == api.ValidatingExceptRuleType && ruleCfg.RuleMode != nil) ||
			(ruleCfg.RuleType == api.ValidatingDenyRuleType && ruleCfg.RuleMode != nil && !modes.Contains(*ruleCfg.RuleMode)) {
			code = api.RESTErrInvalidRequest
		}
	}
	if code != 0 {
		restRespError(w, http.StatusBadRequest, code)
		return
	}

	var ruleTypeKey string // "exception", "deny", "fed_admctrl_exception" or "fed_admctrl_deny"
	if ruleCfg.CfgType == api.CfgTypeFederal {
		if ruleCfg.RuleType == api.ValidatingExceptRuleType {
			ruleTypeKey = share.FedAdmCtrlExceptRulesType
		} else if ruleCfg.RuleType == api.ValidatingDenyRuleType {
			ruleTypeKey = share.FedAdmCtrlDenyRulesType
		}
	} else {
		ruleTypeKey = ruleCfg.RuleType
	}
	if currRule, err := cacher.GetAdmissionRule(admission.NvAdmValidateType, ruleTypeKey, ruleCfg.ID, acc); err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	} else if currRule.CfgType == api.CfgTypeGround {
		restRespError(w, http.StatusBadRequest, api.RESTErrOpNotAllowed)
		return
	}

	var lock cluster.LockInterface
	if lock, err = lockClusKey(w, share.CLUSLockAdmCtrlKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	clusConf := clusHelper.GetAdmissionRule(admission.NvAdmValidateType, ruleTypeKey, ruleCfg.ID)
	if clusConf == nil {
		restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
		return
	}
	if (clusConf.Critical && !sameRuleSettings(ruleCfg, clusConf)) || clusConf.CfgType == share.GroundCfg {
		restRespError(w, http.StatusBadRequest, api.RESTErrOpNotAllowed)
		return
	}

	if !clusConf.Critical && ruleCfg.Criteria != nil {
		clusConf.Criteria, err = cache.AdmCriteria2CLUS(ruleCfg.Criteria)
		if err != nil {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
			return
		}
	}
	if !clusConf.Critical && ruleCfg.Comment != nil {
		clusConf.Comment = *ruleCfg.Comment
	}
	if ruleCfg.Disable != nil {
		clusConf.Disable = *ruleCfg.Disable
	}
	if !clusConf.Critical && ruleCfg.RuleMode != nil {
		clusConf.RuleMode = *ruleCfg.RuleMode
	}
	if !clusConf.Critical && ruleCfg.Containers != nil {
		if applyTarget, err := getAdmCtrlRuleContainers(ruleCfg.Containers); err != nil {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
			return
		} else {
			clusConf.Containers = applyTarget
		}
	}

	ruleOptions := nvsysadmission.GetAdmRuleTypeOptions(ruleCfg.RuleType)
	if err := validateAdmCtrlCriteria(clusConf.Criteria, ruleOptions.K8sOptions.RuleOptions, ruleCfg.RuleType); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Admission rule validation failed")
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
		return
	}

	if err = clusHelper.PutAdmissionRule(admission.NvAdmValidateType, ruleTypeKey, clusConf); err != nil {
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}

	if ruleCfg.CfgType == api.CfgTypeFederal {
		updateFedRulesRevision([]string{ruleTypeKey}, acc, login)
	}

	opa.ConvertToRegoRule(clusConf)

	restRespSuccess(w, r, nil, acc, login, &confData, "Patch admission control rule")
}

func handlerDeleteAdmissionRule(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id, err := getRuleId(w, ps)
	if err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	} else if (id <= api.AdmCtrlCrdRuleIDMax) && (id >= api.AdmCtrlCrdRuleIDBase) {
		restRespError(w, http.StatusBadRequest, api.RESTErrOpNotAllowed)
		return
	}

	rule, err := getAdmissionRule(id, acc)
	if err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	} else if rule.Critical {
		restRespError(w, http.StatusBadRequest, api.RESTErrOpNotAllowed)
		return
	}

	var ruleTypeKey string // internal rule type: "exception", "deny", "fed_admctrl_exception" or "fed_admctrl_deny"
	if rule.CfgType == api.CfgTypeFederal {
		if rule.RuleType == api.ValidatingExceptRuleType {
			ruleTypeKey = share.FedAdmCtrlExceptRulesType
		} else if rule.RuleType == api.ValidatingDenyRuleType {
			ruleTypeKey = share.FedAdmCtrlDenyRulesType
		}
	} else {
		ruleTypeKey = rule.RuleType
	}

	var lock cluster.LockInterface
	if lock, err = lockClusKey(w, share.CLUSLockAdmCtrlKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	arhs, _ := clusHelper.GetAdmissionRuleList(admission.NvAdmValidateType, ruleTypeKey)
	var idx int = -1
	for i, arh := range arhs {
		if arh.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		// force writing the same header list value to kv so that cacher can do self-check
		clusHelper.PutAdmissionRuleList(admission.NvAdmValidateType, ruleTypeKey, arhs)
		log.WithFields(log.Fields{"id": id, "ruleTypeKey": ruleTypeKey}).Error("Admission rule doesn't exist")
		restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
		return
	}

	size := len(arhs)
	copy(arhs[idx:], arhs[idx+1:])
	arhs[size-1] = nil
	arhs = arhs[:size-1]

	txn := cluster.Transact()
	defer txn.Close()

	clusHelper.PutAdmissionRuleListTxn(txn, admission.NvAdmValidateType, ruleTypeKey, arhs)
	clusHelper.DeleteAdmissionRuleTxn(txn, admission.NvAdmValidateType, ruleTypeKey, id)
	opa.DeletePolicy(id)

	if applyTransact(w, txn) != nil {
		return
	}

	if id > api.StartingFedAdmRespRuleID && id < api.MaxFedAdmRespRuleID {
		updateFedRulesRevision([]string{ruleTypeKey}, acc, login)
	}

	restRespSuccess(w, r, nil, acc, login, nil, "Delete admission control rule")
}

func handlerGetAdmissionTest(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Info()
	defer r.Body.Close()

	if !k8sPlatform {
		restRespError(w, http.StatusPreconditionFailed, api.RESTErrAdmCtrlUnSupported)
		return
	}
	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}
	if _, err := cacher.GetAdmissionState(acc); err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	var errs []string
	k8sClusterRoles := []string{resource.NvRbacRole, resource.NvAdmCtrlRole, resource.NvAppRole}
	if errs, _ = resource.VerifyNvRbacRoles(k8sClusterRoles, false); len(errs) == 0 {
		errs, _ = resource.VerifyNvRbacRoleBindings(k8sClusterRoles, false, true)
	}
	if len(errs) > 0 {
		msg := strings.Join(errs, "<p>")
		restRespErrorMessage(w, http.StatusNotFound, api.RESTErrK8sNvRBAC, msg)
		return
	} else {
		if result, err := admission.TestAdmWebhookConnection(resource.NvAdmSvcName); result != admission.TestSucceeded {
			errorCode := api.RESTErrK8sApiSrvToWebhook
			if err != nil && strings.Index(err.Error(), " 403 ") > 0 && strings.Index(err.Error(), "forbidden") > 0 {
				if result == admission.TestFailedAtRead {
					errorCode = api.RESTErrNvPermission
				} else if result == admission.TestFailedAtWrite {
					errorCode = api.RESTErrNoUpdatePermission
				}
			}
			restRespError(w, http.StatusNotFound, errorCode)
		} else {
			restRespSuccess(w, r, nil, acc, login, nil, "Test admission control client mode")
		}
	}
}

func handlerAdmCtrlExport(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	// allow export no matter it's k8s env or not
	acc, login := getAccessControl(w, r, access.AccessOPRead)
	if acc == nil {
		return
	}

	var rconf api.RESTAdmCtrlRulesExport
	body, _ := io.ReadAll(r.Body)
	err := json.Unmarshal(body, &rconf)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	apiversion := fmt.Sprintf("%s/%s", common.OEMSecurityRuleGroup, resource.NvAdmCtrlSecurityRuleVersion)
	metadatadName := share.ScopeLocal
	kind := resource.NvAdmCtrlSecurityRuleKind
	resp := resource.NvAdmCtrlSecurityRule{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiversion,
			Kind:       kind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: metadatadName,
		},
		Spec: resource.NvSecurityAdmCtrlSpec{},
	}

	enable := false
	mode := share.AdmCtrlModeProtect
	admClientMode := share.AdmClientModeSvc
	if rconf.ExportConfig {
		// export admission control config
		if k8sPlatform {
			state, err := cacher.GetAdmissionState(acc)
			if err != nil {
				restRespNotFoundLogAccessDenied(w, login, err)
				return
			}
			enable = *state.Enable
			mode = *state.Mode
			admClientMode = *state.AdmClientMode
		}
		resp.Spec.Config = &resource.NvSecurityAdmCtrlConfig{
			Enable:        &enable,
			Mode:          &mode,
			AdmClientMode: &admClientMode,
		}
	}

	if len(rconf.IDs) > 0 {
		// export admission control rules
		var lock cluster.LockInterface
		if lock, err = lockClusKey(w, share.CLUSLockAdmCtrlKey); err != nil {
			return
		}
		defer clusHelper.ReleaseLock(lock)

		var admissionRules []*resource.NvSecurityAdmCtrlRule
		actionAllow := api.ValidatingAllowRuleType
		actionDeny := api.ValidatingDenyRuleType
		// export selected admission control rules
		var ids utils.Set = utils.NewSet()
		admissionRules = make([]*resource.NvSecurityAdmCtrlRule, 0, len(rconf.IDs))
		for _, id := range rconf.IDs {
			if ids.Contains(id) {
				continue
			}
			rule, err := getAdmissionRule(id, acc)
			if rule == nil || err != nil {
				restRespNotFoundLogAccessDenied(w, login, err)
				return
			}
			action := &actionDeny
			if rule.RuleType == api.ValidatingExceptRuleType || rule.RuleType == share.FedAdmCtrlExceptRulesType {
				action = &actionAllow
			}
			ruleItem := resource.NvSecurityAdmCtrlRule{
				Action:   action,
				Criteria: rule.Criteria,
			}
			if rule.Critical {
				ruleItem.ID = &rule.ID
			}
			ruleItem.Disabled = &rule.Disable
			if *ruleItem.Action == actionDeny {
				ruleItem.RuleMode = &rule.RuleMode
			}
			if rule.Comment != "" {
				ruleItem.Comment = &rule.Comment
			}
			if len(rule.Containers) > 0 {
				ruleItem.Containers = rule.Containers
			} else {
				ruleItem.Containers = []string{share.AdmCtrlRuleContainers}
			}
			admissionRules = append(admissionRules, &ruleItem)
			ids.Add(id)
		}
		resp.Spec.Rules = admissionRules
	}

	doExport("cfgAdmissionRulesExport.yaml", "admission control settings", rconf.RemoteExportOptions, resp, w, r, acc, login)
}

func handlerAdmCtrlImport(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if _, err := cacher.GetAdmissionState(acc); err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	tid := r.Header.Get("X-Transaction-ID")
	_importHandler(w, r, tid, share.IMPORT_TYPE_ADMCTRL, share.PREFIX_IMPORT_ADMCTRL, acc, login)
}

func importAdmCtrl(scope string, loginDomainRoles access.DomainRole, importTask share.CLUSImportTask, postImportOp kv.PostImportFunc) error {
	log.Debug()
	defer os.Remove(importTask.TempFilename)

	json_data, _ := os.ReadFile(importTask.TempFilename)
	var secRule resource.NvAdmCtrlSecurityRule
	if err := json.Unmarshal(json_data, &secRule); err != nil || secRule.APIVersion != "neuvector.com/v1" || secRule.Kind != resource.NvAdmCtrlSecurityRuleKind {
		msg := "Invalid security rule(s)"
		log.WithFields(log.Fields{"error": err}).Error(msg)
		postImportOp(fmt.Errorf("%s", msg), importTask, loginDomainRoles, "", share.IMPORT_TYPE_ADMCTRL)
		return nil
	}

	var inc float32
	var progress float32 // progress percentage

	inc = 90.0 / float32(5)
	progress = 6

	importTask.Percentage = int(progress)
	importTask.Status = share.IMPORT_RUNNING
	clusHelper.PutImportTask(&importTask)

	var err error
	var crdHandler nvCrdHandler
	crdHandler.Init(share.CLUSLockAdmCtrlKey)
	if crdHandler.AcquireLock(clusterLockWait) {
		defer crdHandler.ReleaseLock()

		// [1] parse security rule in the yaml file
		parsedCfg, errCount, errMsg, _ := crdHandler.parseCurCrdAdmCtrlContent(&secRule, share.ReviewTypeImportAdmCtrl, share.ReviewTypeDisplayAdmission)
		if errCount > 0 {
			err = fmt.Errorf("%s", errMsg)
		} else {
			progress += inc
			importTask.Percentage = int(progress)
			clusHelper.PutImportTask(&importTask)

			acc := access.NewAdminAccessControl()
			// [2] import admission control configuration described in the yaml file
			if k8sPlatform && parsedCfg.AdmCtrlCfg != nil {
				var currState *api.RESTAdmissionState
				if currState, err = cacher.GetAdmissionState(acc); err == nil {
					if currState.CfgType == api.CfgTypeGround {
						err = fmt.Errorf("%s", restErrMessage[api.RESTErrOpNotAllowed])
					} else {
						err = crdHandler.crdHandleAdmCtrlConfig(scope, parsedCfg.AdmCtrlCfg, nil, share.ReviewTypeImportAdmCtrl)
					}
				}
				if err != nil {
					importTask.Status = err.Error()
				}
				progress += inc
				importTask.Percentage = int(progress)
				clusHelper.PutImportTask(&importTask)
			}
			if err == nil && parsedCfg.AdmCtrlRulesCfg != nil {
				// [3] delete all user-created non-default admission control rules
				ruleTypeKeys := []string{api.ValidatingExceptRuleType, api.ValidatingDenyRuleType}
				if err, _ = deleteAdmissionRules(nil, scope, ruleTypeKeys, acc); err != nil {
					importTask.Status = err.Error()
				}
				progress += inc
				importTask.Percentage = int(progress)
				clusHelper.PutImportTask(&importTask)
				if err == nil && len(parsedCfg.AdmCtrlRulesCfg) > 0 {
					var cacheRecord share.CLUSCrdSecurityRule
					// [4] import all admission control rules defined in the yaml file
					crdHandler.crdHandleAdmCtrlRules(scope, parsedCfg.AdmCtrlRulesCfg, &cacheRecord, share.ReviewTypeImportAdmCtrl)
					progress += inc
					importTask.Percentage = int(progress)
					clusHelper.PutImportTask(&importTask)
				}
			}
			importTask.Percentage = 90
			clusHelper.PutImportTask(&importTask)
		}
	}

	postImportOp(err, importTask, loginDomainRoles, "", share.IMPORT_TYPE_ADMCTRL)

	return nil
}

func handlerPromoteAdmissionRules(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := isFedOpAllowed(api.FedRoleMaster, _fedAdminRequired, w, r)
	if acc == nil || login == nil {
		return
	}

	var promoteData api.RESTAdmCtrlPromoteRequestData
	body, _ := io.ReadAll(r.Body)
	err := json.Unmarshal(body, &promoteData)
	if err != nil || promoteData.Request == nil || len(promoteData.Request.IDs) == 0 {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	fedIdInUse := utils.NewSet()   // id of existing fed admission control rules
	allowIdInUse := utils.NewSet() // id of existing non-fed admission control allow rules
	denyIdInUse := utils.NewSet()  // id of existing non-fed admission control deny rules
	ruleTypesUpdated := utils.NewSet()
	var errMsg string
	var fedArhs map[string][]*share.CLUSRuleHead = make(map[string][]*share.CLUSRuleHead, 2)

	var lock cluster.LockInterface
	if lock, err = lockClusKey(w, share.CLUSLockAdmCtrlKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	for _, ruleType := range []string{api.ValidatingExceptRuleType, api.ValidatingDenyRuleType, share.FedAdmCtrlExceptRulesType, share.FedAdmCtrlDenyRulesType} {
		arhs, _ := clusHelper.GetAdmissionRuleList(admission.NvAdmValidateType, ruleType)
		for _, arh := range arhs {
			switch ruleType {
			case share.FedAdmCtrlExceptRulesType, share.FedAdmCtrlDenyRulesType:
				fedIdInUse.Add(arh.ID)
			case api.ValidatingExceptRuleType:
				allowIdInUse.Add(arh.ID)
			case api.ValidatingDenyRuleType:
				denyIdInUse.Add(arh.ID)
			}
		}
		if ruleType == share.FedAdmCtrlExceptRulesType || ruleType == share.FedAdmCtrlDenyRulesType {
			fedArhs[ruleType] = arhs
		}
	}

	txn := cluster.Transact()
	defer txn.Close()

	for _, id := range promoteData.Request.IDs {
		if id == 0 || (id > api.StartingFedAdmRespRuleID && id < api.MaxFedAdmRespRuleID) {
			continue
		}
		var ruleType string
		var fedRuleTypeKey string
		if allowIdInUse.Contains(id) {
			ruleType = api.ValidatingExceptRuleType
			fedRuleTypeKey = share.FedAdmCtrlExceptRulesType
		} else if denyIdInUse.Contains(id) {
			ruleType = api.ValidatingDenyRuleType
			fedRuleTypeKey = share.FedAdmCtrlDenyRulesType
		} else {
			errMsg = fmt.Sprintf("rule not found(for rule %d)", id)
			break
		}
		rule := clusHelper.GetAdmissionRule(admission.NvAdmValidateType, ruleType, id) // rule is *share.CLUSAdmissionRule
		if rule == nil {
			errMsg = fmt.Sprintf("rule not found(for rule %d)", id)
			break
		}
		if rule.Critical {
			continue
		}

		fedRuleID := getAvailableRuleID("admCtrl", fedIdInUse, share.FederalCfg)
		if fedRuleID == 0 {
			errMsg = fmt.Sprintf("No free rule id available(for rule %d)", id)
			break
		}

		rule.ID = fedRuleID
		rule.CfgType = share.FederalCfg
		comment := fmt.Sprintf("promoted from rule %d", id)
		if rule.Comment == "" {
			rule.Comment = comment
		} else {
			rule.Comment = fmt.Sprintf("%s (%s)", rule.Comment, comment)
		}
		clusHelper.PutAdmissionRuleTxn(txn, admission.NvAdmValidateType, fedRuleTypeKey, rule)

		if arhs, ok := fedArhs[fedRuleTypeKey]; ok {
			rh := &share.CLUSRuleHead{
				ID:      fedRuleID,
				CfgType: share.FederalCfg,
			}
			fedArhs[fedRuleTypeKey] = append(arhs, rh)
			ruleTypesUpdated.Add(fedRuleTypeKey)
		}
		fedIdInUse.Add(fedRuleID)
	}
	if errMsg == "" {
		if ruleTypesUpdated.Cardinality() == 0 {
			errMsg = "No rule to promote"
		} else {
			for ruleTypes := range ruleTypesUpdated.Iter() {
				fedRuleTypeKey := ruleTypes.(string)
				if arhs, ok := fedArhs[fedRuleTypeKey]; ok {
					clusHelper.PutAdmissionRuleListTxn(txn, admission.NvAdmValidateType, fedRuleTypeKey, arhs)
				}
			}
			if applyTransact(w, txn) == nil {
				updateFedRulesRevision(ruleTypesUpdated.ToStringSlice(), acc, login)
				restRespSuccess(w, r, nil, acc, login, nil, "Promote admission control rule")
			}
			return
		}
	}
	restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrPromoteFail, errMsg)
}

func validateCustomPathCriteria(crt *share.CLUSAdmRuleCriterion) (bool, bool) {
	var allowedOp, allowedValue bool

	options := nvsysadmission.GetCustomCriteriaOptions()

	for _, oneType := range options {
		if crt.ValueType == oneType.ValueType {
			for _, v := range oneType.Ops {
				if crt.Op == v {
					allowedOp = true
				}
			}

			if crt.ValueType == "key" || crt.Op == share.CriteriaOpExist || crt.Op == share.CriteriaOpNotExist {
				allowedValue = true
				return allowedOp, allowedValue
			}

			if crt.ValueType == "string" {
				if len(crt.Value) > 1 {
					allowedValue = true
				}
			}

			if crt.ValueType == "number" {
				items := strings.Split(crt.Value, ",")
				for _, v := range items {
					if _, err := strconv.ParseFloat(v, 64); err == nil {
						allowedValue = true // meaning any valid float value is allowed
					} else {
						return allowedOp, false
					}
				}
			}

			if crt.ValueType == "boolean" {
				items := strings.Split(crt.Value, ",")
				for _, v := range items {
					if v == "true" || v == "false" {
						allowedValue = true
					} else {
						return allowedOp, false
					}
				}
			}
		}
	}

	return allowedOp, allowedValue
}

func validateSaBindRiskyRoleCriteria(crt *share.CLUSAdmRuleCriterion, options map[string]*api.RESTAdmissionRuleOption) (bool, bool) {
	var allowedOp, allowedValue bool

	if option, exist := options[crt.Name]; exist {
		for _, op := range option.Ops {
			if op == crt.Op {
				allowedOp = true
				break
			}
		}
	}

	set := utils.NewSet()
	validValues := cache.GetPredefinedRiskyRoles()
	for _, v := range validValues {
		set.Add(v)
	}

	items := strings.Split(crt.Value, ",")
	for _, v := range items {
		if set.Contains(v) {
			allowedValue = true
		} else {
			return allowedOp, false
		}
	}

	return allowedOp, allowedValue
}

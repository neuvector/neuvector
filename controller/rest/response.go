package rest

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	"github.com/julienschmidt/httprouter"
	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

var responseRuleOptions map[string]*api.RESTResponseRuleOptions
var responseRuleOptionsForLocalUsers map[string]*api.RESTResponseRuleOptions

func getResponseExportPolicyName(gName string, id uint32) string {
	policyName := share.DefaultPolicyName
	if gName != "" {
		if strings.HasPrefix(gName, api.FederalGroupPrefix) {
			policyName = share.FedPolicyName
		}
	} else if id > api.StartingFedAdmRespRuleID && id < api.MaxFedAdmRespRuleID {
		policyName = share.FedPolicyName
	}
	return policyName
}

func getResponsePolicyName(w http.ResponseWriter, id string) (uint32, string, error) {
	idNum, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		log.WithFields(log.Fields{"id": id, "err": err}).Error("Invalid ID")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return 0, "", common.ErrObjectNotFound
	}
	policyName := getResponseExportPolicyName("", uint32(idNum))
	return uint32(idNum), policyName, nil
}

func getSecurityEventNameList() []string {
	var output []string = make([]string, 0)
	var names []string = make([]string, 0)

	output = append(output, "name:"+common.NetworkViolation)

	for _, info := range common.LogIncidentMap {
		names = append(names, "name:"+info.Name)
	}
	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })
	output = append(output, names...)

	names = nil
	for _, info := range common.LogThreatMap {
		names = append(names, "name:"+info.Name)
	}

	rns := cacher.GetDlpRuleNames()
	if rns != nil {
		for _, rn := range *rns {
			tmp := fmt.Sprintf("%s%s", common.DlpPrefix, rn)
			names = append(names, "name:"+tmp)
		}
	}

	wns := cacher.GetWafRuleNames()
	if wns != nil {
		for _, wn := range *wns {
			tmp := fmt.Sprintf("%s%s", common.WafPrefix, wn)
			names = append(names, "name:"+tmp)
		}
	}

	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })
	output = append(output, names...)

	return output
}

func getEventNameList(isGlobalUser bool) []string {
	var names []string = make([]string, 0, len(common.LogEventMap))
	for id, info := range common.LogEventMap {
		if !isGlobalUser && (id == share.CLUSEvAdmCtrlK8sConfigured || id == share.CLUSEvAdmCtrlK8sConfigFailed) {
			continue
		}
		names = append(names, "name:"+info.Name)
	}
	return names
}

func getEventLevelList(levels []string) []string {
	var lvs []string = make([]string, 0, len(levels))
	for _, lv := range levels {
		lvs = append(lvs, "level:"+lv)
	}
	return lvs
}

func getCVEReportNameList() []string {
	names := []string{
		"name:" + api.EventNameContainerScanReport,
		"name:" + api.EventNameHostScanReport,
		"name:" + api.EventNameRegistryScanReport,
		"name:" + api.EventNamePlatformScanReport,
	}
	return names
}

func getComplianceItemNameList() []string {
	scripts := clusHelper.GetAllCustomCheckConfig()
	names := make([]string, 0)

	for group, script := range scripts {
		for _, scr := range script.Scripts {
			k := fmt.Sprintf("%s:%s/%s", share.EventCondTypeName, group, scr.Name)
			names = append(names, k)
		}
	}
	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })
	names = append([]string{
		"name:" + api.EventNameComplianceImageBenchViolation,
		"name:" + api.EventNameComplianceContainerFileBenchViolation,
		"name:" + api.EventNameComplianceContainerBenchViolation,
		"name:" + api.EventNameComplianceContainerCustomCheckViolation,
		"name:" + api.EventNameComplianceHostBenchViolation,
		"name:" + api.EventNameComplianceHostCustomCheckViolation,
	}, names...)
	return names
}

func getAdmCtrlNameList() []string {
	names := []string{
		"name:" + api.EventNameAdmCtrlK8sReqAllowed,
		"name:" + api.EventNameAdmCtrlK8sReqViolation,
		"name:" + api.EventNameAdmCtrlK8sReqDenied,
	}
	return names
}

func getServerlessNameList() []string {
	names := []string{
		"name:" + api.EventNameAwsLambdaScan,
	}
	return names
}

func getResponeRuleOptions(acc *access.AccessControl) map[string]*api.RESTResponseRuleOptions {
	if responseRuleOptions == nil {
		responseRuleOptions = map[string]*api.RESTResponseRuleOptions{
			share.EventEvent: {
				Types: []string{share.EventCondTypeName, share.EventCondTypeLevel},
				Name:  getEventNameList(true),
				Level: getEventLevelList(api.LogLevelList),
			},
			share.EventCVEReport: {
				Types: []string{share.EventCondTypeName, share.EventCondTypeLevel,
					share.EventCondTypeCVEHigh, share.EventCondTypeCVEMedium,
					share.EventCondTypeCVEName, share.EventCondTypeCVEHighWithFix},
				Name:  getCVEReportNameList(),
				Level: getEventLevelList([]string{api.LogLevelCRIT, api.LogLevelERR, api.LogLevelWARNING}),
			},
			share.EventRuntime: {
				Types: []string{share.EventCondTypeName, share.EventCondTypeLevel, share.EventCondTypeProc},
				Name:  getSecurityEventNameList(),
				Level: getEventLevelList([]string{api.LogLevelCRIT, api.LogLevelERR, api.LogLevelWARNING, api.LogLevelNOTICE, api.LogLevelINFO}),
			},
			/*
				share.EventIncident: {
					Types: []string{share.EventCondTypeName, share.EventCondTypeLevel, share.EventCondTypeProc},
					Name:  getSecurityEventNameList(),
					Level: getEventLevelList([]string{api.LogLevelCRIT, api.LogLevelWARNING}),
				},
				share.EventViolation: {
					Types: []string{share.EventCondTypeLevel},
					Level: getEventLevelList([]string{api.LogLevelCRIT, api.LogLevelWARNING}),
				},
				share.EventThreat: {
					Types: []string{share.EventCondTypeLevel},
					Level: getEventLevelList(api.ThreatLevelList),
				},
			*/
			share.EventServerless: {
				Types: []string{share.EventCondTypeName, share.EventCondTypeLevel},
				Name:  getServerlessNameList(),
				Level: getEventLevelList([]string{api.LogLevelWARNING, api.LogLevelINFO}),
			},
			share.EventCompliance: {
				Types: []string{share.EventCondTypeLevel, share.EventCondTypeName},
				Name:  getComplianceItemNameList(),
				Level: getEventLevelList([]string{api.LogLevelWARNING}),
			},
			share.EventAdmCtrl: {
				Types: []string{share.EventCondTypeName, share.EventCondTypeLevel},
				Name:  getAdmCtrlNameList(),
				Level: getEventLevelList([]string{api.LogLevelCRIT, api.LogLevelWARNING, api.LogLevelINFO}),
			},
		}
	} else {
		//dlp sensor rule needs dynamic update for "security-event"
		responseRuleOptions[share.EventRuntime] = &api.RESTResponseRuleOptions{
			Types: []string{share.EventCondTypeName, share.EventCondTypeLevel, share.EventCondTypeProc},
			Name:  getSecurityEventNameList(),
			Level: getEventLevelList([]string{api.LogLevelCRIT, api.LogLevelERR, api.LogLevelWARNING, api.LogLevelNOTICE, api.LogLevelINFO}),
		}
		responseRuleOptions[share.EventCompliance] = &api.RESTResponseRuleOptions{
			Types: []string{share.EventCondTypeLevel, share.EventCondTypeName},
			Name:  getComplianceItemNameList(),
			Level: getEventLevelList([]string{api.LogLevelWARNING}),
		}
	}
	if !acc.HasGlobalPermissions(share.PERMS_RUNTIME_POLICIES, 0) {
		if responseRuleOptionsForLocalUsers == nil {
			responseRuleOptionsForLocalUsers = map[string]*api.RESTResponseRuleOptions{
				share.EventEvent: {
					Types: responseRuleOptions[share.EventEvent].Types,
					Name:  getEventNameList(false),
					Level: responseRuleOptions[share.EventEvent].Level,
				},
				share.EventCVEReport:  responseRuleOptions[share.EventCVEReport],
				share.EventRuntime:    responseRuleOptions[share.EventRuntime],
				share.EventCompliance: responseRuleOptions[share.EventCompliance],
			}
		}
		return responseRuleOptionsForLocalUsers
	} else {
		return responseRuleOptions
	}
}

func handlerResponseRuleOptions(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	query := restParseQuery(r)
	scope, err := checkScopeParameter(w, query, share.ScopeLocal, enumScopeLocal+enumScopeFed)
	if err != nil {
		return
	}
	if (scope == share.ScopeFed && (!acc.IsFedReader() && !acc.IsFedAdmin() && !acc.HasPermFed())) || !acc.Authorize(&share.CLUSResponseRuleOptionsDummy{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	var resp api.RESTResponseRuleOptionData
	resp.Options = getResponeRuleOptions(acc)

	// Fill webhook names
	if scope == share.ScopeFed {
		if fedRole := cacher.GetFedMembershipRoleNoAuth(); fedRole == api.FedRoleMaster && (acc.IsFedReader() || acc.IsFedAdmin()) {
			sc := cacher.GetFedSystemConfig(acc)
			resp.Webhooks = make([]string, len(sc.Webhooks))
			for i, wh := range sc.Webhooks {
				resp.Webhooks[i] = wh.Name
			}
		}
	} else if scope == share.ScopeLocal {
		sc := cacher.GetSystemConfig(access.NewReaderAccessControl())
		resp.Webhooks = make([]string, len(sc.Webhooks))
		for i, wh := range sc.Webhooks {
			resp.Webhooks[i] = wh.Name
		}
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get response rule options")
}

func isValidAction(act string) bool {
	if act != share.EventActionQuarantine &&
		act != share.EventActionSuppressLog && act != share.EventActionWebhook {
		return false
	}
	return true
}

func validateResponseRule(r *api.RESTResponseRule, grpMustExist bool, acc *access.AccessControl) error {
	if r.Event == "" {
		return fmt.Errorf("Missing event for response rule")
	}

	options := getResponeRuleOptions(acc)
	if option, ok := options[r.Event]; !ok {
		return fmt.Errorf("Unsupported event for response rule")
	} else if len(r.Conditions) > 0 {
		cds := utils.NewSet()
		for i, cd := range r.Conditions {
			var found bool = false
			for _, a := range option.Types {
				if a == cd.CondType {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("Unsupported condition type for event %s", r.Event)
			} else if r.Event == share.EventCVEReport {
				// value validation
				if cd.CondType == share.EventCondTypeCVEHigh || cd.CondType == share.EventCondTypeCVEMedium {
					id, err := strconv.Atoi(cd.CondValue)
					if err != nil || id <= 0 {
						return fmt.Errorf("Invalid cve-high value:n %s", cd.CondValue)
					}
				} else if cd.CondType == share.EventCondTypeCVEHighWithFix {
					invalid := false
					ss := strings.Split(cd.CondValue, "/")
					for _, n := range ss {
						if id, err := strconv.Atoi(n); err != nil || id <= 0 {
							invalid = true
							break
						}
					}
					if len(ss) > 2 || invalid {
						return fmt.Errorf("Invalid cve-high-with-fix value:n %s", cd.CondValue)
					}
				} else if cd.CondType == share.EventCondTypeCVEName {
					r.Conditions[i].CondValue = strings.ToUpper(cd.CondValue)
				}
			} //else if r.Event == share.EventCompliance {
			// value validation
			// }
			if !cds.Contains(cd.CondType) {
				cds.Add(cd.CondType)
			} else {
				return fmt.Errorf("Duplicate condition type %s in one rule", cd.CondType)
			}
		}
	}

	if len(r.Actions) == 0 {
		return fmt.Errorf("No action specified in the response rule")
	}

	var scWebhooks []share.CLUSWebhook
	for _, act := range r.Actions {
		if !isValidAction(act) {
			return fmt.Errorf("Action %s is not supported", act)
		}

		// We specifically allow action to be webhook without specifying webhook name,
		// because it is allowed in the pre-multi-webhook config.
		if act == share.EventActionWebhook && len(r.Webhooks) > 0 {
			if scWebhooks == nil {
				if r.CfgType == api.CfgTypeFederal {
					if sc, _ := clusHelper.GetFedSystemConfigRev(acc); sc != nil {
						scWebhooks = sc.Webhooks
					}
				} else {
					if sc, _ := clusHelper.GetSystemConfigRev(access.NewReaderAccessControl()); sc != nil {
						scWebhooks = sc.Webhooks
					}
				}
				if len(scWebhooks) == 0 {
					return fmt.Errorf("Failed to read webhooks info in system configuration")
				}
			}
		WebhookLoop:
			for _, w := range r.Webhooks {
				for _, scw := range scWebhooks {
					if w == scw.Name {
						continue WebhookLoop
					}
				}

				return fmt.Errorf("Webhook %s is not defined", w)
			}
		}
	}

	grpCfgType := cfgTypeMapping[r.CfgType]
	if r.Group != "" {
		grp, _, _ := clusHelper.GetGroup(r.Group, acc)
		if grpMustExist && grp == nil {
			return fmt.Errorf("Group %s is not found", r.Group)
		} else if grp != nil {
			grpCfgType = grp.CfgType
		}
	}

	reservedGroups := utils.NewSetFromStringSlice([]string{api.LearnedExternal})
	switch grpCfgType {
	case share.FederalCfg:
		reservedGroups.Add(api.FedAllHostGroup)
		reservedGroups.Add(api.FedAllContainerGroup)
	default:
		reservedGroups.Add(api.AllHostGroup)
		reservedGroups.Add(api.AllContainerGroup)
	}
	if reservedGroups.Contains(r.Group) {
		// fed.nodes/fed.containers/external are allowed for fed response rules
		// nodes/containers/external are allowed for local response rules
	} else if (r.CfgType == api.CfgTypeFederal && grpCfgType != share.FederalCfg) ||
		(r.CfgType != api.CfgTypeFederal && grpCfgType == share.FederalCfg) {
		return fmt.Errorf("Rule cannot be applied to group %s", r.Group)
	}

	return nil
}

func responseRule2Cluster(r *api.RESTResponseRule) *share.CLUSResponseRule {
	ret := &share.CLUSResponseRule{
		ID:         r.ID,
		Event:      r.Event,
		Comment:    r.Comment,
		Group:      r.Group,
		Conditions: r.Conditions, // Conditions []CLUSEventCondition `json:"conditions,omitempty"`
		Actions:    r.Actions,    // Actions    []string             `json:"actions"`
		Webhooks:   r.Webhooks,
		Disable:    r.Disable,
		CfgType:    cfgTypeMapping[r.CfgType],
	}
	return ret
}

// caller has been verified for federal admin access right
func replaceFedResponseRules(rulesNew map[uint32]*share.CLUSResponseRule, rhsNew []*share.CLUSRuleHead) bool {
	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to acquire cluster lock")
		return false
	}
	defer clusHelper.ReleaseLock(lock)

	txn := cluster.Transact()
	defer txn.Close()

	var lastError error

	// delete obsolete id keys
	rhsExisting := clusHelper.GetResponseRuleList(share.FedPolicyName)
	for _, rhExisting := range rhsExisting {
		if _, ok := rulesNew[rhExisting.ID]; !ok { // in existing but not in latest. so delete it
			clusHelper.DeleteResponseRuleTxn(share.FedPolicyName, txn, rhExisting.ID)
		}
	}
	// write id keys
	for _, ruleNew := range rulesNew {
		if ruleNew != nil {
			ruleExisting, _ := clusHelper.GetResponseRule(share.FedPolicyName, ruleNew.ID)
			if ruleExisting == nil || !reflect.DeepEqual(*ruleNew, *ruleExisting) {
				if err := clusHelper.PutResponseRuleTxn(share.FedPolicyName, txn, ruleNew); err != nil {
					lastError = err
					break
				}
			}
		}
	}
	if !reflect.DeepEqual(rhsNew, rhsExisting) {
		// overwrite rule headers list
		if err := clusHelper.PutResponseRuleListTxn(share.FedPolicyName, txn, rhsNew); err != nil {
			lastError = err
		}
	}

	if lastError != nil {
		log.WithFields(log.Fields{"error": lastError}).Error("Atomic write to the cluster failed")
		return false
	}

	if ok, err := txn.Apply(); err != nil || !ok {
		log.WithFields(log.Fields{"ok": ok, "error": err}).Error("Atomic write to the cluster failed")
		return false
	}

	return true
}

func handlerResponseRuleList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	query := restParseQuery(r)
	scope, err := checkScopeParameter(w, query, share.ScopeAll, enumScopeLocal+enumScopeFed+enumScopeAll)
	if err != nil {
		return
	}

	size := query.limit
	if size == 0 {
		size = 20
	}
	resp := api.RESTResponseRulesData{Rules: make([]*api.RESTResponseRule, 0, size)}
	if cacher.GetResponseRuleCount(scope, acc) <= query.start {
		restRespSuccess(w, r, &resp, acc, login, nil, "Get response rule list")
		return
	}

	rules := cacher.GetAllResponseRules(scope, acc)
	if len(rules) <= query.start {
		restRespSuccess(w, r, &resp, acc, login, nil, "Get response rule list")
		return
	}

	var collectedRules []*api.RESTResponseRule
	if query.limit == 0 {
		collectedRules = rules[query.start:]
	} else {
		var end int
		if query.start+query.limit > len(rules) {
			end = len(rules)
		} else {
			end = query.start + query.limit
		}
		collectedRules = rules[query.start:end]
	}

	resp.Rules = append(resp.Rules, collectedRules...)

	log.WithFields(log.Fields{"entries": len(resp.Rules)}).Debug("Response")
	restRespSuccess(w, r, &resp, acc, login, nil, "Get response rule list")
}

func handlerResponseRuleShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id, policyName, err := getResponsePolicyName(w, ps.ByName("id"))
	if err != nil {
		return
	}

	var resp api.RESTResponseRuleData

	rule, err := cacher.GetResponseRule(policyName, id, acc)
	if rule == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	resp.Rule = rule

	restRespSuccess(w, r, &resp, acc, login, nil, "Get response rule show")
}

// this API doesn't support multi-clusters(fed)
func handlerResponseRuleShowWorkload(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id := ps.ByName("id")
	var resp api.RESTResponseRulesData
	rules, err := cacher.GetWorkloadResponseRules(share.DefaultPolicyName, id, acc)
	if rules == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	resp.Rules = rules

	restRespSuccess(w, r, &resp, acc, login, nil, "Get response rule for a container")
}

func writeResponseRules(policyName string, txn *cluster.ClusterTransact, crs []*share.CLUSResponseRule) error {
	for _, cr := range crs {
		if err := clusHelper.PutResponseRuleTxn(policyName, txn, cr); err != nil {
			return err
		}
	}
	return nil
}

func deleteResponseRules(policyName string, txn *cluster.ClusterTransact, dels utils.Set) {
	for id := range dels.Iter() {
		clusHelper.DeleteResponseRuleTxn(policyName, txn, id.(uint32))
	}
}

func insertResponseRule(policyName string, w http.ResponseWriter, insert *api.RESTResponseRuleInsert,
	lockAcquired, grpMustExist bool, cfgType share.TCfgType, acc *access.AccessControl) ([]uint32, error) {
	log.Debug()

	if insert == nil || len(insert.Rules) == 0 {
		e := "No rule"
		log.Error(e)
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return nil, errors.New(e)
	}
	for _, rule := range insert.Rules {
		if len(rule.Conditions) == 0 {
			e := "No criteria"
			log.Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
			return nil, errors.New(e)
		}
	}

	if !lockAcquired {
		// Acquire locks
		plock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
		if err != nil {
			e := "Failed to acquire cluster policy lock"
			log.WithFields(log.Fields{"error": err}).Error(e)
			restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, e)
			return nil, err
		}
		defer clusHelper.ReleaseLock(plock)
	}

	slock, err := clusHelper.AcquireLock(share.CLUSLockServerKey, clusterLockWait)
	if err != nil {
		e := "Failed to acquire cluster server lock"
		log.WithFields(log.Fields{"error": err}).Error(e)
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, e)
		return nil, err
	}
	defer clusHelper.ReleaseLock(slock)
	// --

	crhs := clusHelper.GetResponseRuleList(policyName)

	ids := utils.NewSet()
	for _, crh := range crhs {
		ids.Add(crh.ID)
	}

	toIdx, after := locatePosition(crhs, insert.After, -1)
	if toIdx == -1 {
		e := "Insert position cannot be found"
		log.WithFields(log.Fields{"after": after}).Error(e)
		restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
		return nil, errors.New(e)
	}

	idAdded := make([]uint32, 0, len(insert.Rules))
	newRules := make([]*share.CLUSResponseRule, len(insert.Rules))
	for i, rr := range insert.Rules {
		if ids.Contains(rr.ID) {
			e := "Duplicate rule ID"
			log.WithFields(log.Fields{"id": rr.ID}).Error(e)
			restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
			return nil, errors.New(e)
		}

		if rr.ID == api.PolicyAutoID {
			cfgType := cfgTypeMapping[rr.CfgType]
			rr.ID = getAvailableRuleID(ruleTypeRespRule, ids, cfgType)
			if rr.ID == 0 {
				err := errors.New("Failed to locate available rule ID")
				log.WithFields(log.Fields{"id": rr.ID}).Error(err)
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
				return nil, err
			}
		}
		idAdded = append(idAdded, rr.ID)

		if err := validateResponseRule(rr, grpMustExist, acc); err != nil {
			log.WithFields(log.Fields{"error": err}).Error()
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
			return nil, err
		} else {
			cr := responseRule2Cluster(rr)
			ids.Add(cr.ID)
			newRules[i] = cr
		}
	}

	txn := cluster.Transact()
	defer txn.Close()

	var lastError error
	if err := writeResponseRules(policyName, txn, newRules); err != nil {
		lastError = err
	}

	news := make([]*share.CLUSRuleHead, len(insert.Rules))
	for i, r := range insert.Rules {
		news[i] = &share.CLUSRuleHead{
			ID:      r.ID,
			CfgType: cfgTypeMapping[insert.Rules[0].CfgType],
		}
	}

	crhs = append(crhs[:toIdx], append(news, crhs[toIdx:]...)...)

	if err := clusHelper.PutResponseRuleListTxn(policyName, txn, crhs); err != nil {
		lastError = err
	}

	if lastError != nil {
		log.WithFields(log.Fields{"error": lastError}).Error()
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return nil, lastError
	}

	if ok, err := txn.Apply(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return nil, err
	} else if !ok {
		err = errors.New("Atomic write failed")
		log.Error(err.Error())
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return nil, err
	}

	return idAdded, nil
}

func handlerResponseRuleAction(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}

	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTResponseRuleActionData
	err := json.Unmarshal(body, &rconf)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	if rconf.Insert != nil && len(rconf.Insert.Rules) > 0 {
		firstCfgType := rconf.Insert.Rules[0].CfgType
		if firstCfgType == "" {
			firstCfgType = api.CfgTypeUserCreated
		}
		for _, r := range rconf.Insert.Rules {
			if r != nil {
				if r.CfgType == "" {
					r.CfgType = api.CfgTypeUserCreated
				}
				if r.CfgType != firstCfgType {
					log.Error("Request error: rules in different cfgType")
					restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
					return
				}
			}
		}
		var policyName string
		if firstCfgType == api.CfgTypeFederal {
			policyName = share.FedPolicyName
		} else {
			policyName = share.DefaultPolicyName
		}
		_, err = insertResponseRule(policyName, w, rconf.Insert, false, true, cfgTypeMapping[firstCfgType], acc)
		if err == nil {
			if policyName == share.FedPolicyName {
				updateFedRulesRevision([]string{share.FedResponseRulesType}, acc, login)
			}
			restRespSuccess(w, r, nil, acc, login, &rconf, "Insert response rule")
		}
	}
}

func handlerResponseRuleConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}

	id, policyName, err := getResponsePolicyName(w, ps.ByName("id"))
	if err != nil {
		return
	}

	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTResponseRuleConfigData
	err = json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	if rconf.Config.ID != id {
		e := "Rule ID mismatch in the request"
		log.WithFields(log.Fields{"id": id}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}
	if rconf.Config.Conditions != nil && len(*rconf.Config.Conditions) == 0 {
		e := "No criteria"
		log.Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}

	rule, err := cacher.GetResponseRule(policyName, id, acc)
	if rule == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	// Acquire locks
	plock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		e := "Failed to acquire cluster policy lock"
		log.WithFields(log.Fields{"error": err}).Error(e)
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, e)
		return
	}
	defer clusHelper.ReleaseLock(plock)

	slock, err := clusHelper.AcquireLock(share.CLUSLockServerKey, clusterLockWait)
	if err != nil {
		e := "Failed to acquire cluster server lock"
		log.WithFields(log.Fields{"error": err}).Error(e)
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, e)
		return
	}
	defer clusHelper.ReleaseLock(slock)
	// ---

	rc := rconf.Config

	cconf, _ := clusHelper.GetResponseRule(policyName, rc.ID)
	if cconf == nil {
		e := "Response rule doesn't exist"
		log.WithFields(log.Fields{"id": rc.ID}).Error(e)
		restRespErrorMessage(w, http.StatusNotFound, api.RESTErrObjectNotFound, e)
		return
	}

	if rc.Group != nil {
		cconf.Group = *rc.Group
	}
	if rc.Event != nil {
		cconf.Event = *rc.Event
	}
	if rc.Conditions != nil {
		cconf.Conditions = *rc.Conditions
	}
	if rc.Actions != nil {
		cconf.Actions = *rc.Actions
	}
	if rc.Webhooks != nil {
		cconf.Webhooks = *rc.Webhooks
	}
	if rc.Comment != nil {
		cconf.Comment = *rc.Comment
	}
	if rc.Disable != nil {
		cconf.Disable = *rc.Disable
	}

	rr := cacher.ResponseRule2REST(cconf)
	if err := validateResponseRule(rr, true, acc); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
		return
	} else {
		if err := clusHelper.PutResponseRule(policyName, cconf); err != nil {
			log.WithFields(log.Fields{"error": err}).Error()
			restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
			return
		}
	}

	if policyName == share.FedPolicyName {
		updateFedRulesRevision([]string{share.FedResponseRulesType}, acc, login)
	}
	restRespSuccess(w, r, nil, acc, login, &rconf, "Config response rule")
}

func handlerResponseRuleDelete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id, policyName, err := getResponsePolicyName(w, ps.ByName("id"))
	if err != nil {
		return
	}

	rule, err := cacher.GetResponseRule(policyName, id, acc)
	if rule == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	if rule.CfgType == api.CfgTypeGround {
		e := "Rule created by CRD cannot be deleted"
		log.WithFields(log.Fields{"id": rule.ID}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}

	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to acquire cluster lock")
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, err.Error())
		return
	}
	defer clusHelper.ReleaseLock(lock)

	crhs := clusHelper.GetResponseRuleList(policyName)

	var idx int = -1
	for i, crh := range crhs {
		if crh.ID == id {
			idx = i
			break
		}
	}

	if idx == -1 {
		log.WithFields(log.Fields{"id": id}).Error("Event rule doesn't exist")
		restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
		return
	}

	size := len(crhs)
	copy(crhs[idx:], crhs[idx+1:])
	crhs[size-1] = nil
	crhs = crhs[:size-1]

	txn := cluster.Transact()
	defer txn.Close()

	if err := clusHelper.PutResponseRuleListTxn(policyName, txn, crhs); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}

	dels := utils.NewSet(id)
	deleteResponseRules(policyName, txn, dels)
	if ok, err := txn.Apply(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	} else if !ok {
		err = errors.New("Atomic write failed")
		log.Error(err.Error())
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}

	if policyName == share.FedPolicyName {
		updateFedRulesRevision([]string{share.FedResponseRulesType}, acc, login)
	}
	restRespSuccess(w, r, nil, acc, login, nil, "Delete response rule")
}

func handlerResponseRuleDeleteAll(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}

	query := restParseQuery(r)
	scope, err := checkScopeParameter(w, query, share.ScopeLocal, enumScopeLocal+enumScopeFed)
	if err != nil {
		return
	}

	var policyName string
	if scope == share.ScopeFed {
		policyName = share.ScopeFed
	} else {
		policyName = share.DefaultPolicyName
	}

	rules := cacher.GetAllResponseRules(scope, acc)
	allowed := utils.NewSet()
	for _, r := range rules {
		allowed.Add(r.ID)
	}
	if allowed.Cardinality() == 0 {
		restRespSuccess(w, r, nil, acc, login, nil, "Delete all response rules")
		return
	}

	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to acquire cluster lock")
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, err.Error())
		return
	}
	defer clusHelper.ReleaseLock(lock)

	crhs := clusHelper.GetResponseRuleList(policyName)

	keeps := make([]*share.CLUSRuleHead, 0)
	dels := utils.NewSet()
	for _, crh := range crhs {
		if allowed.Contains(crh.ID) {
			dels.Add(crh.ID)
		}
	}

	txn := cluster.Transact()
	defer txn.Close()

	if err := clusHelper.PutResponseRuleListTxn(policyName, txn, keeps); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}
	deleteResponseRules(policyName, txn, dels)

	if ok, err := txn.Apply(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	} else if !ok {
		err = errors.New("Atomic write failed")
		log.Error(err.Error())
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}

	if policyName == share.FedPolicyName {
		updateFedRulesRevision([]string{share.FedResponseRulesType}, acc, login)
	}
	restRespSuccess(w, r, nil, acc, login, nil, "Delete all response rules")
}

func handlerResponseRuleExport(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	// allow export no matter it's k8s env or not
	acc, login := getAccessControl(w, r, access.AccessOPRead)
	if acc == nil {
		return
	}

	scope, err := checkExportScope(w, r, share.IMPORT_TYPE_RESPONSE, login)
	if err != nil {
		return
	}

	var rconf api.RESTResponseRulesExport
	body, _ := io.ReadAll(r.Body)
	err = json.Unmarshal(body, &rconf)
	if err != nil || len(rconf.IDs) == 0 {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	apiVersion := resource.NvResponseSecurityRuleVersion
	resp := resource.NvResponseSecurityRuleList{
		TypeMeta: metav1.TypeMeta{
			Kind:       resource.NvListKind,
			APIVersion: apiVersion,
		},
	}

	// do not support mixed export of fed/local response rules. rules do not qualify scope are filtered out.
	exportIDs := make([]uint32, 0, len(rconf.IDs))
	for _, id := range rconf.IDs {
		isFedRule := isFedPolicyID(id)
		if (scope == share.ScopeFed && isFedRule) || (scope == share.ScopeLocal && !isFedRule) {
			exportIDs = append(exportIDs, id)
		} else {
			log.WithFields(log.Fields{"id": id, "scope": scope}).Warn("skip")
		}
	}

	exportFileName := "cfgResponseRulesExport.yaml"
	exportType := "response rules"
	if scope == share.ScopeFed {
		exportFileName = "cfgFedResponseRulesExport.yaml"
		exportType = "federal " + exportType
	}

	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		e := "Failed to acquire cluster lock"
		log.WithFields(log.Fields{"error": err}).Error(e)
		return
	}
	defer clusHelper.ReleaseLock(lock)

	apiversion := fmt.Sprintf("%s/%s", common.OEMSecurityRuleGroup, resource.NvResponseSecurityRuleVersion)
	for _, id := range exportIDs {
		// export response rules
		responseRules, err := exportResponseRules(scope, "", id, acc)
		if err != nil {
			e := fmt.Sprintf("Failed to export response rule %v", id)
			log.WithFields(log.Fields{"err": err}).Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
			return
		}
		if len(responseRules) == 0 || responseRules[0] == nil {
			continue
		}
		responseRule := responseRules[0]
		crName, err := genResponseRuleCrName(id, scope, *responseRule)
		if err != nil {
			log.WithFields(log.Fields{"id": id, "scope": scope, "err": err}).Error()
			continue
		}
		respTemp := resource.NvResponseSecurityRule{
			TypeMeta: metav1.TypeMeta{
				APIVersion: apiversion,
				Kind:       resource.NvResponseSecurityRuleKind,
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: crName,
			},
			Spec: resource.NvSecurityResponseSpec{
				Rule: *responseRule,
			},
		}
		resp.Items = append(resp.Items, respTemp)
	}

	doExport(exportFileName, exportType, rconf.RemoteExportOptions, resp, w, r, acc, login)
}

func handlerResponseRuleImport(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	tid := r.Header.Get("X-Transaction-ID")
	_importHandler(w, r, tid, share.IMPORT_TYPE_RESPONSE, share.PREFIX_IMPORT_RESPONSE, share.PERMS_RUNTIME_POLICIES, acc, login)
}

func genResponseRuleCrName(id uint32, scope string, crdRule resource.NvCrdResponseRule) (string, error) {
	rMini := api.RESTResponseRule{
		ID:         id,
		Event:      crdRule.Event,
		Conditions: crdRule.Conditions,
		Actions:    crdRule.Actions,
		Webhooks:   crdRule.Webhooks,
	}
	jsonData, err := json.Marshal(&rMini)
	if err != nil {
		return "", err
	}
	b := sha256.Sum256(jsonData)
	crName := fmt.Sprintf("%s--%s", crdRule.Event, hex.EncodeToString(b[:]))
	if scope == share.ScopeFed {
		crName = api.FederalGroupPrefix + crName
	}

	return crName, nil
}

func exportResponseRules(scope, gName string, id uint32, acc *access.AccessControl) ([]*resource.NvCrdResponseRule, error) {
	policyName := getResponseExportPolicyName(gName, id)
	if id != 0 {
		// export a specific response rule
		r, err := cacher.GetResponseRule(policyName, id, acc)
		if err != nil {
			return nil, err
		}
		if gName != r.Group {
			if gName == "" {
				// ignore per-group's response rules when exporting global response rules because
				//  response rules for a specific group must be exported with group by POST("/v1/file/group")
				return nil, nil
			}
			return nil, fmt.Errorf("response rule %d is for group <%s>", id, r.Group)
		}
		crdRule := &resource.NvCrdResponseRule{
			PolicyName: policyName,
			Event:      r.Event,
			Actions:    r.Actions,
			Comment:    r.Comment,
			Disable:    r.Disable,
			Webhooks:   r.Webhooks,
			Conditions: r.Conditions,
		}
		return []*resource.NvCrdResponseRule{crdRule}, nil
	}
	if gName != "" {
		var rules []*resource.NvCrdResponseRule
		// export all response rules that are for the group
		allRules := cacher.GetAllResponseRules(scope, acc)
		for _, r := range allRules {
			if r.Group == gName {
				crdRule := &resource.NvCrdResponseRule{
					PolicyName: policyName,
					Event:      r.Event,
					Actions:    r.Actions,
					Comment:    r.Comment,
					Disable:    r.Disable,
					Webhooks:   r.Webhooks,
					Conditions: r.Conditions,
				}
				rules = append(rules, crdRule)
			}
		}
		return rules, nil
	}

	return nil, nil
}

func parseResponseYamlFile(importData []byte) ([]resource.NvResponseSecurityRule, error) {
	importDataStr := string(importData)
	yamlParts := strings.Split(importDataStr, "\n---\n")

	// check whether it's Windows format
	if len(yamlParts) == 1 && strings.Contains(importDataStr, "\r\n") {
		yamlParts = strings.Split(importDataStr, "\r\n---\r\n")
	}

	var err error
	var nvSecRules []resource.NvResponseSecurityRule

	for i, yamlPart := range yamlParts {
		var sb strings.Builder
		scanner := bufio.NewScanner(strings.NewReader(yamlPart))
		for scanner.Scan() {
			line := scanner.Text()
			lineTrimmed := strings.TrimSpace(line)
			if len(lineTrimmed) == 0 || lineTrimmed[0] == byte('#') {
				continue
			} else {
				sb.WriteString(line)
				sb.WriteString("\n")
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error reading YAML part %d: %s", i, err)
		}
		yamlPart = sb.String()
		sb.Reset()
		if len(yamlPart) == 0 {
			continue
		}

		var jsonData []byte
		if jsonData, err = yaml.YAMLToJSON([]byte(yamlPart)); err == nil {
			var nvCrList resource.NvCrList
			if err = json.Unmarshal(jsonData, &nvCrList); err == nil {
				if nvCrList.Kind == "List" {
					if len(nvCrList.Items) > 0 {
						nvCr := nvCrList.Items[0]
						if nvCr.Kind == resource.NvResponseSecurityRuleListKind || nvCr.Kind == resource.NvResponseSecurityRuleKind {
							var nvSecRuleList resource.NvResponseSecurityRuleList
							if err = json.Unmarshal(jsonData, &nvSecRuleList); err == nil {
								nvSecRules = append(nvSecRules, nvSecRuleList.Items...)
							}
						} else {
							err = fmt.Errorf("kind: %s", nvCr.Kind)
						}
					}
				} else {
					if nvCrList.Kind == resource.NvResponseSecurityRuleListKind || nvCrList.Kind == resource.NvResponseSecurityRuleKind {
						var nvSecRule resource.NvResponseSecurityRule
						if err = json.Unmarshal(jsonData, &nvSecRule); err == nil {
							nvSecRules = append(nvSecRules, nvSecRule)
						}
					} else {
						err = fmt.Errorf("kind: %s", nvCrList.Kind)
					}
				}
			}
		}
		if err != nil {
			err = fmt.Errorf("Invalid yaml(%d): %s", i, err.Error())
			break
		}
	}

	if err == nil {
		if err == nil {
			for _, r := range nvSecRules {
				if r.APIVersion != "neuvector.com/v1" || r.Kind != resource.NvResponseSecurityRuleKind {
					err = fmt.Errorf("Invalid yaml, apiVersion: %s, kind: %s", r.APIVersion, r.Kind)
					break
				}
			}
		}
	}

	if err != nil {
		nvSecRules = nil
	}

	return nvSecRules, err
}

func importResponse(loginDomainRoles access.DomainRole, importTask share.CLUSImportTask,
	postImportOp kv.PostImportFunc, acc *access.AccessControl, login *loginSession) error {
	log.Debug()
	defer os.Remove(importTask.TempFilename)

	var secRules []resource.NvResponseSecurityRule
	json_data, err := os.ReadFile(importTask.TempFilename)
	if err == nil {
		secRules, err = parseResponseYamlFile(json_data)
	}
	if err != nil {
		msg := "Failed to read/parse the imported file"
		log.WithFields(log.Fields{"error": err}).Error(msg)
		postImportOp(errors.New(msg), importTask, loginDomainRoles, "", share.IMPORT_TYPE_RESPONSE)
		return nil
	} else if len(secRules) == 0 {
		log.Info("no security rule in yaml")
		postImportOp(nil, importTask, loginDomainRoles, "", share.IMPORT_TYPE_RESPONSE)
		return nil
	}

	var inc float32
	var progress float32 // progress percentage

	inc = 90.0 / float32(3+len(secRules))
	parsedResponseCfgs := make([]*resource.NvSecurityParse, 0, len(secRules))
	progress = 6

	importTask.Percentage = int(progress)
	importTask.Status = share.IMPORT_RUNNING
	_ = clusHelper.PutImportTask(&importTask) // Ignore error because progress update is non-critical

	var crdHandler nvCrdHandler
	crdHandler.Init(share.CLUSLockPolicyKey, importCallerRest)
	if crdHandler.AcquireLock(clusterLockWait) {
		defer crdHandler.ReleaseLock()

		// [1] parse all non-group-dependent response security rules in the yaml file
		for _, secRule := range secRules {
			parsedCfg, errCount, errMsg, _ := crdHandler.parseCurCrdResponseContent(&secRule, share.ReviewTypeImportResponse, share.ReviewTypeDisplayResponse)
			if errCount > 0 {
				err = errors.New(errMsg)
				break
			}
			if (importTask.Scope == share.ScopeFed && parsedCfg.CfgType != share.FederalCfg) ||
				(importTask.Scope == share.ScopeLocal && parsedCfg.CfgType != share.UserCreated) {
				log.WithFields(log.Fields{"scope": importTask.Scope, "event": parsedCfg.ResponseCfg.Event}).Warn("skip")
				err = fmt.Errorf("Response rule %s is not allowed for import with scope=%s", secRule.GetName(), importTask.Scope)
				break
			}
			parsedResponseCfgs = append(parsedResponseCfgs, parsedCfg)
		}
		if err != nil {
			postImportOp(err, importTask, loginDomainRoles, "", share.IMPORT_TYPE_RESPONSE)
			return nil
		}

		if importTask.Overwrite == "1" {
			kv.DeleteResponseRuleByGroup("")
		}

		oneSuccess := false
		progress += inc
		importTask.Percentage = int(progress)
		_ = clusHelper.PutImportTask(&importTask) // Ignore error because progress update is non-critical

		for _, parsedCfg := range parsedResponseCfgs {
			cacheRecord := share.CLUSCrdSecurityRule{
				ResponseRules: &share.CLUSCrdResponseRules{},
			}
			// [4] import all security rules defined in the yaml file
			err = crdHandler.crdHandleResponseRule(parsedCfg.CfgType, parsedCfg.ResponseCfg, &cacheRecord, share.ReviewTypeImportResponse)
			if err != nil {
				break
			}
			oneSuccess = true
			progress += inc
			importTask.Percentage = int(progress)
			_ = clusHelper.PutImportTask(&importTask)
		}
		importTask.Percentage = 90
		_ = clusHelper.PutImportTask(&importTask) // Ignore error because progress update is non-critical

		if oneSuccess && importTask.Scope == share.ScopeFed {
			updateFedRulesRevision([]string{share.FedResponseRulesType}, acc, login)
		}
	}

	postImportOp(err, importTask, loginDomainRoles, "", share.IMPORT_TYPE_RESPONSE)

	return nil
}

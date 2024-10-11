package rest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/julienschmidt/httprouter"
	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

var responseRuleOptions map[string]*api.RESTResponseRuleOptions
var responseRuleOptionsForLocalUsers map[string]*api.RESTResponseRuleOptions

func getResPolicyName(w http.ResponseWriter, id string) (int, string, error) {
	idNum, err := strconv.Atoi(id)
	if err != nil || idNum <= 0 {
		log.WithFields(log.Fields{"id": id, "err": err}).Error("Invalid ID")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return 0, "", common.ErrObjectNotFound
	}
	if idNum > api.StartingFedAdmRespRuleID {
		return idNum, share.FedPolicyName, nil
	} else {
		return idNum, share.DefaultPolicyName, nil
	}
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
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	var scope string
	if scope = restParseQuery(r).pairs[api.QueryScope]; scope == "" {
		scope = share.ScopeLocal
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

func validateResponseRule(r *api.RESTResponseRule, acc *access.AccessControl) error {
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

	if r.Group != "" {
		grp, _, _ := clusHelper.GetGroup(r.Group, acc)
		if grp == nil {
			return fmt.Errorf("Group %s is not found", r.Group)
		} else {
			if r.Group == api.LearnedExternal || r.Group == api.AllHostGroup {
				// containers/external/nodes are allowed for fed response rules
			} else if (r.CfgType == api.CfgTypeFederal && grp.CfgType != share.FederalCfg) ||
				(r.CfgType != api.CfgTypeFederal && grp.CfgType == share.FederalCfg) {
				return fmt.Errorf("Rule cannot be applied to group %s", r.Group)
			}
		}
	} else if (r.CfgType == api.CfgTypeFederal && !acc.IsFedAdmin()) ||
		(r.CfgType != api.CfgTypeFederal && !acc.HasGlobalPermissions(share.PERMS_RUNTIME_POLICIES, share.PERMS_RUNTIME_POLICIES)) {
		return common.ErrObjectAccessDenied
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
	}
	ret.CfgType = cfgTypeMapping[r.CfgType]
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
				clusHelper.PutResponseRuleTxn(share.FedPolicyName, txn, ruleNew)
			}
		}
	}
	if !reflect.DeepEqual(rhsNew, rhsExisting) {
		// overwrite rule headers list
		clusHelper.PutResponseRuleListTxn(share.FedPolicyName, txn, rhsNew)
	}

	if ok, err := txn.Apply(); err != nil || !ok {
		log.WithFields(log.Fields{"ok": ok, "error": err}).Error("Atomic write to the cluster failed")
		return false
	}

	return true
}

func handlerResponseRuleList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	query := restParseQuery(r)
	scope := query.pairs[api.QueryScope] // empty string means fed & local rules

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
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id, policyName, err := getResPolicyName(w, ps.ByName("id"))
	if err != nil {
		return
	}

	var resp api.RESTResponseRuleData

	rule, err := cacher.GetResponseRule(policyName, uint32(id), acc)
	if rule == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	resp.Rule = rule

	restRespSuccess(w, r, &resp, acc, login, nil, "Get response rule show")
}

// this API doesn't support multi-clusters(fed)
func handlerResponseRuleShowWorkload(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
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

func writeResponseRules(policyName string, txn *cluster.ClusterTransact, crs []*share.CLUSResponseRule) {
	for _, cr := range crs {
		clusHelper.PutResponseRuleTxn(policyName, txn, cr)
	}
}

func deleteResponseRules(policyName string, txn *cluster.ClusterTransact, dels utils.Set) {
	for id := range dels.Iter() {
		clusHelper.DeleteResponseRuleTxn(policyName, txn, id.(uint32))
	}
}

func insertResponseRule(policyName string, w http.ResponseWriter, r *http.Request, insert *api.RESTResponseRuleInsert, acc *access.AccessControl) error {
	log.Debug("")

	// Acquire locks
	plock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		e := "Failed to acquire cluster policy lock"
		log.WithFields(log.Fields{"error": err}).Error(e)
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, e)
		return err
	}
	defer clusHelper.ReleaseLock(plock)

	slock, err := clusHelper.AcquireLock(share.CLUSLockServerKey, clusterLockWait)
	if err != nil {
		e := "Failed to acquire cluster server lock"
		log.WithFields(log.Fields{"error": err}).Error(e)
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, e)
		return err
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
		return fmt.Errorf("%s", e)
	}

	var cfgType share.TCfgType = share.UserCreated
	if policyName == share.FedPolicyName {
		cfgType = share.FederalCfg
	}

	newRules := make([]*share.CLUSResponseRule, len(insert.Rules))
	for i, rr := range insert.Rules {
		if ids.Contains(rr.ID) {
			e := "Duplicate rule ID"
			log.WithFields(log.Fields{"id": rr.ID}).Error(e)
			restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
			return fmt.Errorf("%s", e)
		}

		if rr.ID == api.PolicyAutoID {
			rr.ID = getAvailableRuleID(ruleTypeRespRule, ids, cfgType)
			if rr.ID == 0 {
				err := errors.New("Failed to locate available rule ID")
				log.WithFields(log.Fields{"id": rr.ID}).Error(err)
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
				return err
			}
		}

		if err := validateResponseRule(rr, acc); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("")
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
			return err
		} else {
			cr := responseRule2Cluster(rr)
			ids.Add(cr.ID)
			newRules[i] = cr
		}
	}

	txn := cluster.Transact()
	defer txn.Close()

	writeResponseRules(policyName, txn, newRules)

	news := make([]*share.CLUSRuleHead, len(insert.Rules))
	for i, r := range insert.Rules {
		news[i] = &share.CLUSRuleHead{
			ID:      r.ID,
			CfgType: cfgType,
		}
	}

	crhs = append(crhs[:toIdx], append(news, crhs[toIdx:]...)...)

	clusHelper.PutResponseRuleListTxn(policyName, txn, crhs)

	if ok, err := txn.Apply(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return err
	} else if !ok {
		err = errors.New("Atomic write failed")
		log.Error(err.Error())
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return err
	}

	return nil
}

func handlerResponseRuleAction(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
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
		for _, r := range rconf.Insert.Rules {
			if r != nil {
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
		err = insertResponseRule(policyName, w, r, rconf.Insert, acc)
		if err == nil {
			if policyName == share.FedPolicyName {
				updateFedRulesRevision([]string{share.FedResponseRulesType}, acc, login)
			}
			restRespSuccess(w, r, nil, acc, login, &rconf, "Insert response rule")
		}
	}
}

func handlerResponseRuleConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id, policyName, err := getResPolicyName(w, ps.ByName("id"))
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

	if rconf.Config.ID != uint32(id) {
		e := "Rule ID mismatch in the request"
		log.WithFields(log.Fields{"id": id}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}

	rule, err := cacher.GetResponseRule(policyName, uint32(id), acc)
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
	if err := validateResponseRule(rr, acc); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
		return
	} else {
		if err := clusHelper.PutResponseRule(policyName, cconf); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("")
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
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id, policyName, err := getResPolicyName(w, ps.ByName("id"))
	if err != nil {
		return
	}

	rule, err := cacher.GetResponseRule(policyName, uint32(id), acc)
	if rule == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
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
		if crh.ID == uint32(id) {
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

	clusHelper.PutResponseRuleListTxn(policyName, txn, crhs)

	dels := utils.NewSet(uint32(id))
	deleteResponseRules(policyName, txn, dels)
	if ok, err := txn.Apply(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
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
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}

	query := restParseQuery(r)
	scope := query.pairs[api.QueryScope]
	if scope == "" {
		scope = share.ScopeLocal
	} else if scope != share.ScopeFed && scope != share.ScopeLocal {
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
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

	clusHelper.PutResponseRuleListTxn(policyName, txn, keeps)
	deleteResponseRules(policyName, txn, dels)

	if ok, err := txn.Apply(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
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

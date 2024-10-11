package rest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/glenn-brown/golang-pkg-pcre/src/pkg/pcre"
	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
)

func handlerWafSensorList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	query := restParseQuery(r)

	var resp api.RESTWafSensorsData
	resp.Sensors = make([]*api.RESTWafSensor, 0)

	wafsensors := cacher.GetAllWafSensors(acc)
	// Filter
	if len(wafsensors) <= query.start {
		restRespSuccess(w, r, &resp, acc, login, nil, "Get waf rule list")
		return
	}

	if len(wafsensors) > 1 && len(query.sorts) > 0 {
		// Convert struct slice to interface slice
		var data []interface{} = make([]interface{}, len(wafsensors))
		for i, d := range wafsensors {
			data[i] = d
		}
		// Sort
		restNewSorter(data, query.sorts).Sort()
		for i, d := range data {
			wafsensors[i] = d.(*api.RESTWafSensor)
		}
	} else {
		sort.Slice(wafsensors, func(i, j int) bool { return wafsensors[i].Name < wafsensors[j].Name })
	}

	if query.limit == 0 {
		resp.Sensors = wafsensors[query.start:]
	} else {
		var end int
		if query.start+query.limit > len(wafsensors) {
			end = len(wafsensors)
		} else {
			end = query.start + query.limit
		}
		resp.Sensors = wafsensors[query.start:end]
	}

	//always put predefined sensor in front
	preSensors := make([]*api.RESTWafSensor, 0)
	userSensors := make([]*api.RESTWafSensor, 0)
	for _, sen := range resp.Sensors {
		if sen.Predefine {
			preSensors = append(preSensors, sen)
		} else {
			userSensors = append(userSensors, sen)
		}
	}
	preSensors = append(preSensors, userSensors...)
	resp.Sensors = preSensors

	log.WithFields(log.Fields{"entries": len(resp.Sensors)}).Debug("Response")
	restRespSuccess(w, r, &resp, acc, login, nil, "Get all waf sensors")
}

func handlerWafRuleList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	query := restParseQuery(r)

	var resp api.RESTWafRulesData
	resp.Rules = make([]*api.RESTWafRule, 0)

	rules, err := cacher.GetWafRules(acc)
	if rules == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	// Filter
	if len(rules) <= query.start {
		restRespSuccess(w, r, &resp, acc, login, nil, "Get waf rule list")
		return
	}

	if len(rules) > 1 && len(query.sorts) > 0 {
		// Convert struct slice to interface slice
		var data []interface{} = make([]interface{}, len(rules))
		for i, d := range rules {
			data[i] = d
		}
		// Sort
		restNewSorter(data, query.sorts).Sort()
		for i, d := range data {
			rules[i] = d.(*api.RESTWafRule)
		}
	} else {
		sort.Slice(rules, func(i, j int) bool { return rules[i].Name < rules[j].Name })
	}

	if query.limit == 0 {
		resp.Rules = rules[query.start:]
	} else {
		var end int
		if query.start+query.limit > len(rules) {
			end = len(rules)
		} else {
			end = query.start + query.limit
		}
		resp.Rules = rules[query.start:end]
	}
	log.WithFields(log.Fields{"entries": len(resp.Rules)}).Debug("Response")
	restRespSuccess(w, r, &resp, acc, login, nil, "Get all waf rules")
}

func handlerWafGroupList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	query := restParseQuery(r)

	var resp api.RESTWafGroupsData
	resp.WafGroups = make([]*api.RESTWafGroup, 0)

	wafgroups := cacher.GetAllWafGroup(acc)
	// Filter
	if len(wafgroups) <= query.start {
		restRespSuccess(w, r, &resp, acc, login, nil, "Get waf group list")
		return
	}

	if len(wafgroups) > 1 && len(query.sorts) > 0 {
		// Convert struct slice to interface slice
		var data []interface{} = make([]interface{}, len(wafgroups))
		for i, d := range wafgroups {
			data[i] = d
		}
		// Sort
		restNewSorter(data, query.sorts).Sort()
		for i, d := range data {
			wafgroups[i] = d.(*api.RESTWafGroup)
		}
	} else {
		sort.Slice(wafgroups, func(i, j int) bool { return wafgroups[i].Name < wafgroups[j].Name })
	}

	if query.limit == 0 {
		resp.WafGroups = wafgroups[query.start:]
	} else {
		var end int
		if query.start+query.limit > len(wafgroups) {
			end = len(wafgroups)
		} else {
			end = query.start + query.limit
		}
		resp.WafGroups = wafgroups[query.start:end]
	}
	log.WithFields(log.Fields{"entries": len(resp.WafGroups)}).Debug("all waf groups")
	restRespSuccess(w, r, &resp, acc, login, nil, "Get all waf group")
}

func handlerWafSensorShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	drsensor := ps.ByName("name")

	wafsensor, err := cacher.GetWafSensor(drsensor, acc)
	if wafsensor == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}
	resp := api.RESTWafSensorData{Sensor: wafsensor}
	restRespSuccess(w, r, &resp, acc, login, nil, "Get waf sensor detail")
}

func handlerWafRuleShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	name := ps.ByName("name")

	rule, err := cacher.GetWafRule(name, acc)
	if rule == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}
	resp := api.RESTWafRuleData{Rule: rule}
	restRespSuccess(w, r, &resp, acc, login, nil, "Get waf rule detail")
}

func handlerWafGroupShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	dgroup := ps.ByName("name")

	//Authorize group
	exist, err := cacher.DoesGroupExist(dgroup, acc)
	if !exist {
		log.WithFields(log.Fields{"group": dgroup}).Debug("Group does not exist!")
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	wafgroup, err := cacher.GetWafGroup(dgroup, acc)
	if wafgroup == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}
	resp := api.RESTWafGroupData{WafGroup: wafgroup}
	restRespSuccess(w, r, &resp, acc, login, nil, "Get waf group detail")
}

var regWafPattern *regexp.Regexp = regexp.MustCompile(`^\.*\*$`)

func validateWafRuleConfig(list []api.RESTWafRule) error {
	for _, rule := range list {
		if !isObjectNameValid(rule.Name) || len(rule.Name) > api.DlpRuleNameMaxLen {
			log.WithFields(log.Fields{"name": rule.Name, "name_len": len(rule.Name)}).Error("Invalid rule name")
			return fmt.Errorf("waf rule %s: invalid name format", rule.Name)
		}
		if len(rule.Patterns) == 0 {
			log.WithFields(log.Fields{"name": rule.Name}).Error("Waf rule must have pattern")
			return fmt.Errorf("waf rule %s: waf rule must have pattern", rule.Name)
		}
		if len(rule.Patterns) > api.DlpRulePatternMaxNum {
			log.WithFields(log.Fields{"name": rule.Name, "num": len(rule.Patterns), "max": api.DlpRulePatternMaxNum}).Error("Waf rule exceed max patterns")
			return fmt.Errorf("waf rule %s: must have no more than %d patterns", rule.Name, api.DlpRulePatternMaxNum)
		}
		total_len := 0
		for _, pt := range rule.Patterns {
			if pt.Op == share.CriteriaOpRegex || pt.Op == share.CriteriaOpNotRegex {
				if len(pt.Value) > api.DlpRulePatternMaxLen || len(pt.Value) <= 0 {
					log.WithFields(log.Fields{"pattern": pt.Value, "pattern_len": len(pt.Value)}).Error("Invalid pattern length")
					return fmt.Errorf("waf rule %s: invalid pattern length (%d)", rule.Name, len(pt.Value))
				}
				total_len += len(pt.Value)
				if total_len > api.DlpRulePatternTotalMaxLen {
					log.WithFields(log.Fields{"total": total_len, "max": api.DlpRulePatternTotalMaxLen}).Error("Exceed max total pattern length")
					return fmt.Errorf("waf rule %s: total pattern length %d exceed max allowed %d", rule.Name, total_len, api.DlpRulePatternTotalMaxLen)
				}
				if pt.Context != "" &&
					pt.Context != share.DlpPatternContextURI &&
					pt.Context != share.DlpPatternContextHEAD &&
					pt.Context != share.DlpPatternContextBODY &&
					pt.Context != share.DlpPatternContextPACKET {
					log.WithFields(log.Fields{"context": pt.Context}).Error("Invalid pattern context")
					return fmt.Errorf("waf rule %s: invalid pattern context (%s)", rule.Name, pt.Context)
				}
				if _, err := pcre.Compile(pt.Value, 0); err != nil {
					log.WithFields(log.Fields{"error": err}).Error("Invalid regex in pattern criteria")
					return fmt.Errorf("waf rule %s: invalid regex in pattern criteria (%s)", rule.Name, pt.Value)
				} else {
					if regWafPattern.MatchString(pt.Value) {
						log.WithFields(log.Fields{"error": err}).Error("Invalid regex in pattern criteria")
						return fmt.Errorf("waf rule %s: invalid regex in pattern criteria (%s)", rule.Name, pt.Value)
					}
				}
			}
		}
	}
	return nil
}

// lock is alreay hold when call this function
// clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
func createDefaultWafSensor() {
	kv.CreateDefWafRules(true)
	kv.CreatePreWafSensor(true)
}

func createWafSensor(w http.ResponseWriter, conf *api.RESTWafSensorConfig, cfgType share.TCfgType) error {

	sensor := &share.CLUSWafSensor{
		Name:          conf.Name,
		Groups:        make(map[string]string),
		RuleListNames: make(map[string]string),
		RuleList:      make(map[string]*share.CLUSWafRule),
		PreRuleList:   make(map[string][]*share.CLUSWafRule),
		Predefine:     false,
		CfgType:       cfgType,
	}
	if conf.Comment != nil {
		sensor.Comment = *conf.Comment
	}

	var defsensor *share.CLUSWafSensor
	defsensor = clusHelper.GetWafSensor(share.CLUSWafDefaultSensor)

	/*
	 * create default waf sensor.
	 */
	if defsensor == nil {
		createDefaultWafSensor()
		defsensor = clusHelper.GetWafSensor(share.CLUSWafDefaultSensor)
		if defsensor == nil {
			e := "sensor cannot be created in cluster!"
			log.WithFields(log.Fields{"sensor": sensor.Name}).Error(e)
			restRespErrorMessage(w, http.StatusNotFound, api.RESTErrObjectNotFound, e)
			return fmt.Errorf("%s", e)
		}
		log.Debug("Creating default waf sensor!")
	}

	if defsensor.RuleList == nil {
		defsensor.RuleList = make(map[string]*share.CLUSWafRule)
	}
	if defsensor.PreRuleList == nil {
		defsensor.PreRuleList = make(map[string][]*share.CLUSWafRule)
	}

	for _, rdr := range *conf.Rules {
		rdr.Name = common.GetInternalWafRuleName(rdr.Name, sensor.Name)
		cdr := share.CLUSWafRule{
			Name:    rdr.Name,
			CfgType: cfgType,
		}
		for _, rpt := range rdr.Patterns {
			cdr.Patterns = append(cdr.Patterns, share.CLUSWafCriteriaEntry{
				Key:     rpt.Key,
				Value:   rpt.Value,
				Op:      rpt.Op,
				Context: rpt.Context,
			})
		}
		cdr.ID = common.GetWafRuleID(defsensor)
		if cdr.ID == 0 {
			e := "Waf rule id overflow!"
			log.WithFields(log.Fields{"ID": cdr.ID}).Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
			return fmt.Errorf("%s", e)
		}

		//save full rule with pattern in default sensor
		defsensor.RuleList[cdr.Name] = &cdr

		//new sensor use this rule, only save name
		sensor.RuleListNames[rdr.Name] = rdr.Name
	}
	//save full rule with pattern in default sensor
	clusHelper.PutWafSensor(defsensor, false)

	//create new sensor
	clusHelper.PutWafSensor(sensor, true)

	return nil
}

func handlerWafSensorCreate(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	// Read request
	body, _ := io.ReadAll(r.Body)
	var rconf api.RESTWafSensorConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		log.WithFields(log.Fields{"error": err, "rconf": rconf}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	conf := rconf.Config

	//check user permission before creation
	if !acc.Authorize(&share.CLUSWafSensor{Name: conf.Name}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	if len(conf.Name) > api.DlpSensorNameMaxLen {
		e := fmt.Sprintf("Sensor name exceed max %d length!", api.DlpSensorNameMaxLen)
		log.WithFields(log.Fields{"name": conf.Name, "name_length": len(conf.Name)}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidName, e)
		return
	}

	if !isObjectNameValid(conf.Name) {
		e := "Invalid characters in name"
		log.WithFields(log.Fields{"name": conf.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidName, e)
		return
	}
	if conf.Name == share.CLUSWafDefaultSensor || strings.HasPrefix(conf.Name, api.FederalGroupPrefix) {
		e := "Cannot create sensor with reserved name"
		log.WithFields(log.Fields{"name": conf.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidName, e)
		return
	}

	if cached, err := cacher.DoesWafSensorExist(conf.Name, acc); cached {
		e := "waf sensor already exists"
		log.WithFields(log.Fields{"name": conf.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrDuplicateName, e)
		return
	} else if err == common.ErrObjectAccessDenied {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	if conf.Comment != nil {
		if len(*conf.Comment) > api.DlpRuleCommentMaxLen {
			e := fmt.Sprintf("Comment exceed max %d characters!", api.DlpRuleCommentMaxLen)
			log.WithFields(log.Fields{"name": conf.Name, "comment_length": len(*conf.Comment)}).Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
			return
		}
	}
	if conf.RuleChgList != nil || conf.RuleDelList != nil {
		e := "Cannot change or delete rules when creating sensor"
		log.WithFields(log.Fields{"name": conf.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}
	if conf.Rules == nil {
		rules := make([]api.RESTWafRule, 0)
		conf.Rules = &rules
	}
	if err := validateWafRuleConfig(*conf.Rules); err != nil {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
		return
	}

	if lock, err := lockClusKey(w, share.CLUSLockPolicyKey); err == nil {
		defer clusHelper.ReleaseLock(lock)

		if err := createWafSensor(w, conf, share.UserCreated); err == nil {
			restRespSuccess(w, r, nil, acc, login, &rconf, "Create waf sensor")
		}
	}
}

func updateWafSensor(w http.ResponseWriter, conf *api.RESTWafSensorConfig, reviewType share.TReviewType, sensor *share.CLUSWafSensor) error {
	var cfgType share.TCfgType = share.UserCreated
	if reviewType != share.ReviewTypeCRD && sensor.CfgType == share.GroundCfg {
		restRespError(w, http.StatusBadRequest, api.RESTErrOpNotAllowed)
		return fmt.Errorf("%s", restErrMessage[api.RESTErrOpNotAllowed])
	} else if reviewType == share.ReviewTypeCRD {
		cfgType = share.GroundCfg
	}

	modified := false
	defsensor := clusHelper.GetWafSensor(share.CLUSWafDefaultSensor)
	if defsensor.RuleList == nil {
		defsensor.RuleList = make(map[string]*share.CLUSWafRule)
	}
	if defsensor.PreRuleList == nil {
		defsensor.PreRuleList = make(map[string][]*share.CLUSWafRule)
	}
	if conf.Rules != nil {
		if len(sensor.RuleListNames) != len(*conf.Rules) || (conf.Comment != nil && sensor.Comment != *conf.Comment) || sensor.CfgType != cfgType {
			modified = true
		} else {
			// iterate thru rules to see whether we need to update the sensor
		COMPARE_RULES:
			for _, ruleConf := range *conf.Rules {
				if rule, ok := defsensor.RuleList[ruleConf.Name]; ok {
					if len(ruleConf.Patterns) != len(rule.Patterns) {
						modified = true
						break
					} else {
						for idx, ptnConf := range ruleConf.Patterns {
							ptn := rule.Patterns[idx]
							if ptn.Key != ptnConf.Key || ptn.Value != ptnConf.Value || ptn.Op != ptnConf.Op || ptn.Context != ptnConf.Context {
								modified = true
								break COMPARE_RULES
							}
						}
					}
				} else {
					modified = true
					break
				}
			}
		}
	} else {
		modified = true
	}
	if !modified {
		return nil
	}

	if conf.Comment != nil {
		sensor.Comment = *conf.Comment
	}

	if sensor.RuleListNames == nil {
		sensor.RuleListNames = make(map[string]string)
	}

	if conf.Rules != nil { //used by GUI
		var newRuleListNames map[string]string = make(map[string]string)
		var delRuleListNames map[string]string = make(map[string]string)

		//newly created list
		for _, rdr := range *conf.Rules {
			rdr.Name = common.GetInternalWafRuleName(rdr.Name, sensor.Name)
			newRuleListNames[rdr.Name] = rdr.Name
		}

		//list need to be deleted
		for _, rn := range sensor.RuleListNames { //old
			if _, ok := newRuleListNames[rn]; !ok { //not in new
				delRuleListNames[rn] = rn
			}
		}

		for _, rn := range delRuleListNames {
			_, foundInAll := defsensor.RuleList[rn]

			if foundInAll {
				delete(defsensor.RuleList, rn)
			}
			delete(sensor.RuleListNames, rn)
		}

		if sensor.RuleListNames == nil {
			sensor.RuleListNames = make(map[string]string)
		}

		for _, rdr := range *conf.Rules {
			rdr.Name = common.GetInternalWafRuleName(rdr.Name, sensor.Name)
			//used by this sensor
			_, foundInLocal := sensor.RuleListNames[rdr.Name]
			//created rule
			tcdr, foundInAll := defsensor.RuleList[rdr.Name]
			cdr := share.CLUSWafRule{
				Name:    rdr.Name,
				CfgType: cfgType,
			}
			for _, rpt := range rdr.Patterns {
				cdr.Patterns = append(cdr.Patterns, share.CLUSWafCriteriaEntry{
					Key:     rpt.Key,
					Value:   rpt.Value,
					Op:      rpt.Op,
					Context: rpt.Context,
				})
			}
			if foundInLocal && foundInAll {
				cdr.ID = tcdr.ID
			} else {
				cdr.ID = common.GetWafRuleID(defsensor)
				if cdr.ID == 0 {
					e := "Waf rule id overflow!"
					log.WithFields(log.Fields{"ID": cdr.ID}).Error(e)
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
					return fmt.Errorf("%s", e)
				}
			}
			//save full rule with pattern in default sensor
			defsensor.RuleList[cdr.Name] = &cdr
			//sensor use this rule, only save name
			sensor.RuleListNames[rdr.Name] = rdr.Name
		}
	} else { //used by CLI
		if conf.RuleDelList != nil {
			log.Debug("delete waf rule list used by sensor!")
			for _, rdr := range *conf.RuleDelList {
				origname := rdr.Name
				rdr.Name = common.GetInternalWafRuleName(rdr.Name, sensor.Name)
				//used by this sensor
				_, foundInLocal := sensor.RuleListNames[rdr.Name]
				//user created rule
				_, foundInAll := defsensor.RuleList[rdr.Name]

				if foundInLocal && foundInAll {
					delete(sensor.RuleListNames, rdr.Name)
					delete(defsensor.RuleList, rdr.Name)
				} else {
					//for upgrade, check rule name without WAFRuleTag
					//used by this sensor
					_, foundInLocal = sensor.RuleListNames[origname]
					//user created rule
					_, foundInAll = defsensor.RuleList[origname]
					if foundInLocal && foundInAll {
						delete(sensor.RuleListNames, origname)
						delete(defsensor.RuleList, origname)
					}
					if !foundInLocal {
						e := "Cannot find waf rule in this sensor!"
						log.WithFields(log.Fields{"sensor": conf.Name, "rulename": rdr.Name}).Error(e)
						restRespErrorMessage(w, http.StatusNotFound, api.RESTErrObjectNotFound, e)
						return fmt.Errorf("%s", e)
					}
					if !foundInAll {
						e := "Cannot find full waf rule to delete!"
						log.WithFields(log.Fields{"sensor": defsensor.Name, "rulename": rdr.Name}).Error(e)
						restRespErrorMessage(w, http.StatusNotFound, api.RESTErrObjectNotFound, e)
						return fmt.Errorf("%s", e)
					}
				}
			}
		}

		if conf.RuleChgList != nil {
			log.Debug("modify waf rule list used by sensor!")
			for _, rdr := range *conf.RuleChgList {
				origname := rdr.Name
				rdr.Name = common.GetInternalWafRuleName(rdr.Name, sensor.Name)
				//used by this sensor
				_, foundInLocal := sensor.RuleListNames[rdr.Name]
				//user created rule
				tcdr, foundInAll := defsensor.RuleList[rdr.Name]
				cdr := share.CLUSWafRule{
					Name:    rdr.Name,
					CfgType: cfgType,
				}
				for _, rpt := range rdr.Patterns {
					cdr.Patterns = append(cdr.Patterns, share.CLUSWafCriteriaEntry{
						Key:     rpt.Key,
						Value:   rpt.Value,
						Op:      rpt.Op,
						Context: rpt.Context,
					})
				}
				if foundInLocal && foundInAll {
					cdr.ID = tcdr.ID
				} else {
					//for upgrade, check rule name without WAFRuleTag
					//used by this sensor
					_, foundInLocal = sensor.RuleListNames[origname]
					//user created rule
					_, foundInAll = defsensor.RuleList[origname]
					if foundInLocal && foundInAll {
						delete(sensor.RuleListNames, origname)
						delete(defsensor.RuleList, origname)
					}
					cdr.ID = common.GetWafRuleID(defsensor)
					if cdr.ID == 0 {
						e := "Waf rule id overflow!"
						log.WithFields(log.Fields{"ID": cdr.ID}).Error(e)
						restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
						return fmt.Errorf("%s", e)
					}
				}
				//save full rule with pattern in default sensor
				defsensor.RuleList[cdr.Name] = &cdr
				//sensor use this rule, only save name
				sensor.RuleListNames[rdr.Name] = rdr.Name
			}
		}
	}
	sensor.CfgType = cfgType

	txn := cluster.Transact()
	defer txn.Close()

	clusHelper.PutWafSensorTxn(txn, defsensor)
	clusHelper.PutWafSensorTxn(txn, sensor)
	txn.Apply()

	return nil
}

func handlerWafSensorConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	name := ps.ByName("name")

	// Read request
	body, _ := io.ReadAll(r.Body)
	var rconf api.RESTWafSensorConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		log.WithFields(log.Fields{"error": err, "rconf": rconf}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	conf := rconf.Config

	if conf.Name != name {
		e := "Name mismatch"
		log.WithFields(log.Fields{"name": conf.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}

	if !acc.Authorize(&share.CLUSWafSensor{Name: name}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	if conf.Name == share.CLUSWafDefaultSensor {
		e := "Cannot edit sensor with reserved name"
		log.WithFields(log.Fields{"name": conf.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidName, e)
		return
	}

	if conf.Comment != nil {
		if len(*conf.Comment) > api.DlpRuleCommentMaxLen {
			e := fmt.Sprintf("Comment exceed max %d characters!", api.DlpRuleCommentMaxLen)
			log.WithFields(log.Fields{"name": conf.Name, "comment_length": len(*conf.Comment)}).Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
			return
		}
	}

	if conf.Rules != nil {
		if err := validateWafRuleConfig(*conf.Rules); err != nil {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
			return
		}
	}

	if conf.RuleChgList != nil {
		if err := validateWafRuleConfig(*conf.RuleChgList); err != nil {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
			return
		}
	}

	if lock, err := lockClusKey(w, share.CLUSLockPolicyKey); err == nil {
		defer clusHelper.ReleaseLock(lock)

		if sensor := clusHelper.GetWafSensor(name); sensor == nil {
			e := "waf sensor doesn't exist"
			log.WithFields(log.Fields{"name": name}).Error(e)
			restRespErrorMessage(w, http.StatusNotFound, api.RESTErrObjectNotFound, e)
			return
		} else {
			if err := updateWafSensor(w, conf, 0, sensor); err == nil {
				restRespSuccess(w, r, nil, acc, login, &rconf, "Configure waf sensor")
			}
		}
	}
}

func processGroupSensors(w http.ResponseWriter, cg *share.CLUSWafGroup, sensors []api.RESTWafConfig) error {
	for _, rs := range sensors {
		if rs.Name == share.CLUSWafDefaultSensor {
			e := "Cannot use default sensor in waf group!"
			log.WithFields(log.Fields{"name": rs.Name}).Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
			return fmt.Errorf("%s", e)
		}
		if rs.Action != share.DlpRuleActionAllow && rs.Action != share.DlpRuleActionDrop {
			e := "Action is not supported!"
			log.WithFields(log.Fields{"sensor": rs}).Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
			return fmt.Errorf("%s", e)
		}
		if cs := clusHelper.GetWafSensor(rs.Name); cs == nil {
			e := "Waf sensor does not exist"
			log.WithFields(log.Fields{"sensor": rs}).Warn(e)
		}
		cs := share.CLUSWafSetting{Name: rs.Name, Action: rs.Action}
		if ret, ok := common.MergeWafSensors(cg.Sensors, &cs); ok {
			cg.Sensors = ret
		}
	}

	return nil
}

func handlerWafGroupConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	name := ps.ByName("name")

	// Read request
	body, _ := io.ReadAll(r.Body)
	var rconf api.RESTWafGroupConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		log.WithFields(log.Fields{"error": err, "rconf": rconf}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	conf := rconf.Config

	if conf.Name != name {
		e := "Name mismatch"
		log.WithFields(log.Fields{"name": conf.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}
	if cached, err := cacher.GetWafGroup(conf.Name, acc); cached == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	} else {
		if g, _ := cacher.GetGroupCache(conf.Name, acc); g != nil && g.CfgType == share.GroundCfg {
			restRespError(w, http.StatusBadRequest, api.RESTErrOpNotAllowed)
			return
		}
	}

	var lock cluster.LockInterface
	if lock, err = lockClusKey(w, share.CLUSLockPolicyKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	// Read from cluster
	cg := clusHelper.GetWafGroup(name)
	if cg == nil {
		e := "Waf group doesn't exist"
		log.WithFields(log.Fields{"name": name}).Error(e)
		restRespErrorMessage(w, http.StatusNotFound, api.RESTErrObjectNotFound, e)
		return
	}

	// Apply waf changes
	if conf.Status != nil {
		cg.Status = *conf.Status
	}

	if conf.RepSensors != nil { //used by GUI
		//delete existing sensor list used by waf group
		cg.Sensors = make([]*share.CLUSWafSetting, 0)

		//add replace sensor list to the waf group
		if len(*conf.RepSensors) > 0 {
			if err := processGroupSensors(w, cg, *conf.RepSensors); err != nil {
				return
			}
		}
	} else { //used by CLI
		if conf.DelSensors != nil {
			if cg.Sensors == nil {
				cg.Sensors = make([]*share.CLUSWafSetting, 0)
			}
			if len(*conf.DelSensors) > 0 && len(cg.Sensors) > 0 {
				for _, rs := range *conf.DelSensors {
					cs := &share.CLUSWafSetting{Name: rs, Action: share.DlpRuleActionDrop}
					idx, found := common.FindSensorInWafGroup(cg.Sensors, cs)
					if found {
						cg.Sensors[idx] = nil
					} else {
						e := "Cannot find sensor to delete!"
						log.WithFields(log.Fields{"sensor": rs}).Error(e)
						//restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrObjectNotFound, e)
					}
				}

				list := make([]*share.CLUSWafSetting, 0)
				for _, cs := range cg.Sensors {
					if cs != nil {
						list = append(list, cs)
					}
				}
				cg.Sensors = list
			}
		}

		if conf.Sensors != nil {
			if cg.Sensors == nil || len(*conf.Sensors) == 0 {
				cg.Sensors = make([]*share.CLUSWafSetting, 0)
			}
			if len(*conf.Sensors) > 0 {
				if err := processGroupSensors(w, cg, *conf.Sensors); err != nil {
					return
				}
			}
		}
	}

	// Write waf group definition into key-value store
	if err := clusHelper.PutWafGroup(cg, false); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}
	restRespSuccess(w, r, nil, acc, login, &rconf, "Configure waf group")
}

func deleteWafSensor(w http.ResponseWriter, name string, reviewType share.TReviewType, lockOwned bool,
	acc *access.AccessControl, login *loginSession) error {

	rwafsensor, err := cacher.GetWafSensor(name, acc)
	if rwafsensor == nil {
		log.WithFields(log.Fields{"name": name}).Error("Fail to get sensor from cache!")
		restRespNotFoundLogAccessDenied(w, login, err)
		return err
	} else if reviewType != share.ReviewTypeCRD && rwafsensor.CfgType == api.CfgTypeGround {
		restRespError(w, http.StatusBadRequest, api.RESTErrOpNotAllowed)
		return fmt.Errorf("%s", restErrMessage[api.RESTErrOpNotAllowed])
	}

	if name == share.CLUSWafDefaultSensor {
		e := "Cannot delete default sensor!"
		log.WithFields(log.Fields{"name": name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return fmt.Errorf("%s", e)
	}

	var lock cluster.LockInterface
	if !lockOwned {
		if lock, err = lockClusKey(w, share.CLUSLockPolicyKey); err != nil {
			return err
		}
		defer clusHelper.ReleaseLock(lock)
	}

	wafsensor := clusHelper.GetWafSensor(name)
	if wafsensor == nil {
		log.WithFields(log.Fields{"name": name}).Error("Fail to get waf sensor!")
		restRespError(w, http.StatusBadRequest, api.RESTErrObjectNotFound)
		return fmt.Errorf("%s", restErrMessage[api.RESTErrObjectNotFound])
	}
	defsensor := clusHelper.GetWafSensor(share.CLUSWafDefaultSensor)

	txn := cluster.Transact()
	defer txn.Close()

	if defsensor.RuleList == nil {
		defsensor.RuleList = make(map[string]*share.CLUSWafRule)
	}
	if defsensor.PreRuleList == nil {
		defsensor.PreRuleList = make(map[string][]*share.CLUSWafRule)
	}
	for _, rn := range wafsensor.RuleListNames {
		delete(defsensor.RuleList, rn)
	}
	clusHelper.PutWafSensorTxn(txn, defsensor)
	clusHelper.DeleteWafSensorTxn(txn, name)

	txn.Apply()

	return nil
}

func handlerWafSensorDelete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	name := ps.ByName("name")

	if err := deleteWafSensor(w, name, 0, false, acc, login); err == nil {
		restRespSuccess(w, r, nil, acc, login, nil, "Delete waf sensor")
	}
}

func handlerWafExport(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	// allow export no matter it's k8s env or not
	acc, login := getAccessControl(w, r, access.AccessOPRead)
	if acc == nil {
		return
	}

	if !acc.Authorize(&share.CLUSWafSensor{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	var rconf api.RESTWafSensorExport
	body, _ := io.ReadAll(r.Body)
	err := json.Unmarshal(body, &rconf)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	apiVersion := resource.NvSecurityRuleVersion
	resp := resource.NvWafSecurityRuleList{
		TypeMeta: metav1.TypeMeta{
			Kind:       resource.NvListKind,
			APIVersion: apiVersion,
		},
		Items: make([]resource.NvWafSecurityRule, 0, len(rconf.Names)),
	}

	// export waf sensors
	var lock cluster.LockInterface
	if lock, err = lockClusKey(w, share.CLUSLockPolicyKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	apiversion := fmt.Sprintf("%s/%s", common.OEMClusterSecurityRuleGroup, resource.NvWafSecurityRuleVersion)
	defSensor := clusHelper.GetWafSensor(share.CLUSWafDefaultSensor)
	// export selected waf sensors
	for _, name := range rconf.Names {
		sensor := clusHelper.GetWafSensor(name)
		if sensor == nil {
			e := "waf sensor doesn't exist"
			log.WithFields(log.Fields{"name": name}).Error(e)
			restRespErrorMessage(w, http.StatusNotFound, api.RESTErrObjectNotFound, e)
			return
		}
		if sensor.Predefine {
			continue
		}

		ruleList := make([]*resource.NvSecurityWafRule, 0, len(sensor.RuleListNames))
		for rName := range sensor.RuleListNames {
			if r, ok := defSensor.RuleList[rName]; ok {
				patterns := make([]api.RESTWafCriteriaEntry, len(r.Patterns))
				for idx, p := range r.Patterns {
					patterns[idx] = api.RESTWafCriteriaEntry{
						Key:     p.Key,
						Value:   p.Value,
						Op:      p.Op,
						Context: p.Context,
					}
				}
				if ss := strings.Split(rName, common.WAFRuleTag); len(ss) > 1 {
					r.Name = ss[1] // use simple name for exported sensor's rules
					rule := &resource.NvSecurityWafRule{
						Name:     &r.Name,
						Patterns: patterns,
					}
					ruleList = append(ruleList, rule)
				}
			}
		}
		kind := resource.NvWafSecurityRuleKind
		resptmp := resource.NvWafSecurityRule{
			TypeMeta: metav1.TypeMeta{
				Kind:       kind,
				APIVersion: apiversion,
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: sensor.Name,
			},
			Spec: resource.NvSecurityWafSpec{
				Sensor: &resource.NvSecurityWafSensor{
					Name:     sensor.Name,
					RuleList: ruleList,
					Comment:  &sensor.Comment,
				},
			},
		}
		resp.Items = append(resp.Items, resptmp)
	}

	doExport("cfgWafExport.yaml", "WAF sensors", rconf.RemoteExportOptions, resp, w, r, acc, login)
}

func handlerWafImport(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	if !acc.Authorize(&share.CLUSWafSensor{Name: share.CLUSWafDefaultSensor}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	tid := r.Header.Get("X-Transaction-ID")
	_importHandler(w, r, tid, share.IMPORT_TYPE_WAF, share.PREFIX_IMPORT_WAF, acc, login)
}

// if there are multiple yaml documents(separated by "---" line) in the yaml file, only the first document is parsed for import
func importWaf(scope string, loginDomainRoles access.DomainRole, importTask share.CLUSImportTask, postImportOp kv.PostImportFunc) error {
	log.Debug()
	defer os.Remove(importTask.TempFilename)

	json_data, _ := os.ReadFile(importTask.TempFilename)
	var secRuleList resource.NvWafSecurityRuleList
	var secRule resource.NvWafSecurityRule
	var secRules []resource.NvWafSecurityRule
	var invalidCrdKind bool
	var err error
	if err = json.Unmarshal(json_data, &secRuleList); err != nil || len(secRuleList.Items) == 0 {
		if err = json.Unmarshal(json_data, &secRule); err == nil {
			secRules = append(secRules, secRule)
		}
	} else {
		secRules = secRuleList.Items
	}
	for _, r := range secRules {
		if r.APIVersion != "neuvector.com/v1" || r.Kind != resource.NvWafSecurityRuleKind {
			invalidCrdKind = true
			break
		}
	}
	if invalidCrdKind || len(secRules) == 0 {
		msg := "Invalid security rule(s)"
		log.WithFields(log.Fields{"error": err}).Error(msg)
		postImportOp(fmt.Errorf("%s", msg), importTask, loginDomainRoles, "", share.IMPORT_TYPE_WAF)
		return nil
	}

	var inc float32
	var progress float32 // progress percentage

	inc = 90.0 / float32(2+len(secRules))
	parsedWafCfgs := make([]*resource.NvSecurityParse, 0, len(secRules))
	progress = 6

	importTask.Percentage = int(progress)
	importTask.Status = share.IMPORT_RUNNING
	clusHelper.PutImportTask(&importTask)

	var crdHandler nvCrdHandler
	crdHandler.Init(share.CLUSLockPolicyKey)
	if crdHandler.AcquireLock(clusterLockWait) {
		defer crdHandler.ReleaseLock()

		// [1]: parse all security rules in the yaml file
		for _, secRule := range secRules {
			parsedCfg, errCount, errMsg, _ := crdHandler.parseCurCrdWafContent(&secRule, share.ReviewTypeImportWAF, share.ReviewTypeDisplayWAF)
			if errCount > 0 {
				err = fmt.Errorf("%s", errMsg)
				break
			} else {
				parsedWafCfgs = append(parsedWafCfgs, parsedCfg)
			}
		}

		if err == nil {
			progress += inc
			importTask.Percentage = int(progress)
			clusHelper.PutImportTask(&importTask)

			// [2]: import a waf sensor in the yaml file
			for _, parsedCfg := range parsedWafCfgs {
				if parsedCfg.WafSensorCfg != nil {
					var cacheRecord share.CLUSCrdSecurityRule
					// [2] import WAF sensor defined in the yaml file
					if err = crdHandler.crdHandleWafSensor(scope, parsedCfg.WafSensorCfg, &cacheRecord, share.ReviewTypeImportWAF); err != nil {
						importTask.Status = err.Error()
						break
					}
					progress += inc
					importTask.Percentage = int(progress)
					clusHelper.PutImportTask(&importTask)
				}
			}
			importTask.Percentage = 90
			clusHelper.PutImportTask(&importTask)
		}
	}

	postImportOp(err, importTask, loginDomainRoles, "", share.IMPORT_TYPE_WAF)

	return nil
}

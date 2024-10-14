package rest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/rpc"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

var fileAccessOptionList []string = []string{
	share.FileAccessBehaviorBlock,
	share.FileAccessBehaviorMonitor,
}
var fileAccessOptionSet utils.Set = utils.NewSetFromSliceKind(fileAccessOptionList)

// only support simple wildcard
// 1. /dir/xxx
// 2. /dir/xxx.*
// 3. /dir/*.xxx
// 4. /dir/*/abc/*
// not support [] () regexp
func parseFileFilter(filter string) (string, string, bool) {
	if strings.HasSuffix(filter, "/") {
		filter += "*"
	}
	var base string
	var regxStr string
	filter = filepath.Clean(filter)
	if strings.ContainsAny(filter, "[]()<>") ||
		strings.Contains(filter, "..") ||
		strings.Contains(filter, "/./") {
		return "", "", false
	}
	filter = strings.Replace(filter, ".", "\\.", -1)
	filter = strings.Replace(filter, "*", ".*", -1)
	if a := strings.LastIndex(filter, "/"); a >= 0 {
		base = filter[:a]
		regxStr = filter[a+1:]
	} else {
		return "", "", false
	}
	if regxStr == "" {
		return "", "", false
	} else if !strings.Contains(regxStr, "*") {
		// single file
		base += "/" + regxStr
		regxStr = ""
	}
	if _, err := regexp.Compile(base); err != nil {
		return "", "", false
	}
	if _, err := regexp.Compile(regxStr); err != nil {
		return "", "", false
	}
	return base, regxStr, true
}

// caller has been verified for federal admin access right, no CRD rules
func replaceFedFileMonitorProfiles(profiles []*share.CLUSFileMonitorProfile, accessRules []*share.CLUSFileAccessRule) bool {
	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to acquire cluster lock")
		return false
	}
	defer clusHelper.ReleaseLock(lock)

	txn := cluster.Transact()
	defer txn.Close()

	existing := clusHelper.GetAllFileMonitorProfileSubKeys(share.ScopeFed)
	for _, profile := range profiles {
		var fmp *share.CLUSFileMonitorProfile
		if existing.Contains(profile.Group) { // found in latest & existing
			fmp, _ = clusHelper.GetFileMonitorProfile(profile.Group)
		}
		if fmp == nil || !reflect.DeepEqual(profile, fmp) { // not found in existing or it's different/modified
			clusHelper.PutFileMonitorProfileTxn(txn, profile.Group, profile)
		}
		if existing.Contains(profile.Group) {
			existing.Remove(profile.Group)
		}
	}
	// delete obsolete file monitor profile keys
	for name := range existing.Iter() {
		clusHelper.DeleteFileMonitorTxn(txn, name.(string))
	}

	existing = clusHelper.GetAllFileAccessRuleSubKeys(share.ScopeFed)
	for _, accessRule := range accessRules {
		var far *share.CLUSFileAccessRule
		if existing.Contains(accessRule.Group) { // found in latest & existing
			far, _ = clusHelper.GetFileAccessRule(accessRule.Group)
		}
		if far == nil || !reflect.DeepEqual(accessRule, far) { // not found in existing or it's different/modified
			clusHelper.PutFileAccessRuleTxn(txn, accessRule.Group, accessRule)
		}
		if existing.Contains(accessRule.Group) {
			existing.Remove(accessRule.Group)
		}
	}
	// delete obsolete file access rule keys
	for name := range existing.Iter() {
		clusHelper.DeleteFileAccessRuleTxn(txn, name.(string))
	}

	if ok, err := txn.Apply(); err != nil || !ok {
		log.WithFields(log.Fields{"ok": ok, "error": err}).Error("Atomic write to the cluster failed")
	}

	return true
}

func handlerFileMonitorConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	group := ps.ByName("name")

	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTFileMonitorConfigData
	err := json.Unmarshal(body, &rconf)
	config := rconf.Config
	if err != nil || config == nil ||
		(config.AddFilters == nil && config.DelFilters == nil && config.UpdateFilters == nil) {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	if !cacher.AuthorizeFileMonitorProfile(group, acc) {
		restRespAccessDenied(w, login)
		return
	}

	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Acquire lock error")
		return
	}
	defer clusHelper.ReleaseLock(lock)

	// Check if we can config the profile. Only need authorize group
	grp, err := cacher.GetGroupBrief(group, false, acc)
	if err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	if grp.Kind != share.GroupKindContainer {
		// "nodes" : share.GroupKindNode
		log.WithFields(log.Fields{"group": group, "kind": grp.Kind}).Error("Get profile failed!")
		restRespError(w, http.StatusBadRequest, api.RESTErrObjectNotFound)
		return
	}

	var profChanged bool
	profConf, profRev := clusHelper.GetFileMonitorProfile(group)
	ruleConf, ruleRev := clusHelper.GetFileAccessRule(group)

	tm := time.Now().UTC()
	// delete filters
	if config.DelFilters != nil {
		for _, filter := range config.DelFilters {
			for i, cfilter := range profConf.Filters {
				//	if !cfilter.CustomerAdd {
				//		continue
				//	}
				if cfilter.Filter == filter.Filter {
					profConf.Filters = append(profConf.Filters[:i], profConf.Filters[i+1:]...)
					// delete the rule
					idx := utils.FilterIndexKey(cfilter.Path, cfilter.Regex)
					if _, ok := ruleConf.Filters[idx]; ok {
						delete(ruleConf.Filters, idx)
					} else {
						log.WithFields(log.Fields{"filter": filter.Filter, "group": group}).Error("invalid rule entry")
						restRespError(w, http.StatusBadRequest, api.RESTErrObjectNotFound)
						return
					}
					profChanged = true
					break
				}
			}
		}
	}
	// validate add
	if config.AddFilters != nil {
		for _, filter := range config.AddFilters {
			path := filter.Filter
			filter.Filter = filepath.Clean(filter.Filter)
			if filter.Filter == "." || filter.Filter == "/" {
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest,
					fmt.Sprintf("Unsupported filter: %s[%s]", path, filter.Filter))
				return
			}

			// append the "/" back
			if path[len(path)-1:] == "/" {
				filter.Filter += "/"
			}

			base, regex, ok := parseFileFilter(filter.Filter)
			if !ok {
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest,
					fmt.Sprintf("Unsupported filter: %s", filter.Filter))
				return
			}

			for i, cfilter := range profConf.Filters {
				if cfilter.Filter == filter.Filter {
					// conflict, delete predefined
					if !cfilter.CustomerAdd {
						profConf.Filters = append(profConf.Filters[:i], profConf.Filters[i+1:]...)
						// replace the rule below
						idx := utils.FilterIndexKey(cfilter.Path, cfilter.Regex)
						delete(ruleConf.Filters, idx)
						break
					} else {
						restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest,
							fmt.Sprintf("duplicate filter: %s", filter.Filter))
						return
					}
				}
			}
			flt := share.CLUSFileMonitorFilter{
				Filter:      filter.Filter,
				Path:        base,
				Regex:       regex,
				Recursive:   filter.Recursive,
				CustomerAdd: true,
			}
			if fileAccessOptionSet.Contains(filter.Behavior) {
				flt.Behavior = filter.Behavior
			} else {
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Invalid File access option")
				return
			}

			profConf.Filters = append(profConf.Filters, flt)
			// add rule
			idx := utils.FilterIndexKey(flt.Path, flt.Regex)
			capps := make([]string, len(filter.Apps))
			copy(capps, filter.Apps)
			frule := &share.CLUSFileAccessFilterRule{
				Apps:        capps,
				CreatedAt:   tm,
				UpdatedAt:   tm,
				Behavior:    flt.Behavior,
				CustomerAdd: true,
			}
			ruleConf.Filters[idx] = frule
			profChanged = true
		}
	}

	// update filter's items, filter not change
	if config.UpdateFilters != nil {
		for _, filter := range config.UpdateFilters {
			for i, cfilter := range profConf.Filters {
				if !cfilter.CustomerAdd {
					continue
				}
				if cfilter.Filter == filter.Filter {
					// update the rule
					idx := utils.FilterIndexKey(cfilter.Path, cfilter.Regex)
					capps := make([]string, len(filter.Apps))
					copy(capps, filter.Apps)

					frule := &share.CLUSFileAccessFilterRule{
						Apps:        capps,
						CreatedAt:   tm,
						UpdatedAt:   tm,
						CustomerAdd: true,
					}

					if fileAccessOptionSet.Contains(filter.Behavior) {
						frule.Behavior = filter.Behavior
					} else {
						restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Invalid File access option")
						return
					}

					ruleConf.Filters[idx] = frule
					if filter.Recursive != cfilter.Recursive {
						profChanged = true
						profConf.Filters[i].Recursive = filter.Recursive
					}
					if profConf.Filters[i].Behavior != frule.Behavior {
						profChanged = true
						profConf.Filters[i].Behavior = frule.Behavior
					}
					break
				}
			}
		}
	}

	if profChanged {
		// Write to cluster
		if err := clusHelper.PutFileMonitorProfile(group, profConf, profRev); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Write cluster fail")
			restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
			return
		}
	}
	// Write access rule
	if err := clusHelper.PutFileAccessRule(group, ruleConf, ruleRev); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Write cluster fail")
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}

	if profConf.CfgType == share.FederalCfg {
		updateFedRulesRevision([]string{share.FedFileMonitorProfilesType}, acc, login)
	}

	restRespSuccess(w, r, nil, acc, login, &rconf, "Configure file monitor profile")
}

func handlerFileMonitorList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	var predefined bool
	query := restParseQuery(r)
	scope := query.pairs[api.QueryScope] // empty string means fed & local file mointor list

	for key := range r.URL.Query() {
		if strings.Contains(key, api.FilterByPredefined) {
			predefined = true
			break
		}
	}
	profiles := cacher.GetAllFileMonitorProfile(scope, acc, predefined)
	for _, profile := range profiles {
		if len(profile.Filters) > 1 {
			sort.Slice(profile.Filters, func(i, j int) bool {
				return profile.Filters[i].Filter < profile.Filters[j].Filter && profile.Filters[i].CfgType < profile.Filters[j].CfgType
			})
		}
	}

	resp := api.RESTFileMonitorProfilesData{Profiles: profiles}

	log.WithFields(log.Fields{"entries": len(resp.Profiles)}).Debug()
	restRespSuccess(w, r, &resp, acc, login, nil, "Get file monitor profile list")
}

func handlerFileMonitorShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	var predefined bool
	name := ps.ByName("name")
	query := r.URL.Query()
	for key := range query {
		if strings.Contains(key, api.FilterByPredefined) {
			predefined = true
			break
		}
	}

	// Check if we can config the profile. Only need authorize group
	grp, err := cacher.GetGroupBrief(name, false, acc)
	if err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	if grp.Kind != share.GroupKindContainer {
		// "nodes" : share.GroupKindNode
		log.WithFields(log.Fields{"group": name, "kind": grp.Kind}).Error("Get profile failed!")
		restRespError(w, http.StatusBadRequest, api.RESTErrObjectNotFound)
		return
	}

	profile, err := cacher.GetFileMonitorProfile(name, acc, predefined)
	if profile == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	if len(profile.Filters) > 1 {
		sort.Slice(profile.Filters, func(i, j int) bool {
			return profile.Filters[i].Filter < profile.Filters[j].Filter && profile.Filters[i].CfgType < profile.Filters[j].CfgType
		})
	}
	resp := api.RESTFileMonitorProfileData{Profile: profile}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get file monitor profile")
}

func handlerFileMonitorFile(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !authDebugCaller(w, acc, login) {
		return
	}

	query := restParseQuery(r)

	agentID, wlID, err := getAgentWorkloadFromFilter(query.filters, acc)
	if err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	var csf share.CLUSFilter
	csf.Workload = wlID

	files, err := rpc.GetFileMonitorFile(agentID, &csf)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to make RPC call")
		restRespError(w, http.StatusInternalServerError, api.RESTErrClusterRPCError)
		return
	}

	mfile := make([]*api.RESTFileMonitorFile, len(files))
	for i, f := range files {
		file := &api.RESTFileMonitorFile{
			Path:    f.Path,
			Mask:    f.Mask,
			IsDir:   f.IsDir,
			Protect: f.Protect,
			Files:   f.Files,
		}
		mfile[i] = file
	}
	resp := api.RESTFileMonitorFileData{Files: mfile}

	log.WithFields(log.Fields{"entries": len(files)}).Debug()
	restRespSuccess(w, r, &resp, acc, login, nil, "Get file monitor files")
}

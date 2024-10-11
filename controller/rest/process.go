package rest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/ruleid"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

func isValidKindProcessProfile(kind string) bool {
	switch kind {
	case share.GroupKindContainer: // service or user-defined groups
	case share.GroupKindNode: // nodes
	default:
		return false
	}
	return true
}

// caller has been verified for federal admin access right
func replaceFedProcessProfiles(profiles []*share.CLUSProcessProfile) bool {
	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to acquire cluster lock")
		return false
	}
	defer clusHelper.ReleaseLock(lock)

	txn := cluster.Transact()
	defer txn.Close()

	existing := clusHelper.GetAllProcessProfileSubKeys(share.ScopeFed)
	for _, profile := range profiles {
		var pp *share.CLUSProcessProfile
		if existing.Contains(profile.Group) { // found in latest & existing
			pp = clusHelper.GetProcessProfile(profile.Group)
		}
		if pp == nil || !reflect.DeepEqual(profile, pp) {
			clusHelper.PutProcessProfileTxn(txn, profile.Group, profile)
		}
		if existing.Contains(profile.Group) {
			existing.Remove(profile.Group)
		}
	}
	// delete obsolete file access rule keys
	for name := range existing.Iter() {
		clusHelper.DeleteProcessProfileTxn(txn, name.(string))
	}

	if ok, err := txn.Apply(); err != nil || !ok {
		log.WithFields(log.Fields{"ok": ok, "error": err}).Error("Atomic write to the cluster failed")
	}

	return true
}

func handlerProcessProfileList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	query := restParseQuery(r)
	scope := query.pairs[api.QueryScope] // empty string means fed & local process profiles

	var resp api.RESTProcessProfilesData
	resp.Profiles = make([]*api.RESTProcessProfile, 0)

	allCached := cacher.GetAllProcessProfile(scope, acc)
	allSize := 0
	for _, cached := range allCached {
		allSize += len(cached)
	}
	// Filter
	if allSize <= query.start {
		restRespSuccess(w, r, &resp, acc, login, nil, "Get policy rule list")
		return
	}
	profiles := make([]*api.RESTProcessProfile, allSize)
	idx := 0

	// Sort
	for _, cached := range allCached {
		if len(cached) > 1 && len(query.sorts) > 0 {
			// Convert struct slice to interface slice
			var data []interface{} = make([]interface{}, len(cached))
			for i, d := range cached {
				data[i] = d
			}
			// Sort
			restNewSorter(data, query.sorts).Sort()
			for _, d := range data {
				profiles[idx] = d.(*api.RESTProcessProfile)
				idx++
			}
		} else {
			sort.Slice(cached, func(i, j int) bool { return cached[i].Group < cached[j].Group })
			for _, p := range cached {
				profiles[idx] = p
				idx++
			}
		}
	}

	if query.limit == 0 {
		resp.Profiles = profiles[query.start:]
	} else {
		var end int
		if query.start+query.limit > len(profiles) {
			end = len(profiles)
		} else {
			end = query.start + query.limit
		}
		resp.Profiles = profiles[query.start:end]
	}

	log.WithFields(log.Fields{"entries": len(resp.Profiles)}).Debug()
	restRespSuccess(w, r, &resp, acc, login, nil, "Get all process profile")
}

func handlerProcessProfileShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	group := ps.ByName("name")
	if grp, err := cacher.GetGroupBrief(group, false, acc); err == nil {
		if !isValidKindProcessProfile(grp.Kind) {
			log.WithFields(log.Fields{"group": group, "kind": grp.Kind}).Error("Get profile failed!")
			restRespError(w, http.StatusBadRequest, api.RESTErrObjectNotFound)
			return
		}
	} else {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	profile, err := cacher.GetProcessProfile(group, acc)
	if profile == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}
	resp := api.RESTProcessProfileData{Profile: profile}
	restRespSuccess(w, r, &resp, acc, login, nil, "Get process profile detail")
}

func validateProcessProfileConfig(list []api.RESTProcessProfileEntryConfig) error {
	for i, proc := range list {
		if proc.Action != share.PolicyActionAllow && proc.Action != share.PolicyActionDeny {
			log.WithFields(log.Fields{"proc": proc}).Error("Action not supported!")
			return fmt.Errorf("process %s: action is not supported", proc.Name)
		}

		// check valid name and path fields
		proc.Name = strings.TrimSpace(proc.Name)
		if proc.Name == "" {
			log.WithFields(log.Fields{"Path": proc.Path, "Name": proc.Name}).Error("PROC: illegal format")
			return fmt.Errorf("process %s: %s, name can not be empty or blank spaces", proc.Name, proc.Path)
		}

		// log.WithFields(log.Fields{"Path": proc.Path}).Error("PROC:")
		norm, ok := ValidProcessProfilePath(proc.Path)
		if ok {
			proc.Path = norm // replaced
		} else {
			log.WithFields(log.Fields{"Path": proc.Path, "Name": proc.Name}).Error("PROC: illegal format")
			return fmt.Errorf("process %s: %s, path is not supported", proc.Name, proc.Path)
		}

		// no such entry, name=* and path is empty
		if proc.Name == "*" && proc.Path == "" {
			log.WithFields(log.Fields{"Path": proc.Path, "Name": proc.Name}).Error("PROC: illegal format")
			return fmt.Errorf("process %s: %s, empty path is not supported", proc.Name, proc.Path)
		}

		// avoid deny all entries
		if proc.Name == "*" && (proc.Path == "*" || proc.Path == "/*") && proc.Action == share.PolicyActionDeny {
			log.WithFields(log.Fields{"Path": proc.Path, "Name": proc.Name}).Error("PROC: deny all")
			return fmt.Errorf("Invalid entry: deny all processes[ %s: %s]", proc.Name, proc.Path)
		}

		// update
		list[i].Name = proc.Name
		list[i].Path = proc.Path
	}
	return nil
}

func handlerProcessProfileConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	group := ps.ByName("name")

	// Read request
	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTProcessProfileConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		log.WithFields(log.Fields{"error": err, "rconf": rconf}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	conf := rconf.Config
	log.WithFields(log.Fields{"conf": conf}).Debug("")
	if conf.ProcessChgList != nil {
		if err := validateProcessProfileConfig(*conf.ProcessChgList); err != nil {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
			return
		}
	}

	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Acquire lock error")
		return
	}
	defer clusHelper.ReleaseLock(lock)

	// Check if we can config the profile. Only need authorize group
	if grp, err := cacher.GetGroupBrief(group, false, acc); err == nil {
		if !isValidKindProcessProfile(grp.Kind) {
			log.WithFields(log.Fields{"group": group, "kind": grp.Kind}).Error("Get profile failed!")
			restRespError(w, http.StatusBadRequest, api.RESTErrObjectNotFound)
			return
		}
	} else {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	profile := clusHelper.GetProcessProfile(group)
	if profile == nil {
		log.WithFields(log.Fields{"group": group}).Error("Get profile failed!")
		restRespError(w, http.StatusBadRequest, api.RESTErrObjectNotFound)
		return
	}

	// --
	if conf.HashEnable != nil {
		profile.HashEnable = *conf.HashEnable
		if !profile.HashEnable {
			for _, pp := range profile.Process {
				pp.Hash = nil
			}
		}
	}

	if conf.AlertDisable != nil {
		profile.AlertDisable = *conf.AlertDisable
	}

	if conf.Baseline != nil {
		if !utils.DoesGroupHavePolicyMode(group) {
			log.WithFields(log.Fields{"group": group, "baseline": *conf.Baseline}).Error("Invalid group")
			restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
			return
		}

		blValue := strings.ToLower(*conf.Baseline)
		if utils.IsGroupNodes(group) && blValue != share.ProfileBasic {
			// nodes is not change-able, always "share.ProfileBasic"
			log.WithFields(log.Fields{"group": group, "baseline": *conf.Baseline}).Error("Invalid profile baseline")
			restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
			return
		}

		switch blValue {
		case share.ProfileBasic:
			profile.Baseline = share.ProfileBasic
		case share.ProfileDefault_UNUSED, share.ProfileShield_UNUSED, share.ProfileZeroDrift:
			profile.Baseline = share.ProfileZeroDrift
		default:
			log.WithFields(log.Fields{"group": group, "baseline": *conf.Baseline}).Error("Invalid profile baseline")
			restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
			return
		}
	}

	// new/modified entry as UserCreated type
	var rule_cfg share.TCfgType = share.UserCreated
	if strings.HasPrefix(group, api.FederalGroupPrefix) {
		rule_cfg = share.FederalCfg
	}

	// commom path from UI
	// Handle delete first so that UI can do a replacement within one call
	// We handle replace by deleting first then add
	deleted := make(map[string]*share.CLUSProcessProfileEntry)
	if conf.ProcessDelList != nil {
		for _, proc := range *conf.ProcessDelList {
			p := &share.CLUSProcessProfileEntry{
				Name:    proc.Name,
				Path:    proc.Path,
				Action:  proc.Action,
				CfgType: rule_cfg,
			}

			idx, found := common.FindProcessInProfile(profile.Process, p)
			if found {
				key := proc.Name + ":" + proc.Path
				deleted[key] = profile.Process[idx]
			} else {
				log.WithFields(log.Fields{"group": group, "rule": p}).Error("Cannot find rule")
				restRespError(w, http.StatusBadRequest, api.RESTErrObjectNotFound)
				return
			}
		}

		list := make([]*share.CLUSProcessProfileEntry, 0)
		for _, p := range profile.Process {
			key := p.Name + ":" + p.Path
			if d, ok := deleted[key]; ok && (d.CfgType == p.CfgType) {
				// meet all comparing criteria
				continue
			}
			list = append(list, p)
		}
		profile.Process = list
	}

	// add (update : del then add)
	if conf.ProcessChgList != nil {
		for _, proc := range *conf.ProcessChgList {
			var created time.Time
			key := proc.Name + ":" + proc.Path
			if d, ok := deleted[key]; ok {
				log.WithFields(log.Fields{"rule": d}).Debug("precedent")
				created = d.CreatedAt
			}
			p := share.CLUSProcessProfileEntry{
				Name:            proc.Name,
				Path:            proc.Path,
				CfgType:         rule_cfg,
				Action:          proc.Action,
				Uuid:            ruleid.NewUuid(),
				CreatedAt:       created,
				AllowFileUpdate: proc.AllowFileUpdate,
			}
			if ret, ok := common.MergeProcess(profile.Process, &p, true); ok {
				profile.Process = ret
			}
		}
	}

	clusHelper.PutProcessProfile(group, profile)
	if profile.CfgType == share.FederalCfg {
		updateFedRulesRevision([]string{share.FedProcessProfilesType}, acc, login)
	}
	restRespSuccess(w, r, nil, acc, login, &rconf, "Configure process profile")
}

func ValidProcessProfilePath(path string) (string, bool) {
	// trim blank spaces at front and the end
	path = strings.TrimSpace(path)

	// specific to current enforecer rules
	// accept rules
	if len(path) == 0 || path == "*" {
		return path, true // keep the "" and "*"
	}

	// reject rules
	// (1) ended with "/"  <== "/*" recursive rule
	// (2) started without a "/"
	// (3) include "<" or ">"
	// (4) more than one "*"
	if strings.HasSuffix(path, "/") || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "<>") || strings.Count(path, "*") > 1 {
		return "", false
	}

	// regular file
	path = filepath.Clean(path)
	if path == "." || path == "/" {
		return "", false
	}
	return path, true
}

func handlerProcRuleShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()
	procRuleHelper := ruleid.GetProcessRuleIDHelper()
	if procRuleHelper == nil {
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	uuid := ps.ByName("uuid")
	if entry, err := procRuleHelper.FindProcessRuleToRest(uuid, acc); entry != nil {
		resp := api.RESTProcessRulesResp{Entries: make([]api.RESTProcessUuidEntry, 1)}
		resp.Entries[0] = *entry
		restRespSuccess(w, r, &resp, acc, login, nil, "Get process rule")
	} else {
		restRespNotFoundLogAccessDenied(w, login, err)
	}
}

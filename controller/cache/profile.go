package cache

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/ruleid"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
	log "github.com/sirupsen/logrus"
)

var profileAlertDisable bool = false
var profileHashEnable bool = false
var profileGroups map[string]*share.CLUSProcessProfile = make(map[string]*share.CLUSProcessProfile) // key is group name

// update profile from config
func profileConfigUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	group := share.CLUSProfileKey2Name(key)
	procRuleHelper := ruleid.GetProcessRuleIDHelper()
	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		var profile share.CLUSProcessProfile
		if err := json.Unmarshal(value, &profile); err != nil {
			log.WithFields(log.Fields{"err": err}).Debug("Fail to decode")
			return
		}

		cacheMutexLock()
		profileGroups[group] = &profile
		cacheMutexUnlock()
		if procRuleHelper != nil {
			procRuleHelper.AddProcesProfile(&profile)
		}

	case cluster.ClusterNotifyDelete:
		cacheMutexLock()
		if profile, ok := profileGroups[group]; ok {
			if procRuleHelper != nil {
				procRuleHelper.DeleteProcesProfile(profile)
			}
			delete(profileGroups, group)
		}
		cacheMutexUnlock()
		log.WithFields(log.Fields{"group": group}).Debug("Delete")
	}
}

// handle new process report by enforcer
func handleProfileReport(gproc map[string][]*share.CLUSProcessProfileEntry) error {
	//	log.WithFields(log.Fields{"gproc": gproc}).Debug()
	for group, procs := range gproc {
		var profile *share.CLUSProcessProfile
		var update bool
		if !utils.DoesGroupHavePolicyMode(group) {
			log.WithFields(log.Fields{"group": group}).Debug("Invalid learned group")
			continue
		}

		accReadAll := access.NewReaderAccessControl()
		if profile = clusHelper.GetProcessProfile(group); profile != nil {
			if len(profile.Process) == 0 {
				if exist, _, _ := clusHelper.GetGroup(group, accReadAll); exist != nil {
					if profile.Mode == "" {
						update = true
						if !utils.IsGroupNodes(group) { // not apply to "nodes"
							profile.Baseline = getNewServiceProfileBaseline() // not for "node"
						}

						if exist.ProfileMode != "" {
							profile.Mode = exist.ProfileMode // replaced
						} else {
							_, profile.Mode = getNewServicePolicyMode()
						}
					}
				} else {
					log.WithFields(log.Fields{"group": group}).Error("Fail to get group")
					return errors.New("fail to find group")
				}
			}
			for _, proc := range procs {
				if proc.Action == share.PolicyActionLearn {
					proc.Action = share.PolicyActionAllow
					proc.Uuid = ruleid.NewUuid()
					proc.AllowFileUpdate = false
					if ret, ok := common.MergeProcess(profile.Process, proc, false); ok {
						profile.Process = ret
						update = true
					}
				}
			}
		} else {
			//create a new group
			update = true
			profile = &share.CLUSProcessProfile{
				Group:        group,
				Baseline:     getNewServiceProfileBaseline(),
				AlertDisable: profileAlertDisable,
				HashEnable:   profileHashEnable,
				Process:      nil,
			}

			if utils.IsGroupNodes(group) {
				profile.Baseline = share.ProfileBasic // for "node"
			}

			//the cache group maybe slow than this
			if exist, _, _ := clusHelper.GetGroup(group, accReadAll); exist != nil && exist.ProfileMode != "" {
				profile.Mode = exist.ProfileMode // replaced
			} else {
				_, profile.Mode = getNewServicePolicyMode()
			}

			for _, proc := range procs {
				if proc.Action == share.PolicyActionLearn {
					proc.Action = share.PolicyActionAllow
					proc.Uuid = ruleid.NewUuid()
					if ret, ok := common.MergeProcess(profile.Process, proc, false); ok {
						profile.Process = ret
					}
				}
			}
		}

		//first update to config/, then to network/
		if update {
			if err := clusHelper.PutProcessProfile(group, profile); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Put process profile fail")
				return errors.New("fail to put process profile")
			}
		}
	}
	return nil
}

func createProcessProfile(txn *cluster.ClusterTransact, group, mode, baseline string, cfgType share.TCfgType) bool {
	profile := &share.CLUSProcessProfile{
		Group:        group,
		AlertDisable: profileAlertDisable,
		HashEnable:   profileHashEnable,
		Mode:         mode,
		Process:      nil,
		CfgType:      cfgType,
	}

	if utils.DoesGroupHavePolicyMode(group) {
		if utils.IsGroupNodes(group) {
			profile.Baseline = share.ProfileBasic // for "node"
		} else {
			if cfgType == share.GroundCfg && baseline != "" {
				profile.Baseline = baseline
			} else {
				profile.Baseline = getNewServiceProfileBaseline()
			}
		}
	}

	if txn == nil {
		if err := clusHelper.PutProcessProfileIfNotExist(group, profile); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Put process profile fail")
			return false
		}
	} else {
		_ = clusHelper.PutProcessProfileTxn(txn, group, profile)
	}
	return true
}

func (m CacheMethod) CreateProcessProfile(group, mode, baseline string, cfgType share.TCfgType) bool {
	return createProcessProfile(nil, group, mode, baseline, cfgType)
}

func (m CacheMethod) CreateProcessProfileTxn(txn *cluster.ClusterTransact, group, mode, baseline string, cfgType share.TCfgType) bool {
	return createProcessProfile(txn, group, mode, baseline, cfgType)
	// txn.Apply() is called in caller
}

func (m *CacheMethod) GetProcessProfile(group string, acc *access.AccessControl) (*api.RESTProcessProfile, error) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	if p, ok := profileGroups[group]; ok {
		if !acc.Authorize(p, getAccessObjectFuncNoLock) {
			return nil, common.ErrObjectAccessDenied
		}

		resp := api.RESTProcessProfile{
			Group:        p.Group,
			Baseline:     p.Baseline,
			AlertDisable: p.AlertDisable,
			HashEnable:   p.HashEnable,
			Mode:         p.Mode,
			ProcessList:  make([]*api.RESTProcessProfileEntry, 0),
		}

		var lastName, lastPath string
		var lastCfgType share.TCfgType
		for _, gproc := range p.Process {
			// Sorted slices by Name(s), then Path(s)
			// existing data, skip duplicate entry by comparing Name and Path
			// still allow different Names but the same Path (could be wildcard or symbolic links like busybox)
			if gproc.Name == lastName && gproc.Path == lastPath && gproc.CfgType == lastCfgType {
				//	log.WithFields(log.Fields{"lastName": lastName, "lastPath": lastPath, "User": gproc.User}).Debug("PROC: ")
				continue
			}

			proc := &api.RESTProcessProfileEntry{
				Name: gproc.Name,
				Path: gproc.Path,
				User: gproc.User,
				Uuid: gproc.Uuid,
				//Uid:    gproc.Uid,
				Action:           gproc.Action,
				AllowFileUpdate:  gproc.AllowFileUpdate,
				CreatedTimeStamp: gproc.CreatedAt.Unix(),
				UpdatedTimeStamp: gproc.UpdatedAt.Unix(),
			}

			proc.CfgType = cfgTypeMapping[gproc.CfgType]
			resp.ProcessList = append(resp.ProcessList, proc)

			// store for reference
			lastName = proc.Name
			lastPath = proc.Path
			lastCfgType = gproc.CfgType
		}
		return &resp, nil
	}
	return nil, common.ErrObjectNotFound
}

func (m *CacheMethod) GetAllProcessProfile(scope string, acc *access.AccessControl) [][]*api.RESTProcessProfile {
	var getLocal, getFed bool
	var localGrpsCount, fedGrpsCount int
	if scope == share.ScopeLocal {
		getLocal = true
	} else if scope == share.ScopeFed {
		getFed = true
	} else if scope == share.ScopeAll {
		getFed = true
		getLocal = true
	} else {
		return nil
	}

	cacheMutexRLock()
	for _, cache := range groupCacheMap {
		if getLocal && cache.group.CfgType != share.FederalCfg {
			localGrpsCount++
		}
		if getFed && cache.group.CfgType == share.FederalCfg {
			fedGrpsCount++
		}
	}
	localProfiles := make([]*api.RESTProcessProfile, 0, localGrpsCount)
	fedProfiles := make([]*api.RESTProcessProfile, 0, fedGrpsCount)

	for _, p := range profileGroups {
		if !acc.Authorize(p, getAccessObjectFuncNoLock) {
			continue
		}

		if (getFed && p.CfgType == share.FederalCfg) || (getLocal && p.CfgType != share.FederalCfg) {
			resp := api.RESTProcessProfile{
				Group:        p.Group,
				Baseline:     p.Baseline,
				AlertDisable: p.AlertDisable,
				HashEnable:   p.HashEnable,
				Mode:         p.Mode,
				ProcessList:  make([]*api.RESTProcessProfileEntry, 0),
			}
			for _, gproc := range p.Process {
				proc := &api.RESTProcessProfileEntry{
					Name: gproc.Name,
					Path: gproc.Path,
					User: gproc.User,
					Uuid: gproc.Uuid,
					//Uid:    gproc.Uid,
					Action:           gproc.Action,
					AllowFileUpdate:  gproc.AllowFileUpdate,
					CreatedTimeStamp: gproc.CreatedAt.Unix(),
					UpdatedTimeStamp: gproc.UpdatedAt.Unix(),
				}

				proc.CfgType = cfgTypeMapping[gproc.CfgType]
				resp.ProcessList = append(resp.ProcessList, proc)
			}
			if getLocal && p.CfgType != share.FederalCfg {
				localProfiles = append(localProfiles, &resp)
			}
			if getFed && p.CfgType == share.FederalCfg {
				fedProfiles = append(fedProfiles, &resp)
			}
		}
	}
	cacheMutexRUnlock()

	profiles := make([][]*api.RESTProcessProfile, 0, 2)
	if len(fedProfiles) > 0 {
		profiles = append(profiles, fedProfiles)
	}
	if len(localProfiles) > 0 {
		profiles = append(profiles, localProfiles)
	}

	return profiles
}

// caller owns cacheMutexRLock & has readAll right
func (m *CacheMethod) GetFedProcessProfileCache() []*share.CLUSProcessProfile {
	count := 0
	for groupName := range profileGroups {
		if strings.HasPrefix(groupName, api.FederalGroupPrefix) {
			count++
		}
	}

	ret := make([]*share.CLUSProcessProfile, 0, count)
	for groupName, p := range profileGroups {
		if !strings.HasPrefix(groupName, api.FederalGroupPrefix) {
			continue
		}
		if g := getGroupWithoutLock(groupName); g == nil {
			continue
		}

		resp := share.CLUSProcessProfile{
			Group:        p.Group,
			AlertDisable: p.AlertDisable,
			HashEnable:   p.HashEnable,
			Mode:         p.Mode,
			Process:      make([]*share.CLUSProcessProfileEntry, 0, len(p.Process)),
			CfgType:      p.CfgType,
		}
		for _, gproc := range p.Process {
			proc := &share.CLUSProcessProfileEntry{
				Name:            gproc.Name,
				Path:            gproc.Path,
				User:            gproc.User,
				Action:          gproc.Action,
				CfgType:         gproc.CfgType,
				CreatedAt:       gproc.CreatedAt,
				UpdatedAt:       gproc.UpdatedAt,
				Uuid:            gproc.Uuid,
				AllowFileUpdate: gproc.AllowFileUpdate,
				//Uid:     gproc.Uid,
			}
			resp.Process = append(resp.Process, proc)
		}
		ret = append(ret, &resp)
	}
	return ret
}

// a dedicated service for reporting system with serialized in the occuring sequence
var processEntries []map[string][]*share.CLUSProcessProfileEntry = make([]map[string][]*share.CLUSProcessProfileEntry, 0)
var processEntryMux sync.Mutex

func ProcReportBkgSvc() {
	for {
		processEntryMux.Lock()
		len := len(processEntries)
		processEntryMux.Unlock()
		if len > 0 {
			if kv.IsImporting() {
				processEntryMux.Lock()
				processEntries = make([]map[string][]*share.CLUSProcessProfileEntry, 0)
				processEntryMux.Unlock()
			} else {
				if lock, _ := clusHelper.AcquireLock(share.CLUSLockPolicyKey, policyClusterLockWait); lock != nil {
					var gprocs []map[string][]*share.CLUSProcessProfileEntry
					index := len
					if index > 32 { // TODO: 32 entries
						index = 32
					}

					processEntryMux.Lock()
					gprocs, processEntries = processEntries[:index], processEntries[index:]
					processEntryMux.Unlock()

					for _, gproc := range gprocs {
						_ = handleProfileReport(gproc)
					}
					clusHelper.ReleaseLock(lock)
				}
			}
		} else {
			time.Sleep(time.Millisecond * 100) // yield
		}
	}
}

func AddProcessReport(gproc map[string][]*share.CLUSProcessProfileEntry) bool {
	processEntryMux.Lock()
	processEntries = append(processEntries, gproc)
	processEntryMux.Unlock()
	return true
}

func addK8sProbeApps(group string, probeCmds []k8sProbeCmd) {
	gproc := make(map[string][]*share.CLUSProcessProfileEntry)
	var procs []*share.CLUSProcessProfileEntry
	for _, p := range probeCmds {
		proc := &share.CLUSProcessProfileEntry{
			Name:      p.app,
			Path:      p.path,
			ProbeCmds: p.cmds,
			Action:    share.PolicyActionLearn,
			CfgType:   share.Learned,
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		}
		procs = append(procs, proc)
	}

	if len(procs) > 0 {
		gproc[group] = procs
		if isLeader() {
			_ = handleProfileReport(gproc)
		} else {
			AddProcessReport(gproc) // put into a queue
		}
	}
}

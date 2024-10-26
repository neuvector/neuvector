package cache

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	admission "github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg"
	"github.com/neuvector/neuvector/controller/scan"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

type tFedClusterCache struct { // only master cluster needs to get/set this cache
	cluster    *share.CLUSFedJointClusterInfo
	tokenCache map[string]string // key is mainSessionID (from claim.id in login token of master cluster). value is token with admin role
}

const _maxScanResultCount int = 2

// On master cluster,   it stores the revisions of all types of fed rules.
// On managed clusters, it stores the last downloaded revisions of all types of fed rules.
var fedRulesRevisionCache share.CLUSFedRulesRevision

// On master cluster,   it stores the revisions of fed registry/repo scan data
// On managed clusters, it stores the revisions of fed registry/repo scan data from the lastest polling
var fedScanDataRevsCache share.CLUSFedScanRevisions

// On master cluster,   it stores the scan result md5 of the scanned images in fed registry/repo
// On managed clusters, it stores the scan result md5 of the scanned images in fed registry/repo from the lastest polling
var fedScanResultMD5 map[string]map[string]string = make(map[string]map[string]string) // registry name : image id : scan result md5

var cachedFedSettingsRev map[string]uint64 // contains only the revisions of the fed rules subset for the last polling managed cluster
var cachedFedSettingBytes []byte           // contains only the fed rules subset for the last polling managed cluster

var fedMembershipCache share.CLUSFedMembership
var fedJoinedClustersCache = make(map[string]*tFedClusterCache)               // key is cluster id
var fedJoinedClusterStatusCache = make(map[string]share.CLUSFedClusterStatus) // key is cluster id, value ex: _fedClusterJoined, _fedClusterSynced
var fedSettingsCache share.CLUSFedSettings                                    // general fed settings
var fedCacheMutex sync.RWMutex                                                // for accessing fedMembershipCache/fedJoinedClustersCache/fedJoinedClusterStatusCache

func fedInit(restoredFedRole string) {
	m := clusHelper.GetFedMembership()
	if m == nil {
		m = &share.CLUSFedMembership{}
		_ = clusHelper.PutFedMembership(m)
	}
	l := clusHelper.GetFedJointClusterList()
	if l == nil {
		l = &share.CLUSFedJoinedClusterList{IDs: make([]string, 0)}
		_ = clusHelper.PutFedJointClusterList(l)
	}

	revCache, _ := clusHelper.GetFedRulesRevisionRev()
	if revCache == nil || len(revCache.Revisions) == 0 {
		clusHelper.UpdateFedRulesRevision(nil)
	} else {
		if restoredFedRole == api.FedRoleMaster {
			// now on master cluster
			// 1. restore to kv is done
			// 2. kv watchers are not registered yet
			// when pv is used, later after kv watchers are registered, it may take long time to update master's cache for all fed-related group/policy keys.
			// do not init fedRulesRevisionCache with the latest object/config/federation/rules_revision value before the fed groups/policies are updated in master's cache
			empty := share.CLUSEmptyFedRulesRevision()
			fedRulesRevisionCache.Revisions = empty.Revisions
		} else {
			wrt := false
			empty := share.CLUSEmptyFedRulesRevision()
			for ruleType, rev := range empty.Revisions {
				if _, ok := revCache.Revisions[ruleType]; !ok {
					revCache.Revisions[ruleType] = rev
					wrt = true
				}
			}
			if wrt {
				_ = clusHelper.PutFedRulesRevision(nil, revCache)
			}
			fedRulesRevisionCache.Revisions = revCache.Revisions
		}
	}
}

func fedCacheMutexLock() {
	cctx.MutexLog.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("Acquire ...")
	fedCacheMutex.Lock()
}

func fedCacheMutexUnlock() {
	fedCacheMutex.Unlock()
	cctx.MutexLog.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("Released")
}

func fedCacheMutexRLock() {
	cctx.MutexLog.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("Acquire ...")
	fedCacheMutex.RLock()
}

func fedCacheMutexRUnlock() {
	fedCacheMutex.RUnlock()
	cctx.MutexLog.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("Released")
}

func fedScanDataCacheMutexLock() {
	cctx.MutexLog.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("Acquire ...")
	fedCacheMutex.Lock()
}

func fedScanDataCacheMutexUnlock() {
	fedCacheMutex.Unlock()
	cctx.MutexLog.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("Released")
}

func fedScanDataCacheMutexRLock() {
	cctx.MutexLog.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("Acquire ...")
	fedCacheMutex.RLock()
}

func fedScanDataCacheMutexRUnlock() {
	fedCacheMutex.RUnlock()
	cctx.MutexLog.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("Released")
}

/*
func serializeFile(fileName string, dataBase64 string) {
	if len(dataBase64) > 0 {
		_, err := os.Stat(fileName)
		if err != nil && os.IsNotExist(err) {
			if data, err := base64.StdEncoding.DecodeString(dataBase64); err == nil {
				if err = os.WriteFile(fileName, data, 0600); err == nil {
					return
				} else {
					log.WithFields(log.Fields{"error": err, "path": fileName}).Error("serialize")
				}
			} else {
				log.WithFields(log.Fields{"error": err, "path": fileName}).Error("decode")
			}
		} else {
			log.Debug("found existing file")
		}
	} else {
		log.WithFields(log.Fields{"path": fileName}).Error("empty dataBase64")
	}
}
*/

func purgeFiles(fileNamePrefix string) {
	dir := "/etc/neuvector/certs"
	pathPrefix := fmt.Sprintf("%s/%s", dir, fileNamePrefix)
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if info != nil && strings.Index(path, pathPrefix) == 0 {
			os.Remove(path)
		}
		return nil
	})
}

func fedConfigUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	cfgType := share.CLUSFedKey2CfgKey(key)
	log.WithFields(log.Fields{"cfgType": cfgType}).Debug()
	fedCacheMutexLock()
	defer fedCacheMutexUnlock()

	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		switch cfgType {
		case share.CLUSFedMembershipSubKey:
			var m share.CLUSFedMembership
			var dec common.DecryptUnmarshaller
			_ = dec.Unmarshal(value, &m)
			log.WithFields(log.Fields{"role": m.FedRole}).Info()
			if m.FedRole == api.FedRoleMaster {
				access.UpdateUserRoleForFedRoleChange(api.FedRoleMaster)
				_, _ = kv.GetFedCaCertPath(m.MasterCluster.ID)
				go func() { _ = cctx.StartStopFedPingPollFunc(share.StartFedRestServer, m.PingInterval, nil) }()
			} else if m.FedRole == api.FedRoleJoint {
				var param interface{} = &m.JointCluster
				if err := cctx.StartStopFedPingPollFunc(share.JointLoadOwnKeys, 0, param); err == nil {
					//serializeFile(masterCaCertPath, m.MasterCluster.CACert)
					go func() { _ = cctx.StartStopFedPingPollFunc(share.StartPollFedMaster, m.PollInterval, nil) }()
				}
			} else if m.FedRole == api.FedRoleNone {
				access.UpdateUserRoleForFedRoleChange(api.FedRoleNone)
				_ = cctx.StartStopFedPingPollFunc(share.PurgeJointKeys, 0, nil)
				go func() { _ = cctx.StartStopFedPingPollFunc(share.StopFedRestServer, 0, nil) }()
				purgeFiles("fed.master.")
				purgeFiles("fed.client.")
				fedSystemConfigCache = share.CLUSSystemConfig{CfgType: share.FederalCfg}
				cachedFedSettingsRev = nil
				cachedFedSettingBytes = nil
			}
			fedMembershipCache = m
			if m.FedRole == api.FedRoleNone {
				fedScanDataRevsCache = share.CLUSFedScanRevisions{}
				fedScanResultMD5 = make(map[string]map[string]string)
			}
			scan.FedRoleChangeNotify(m.FedRole)
		case share.CLUSFedClustersSubKey:
			id := share.CLUSFedKey2ClusterIdKey(key)
			if id != "" {
				var cluster share.CLUSFedJointClusterInfo
				var dec common.DecryptUnmarshaller
				_ = dec.Unmarshal(value, &cluster)
				cache, ok := fedJoinedClustersCache[id]
				if cache == nil || !ok {
					log.WithFields(log.Fields{"id": id}).Info("add")
					cache = &tFedClusterCache{
						cluster:    &cluster,
						tokenCache: make(map[string]string),
					}
					var param interface{} = &cluster
					_ = cctx.StartStopFedPingPollFunc(share.MasterLoadJointKeys, 0, param)
					fedJoinedClustersCache[id] = cache
				} else {
					if cache.cluster.Name != cluster.Name {
						cache.cluster.Name = cluster.Name
					}
					cache.cluster.Disabled = cluster.Disabled
					cache.cluster.ProxyRequired = cluster.ProxyRequired
					cache.cluster.RestVersion = cluster.RestVersion
				}
				if isLeader() && cluster.Disabled {
					data := share.CLUSFedClusterStatus{Status: 207} // _fedLicenseDisallowed
					_ = clusHelper.PutFedJointClusterStatus(id, &data)
				}
			}
		case share.CLUSFedClustersStatusSubKey:
			id := share.CLUSFedKey2ClusterIdKey(key)
			var status share.CLUSFedClusterStatus
			_ = json.Unmarshal(value, &status)
			if status.Nodes == 0 {
				status.Nodes = 1
			}
			fedJoinedClusterStatusCache[id] = status
		case share.CLUSFedRulesRevisionSubKey:
			var revCache share.CLUSFedRulesRevision
			_ = json.Unmarshal(value, &revCache)
			// when demote/leave/kicked, in kv the cluster's fedRole is updated first and the CLUSFedRulesRevisionSubKey is updated last(after all fed rules are deleted).
			// however, it may take a while for all deleted fed rule keys to be updated in cache.
			if isLeader() && fedMembershipCache.FedRole == api.FedRoleNone {
				allRevZero := true
				for _, v := range revCache.Revisions {
					if v != 0 {
						allRevZero = false
						break
					}
				}
				if allRevZero {
					// the last kv update for demote/leave/kicked is received
					if m := clusHelper.GetFedMembership(); m != nil {
						if m.PendingDismiss {
							m.PendingDismiss = false
							_ = clusHelper.PutFedMembership(m)
						}
					}
				}
			}
			fedRulesRevisionCache.Revisions = revCache.Revisions
			if fedMembershipCache.FedRole != api.FedRoleMaster {
				cachedFedSettingBytes = nil
			}
		case share.CLUSFedToPingPollSubKey:
			if isLeader() {
				var doPingPoll share.CLUSFedDoPingPoll
				_ = json.Unmarshal(value, &doPingPoll)
				go func() { _ = cctx.StartStopFedPingPollFunc(doPingPoll.Cmd, doPingPoll.FullPolling, nil) }()
			}
		case share.CFGEndpointSystem:
			var cfg share.CLUSSystemConfig
			_ = json.Unmarshal(value, &cfg)
			fedWebhookCacheTemp := make(map[string]*webhookCache, 0)
			for _, h := range cfg.Webhooks {
				if h.Enable {
					fedWebhookCacheTemp[h.Name] = &webhookCache{
						c:        common.NewWebHook(h.Url, h.Type),
						url:      h.Url,
						useProxy: h.UseProxy,
					}
				}
			}
			fedWebhookCacheMap = fedWebhookCacheTemp
			fedSystemConfigCache = cfg
		case share.CLUSFedSettingsSubKey:
			var cfg share.CLUSFedSettings
			_ = json.Unmarshal(value, &cfg)
			fedSettingsCache = cfg
		}
	case cluster.ClusterNotifyDelete:
		switch cfgType {
		case share.CLUSFedClustersListSubKey:
			fedJoinedClustersCache = make(map[string]*tFedClusterCache)
			fedJoinedClusterStatusCache = make(map[string]share.CLUSFedClusterStatus)
		case share.CLUSFedClustersSubKey:
			id := share.CLUSFedKey2ClusterIdKey(key)
			if _, ok := fedJoinedClustersCache[id]; ok {
				log.WithFields(log.Fields{"id": id}).Info("del")
				delete(fedJoinedClustersCache, id)
				purgeFiles(fmt.Sprintf("fed.client.%s.", id))
				var param interface{} = &id
				_ = cctx.StartStopFedPingPollFunc(share.MasterUnloadJointKeys, 0, param)
			}
		case share.CLUSFedClustersStatusSubKey:
			id := share.CLUSFedKey2ClusterIdKey(key)
			delete(fedJoinedClusterStatusCache, id)
		}
	}
}

func (m CacheMethod) GetFedMembershipRole(acc *access.AccessControl) (string, error) {
	fedCacheMutexRLock()
	defer fedCacheMutexRUnlock()

	if acc.Authorize(&fedMembershipCache, nil) || acc.HasPermFed() {
		return fedMembershipCache.FedRole, nil
	}

	return "", common.ErrObjectAccessDenied
}

func (m CacheMethod) GetFedMember(statusMap map[int]string, acc *access.AccessControl) (*api.RESTFedMembereshipData, error) {
	fedCacheMutexRLock()
	defer fedCacheMutexRUnlock()

	if !acc.Authorize(&fedMembershipCache, nil) {
		return nil, common.ErrObjectAccessDenied
	}

	s := &api.RESTFedMembereshipData{
		FedRole:       fedMembershipCache.FedRole,
		LocalRestInfo: fedMembershipCache.LocalRestInfo,
		UseProxy:      fedMembershipCache.UseProxy,
	}
	if fedMembershipCache.FedRole != api.FedRoleNone {
		s.MasterCluster = &api.RESTFedMasterClusterInfo{
			ID:       fedMembershipCache.MasterCluster.ID,
			RestInfo: fedMembershipCache.MasterCluster.RestInfo,
		}
	}

	switch fedMembershipCache.FedRole {
	case api.FedRoleMaster:
		s.MasterCluster.Name = m.GetSystemConfigClusterName(acc)
		s.MasterCluster.Status = statusMap[0] // _fedSuccess meaning active
		s.MasterCluster.RestVersion = kv.GetRestVer()
		s.JointClusters = make([]*api.RESTFedJointClusterInfo, 0, len(fedJoinedClustersCache))
		for _, c := range fedJoinedClustersCache {
			jointCluster := &api.RESTFedJointClusterInfo{
				Name:          c.cluster.Name,
				ID:            c.cluster.ID,
				RestInfo:      c.cluster.RestInfo,
				RestVersion:   c.cluster.RestVersion,
				ProxyRequired: c.cluster.ProxyRequired,
			}
			if cache, ok := fedJoinedClusterStatusCache[c.cluster.ID]; ok && cache.Status > 0 {
				jointCluster.Status = statusMap[cache.Status]
			}
			s.JointClusters = append(s.JointClusters, jointCluster)
		}
		sort.Slice(s.JointClusters, func(i, j int) bool { return s.JointClusters[i].Name < s.JointClusters[j].Name })
	case api.FedRoleJoint:
		s.MasterCluster.Name = fedMembershipCache.MasterCluster.Name
		if cache, ok := fedJoinedClusterStatusCache[s.MasterCluster.ID]; ok && cache.Status > 0 {
			s.MasterCluster.Status = statusMap[cache.Status]
		}
		local := &api.RESTFedJointClusterInfo{
			Name:     m.GetSystemConfigClusterName(acc),
			ID:       fedMembershipCache.JointCluster.ID,
			RestInfo: fedMembershipCache.JointCluster.RestInfo,
		}
		if cache, ok := fedJoinedClusterStatusCache[fedMembershipCache.JointCluster.ID]; ok && cache.Status > 0 {
			local.Status = statusMap[cache.Status]
		}
		s.JointClusters = []*api.RESTFedJointClusterInfo{local}
	}

	return s, nil
}

// return rest info, use system https/http proxy or not
func (m CacheMethod) GetFedLocalRestInfo(acc *access.AccessControl) (share.CLUSRestServerInfo, int8) {
	fedCacheMutexRLock()
	defer fedCacheMutexRUnlock()

	var useProxy int8
	if fedMembershipCache.UseProxy == "https" {
		useProxy = 1 // 1 means const_https_proxy
	}
	if acc.Authorize(&fedMembershipCache, nil) || acc.HasPermFed() {
		return fedMembershipCache.LocalRestInfo, useProxy
	}
	return share.CLUSRestServerInfo{}, useProxy
}

func (m CacheMethod) GetFedMasterCluster(acc *access.AccessControl) api.RESTFedMasterClusterInfo {
	fedCacheMutexRLock()
	defer fedCacheMutexRUnlock()

	if acc.Authorize(&fedMembershipCache, nil) && fedMembershipCache.FedRole != api.FedRoleNone {
		return api.RESTFedMasterClusterInfo{
			Name:     fedMembershipCache.MasterCluster.Name,
			ID:       fedMembershipCache.MasterCluster.ID,
			Secret:   fedMembershipCache.MasterCluster.Secret,
			RestInfo: fedMembershipCache.MasterCluster.RestInfo,
		}
	}
	return api.RESTFedMasterClusterInfo{}
}

func (m CacheMethod) GetFedLocalJointCluster(acc *access.AccessControl) api.RESTFedJointClusterInfo {
	fedCacheMutexRLock()
	defer fedCacheMutexRUnlock()

	if acc.Authorize(&fedMembershipCache, nil) && fedMembershipCache.FedRole == api.FedRoleJoint {
		return api.RESTFedJointClusterInfo{
			ID:            fedMembershipCache.JointCluster.ID,
			Secret:        fedMembershipCache.JointCluster.Secret,
			RestInfo:      fedMembershipCache.JointCluster.RestInfo,
			ProxyRequired: fedMembershipCache.JointCluster.ProxyRequired,
		}
	}
	return api.RESTFedJointClusterInfo{}
}

func (m CacheMethod) GetFedJoinedClusterToken(id, mainSessionID string, acc *access.AccessControl) (string, error) {
	fedCacheMutexRLock()
	defer fedCacheMutexRUnlock()

	if acc.Authorize(&fedMembershipCache, nil) || acc.HasPermFed() {
		if c, ok := fedJoinedClustersCache[id]; ok && c != nil && c.cluster != nil {
			if token, ok := c.tokenCache[mainSessionID]; ok {
				return token, nil
			} else {
				return "", nil
			}
		}
	}
	return "", errors.New("managed cluster not exist")
}

func (m CacheMethod) GetFedJoinedClusterCount() int {
	fedCacheMutexRLock()
	defer fedCacheMutexRUnlock()

	return len(fedJoinedClustersCache)
}

func (m CacheMethod) GetFedJoinedClusterIdMap(acc *access.AccessControl) map[string]bool {
	fedCacheMutexRLock()
	defer fedCacheMutexRUnlock()

	if acc.Authorize(&fedMembershipCache, nil) || acc.HasPermFed() {
		list := make(map[string]bool, len(fedJoinedClustersCache))
		for id, cache := range fedJoinedClustersCache {
			list[id] = cache.cluster.Disabled
		}
		return list
	}
	return nil
}

func (m CacheMethod) GetFedJoinedClusterNameList(acc *access.AccessControl) []string {
	fedCacheMutexRLock()
	defer fedCacheMutexRUnlock()

	if acc.Authorize(&fedMembershipCache, nil) || acc.HasPermFed() {
		list := make([]string, 0, len(fedJoinedClustersCache))
		for _, c := range fedJoinedClustersCache {
			list = append(list, c.cluster.Name)
		}
		return list
	}
	return nil
}

func (m CacheMethod) GetFedJoinedCluster(id string, acc *access.AccessControl) share.CLUSFedJointClusterInfo {
	fedCacheMutexRLock()
	defer fedCacheMutexRUnlock()

	if acc.Authorize(&fedMembershipCache, nil) || acc.HasPermFed() {
		if c, ok := fedJoinedClustersCache[id]; ok && c != nil && c.cluster != nil {
			return *c.cluster
		}
	}
	return share.CLUSFedJointClusterInfo{}
}

func (m CacheMethod) GetFedJoinedClusterStatus(id string, acc *access.AccessControl) share.CLUSFedClusterStatus {
	fedCacheMutexRLock()
	defer fedCacheMutexRUnlock()

	if acc.Authorize(&fedMembershipCache, nil) || acc.HasPermFed() {
		if s, ok := fedJoinedClusterStatusCache[id]; ok {
			return s
		}
	}
	return share.CLUSFedClusterStatus{Status: -1}
}

// Be careful when calling the following functions because access control is not applied
func (m CacheMethod) GetFedMembershipRoleNoAuth() string {
	fedCacheMutexRLock()
	defer fedCacheMutexRUnlock()

	return fedMembershipCache.FedRole
}

func (m CacheMethod) SetFedJoinedClusterToken(id, mainSessionID, token string) {
	fedCacheMutexLock()
	defer fedCacheMutexUnlock()

	if id != "" {
		if c, ok := fedJoinedClustersCache[id]; ok && c != nil {
			if token == "" {
				delete(c.tokenCache, mainSessionID)
			} else {
				c.tokenCache[mainSessionID] = token
			}
		}
	} else {
		for _, c := range fedJoinedClustersCache {
			delete(c.tokenCache, mainSessionID)
		}
	}
}

// only called by master cluster. caller doesn't own cache lock
func (m CacheMethod) GetFedRules(reqRevs map[string]uint64, acc *access.AccessControl) ([]byte, map[string]uint64, error) {
	askRevMap := make(map[string]uint64, len(reqRevs))

	fedCacheMutexLock()
	defer fedCacheMutexUnlock()

	for ruleType, rev := range reqRevs {
		if fedRev, ok := fedRulesRevisionCache.Revisions[ruleType]; ok {
			if rev != fedRev {
				askRevMap[ruleType] = fedRev
			}
		}
	}

	// now askRevMap contains only those fed rules that the managed cluster misses
	var settings []byte
	if len(askRevMap) > 0 {
		useCache := true
		if len(askRevMap) == len(cachedFedSettingsRev) {
			for ruleType, rev := range askRevMap {
				if cacheRev, ok := cachedFedSettingsRev[ruleType]; !ok || rev != cacheRev {
					useCache = false
					break
				}
			}
		} else {
			useCache = false
		}
		if useCache {
			settings = make([]byte, len(cachedFedSettingBytes))
			copy(settings, cachedFedSettingBytes)
		} else {
			var current api.RESTFedRulesSettings
			cacheMutexRLock()
			for ruleType, fedRev := range askRevMap {
				switch ruleType {
				case share.FedAdmCtrlExceptRulesType, share.FedAdmCtrlDenyRulesType:
					if current.AdmCtrlRulesData == nil {
						current.AdmCtrlRulesData = &share.CLUSFedAdmCtrlRulesData{Revision: fedRev, Rules: make(map[string]*share.CLUSAdmissionRules)}
					}
					current.AdmCtrlRulesData.Rules[ruleType], _ = m.GetFedAdmissionRulesCache(admission.NvAdmValidateType, ruleType)
				case share.FedNetworkRulesType:
					current.NetworkRulesData = &share.CLUSFedNetworkRulesData{Revision: fedRev}
					current.NetworkRulesData.Rules, current.NetworkRulesData.RuleHeads = m.GetFedNetworkRulesCache()
				case share.FedGroupType:
					current.GroupsData = &share.CLUSFedGroupsData{Revision: fedRev, Groups: m.GetFedGroupsCache()}
				case share.FedResponseRulesType:
					current.ResponseRulesData = &share.CLUSFedResponseRulesData{Revision: fedRev}
					current.ResponseRulesData.Rules, current.ResponseRulesData.RuleHeads = m.GetFedResponseRulesCache()
				case share.FedFileMonitorProfilesType:
					current.FileMonitorData = &share.CLUSFedFileMonitorData{Revision: fedRev}
					current.FileMonitorData.Profiles, current.FileMonitorData.AccessRules = m.GetFedFileMonitorProfileCache()
				case share.FedProcessProfilesType:
					current.ProcessProfilesData = &share.CLUSFedProcessProfileData{Revision: fedRev, Profiles: m.GetFedProcessProfileCache()}
				case share.FedSystemConfigType:
					current.SystemConfigData = &share.CLUSFedSystemConfigData{Revision: fedRev, SystemConfig: m.GetFedSystemConfig(acc)}
				}
			}
			cacheMutexRUnlock()
			settings, _ = json.Marshal(current)

			tempSettings := make([]byte, len(settings))
			copy(tempSettings, settings)
			cachedFedSettingsRev = askRevMap
			cachedFedSettingBytes = tempSettings
		}
	}

	return settings, askRevMap, nil
}

func (m CacheMethod) GetAllFedRulesRevisions() map[string]uint64 {
	fedCacheMutexRLock()
	defer fedCacheMutexRUnlock()

	revisions := make(map[string]uint64, len(fedRulesRevisionCache.Revisions))
	for fedRuleType, rev := range fedRulesRevisionCache.Revisions {
		revisions[fedRuleType] = rev
	}

	return revisions
}

func (m CacheMethod) GetFedSettings() share.CLUSFedSettings {
	fedCacheMutexRLock()
	defer fedCacheMutexRUnlock()

	return fedSettingsCache
}

func collectUpdatedScanResult(regName, imageID, md5 string, updatedResults map[string]*api.RESTFedImageScanResult) {
	name := regName
	if name == common.RegistryFedRepoScanName {
		// on master cluster, the scan summary/data of images in "fed._repo_scan" repo are actually from "_repo_scan" repo
		name = common.RegistryRepoScanName
	}
	summary := clusHelper.GetRegistryImageSummary(name, imageID)
	if summary != nil && summary.Status == api.ScanStatusFinished {
		updatedResults[imageID] = &api.RESTFedImageScanResult{
			MD5:     md5,
			Summary: summary,
			Report:  clusHelper.GetScanReport(share.CLUSRegistryImageDataKey(name, imageID)),
		}
	}
}

// only called by master cluster. caller doesn't own cache lock
// reqRegConfigRev/reqScanResultMD5: what the requesting managed cluster remembers from the last polling.
// reqScanResultMD5: the images md5 for fed registry/repo that are remembered by managed clusters & have different scan data revision from what master cluster has.
func (m CacheMethod) GetFedScanResult(reqRegConfigRev uint64, reqScanResultMD5 map[string]map[string]string,
	reqIgnoreRegs, reqUpToDateRegs []string, fedRegs utils.Set) (api.RESTPollFedScanDataResp, bool) {

	var getFedRegCfg bool
	var throttled bool
	var collectedScanResults int
	var fedSettings share.CLUSFedSettings
	var resp api.RESTPollFedScanDataResp

	fedCacheMutexRLock()
	fedSettings = fedSettingsCache
	fedCacheMutexRUnlock()

	fedDeployRegScanData := true // always deploy fed registry scan data
	resp.DeployRepoScanData = fedSettings.DeployRepoScanData

	scanResultData := api.RESTFedScanResultData{
		UpdatedScanResults: make(map[string]map[string]*api.RESTFedImageScanResult), // registry name : image id : scan result
		DeletedScanResults: make(map[string][]string),                               // registry name : []image id ('registry name : nil' means the reg is deleted on master cluster)
		UpToDateRegs:       reqUpToDateRegs,
	}

	fedScanDataCacheMutexRLock()
	defer fedScanDataCacheMutexRUnlock()

	// check whether any fed registry setting changes
	if fedDeployRegScanData {
		if fedScanDataRevsCache.RegConfigRev != reqRegConfigRev {
			// fed registry settings has been changed
			resp.RegistryCfg = &share.CLUSFedRegistriesData{Revision: fedScanDataRevsCache.RegConfigRev}
			getFedRegCfg = true
		}
	} else {
		// if "deploy fed registry scan data" is disabled, return an empty object so that managed cluster knows about it
		resp.RegistryCfg = &share.CLUSFedRegistriesData{}
	}

	// check whether any fed scan result needs to deploy to the requesting managed cluster
	if fedDeployRegScanData || fedSettings.DeployRepoScanData {
		if fedSettings.DeployRepoScanData {
			if curImagesMD5, ok := fedScanResultMD5[common.RegistryFedRepoScanName]; ok && len(curImagesMD5) > 0 {
				fedRegs.Add(common.RegistryFedRepoScanName)
			}
		}
		// 1. check whether there is scan result change for the images in those fed registry/repo that managed cluster remembers
		// reqImagesMD5: md5(regImageSummaryReport) of images in fed registry/repo that managed cluster remembers
		for regName, reqImagesMD5 := range reqScanResultMD5 {
			// 1-1. check whether the scan result is not deployed anymore or there is no change for that kind of scan result
			if regName == common.RegistryFedRepoScanName {
				if !fedSettings.DeployRepoScanData {
					// 1-1-1. master cluster doesn't deploy repo scan result anymore
					scanResultData.DeletedScanResults[regName] = nil
					continue
				}
			} else {
				if !fedDeployRegScanData {
					// 1-1-2. master cluster doesn't deploy fed registry scan result anymore
					scanResultData.DeletedScanResults[regName] = nil
					continue
				}
			}

			if !fedRegs.Contains(regName) {
				// 1-2. the fed registry remembered by managed cluster is already deleted on master cluster
				scanResultData.DeletedScanResults[regName] = nil
				continue
			}

			curImagesMD5, ok := fedScanResultMD5[regName]
			if ok && len(curImagesMD5) == len(reqImagesMD5) {
				sameScanResultMD5 := true
				for imageID, curMD5 := range curImagesMD5 {
					if reqMD5, ok := reqImagesMD5[imageID]; !ok || curMD5 != reqMD5 {
						sameScanResultMD5 = false
						break
					}
				}
				if sameScanResultMD5 {
					// 1-3. scan result of the fed registry on managed cluster is the same as on master cluster
					scanResultData.UpToDateRegs = append(scanResultData.UpToDateRegs, regName)
					continue
				}
			}

			// 1-4. the fed registry/repo remembered by managed cluster still exists on master cluster & its scan result can be deployed to managed clusters
			var deletedResults []string                                                         // []image id
			updatedResults := make(map[string]*api.RESTFedImageScanResult, _maxScanResultCount) // image id : scan result
			// reqImagesMD5: md5(regImageSummaryReport) of images in fed registry/repo that managed cluster remembers
			// curImagesMD5: current md5(regImageSummaryReport) of images in fed registry/repo on master cluster
			for imageID, reqMD5 := range reqImagesMD5 {
				if curMD5, ok := curImagesMD5[imageID]; !ok {
					// 1-4-1. the image's scan result remembered by managed cluster has been deleted on master cluster
					if deletedResults == nil {
						deletedResults = make([]string, 0, 4)
					}
					deletedResults = append(deletedResults, imageID)
				} else if !throttled {
					if curMD5 != reqMD5 {
						// 1-4-2. the image's scan result has been changed on master cluster
						collectUpdatedScanResult(regName, imageID, curMD5, updatedResults)
						collectedScanResults += 1
						if collectedScanResults >= _maxScanResultCount {
							// for network bandwidth consideration, we only return at most _maxScanResultCount scan results in one polling.
							throttled = true
							break
						}
					}
				}
			}
			if !throttled { // we haven't reached the max scan result number to return yet
				// 1-5. check whether there is a new image (in a known fed registry/repo) scanned on master cluster that managed cluster is unaware of
				for imageID, curMD5 := range curImagesMD5 {
					if _, ok := reqImagesMD5[imageID]; !ok {
						collectUpdatedScanResult(regName, imageID, curMD5, updatedResults)
						collectedScanResults += 1
						if collectedScanResults >= _maxScanResultCount {
							// for network bandwidth consideration, we only return at most _maxScanResultCount scan results in one polling.
							throttled = true
							break
						}
					}
				}
			}
			if len(updatedResults) > 0 {
				scanResultData.UpdatedScanResults[regName] = updatedResults
			}
			if len(deletedResults) > 0 {
				scanResultData.DeletedScanResults[regName] = deletedResults
			}
		}

		if !throttled {
			ignoreRegs := utils.NewSetFromSliceKind(reqIgnoreRegs)
			upToDateRegs := utils.NewSetFromSliceKind(scanResultData.UpToDateRegs)
			// 2. check whether there is new fed registry created on master cluster that managed cluster is unaware of
			for regName, curImagesMD5 := range fedScanResultMD5 {
				if ignoreRegs.Contains(regName) || upToDateRegs.Contains(regName) {
					continue
				}
				isForRepoScan := false
				if regName == common.RegistryFedRepoScanName {
					isForRepoScan = true
				}
				if (isForRepoScan && !fedSettings.DeployRepoScanData) || (!isForRepoScan && !fedDeployRegScanData) {
					// master cluster doesn't deploy scan result of fed registry/repo scan anymore
					continue
				}
				if _, ok := reqScanResultMD5[regName]; !ok {
					// found a new fed registry/repo on master cluster that managed cluster is unaware of
					updatedResults := make(map[string]*api.RESTFedImageScanResult, _maxScanResultCount) // image id : scan result
					for imageID, currMD5 := range curImagesMD5 {
						collectUpdatedScanResult(regName, imageID, currMD5, updatedResults)
						collectedScanResults += 1
						if collectedScanResults >= _maxScanResultCount {
							// for network bandwidth consideration, we only return at most _maxScanResultCount scan results in one polling.
							throttled = true
							break
						}
					}
					if len(updatedResults) > 0 {
						scanResultData.UpdatedScanResults[regName] = updatedResults
					}
				}
				if throttled {
					break
				}
			}
		}
	}

	resp.ScanResultData = scanResultData
	resp.HasMoreScanResult = throttled
	if throttled {
		resp.ThrottleTime = 100 // ms
	}

	return resp, getFedRegCfg
}

// called by master/managed clusters
// it returns a copy of the cached fed registry/repo scan data revisions
func (m CacheMethod) GetFedScanDataRevisions(getRegScanData, getRepoScanData bool) (api.RESTFedScanDataRevs, bool) {
	var scanDataRevs api.RESTFedScanDataRevs

	fedScanDataCacheMutexRLock()
	defer fedScanDataCacheMutexRUnlock()

	if getRegScanData {
		scanDataRevs.RegConfigRev = fedScanDataRevsCache.RegConfigRev
		scanDataRevs.ScannedRegRevs = make(map[string]uint64, len(fedScanDataRevsCache.ScannedRegRevs))
		for k, v := range fedScanDataRevsCache.ScannedRegRevs {
			scanDataRevs.ScannedRegRevs[k] = v
		}
	}
	if getRepoScanData {
		scanDataRevs.ScannedRepoRev = fedScanDataRevsCache.ScannedRepoRev
	}

	if fedScanDataRevsCache.Restoring {
		if elapsed := time.Since(fedScanDataRevsCache.RestoreAt); elapsed > time.Duration(5)*time.Minute {
			fedScanDataRevsCache.Restoring = false
		}
	}

	return scanDataRevs, fedScanDataRevsCache.Restoring
}

// only called by managed cluster once in each polling session
// it's for retrieving scan result md5 of the images in fed registry/repo that have different scan data revision(per fed registry/repo) from what master cluster has
// for the following requests in the same polling session, entries of synced fed registry/repo are removed from the scan result md5 map one by one
// cachedScanDataRevs: revisions of fed registry/repo scan data that managed cluster remembers
// masterScanDataRevs: revisions of the current fed registry/repo scan data from master cluster
func (m CacheMethod) GetFedScanResultMD5(cachedScanDataRevs, masterScanDataRevs api.RESTFedScanDataRevs) map[string]map[string]string {

	fedScanDataCacheMutexRLock()
	defer fedScanDataCacheMutexRUnlock()

	scanResultMD5 := make(map[string]map[string]string, len(fedScanResultMD5)) // registry name : image id : scan result md5
	// iterate thru all fed registry/repo that managed cluster remembers
	// collect scan result md5 of images in the fed registry/repo who have different scan data revision from what master cluster has
	for regName, cachedImagesMD5 := range fedScanResultMD5 {
		if regName == common.RegistryFedRepoScanName {
			if cachedScanDataRevs.ScannedRepoRev == masterScanDataRevs.ScannedRepoRev {
				continue
			}
			// now we know fed repo on managed cluster has different scan data revision from what master cluster has
			imagesMD5 := make(map[string]string, len(cachedImagesMD5)) // image id : scan result md5
			for imageID, md5 := range cachedImagesMD5 {
				imagesMD5[imageID] = md5
			}
			scanResultMD5[regName] = imagesMD5
		} else {
			if cachedRegRev, ok1 := cachedScanDataRevs.ScannedRegRevs[regName]; ok1 {
				if masterRegRev, ok2 := masterScanDataRevs.ScannedRegRevs[regName]; !ok2 {
					// the fed registry is deleted on master cluster
					delete(cachedScanDataRevs.ScannedRegRevs, regName)
					_ = clusHelper.DeleteRegistryKeys(regName)
					_ = clusHelper.DeleteRegistry(nil, regName)
				} else if cachedRegRev != masterRegRev {
					// the fed registry on managed cluster has different scan data revision from what master cluster has. collect scan result md5 of images in the fed registry
					imagesMD5 := make(map[string]string, len(cachedImagesMD5)) // image id : scan result md5
					for imageID, md5 := range cachedImagesMD5 {
						imagesMD5[imageID] = md5
					}
					scanResultMD5[regName] = imagesMD5
				}
			}
		}
	}

	return scanResultMD5
}

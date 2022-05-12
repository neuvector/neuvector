package cache

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

type fedClusterCache struct { // only master cluster needs to get/set this cache
	cluster    *share.CLUSFedJointClusterInfo
	tokenCache map[string]string // key is mainSessionID (from claim.id in login token of master cluster). value is token with admin role
}

type tFedSettingsCache struct {
	revisions map[string]uint64
	settings  []byte
}

// On master cluster, it stores the revision of all types of fed rules.
// On joint cluster, it stores the last downloaded revision of all types of fed rules.
var fedRulesRevisionCache share.CLUSFedRulesRevision

var cachedFedSettingsRev map[string]uint64
var cachedFedSettingBytes []byte

var fedMembershipCache share.CLUSFedMembership
var fedJoinedClustersCache = make(map[string]*fedClusterCache) // key is cluster id
var fedJoinedClusterStatusCache = make(map[string]int)         // key is cluster id, value ex: _fedClusterJoined, _fedClusterSynced
var fedCacheMutex sync.RWMutex                                 // for accessing fedMembershipCache/fedJoinedClustersCache/fedJoinedClusterStatusCache

func fedInit() {
	m := clusHelper.GetFedMembership()
	if m == nil {
		m = &share.CLUSFedMembership{}
		clusHelper.PutFedMembership(m)
	}
	l := clusHelper.GetFedJointClusterList()
	if l == nil {
		l = &share.CLUSFedJoinedClusterList{IDs: make([]string, 0)}
		clusHelper.PutFedJointClusterList(l)
	}

	revCache, _ := clusHelper.GetFedRulesRevisionRev()
	if revCache == nil || len(revCache.Revisions) == 0 {
		clusHelper.UpdateFedRulesRevision(nil)
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
			clusHelper.PutFedRulesRevision(nil, revCache)
		}
		fedRulesRevisionCache.Revisions = revCache.Revisions
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

func serializeFile(fileName string, dataBase64 string) {
	if len(dataBase64) > 0 {
		_, err := os.Stat(fileName)
		if err != nil && os.IsNotExist(err) {
			if data, err := base64.StdEncoding.DecodeString(dataBase64); err == nil {
				if err = ioutil.WriteFile(fileName, data, 0600); err == nil {
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

func purgeFiles(fileNamePrefix string) {
	dir := "/etc/neuvector/certs"
	pathPrefix := fmt.Sprintf("%s/%s", dir, fileNamePrefix)
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if info != nil && strings.Index(path, pathPrefix) == 0 {
			os.Remove(path)
		}
		return nil
	})
}

func fedConfigUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	log.Debug()

	cfgType := share.CLUSFedKey2CfgKey(key)
	fedCacheMutexLock()
	defer fedCacheMutexUnlock()

	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		switch cfgType {
		case share.CLUSFedMembershipSubKey:
			var m share.CLUSFedMembership
			var dec common.DecryptUnmarshaller
			dec.Unmarshal(value, &m)
			log.WithFields(log.Fields{"role": m.FedRole}).Info()
			if m.FedRole == api.FedRoleMaster {
				access.UpdateUserRoleForFedRoleChange(api.FedRoleMaster)
				kv.GetFedCaCertPath(m.MasterCluster.ID)
				go cctx.StartStopFedPingPollFunc(share.StartFedRestServer, m.PingInterval, nil)
			} else if m.FedRole == api.FedRoleJoint {
				var param interface{} = &m.JointCluster
				if err := cctx.StartStopFedPingPollFunc(share.JointLoadOwnKeys, 0, param); err == nil {
					//serializeFile(masterCaCertPath, m.MasterCluster.CACert)
					go cctx.StartStopFedPingPollFunc(share.StartPollFedMaster, m.PollInterval, nil)
				}
			} else if m.FedRole == api.FedRoleNone {
				access.UpdateUserRoleForFedRoleChange(api.FedRoleNone)
				cctx.StartStopFedPingPollFunc(share.PurgeJointKeys, 0, nil)
				go cctx.StartStopFedPingPollFunc(share.StopFedRestServer, 0, nil)
				purgeFiles("fed.master.")
				purgeFiles("fed.client.")
				fedSystemConfigCache = share.CLUSSystemConfig{CfgType: share.FederalCfg}
			}
			fedMembershipCache = m
		case share.CLUSFedClustersSubKey:
			id := share.CLUSFedKey2ClusterIdKey(key)
			if id != "" {
				var cluster share.CLUSFedJointClusterInfo
				var dec common.DecryptUnmarshaller
				dec.Unmarshal(value, &cluster)
				cache, ok := fedJoinedClustersCache[id]
				if cache == nil || !ok {
					log.WithFields(log.Fields{"id": id}).Info("add")
					cache = &fedClusterCache{
						cluster:    &cluster,
						tokenCache: make(map[string]string),
					}
					var param interface{} = &cluster
					cctx.StartStopFedPingPollFunc(share.MasterLoadJointKeys, 0, param)
					fedJoinedClustersCache[id] = cache
				} else {
					if cache.cluster.Name != cluster.Name {
						cache.cluster.Name = cluster.Name
					}
					cache.cluster.Disabled = cluster.Disabled
					cache.cluster.ProxyRequired = cluster.ProxyRequired
				}
				if isLeader() && cluster.Disabled {
					data := share.CLUSFedClusterStatus{Status: 207} // _fedLicenseDisallowed
					clusHelper.PutFedJointClusterStatus(id, &data)
				}
			}
		case share.CLUSFedClustersStatusSubKey:
			id := share.CLUSFedKey2ClusterIdKey(key)
			var status share.CLUSFedClusterStatus
			json.Unmarshal(value, &status)
			fedJoinedClusterStatusCache[id] = status.Status
		case share.CLUSFedRulesRevisionSubKey:
			var revCache share.CLUSFedRulesRevision
			json.Unmarshal(value, &revCache)
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
							clusHelper.PutFedMembership(m)
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
				json.Unmarshal(value, &doPingPoll)
				go cctx.StartStopFedPingPollFunc(doPingPoll.Cmd, doPingPoll.FullPolling, nil)
			}
		case share.CFGEndpointSystem:
			var cfg share.CLUSSystemConfig
			json.Unmarshal(value, &cfg)
			fedWebhookCacheTemp := make(map[string]*webhookCache, 0)
			for _, h := range cfg.Webhooks {
				if h.Enable {
					fedWebhookCacheTemp[h.Name] = &webhookCache{conn: common.NewWebHook(h.Url), target: h.Type}
				}
			}
			fedWebhookCacheMap = fedWebhookCacheTemp
			fedSystemConfigCache = cfg
		}
	case cluster.ClusterNotifyDelete:
		switch cfgType {
		case share.CLUSFedClustersListSubKey:
			fedJoinedClustersCache = make(map[string]*fedClusterCache)
			fedJoinedClusterStatusCache = make(map[string]int)
		case share.CLUSFedClustersSubKey:
			id := share.CLUSFedKey2ClusterIdKey(key)
			if _, ok := fedJoinedClustersCache[id]; ok {
				log.WithFields(log.Fields{"id": id}).Info("del")
				delete(fedJoinedClustersCache, id)
				purgeFiles(fmt.Sprintf("fed.client.%s.", id))
				var param interface{} = &id
				cctx.StartStopFedPingPollFunc(share.MasterUnloadJointKeys, 0, param)
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

	if !acc.Authorize(&fedMembershipCache, nil) {
		return "", common.ErrObjectAccessDenied
	}

	return fedMembershipCache.FedRole, nil
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
		s.JointClusters = make([]*api.RESTFedJointClusterInfo, 0, len(fedJoinedClustersCache))
		for _, c := range fedJoinedClustersCache {
			jointCluster := &api.RESTFedJointClusterInfo{
				Name:          c.cluster.Name,
				ID:            c.cluster.ID,
				RestInfo:      c.cluster.RestInfo,
				ProxyRequired: c.cluster.ProxyRequired,
			}
			if status, ok := fedJoinedClusterStatusCache[c.cluster.ID]; ok && status > 0 {
				jointCluster.Status = statusMap[status]
			}
			s.JointClusters = append(s.JointClusters, jointCluster)
		}
		sort.Slice(s.JointClusters, func(i, j int) bool { return s.JointClusters[i].Name < s.JointClusters[j].Name })
	case api.FedRoleJoint:
		s.MasterCluster.Name = fedMembershipCache.MasterCluster.Name
		if status, ok := fedJoinedClusterStatusCache[s.MasterCluster.ID]; ok && status > 0 {
			s.MasterCluster.Status = statusMap[status]
		}
		local := &api.RESTFedJointClusterInfo{
			Name:     m.GetSystemConfigClusterName(acc),
			ID:       fedMembershipCache.JointCluster.ID,
			RestInfo: fedMembershipCache.JointCluster.RestInfo,
		}
		if status, ok := fedJoinedClusterStatusCache[fedMembershipCache.JointCluster.ID]; ok && status > 0 {
			local.Status = statusMap[status]
		}
		s.JointClusters = []*api.RESTFedJointClusterInfo{local}
	}

	return s, nil
}

// return rest info, use system https/http proxy or not
func (m CacheMethod) GetFedLocalRestInfo(acc *access.AccessControl) (share.CLUSRestServerInfo, string) {
	fedCacheMutexRLock()
	defer fedCacheMutexRUnlock()

	useProxy := fedMembershipCache.UseProxy
	if acc.Authorize(&fedMembershipCache, nil) {
		return fedMembershipCache.LocalRestInfo, useProxy
	}
	return share.CLUSRestServerInfo{}, ""
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

	if acc.Authorize(&fedMembershipCache, nil) {
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

	if acc.Authorize(&fedMembershipCache, nil) {
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

	if acc.Authorize(&fedMembershipCache, nil) {
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

	if acc.Authorize(&fedMembershipCache, nil) {
		if c, ok := fedJoinedClustersCache[id]; ok && c != nil && c.cluster != nil {
			return *c.cluster
		}
	}
	return share.CLUSFedJointClusterInfo{}
}

func (m CacheMethod) GetFedJoinedClusterStatus(id string, acc *access.AccessControl) int {
	fedCacheMutexRLock()
	defer fedCacheMutexRUnlock()

	if acc.Authorize(&fedMembershipCache, nil) {
		if s, ok := fedJoinedClusterStatusCache[id]; ok && s > 0 {
			return s
		}
	}
	return -1
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

	if c, ok := fedJoinedClustersCache[id]; ok && c != nil {
		if token == "" {
			delete(c.tokenCache, mainSessionID)
		} else {
			c.tokenCache[mainSessionID] = token
		}
	}
}

// only called by master cluster. caller doesn't own cache lock
func (m CacheMethod) GetFedRules(reqRevs map[string]uint64, acc *access.AccessControl) ([]byte, map[string]uint64, error) {
	var current *api.RESTFedRulesSettings
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
	if len(askRevMap) == 0 {
		return nil, askRevMap, nil
	} else {
		if len(cachedFedSettingBytes) > 0 {
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
				settings := make([]byte, len(cachedFedSettingBytes))
				copy(settings, cachedFedSettingBytes)
				return settings, askRevMap, nil
			}
		}
	}
	cacheMutexRLock()
	for ruleType, fedRev := range askRevMap {
		if current == nil {
			current = &api.RESTFedRulesSettings{}
		}
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
	var settings []byte
	if current != nil {
		settings, _ = json.Marshal(*current)
	}
	cacheMutexRUnlock()

	if cachedFedSettingBytes == nil {
		tempSettings := make([]byte, len(settings))
		copy(tempSettings, settings)
		cachedFedSettingsRev = askRevMap
		cachedFedSettingBytes = tempSettings
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

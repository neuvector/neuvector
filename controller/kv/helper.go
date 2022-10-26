package kv

import (
	"bytes"
	"crypto/md5"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/container"
	"github.com/neuvector/neuvector/share/utils"
)

type MockKvConfigUpdateFunc func(nType cluster.ClusterNotifyType, key string, value []byte)

type LogEventFunc func(share.TLogEvent, time.Time, int, string)

type ClusterHelper interface {
	AcquireLock(key string, wait time.Duration) (cluster.LockInterface, error)
	ReleaseLock(cluster.LockInterface) error

	UpgradeClusterKV()
	UpgradeClusterImport(ver *share.CLUSCtrlVersion)
	FixMissingClusterKV()

	PutInstallationID() (string, error)
	GetInstallationID() (string, error)

	GetAllControllers() []*share.CLUSController
	GetAllEnforcers() []*share.CLUSAgent

	SetCtrlState(key string) error
	UnsetCtrlState(key string)
	GetCtrlState(key string) bool

	GetSystemConfigRev(acc *access.AccessControl) (*share.CLUSSystemConfig, uint64)
	PutSystemConfigRev(conf *share.CLUSSystemConfig, rev uint64) error
	GetScanConfigRev(acc *access.AccessControl) (*share.CLUSScanConfig, uint64)
	GetFedSystemConfigRev(acc *access.AccessControl) (*share.CLUSSystemConfig, uint64)
	PutFedSystemConfigRev(conf *share.CLUSSystemConfig, rev uint64) error

	GetDomain(name string, acc *access.AccessControl) (*share.CLUSDomain, uint64, error)
	PutDomain(cd *share.CLUSDomain, rev uint64) error
	PutDomainIfNotExist(cd *share.CLUSDomain) error
	DeleteDomain(name string) error

	GetAllLearnedGroups(acc *access.AccessControl) map[string]*share.CLUSGroup
	GetAllGroups(scope string, acc *access.AccessControl) map[string]*share.CLUSGroup
	GetAllGroupNames(scope string) utils.Set
	GetGroup(name string, acc *access.AccessControl) (*share.CLUSGroup, uint64, error)
	PutGroup(group *share.CLUSGroup, create bool) error
	PutGroupRev(group *share.CLUSGroup, rev uint64) error
	PutGroupTxn(txn *cluster.ClusterTransact, group *share.CLUSGroup) error
	DeleteGroup(name string) error
	DeleteGroupTxn(txn *cluster.ClusterTransact, name string) error

	GetPolicyRuleList() []*share.CLUSRuleHead
	PutPolicyRuleList(crhs []*share.CLUSRuleHead) error
	PutPolicyRuleListTxn(txn *cluster.ClusterTransact, crhs []*share.CLUSRuleHead) error
	PutPolicyRuleListZip(key string, array []byte) error
	GetPolicyRule(id uint32) (*share.CLUSPolicyRule, uint64)
	PutPolicyRule(rule *share.CLUSPolicyRule) error
	PutPolicyRuleTxn(txn *cluster.ClusterTransact, rule *share.CLUSPolicyRule) error
	PutPolicyRuleRev(rule *share.CLUSPolicyRule, rev uint64) error
	DeletePolicyRule(id uint32) error
	DeletePolicyRuleTxn(txn *cluster.ClusterTransact, id uint32) error
	PutPolicyVer(s *share.CLUSGroupIPPolicyVer) error

	GetResponseRuleList(policyName string) []*share.CLUSRuleHead
	PutResponseRuleList(policyName string, crhs []*share.CLUSRuleHead) error
	PutResponseRuleListTxn(policyName string, txn *cluster.ClusterTransact, crhs []*share.CLUSRuleHead) error
	GetResponseRule(policyName string, id uint32) (*share.CLUSResponseRule, uint64)
	PutResponseRule(policyName string, rule *share.CLUSResponseRule) error
	PutResponseRuleTxn(policyName string, txn *cluster.ClusterTransact, rule *share.CLUSResponseRule) error
	PutResponseRuleRev(policyName string, rule *share.CLUSResponseRule, rev uint64) error
	DeleteResponseRule(policyName string, id uint32) error
	DeleteResponseRuleTxn(policyName string, txn *cluster.ClusterTransact, id uint32) error

	GetAllServers(acc *access.AccessControl) map[string]*share.CLUSServer
	GetServerRev(name string, acc *access.AccessControl) (*share.CLUSServer, uint64, error)
	PutServerRev(server *share.CLUSServer, rev uint64) error
	PutServerIfNotExist(server *share.CLUSServer) error
	DeleteServer(name string) error

	GetAllUsers(acc *access.AccessControl) map[string]*share.CLUSUser
	GetAllUsersNoAuth() map[string]*share.CLUSUser
	GetUserRev(fullname string, acc *access.AccessControl) (*share.CLUSUser, uint64, error)
	PutUserRev(user *share.CLUSUser, rev uint64) error
	PutUser(user *share.CLUSUser) error
	CreateUser(user *share.CLUSUser) error
	DeleteUser(fullname string) error

	GetProcessProfile(group string) *share.CLUSProcessProfile
	PutProcessProfile(group string, pg *share.CLUSProcessProfile) error
	PutProcessProfileTxn(txn *cluster.ClusterTransact, group string, pg *share.CLUSProcessProfile) error
	PutProcessProfileIfNotExist(group string, pg *share.CLUSProcessProfile) error
	DeleteProcessProfile(group string) error
	DeleteProcessProfileTxn(txn *cluster.ClusterTransact, group string) error
	GetAllProcessProfileSubKeys(scope string) utils.Set

	GetScanner(id string, acc *access.AccessControl) *share.CLUSScanner
	GetAllScanner(acc *access.AccessControl) []*share.CLUSScanner
	PutScannerTxn(txn *cluster.ClusterTransact, s *share.CLUSScanner) error
	DeleteScanner(id string) error
	GetScannerStats(id string) (*share.CLUSScannerStats, error)
	CreateScannerStats(id string) error
	PutScannerStats(id string, objType share.ScanObjectType, result *share.ScanResult) error
	GetScannerDB(store string) []*share.CLUSScannerDB

	GetScanReport(key string) *share.CLUSScanReport
	GetScanState(key string) *share.CLUSScanState

	GetAllComplianceProfiles(acc *access.AccessControl) []*share.CLUSComplianceProfile
	GetComplianceProfile(name string, acc *access.AccessControl) (*share.CLUSComplianceProfile, uint64, error)
	PutComplianceProfile(cp *share.CLUSComplianceProfile, rev uint64) error
	PutComplianceProfileIfNotExist(cp *share.CLUSComplianceProfile) error

	GetAllVulnerabilityProfiles(acc *access.AccessControl) []*share.CLUSVulnerabilityProfile
	GetVulnerabilityProfile(name string, acc *access.AccessControl) (*share.CLUSVulnerabilityProfile, uint64, error)
	PutVulnerabilityProfile(cp *share.CLUSVulnerabilityProfile, rev uint64) error
	PutVulnerabilityProfileIfNotExist(cp *share.CLUSVulnerabilityProfile) error

	GetRegistry(name string, acc *access.AccessControl) (*share.CLUSRegistryConfig, uint64, error)
	GetAllRegistry(scope string) []*share.CLUSRegistryConfig
	PutRegistry(config *share.CLUSRegistryConfig, rev uint64) error
	PutRegistryIfNotExist(config *share.CLUSRegistryConfig) error
	DeleteRegistry(txn *cluster.ClusterTransact, name string) error
	DeleteRegistryKeys(name string) error
	PutRegistryState(name string, state *share.CLUSRegistryState) error
	GetRegistryState(name string) *share.CLUSRegistryState
	PutRegistryImageSummary(name, id string, sum *share.CLUSRegistryImageSummary) error
	GetRegistryImageSummary(name, id string) *share.CLUSRegistryImageSummary
	PutRegistryImageSummaryAndReport(name, id, fedRole string, sum *share.CLUSRegistryImageSummary, report *share.CLUSScanReport) error
	DeleteRegistryImageSummaryAndReport(name, id, fedRole string) error
	UpdateFedScanDataRevisions(regOp, scanDataOp, regName, id string) error
	GetFedScanRevisions() (share.CLUSFedScanRevisions, uint64, error)
	PutFedScanRevisions(scanRevs *share.CLUSFedScanRevisions, rev *uint64) error

	GetAllFileMonitorProfile() map[string]*share.CLUSFileMonitorProfile
	GetAllFileMonitorProfileSubKeys(scope string) utils.Set
	GetFileMonitorProfile(name string) (*share.CLUSFileMonitorProfile, uint64)
	PutFileMonitorProfile(name string, conf *share.CLUSFileMonitorProfile, rev uint64) error
	PutFileMonitorProfileIfNotExist(name string, conf *share.CLUSFileMonitorProfile) error
	PutFileMonitorProfileTxn(txn *cluster.ClusterTransact, name string, conf *share.CLUSFileMonitorProfile) error
	DeleteFileMonitor(name string) error
	DeleteFileMonitorTxn(txn *cluster.ClusterTransact, name string) error

	GetAdmissionCertRev(svcName string) (*share.CLUSAdmissionCertCloaked, uint64) // obsolete
	GetObjectCertRev(cn string) (*share.CLUSX509Cert, uint64, error)
	PutObjectCert(cn, keyPath, certPath string, cert *share.CLUSX509Cert) error
	GetAdmissionStateRev(svcName string) (*share.CLUSAdmissionState, uint64)
	PutAdmissionRule(admType, ruleType string, rule *share.CLUSAdmissionRule) error
	PutAdmissionStateRev(svcName string, state *share.CLUSAdmissionState, rev uint64) error
	GetAdmissionRuleList(admType, ruleType string) ([]*share.CLUSRuleHead, error)
	PutAdmissionRuleList(admType, ruleType string, crhs []*share.CLUSRuleHead) error
	GetAdmissionRule(admType, ruleType string, id uint32) *share.CLUSAdmissionRule
	DeleteAdmissionRule(admType, ruleType string, id uint32) error
	GetAdmissionStatsRev() (*share.CLUSAdmissionStats, uint64)
	PutAdmissionStatsRev(stats *share.CLUSAdmissionStats, rev uint64) error
	// transaction APIs:
	PutAdmissionRuleTxn(txn *cluster.ClusterTransact, admType, ruleType string, rule *share.CLUSAdmissionRule) error
	PutAdmissionRuleListTxn(txn *cluster.ClusterTransact, admType, ruleType string, crhs []*share.CLUSRuleHead) error
	DeleteAdmissionRuleTxn(txn *cluster.ClusterTransact, admType, ruleType string, id uint32) error

	GetFileAccessRule(name string) (*share.CLUSFileAccessRule, uint64)
	PutFileAccessRule(name string, conf *share.CLUSFileAccessRule, rev uint64) error
	PutFileAccessRuleIfNotExist(name string, conf *share.CLUSFileAccessRule) error
	PutFileAccessRuleTxn(txn *cluster.ClusterTransact, name string, conf *share.CLUSFileAccessRule) error
	DeleteFileAccessRule(name string) error
	DeleteFileAccessRuleTxn(txn *cluster.ClusterTransact, name string) error
	GetAllFileAccessRuleSubKeys(scope string) utils.Set
	GetCrdSecurityRuleRecord(crdKind, crdName string) *share.CLUSCrdSecurityRule
	PutCrdSecurityRuleRecord(crdKind, crdName string, rules *share.CLUSCrdSecurityRule) error
	DeleteCrdSecurityRuleRecord(crdKind, crdName string) error
	GetCrdSecurityRuleRecordList(crdKind string) map[string]*share.CLUSCrdSecurityRule

	GetFedMembership() *share.CLUSFedMembership
	PutFedMembership(s *share.CLUSFedMembership) error
	GetFedJointClusterList() *share.CLUSFedJoinedClusterList
	PutFedJointClusterList(list *share.CLUSFedJoinedClusterList) error
	PutFedJointClusterStatus(id string, status *share.CLUSFedClusterStatus) error
	DeleteFedJointClusterStatus(id string) error
	GetFedJointCluster(id string) *share.CLUSFedJointClusterInfo
	PutFedJointCluster(jointCluster *share.CLUSFedJointClusterInfo) error
	DeleteFedJointCluster(id string) error
	GetFedRulesRevisionRev() (*share.CLUSFedRulesRevision, uint64)
	UpdateFedRulesRevision(ruleTypes []string) bool
	PutFedRulesRevision(txn *cluster.ClusterTransact, settings *share.CLUSFedRulesRevision) error
	FedTriggerInstantPingPoll(cmd, fullPolling uint32)
	EnableDisableJointClusters(ids []string, toDisable bool, fedKeyLocked bool)
	ConfigFedRole(userName, role string, acc *access.AccessControl) error
	GetFedSettings() share.CLUSFedSettings
	PutFedSettings(txn *cluster.ClusterTransact, cfg share.CLUSFedSettings) error

	GetDlpSensor(name string) *share.CLUSDlpSensor
	GetAllDlpSensors() []*share.CLUSDlpSensor
	PutDlpSensor(sensor *share.CLUSDlpSensor, create bool) error
	PutDlpSensorTxn(txn *cluster.ClusterTransact, sensor *share.CLUSDlpSensor) error
	DeleteDlpSensor(name string) error
	DeleteDlpSensorTxn(txn *cluster.ClusterTransact, name string) error
	GetDlpGroup(group string) *share.CLUSDlpGroup
	PutDlpGroup(group *share.CLUSDlpGroup, create bool) error
	PutDlpGroupTxn(txn *cluster.ClusterTransact, group *share.CLUSDlpGroup) error
	DeleteDlpGroup(group string) error

	GetWafSensor(name string) *share.CLUSWafSensor
	GetAllWafSensors() []*share.CLUSWafSensor
	PutWafSensor(sensor *share.CLUSWafSensor, create bool) error
	PutWafSensorTxn(txn *cluster.ClusterTransact, sensor *share.CLUSWafSensor) error
	DeleteWafSensor(name string) error
	DeleteWafSensorTxn(txn *cluster.ClusterTransact, name string) error
	GetWafGroup(group string) *share.CLUSWafGroup
	PutWafGroup(group *share.CLUSWafGroup, create bool) error
	PutWafGroupTxn(txn *cluster.ClusterTransact, group *share.CLUSWafGroup) error
	DeleteWafGroup(group string) error

	GetCustomCheckConfig(name string) (*share.CLUSCustomCheckGroup, uint64)
	GetAllCustomCheckConfig() map[string]*share.CLUSCustomCheckGroup
	PutCustomCheckConfig(name string, conf *share.CLUSCustomCheckGroup, rev uint64) error
	DeleteCustomCheckConfig(name string) error

	GetCrdRecord(string) *share.CLUSCrdRecord
	PutCrdRecord(*share.CLUSCrdRecord, string) error
	DeleteCrdRecord(string) error
	GetCrdEventQueue() *share.CLUSCrdEventRecord
	PutCrdEventQueue(*share.CLUSCrdEventRecord) error

	GetAwsCloudResource(projectName string) (*share.CLUSAwsResource, error)
	PutAwsCloudResource(project *share.CLUSAwsResource) error
	DeleteAwsCloudResource(projectName string) error
	GetAwsLambda(project, region, funcName string) *share.CLUSAwsFuncScanOutputList
	PutAwsLambda(project, region, funcName string, output *share.CLUSAwsFuncScanOutputList) error
	DeleteAwsLambda(project, region, funcName string) error
	DeleteAwsProjectCfg(projectName string) error
	GetAwsProjectCfg(projectName string, acc *access.AccessControl) (*share.CLUSAwsProjectCfg, error)
	PutAwsProjectCfg(projectName string, record *share.CLUSAwsProjectCfg) error
	// custom roles
	GetAllCustomRoles(acc *access.AccessControl) map[string]*share.CLUSUserRole
	GetCustomRoleRev(name string, acc *access.AccessControl) (*share.CLUSUserRole, uint64, error)
	PutCustomRoleRev(user *share.CLUSUserRole, rev uint64, acc *access.AccessControl) error
	CreateCustomRole(user *share.CLUSUserRole, acc *access.AccessControl) error
	DeleteCustomRole(name string) error

	//
	DuplicateNetworkKey(key string, value []byte) error
	DuplicateNetworkKeyTxn(txn *cluster.ClusterTransact, key string, value []byte) error
	RestoreNetworkKeys()
	DuplicateNetworkSystemKeyTxn(txn *cluster.ClusterTransact, key string, value []byte) error

	// password profile
	GetAllPwdProfiles(acc *access.AccessControl) map[string]*share.CLUSPwdProfile
	GetPwdProfileRev(name string, acc *access.AccessControl) (*share.CLUSPwdProfile, uint64, error)
	PutPwdProfileRev(profile *share.CLUSPwdProfile, rev uint64) error
	DeletePwdProfile(name string) error
	GetActivePwdProfileName() string
	PutActivePwdProfileName(name string) error

	// import task
	GetImportTask() (share.CLUSImportTask, error)
	PutImportTask(importTask *share.CLUSImportTask) error

	// mock for unittest
	SetCacheMockCallback(keyStore string, mockFunc MockKvConfigUpdateFunc)
}

type clusterHelper struct {
	id      string
	version string
	persist bool
}

var clusHelperImpl *clusterHelper
var clusHelper ClusterHelper

func newClusterHelper(id, version string, persist bool) ClusterHelper {
	clusHelperImpl = new(clusterHelper)
	clusHelperImpl.id = id
	clusHelperImpl.version = version
	clusHelperImpl.persist = persist
	return clusHelperImpl
}

func GetClusterHelper() ClusterHelper {
	return clusHelperImpl
}

func getAllSubKeys(scope, store string) utils.Set {
	groups := utils.NewSet()

	var getLocal, getFed bool
	switch scope {
	case share.ScopeLocal:
		getLocal = true
	case share.ScopeFed:
		getFed = true
	}
	keys, _ := cluster.GetStoreKeys(store)
	for _, key := range keys {
		name := share.CLUSFileMonitorKey2Group(key)
		if strings.HasPrefix(name, api.FederalGroupPrefix) {
			if getFed {
				groups.Add(name)
			}
		} else if getLocal {
			groups.Add(name)
		}
	}

	return groups
}

var enc common.EncryptMarshaller
var dec common.DecryptUnmarshaller

// This is simplified version of locking, caller not be able to stop wait and not be able to
// get notified when lock is lock.
func (m clusterHelper) AcquireLock(key string, wait time.Duration) (cluster.LockInterface, error) {
	lock, err := cluster.NewLock(key, wait)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "key": key}).Error("Create lock error")
		return nil, err
	} else if lock == nil {
		err = fmt.Errorf("Failed to create lock")
		log.WithFields(log.Fields{"error": err, "key": key}).Error("Create lock error")
		return nil, err
	}

	stopCh := make(<-chan struct{})
	lostCh, err := lock.Lock(stopCh)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "key": key}).Error("Acquire lock error")
		return nil, err
	} else if lostCh == nil {
		err = fmt.Errorf("Unable to acquire lock after %v", wait)
		if value, _ := cluster.Get(share.CLUSCtrlDistLockKey(key)); value != nil {
			// Print locked-by info
			var locker share.CLUSDistLocker
			json.Unmarshal(value, &locker)
			log.WithFields(log.Fields{
				"key":         key,
				"caller":      utils.GetCaller(2, []string{"AcquireLock", "lockClusKey"}),
				"locked-by":   container.ShortContainerId(locker.LockedBy),
				"lock-caller": locker.Caller,
				"locked-at":   api.RESTTimeString(locker.LockedAt),
			}).Error("Acquire lock error: " + err.Error())
		} else {
			log.WithFields(log.Fields{"key": key}).Error("Acquire lock error: " + err.Error())
		}
		return nil, err
	}

	// Write locked-by info
	// 0: callers(), 1: GetCaller(), 2: AcquireLock(), 3: lockClusKey()
	fn := utils.GetCaller(2, []string{"AcquireLock", "lockClusKey"})
	locker := &share.CLUSDistLocker{LockedBy: m.id, Caller: fn, LockedAt: time.Now()}
	value, _ := json.Marshal(locker)
	cluster.Put(share.CLUSCtrlDistLockKey(key), value)

	return lock, nil
}

func (m clusterHelper) ReleaseLock(lock cluster.LockInterface) error {
	// Delete locked-by key
	cluster.Delete(share.CLUSCtrlDistLockKey(lock.Key()))
	return lock.Unlock()
}

func (m clusterHelper) get(key string) ([]byte, uint64, error) {
	value, rev, err := cluster.GetRev(key)
	if err != nil || value == nil {
		return nil, rev, err
	} else {
		var wrt bool
		if value, err, wrt = UpgradeAndConvert(key, value); wrt {
			value, rev, err = cluster.GetRev(key)
			// [31, 139] is the first 2 bytes of gzip-format data
			if len(value) >= 2 && value[0] == 31 && value[1] == 139 &&
				(strings.HasPrefix(key, share.CLUSCrdProcStore) || strings.HasPrefix(key, share.CLUSConfigCrdStore)) {
				value = utils.GunzipBytes(value)
				if value == nil {
					err = fmt.Errorf("Failed to unzip data")
				}
			}
		}
		return value, rev, err
	}
}

func (m clusterHelper) putSizeAware(key string, value []byte) error {
	if len(value) >= cluster.KVValueSizeMax { // 512 * 1024
		zb := utils.GzipBytes(value)
		if len(zb) >= cluster.KVValueSizeMax { // 512 * 1024
			err := fmt.Errorf("zip data(%d) too big", len(zb))
			log.WithFields(log.Fields{"key": key}).Error(err)
			return err
		}
		return cluster.PutBinary(key, zb)
	} else {
		return cluster.Put(key, value)
	}
}

/*
func (m clusterHelper) putSizeAwareRev(key string, value []byte, rev uint64) error {
	if len(value) >= cluster.KVValueSizeMax { // 512 * 1024
		zb := utils.GzipBytes(value)
		if len(zb) >= cluster.KVValueSizeMax { // 512 * 1024
			err := fmt.Errorf("zip data(%d) too big", len(zb))
			log.WithFields(log.Fields{"key": key}).Error(err)
			return err
		}
		return cluster.PutBinaryRev(key, zb, rev)
	} else {
		return cluster.PutRev(key, value, rev)
	}
}

// do not consider UpgradeAndConvert yet. if need to do UpgradeAndConvert, value size needs to be considered in UpgradeAndConvert()
func (m clusterHelper) getGzipAware(key string) ([]byte, uint64, error) {
	value, rev, err := cluster.GetRev(key)
	if err != nil || value == nil {
		return nil, rev, err
	} else {
		// [31, 139] is the first 2 bytes of gzip-format data
		if len(value) >= 2 && value[0] == 31 && value[1] == 139 {
			value = utils.GunzipBytes(value)
			if value == nil {
				err = fmt.Errorf("Failed to unzip data")
			}
		}
		return value, rev, err
	}
}

*/
func (m clusterHelper) PutInstallationID() (string, error) {
	if id, _ := m.GetInstallationID(); id != "" {
		return id, nil
	}

	id, err := utils.GetGuid()
	if err != nil {
		return "", err
	}

	key := share.CLUSCtrlInstallationKey
	if err = cluster.Put(key, []byte(id)); err != nil {
		return "", err
	} else {
		return id, nil
	}
}

func (m clusterHelper) GetInstallationID() (string, error) {
	key := share.CLUSCtrlInstallationKey
	value, _, err := m.get(key)
	if value != nil {
		return string(value[:]), nil
	} else {
		return "", err
	}
}

func (m clusterHelper) GetAllEnforcers() []*share.CLUSAgent {
	store := share.CLUSAgentStore
	keys, _ := cluster.GetStoreKeys(store)
	all := make([]*share.CLUSAgent, 0)
	for _, key := range keys {
		if value, err := cluster.Get(key); err == nil {
			var agent share.CLUSAgent
			json.Unmarshal(value, &agent)
			all = append(all, &agent)
		} else {
			log.WithFields(log.Fields{"error": err}).Debug("")
		}
	}
	return all
}

func (m clusterHelper) GetAllControllers() []*share.CLUSController {
	store := share.CLUSControllerStore
	keys, _ := cluster.GetStoreKeys(store)
	all := make([]*share.CLUSController, 0)
	for _, key := range keys {
		if value, err := cluster.Get(key); err == nil {
			var ctrl share.CLUSController
			json.Unmarshal(value, &ctrl)
			all = append(all, &ctrl)
		} else {
			log.WithFields(log.Fields{"error": err}).Debug("")
		}
	}
	return all
}

func (m clusterHelper) SetCtrlState(key string) error {
	return cluster.Put(key, []byte(share.CLUSCtrlEnabledValue))
}

func (m clusterHelper) UnsetCtrlState(key string) {
	cluster.Delete(key)
}

func (m clusterHelper) GetCtrlState(key string) bool {
	value, _, _ := m.get(key)
	return value != nil
}

func (m clusterHelper) GetSystemConfigRev(acc *access.AccessControl) (*share.CLUSSystemConfig, uint64) {
	var conf share.CLUSSystemConfig

	key := share.CLUSConfigSystemKey
	value, rev, _ := m.get(key)
	if value != nil {
		json.Unmarshal(value, &conf)

		if !acc.Authorize(&conf, nil) {
			return nil, 0
		}

		return &conf, rev
	} else {
		// Cannot return &common.DefaultSystemConfig, the caller will change the content
		conf = common.DefaultSystemConfig

		if !acc.Authorize(&conf, nil) {
			return nil, 0
		}

		return &conf, 0
	}
}

func (m clusterHelper) PutSystemConfigRev(conf *share.CLUSSystemConfig, rev uint64) error {
	key := share.CLUSConfigSystemKey
	value, _ := enc.Marshal(conf)
	err := cluster.PutRev(key, value, rev)
	if err == nil {
		return cluster.Put(share.NetworkSystemKey, value)
	}
	return err
}

func (m clusterHelper) GetScanConfigRev(acc *access.AccessControl) (*share.CLUSScanConfig, uint64) {
	var conf share.CLUSScanConfig

	key := share.CLUSConfigScanKey
	value, rev, _ := m.get(key)
	if value != nil {
		json.Unmarshal(value, &conf)

		if !acc.Authorize(&conf, nil) {
			return nil, 0
		}

		return &conf, rev
	} else {
		if !acc.Authorize(&conf, nil) {
			return nil, 0
		}

		return &conf, 0
	}
}

func (m clusterHelper) GetFedSystemConfigRev(acc *access.AccessControl) (*share.CLUSSystemConfig, uint64) {
	var conf share.CLUSSystemConfig

	if !acc.Authorize(&conf, nil) {
		return nil, 0
	}

	key := share.CLUSFedKey(share.CFGEndpointSystem)
	value, rev, _ := m.get(key)
	if value != nil {
		json.Unmarshal(value, &conf)
		return &conf, rev
	} else {
		return &conf, 0
	}
}

func (m clusterHelper) PutFedSystemConfigRev(conf *share.CLUSSystemConfig, rev uint64) error {
	key := share.CLUSFedKey(share.CFGEndpointSystem)
	conf.CfgType = share.FederalCfg
	value, _ := enc.Marshal(conf)
	if rev == 0 {
		return cluster.Put(key, value)
	} else {
		return cluster.PutRev(key, value, rev)
	}
}

func (m clusterHelper) GetDomain(name string, acc *access.AccessControl) (*share.CLUSDomain, uint64, error) {
	key := share.CLUSDomainKey(name)
	if value, rev, _ := m.get(key); value != nil {
		var domain share.CLUSDomain
		json.Unmarshal(value, &domain)

		if !acc.Authorize(&domain, nil) {
			return nil, 0, common.ErrObjectAccessDenied
		}

		return &domain, rev, nil
	}
	return nil, 0, common.ErrObjectNotFound
}

func (m clusterHelper) PutDomainIfNotExist(domain *share.CLUSDomain) error {
	key := share.CLUSDomainKey(domain.Name)
	value, _ := enc.Marshal(domain)
	return cluster.PutIfNotExist(key, value, true)
}

func (m clusterHelper) PutDomain(domain *share.CLUSDomain, rev uint64) error {
	key := share.CLUSDomainKey(domain.Name)
	value, _ := enc.Marshal(domain)
	return cluster.PutRev(key, value, rev)
}

func (m clusterHelper) DeleteDomain(name string) error {
	key := share.CLUSDomainKey(name)
	return cluster.Delete(key)
}

func (m clusterHelper) GetAllLearnedGroups(acc *access.AccessControl) map[string]*share.CLUSGroup {
	groups := make(map[string]*share.CLUSGroup)

	store := share.CLUSConfigGroupStore
	keys, _ := cluster.GetStoreKeys(store)
	for _, key := range keys {
		if value, _, _ := m.get(key); value != nil {
			var group share.CLUSGroup
			json.Unmarshal(value, &group)
			if !acc.Authorize(&group, nil) {
				continue
			}

			if group.CfgType == share.Learned {
				groups[group.Name] = &group
			}
		}
	}

	return groups
}

// notice: for "fed" scope, groups of "external"/"nodes"/"containers" are also returned
func (m clusterHelper) GetAllGroups(scope string, acc *access.AccessControl) map[string]*share.CLUSGroup {
	groups := make(map[string]*share.CLUSGroup)

	var getLocal, getFed bool
	switch scope {
	case share.ScopeLocal:
		getLocal = true
	case share.ScopeFed:
		getFed = true
	}
	store := share.CLUSConfigGroupStore
	keys, _ := cluster.GetStoreKeys(store)
	for _, key := range keys {
		gprName := share.CLUSGroupKey2Name(key)
		if (getFed && strings.HasPrefix(gprName, api.FederalGroupPrefix)) || (getLocal && !strings.HasPrefix(gprName, api.FederalGroupPrefix)) {
			if value, _, _ := m.get(key); value != nil {
				var group share.CLUSGroup
				json.Unmarshal(value, &group)

				if !acc.Authorize(&group, nil) {
					continue
				}

				if (group.CfgType == share.FederalCfg && getFed) || (group.CfgType != share.FederalCfg && getLocal) ||
					group.Name == api.LearnedExternal {
					groups[group.Name] = &group
				}
			}
		}
	}

	return groups
}

func (m clusterHelper) GetAllGroupNames(scope string) utils.Set {
	return getAllSubKeys(scope, share.CLUSConfigGroupStore)
}

func (m clusterHelper) GetGroup(name string, acc *access.AccessControl) (*share.CLUSGroup, uint64, error) {
	var group share.CLUSGroup

	key := share.CLUSGroupKey(name)
	if value, rev, _ := m.get(key); value != nil {
		json.Unmarshal(value, &group)
		if !acc.Authorize(&group, nil) {
			return nil, 0, common.ErrObjectAccessDenied
		}
		return &group, rev, nil
	}
	return nil, 0, common.ErrObjectNotFound
}

func (m clusterHelper) PutGroup(group *share.CLUSGroup, create bool) error {
	key := share.CLUSGroupKey(group.Name)
	if group.ProfileMode == "" {
		group.ProfileMode = group.PolicyMode
	}

	value, _ := json.Marshal(group)
	if create {
		if err := cluster.PutIfNotExist(key, value, false); err != nil {
			return err
		}
		return m.DuplicateNetworkKeyIfNotExist(key, value)
	}

	m.DuplicateNetworkKey(key, value)
	return cluster.Put(key, value)
}

func (m clusterHelper) PutGroupRev(group *share.CLUSGroup, rev uint64) error {
	key := share.CLUSGroupKey(group.Name)
	if group.ProfileMode == "" {
		group.ProfileMode = group.PolicyMode
	}

	value, _ := json.Marshal(group)
	if err := cluster.PutRev(key, value, rev); err != nil {
		return err
	}

	return m.DuplicateNetworkKeyIfNotExist(key, value)
}

func (m clusterHelper) PutGroupTxn(txn *cluster.ClusterTransact, group *share.CLUSGroup) error {
	key := share.CLUSGroupKey(group.Name)
	if group.ProfileMode == "" {
		group.ProfileMode = group.PolicyMode
	}
	value, _ := json.Marshal(group)
	txn.Put(key, value)
	m.DuplicateNetworkKeyTxn(txn, key, value)
	return nil
}

func (m clusterHelper) DeleteGroup(name string) error {
	cluster.Delete(share.CLUSGroupKey(name))
	return cluster.Delete(share.CLUSGroupNetworkKey(name))
}

func (m clusterHelper) DeleteGroupTxn(txn *cluster.ClusterTransact, name string) error {
	txn.Delete(share.CLUSGroupKey(name))
	txn.Delete(share.CLUSGroupNetworkKey(name))

	return nil
}

// -- Policy

func (m clusterHelper) GetPolicyRuleList() []*share.CLUSRuleHead {
	crhs := make([]*share.CLUSRuleHead, 0)
	//since 3.2.1 rulelist key is changed to
	//CLUSPolicyZipRuleListKey from CLUSPolicyRuleListKey
	key := share.CLUSPolicyZipRuleListKey(share.DefaultPolicyName)
	if value, _, _ := m.get(key); value != nil {
		json.Unmarshal(value, &crhs)
		return crhs
	}

	return crhs
}

func (m clusterHelper) PutPolicyRuleList(crhs []*share.CLUSRuleHead) error {
	//since 3.2.1 rulelist key is changed to
	//CLUSPolicyZipRuleListKey from CLUSPolicyRuleListKey
	key := share.CLUSPolicyZipRuleListKey(share.DefaultPolicyName)
	value, _ := json.Marshal(crhs)
	zb := utils.GzipBytes(value)
	return cluster.PutBinary(key, zb)
}

func (m clusterHelper) PutPolicyRuleListTxn(txn *cluster.ClusterTransact, crhs []*share.CLUSRuleHead) error {
	// 	err := m.PutPolicyRuleList(crhs)
	// 	if err != nil {
	// 		log.WithFields(log.Fields{"error": err}).Error("Failed to write to cluster")
	// 	}
	// 	return err

	// transaction has 64-entry limitation ! multiple transactions are triggered in txn.Apply() if > 64 entries
	//since 3.2.1 rulelist key is changed to
	//CLUSPolicyZipRuleListKey from CLUSPolicyRuleListKey
	key := share.CLUSPolicyZipRuleListKey(share.DefaultPolicyName)
	value, _ := json.Marshal(crhs)
	zb := utils.GzipBytes(value)
	txn.PutBinary(key, zb)
	return nil
}

func (m clusterHelper) PutPolicyRuleListZip(key string, array []byte) error {
	zb := utils.GzipBytes(array)
	return cluster.PutBinary(key, zb)
}

func (m clusterHelper) GetPolicyRule(id uint32) (*share.CLUSPolicyRule, uint64) {
	key := share.CLUSPolicyRuleKey(share.DefaultPolicyName, id)
	if value, rev, _ := m.get(key); value != nil {
		var rule share.CLUSPolicyRule
		json.Unmarshal(value, &rule)
		return &rule, rev
	}

	return nil, 0
}

func (m clusterHelper) PutPolicyRule(rule *share.CLUSPolicyRule) error {
	key := share.CLUSPolicyRuleKey(share.DefaultPolicyName, rule.ID)
	value, _ := json.Marshal(rule)
	return cluster.Put(key, value)
}

func (m clusterHelper) PutPolicyRuleTxn(txn *cluster.ClusterTransact, rule *share.CLUSPolicyRule) error {
	// 	err := m.PutPolicyRule(rule)
	// 	if err != nil {
	// 		log.WithFields(log.Fields{"error": err}).Error("Failed to write to cluster")
	// 	}
	// 	return err

	// transaction has 64-entry limitation ! multiple transactions are triggered in txn.Apply() if > 64 entries
	key := share.CLUSPolicyRuleKey(share.DefaultPolicyName, rule.ID)
	value, _ := json.Marshal(rule)
	txn.Put(key, value)
	return nil
}

func (m clusterHelper) PutPolicyRuleRev(rule *share.CLUSPolicyRule, rev uint64) error {
	key := share.CLUSPolicyRuleKey(share.DefaultPolicyName, rule.ID)
	value, _ := json.Marshal(rule)
	return cluster.PutRev(key, value, rev)
}

func (m clusterHelper) DeletePolicyRule(id uint32) error {
	key := share.CLUSPolicyRuleKey(share.DefaultPolicyName, id)
	return cluster.Delete(key)
}

func (m clusterHelper) DeletePolicyRuleTxn(txn *cluster.ClusterTransact, id uint32) error {
	// 	err := m.DeletePolicyRule(id)
	// 	if err != nil {
	// 		log.WithFields(log.Fields{"error": err}).Error("Failed to write to cluster")
	// 	}
	// 	return err

	// transaction has 64-entry limitation ! multiple transactions are triggered in txn.Apply() if > 64 entries
	key := share.CLUSPolicyRuleKey(share.DefaultPolicyName, id)
	txn.Delete(key)
	return nil
}

func (m clusterHelper) PutPolicyVer(s *share.CLUSGroupIPPolicyVer) error {
	key := share.CLUSPolicyIPRulesKey(s.Key)
	value, _ := enc.Marshal(s)
	return cluster.Put(key, value)
}

// event policy

func (m clusterHelper) GetResponseRuleList(policyName string) []*share.CLUSRuleHead {
	crhs := make([]*share.CLUSRuleHead, 0)
	key := share.CLUSResponseRuleListKey(policyName)
	if value, _, _ := m.get(key); value != nil {
		json.Unmarshal(value, &crhs)
		return crhs
	}

	return crhs
}

func (m clusterHelper) GetResponseRule(policyName string, id uint32) (*share.CLUSResponseRule, uint64) {
	key := share.CLUSResponseRuleKey(policyName, id)
	if value, rev, _ := m.get(key); value != nil {
		var rule share.CLUSResponseRule
		json.Unmarshal(value, &rule)
		return &rule, rev
	}

	return nil, 0
}

func (m clusterHelper) PutResponseRuleList(policyName string, crhs []*share.CLUSRuleHead) error {
	key := share.CLUSResponseRuleListKey(policyName)
	value, _ := json.Marshal(crhs)
	return cluster.Put(key, value)
}

func (m clusterHelper) PutResponseRuleListTxn(policyName string, txn *cluster.ClusterTransact, crhs []*share.CLUSRuleHead) error {
	key := share.CLUSResponseRuleListKey(policyName)
	value, _ := json.Marshal(crhs)
	txn.Put(key, value)
	return nil
}

func (m clusterHelper) PutResponseRuleRev(policyName string, rule *share.CLUSResponseRule, rev uint64) error {
	key := share.CLUSResponseRuleKey(policyName, rule.ID)
	value, _ := json.Marshal(rule)
	return cluster.PutRev(key, value, rev)
}

func (m clusterHelper) PutResponseRule(policyName string, rule *share.CLUSResponseRule) error {
	key := share.CLUSResponseRuleKey(policyName, rule.ID)
	value, _ := json.Marshal(rule)
	return cluster.Put(key, value)
}

func (m clusterHelper) PutResponseRuleTxn(policyName string, txn *cluster.ClusterTransact, rule *share.CLUSResponseRule) error {
	key := share.CLUSResponseRuleKey(policyName, rule.ID)
	value, _ := json.Marshal(rule)
	txn.Put(key, value)
	return nil
}

func (m clusterHelper) DeleteResponseRule(policyName string, id uint32) error {
	key := share.CLUSResponseRuleKey(policyName, id)
	return cluster.Delete(key)
}

func (m clusterHelper) DeleteResponseRuleTxn(policyName string, txn *cluster.ClusterTransact, id uint32) error {
	key := share.CLUSResponseRuleKey(policyName, id)
	txn.Delete(key)
	return nil
}

// Server

func (m clusterHelper) GetAllServers(acc *access.AccessControl) map[string]*share.CLUSServer {
	servers := make(map[string]*share.CLUSServer)

	keys, _ := cluster.GetStoreKeys(share.CLUSConfigServerStore)
	for _, key := range keys {
		if value, _, _ := m.get(key); value != nil {
			var cs share.CLUSServer
			json.Unmarshal(value, &cs)

			if !acc.Authorize(&cs, nil) {
				continue
			}

			servers[cs.Name] = &cs
		}
	}

	return servers
}

func (m clusterHelper) GetServerRev(name string, acc *access.AccessControl) (*share.CLUSServer, uint64, error) {
	key := share.CLUSServerKey(name)
	if value, rev, _ := m.get(key); value != nil {
		var server share.CLUSServer
		json.Unmarshal(value, &server)

		if !acc.Authorize(&server, nil) {
			return nil, 0, common.ErrObjectAccessDenied
		}

		return &server, rev, nil
	}
	return nil, 0, common.ErrObjectNotFound
}

func (m clusterHelper) PutServerRev(server *share.CLUSServer, rev uint64) error {
	key := share.CLUSServerKey(server.Name)
	value, _ := enc.Marshal(server)
	return cluster.PutRev(key, value, rev)
}

func (m clusterHelper) PutServerIfNotExist(server *share.CLUSServer) error {
	key := share.CLUSServerKey(server.Name)
	value, _ := enc.Marshal(server)
	return cluster.PutIfNotExist(key, value, true)
}

func (m clusterHelper) DeleteServer(name string) error {
	key := share.CLUSServerKey(name)
	return cluster.Delete(key)
}

// User/User role

func (m clusterHelper) GetAllUsers(acc *access.AccessControl) map[string]*share.CLUSUser {
	users := make(map[string]*share.CLUSUser)

	keys, _ := cluster.GetStoreKeys(share.CLUSConfigUserStore)
	for _, key := range keys {
		if value, _, _ := m.get(key); value != nil {
			var user share.CLUSUser
			json.Unmarshal(value, &user)

			if !acc.Authorize(&user, nil) {
				continue
			}
			users[user.Fullname] = &user
		}
	}

	return users
}

// caller needs to decide whether to authorize accessing each returned user object
func (m clusterHelper) GetAllUsersNoAuth() map[string]*share.CLUSUser {
	users := make(map[string]*share.CLUSUser)

	keys, _ := cluster.GetStoreKeys(share.CLUSConfigUserStore)
	for _, key := range keys {
		if value, _, _ := m.get(key); value != nil {
			var user share.CLUSUser
			json.Unmarshal(value, &user)
			users[user.Fullname] = &user
		}
	}

	return users
}

func (m clusterHelper) GetUserRev(fullname string, acc *access.AccessControl) (*share.CLUSUser, uint64, error) {
	key := share.CLUSUserKey(url.QueryEscape(fullname))
	if value, rev, _ := m.get(key); value != nil {
		var user share.CLUSUser
		json.Unmarshal(value, &user)

		if !acc.Authorize(&user, nil) {
			return nil, 0, common.ErrObjectAccessDenied
		}

		return &user, rev, nil
	}
	return nil, 0, common.ErrObjectNotFound
}

func (m clusterHelper) PutUserRev(user *share.CLUSUser, rev uint64) error {
	key := share.CLUSUserKey(url.QueryEscape(user.Fullname))
	value, _ := json.Marshal(user)
	return cluster.PutRev(key, value, rev)
}

func (m clusterHelper) PutUser(user *share.CLUSUser) error {
	key := share.CLUSUserKey(url.QueryEscape(user.Fullname))
	value, _ := json.Marshal(user)
	return cluster.Put(key, value)
}

func (m clusterHelper) CreateUser(user *share.CLUSUser) error {
	key := share.CLUSUserKey(url.QueryEscape(user.Fullname))
	value, _ := json.Marshal(user)
	// User password is already hashed
	return cluster.PutIfNotExist(key, value, false)
}

func (m clusterHelper) DeleteUser(fullname string) error {
	key := share.CLUSUserKey(url.QueryEscape(fullname))
	return cluster.Delete(key)
}

func (m clusterHelper) GetProcessProfile(group string) *share.CLUSProcessProfile {
	key := share.CLUSProfileConfigKey(group)
	if value, _, _ := m.get(key); value != nil {
		var pp share.CLUSProcessProfile
		json.Unmarshal(value, &pp)
		return &pp
	}
	return nil
}

func (m clusterHelper) PutProcessProfile(group string, pg *share.CLUSProcessProfile) error {
	// nodes [default policy mode]: "Discover"
	if group == api.AllHostGroup && pg.Mode == "" {
		pg.Mode = share.PolicyModeLearn
	}

	key := share.CLUSProfileConfigKey(group)
	value, _ := json.Marshal(pg)
	// To suppress extensive logging
	log.WithFields(log.Fields{"key": key, "group": pg.Group, "mode": pg.Mode, "process": len(pg.Process)}).Debug()
	m.DuplicateNetworkKey(key, value)
	return cluster.PutQuiet(key, value)
}

func (m clusterHelper) PutProcessProfileTxn(txn *cluster.ClusterTransact, group string, pg *share.CLUSProcessProfile) error {
	// nodes [default policy mode]: "Discover"
	if group == api.AllHostGroup && pg.Mode == "" {
		pg.Mode = share.PolicyModeLearn
	}

	key := share.CLUSProfileConfigKey(group)
	value, _ := json.Marshal(pg)
	log.WithFields(log.Fields{"key": key, "group": pg.Group, "mode": pg.Mode, "process": len(pg.Process)}).Debug()
	txn.PutQuiet(key, value)
	m.DuplicateNetworkKeyTxn(txn, key, value)
	return nil
}

func (m clusterHelper) PutProcessProfileIfNotExist(group string, pg *share.CLUSProcessProfile) error {
	key := share.CLUSProfileConfigKey(group)
	value, _ := json.Marshal(pg)

	log.WithFields(log.Fields{"key": key, "group": pg.Group, "process": len(pg.Process)}).Debug("GRP: ")
	m.DuplicateNetworkKeyIfNotExist(key, value)
	return cluster.PutIfNotExist(key, value, true)
}

func (m clusterHelper) DeleteProcessProfile(group string) error {
	cluster.Delete(share.CLUSProfileConfigKey(group))
	return cluster.Delete(share.CLUSProfileKey(group))
}

func (m clusterHelper) DeleteProcessProfileTxn(txn *cluster.ClusterTransact, group string) error {
	txn.Delete(share.CLUSProfileConfigKey(group))
	txn.Delete(share.CLUSProfileKey(group))
	return nil
}

func (m clusterHelper) GetAllProcessProfileSubKeys(scope string) utils.Set {
	return getAllSubKeys(scope, share.CLUSConfigProcessProfileStore)
}

// Scanner
func (m clusterHelper) PutScannerTxn(txn *cluster.ClusterTransact, s *share.CLUSScanner) error {
	key := share.CLUSScannerKey(s.ID)
	value, _ := enc.Marshal(s)
	txn.Put(key, value)
	return nil
}

func (m clusterHelper) GetAllScanner(acc *access.AccessControl) []*share.CLUSScanner {
	scanners := make([]*share.CLUSScanner, 0)
	if keys, err := cluster.GetStoreKeys(share.CLUSScannerStore); err == nil {
		for _, key := range keys {
			var s share.CLUSScanner
			value, _, _ := m.get(key)
			if value != nil {
				json.Unmarshal(value, &s)

				if acc.Authorize(&s, nil) && s.ID != share.CLUSScannerDBVersionID {
					scanners = append(scanners, &s)
				}
			}
		}
	}
	return scanners
}

func (m clusterHelper) GetScannerStats(id string) (*share.CLUSScannerStats, error) {
	var s share.CLUSScannerStats
	key := share.CLUSScannerStatsKey(id)
	value, _, _ := m.get(key)
	if value == nil {
		return nil, common.ErrObjectNotFound
	}

	json.Unmarshal(value, &s)
	return &s, nil
}

func (m clusterHelper) CreateScannerStats(id string) error {
	// Create scanner stats if not exist
	var s share.CLUSScannerStats
	key := share.CLUSScannerStatsKey(id)
	value, _ := json.Marshal(s)
	cluster.PutRev(key, value, 0)
	return nil
}

func (m clusterHelper) PutScannerStats(id string, objType share.ScanObjectType, result *share.ScanResult) error {
	// result can be nil
	var scanned bool
	if result != nil && (result.Error == share.ScanErrorCode_ScanErrNone || result.Error == share.ScanErrorCode_ScanErrNotSupport) {
		scanned = true
	}

	var s share.CLUSScannerStats
	key := share.CLUSScannerStatsKey(id)

	retry := 0
	for retry < 3 {
		value, rev, _ := m.get(key)
		if value == nil {
			return common.ErrObjectNotFound
		}

		json.Unmarshal(value, &s)

		switch objType {
		case share.ScanObjectType_IMAGE:
			s.TotalImages++
			if scanned {
				s.ScannedImages++
			}
		case share.ScanObjectType_CONTAINER:
			s.TotalContainers++
			if scanned {
				s.ScannedContainers++
			}
		case share.ScanObjectType_HOST:
			s.TotalHosts++
			if scanned {
				s.ScannedHosts++
			}
		case share.ScanObjectType_SERVERLESS:
			s.TotalServerless++
			if scanned {
				s.ScannedServerless++
			}
		}

		value, _ = json.Marshal(s)
		if err := cluster.PutRev(key, value, rev); err != nil {
			retry++
		} else {
			return nil
		}
	}

	return common.ErrAtomicWriteFail
}

func (m clusterHelper) GetScanner(id string, acc *access.AccessControl) *share.CLUSScanner {
	key := share.CLUSScannerKey(id)
	value, _, _ := m.get(key)
	if value != nil {
		var s share.CLUSScanner
		json.Unmarshal(value, &s)

		if !acc.Authorize(&s, nil) {
			return nil
		}

		return &s
	}
	return nil
}

func (m clusterHelper) DeleteScanner(id string) error {
	key := share.CLUSScannerStatsKey(id)
	cluster.Delete(key)
	key = share.CLUSScannerKey(id)
	return cluster.Delete(key)
}

func (m clusterHelper) GetScannerDB(store string) []*share.CLUSScannerDB {
	dbs := make([]*share.CLUSScannerDB, 0)
	keys, _ := cluster.GetStoreKeys(store)
	for _, key := range keys {
		if value, _, _ := m.get(key); value != nil {
			var db share.CLUSScannerDB
			uzb := utils.GunzipBytes(value)
			if uzb == nil {
				log.Error("Failed to unzip data")
				continue
			}

			err := json.Unmarshal(uzb, &db)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Cannot decode db")
				continue
			}

			dbs = append(dbs, &db)
		}
	}
	return dbs
}

// Compliance Profile
func (m clusterHelper) GetAllComplianceProfiles(acc *access.AccessControl) []*share.CLUSComplianceProfile {
	cps := make([]*share.CLUSComplianceProfile, 0)

	keys, _ := cluster.GetStoreKeys(share.CLUSConfigComplianceProfileStore)
	for _, key := range keys {
		if value, _, _ := m.get(key); value != nil {
			var cp share.CLUSComplianceProfile
			json.Unmarshal(value, &cp)

			if !acc.Authorize(&cp, nil) {
				continue
			}

			cps = append(cps, &cp)
		}
	}

	return cps
}

func (m clusterHelper) GetComplianceProfile(name string, acc *access.AccessControl) (*share.CLUSComplianceProfile, uint64, error) {
	key := share.CLUSComplianceProfileKey(name)
	value, rev, _ := m.get(key)
	if value != nil {
		var cp share.CLUSComplianceProfile
		json.Unmarshal(value, &cp)

		if !acc.Authorize(&cp, nil) {
			return nil, 0, common.ErrObjectAccessDenied
		}

		return &cp, rev, nil
	}
	return nil, 0, common.ErrObjectNotFound
}

func (m clusterHelper) PutComplianceProfile(cp *share.CLUSComplianceProfile, rev uint64) error {
	key := share.CLUSComplianceProfileKey(cp.Name)
	value, _ := json.Marshal(cp)
	return cluster.PutRev(key, value, rev)
}

func (m clusterHelper) PutComplianceProfileIfNotExist(cp *share.CLUSComplianceProfile) error {
	key := share.CLUSComplianceProfileKey(cp.Name)
	value, _ := json.Marshal(cp)
	return cluster.PutIfNotExist(key, value, false)
}

// Vulnerability Profile
func (m clusterHelper) GetAllVulnerabilityProfiles(acc *access.AccessControl) []*share.CLUSVulnerabilityProfile {
	cps := make([]*share.CLUSVulnerabilityProfile, 0)

	keys, _ := cluster.GetStoreKeys(share.CLUSConfigVulnerabilityProfileStore)
	for _, key := range keys {
		if value, _, _ := m.get(key); value != nil {
			var cp share.CLUSVulnerabilityProfile
			json.Unmarshal(value, &cp)

			if !acc.Authorize(&cp, nil) {
				continue
			}

			cps = append(cps, &cp)
		}
	}

	return cps
}

func (m clusterHelper) GetVulnerabilityProfile(name string, acc *access.AccessControl) (*share.CLUSVulnerabilityProfile, uint64, error) {
	key := share.CLUSVulnerabilityProfileKey(name)
	value, rev, _ := m.get(key)
	if value != nil {
		var cp share.CLUSVulnerabilityProfile
		json.Unmarshal(value, &cp)

		if !acc.Authorize(&cp, nil) {
			return nil, 0, common.ErrObjectAccessDenied
		}

		return &cp, rev, nil
	}
	return nil, 0, common.ErrObjectNotFound
}

func (m clusterHelper) PutVulnerabilityProfile(cp *share.CLUSVulnerabilityProfile, rev uint64) error {
	key := share.CLUSVulnerabilityProfileKey(cp.Name)
	value, _ := json.Marshal(cp)
	return cluster.PutRev(key, value, rev)
}

func (m clusterHelper) PutVulnerabilityProfileIfNotExist(cp *share.CLUSVulnerabilityProfile) error {
	key := share.CLUSVulnerabilityProfileKey(cp.Name)
	value, _ := json.Marshal(cp)
	return cluster.PutIfNotExist(key, value, false)
}

// Registry Scan
func (m clusterHelper) PutRegistryImageSummary(name, id string, sum *share.CLUSRegistryImageSummary) error {
	key := share.CLUSRegistryImageStateKey(name, id)
	value, _ := json.Marshal(sum)
	return cluster.Put(key, value)
}

func (m clusterHelper) GetRegistryImageSummary(name, id string) *share.CLUSRegistryImageSummary {
	if value, _ := cluster.Get(share.CLUSRegistryImageStateKey(name, id)); value != nil {
		var summary share.CLUSRegistryImageSummary
		json.Unmarshal(value, &summary)
		return &summary
	}
	return nil
}

// called only on master cluster
func (m clusterHelper) UpdateFedScanDataRevisions(regOp, scanDataOp, regName, id string) error {
	var err error
	retry := 0
	isForRepo := false
	if regName == common.RegistryRepoScanName {
		// whenever scan summary for an image under "_repo_scan" repo is updated/deleted on master cluster, we increase "fed._repo_scan" repo's revision
		regName = common.RegistryFedRepoScanName
		isForRepo = true
	} else if !strings.HasPrefix(regName, api.FederalGroupPrefix) {
		return nil
	}
	key := share.CLUSScanStateKey(share.CLUSFedScanDataRevSubKey)
	for retry < 3 {
		scanRevs, rev, err := m.GetFedScanRevisions()
		if err != nil {
			return err
		}
		if regOp != "" {
			// there is fed registry configuration change
			scanRevs.RegConfigRev += 1
			if scanRevs.RegConfigRev == 0 {
				scanRevs.RegConfigRev += 1
			}
			if regOp == resource.Delete {
				if isForRepo {
					// "fed._repo_scan" repo actually is "_repo_scan" repo on master cluster. it can never be deleted by users
				} else {
					delete(scanRevs.ScannedRegRevs, regName)
				}
			}
		}
		if scanDataOp != "" && id != "" {
			// there is scan result change for an image in a fed registry/repo
			if isForRepo {
				scanRevs.ScannedRepoRev += 1
				if scanRevs.ScannedRepoRev == 0 {
					scanRevs.ScannedRepoRev += 1
				}
			} else {
				rev := scanRevs.ScannedRegRevs[regName] + 1
				if rev == 0 {
					rev += 1
				}
				scanRevs.ScannedRegRevs[regName] = rev
			}
		}

		value, _ := json.Marshal(&scanRevs)
		if err = cluster.PutRev(key, value, rev); err == nil {
			break
		}
		retry++
	}
	if retry >= 3 {
		log.WithFields(log.Fields{"regName": regName, "error": err}).Error()
	}

	return err
}

func (m clusterHelper) DeleteRegistryImageSummaryAndReport(name, id, fedRole string) error {
	txn := cluster.Transact()
	defer txn.Close()

	txn.Delete(share.CLUSRegistryImageStateKey(name, id))
	txn.Delete(share.CLUSRegistryImageDataKey(name, id))

	if ok, err := txn.Apply(); err != nil {
		return err
	} else if !ok {
		return common.ErrAtomicWriteFail
	}

	if fedRole == api.FedRoleMaster {
		m.UpdateFedScanDataRevisions("", resource.Delete, name, id)
	}

	if m.persist {
		deleteRegistryImageSummary(name, id)
		deleteRegistryImageReport(name, id)
	}

	return nil
}

func (m clusterHelper) PutRegistryImageSummaryAndReport(name, id, fedRole string, sum *share.CLUSRegistryImageSummary, report *share.CLUSScanReport) error {
	txn := cluster.Transact()
	defer txn.Close()

	key := share.CLUSRegistryImageStateKey(name, id)
	vSum, _ := json.Marshal(sum)
	txn.Put(key, vSum)

	key = share.CLUSRegistryImageDataKey(name, id)
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	enc.Encode(report)
	zbRpt := utils.GzipBytes(buf.Bytes())
	txn.PutBinary(key, zbRpt)

	if ok, err := txn.Apply(); err != nil {
		return err
	} else if !ok {
		return common.ErrAtomicWriteFail
	}

	if fedRole == api.FedRoleMaster {
		m.UpdateFedScanDataRevisions("", resource.Update, name, id)
	}

	if m.persist {
		writeRegistryImageSummary(name, id, vSum)
		writeRegistryImageReport(name, id, zbRpt)
	}

	return nil
}

func (m clusterHelper) GetFedScanRevisions() (share.CLUSFedScanRevisions, uint64, error) {
	var scanRevs share.CLUSFedScanRevisions

	value, rev, err := m.get(share.CLUSScanStateKey(share.CLUSFedScanDataRevSubKey))
	if err != nil {
		return scanRevs, 0, err
	}

	json.Unmarshal(value, &scanRevs)
	if scanRevs.ScannedRegRevs == nil {
		scanRevs.ScannedRegRevs = make(map[string]uint64)
	}

	return scanRevs, rev, nil
}

func (m clusterHelper) PutFedScanRevisions(scanRevs *share.CLUSFedScanRevisions, rev *uint64) error {
	key := share.CLUSScanStateKey(share.CLUSFedScanDataRevSubKey)
	value, _ := json.Marshal(&scanRevs)
	if rev != nil {
		return cluster.PutRev(key, value, *rev)
	} else {
		return cluster.Put(key, value)
	}
}

func (m clusterHelper) GetRegistry(name string, acc *access.AccessControl) (*share.CLUSRegistryConfig, uint64, error) {
	key := share.CLUSRegistryConfigKey(name)
	value, rev, _ := m.get(key)
	if value != nil {
		var cfg share.CLUSRegistryConfig
		json.Unmarshal(value, &cfg)

		if !acc.Authorize(&cfg, nil) {
			return nil, 0, common.ErrObjectAccessDenied
		}

		return &cfg, rev, nil
	}
	return nil, 0, common.ErrObjectNotFound
}

func (m clusterHelper) GetAllRegistry(scope string) []*share.CLUSRegistryConfig {
	configs := make([]*share.CLUSRegistryConfig, 0)

	var getLocal, getFed bool
	switch scope {
	case share.ScopeLocal:
		getLocal = true
	case share.ScopeFed:
		getFed = true
	case share.ScopeAll:
		getLocal = true
		getFed = true
	}
	if keys, err := cluster.GetStoreKeys(share.CLUSConfigRegistryStore); err == nil {
		for _, key := range keys {
			name := share.CLUSKeyNthToken(key, 3)
			if strings.HasPrefix(name, api.FederalGroupPrefix) {
				// "fed.xxx" registry
				if !getFed {
					continue
				}
			} else {
				// "xxx" registry
				if !getLocal {
					continue
				}
			}
			var config share.CLUSRegistryConfig
			value, _, _ := m.get(key)
			if value != nil {
				json.Unmarshal(value, &config)
				configs = append(configs, &config)
			}
		}
	}
	return configs
}

func (m clusterHelper) PutRegistry(config *share.CLUSRegistryConfig, rev uint64) error {
	key := share.CLUSRegistryConfigKey(config.Name)
	value, _ := enc.Marshal(config)
	return cluster.PutRev(key, value, rev)
}

func (m clusterHelper) PutRegistryIfNotExist(config *share.CLUSRegistryConfig) error {
	key := share.CLUSRegistryConfigKey(config.Name)
	value, _ := enc.Marshal(config)
	if m.persist {
		createRegistryDir(config.Name)
	}
	return cluster.PutIfNotExist(key, value, true)
}

func (m clusterHelper) DeleteRegistry(txn *cluster.ClusterTransact, name string) error {
	key1 := share.CLUSRegistryConfigKey(name)
	key2 := share.CLUSRegistryStateKey(name)
	if txn == nil {
		cluster.Delete(key1)
		cluster.Delete(key2)
	} else {
		txn.Delete(key1)
		txn.Delete(key2)
	}
	if m.persist {
		deleteRegistryDir(name)
	}
	return nil
}

func (m clusterHelper) PutRegistryState(name string, state *share.CLUSRegistryState) error {
	key := share.CLUSRegistryStateKey(name)
	value, _ := json.Marshal(state)
	return cluster.Put(key, value)
}

func (m clusterHelper) GetRegistryState(name string) *share.CLUSRegistryState {
	key := share.CLUSRegistryStateKey(name)
	if value, _, _ := m.get(key); len(value) > 0 {
		var state share.CLUSRegistryState
		json.Unmarshal(value, &state)
		return &state
	}
	return nil
}

func (m clusterHelper) DeleteRegistryKeys(name string) error {
	txn := cluster.Transact()
	defer txn.Close()

	store := share.CLUSRegistryImageStateStore(name)
	if keys, err := cluster.GetStoreKeys(store); err == nil {
		for _, key := range keys {
			txn.Delete(key)
		}
	}
	txn.Delete(store)

	store = share.CLUSRegistryImageDataStore(name)
	if keys, err := cluster.GetStoreKeys(store); err == nil {
		for _, key := range keys {
			txn.Delete(key)
		}
	}
	txn.Delete(store)

	if ok, err := txn.Apply(); err != nil {
		return err
	} else if !ok {
		return common.ErrAtomicWriteFail
	}

	return nil
}

func (m clusterHelper) GetScanState(key string) *share.CLUSScanState {
	if value, _, _ := m.get(key); len(value) > 0 {
		var state share.CLUSScanState
		json.Unmarshal(value, &state)
		return &state
	}
	return nil
}

func (m clusterHelper) GetScanReport(key string) *share.CLUSScanReport {
	if value, _, _ := m.get(key); len(value) > 0 {
		if uzb := utils.GunzipBytes(value); uzb != nil {
			var report share.CLUSScanReport

			{
				buf := bytes.NewBuffer(uzb)
				dec := gob.NewDecoder(buf)
				if err := dec.Decode(&report); err == nil {
					return &report
				}
			}

			if err := json.Unmarshal(uzb, &report); err == nil {
				log.WithFields(log.Fields{"key": key}).Debug("Convert json scan report")
				var buf bytes.Buffer
				enc := gob.NewEncoder(&buf)
				enc.Encode(&report)
				zb := utils.GzipBytes(buf.Bytes())
				cluster.PutQuiet(key, zb)
				return &report
			}
		}
	}
	return nil
}

func (m clusterHelper) GetAllFileMonitorProfile() map[string]*share.CLUSFileMonitorProfile {
	confs := make(map[string]*share.CLUSFileMonitorProfile, 0)

	store := share.CLUSConfigFileMonitorStore
	keys, _ := cluster.GetStoreKeys(store)
	for _, key := range keys {
		name := share.CLUSFileMonitorKey2Group(key)
		if value, _, _ := m.get(key); value != nil {
			var conf share.CLUSFileMonitorProfile
			json.Unmarshal(value, &conf)

			confs[name] = &conf
		}
	}
	return confs
}

func (m clusterHelper) GetAllFileMonitorProfileSubKeys(scope string) utils.Set {
	return getAllSubKeys(scope, share.CLUSConfigFileMonitorStore)
}

func (m clusterHelper) GetFileMonitorProfile(name string) (*share.CLUSFileMonitorProfile, uint64) {
	var conf share.CLUSFileMonitorProfile

	key := share.CLUSFileMonitorKey(name)
	if value, rev, _ := m.get(key); value != nil {
		json.Unmarshal(value, &conf)
		return &conf, rev
	} else {
		return nil, 0
	}
}

func (m clusterHelper) PutFileMonitorProfile(name string, conf *share.CLUSFileMonitorProfile, rev uint64) error {
	key := share.CLUSFileMonitorKey(name)
	value, _ := json.Marshal(conf)
	m.DuplicateNetworkKey(key, value)
	if rev == 0 {
		return cluster.Put(key, value)
	}
	return cluster.PutRev(key, value, rev)
}

func (m clusterHelper) PutFileMonitorProfileIfNotExist(name string, conf *share.CLUSFileMonitorProfile) error {
	key := share.CLUSFileMonitorKey(name)
	value, _ := json.Marshal(conf)
	m.DuplicateNetworkKeyIfNotExist(key, value)
	return cluster.PutIfNotExist(key, value, true)
}

func (m clusterHelper) PutFileMonitorProfileTxn(txn *cluster.ClusterTransact, name string, conf *share.CLUSFileMonitorProfile) error {
	key := share.CLUSFileMonitorKey(name)
	value, _ := json.Marshal(conf)
	txn.Put(key, value)
	m.DuplicateNetworkKeyTxn(txn, key, value)
	return nil
}

func (m clusterHelper) DeleteFileMonitor(name string) error {
	cluster.Delete(share.CLUSFileMonitorKey(name))
	return cluster.Delete(share.CLUSFileMonitorNetworkKey(name))
}

func (m clusterHelper) DeleteFileMonitorTxn(txn *cluster.ClusterTransact, name string) error {
	txn.Delete(share.CLUSFileMonitorKey(name))
	txn.Delete(share.CLUSFileMonitorNetworkKey(name))
	return nil
}

func (m clusterHelper) GetFileAccessRule(name string) (*share.CLUSFileAccessRule, uint64) {
	var conf share.CLUSFileAccessRule

	key := share.CLUSFileAccessRuleKey(name)
	if value, rev, _ := m.get(key); value != nil {
		json.Unmarshal(value, &conf)
		return &conf, rev
	} else {
		return nil, 0
	}
}

func (m clusterHelper) PutFileAccessRule(name string, conf *share.CLUSFileAccessRule, rev uint64) error {
	key := share.CLUSFileAccessRuleKey(name)
	conf.Group = name
	value, _ := json.Marshal(conf)
	// To suppress extensive logging
	// log.WithFields(log.Fields{"key": key, "rev": rev, "group": conf.Group, "filters": conf.Filters, "crds": len(conf.FiltersCRD)}).Debug()
	// log.WithFields(log.Fields{"value": string(value)}).Debug("GRP:")
	m.DuplicateNetworkKey(key, value)
	return cluster.PutQuietRev(key, value, rev)
}

func (m clusterHelper) PutFileAccessRuleIfNotExist(name string, conf *share.CLUSFileAccessRule) error {
	key := share.CLUSFileAccessRuleKey(name)
	conf.Group = name
	value, _ := json.Marshal(conf)
	m.DuplicateNetworkKeyIfNotExist(key, value)
	return cluster.PutIfNotExist(key, value, true)
}

func (m clusterHelper) PutFileAccessRuleTxn(txn *cluster.ClusterTransact, name string, conf *share.CLUSFileAccessRule) error {
	key := share.CLUSFileAccessRuleKey(name)
	conf.Group = name
	value, _ := json.Marshal(conf)
	txn.Put(key, value)
	m.DuplicateNetworkKeyTxn(txn, key, value)
	return nil
}

func (m clusterHelper) DeleteFileAccessRule(name string) error {
	cluster.Delete(share.CLUSFileAccessRuleKey(name))
	return cluster.Delete(share.CLUSFileAccessRuleNetworkKey(name))
}

func (m clusterHelper) DeleteFileAccessRuleTxn(txn *cluster.ClusterTransact, name string) error {
	txn.Delete(share.CLUSFileAccessRuleKey(name))
	txn.Delete(share.CLUSFileAccessRuleNetworkKey(name))
	return nil
}

func (m clusterHelper) GetAllFileAccessRuleSubKeys(scope string) utils.Set {
	return getAllSubKeys(scope, share.CLUSConfigFileAccessRuleStore)
}

// Admission control. Retrieved cert's CaKeyNew/CaCertNew/KeyNew/CertNew are uncloaked, copied to CaKey/CaCert/Key/Cert, and then set to empty
func (m clusterHelper) GetAdmissionCertRev(svcName string) (*share.CLUSAdmissionCertCloaked, uint64) { // obsolete
	var store string
	switch svcName {
	case resource.NvAdmSvcName:
		store = share.CLUSConfigAdmissionControlStore
	case resource.NvCrdSvcName:
		store = share.CLUSConfigCrdStore
	}

	key := share.CLUSAdmissionCertKey(store, share.DefaultPolicyName)
	if value, rev, _ := m.get(key); value != nil {
		var cert share.CLUSAdmissionCertCloaked
		dec.Unmarshal(value, &cert)
		cert.CaKey = []byte(cert.CaKeyNew)
		cert.CaCert = []byte(cert.CaCertNew)
		cert.Key = []byte(cert.KeyNew)
		cert.Cert = []byte(cert.CertNew)
		cert.CaKeyNew, cert.CaCertNew, cert.KeyNew, cert.CertNew = "", "", "", ""
		return &cert, rev
	}

	return nil, 0
}

func (m clusterHelper) GetObjectCertRev(cn string) (*share.CLUSX509Cert, uint64, error) {
	key := share.CLUSObjectCertKey(cn)
	value, rev, err := cluster.GetRev(key)
	if err != nil || value == nil {
		log.WithFields(log.Fields{"cn": cn, "error": err}).Error()
		return nil, rev, err
	} else {
		var cert share.CLUSX509Cert
		dec.Unmarshal(value, &cert)
		return &cert, rev, nil
	}
}

// returns pre-existing cert object in kv if it already in kv
func (m clusterHelper) PutObjectCert(cn, keyPath, certPath string, cert *share.CLUSX509Cert) error {
	key := share.CLUSObjectCertKey(cn)
	value, _ := enc.Marshal(cert)
	err := cluster.PutIfNotExist(key, value, true)
	if err == nil {
		// don't know why: after rolling upgrade(replicas/maxSurge=3), there could be a short period that controller cannot get/put kv
		// (GetRev returns "Key not found" error & Put/PutRev return "CAS put error" & PutIfNotExist returns nil : is it because kv is not syned yet?)
		// so we get again to see whether kv is accessible
		if certExisting, _, _ := clusHelper.GetObjectCertRev(cn); !certExisting.IsEmpty() {
			if cert.Key != certExisting.Key || cert.Cert != certExisting.Cert {
				var valid bool
				if cn != share.CLUSRootCAKey {
					valid = verifyWebServerCert(cn, []byte(certExisting.Cert))
				}
				if !valid {
					return cluster.Put(key, value)
				} else {
					b1 := md5.Sum([]byte(cert.Cert))
					b2 := md5.Sum([]byte(certExisting.Cert))
					log.WithFields(log.Fields{"cn": cn, "certIn": hex.EncodeToString(b1[:]), "certExisting": hex.EncodeToString(b2[:])}).Info("md5")
					err1 := ioutil.WriteFile(keyPath, []byte(certExisting.Key), 0600)
					err2 := ioutil.WriteFile(certPath, []byte(certExisting.Cert), 0600)
					if err1 == nil && err2 == nil {
						return nil
					} else {
						log.WithFields(log.Fields{"err1": err1, "err2": err2, "cn": cn}).Error("failed to write")
						err = fmt.Errorf("failed to write files")
					}
				}
			} else {
				return nil
			}
		} else {
			err = fmt.Errorf("cannot confirm success")
			log.WithFields(log.Fields{"cn": cn, "error": err}).Error()
		}
	}

	return err
}

func (m clusterHelper) GetAdmissionStateRev(svcName string) (*share.CLUSAdmissionState, uint64) {
	var store string
	switch svcName {
	case resource.NvAdmSvcName:
		store = share.CLUSConfigAdmissionControlStore
	case resource.NvCrdSvcName:
		store = share.CLUSConfigCrdStore
	}
	key := share.CLUSAdmissionStateKey(store, share.DefaultPolicyName)

	value, rev, _ := m.get(key)
	if value != nil {
		var state share.CLUSAdmissionState
		json.Unmarshal(value, &state)
		if failurePolicy := state.FailurePolicy; failurePolicy != resource.FailLower && failurePolicy != resource.IgnoreLower {
			state.FailurePolicy = resource.IgnoreLower
		}
		if state.TimeoutSeconds < 1 || state.TimeoutSeconds > 30 {
			state.TimeoutSeconds = resource.DefTimeoutSeconds
		}
		if state.CfgType == 0 {
			state.CfgType = share.UserCreated
		}
		if svcName == resource.NvAdmSvcName {
			for _, ctrlState := range state.CtrlStates {
				ss := strings.Split(ctrlState.Uri, "/")
				if len(ss) >= 3 && ss[2] == admission.NvAdmValidateType {
					ss[2] = admission.UriAdmCtrlNvStatus
					ctrlState.NvStatusUri = strings.Join(ss, "/")
				}
			}
		}
		return &state, rev
	}

	return nil, 0
}

func getAdmCtrlPolicyName(ruleType string) string {
	var policyName string
	switch ruleType {
	case share.FedAdmCtrlExceptRulesType, share.FedAdmCtrlDenyRulesType:
		policyName = share.FedPolicyName
	default:
		policyName = share.DefaultPolicyName
	}
	return policyName
}

func (m clusterHelper) PutAdmissionRule(admType, ruleType string, rule *share.CLUSAdmissionRule) error {
	key := share.CLUSAdmissionRuleKey(getAdmCtrlPolicyName(ruleType), admType, ruleType, rule.ID)
	value, _ := json.Marshal(rule)
	if err := cluster.Put(key, value); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		return err
	}
	return nil
}

func (m clusterHelper) PutAdmissionStateRev(svcName string, state *share.CLUSAdmissionState, rev uint64) error {
	var store string
	switch svcName {
	case resource.NvAdmSvcName:
		store = share.CLUSConfigAdmissionControlStore
	case resource.NvCrdSvcName:
		store = share.CLUSConfigCrdStore
	}
	key := share.CLUSAdmissionStateKey(store, share.DefaultPolicyName)
	value, _ := json.Marshal(state)
	if err := cluster.PutRev(key, value, rev); err != nil {
		log.WithFields(log.Fields{"error": err, "rev": rev}).Error("")
		return err
	}
	return nil
}

func (m clusterHelper) GetAdmissionRuleList(admType, ruleType string) ([]*share.CLUSRuleHead, error) {
	crhs := make([]*share.CLUSRuleHead, 0)
	key := share.CLUSAdmissionRuleListKey(getAdmCtrlPolicyName(ruleType), admType, ruleType)
	if value, _, err := m.get(key); value != nil {
		json.Unmarshal(value, &crhs)
		return crhs, nil
	} else {
		return crhs, err
	}
}

func (m clusterHelper) GetAdmissionRule(admType, ruleType string, id uint32) *share.CLUSAdmissionRule {
	key := share.CLUSAdmissionRuleKey(getAdmCtrlPolicyName(ruleType), admType, ruleType, id)
	if value, _, _ := m.get(key); value != nil {
		var rule share.CLUSAdmissionRule
		json.Unmarshal(value, &rule)
		return &rule
	}

	return nil
}

func (m clusterHelper) PutAdmissionRuleList(admType, ruleType string, crhs []*share.CLUSRuleHead) error {
	key := share.CLUSAdmissionRuleListKey(getAdmCtrlPolicyName(ruleType), admType, ruleType)
	value, _ := json.Marshal(crhs)
	if err := cluster.Put(key, value); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		return err
	}
	return nil
}

func (m clusterHelper) DeleteAdmissionRule(admType, ruleType string, id uint32) error {
	key := share.CLUSAdmissionRuleKey(getAdmCtrlPolicyName(ruleType), admType, ruleType, id)
	return cluster.Delete(key)
}

func (m clusterHelper) GetAdmissionStatsRev() (*share.CLUSAdmissionStats, uint64) {
	stats := share.CLUSAdmissionStats{}
	key := share.CLUSAdmissionStatsKey(share.DefaultPolicyName)
	if value, rev, _ := m.get(key); value != nil {
		json.Unmarshal(value, &stats)
		return &stats, rev
	}

	return &stats, 0
}

func (m clusterHelper) PutAdmissionStatsRev(stats *share.CLUSAdmissionStats, rev uint64) error {
	key := share.CLUSAdmissionStatsKey(share.DefaultPolicyName)
	value, _ := json.Marshal(stats)
	if err := cluster.PutRev(key, value, rev); err != nil {
		log.WithFields(log.Fields{"error": err, "rev": rev}).Error("")
		return err
	}
	return nil
}

func (m clusterHelper) PutAdmissionRuleTxn(txn *cluster.ClusterTransact, admType, ruleType string, rule *share.CLUSAdmissionRule) error {
	key := share.CLUSAdmissionRuleKey(getAdmCtrlPolicyName(ruleType), admType, ruleType, rule.ID)
	value, _ := json.Marshal(rule)
	txn.Put(key, value)
	return nil
}

func (m clusterHelper) PutAdmissionRuleListTxn(txn *cluster.ClusterTransact, admType, ruleType string, crhs []*share.CLUSRuleHead) error {
	key := share.CLUSAdmissionRuleListKey(getAdmCtrlPolicyName(ruleType), admType, ruleType)
	value, _ := json.Marshal(crhs)
	txn.Put(key, value)
	return nil
}

func (m clusterHelper) DeleteAdmissionRuleTxn(txn *cluster.ClusterTransact, admType, ruleType string, id uint32) error {
	key := share.CLUSAdmissionRuleKey(getAdmCtrlPolicyName(ruleType), admType, ruleType, id)
	txn.Delete(key)
	return nil
}

//------
func (m clusterHelper) GetCrdSecurityRuleRecord(crdKind, crdName string) *share.CLUSCrdSecurityRule {
	key := share.CLUSCrdKey(crdKind, crdName)
	if value, _, _ := m.get(key); len(value) > 0 {
		var state share.CLUSCrdSecurityRule
		json.Unmarshal(value, &state)
		return &state
	}
	return nil
}

func (m clusterHelper) PutCrdSecurityRuleRecord(crdKind, crdName string, rules *share.CLUSCrdSecurityRule) error {
	key := share.CLUSCrdKey(crdKind, crdName)
	value, _ := json.Marshal(rules)
	return m.putSizeAware(key, value)
}

func (m clusterHelper) DeleteCrdSecurityRuleRecord(crdKind, crdName string) error {
	key := share.CLUSCrdKey(crdKind, crdName)
	return cluster.Delete(key)
}

func (m clusterHelper) GetCrdSecurityRuleRecordList(crdKind string) map[string]*share.CLUSCrdSecurityRule {
	records := make(map[string]*share.CLUSCrdSecurityRule, 0)
	store := share.CLUSConfigCrdStore
	keys, _ := cluster.GetStoreKeys(store)
	for _, key := range keys {
		id := share.CLUSKeyNthToken(key, 3)
		if id == crdKind {
			if value, _, _ := m.get(key); value != nil {
				var secRule share.CLUSCrdSecurityRule
				json.Unmarshal(value, &secRule)
				records[secRule.Name] = &secRule
			}
		}
	}
	return records
}

// Mult-clusters (Federation)
func (m clusterHelper) GetFedMembership() *share.CLUSFedMembership {
	key := share.CLUSFedKey(share.CLUSFedMembershipSubKey)
	if value, _, _ := m.get(key); value != nil {
		s := share.CLUSFedMembership{}
		dec.Unmarshal(value, &s)
		return &s
	}

	return nil
}

func (m clusterHelper) PutFedMembership(s *share.CLUSFedMembership) error {
	key := share.CLUSFedKey(share.CLUSFedMembershipSubKey)
	value, _ := enc.Marshal(s)
	if err := cluster.Put(key, value); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		return err
	}
	return nil
}

func (m clusterHelper) GetFedJointClusterList() *share.CLUSFedJoinedClusterList {
	key := share.CLUSFedKey(share.CLUSFedClustersListSubKey)
	if value, _, _ := m.get(key); value != nil {
		clusters := share.CLUSFedJoinedClusterList{}
		json.Unmarshal(value, &clusters)
		return &clusters
	}

	return nil
}

func (m clusterHelper) PutFedJointClusterList(list *share.CLUSFedJoinedClusterList) error {
	key := share.CLUSFedKey(share.CLUSFedClustersListSubKey)
	value, _ := json.Marshal(list)
	if err := cluster.Put(key, value); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		return err
	}
	return nil
}

func (m clusterHelper) PutFedJointClusterStatus(id string, status *share.CLUSFedClusterStatus) error {
	value, _ := json.Marshal(status)
	key := share.CLUSFedJointClusterStatusKey(id)
	if err := cluster.Put(key, value); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		return err
	}
	return nil
}

func (m clusterHelper) DeleteFedJointClusterStatus(id string) error {
	if id != "" {
		key := share.CLUSFedJointClusterStatusKey(id)
		return cluster.Delete(key)
	}
	return nil
}

func (m clusterHelper) GetFedJointCluster(id string) *share.CLUSFedJointClusterInfo {
	key := share.CLUSFedJointClusterKey(id)
	if value, _, _ := m.get(key); value != nil {
		cluster := share.CLUSFedJointClusterInfo{}
		dec.Unmarshal(value, &cluster)
		return &cluster
	}

	return nil
}

func (m clusterHelper) PutFedJointCluster(jointCluster *share.CLUSFedJointClusterInfo) error {
	value, _ := enc.Marshal(jointCluster)
	key := share.CLUSFedJointClusterKey(jointCluster.ID)
	if err := cluster.Put(key, value); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		return err
	}
	return nil
}

func (m clusterHelper) DeleteFedJointCluster(id string) error {
	key := share.CLUSFedJointClusterStatusKey(id)
	cluster.Delete(key)
	key = share.CLUSFedJointClusterKey(id)
	return cluster.Delete(key)
}

func (m clusterHelper) GetFedRulesRevisionRev() (*share.CLUSFedRulesRevision, uint64) {
	key := share.CLUSFedKey(share.CLUSFedRulesRevisionSubKey)
	if value, rev, _ := m.get(key); value != nil {
		revisions := share.CLUSFedRulesRevision{}
		json.Unmarshal(value, &revisions)
		return &revisions, rev
	}

	return nil, 0
}

func (m clusterHelper) UpdateFedRulesRevision(ruleTypes []string) bool {
	var err error
	retry := 0
	key := share.CLUSFedKey(share.CLUSFedRulesRevisionSubKey)
	for retry < 3 {
		data, rev := m.GetFedRulesRevisionRev()
		if ruleTypes == nil || data == nil || len(data.Revisions) == 0 {
			emptyFedRev := share.CLUSEmptyFedRulesRevision()
			if data == nil {
				data = emptyFedRev
			} else {
				data.Revisions = emptyFedRev.Revisions
			}
		}
		for _, ruleType := range ruleTypes {
			if fedRev, ok := data.Revisions[ruleType]; ok {
				data.Revisions[ruleType] = fedRev + 1
			} else {
				data.Revisions[ruleType] = 1
			}
		}

		value, _ := json.Marshal(data)
		if err = cluster.PutRev(key, value, rev); err == nil {
			break
		}
		retry++
	}
	if retry >= 3 {
		log.WithFields(log.Fields{"ruleTypes": ruleTypes, "error": err}).Error("")
	}

	return retry < 3
}

// called by joint cluster
func (m clusterHelper) PutFedRulesRevision(txn *cluster.ClusterTransact, revisions *share.CLUSFedRulesRevision) error {
	var value []byte
	key := share.CLUSFedKey(share.CLUSFedRulesRevisionSubKey)
	value, _ = json.Marshal(revisions)
	if txn != nil {
		txn.Put(key, value)
	} else {
		if err := cluster.Put(key, value); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("")
			return err
		}
	}
	return nil
}

func (m clusterHelper) FedTriggerInstantPingPoll(cmd, fullPolling uint32) {
	p := share.CLUSFedDoPingPoll{Cmd: cmd, FullPolling: fullPolling, Now: time.Now().Unix()}
	var value []byte
	key := share.CLUSFedKey(share.CLUSFedToPingPollSubKey)
	value, _ = json.Marshal(&p)
	cluster.Put(key, value)
}

// caller may/not own share.CLUSLockFedKey lock
func (m clusterHelper) EnableDisableJointClusters(ids []string, toDisable bool, fedKeyLocked bool) {
	if ids == nil {
		list := m.GetFedJointClusterList()
		ids = list.IDs
	}
	if len(ids) == 0 {
		return
	}

	if !fedKeyLocked {
		lock, err := m.AcquireLock(share.CLUSLockFedKey, clusterLockWait)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to acquire cluster lock")
			return
		}
		defer m.ReleaseLock(lock)
	}

	data := share.CLUSFedClusterStatus{}
	if toDisable {
		data.Status = 207 // _fedLicenseDisallowed
	} else {
		data.Status = 208 // _fedClusterPinging
	}
	for _, id := range ids {
		c := m.GetFedJointCluster(id)
		if c.ID == id && c.Disabled != toDisable {
			c.Disabled = toDisable
			if err := m.PutFedJointCluster(c); err == nil {
				clusHelper.PutFedJointClusterStatus(id, &data)
			}
		}
	}
}

func (m clusterHelper) ConfigFedRole(userName, role string, acc *access.AccessControl) error {
	// Check if user already exists
	var err error
	if user, rev, _ := m.GetUserRev(userName, acc); user != nil {
		user.Role = role
		if err = m.PutUserRev(user, rev); err != nil {
			log.WithFields(log.Fields{"error": err, "user": userName, "role": role}).Error("Config fed role failed")
			return err
		}
	}

	return nil
}

func (m clusterHelper) GetFedSettings() share.CLUSFedSettings {
	var cfg share.CLUSFedSettings
	key := share.CLUSFedKey(share.CLUSFedSettingsSubKey)
	if value, _, _ := m.get(key); value != nil {
		json.Unmarshal(value, &cfg)
	}
	return cfg
}

func (m clusterHelper) PutFedSettings(txn *cluster.ClusterTransact, cfg share.CLUSFedSettings) error {
	var err error
	var value []byte
	key := share.CLUSFedKey(share.CLUSFedSettingsSubKey)
	value, _ = json.Marshal(cfg)
	if txn != nil {
		txn.Put(key, value)
	} else {
		err = cluster.Put(key, value)
	}
	return err
}

// dlp sensor
func (m clusterHelper) GetDlpSensor(sensor string) *share.CLUSDlpSensor {
	key := share.CLUSDlpRuleConfigKey(sensor)
	if value, _, _ := m.get(key); value != nil {
		var dr share.CLUSDlpSensor
		json.Unmarshal(value, &dr)
		return &dr
	}
	return nil
}

func (m clusterHelper) GetAllDlpSensors() []*share.CLUSDlpSensor {
	keys, _ := cluster.GetStoreKeys(share.CLUSConfigDlpRuleStore)
	sensors := make([]*share.CLUSDlpSensor, 0, len(keys))
	for _, key := range keys {
		if value, _, _ := m.get(key); value != nil {
			var sensor share.CLUSDlpSensor
			json.Unmarshal(value, &sensor)
			sensors = append(sensors, &sensor)
		}
	}

	return sensors
}

func (m clusterHelper) PutDlpSensor(sensor *share.CLUSDlpSensor, create bool) error {
	key := share.CLUSDlpRuleConfigKey(sensor.Name)
	value, _ := json.Marshal(sensor)
	if create {
		return cluster.PutIfNotExist(key, value, false)
	} else {
		return cluster.Put(key, value)
	}
}

func (m clusterHelper) PutDlpSensorTxn(txn *cluster.ClusterTransact, sensor *share.CLUSDlpSensor) error {
	key := share.CLUSDlpRuleConfigKey(sensor.Name)
	value, _ := json.Marshal(sensor)
	txn.Put(key, value)
	return nil
}

func (m clusterHelper) DeleteDlpSensor(sensor string) error {
	key := share.CLUSDlpRuleConfigKey(sensor)
	return cluster.Delete(key)
}

func (m clusterHelper) DeleteDlpSensorTxn(txn *cluster.ClusterTransact, name string) error {
	key := share.CLUSDlpRuleConfigKey(name)
	txn.Delete(key)
	return nil
}

func (m clusterHelper) GetDlpGroup(group string) *share.CLUSDlpGroup {
	key := share.CLUSDlpGroupConfigKey(group)
	if value, _, _ := m.get(key); value != nil {
		var dlpgroup share.CLUSDlpGroup
		json.Unmarshal(value, &dlpgroup)
		return &dlpgroup
	}
	return nil
}

func (m clusterHelper) PutDlpGroup(group *share.CLUSDlpGroup, create bool) error {
	key := share.CLUSDlpGroupConfigKey(group.Name)
	value, _ := json.Marshal(group)
	if create {
		return cluster.PutIfNotExist(key, value, false)
	} else {
		return cluster.Put(key, value)
	}
}

func (m clusterHelper) PutDlpGroupTxn(txn *cluster.ClusterTransact, group *share.CLUSDlpGroup) error {
	key := share.CLUSDlpGroupConfigKey(group.Name)
	value, _ := json.Marshal(group)
	txn.Put(key, value)
	return nil
}

func (m clusterHelper) DeleteDlpGroup(group string) error {
	key := share.CLUSDlpGroupConfigKey(group)
	return cluster.Delete(key)
}

// waf sensor
func (m clusterHelper) GetWafSensor(sensor string) *share.CLUSWafSensor {
	key := share.CLUSWafRuleConfigKey(sensor)
	if value, _, _ := m.get(key); value != nil {
		var dr share.CLUSWafSensor
		json.Unmarshal(value, &dr)
		return &dr
	}
	return nil
}

func (m clusterHelper) GetAllWafSensors() []*share.CLUSWafSensor {
	keys, _ := cluster.GetStoreKeys(share.CLUSConfigWafRuleStore)
	sensors := make([]*share.CLUSWafSensor, 0, len(keys))
	for _, key := range keys {
		if value, _, _ := m.get(key); value != nil {
			var sensor share.CLUSWafSensor
			json.Unmarshal(value, &sensor)
			sensors = append(sensors, &sensor)
		}
	}

	return sensors
}

func (m clusterHelper) PutWafSensor(sensor *share.CLUSWafSensor, create bool) error {
	key := share.CLUSWafRuleConfigKey(sensor.Name)
	value, _ := json.Marshal(sensor)
	if create {
		return cluster.PutIfNotExist(key, value, false)
	} else {
		return cluster.Put(key, value)
	}
}

func (m clusterHelper) PutWafSensorTxn(txn *cluster.ClusterTransact, sensor *share.CLUSWafSensor) error {
	key := share.CLUSWafRuleConfigKey(sensor.Name)
	value, _ := json.Marshal(sensor)
	txn.Put(key, value)
	return nil
}

func (m clusterHelper) DeleteWafSensor(name string) error {
	key := share.CLUSWafRuleConfigKey(name)
	return cluster.Delete(key)
}

func (m clusterHelper) DeleteWafSensorTxn(txn *cluster.ClusterTransact, name string) error {
	key := share.CLUSWafRuleConfigKey(name)
	txn.Delete(key)
	return nil
}

func (m clusterHelper) GetWafGroup(group string) *share.CLUSWafGroup {
	key := share.CLUSWafGroupConfigKey(group)
	if value, _, _ := m.get(key); value != nil {
		var wafgroup share.CLUSWafGroup
		json.Unmarshal(value, &wafgroup)
		return &wafgroup
	}
	return nil
}

func (m clusterHelper) PutWafGroup(group *share.CLUSWafGroup, create bool) error {
	key := share.CLUSWafGroupConfigKey(group.Name)
	value, _ := json.Marshal(group)
	if create {
		return cluster.PutIfNotExist(key, value, false)
	} else {
		return cluster.Put(key, value)
	}
}

func (m clusterHelper) PutWafGroupTxn(txn *cluster.ClusterTransact, group *share.CLUSWafGroup) error {
	key := share.CLUSWafGroupConfigKey(group.Name)
	value, _ := json.Marshal(group)
	txn.Put(key, value)
	return nil
}

func (m clusterHelper) DeleteWafGroup(group string) error {
	key := share.CLUSWafGroupConfigKey(group)
	return cluster.Delete(key)
}

func (m clusterHelper) GetCustomCheckConfig(group string) (*share.CLUSCustomCheckGroup, uint64) {
	var conf share.CLUSCustomCheckGroup
	key := share.CLUSCustomCheckConfigKey(group)
	if value, rev, _ := m.get(key); value != nil {
		json.Unmarshal(value, &conf)
		return &conf, rev
	} else {
		return nil, 0
	}
}

func (m clusterHelper) GetAllCustomCheckConfig() map[string]*share.CLUSCustomCheckGroup {
	scripts := make(map[string]*share.CLUSCustomCheckGroup)
	store := share.CLUSConfigScriptStore
	keys, _ := cluster.GetStoreKeys(store)
	for _, key := range keys {
		group := share.CLUSKeyNthToken(key, 3)
		if value, _, _ := m.get(key); value != nil {
			var conf share.CLUSCustomCheckGroup
			json.Unmarshal(value, &conf)
			scripts[group] = &conf
		}
	}
	return scripts
}

func (m clusterHelper) PutCustomCheckConfig(group string, conf *share.CLUSCustomCheckGroup, rev uint64) error {
	key := share.CLUSCustomCheckConfigKey(group)
	value, _ := json.Marshal(conf)
	m.DuplicateNetworkKey(key, value)
	return cluster.Put(key, value)
}

func (m clusterHelper) DeleteCustomCheckConfig(group string) error {
	cluster.Delete(share.CLUSCustomCheckConfigKey(group))
	return cluster.Delete(share.CLUSCustomCheckNetworkKey(group))
}

func (m clusterHelper) GetCrdRecord(name string) *share.CLUSCrdRecord {
	var records share.CLUSCrdRecord
	key := share.CLUSCrdQueueKey(name)
	if value, _, _ := m.get(key); value != nil {
		json.Unmarshal(value, &records)
		return &records
	}
	return nil
}

func (m clusterHelper) PutCrdRecord(record *share.CLUSCrdRecord, name string) error {
	key := share.CLUSCrdQueueKey(name)
	value, _ := json.Marshal(record)
	return m.putSizeAware(key, value)
}

func (m clusterHelper) DeleteCrdRecord(name string) error {
	key := share.CLUSCrdQueueKey(name)
	return cluster.Delete(key)
}

func (m clusterHelper) GetCrdEventQueue() *share.CLUSCrdEventRecord {
	var records share.CLUSCrdEventRecord
	key := share.CLUSCrdProcStore
	if value, _, _ := m.get(key); value != nil {
		json.Unmarshal(value, &records)
		return &records
	}
	return nil
}

func (m clusterHelper) PutCrdEventQueue(record *share.CLUSCrdEventRecord) error {
	key := share.CLUSCrdProcStore
	value, _ := json.Marshal(record)
	return m.putSizeAware(key, value)
}

func (m clusterHelper) DeleteAwsProjectCfg(projectName string) error {
	key := share.CLUSCloudCfgKey(share.CloudAws, projectName)
	return cluster.Delete(key)
}

func (m clusterHelper) GetAwsProjectCfg(projectName string, acc *access.AccessControl) (*share.CLUSAwsProjectCfg, error) {
	err := common.ErrObjectNotFound
	key := share.CLUSCloudCfgKey(share.CloudAws, projectName)
	if value, _, _ := m.get(key); value != nil {
		var state share.CLUSAwsProjectCfg
		json.Unmarshal(value, &state)
		if acc != nil && !acc.Authorize(&state, nil) {
			return nil, common.ErrObjectAccessDenied
		}
		return &state, nil
	}
	return nil, err
}

func (m clusterHelper) PutAwsProjectCfg(projectName string, record *share.CLUSAwsProjectCfg) error {
	key := share.CLUSCloudCfgKey(share.CloudAws, projectName)
	value, _ := enc.Marshal(record)
	return cluster.Put(key, value)
}

func (m clusterHelper) GetAwsCloudResource(projectName string) (*share.CLUSAwsResource, error) {
	err := common.ErrObjectNotFound
	key := share.CLUSCloudKey(share.CloudAws, projectName)
	if value, _, _ := m.get(key); value != nil {
		var state share.CLUSAwsResource
		json.Unmarshal(value, &state)
		return &state, nil
	}
	return nil, err
}

func (m clusterHelper) PutAwsCloudResource(project *share.CLUSAwsResource) error {
	key := share.CLUSCloudKey(share.CloudAws, project.ProjectName)
	value, _ := enc.Marshal(project)
	return cluster.Put(key, value)
}

func (m clusterHelper) DeleteAwsCloudResource(projectName string) error {
	return cluster.Delete(share.CLUSCloudKey(share.CloudAws, projectName))
}
func (m clusterHelper) GetAwsLambda(project, region, funcName string) *share.CLUSAwsFuncScanOutputList {
	key := share.CLUSCloudFuncKey(share.CloudAws, project, region, funcName)
	if value, _, _ := m.get(key); value != nil {
		var state share.CLUSAwsFuncScanOutputList
		json.Unmarshal(value, &state)
		return &state
	}
	return nil
}

func (m clusterHelper) PutAwsLambda(project, region, funcName string, output *share.CLUSAwsFuncScanOutputList) error {
	key := share.CLUSCloudFuncKey(share.CloudAws, project, region, funcName)
	value, _ := json.Marshal(output)
	return cluster.Put(key, value)
}

func (m clusterHelper) DeleteAwsLambda(project, region, funcName string) error {
	return cluster.Delete(share.CLUSCloudFuncKey(share.CloudAws, project, region, funcName))
}

// custom roles
func (m clusterHelper) GetAllCustomRoles(acc *access.AccessControl) map[string]*share.CLUSUserRole {
	keys, _ := cluster.GetStoreKeys(share.CLUSConfigUserRoleStore)
	roles := make(map[string]*share.CLUSUserRole, len(keys))
	for _, key := range keys {
		if value, _, _ := m.get(key); value != nil {
			var role share.CLUSUserRole
			json.Unmarshal(value, &role)
			if acc.Authorize(&role, nil) {
				roles[role.Name] = &role
			}
		}
	}

	return roles
}

func (m clusterHelper) GetCustomRoleRev(name string, acc *access.AccessControl) (*share.CLUSUserRole, uint64, error) {
	key := share.CLUSUserRoleKey(name)
	if value, rev, _ := m.get(key); value != nil {
		var role share.CLUSUserRole
		json.Unmarshal(value, &role)

		if !acc.Authorize(&role, nil) {
			return nil, 0, common.ErrObjectAccessDenied
		}

		return &role, rev, nil
	}
	return nil, 0, common.ErrObjectNotFound
}

func (m clusterHelper) PutCustomRoleRev(role *share.CLUSUserRole, rev uint64, acc *access.AccessControl) error {
	if !acc.Authorize(role, nil) {
		return common.ErrObjectAccessDenied
	}
	if role.Reserved {
		return fmt.Errorf("Failed to write to read-only role")
	}
	key := share.CLUSUserRoleKey(role.Name)
	value, _ := json.Marshal(role)
	return cluster.PutRev(key, value, rev)
}

func (m clusterHelper) CreateCustomRole(role *share.CLUSUserRole, acc *access.AccessControl) error {
	if !acc.Authorize(role, nil) {
		return common.ErrObjectAccessDenied
	}
	key := share.CLUSUserRoleKey(role.Name)
	value, _ := json.Marshal(role)
	return cluster.PutIfNotExist(key, value, false)
}

func (m clusterHelper) DeleteCustomRole(name string) error {
	key := share.CLUSUserRoleKey(name)
	return cluster.Delete(key)
}

func (m clusterHelper) SetCacheMockCallback(keyStore string, mockFunc MockKvConfigUpdateFunc) {}

func objCfgStore2networkStore(key string) string {
	switch share.CLUSConfigKey2Config(key) {
	case share.CFGEndpointFileMonitor:
		return share.CLUSFileMonitorNetworkKey(share.CLUSKeyLastToken(key))
	case share.CFGEndpointFileAccessRule:
		return share.CLUSFileAccessRuleNetworkKey(share.CLUSKeyLastToken(key))
	case share.CFGEndpointGroup:
		return share.CLUSGroupNetworkKey(share.CLUSKeyLastToken(key))
	case share.CFGEndpointScript:
		return share.CLUSCustomCheckNetworkKey(share.CLUSKeyLastToken(key))
	case share.CFGEndpointProcessProfile:
		return share.CLUSProfileKey(share.CLUSKeyLastToken(key))
	}
	return ""
}

func (m clusterHelper) duplicateProfileKey(key string, value []byte, txn *cluster.ClusterTransact, bPutIfNotExist bool) error {
	if !strings.HasPrefix(key, share.CLUSConfigStore) {
		return nil
	}

	// object/config/endpoint/name to profiles/
	if profileKey := objCfgStore2networkStore(key); profileKey != "" {
		group := share.CLUSKeyLastToken(profileKey)
		if !utils.HasGroupProfiles(group) {
			// skip non-profile groups, like "nv.ip.xxx"
			return nil
		}
		return dispatcher.PutProfile(group, profileKey, utils.GzipBytes(value), txn, bPutIfNotExist)
	}
	return nil
}

func (m clusterHelper) DuplicateNetworkKey(key string, value []byte) error {
	return m.duplicateProfileKey(key, value, nil, false)
}

func (m clusterHelper) DuplicateNetworkKeyIfNotExist(key string, value []byte) error {
	return m.duplicateProfileKey(key, value, nil, true)
}

func (m clusterHelper) DuplicateNetworkKeyTxn(txn *cluster.ClusterTransact, key string, value []byte) error {
	return m.duplicateProfileKey(key, value, txn, false)
}

// only restore the common profiles
func (m clusterHelper) RestoreNetworkKeys() {
	keys, _ := cluster.GetStoreKeys(share.CLUSConfigStore)
	for _, key := range keys {
		if profileKey := objCfgStore2networkStore(key); profileKey != "" {
			if utils.IsGroupNodes(share.CLUSKeyLastToken(profileKey)) {
				// restore keys only under the common profiles
				if value, _, _ := m.get(key); value != nil {
					profile := fmt.Sprintf("%s%s", share.CLUSNodeCommonStoreKey, profileKey)
					// log.WithFields(log.Fields{"from": key, "to": profile}).Debug("DPT: profile")
					cluster.PutQuiet(profile, utils.GzipBytes(value))
				}
			}
		}
	}
}

func (m clusterHelper) DuplicateNetworkSystemKeyTxn(txn *cluster.ClusterTransact, key string, value []byte) error {
	//restore/import need to duplicate network/system key/value
	//so that xff status is correctly pushed to dp
	if key == share.CLUSConfigSystemKey {
		if txn != nil {
			txn.PutQuiet(share.NetworkSystemKey, value)
		} else {
			return cluster.PutQuiet(share.NetworkSystemKey, value)
		}
	}
	return nil
}

// password profile
func (m clusterHelper) GetAllPwdProfiles(acc *access.AccessControl) map[string]*share.CLUSPwdProfile {
	if !acc.Authorize(&share.CLUSPwdProfile{}, nil) {
		return make(map[string]*share.CLUSPwdProfile)
	}

	keys, _ := cluster.GetStoreKeys(share.CLUSConfigPwdProfileStore)
	profiles := make(map[string]*share.CLUSPwdProfile, len(keys))
	for _, key := range keys {
		if value, _, _ := m.get(key); value != nil {
			var profile share.CLUSPwdProfile
			json.Unmarshal(value, &profile)
			profiles[profile.Name] = &profile
		}
	}

	return profiles
}

func (m clusterHelper) GetPwdProfileRev(name string, acc *access.AccessControl) (*share.CLUSPwdProfile, uint64, error) {
	key := share.CLUSPwdProfileKey(name)
	if value, rev, _ := m.get(key); value != nil {
		var profile share.CLUSPwdProfile
		json.Unmarshal(value, &profile)

		if !acc.Authorize(&profile, nil) {
			return nil, 0, common.ErrObjectAccessDenied
		}

		return &profile, rev, nil
	}
	return nil, 0, common.ErrObjectNotFound
}

func (m clusterHelper) PutPwdProfileRev(profile *share.CLUSPwdProfile, rev uint64) error {
	key := share.CLUSPwdProfileKey(profile.Name)
	value, _ := json.Marshal(profile)
	if rev == 0 {
		return cluster.Put(key, value)
	} else {
		return cluster.PutRev(key, value, rev)
	}
}

func (m clusterHelper) DeletePwdProfile(name string) error {
	key := share.CLUSPwdProfileKey(name)
	return cluster.Delete(key)
}

func (m clusterHelper) GetActivePwdProfileName() string {
	if value, _, _ := m.get(share.CLUSConfigPwdProfileStore); value != nil {
		var cfg share.CLUSActivePwdProfileConfig
		json.Unmarshal(value, &cfg)
		return cfg.Name
	}
	return share.CLUSDefPwdProfileName
}

func (m clusterHelper) PutActivePwdProfileName(name string) error {
	cfg := share.CLUSActivePwdProfileConfig{Name: name}
	value, _ := json.Marshal(&cfg)
	return cluster.Put(share.CLUSConfigPwdProfileStore, value)
}

// import task
func (m clusterHelper) GetImportTask() (share.CLUSImportTask, error) {
	key := share.CLUSImportOpKey(share.CLUSImportStatusSubKey)
	var importTask share.CLUSImportTask
	if value, _, _ := m.get(key); value != nil {
		json.Unmarshal(value, &importTask)
		return importTask, nil
	}
	return share.CLUSImportTask{}, common.ErrObjectNotFound
}

func (m clusterHelper) PutImportTask(importTask *share.CLUSImportTask) error {
	importTask.LastUpdateTime = time.Now().UTC()
	key := share.CLUSImportOpKey(share.CLUSImportStatusSubKey)
	value, _ := json.Marshal(importTask)
	return cluster.Put(key, value)
}

package kv

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	admission "github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

type RevertFedRolesFunc func(acc *access.AccessControl)
type PostImportFunc func(err error, importTask share.CLUSImportTask, loginDomainRoles access.DomainRole, tempToken, importType string)
type PauseResumeStoreWatcherFunc func(ip string, port uint16, req share.CLUSStoreWatcherInfo) error

type ConfigHelper interface {
	NotifyConfigChange(endpoint string)
	BackupAll()
	Restore() (string, bool, bool, string, error)
	Export(w *bufio.Writer, sections utils.Set) error
	Import(eps []*common.RPCEndpoint, localCtrlerID, localCtrlerIP string, loginDomainRoles access.DomainRole, importTask share.CLUSImportTask,
		tempToken string, revertFedRoles RevertFedRolesFunc, postImportOp PostImportFunc, pauseResumeStoreWatcher PauseResumeStoreWatcherFunc,
		ignoreFed bool) error
}

var ErrInvalidFileFormat = errors.New("Invalid file format")
var ErrIORead = errors.New("Failed on IO read")
var ErrIOWrite = errors.New("Failed on IO write")
var ErrCluster = errors.New("Failed to access cluster")
var ErrIncompatibleFedRole = errors.New("File is from an incompatible federal-role cluster")
var ErrIncompatibleFedRoleEx = errors.New(`It's not allowed to import from federal-managed cluster to standalone cluster. To override it, select "Import configuration as standalone cluster" and try again`)

type configHelper struct {
	id          string
	version     string
	backupTimer *time.Timer
	cfgMutex    sync.Mutex
	cfgChanged  utils.Set
	persist     bool
}

type fedRulesRevInfo struct {
	fedRulesRevValue string
	fedRole          string
	defAdminRestored bool
}

const clusterLockWait = time.Duration(time.Second * 20)
const NeuvectorDir = "/var/neuvector/"
const configBackupDir = NeuvectorDir + "config/backup/"
const backupDelayIdle = time.Duration(time.Second * 10)

var cfgHelper *configHelper

var orchPlatform string
var orchFlavor string

var evqueue cluster.ObjectQueueInterface

func newConfigHelper(id, version string, persist bool) ConfigHelper {
	c := new(configHelper)
	c.id = id
	c.version = version
	c.persist = persist
	c.backupTimer = time.NewTimer(backupDelayIdle)
	c.backupTimer.Stop()
	c.cfgChanged = utils.NewSet()
	c.startBackupThread()

	cfgHelper = c
	return c
}

func GetConfigHelper() ConfigHelper {
	return cfgHelper
}

func Init(id, version, platform, flavor string, persist bool, isGroupMember FuncIsGroupMember, getConfigData FuncGetConfigKVData,
	evQueue cluster.ObjectQueueInterface) {

	evqueue = evQueue
	for _, ep := range cfgEndpoints {
		cfgEndpointMap[ep.name] = ep
	}

	newConfigHelper(id, version, persist)
	clusHelper = newClusterHelper(id, version, persist)

	orchPlatform = platform
	orchFlavor = flavor
	initDispatcher(isGroupMember, getConfigData)
}

// --

var errDone = errors.New("Done")

func applyTransaction(txn *cluster.ClusterTransact, importTask *share.CLUSImportTask, updateKV bool, processedLines int) {
	if txn.Size() > 0 {
		if ok, err := txn.Apply(); err != nil || !ok {
			log.WithFields(log.Fields{"error": err}).Error("Atomic write failed")
		} else {
			txn.Reset()
		}
		if importTask != nil {
			importTask.LastUpdateTime = time.Now().UTC()
			if updateKV {
				if importTask.TotalLines > 0 {
					percentage := int(processedLines*100) / importTask.TotalLines
					if percentage > 3 {
						importTask.Percentage = percentage
					}
				}
				if importTask.Status != share.IMPORT_RUNNING {
					importTask.Status = share.IMPORT_RUNNING
				}
				clusHelper.PutImportTask(importTask)
			}
		}
	}
}

// Instead of acquiring and releasing lock for every endpoint, this foreach function retains the lock
// if the next endpoint has the same lock key, so we have an atomic operation.
func (c *configHelper) foreachWithLock(eps []*cfgEndpoint, act func(ep *cfgEndpoint, txn *cluster.ClusterTransact) error, importTask *share.CLUSImportTask) error {
	var lastLockKey string
	var lastLock cluster.LockInterface
	var rc error

	txn := cluster.Transact()
	for _, ep := range eps {
		if lastLock == nil || lastLockKey != ep.lock {
			if lastLock != nil {
				applyTransaction(txn, importTask, true, 0)
				clusHelper.ReleaseLock(lastLock)
				lastLock = nil
				lastLockKey = ""
			}

			if lock, err := clusHelper.AcquireLock(ep.lock, clusterLockWait); err != nil {
				continue
			} else {
				lastLock = lock
				lastLockKey = ep.lock
			}
		}

		if rc = act(ep, txn); rc == errDone {
			rc = nil
			break
		} else if rc != nil {
			break
		}
	}

	if lastLock != nil {
		applyTransaction(txn, importTask, true, 0)
		clusHelper.ReleaseLock(lastLock)
	}

	return rc
}

// 'get' is called to get endpoint name; 'act' is to take action on the endpoint
func (c *configHelper) loopWithLock(get func() (string, error), act func(ep *cfgEndpoint, txn *cluster.ClusterTransact) error,
	importTask *share.CLUSImportTask, processedLines *int) error {
	var lastEpName string
	var lastLockKey string
	var lastLock cluster.LockInterface
	var rc error

	txn := cluster.Transact()
	for {
		var name string

		if name, rc = get(); rc == errDone {
			rc = nil
			break
		} else if rc != nil {
			break
		}

		ep, ok := cfgEndpointMap[name]
		if !ok || lastLock == nil || lastLockKey != ep.lock {
			if lastLock != nil {
				applyTransaction(txn, importTask, true, *processedLines)
				if txn.Size() > 0 && lastEpName == share.CFGEndpointPolicy {
					log.Debug("gzip successfully import")
				}
				clusHelper.ReleaseLock(lastLock)
				lastLock = nil
				lastLockKey = ""
			}

			if !ok {
				log.WithFields(log.Fields{"endpoint": name}).Error("Ignore unknown endpoint")
				continue
			}

			if lock, err := clusHelper.AcquireLock(ep.lock, clusterLockWait); err != nil {
				continue
			} else {
				lastLock = lock
				lastLockKey = ep.lock
			}
		}

		if lastEpName != name {
			lastEpName = name
		}

		if rc = act(ep, txn); rc == errDone {
			rc = nil
			break
		} else if rc != nil {
			break
		}
	}

	if lastLock != nil {
		applyTransaction(txn, importTask, true, *processedLines)
		clusHelper.ReleaseLock(lastLock)
	}

	return rc
}

func (c *configHelper) startBackupThread() {
	go func() {
		for {
			select {
			case <-c.backupTimer.C:
				c.doBackup()
			}
		}
	}()
}

func (c *configHelper) NotifyConfigChange(endpoint string) {
	if !c.persist {
		return
	}

	log.WithFields(log.Fields{"endpoint": endpoint}).Debug()

	c.cfgMutex.Lock()
	c.cfgChanged.Add(endpoint)
	c.cfgMutex.Unlock()
	c.backupTimer.Reset(backupDelayIdle)
}

func (c *configHelper) isKvRestoring() (string, bool) {
	var kvRestore share.CLUSKvRestore

	value, _ := cluster.Get(share.CLUSKvRestoreKey)
	if value != nil {
		json.Unmarshal(value, &kvRestore)
		if !kvRestore.StartAt.IsZero() && time.Since(kvRestore.StartAt) < time.Duration(2)*time.Minute {
			return kvRestore.CtrlerID, true
		}
	}

	return "", false
}

func (c *configHelper) doBackup() error {
	if !c.persist {
		return nil
	}

	log.Debug()

	if id, restoring := c.isKvRestoring(); restoring {
		log.WithFields(log.Fields{"id": id}).Debug("Restoring is ongoing")
		return nil
	} else {
		ver := getControlVersion()
		if ver.CtrlVersion == "" && ver.KVVersion == "" {
			return nil
		}
	}

	// Make a copy of changed sections so we don't hold the lock for too long
	c.cfgMutex.Lock()
	changes := c.cfgChanged.Clone()
	c.cfgChanged.Clear()
	c.cfgMutex.Unlock()

	if !IsImporting() {
		fedRole, _ := getFedRole()
		return c.foreachWithLock(cfgEndpoints, func(ep *cfgEndpoint, txn *cluster.ClusterTransact) error { // txn is not used for backup
			if changes.Contains(ep.name) {
				ep.backup(fedRole)
			}
			return nil
		}, nil)
	} else {
		return fmt.Errorf("Another import is ongoing")
	}
}

func (c *configHelper) BackupAll() {
	if !c.persist {
		log.Debug("Config persistence disabled")
		return
	}

	log.Debug()

	// Set all endpoints as to-be-backup and wait for the idel timeout
	c.cfgMutex.Lock()
	for _, ep := range cfgEndpoints {
		c.cfgChanged.Add(ep.name)
	}
	c.cfgMutex.Unlock()
	c.backupTimer.Reset(backupDelayIdle)
	c.writeBackupVersion()
}

func restoreEP(ep *cfgEndpoint, ch chan<- error, importInfo *fedRulesRevInfo) error {
	var rc error

	txn := cluster.Transact()
	if rc = ep.restore(importInfo, txn); rc == errDone {
		rc = nil
	} else if rc != nil {
		log.WithFields(log.Fields{"endpoint": ep.name, "rc": rc}).Error()
	}
	applyTransaction(txn, nil, false, 0)

	if ch != nil {
		ch <- rc
	}

	return rc
}

func restoreEPs(eps utils.Set, ch chan error, importInfo *fedRulesRevInfo) error {
	var err error

	for ep_ := range eps.Iter() {
		ep := ep_.(*cfgEndpoint)
		go restoreEP(ep, ch, importInfo)
	}
	if ch != nil {
		for j := 0; j < eps.Cardinality(); j++ {
			if rc := <-ch; rc != nil {
				err = rc
			}
		}
	}

	return err
}

func (c *configHelper) Restore() (string, bool, bool, string, error) {
	log.Info()

	if !c.persist {
		// For test only!!
		// forgeKVData()

		log.Info("Config persistence disabled")
		// backward-compatibile: update network/config as needed
		clusHelper.RestoreNetworkKeys()

		scanRevs, rev, err := clusHelper.GetFedScanRevisions()
		if err == nil && scanRevs.Restoring {
			scanRevs.Restoring = false
			clusHelper.PutFedScanRevisions(&scanRevs, &rev)
		}

		return "", false, false, "", nil
	} else {
		kvRestore := share.CLUSKvRestore{StartAt: time.Now(), CtrlerID: c.id}
		kvRestoreValue, _ := json.Marshal(&kvRestore)
		if lock, err := clusHelper.AcquireLock(share.CLUSLockRestoreKey, time.Duration(time.Second)); err == nil {
			skipRestore := false
			ver := GetControlVersion()
			if ver.CtrlVersion == "" && ver.KVVersion == "" {
				if id, restoring := c.isKvRestoring(); restoring {
					log.WithFields(log.Fields{"id": id}).Info("Restoring is ongoing")
					skipRestore = true
				} else {
					cluster.Put(share.CLUSKvRestoreKey, kvRestoreValue)
				}
			} else {
				log.WithFields(log.Fields{"ver": ver}).Info("No need")
				skipRestore = true
			}
			clusHelper.ReleaseLock(lock)
			if skipRestore {
				return "", false, false, "", nil
			}
		} else {
			return "", false, false, "", nil
		}
	}

	importInfo := fedRulesRevInfo{}

	// When running outside of container in the dev. environment, this function normally is not needed.
	// kv store file still exist. In the container, kv store file is empty at startup, no need purge.
	var err error
	ch := make(chan error)
	eps := utils.NewSetFromSliceKind(cfgEndpoints)

	// restore federation endpoint
	if rc := restoreEP(fedCfgEndpoint, nil, &importInfo); rc != nil {
		err = rc
	}
	eps.Remove(fedCfgEndpoint)

	// restore process profile/file monitor/access rule endpoints to avoid unnecessary kv PutIfNotExists calls when groups are updated in cache
	priorityCfgEndpoints := utils.NewSet(pprofileCfgEndpoint, fmonitorCfgEndpoint, faccessCfgEndpoint, sigstoreCfgEndpoint, registryCfgEndpoint)
	if rc := restoreEPs(priorityCfgEndpoints, ch, &importInfo); rc != nil {
		err = rc
	}
	eps = eps.Difference(priorityCfgEndpoints)

	// restore group endpoint
	if rc := restoreEP(groupCfgEndpoint, nil, &importInfo); rc != nil {
		err = rc
	}
	eps.Remove(groupCfgEndpoint)

	if rc := restoreEPs(eps, ch, &importInfo); rc != nil {
		err = rc
	}

	go restoreRegistry(ch, importInfo)

	ver := getBackupVersion()
	putControlVersion(&ver)
	log.WithFields(log.Fields{"version": ver}).Info("Done")

	if len(importInfo.fedRulesRevValue) > 0 {
		log.WithFields(log.Fields{"fedRulesRevValue": importInfo.fedRulesRevValue}).Info()
		var fedRulesRev share.CLUSFedRulesRevision
		if err := json.Unmarshal([]byte(importInfo.fedRulesRevValue), &fedRulesRev); err == nil {
			clusHelper.PutFedRulesRevision(nil, &fedRulesRev)
		}
	}

	cluster.Delete(share.CLUSKvRestoreKey)

	return importInfo.fedRole, importInfo.defAdminRestored, true, ver.KVVersion, err
}

type configHeader struct {
	share.CLUSCtrlVersion
	CreatedAt        string   `json:"created_at"`
	Sections         []string `json:"sections"`
	ExportedFromRole string   `json:"exported_from_role"`
}

func getFedRole() (string, *share.CLUSFedRulesRevision) {
	var fedRole string
	m := clusHelper.GetFedMembership()
	if m != nil {
		fedRole = m.FedRole
	}
	data, _ := clusHelper.GetFedRulesRevisionRev()
	return fedRole, data
}

// the written-to-file exported values are always in text format
func (c *configHelper) Export(w *bufio.Writer, sections utils.Set) error {
	log.WithFields(log.Fields{"sections": sections}).Debug()

	now := time.Now()
	fedRole, _ := getFedRole()

	header := &configHeader{
		CLUSCtrlVersion: share.CLUSCtrlVersion{
			CtrlVersion: c.version,
			KVVersion:   latestKVVersion(),
		},
		CreatedAt:        api.RESTTimeString(now),
		ExportedFromRole: fedRole,
	}
	if sections.Contains(api.ConfSectionAll) {
		sections.Remove(api.ConfSectionAll)
		for _, ep := range cfgEndpoints {
			sections.Add(ep.section)
		}
	}
	// Fill header.Sections with order
	added := utils.NewSet()
	for _, ep := range cfgEndpoints {
		if sections.Contains(ep.section) && !added.Contains(ep.section) {
			header.Sections = append(header.Sections, ep.section)
			added.Add(ep.section)
		}
	}

	value, _ := json.Marshal(header)
	line := fmt.Sprintf("%s\n", value)
	if _, err := w.WriteString(line); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to write header")
		return ErrIOWrite
	}

	err := c.foreachWithLock(cfgEndpoints, func(ep *cfgEndpoint, txn *cluster.ClusterTransact) error { // txn is not used for export
		if sections.Contains(ep.section) {
			if err := ep.write(w, fedRole); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Failed to write key/value")
				return ErrIOWrite
			}
		}
		return nil
	}, nil)

	log.Debug("Done")

	return err
}

func (c *configHelper) sections2Endpoints(sections []string) []*cfgEndpoint {
	var eps []*cfgEndpoint
	for _, ep := range cfgEndpoints {
		for _, s := range sections {
			if s == api.ConfSectionAll || s == ep.section {
				eps = append(eps, ep)
			}
		}
	}
	return eps
}

//  1. When import, cluster name is always replaced with the cluster name(if available) specified in the backup file
//  2. When import, fed rules are always replaced with the fed rules specified in the backup file.
//  3. For clusters in fed, Import() doesn't change the existing clusters membership.
//  4. For stand-alone cluster, we allow it to promote to master cluster by importing a master cluster's backup file.
//     However, joined clusters list is not imported. Customer needs to manually trigger join-fed operation.
func (c *configHelper) Import(rpcEps []*common.RPCEndpoint, localCtrlerID, localCtrlerIP string, loginDomainRoles access.DomainRole, importTask share.CLUSImportTask,
	tempToken string, revertFedRoles RevertFedRolesFunc, postImportOp PostImportFunc, pauseResumeStoreWatcher PauseResumeStoreWatcherFunc, ignoreFed bool) error {
	log.Debug()
	defer os.Remove(importTask.TempFilename)

	watcherPaused := false
	err := c.importInternal(rpcEps, localCtrlerID, localCtrlerIP, &importTask, revertFedRoles, pauseResumeStoreWatcher, &watcherPaused, ignoreFed)
	if watcherPaused {
		cluster.ResumeWatcher(share.CLUSObjectStore)
		watcherInfo := share.CLUSStoreWatcherInfo{
			CtrlerID: localCtrlerID,
			Key:      share.CLUSObjectStore,
			Action:   share.StoreWatcherAction_ResumeWatcher,
		}
		for _, rpcEp := range rpcEps {
			if rpcEp.ClusterIP != localCtrlerIP {
				pauseResumeStoreWatcher(rpcEp.ClusterIP, rpcEp.RPCServerPort, watcherInfo)
			}
		}
	}
	postImportOp(err, importTask, loginDomainRoles, tempToken, share.IMPORT_TYPE_CONFIG)

	return nil
}

// value of each key in the file is always in text format (i.e. non-gzip format). Compress it if it's >= 512k before importing to kv
func (c *configHelper) importInternal(rpcEps []*common.RPCEndpoint, localCtrlerID, localCtrlerIP string, importTask *share.CLUSImportTask,
	revertFedRoles RevertFedRolesFunc, pauseResumeStoreWatcher PauseResumeStoreWatcherFunc, watcherPaused *bool, ignoreFed bool) error {
	log.Debug()

	file, err := os.Open(importTask.TempFilename)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to open file")
		return ErrInvalidFileFormat
	}
	defer file.Close()

	var processedLines int
	r := bufio.NewReader(file)
	line, err := r.ReadBytes('\n')
	if err == io.EOF {
		log.Error("Unexpected end of file")
		return ErrInvalidFileFormat
	} else if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to read header")
		return ErrInvalidFileFormat
	}

	var importFedRole string
	var header configHeader
	if err = json.Unmarshal(line, &header); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to unmarshal header")
		return ErrInvalidFileFormat
	}

	currFedRole, currFedRulesRev := getFedRole()
	log.WithFields(log.Fields{"currFedRole": currFedRole, "ignoreFed": ignoreFed}).Info("Before import")
	if i := strings.Index(string(line), `"exported_from_role"`); i > 0 {
		// if the export is from 3.2(which has "exported_from_role" field) or newer, we can check if the import is allowed or not earlier
		importFedRole = header.ExportedFromRole
		if currFedRole == importFedRole || (currFedRole == api.FedRoleNone && importFedRole == api.FedRoleMaster) {
			// 1. stand-alone cluster can import master cluster's exported config (so it's promoted but has no worker clusters)
			// 2. otherwise, only exported config from the same fedRole as current cluster could be imported
			log.WithFields(log.Fields{"fedRole": importFedRole}).Info("Will import from")
			ignoreFed = false
		} else {
			if currFedRole == api.FedRoleNone && importFedRole == api.FedRoleJoint {
				if ignoreFed {
					log.Info("Will import as standalone")
				} else {
					return ErrIncompatibleFedRoleEx
				}
			} else {
				return ErrIncompatibleFedRole
			}
		}
	}

	importInfo := fedRulesRevInfo{}

	// Get all the endpoints to be imported
	eps := c.sections2Endpoints(header.Sections)

	importTask.Percentage += 1
	importTask.LastUpdateTime = time.Now().UTC()
	importTask.Status = share.IMPORT_RUNNING
	clusHelper.PutImportTask(importTask)

	// Consul gets unexpectedly killed while importing a large file. We suspect the active write and watch
	// actions triggers race conditions in consul, so here the object store watch is paused.
	// The watcher is not paused in other controllers, to avoid the complications of making sure 'resume'
	// is called in all conditions.
	cluster.PauseWatcher(share.CLUSObjectStore)
	*watcherPaused = true
	watcherInfo := share.CLUSStoreWatcherInfo{
		CtrlerID: localCtrlerID,
		Key:      share.CLUSObjectStore,
		Action:   share.StoreWatcherAction_PauseWatcher,
	}
	for _, rpcEp := range rpcEps {
		if rpcEp.ClusterIP != localCtrlerIP {
			pauseResumeStoreWatcher(rpcEp.ClusterIP, rpcEp.RPCServerPort, watcherInfo)
		}
	}

	// Purge keys of the endpoints to be imported
	c.foreachWithLock(eps, func(ep *cfgEndpoint, txn *cluster.ClusterTransact) error {
		ep.purge(txn, importTask)
		return nil
	}, importTask)

	// delete/reset scan/state/scan_revisions key when necessary
	if currFedRole == api.FedRoleJoint {
		for _, s := range header.Sections {
			if s == api.ConfSectionAll || s == api.ConfSectionConfig {
				key := share.CLUSScanStateKey(share.CLUSFedScanDataRevSubKey)
				if importFedRole == api.FedRoleNone {
					cluster.Delete(key)
				} else if importFedRole == api.FedRoleJoint {
					scanRevs := share.CLUSFedScanRevisions{
						ScannedRegRevs: make(map[string]uint64),
					}
					value, _ := json.Marshal(&scanRevs)
					cluster.Put(key, value)
				}
				break
			}
		}
	}

	importTask.Percentage += 1
	importTask.LastUpdateTime = time.Now().UTC()
	clusHelper.PutImportTask(importTask)

	// Import key/value from files
	var key, value string

	policyZipRuleListKey := share.CLUSPolicyZipRuleListKey(share.DefaultPolicyName)
	rerr := c.loopWithLock(
		func() (string, error) {
			var err error

			key, value, err = readKeyValue(r)
			if err == io.EOF {
				return "", errDone
			} else if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Failed to read line")
				return "", ErrInvalidFileFormat
			}
			processedLines += 2

			return share.CLUSConfigKey2Config(key), nil
		},
		func(ep *cfgEndpoint, txn *cluster.ClusterTransact) error {
			if skipKeys, ok := _skipKeyInfo[ep.name]; ok {
				for _, skipKeyPath := range skipKeys {
					if key == skipKeyPath { // this key should be skipped
						return nil
					}
				}
			}

			if ep.name == share.CFGEndpointFederation {
				subKey := share.CLUSKeyNthToken(key, 3)
				if subKey == share.CLUSFedMembershipSubKey {
					if ignoreFed {
						var m share.CLUSFedMembership
						b, _ := json.Marshal(m)
						value = string(b)
					}
					var m share.CLUSFedMembership
					var dec common.DecryptUnmarshaller
					if err := dec.Unmarshal([]byte(value), &m); err == nil {
						importFedRole = m.FedRole
						if currFedRole == api.FedRoleJoint && importFedRole != api.FedRoleMaster {
							// force a full fed rules sync because fed rules_revision is unavailable in non-master clusters' backup file
							clusHelper.PutFedRulesRevision(txn, share.CLUSEmptyFedRulesRevision())
						}
						log.WithFields(log.Fields{"fedRole": importFedRole}).Info("Will import from")
					}
					if currFedRole == "" && importFedRole == api.FedRoleMaster {
						// for stand-alone cluster, we allow it to promote to master cluster by importing master cluster's backup file
					} else {
						// otherwise, Import() doesn't change the existing clusters membership.
						return nil
					}
				} else if subKey == share.CLUSFedClustersSubKey {
					// do not change the joint clusters list no matter what
					return nil
				} else if subKey == share.CLUSFedRulesRevisionSubKey {
					if currFedRole == api.FedRoleMaster || importFedRole == api.FedRoleMaster {
						// force a full fed rules sync because fed rules could have changed because of import
						if currFedRulesRev == nil {
							currFedRulesRev = &share.CLUSFedRulesRevision{}
						}
						for k, v := range currFedRulesRev.Revisions {
							currFedRulesRev.Revisions[k] = v + 1
						}
						fedRulesRev, _ := json.Marshal(*currFedRulesRev)
						importInfo.fedRulesRevValue = string(fedRulesRev)
						// do not write to kv now. postpone it at the last write
						return nil
					}
				}
			} else if ep.name == share.CFGEndpointUser {
				var u share.CLUSUser
				for _, field := range []string{"block_login_since", "last_login_at", "pwd_reset_time"} {
					strOld := fmt.Sprintf("\"%s\":\"\"", field)
					strNew := fmt.Sprintf("\"%s\":\"0001-01-01T00:00:00Z\"", field)
					value = strings.Replace(value, strOld, strNew, 1)
				}
				if err := json.Unmarshal([]byte(value), &u); err == nil {
					u.FailedLoginCount = 0
					u.BlockLoginSince = time.Time{}
					u.PwdResetTime = time.Now().UTC()
					data, _ := json.Marshal(&u)
					value = string(data)
				}
			}

			// Value can be empty if a key was never been written when it's exported. No need to
			// write empty string because keys have been purged.
			if len(value) != 0 {
				array, err := upgrade(key, []byte(value))
				if err != nil {
					log.WithFields(log.Fields{"error": err, "key": key, "value": value}).Error("Failed to upgrade key/value")
					return ErrInvalidFileFormat
				}
				if key == policyZipRuleListKey {
					applyTransaction(txn, importTask, true, processedLines)
					//compress rulelist before put to cluster
					clusHelper.PutPolicyRuleListZip(key, array)
				} else {
					clusHelper.DuplicateNetworkKeyTxn(txn, key, array)
					//for CLUSConfigSystemKey only
					clusHelper.DuplicateNetworkSystemKeyTxn(txn, key, array)
					if len(array) >= cluster.KVValueSizeMax && strings.HasPrefix(key, share.CLUSConfigCrdStore) { // 512 * 1024
						zb := utils.GzipBytes(array)
						txn.PutBinary(key, zb)
					} else {
						txn.Put(key, array)
					}
					if txn.Size() >= 64 || (ep.name == share.CFGEndpointAdmissionControl && key == "object/config/admission_control/default/state") {
						applyTransaction(txn, importTask, true, processedLines)
						if ep.name == share.CFGEndpointAdmissionControl && key == "object/config/admission_control/default/state" {
							//time.Sleep(time.Second) // so that controllers have chance to update cache
							var state share.CLUSAdmissionState
							if err := json.Unmarshal([]byte(value), &state); err == nil {
								if ctrlState := state.CtrlStates[admission.NvAdmValidateType]; ctrlState != nil {
									var failurePolicy string
									if state.FailurePolicy == resource.FailLower {
										failurePolicy = resource.Fail
									} else {
										failurePolicy = resource.Ignore
									}
									k8sResInfo := admission.ValidatingWebhookConfigInfo{
										Name: resource.NvAdmValidatingName,
										WebhooksInfo: []*admission.WebhookInfo{
											&admission.WebhookInfo{
												Name: resource.NvAdmValidatingWebhookName,
												ClientConfig: admission.ClientConfig{
													ClientMode:  state.AdmClientMode,
													ServiceName: resource.NvAdmSvcName,
													Path:        ctrlState.Uri,
												},
												FailurePolicy:  failurePolicy,
												TimeoutSeconds: state.TimeoutSeconds,
											},
											&admission.WebhookInfo{
												Name: resource.NvStatusValidatingWebhookName,
												ClientConfig: admission.ClientConfig{
													ClientMode:  state.AdmClientMode,
													ServiceName: resource.NvAdmSvcName,
													Path:        ctrlState.NvStatusUri,
												},
												FailurePolicy:  resource.Ignore,
												TimeoutSeconds: state.TimeoutSeconds,
											},
										},
									}
									admission.ConfigK8sAdmissionControl(&k8sResInfo, ctrlState)
								}
							}
						}
					}
				}
			}
			return nil
		},
		importTask,
		&processedLines,
	)

	if rerr != nil {
		// TO DO: revert prior partial import in case it fails
		return rerr
	}

	if !ignoreFed && importFedRole != currFedRole {
		lock, err := clusHelper.AcquireLock(share.CLUSLockFedKey, clusterLockWait)
		if err != nil {
			log.WithFields(log.Fields{"error": err, "key": key}).Error("Failed to acquire cluster lock")
		} else {
			accAdmin := access.NewFedAdminAccessControl()
			if currFedRole == api.FedRoleMaster ||
				(importFedRole == api.FedRoleMaster && len(header.Sections) == 1 && header.Sections[0] == api.ConfSectionPolicy) {
				// For these 2 cases, we need to promote default admin to fedAdmin explicitly:
				// 1. non-master cluster's All/User backup file(from 3.0/3.1) to master cluster (because default admin is overwritten to be non-fedAdmin)
				// 2. master cluster's Policy backup file to standalone cluster (because default admin's role is not updated by Policy backup file)
				clusHelper.ConfigFedRole(common.DefaultAdminUser, api.UserRoleFedAdmin, accAdmin)
			} else if ((currFedRole == api.FedRoleNone && len(header.Sections) == 1 && header.Sections[0] == api.ConfSectionUser) ||
				currFedRole == api.FedRoleJoint) && importFedRole == api.FedRoleMaster {
				// For these 2 cases, we need to demote all fedAdmin users to admin explicitly explicitly:
				// 1. When import master cluster's backup file to joint cluster, default admin is overwritten to be fedAdmin.
				// 2. When import master cluster's User backup file to stand-alone cluster, default admin is overwritten to be fedAdmin.
				revertFedRoles(accAdmin)
			}
			clusHelper.ReleaseLock(lock)
		}
	}

	//imported config file can be from older/newer version image
	//need to go through upgrade process
	importVer := &share.CLUSCtrlVersion{
		CtrlVersion: header.CtrlVersion,
		KVVersion:   header.KVVersion,
	}
	clusHelper.UpgradeClusterImport(importVer)

	profile := &share.CLUSVulnerabilityProfile{
		Name:    share.DefaultVulnerabilityProfileName,
		Entries: make([]*share.CLUSVulnerabilityProfileEntry, 0),
	}
	clusHelper.PutVulnerabilityProfileIfNotExist(profile)
	createDefaultComplianceProfile()

	if len(importInfo.fedRulesRevValue) > 0 {
		var fedRulesRev share.CLUSFedRulesRevision
		if err := json.Unmarshal([]byte(importInfo.fedRulesRevValue), &fedRulesRev); err == nil {
			clusHelper.PutFedRulesRevision(nil, &fedRulesRev)
		}
	}

	return nil
}

func backupVersionFileName() string {
	return fmt.Sprintf("%s%s.backup", configBackupDir, "version")
}

func getBackupVersion() share.CLUSCtrlVersion {
	var ver share.CLUSCtrlVersion

	source := backupVersionFileName()
	if _, err := os.Stat(source); os.IsNotExist(err) {
		log.Info("Backup doesn't have a version file")
		return ver
	}

	f, err := os.Open(source)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "file": source}).Error("Unable to open version file")
		return ver
	}

	defer f.Close()

	// Restore key/value from files
	r := bufio.NewReader(f)
	value, err := r.ReadString('\n')
	if err == io.EOF || err != nil {
		log.WithFields(log.Fields{"error": err, "file": source}).Error("Unable to read file")
		return ver
	} else {
		json.Unmarshal([]byte(value), &ver)
		return ver
	}
}

func (c *configHelper) writeBackupVersion() error {
	if !c.persist {
		log.Debug("Config persistence disabled")
		return nil
	}

	source := backupVersionFileName()
	if _, err := os.Stat(configBackupDir); os.IsNotExist(err) {
		if err = os.MkdirAll(configBackupDir, 0755); err != nil {
			log.WithFields(log.Fields{"error": err, "dir": configBackupDir}).Error("Failed to make directory")
			return err
		}
	}

	f, err := os.Create(source)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "file": source}).Error("Unable to create file to write")
		return err
	}
	defer f.Close()

	ver := share.CLUSCtrlVersion{
		CtrlVersion: c.version,
		KVVersion:   latestKVVersion(),
	}
	value, _ := json.Marshal(&ver)
	fmt.Fprintf(f, "%s\n", value)

	return nil
}

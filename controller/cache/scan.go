package cache

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/controller/rpc"
	"github.com/neuvector/neuvector/controller/scan"
	"github.com/neuvector/neuvector/controller/scheduler"
	"github.com/neuvector/neuvector/db"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/global"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
)

type scannerCache struct {
	scanner  *share.CLUSScanner
	errCount int
}

type regImageSummaryReport struct {
	Summary []byte
	Report  *share.CLUSScanReport
}

var scannerCacheMap map[string]*scannerCache = make(map[string]*scannerCache)

// grpc call should timeout in scanReqTimeout
const scanReqTimeout = time.Second * 180

const scannerCleanupPeriod = time.Duration(time.Minute * 1)
const scannerClearnupTimeout = time.Second * 20
const scannerClearnupErrorMax = 3

const (
	statusScanNone = iota
	statusScanScheduled
	statusScanning
)

type scanInfo struct {
	agentId                        string
	status                         int
	lastResult                     share.ScanErrorCode
	lastScanTime                   time.Time
	baseOS                         string
	priority                       scheduler.Priority
	retry                          int
	objType                        share.ScanObjectType
	version                        string
	cveDBCreateTime                string
	brief                          *api.RESTScanBrief // Stats of filtered entries
	filteredTime                   time.Time
	idns                           []api.RESTIDName
	signatureVerifiers             []string
	signatureVerificationTimestamp string
}

type scanTaskInfo struct {
	id   string
	info *scanInfo
}

type tAutoScaleHistory struct {
	oldReplicas    uint32 // the scanners count before autoscale
	newReplicas    uint32 // the scanners count after autoscale
	sameScaleTimes uint32 // how many times we continuously scale with the same from/to replicas values
}

const maxRetry = 5

var scanCfg share.CLUSScanConfig
var scanScher scheduler.Schd
var scanMap map[string]*scanInfo = make(map[string]*scanInfo)

const (
	task_Q_Unknown = iota
	task_Q_Empty
	task_Q_NonEmpty
)

var scannerReplicas uint32
var lastTaskQState int = task_Q_Unknown
var contTaskQStateTime time.Time // start time of the time window for scaling up/down calculation

var autoScaleHistory tAutoScaleHistory

// Within scanMutex, cacheMutex can be used; but not the other way around.
var scanMutex sync.RWMutex

func scanMutexLock() {
	cctx.MutexLog.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("Acquire ...")
	scanMutex.Lock()
}

func scanMutexUnlock() {
	scanMutex.Unlock()
	cctx.MutexLog.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("Released")
}

func scanMutexRLock() {
	cctx.MutexLog.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("Acquire ...")
	scanMutex.RLock()
}

func scanMutexRUnlock() {
	scanMutex.RUnlock()
	cctx.MutexLog.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("Released")
}

type scanTask struct {
	id       string
	priority scheduler.Priority
}

func (t *scanTask) Key() string {
	return t.id
}

func (t *scanTask) Priority() scheduler.Priority {
	return t.priority
}

func (t *scanTask) Print(msg string) {
	cctx.ScanLog.WithFields(log.Fields{"id": t.id}).Debug(msg)
}

func (t *scanTask) rpcScanRunning(scanner string, info *scanInfo) {
	var result *share.ScanResult
	var err error

	if info.objType == share.ScanObjectType_CONTAINER {
		result, err = rpc.ScanRunning(scanner, info.agentId, t.id, share.ScanObjectType_CONTAINER, scanReqTimeout)
	} else if info.objType == share.ScanObjectType_HOST {
		result, err = rpc.ScanRunning(scanner, info.agentId, t.id, share.ScanObjectType_HOST, scanReqTimeout)
		if result != nil {
			// TODO: this is a temp. solution to add RancherOS CVEs. Should be added in the database.
			result, err = appendRancherOSCVE(t.id, result, err)
		}
	} else {
		// Do we need get version again? Can k8s be upgraded without restarting controller?
		cctx.k8sVersion, cctx.ocVersion = global.ORCH.GetVersion(false, false)
		result, err = rpc.ScanPlatform(scanner, cctx.k8sVersion, cctx.ocVersion, scanReqTimeout)
	}
	if result == nil || result.Error == share.ScanErrorCode_ScanErrNetwork || result.Error == share.ScanErrorCode_ScanErrInProgress || err != nil {
		// rpc request not made
		cctx.ScanLog.WithFields(log.Fields{"id": t.id, "error": err}).Error()

		var requeue bool
		scanMutexRLock()
		if info, ok := scanMap[t.id]; ok {
			if (info.priority == scheduler.PriorityHigh || scanCfg.AutoScan) && info.retry < maxRetry {
				info.retry++
				cctx.ScanLog.WithFields(log.Fields{
					"id": t.id, "type": info.objType, "retry": info.retry,
				}).Error("Got empty response - requeue")

				info.status = statusScanScheduled
				info.lastResult = share.ScanErrorCode_ScanErrTimeout
				info.lastScanTime = time.Now().UTC()

				requeue = true
			}
		}
		scanMutexRUnlock()

		if requeue {
			updateScanState(t.id, info.objType, api.ScanStatusScheduled)
			scanScher.TaskDone(t, scheduler.TaskActionRequeue)
			return
		}

		result = &share.ScanResult{Error: share.ScanErrorCode_ScanErrTimeout}
	} else if result.Error == share.ScanErrorCode_ScanErrNotSupport ||
		result.Error == share.ScanErrorCode_ScanErrContainerExit {
		result.Error = share.ScanErrorCode_ScanErrNone
	}

	err = putScanReportToCluster(t.id, info, result)
	if err != nil {
		cctx.ScanLog.WithFields(log.Fields{"error": err}).Error("Fail to put report to cluster")
		updateScanState(t.id, info.objType, api.ScanStatusFailed)
	} else {
		updateScanState(t.id, info.objType, api.ScanStatusFinished)
	}

	scanScher.TaskDone(t, scheduler.TaskActionDone)
}

func (t *scanTask) Handler(scanner string) scheduler.Action {
	var ret scheduler.Action
	var ok bool
	var info *scanInfo

	cctx.ScanLog.WithFields(log.Fields{"id": t.id, "scanner": scanner}).Debug()

	scanMutexLock()
	if info, ok = scanMap[t.id]; !ok {
		scanMutexUnlock()
		cctx.ScanLog.WithFields(log.Fields{"id": t.id}).Error("cannot find container")
		ret = scheduler.TaskActionDone
		return ret
	} else {
		// Only wait for result if self is not dispatcher for this task
		/*
			if isDispatcher(info) == false {
				cctx.ScanLog.WithFields(log.Fields{"id": t.id}).Debug("not dispatchable")
				scanMutexUnlock()
				return scheduler.TaskActionRequeueWait
			}
		*/
		info.status = statusScanning
		ret = scheduler.TaskActionWait
	}
	scanMutexUnlock()

	updateScanState(t.id, info.objType, api.ScanStatusScanning)
	go t.rpcScanRunning(scanner, info)

	return ret
}

func (t *scanTask) StartTimer() {
}

func (t *scanTask) CancelTimer() {
}

func (t *scanTask) Expire() {
}

func enableAutoScan() {
	cctx.ScanLog.Debug("")

	scanCfg.AutoScan = true

	// Queue all workload for scan - this can take a long
	// time if we have lots of containers, so use a separate
	// thread to do it
	if !isScanner() {
		return
	}
	go func() {
		var cnt int
		scanMutexLock()
		all := make([]*scanTaskInfo, 0, len(scanMap))
		for id, info := range scanMap {
			all = append(all, &scanTaskInfo{id, info})
		}
		scanMutexUnlock()
		for _, st := range all {
			if !scanCfg.AutoScan {
				break
			}
			if st.info.status == statusScanNone || st.info.status == statusScanning {
				task := &scanTask{id: st.id, priority: scheduler.PriorityLow}
				if st.info.status == statusScanning {
					scanScher.DeleteTask(st.id, scheduler.PriorityLow)
				}
				st.info.status = statusScanScheduled
				st.info.priority = scheduler.PriorityLow
				st.info.retry = 0
				scanScher.AddTask(task, false)
				updateScanState(st.id, st.info.objType, api.ScanStatusScheduled)
				cnt++
			} else {
				cctx.ScanLog.WithFields(log.Fields{
					"id": st.id, "status": st.info.status,
				}).Debug("scan status")
			}
		}
		cctx.ScanLog.WithFields(log.Fields{"count": cnt}).Debug("Queued containers")
	}()
}

func disableAutoScan() {
	cctx.ScanLog.WithFields(log.Fields{"isScanner": isScanner()}).Debug("")

	scanCfg.AutoScan = false

	if !isScanner() {
		return
	}
	// cancel all existing workloads queued by auto scan
	go func() {
		scanMutexLock()
		for id, info := range scanMap {
			if info.status == statusScanScheduled && info.priority == scheduler.PriorityLow {
				info.status = statusScanNone
				info.retry = 0
				updateScanState(id, info.objType, api.ScanStatusIdle)
			}
		}
		scanScher.ClearTaskQueue(scheduler.PriorityLow)
		scanMutexUnlock()
	}()
}

func scanObject(id string) {
	cctx.ScanLog.WithFields(log.Fields{"id": id}).Debug("")

	var add, remove bool

	scanMutexLock()
	info, ok := scanMap[id]
	if ok {
		switch info.status {
		case statusScanNone:
			info.status = statusScanScheduled
			info.priority = scheduler.PriorityHigh
			add = true
		case statusScanScheduled, statusScanning:
			remove = true
			add = true
			info.priority = scheduler.PriorityHigh
		}
	} else {
		cctx.ScanLog.WithFields(log.Fields{"id": id}).Error("scan object not found")
	}

	if add && info != nil {
		cctx.ScanLog.WithFields(log.Fields{"id": id, "type": info.objType}).Debug("Add task")

		task := &scanTask{id: id, priority: scheduler.PriorityHigh}
		if remove {
			if scanScher.DeleteTask(id, scheduler.PriorityLow) {
				scanScher.AddTask(task, false)
				updateScanState(id, info.objType, api.ScanStatusScheduled)
			}
		} else {
			scanScher.AddTask(task, false)
			updateScanState(id, info.objType, api.ScanStatusScheduled)
		}
	}
	scanMutexUnlock()
}

func (m CacheMethod) ScanWorkload(id string, acc *access.AccessControl) error {
	if cache := getWorkloadCache(id); cache == nil {
		return common.ErrObjectNotFound
	} else if !acc.Authorize(&share.CLUSWorkloadScanDummy{Domain: cache.workload.Domain}, nil) {
		return common.ErrObjectAccessDenied
	}

	scanObject(id)
	return nil
}

func (m CacheMethod) ScanHost(id string, acc *access.AccessControl) error {
	if cache := getHostCache(id); cache == nil {
		return common.ErrObjectNotFound
	} else if !acc.Authorize(cache.host, nil) {
		return common.ErrObjectAccessDenied
	}

	scanObject(id)
	return nil
}

func (m CacheMethod) ScanPlatform(acc *access.AccessControl) error {
	cctx.ScanLog.Debug()

	if !acc.Authorize(&share.CLUSHost{}, nil) {
		return common.ErrObjectAccessDenied
	}

	scanObject(common.ScanPlatformID)
	return nil
}

// With scan mutex locked
func refreshScanCache(id string, info *scanInfo, vpf scanUtils.VPFInterface) {
	reportVuls, _ := db.GetVulnerability(id)
	localVulTraits := scanUtils.ExtractVulnerability(reportVuls)

	vpf.FilterVulTraits(localVulTraits, info.idns)
	criticals, highs, meds := scanUtils.CountVulTrait(localVulTraits)
	brief := fillScanBrief(info, criticals, highs, meds)
	info.brief = brief
	info.filteredTime = time.Now()

	switch info.objType {
	case share.ScanObjectType_CONTAINER:
		if c := getWorkloadCache(id); c != nil {
			c.scanBrief = brief
		}
	case share.ScanObjectType_HOST:
		if c := getHostCache(id); c != nil {
			c.scanBrief = brief
		}
	}
}

func scanRefresh(ctx context.Context, vpf scanUtils.VPFInterface) {
	log.Debug()

	i := 0

	scanMutexLock()
	ids := make([]string, len(scanMap))
	for id := range scanMap {
		ids[i] = id
		i++
	}
	scanMutexUnlock()

	for _, id := range ids {
		scanMutexLock()
		if info, ok := scanMap[id]; ok {
			// object scanned and vpf has updated
			if info.status == statusScanNone && !info.lastScanTime.IsZero() && vpf.GetUpdatedTime().After(info.filteredTime) {
				refreshScanCache(id, info, vpf)
			}
		}
		scanMutexUnlock()

		select {
		case <-ctx.Done():
			log.Debug("Canceled")
			return
		default:
			// not canceled, continue
		}
	}
}

func scanVulProfUpdate() {
	log.Debug()

	name := share.DefaultVulnerabilityProfileName
	vpf := cacher.GetVulnerabilityProfileInterface(name)

	vpMutex.RLock()
	if c, ok := vpCacheMap[name]; ok {
		ctx, cancel := context.WithCancel(context.Background())
		c.updateCtx, c.updateCancel = ctx, cancel

		go func() {
			log.Debug("Start update cache")
			scanRefresh(ctx, vpf)
			scan.RegistryScanCacheRefresh(ctx, vpf)
			cancel()
			log.Debug("Finish update cache")
		}()
	}
	vpMutex.RUnlock()
}

// This is called on every controller by key update
func scanDone(id string, objType share.ScanObjectType, report *share.CLUSScanReport) {
	cctx.ScanLog.WithFields(log.Fields{
		"id": id, "type": objType, "result": scanUtils.ScanErrorToStr(report.Error),
	}).Debug("")

	var criticals, highs, meds, lows []string
	var fixedCriticalsInfo []scanUtils.FixedVulInfo
	var fixedHighsInfo []scanUtils.FixedVulInfo
	var alives utils.Set // vul names that are not filtered
	var dbAssetVul *db.DbAssetVul
	var baseOS string

	scanMutexLock()
	info, ok := scanMap[id]
	if ok {
		info.status = statusScanNone
		info.retry = 0
		info.lastResult = report.Error
		info.lastScanTime = report.ScannedAt
		info.baseOS = report.Namespace
		info.version = report.Version
		info.cveDBCreateTime = report.CVEDBCreateTime
		if report.SignatureInfo != nil {
			info.signatureVerifiers = report.SignatureInfo.Verifiers
			info.signatureVerificationTimestamp = report.SignatureInfo.VerificationTimestamp
		}

		// Filter and count vulnerabilities
		vpf := cacher.GetVulnerabilityProfileInterface(share.DefaultVulnerabilityProfileName)
		localVulTraits := scanUtils.ExtractVulnerability(report.Vuls)
		alives = vpf.FilterVulTraits(localVulTraits, info.idns)
		criticals, highs, meds, lows, fixedCriticalsInfo, fixedHighsInfo = scanUtils.GatherVulTrait(localVulTraits)
		brief := fillScanBrief(info, len(criticals), len(highs), len(meds))
		info.brief = brief
		info.filteredTime = time.Now()

		switch objType {
		case share.ScanObjectType_CONTAINER:
			if c := getWorkloadCache(id); c != nil {
				c.scanBrief = brief
				dbAssetVul = getWorkloadDbAssetVul(c, criticals, highs, meds, lows, info.lastScanTime)
			}
		case share.ScanObjectType_HOST:
			if c := getHostCache(id); c != nil {
				c.scanBrief = brief
				dbAssetVul = getHostDbAssetVul(c, criticals, highs, meds, lows, info.lastScanTime)
			}
		case share.ScanObjectType_PLATFORM:
			dbAssetVul = getPlatformDbAssetVul(criticals, highs, meds, lows, baseOS, info.lastScanTime)
		}
	} else {
		cctx.ScanLog.WithFields(log.Fields{"id": id, "type": objType}).Debug("Scan object is gone")
	}
	scanMutexUnlock()

	if ok && dbAssetVul != nil {
		dbAssetVul.Vuls = report.Vuls
		dbAssetVul.Modules = report.Modules

		if len(info.idns) > 0 {
			b, err := json.Marshal(info.idns)
			if err == nil {
				dbAssetVul.Idns = string(b)
			}
		}

		err := db.PopulateAssetVul(dbAssetVul)
		if err != nil {
			log.WithError(err).Error("Failed to poulate asset to db")
		}
		report.Vuls = nil
		report.Modules = nil
	}

	// all controller should call auditUpdate to record the log, the leader will take action
	if alives != nil {
		clog := scanReport2ScanLog(id, objType, report, criticals, highs, meds, nil, nil, nil, "")
		syncLock(syncCatgAuditIdx)
		auditUpdate(id, share.EventCVEReport, objType, clog, alives, fixedCriticalsInfo, fixedHighsInfo)
		syncUnlock(syncCatgAuditIdx)
	}
}

func (m CacheMethod) GetScannerCount(acc *access.AccessControl) (int, string, string) {
	cacheMutexRLock()
	defer cacheMutexRUnlock()
	sdb := scanUtils.GetScannerDB()
	dbTime := sdb.CVEDBCreateTime
	dbVers := sdb.CVEDBVersion
	if acc.HasGlobalPermissions(share.PERMS_CLUSTER_READ, 0) {
		return len(scannerCacheMap), dbTime, dbVers
	} else {
		var count int
		for _, s := range scannerCacheMap {
			if !acc.Authorize(s.scanner, nil) {
				continue
			}
			count++
		}
		return count, dbTime, dbVers
	}
}

func (m CacheMethod) GetAllScanners(acc *access.AccessControl) []*api.RESTScanner {
	cacheMutexRLock()
	defer cacheMutexRUnlock()

	scanners := make([]*api.RESTScanner, 0, len(scannerCacheMap))
	for _, cache := range scannerCacheMap {
		if !acc.Authorize(cache.scanner, nil) {
			continue
		}
		s := cache.scanner
		scanner := api.RESTScanner{
			ID:              s.ID,
			CVEDBVersion:    s.CVEDBVersion,
			CVEDBCreateTime: s.CVEDBCreateTime,
			JoinedTS:        s.JoinedAt.Unix(),
			RPCServer:       s.RPCServer,
			RPCServerPort:   s.RPCServerPort,
		}
		if stats, err := clusHelper.GetScannerStats(s.ID); err != nil {
			log.WithFields(log.Fields{"scanner": s.ID, "error": err}).Error("Failed to get scanner stats")
		} else {
			scanner.Containers = stats.ScannedContainers
			scanner.Hosts = stats.ScannedHosts
			scanner.Images = stats.ScannedImages
			scanner.Serverless = stats.ScannedServerless
		}
		scanners = append(scanners, &scanner)
	}
	return scanners
}

func addScanner(id string) error {
	return scanScher.AddProcessor(id)
}

func removeScanner(id string) error {
	_, err := scanScher.DelProcessor(id)
	return err
}

func scannerDBChange(newVer string) {
	if !isScanner() {
		return
	}

	if !scanCfg.AutoScan {
		return
	}

	go func() {
		scanMutexLock()
		for id, info := range scanMap {
			if info.status == statusScanNone && info.version != newVer {
				info.status = statusScanScheduled
				info.priority = scheduler.PriorityLow
				info.retry = 0
				task := &scanTask{id: id, priority: scheduler.PriorityLow}
				scanScher.AddTask(task, false)
				updateScanState(id, info.objType, api.ScanStatusScheduled)
			}
		}
		scanMutexUnlock()
	}()
}

func scanMapAdd(taskId string, agentId string, idns []api.RESTIDName, objType share.ScanObjectType) {

	scanMutexLock()
	if info, ok := scanMap[taskId]; ok {
		info.agentId = agentId
		scanMutexUnlock()
		return
	}

	info := &scanInfo{
		agentId: agentId,
		status:  statusScanNone,
		objType: objType,
		idns:    idns,
	}
	scanMap[taskId] = info

	// When controller starts, scanStateHandler maybe called before the object is added.
	// We simulate the call if this is a new object
	var skey string
	if objType == share.ScanObjectType_CONTAINER {
		skey = share.CLUSScanStateWorkloadKey(taskId)
	} else if objType == share.ScanObjectType_HOST {
		skey = share.CLUSScanStateHostKey(taskId)
	} else {
		skey = share.CLUSScanStatePlatformKey(taskId)
	}

	// If controller simply restarts or rolling upgraded, don't rescan
	// the object. Only start automatically for new workload.
	if value, err := cluster.Get(skey); err == nil {
		// state key exists, the workload has been added in another controller or in previous run
		scanMutexUnlock()

		// We must call scanStateHandler() here because if the kv callback comes earlier,
		// scanMap[] entry does not exist yet.
		scanStateHandler(cluster.ClusterNotifyAdd, skey, value)

		// However, if the kv callback comes later, can we skip it? We used to set a flag
		// here, but when the kv callback does come, we don't know if the value has changed
		// or not, so for now, we let it call once again.
	} else if isScanner() {
		// Always scan the platform even auto-scan is disabled
		if objType == share.ScanObjectType_PLATFORM {
			info.status = statusScanScheduled
			info.priority = scheduler.PriorityHigh
			task := &scanTask{id: taskId, priority: scheduler.PriorityHigh}
			scanScher.AddTask(task, true)
			updateScanState(taskId, info.objType, api.ScanStatusScheduled)
		} else if scanCfg.AutoScan {
			info.status = statusScanScheduled
			info.priority = scheduler.PriorityLow
			task := &scanTask{id: taskId, priority: scheduler.PriorityLow}
			scanScher.AddTask(task, false)
			updateScanState(taskId, info.objType, api.ScanStatusScheduled)
		}
		scanMutexUnlock()
	} else {
		scanMutexUnlock()
	}
}

func scanMapDelete(taskId string) {
	scanMutexLock()
	info, ok := scanMap[taskId]
	if !ok {
		scanMutex.Unlock()
		return
	}
	delete(scanMap, taskId)
	scanMutexUnlock()

	if isScanner() {
		scanScher.DeleteTask(taskId, info.priority)

		/* delete scan report if any */
		var key, skey string
		if info.objType == share.ScanObjectType_CONTAINER {
			key = share.CLUSScanDataWorkloadKey(taskId)
			skey = share.CLUSScanStateWorkloadKey(taskId)
		} else if info.objType == share.ScanObjectType_HOST {
			key = share.CLUSScanDataHostKey(taskId)
			skey = share.CLUSScanStateHostKey(taskId)
		} else if info.objType == share.ScanObjectType_PLATFORM {
			key = share.CLUSScanDataPlatformKey(taskId)
			skey = share.CLUSScanStatePlatformKey(taskId)
		}
		_ = cluster.Delete(key)
		_ = cluster.Delete(skey)
	}
}

func scanWorkloadAdd(id string, param interface{}) {
	// This can be called when the controller restarts, where scanning is not needed if
	// the workload has been scanned.
	cache := param.(*workloadCache)
	workload := cache.workload
	if !common.OEMIgnoreWorkload(workload) {
		// Use DisplayName for image
		idns := []api.RESTIDName{{Domains: []string{workload.Domain}, DisplayName: workload.Image}}
		scanMapAdd(id, workload.AgentID, idns, share.ScanObjectType_CONTAINER)
		// Read bench checks into cache in case its notification came earlier
		benchStateHandler(cluster.ClusterNotifyAdd, share.CLUSBenchStateWorkloadKey(id), nil)
	}
}

func scanWorkloadAgentChange(id string, param interface{}) {
	workload := param.(*workloadCache).workload

	scanMutexLock()
	if info, ok := scanMap[id]; ok {
		info.agentId = workload.AgentID
	}
	scanMutexUnlock()
}

func scanWorkloadDelete(id string, param interface{}) {
	scanMapDelete(id)
}

func scanAgentAdd(id string, param interface{}) {
	// This can be called when the controller restarts, where scanning is not needed if
	// the host has been scanned.
	agent := param.(*agentCache).agent
	scanMapAdd(agent.HostID, id, nil, share.ScanObjectType_HOST)
}

func scanHostDelete(id string, param interface{}) {
	scanMapDelete(id)
}

func scanAgentDelete(id string, param interface{}) {
	// purge incomplete scanning jobs but keep completed scans
	scanMutexLock()
	defer scanMutexUnlock()
	for task, info := range scanMap {
		if info.agentId == id {
			if info.cveDBCreateTime == "" { // incompleted, not done yet
				log.WithFields(log.Fields{"task": task, "info": info}).Info()
				delete(scanMap, task)
			}
		}
	}
}

func scanConfigUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		var cfg share.CLUSScanConfig
		if err := json.Unmarshal(value, &cfg); err != nil {
			cctx.ScanLog.WithFields(log.Fields{"err": err}).Debug("Fail to decode")
			return
		}

		cctx.ScanLog.WithFields(log.Fields{"config": cfg}).Debug("")
		if cfg.AutoScan && !scanCfg.AutoScan {
			enableAutoScan()
		} else if !cfg.AutoScan && scanCfg.AutoScan {
			disableAutoScan()
		}
	case cluster.ClusterNotifyDelete:
		disableAutoScan()
	}
}

func putScanReportToCluster(id string, info *scanInfo, result *share.ScanResult) error {
	cctx.ScanLog.WithFields(log.Fields{
		"id": id, "type": info.objType, "result": scanUtils.ScanErrorToStr(result.Error),
	}).Debug("")

	var key string
	if info.objType == share.ScanObjectType_CONTAINER {
		key = share.CLUSScanDataWorkloadKey(id)
	} else if info.objType == share.ScanObjectType_HOST {
		key = share.CLUSScanDataHostKey(id)
	} else {
		key = share.CLUSScanDataPlatformKey(id)
	}

	now := time.Now().UTC()
	report := share.CLUSScanReport{ScannedAt: now, ScanResult: *result}

	// Write full report and a piece of state data so we only need act upon the state data change notification
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(&report); err == nil {
		zb := utils.GzipBytes(buf.Bytes())
		return cluster.PutBinary(key, zb)
	} else {
		return err
	}
}

func updateScanState(id string, nType share.ScanObjectType, status string) {
	cctx.ScanLog.WithFields(log.Fields{"id": id, "status": status}).Debug("")
	var skey string
	if nType == share.ScanObjectType_CONTAINER {
		skey = share.CLUSScanStateWorkloadKey(id)
	} else if nType == share.ScanObjectType_HOST {
		skey = share.CLUSScanStateHostKey(id)
	} else {
		skey = share.CLUSScanStatePlatformKey(id)
	}

	state := &share.CLUSScanState{Status: status}
	if status == api.ScanStatusFinished {
		state.ScannedAt = time.Now().UTC()
	}
	value, _ := json.Marshal(state)
	_ = cluster.Put(skey, value)
}

func scanStateHandler(nType cluster.ClusterNotifyType, key string, value []byte) {
	cctx.ScanLog.WithFields(log.Fields{"type": cluster.ClusterNotifyName[nType], "key": key}).Debug("")

	if nType == cluster.ClusterNotifyDelete {
		return
	}

	var state share.CLUSScanState
	err := json.Unmarshal(value, &state)
	if err != nil {
		return
	}

	id := share.CLUSScanStateKey2ID(key)
	scanMutexRLock()
	info, ok := scanMap[id]
	scanMutexRUnlock()
	if !ok {
		return
	}

	cctx.ScanLog.WithFields(log.Fields{"key": key, "status": state.Status}).Debug("")

	// For unfinished scan, update status without creating log
	if state.Status == api.ScanStatusScheduled ||
		state.Status == api.ScanStatusIdle ||
		state.Status == api.ScanStatusScanning {
		brief := &api.RESTScanBrief{
			Status: state.Status,
		}
		if info.objType == share.ScanObjectType_CONTAINER {
			if c := getWorkloadCache(id); c != nil {
				c.scanBrief = brief
			}
		} else if info.objType == share.ScanObjectType_HOST {
			if c := getHostCache(id); c != nil {
				c.scanBrief = brief
			}
		}
		if state.Status == api.ScanStatusScheduled {
			info.status = statusScanScheduled
		} else if state.Status == api.ScanStatusIdle {
			info.status = statusScanNone
		} else if state.Status == api.ScanStatusScanning {
			info.status = statusScanning
		}
		return
	}

	// For finished scan, pull the report, call scanDone()
	var objType share.ScanObjectType
	var dkey string
	t := share.CLUSScanStateKey2Type(key)
	if t == "workload" {
		objType = share.ScanObjectType_CONTAINER
		dkey = share.CLUSScanDataWorkloadKey(id)
	} else if t == "host" {
		objType = share.ScanObjectType_HOST
		dkey = share.CLUSScanDataHostKey(id)
	} else {
		objType = share.ScanObjectType_PLATFORM
		dkey = share.CLUSScanDataPlatformKey(id)
	}

	if report := clusHelper.GetScanReport(dkey); report != nil {
		scanDone(id, objType, report)
	}
}

func registryStateHandler(nType cluster.ClusterNotifyType, key string, value []byte) {
	cctx.ScanLog.WithFields(log.Fields{"type": cluster.ClusterNotifyName[nType], "key": key}).Debug("")

	name := share.CLUSKeyNthToken(key, 3)

	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		var state share.CLUSRegistryState
		_ = json.Unmarshal(value, &state)
		scan.RegistryStateUpdate(name, &state)
	case cluster.ClusterNotifyDelete:
		// State is deleted when registry deleted. No handling here.
	}
}

func registryImageStateHandler(nType cluster.ClusterNotifyType, key string, value []byte) {
	cctx.ScanLog.WithFields(log.Fields{"type": cluster.ClusterNotifyName[nType], "key": key}).Debug()

	name := share.CLUSKeyNthToken(key, 3)
	id := share.CLUSKeyNthToken(key, 4)

	var fedRegName string
	fedRole := cacher.GetFedMembershipRoleNoAuth()
	if fedRole == api.FedRoleMaster {
		if name == common.RegistryRepoScanName {
			fedRegName = common.RegistryFedRepoScanName
		} else if strings.HasPrefix(name, api.FederalGroupPrefix) {
			fedRegName = name
		}
	} else if fedRole == api.FedRoleJoint && strings.HasPrefix(name, api.FederalGroupPrefix) {
		fedRegName = name
	}

	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		var sum share.CLUSRegistryImageSummary
		_ = json.Unmarshal(value, &sum)

		if fedRole == api.FedRoleJoint && strings.HasPrefix(name, api.FederalGroupPrefix) && (name != common.RegistryFedRepoScanName) {
			// when a new fed registry with its image scan result are deployed to a worker cluster, it's possible that
			//  "object/config/" watcher handler is called after "scan/" watcher handler.
			// when this happens, we need to make sure the fed registry is known by worker cluster or the fed scan result will be ignored.
			if exist := scan.CheckRegistry(name); !exist {
				if config, _, err := clusHelper.GetRegistry(name, access.NewFedAdminAccessControl()); config != nil {
					var enc common.EncryptMarshaller
					value, _ := enc.Marshal(config)
					scan.RegistryConfigHandler(cluster.ClusterNotifyAdd, share.CLUSRegistryConfigKey(name), value)
				} else {
					cctx.ScanLog.WithFields(log.Fields{"error": err, "name": name}).Error()
				}
			}
		}

		vpf := cacher.GetVulnerabilityProfileInterface(share.DefaultVulnerabilityProfileName)
		alives, criticals, highs, meds, fixedCriticalsInfo, fixedHighsInfo, layerCriticals, layerHighs, layerMeds := scan.RegistryImageStateUpdate(name, id, &sum, systemConfigCache.SyslogCVEInLayers, vpf)

		if sum.Status == api.ScanStatusFinished && sum.Result == share.ScanErrorCode_ScanErrNone {
			var report *share.CLUSScanReport
			key := share.CLUSRegistryImageDataKey(name, id)
			report = clusHelper.GetScanReport(key)
			if report != nil {
				// for any scan report on master/standalone cluster & non-fed scan report on managed cluster
				if fedRole != api.FedRoleJoint || !strings.HasPrefix(name, api.FederalGroupPrefix) {
					if alives != nil {
						clog := scanReport2ScanLog(id, share.ScanObjectType_IMAGE, report, criticals, highs, meds, layerCriticals, layerHighs, layerMeds, name)
						syncLock(syncCatgAuditIdx)
						auditUpdate(id, share.EventCVEReport, share.ScanObjectType_IMAGE, clog, alives, fixedCriticalsInfo, fixedHighsInfo)
						syncUnlock(syncCatgAuditIdx)
					}

					clog := scanReport2BenchLog(id, share.ScanObjectType_IMAGE, report, name)
					syncLock(syncCatgAuditIdx)
					benchUpdate(share.EventCompliance, clog)
					syncUnlock(syncCatgAuditIdx)
				}

				if fedRegName != "" {
					scanResult := regImageSummaryReport{
						Summary: value,
						Report:  report,
					}
					fedScanDataCacheMutexLock()
					currImagesMD5, ok := fedScanResultMD5[fedRegName]
					if !ok || currImagesMD5 == nil {
						currImagesMD5 = make(map[string]string, 1)
					}
					if report != nil && report.SignatureInfo != nil {
						if report.SignatureInfo.Verifiers != nil {
							sort.Strings(report.SignatureInfo.Verifiers)
						}
						report.SignatureInfo.VerificationTimestamp = ""
						report.SignatureInfo.VerificationError = 0
					}
					res, _ := json.Marshal(&scanResult)
					md5Sum := md5.Sum(res)
					currImagesMD5[id] = hex.EncodeToString(md5Sum[:])
					fedScanResultMD5[fedRegName] = currImagesMD5
					fedScanDataCacheMutexUnlock()
				}
			} else if fedRegName != "" {
				log.WithFields(log.Fields{"name": fedRegName, "id": id}).Error("no scan report")
			}
		}

	case cluster.ClusterNotifyDelete:
		scan.RegistryImageStateUpdate(name, id, nil, false, nil)
		if fedRegName != "" {
			fedScanDataCacheMutexLock()
			if currImagesMD5, ok := fedScanResultMD5[fedRegName]; ok {
				delete(currImagesMD5, id)
			}
			fedScanDataCacheMutexUnlock()
		}

		if err := db.DeleteAssetByID(db.AssetImage, id); err != nil {
			log.WithFields(log.Fields{"err": err, "id": id}).Error("Delete asset in db failed.")
		}
	}
}

func fedScanRevsHandler(nType cluster.ClusterNotifyType, key string, value []byte) {
	log.WithFields(log.Fields{"type": cluster.ClusterNotifyName[nType], "key": key}).Debug()

	fedScanDataCacheMutexLock()
	defer fedScanDataCacheMutexUnlock()

	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		var scanDataRevs share.CLUSFedScanRevisions
		_ = json.Unmarshal(value, &scanDataRevs)
		fedScanDataRevsCache = scanDataRevs

	case cluster.ClusterNotifyDelete:
		fedScanDataRevsCache = share.CLUSFedScanRevisions{}
		fedScanResultMD5 = make(map[string]map[string]string)
	}
}

func ScannerUpdateHandler(nType cluster.ClusterNotifyType, key string, value []byte, modifyIdx uint64) {
	log.WithFields(log.Fields{"type": cluster.ClusterNotifyName[nType], "key": key}).Debug("")
	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		// For the built-in scanner, the CVEDB version can change
		var s share.CLUSScanner
		if err := json.Unmarshal(value, &s); err == nil {
			log.WithFields(log.Fields{"scanner": s}).Info("Add or update scanner")

			if s.ID == share.CLUSScannerDBVersionID {
				// Dummy scanner to indicate db version change. It should not stored in the map.
				newStore := fmt.Sprintf("%s%s/", share.CLUSScannerDBStore, s.CVEDBVersion)

				newDB := &share.CLUSScannerDB{
					CVEDBVersion:    s.CVEDBVersion,
					CVEDBCreateTime: s.CVEDBCreateTime,
					CVEDB:           make(map[string]*share.ScanVulnerability),
				}

				// Reassemble
				dbs := clusHelper.GetScannerDB(newStore)
				for _, db := range dbs {
					for _, cve := range db.CVEDB {
						newDB.CVEDB[cve.Name] = cve
					}
				}

				log.WithFields(log.Fields{"cvedb": newDB.CVEDBVersion, "entries": len(newDB.CVEDB)}).Info()

				scanUtils.SetScannerDB(newDB)
				scan.ScannerDBChange(newDB)
				scannerDBChange(newDB.CVEDBVersion)
			} else {
				// Real Scanner
				cacheMutexLock()
				if exist, ok := scannerCacheMap[s.ID]; ok {
					exist.scanner = &s
					exist.errCount = 0
				} else {
					scannerCacheMap[s.ID] = &scannerCache{scanner: &s, errCount: 0}
				}
				cacheMutexUnlock()

				if !s.BuiltIn {
					rpc.AddScanner(&s)
					if err := scan.AddScanner(s.ID); err != nil {
						log.WithError(err).Warn("failed to add scanner to reg scheduler")
					}
					if err := addScanner(s.ID); err != nil {
						log.WithError(err).Warn("failed to add scanner to scheduler")
					}
				} else if s.ID == localDev.Ctrler.ID {
					rpc.AddScanner(&s)
					if err := scan.AddScanner(s.ID); err != nil {
						log.WithError(err).Warn("failed to add scanner to reg scheduler")
					}
					if err := addScanner(s.ID); err != nil {
						log.WithError(err).Warn("failed to add scanner to scheduler")
					}
				}
			}
		}
	case cluster.ClusterNotifyDelete:
		id := share.CLUSScannerKey2ID(key)
		if id == share.CLUSScannerDBVersionID {
			log.WithFields(log.Fields{"scanner": id}).Error("Cannot delete dummy db version scanner")
		} else {
			log.WithFields(log.Fields{"scanner": id}).Info("Delete scanner")

			cacheMutexLock()
			delete(scannerCacheMap, id)
			cacheMutexUnlock()

			rpc.RemoveScanner(id)
			if err := scan.RemoveScanner(id); err != nil {
				log.WithError(err).Warn("failed to remove scanner from reg scheduler")
			}
			if err := removeScanner(id); err != nil {
				log.WithError(err).Warn("failed to remove scanner from scheduler")
			}
		}
	}
}

func ScanUpdateHandler(nType cluster.ClusterNotifyType, key string, value []byte, modifyIdx uint64) {
	object := share.CLUSScanKey2Subject(key)
	switch object {
	case "bench":
		benchStateHandler(nType, key, value)
	case "report":
		scanStateHandler(nType, key, value)
	case "registry":
		registryStateHandler(nType, key, value)
	case "image":
		registryImageStateHandler(nType, key, value)
	case share.CLUSFedScanDataRevSubKey:
		fedScanRevsHandler(nType, key, value)
	}
}

func scanLicenseUpdate(id string, param interface{}) {

	// Cache lock must be within scan lock, so get the map first
	wls := make(map[string]struct{ a, d string }, len(wlCacheMap))
	hosts := make(map[string]string, len(agentCacheMap))
	cacheMutexRLock()
	for id, cache := range wlCacheMap {
		wls[id] = struct{ a, d string }{a: cache.workload.AgentID, d: cache.workload.Domain}
	}
	for id, cache := range agentCacheMap {
		hosts[cache.agent.HostID] = id
	}
	cacheMutexRUnlock()

	for id, m := range wls {
		idns := []api.RESTIDName{{Domains: []string{m.d}}}
		scanMapAdd(id, m.a, idns, share.ScanObjectType_CONTAINER)
	}
	for id, a := range hosts {
		scanMapAdd(id, a, nil, share.ScanObjectType_HOST)
	}
	scanMapAdd(common.ScanPlatformID, "", nil, share.ScanObjectType_PLATFORM)
}

func scanBecomeScanner() {
	log.Debug()

	scanMutexLock()
	for taskId, info := range scanMap {
		if info.status != statusScanNone {
			info.status = statusScanScheduled
			if info.priority == scheduler.PriorityHigh {
				task := &scanTask{id: taskId, priority: scheduler.PriorityHigh}
				scanScher.AddTask(task, true)
			} else {
				task := &scanTask{id: taskId, priority: scheduler.PriorityLow}
				scanScher.AddTask(task, false)
			}
			updateScanState(taskId, info.objType, api.ScanStatusScheduled)
		}
	}
	scanMutexUnlock()
}

func rescaleScanner(autoscaleCfg share.CLUSSystemConfigAutoscale, totalScanners uint32, taskCount int) {
	var setTimeWindow bool
	var newReplicas uint32 = totalScanners

	if taskCount == 0 {
		// there is no scanning task waiting in the queue now
		if lastTaskQState == task_Q_Unknown || lastTaskQState == task_Q_NonEmpty {
			// init/had scanning task -> no scanning task now
			lastTaskQState = task_Q_Empty
			setTimeWindow = true // start calculation time window
		} else {
			// had no scanning task -> still has no scanning task now
			if time.Since(contTaskQStateTime) > time.Duration(3)*time.Minute {
				// it has been continuously long enough time that no scanning task is waiting in the queue. reduce scanner count by 1
				// it could take about 3 ~ 4 minutes to terminate a scanner considering scannerTicker is 1 minute
				newReplicas = newReplicas - 1
				setTimeWindow = true // reset calculation time window
			}
		}
	} else {
		// there is scanning task waiting in the queue now
		if autoscaleCfg.Strategy == api.AutoScaleImmediate {
			// increase scanner count by 1 with immediate stragedy.
			// it could take about 0 ~ 1 minute to start a new scanner considering scannerTicker is 1 minute
			newReplicas = newReplicas + 1
			lastTaskQState = task_Q_NonEmpty
			setTimeWindow = true // reset calculation time window
		} else if autoscaleCfg.Strategy == api.AutoScaleDelayed {
			if lastTaskQState == task_Q_Unknown || lastTaskQState == task_Q_Empty {
				// init/had no scanning task -> has scanning task now
				lastTaskQState = task_Q_NonEmpty
				setTimeWindow = true // start calculation time window
			} else {
				// had scanning task -> still has scanning task now
				if time.Since(contTaskQStateTime) > time.Duration(5)*time.Minute {
					// it has been continuously long enough time that at lease one scanning task is waiting in the queue. increase scanner count by 1
					// it could take about 5 ~ 6 minutes to start a new scanner considering scannerTicker is 1 minute
					newReplicas = newReplicas + 1
					setTimeWindow = true // reset calculation time window
				}
			}
		}
	}

	if newReplicas < autoscaleCfg.MinPods {
		newReplicas = autoscaleCfg.MinPods
	} else if newReplicas > autoscaleCfg.MaxPods {
		newReplicas = autoscaleCfg.MaxPods
	}
	if newReplicas != totalScanners {
		skipScale := false
		thisAutoScale := tAutoScaleHistory{
			oldReplicas:    totalScanners,
			newReplicas:    newReplicas,
			sameScaleTimes: 1,
		}
		if autoScaleHistory.sameScaleTimes >= 1 {
			if thisAutoScale.oldReplicas == autoScaleHistory.oldReplicas && thisAutoScale.newReplicas == autoScaleHistory.newReplicas {
				// this time we scale using the same from/to replicas values like in last auto-scaling
				// it implies someone reverted scanner replicas after we set it last time
				log.WithFields(log.Fields{"from": autoScaleHistory.oldReplicas, "to": autoScaleHistory.newReplicas}).Info("same scaling as the last time")
				autoScaleHistory.sameScaleTimes += 1
			} else {
				autoScaleHistory = thisAutoScale
			}
		} else {
			autoScaleHistory = thisAutoScale
		}
		if autoScaleHistory.sameScaleTimes > 4 {
			// someone reverted scanner replicas 4 times continusously.
			acc := access.NewAdminAccessControl()
			if cfg := cacher.GetSystemConfig(acc); cfg.ScannerAutoscale.Strategy != api.AutoScaleNone {
				log.WithFields(log.Fields{"strategy": cfg.ScannerAutoscale.Strategy}).Info("autoscale disabled")
				if cconf, rev := clusHelper.GetSystemConfigRev(acc); cconf != nil {
					cconf.ScannerAutoscale.Strategy = api.AutoScaleNone
					cconf.ScannerAutoscale.DisabledByOthers = true
					if err := clusHelper.PutSystemConfigRev(cconf, rev); err == nil {
						clog := share.CLUSEventLog{
							Event:      share.CLUSEvScannerAutoScaleDisabled,
							ReportedAt: time.Now().UTC(),
						}
						clog.Msg = "Scanner autoscale is disabled because someone reverted the scaling for 3 continous times."
						_ = cctx.EvQueue.Append(&clog)
						skipScale = true
						log.Info(clog.Msg)
					} else {
						log.WithFields(log.Fields{"strategy": cfg.ScannerAutoscale.Strategy}).Info("failed to disabl autoscale")
					}
				}
			}
			autoScaleHistory = tAutoScaleHistory{}
		}
		if !skipScale {
			if err := resource.UpdateDeploymentReplicates("neuvector-scanner-pod", int32(newReplicas)); err == nil {
				log.WithFields(log.Fields{"from": totalScanners, "history": autoScaleHistory}).Info("autoscale")
			}
		}
	}

	if setTimeWindow {
		contTaskQStateTime = time.Now().UTC()
	}
}

func scanInit() {
	scanScher.Init()

	acc := access.NewReaderAccessControl()
	cfg, _ := clusHelper.GetScanConfigRev(acc)
	scanCfg = *cfg

	key := share.CLUSVulnerabilityProfileKey(share.DefaultVulnerabilityProfileName)
	if value, err := cluster.Get(key); err == nil {
		vulnerabilityConfigUpdate(cluster.ClusterNotifyModify, key, value)
	}
}

/*----------------------------------------------------------------------*/
/*----------------------------------------------------------------------*/
func (m CacheMethod) GetScanConfig(acc *access.AccessControl) (*api.RESTScanConfig, error) {
	cctx.ScanLog.Debug("")

	if !acc.Authorize(&scanCfg, nil) {
		return nil, common.ErrObjectAccessDenied
	}

	var cfg *api.RESTScanConfig
	if scanCfg.AutoScan {
		cfg = &api.RESTScanConfig{AutoScan: true}
	} else {
		cfg = &api.RESTScanConfig{AutoScan: false}
	}

	return cfg, nil
}

func (m CacheMethod) GetScanStatus(acc *access.AccessControl) (*api.RESTScanStatus, error) {
	var status api.RESTScanStatus

	if !acc.Authorize(&status, nil) {
		return nil, common.ErrObjectAccessDenied
	}

	scanMutexRLock()
	defer scanMutexRUnlock()

	for _, info := range scanMap {
		if info.status == statusScanScheduled {
			status.Scheduled++
		} else if info.status == statusScanning {
			status.Scanning++
		} else if !info.lastScanTime.IsZero() {
			status.Scanned++
		}
	}
	sdb := scanUtils.GetScannerDB()
	status.CVEDBVersion = sdb.CVEDBVersion
	status.CVEDBCreateTime = sdb.CVEDBCreateTime
	return &status, nil
}

func fillScanBrief(info *scanInfo, critical, high, med int) *api.RESTScanBrief {
	brief := &api.RESTScanBrief{
		CVEDBVersion:    info.version,
		CVEDBCreateTime: info.cveDBCreateTime,
	}

	switch info.status {
	case statusScanScheduled:
		brief.Status = api.ScanStatusScheduled
	case statusScanning:
		brief.Status = api.ScanStatusScanning
	case statusScanNone:
		if !info.lastScanTime.IsZero() {
			if info.lastResult == share.ScanErrorCode_ScanErrNone {
				brief.Status = api.ScanStatusFinished
				brief.CriticalVuls = critical
				brief.HighVuls = high
				brief.MedVuls = med
			} else if info.lastResult == share.ScanErrorCode_ScanErrNotSupport ||
				info.lastResult == share.ScanErrorCode_ScanErrContainerExit {
				brief.Status = api.ScanStatusFinished
			} else {
				brief.Status = api.ScanStatusFailed
			}
			brief.ScannedTimeStamp = info.lastScanTime.Unix()
			brief.ScannedAt = api.RESTTimeString(info.lastScanTime)
			brief.Result = scanUtils.ScanErrorToStr(info.lastResult)
		} else {
			brief.Status = api.ScanStatusIdle
		}
		brief.BaseOS = info.baseOS
	}

	return brief
}

func scanBrief2REST(info *scanInfo) *api.RESTScanBrief {
	var r api.RESTScanBrief

	// What is stored in info.brief is the last scan result. If an entity is in scanning state,
	// set its status explicitly. NOTE: scanBrief in the workload is always the last scan result.
	switch info.status {
	case statusScanScheduled:
		r.Status = api.ScanStatusScheduled
	case statusScanning:
		r.Status = api.ScanStatusScanning
	case statusScanNone:
		if !info.lastScanTime.IsZero() {
			if info.brief != nil {
				r = *info.brief
			} else {
				r.ScannedTimeStamp = info.lastScanTime.Unix()
				r.ScannedAt = api.RESTTimeString(info.lastScanTime)
				r.Result = scanUtils.ScanErrorToStr(info.lastResult)
			}
		} else {
			r.Status = api.ScanStatusIdle
		}
		r.BaseOS = info.baseOS
	}
	sdb := scanUtils.GetScannerDB()
	r.CVEDBVersion = sdb.CVEDBVersion
	r.CVEDBCreateTime = sdb.CVEDBCreateTime
	return &r
}

func (m CacheMethod) GetVulnerabilityReport(id, showTag string) ([]*api.RESTVulnerability, []*api.RESTScanModule, error) {
	scanMutexRLock()
	defer scanMutexRUnlock()

	if info, ok := scanMap[id]; ok {
		vpf := cacher.GetVulnerabilityProfileInterface(share.DefaultVulnerabilityProfileName)
		if info.status == statusScanNone && !info.lastScanTime.IsZero() && vpf.GetUpdatedTime().After(info.filteredTime) {
			refreshScanCache(id, info, vpf)
		}

		sdb := scanUtils.GetScannerDB()

		reportVuls, reportModules, err := db.GetVulnerabilityModule(id)
		if err != nil {
			return nil, nil, err
		}

		localVulTraits := scanUtils.ExtractVulnerability(reportVuls)
		vpf.FilterVulTraits(localVulTraits, info.idns)
		vuls := scanUtils.FillVulTraits(sdb.CVEDB, info.baseOS, localVulTraits, showTag, false)
		modules := make([]*api.RESTScanModule, len(reportModules))
		for i, m := range reportModules {
			modules[i] = scanUtils.ScanModule2REST(m)
		}
		return vuls, modules, nil
	} else {
		return nil, nil, common.ErrObjectNotFound
	}
}

func (m CacheMethod) GetScanPlatformSummary(acc *access.AccessControl) (*api.RESTScanPlatformSummary, error) {
	scanMutexRLock()
	defer scanMutexRUnlock()

	if acc.Authorize(&share.CLUSHost{}, nil) {
		if info, ok := scanMap[common.ScanPlatformID]; ok {
			brief := scanBrief2REST(info)
			s := &api.RESTScanPlatformSummary{RESTScanBrief: *brief}
			s.Platform, s.K8sVersion, s.OCVersion = m.GetPlatform()
			return s, nil
		} else {
			return nil, common.ErrObjectNotFound
		}
	} else {
		return nil, common.ErrObjectAccessDenied
	}
}

func getWorkloadDbAssetVul(c *workloadCache, criticals, highs, meds, lows []string, lastScanTime time.Time) *db.DbAssetVul {
	d := &db.DbAssetVul{
		Type:             db.AssetWorkload,
		AssetID:          c.workload.ID,
		Name:             c.podName,
		W_domain:         c.workload.Domain,
		W_service_group:  c.serviceName,
		W_workload_image: c.workload.Image,
		CVE_critical:     len(criticals),
		CVE_high:         len(highs),
		CVE_medium:       len(meds),
		CVE_low:          len(lows),
	}

	apps := translateWorkloadApps(c.workload)
	b, err := json.Marshal(apps)
	if err == nil {
		d.W_applications = string(b)
	}

	d.Policy_mode, _ = getWorkloadPerGroupPolicyMode(c)
	d.Scanned_at = api.RESTTimeString(lastScanTime.UTC())
	return d
}

func getHostDbAssetVul(c *hostCache, criticals, highs, meds, lows []string, lastScanTime time.Time) *db.DbAssetVul {
	d := &db.DbAssetVul{
		Type:         db.AssetNode,
		AssetID:      c.host.ID,
		Name:         c.host.Name,
		CVE_critical: len(criticals),
		CVE_high:     len(highs),
		CVE_medium:   len(meds),
		CVE_low:      len(lows),
		N_os:         c.host.OS,
		N_kernel:     c.host.Kernel,
		N_cpus:       int(c.host.CPUs),
		N_memory:     c.host.Memory,
		N_containers: c.workloads.Cardinality(),
	}

	d.Policy_mode, _ = getHostPolicyMode(c)
	d.Scanned_at = api.RESTTimeString(lastScanTime.UTC())
	return d
}

func getPlatformDbAssetVul(criticals, highs, meds, lows []string, baseOS string, lastScanTime time.Time) *db.DbAssetVul {
	d := &db.DbAssetVul{
		Type:         db.AssetPlatform,
		AssetID:      common.ScanPlatformID,
		Name:         localDev.Host.Platform,
		CVE_critical: len(criticals),
		CVE_high:     len(highs),
		CVE_medium:   len(meds),
		CVE_low:      len(lows),
		P_version:    cctx.k8sVersion,
		P_base_os:    baseOS,
	}
	d.Scanned_at = api.RESTTimeString(lastScanTime.UTC())
	return d
}

func ExtractVulAttributes(vulsb []byte, indsStr string) []string {
	cveList := make([]string, 0)

	Vuls, err := db.UnzipVuls(vulsb)
	if err != nil {
		return cveList
	}

	inds := make([]api.RESTIDName, 0)
	if indsStr != "" {
		if err := json.Unmarshal([]byte(indsStr), &inds); err != nil {
			return cveList
		}
	}

	// perform VPF, only non-filtered vuls will be returned..
	vpf := cacher.GetVulnerabilityProfileInterface(share.DefaultVulnerabilityProfileName)
	Vuls = vpf.FilterVuls(Vuls, inds)

	var cveSet utils.Set = utils.NewSet()
	for _, vul := range Vuls {
		if cveSet.Contains(vul.Name) {
			continue
		}
		cveSet.Add(vul.Name)

		fix := "nf"
		if len(vul.FixedVersion) > 0 {
			fix = "wf"
		}
		cveList = append(cveList, fmt.Sprintf("%s;%s;%s", vul.Name, vul.DBKey, fix))
	}

	return cveList
}

func FillVulPackages(mu *sync.Mutex, cvePackages map[string]map[string]utils.Set, vulsb []byte, idnsStr string, cveList *[]string, cveStat map[string]*int) error {

	var Vuls []*share.ScanVulnerability
	if uzb := utils.GunzipBytes(vulsb); uzb != nil {
		buf := bytes.NewBuffer(uzb)
		dec := gob.NewDecoder(buf)
		if err := dec.Decode(&Vuls); err != nil {
			log.WithFields(log.Fields{"vulsb": string(vulsb)}).Error("unzip vuls bytes error")
			return err
		}
	}

	idns := make([]api.RESTIDName, 0)
	if idnsStr != "" {
		if err := json.Unmarshal([]byte(idnsStr), &idns); err != nil {
			log.WithFields(log.Fields{"idnsStr": idnsStr}).Error("unmarshal idnsStr error")
			return err
		}
	}

	// perform VPF, only non-filtered vuls will be returned..
	vpf := cacher.GetVulnerabilityProfileInterface(share.DefaultVulnerabilityProfileName)
	Vuls = vpf.FilterVuls(Vuls, idns)

	var cveSet utils.Set = utils.NewSet()
	mu.Lock()
	for _, vul := range Vuls {
		if _, exist := cvePackages[vul.Name]; exist {
			_, ok := cvePackages[vul.Name][vul.PackageName]
			if !ok {
				cvePackages[vul.Name][vul.PackageName] = utils.NewSet()
			}
			cvePackages[vul.Name][vul.PackageName].Add(api.RESTVulnPackageVersion{
				PackageVersion: vul.PackageVersion,
				FixedVersion:   vul.FixedVersion,
			})
		}

		if cveStat != nil {
			if value, exists := cveStat[vul.Severity]; exists && value != nil {
				*value++
			}
		}

		// get distinct CVEs
		if cveList != nil {
			if cveSet.Contains(vul.Name) {
				continue
			}
			cveSet.Add(vul.Name)
			fix := "nf"
			if len(vul.FixedVersion) > 0 {
				fix = "wf"
			}

			*cveList = append(*cveList, fmt.Sprintf("%s;%s;%s", vul.Name, vul.DBKey, fix))
		}
	}
	mu.Unlock()

	return nil
}

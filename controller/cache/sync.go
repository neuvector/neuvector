package cache

import (
	"encoding/json"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/rpc"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

type syncTxFunc func() *syncDataMsg
type syncRxFunc func(msg *syncDataMsg) int

type syncCatgInfo struct {
	catgName string
	tx       syncTxFunc
	rx       syncRxFunc
}

type syncCatgAux struct {
	modifyIdx uint64
	mtx       sync.RWMutex
}

const (
	syncTxErrorNone          = 0
	syncTxErrorNotSupported  = -1
	syncTxErrorHandlingFail  = -2
	syncTxErrorMsgExceedSize = -3
)

const (
	syncRxErrorNone    = 0
	syncRxErrorRetry   = -1
	syncRxErrorCluster = -2
	syncRxErrorFailed  = -3
)

type syncDataMsg struct {
	CatgName  string `json:"name"`
	ErrorCode int    `json:"error_code,omitempty"`
	ModifyIdx uint64 `json:"modifyIdx"`
	Data      []byte `json:"data"`
}

const (
	syncCatgEventIdx = iota
	syncCatgThreatIdx
	syncCatgGraphIdx
	syncCatgIncidentIdx
	syncCatgAuditIdx
	syncCatgActivityIdx
)

var syncCatgAuxArray []syncCatgAux = make([]syncCatgAux, 6)

const (
	syncCatgEvent    = "event"
	syncCatgThreat   = "threat"
	syncCatgGraph    = "graph"
	syncCatgIncident = "incident"
	syncCatgAudit    = "audit"
	syncCatgActivity = "activity"
)

var syncCatgArray = []syncCatgInfo{
	{syncCatgEvent, syncEventTx, syncEventRx},
	{syncCatgThreat, syncThreatTx, syncThreatRx},
	{syncCatgGraph, syncGraphTx, syncGraphRx},
	{syncCatgIncident, syncIncidentTx, syncIncidentRx},
	{syncCatgAudit, syncAuditTx, syncAuditRx},
	{syncCatgActivity, syncActivityTx, syncActivityRx},
}

type ctrlResyncFilter struct {
	ctrlID string
}

func checkModifyIdx(catg int, idx uint64) bool {
	return (idx > syncCatgAuxArray[catg].modifyIdx)
}

func setModifyIdx(catg int, idx uint64) {
	syncCatgAuxArray[catg].modifyIdx = idx
}

func getModifyIdx(catg int) uint64 {
	return syncCatgAuxArray[catg].modifyIdx
}

func validateModifyIdx(catg int, modifyIdx uint64) bool {
	localIdx := getModifyIdx(catg)
	if localIdx > modifyIdx {
		log.WithFields(log.Fields{
			"local idx": localIdx, "sync idx": modifyIdx, "sync": catg,
		}).Error("data mis-alligned")
		return false
	} else {
		return true
	}
}

func syncLock(catg int) {
	syncCatgAuxArray[catg].mtx.Lock()
}

func syncUnlock(catg int) {
	syncCatgAuxArray[catg].mtx.Unlock()
}

func syncRLock(catg int) {
	syncCatgAuxArray[catg].mtx.RLock()
}

func syncRUnlock(catg int) {
	syncCatgAuxArray[catg].mtx.RUnlock()
}

func GetSyncTxData(catgName string) []byte {
	var msg *syncDataMsg
	for _, info := range syncCatgArray {
		if info.catgName == catgName {
			msg = info.tx()
			if msg == nil {
				log.WithFields(log.Fields{"sync": catgName}).Error("sync request handle fail")
				msg = &syncDataMsg{CatgName: catgName, ErrorCode: syncTxErrorHandlingFail}
			}
			break
		}
	}

	if msg == nil {
		log.WithFields(log.Fields{"sync": catgName}).Error("unknow sync request")
		msg = &syncDataMsg{CatgName: catgName, ErrorCode: syncTxErrorNotSupported}
	}

	value, err := json.Marshal(msg)
	if err != nil {
		// This should not happen
		log.WithFields(log.Fields{
			"sync": msg.CatgName, "idx": msg.ModifyIdx, "data": len(msg.Data), "error": err,
		}).Error("Fail to create sync msg")
		return nil
	}

	zb := utils.GzipBytes(value)
	log.WithFields(log.Fields{
		"sync": msg.CatgName, "idx": msg.ModifyIdx, "data": len(msg.Data), "value": len(value), "zb": len(zb),
	}).Debug("")
	return zb
}

func cbSync(subject string, body []byte, args ...interface{}) {
	ret := args[0].(*int)

	if body == nil {
		*ret = syncRxErrorRetry
		log.WithFields(log.Fields{"subject": subject}).Error("request timeout")
		return
	}

	uzb := utils.GunzipBytes(body)
	if uzb == nil {
		log.WithFields(log.Fields{"subject": subject, "body": len(body)}).Error("unzip error")
		*ret = syncRxErrorFailed
		return
	}

	var msg syncDataMsg
	if err := json.Unmarshal(uzb, &msg); err != nil {
		log.WithFields(log.Fields{"subject": subject, "body": len(body)}).Error("unmarshal error")
		*ret = syncRxErrorFailed
		return
	}

	if msg.ErrorCode != syncTxErrorNone {
		log.WithFields(log.Fields{"subject": subject, "error": msg.ErrorCode}).Error("sync error")
		*ret = syncRxErrorFailed
		return
	}

	log.WithFields(log.Fields{
		"sync": msg.CatgName, "idx": msg.ModifyIdx, "body": len(body), "data": len(msg.Data),
	}).Debug("")

	for _, info := range syncCatgArray {
		if info.catgName == msg.CatgName {
			*ret = info.rx(&msg)
			return
		}
	}
	log.WithFields(log.Fields{"sync": msg.CatgName}).Error("unknown sync reply")
	*ret = syncRxErrorFailed
}

// Return data parsing error code and grpc error
func reqSyncGrpc(target, catgName string) (int, error) {
	reply, err := rpc.ReqSyncStream(target, localDev.Ctrler.RPCServerPort, catgName, localDev.Ctrler.ClusterIP)
	if err == nil {
		log.WithFields(log.Fields{"sync": catgName}).Debug("receive sync reply")
		var ret int = 0
		cbSync(catgName, reply.Data, &ret)
		return ret, nil
	} else {
		// If the rpc call is not implemented, try the non-streaming call
		log.WithFields(log.Fields{"error": err}).Error("rpc sync error")
		if st, ok := status.FromError(err); !ok || st.Code() != codes.Unimplemented {
			return 0, err
		}
	}

	reply, err = rpc.ReqSync(target, localDev.Ctrler.RPCServerPort, catgName, localDev.Ctrler.ClusterIP)
	if err == nil {
		log.WithFields(log.Fields{"sync": catgName}).Debug("receive sync reply")
		var ret int = 0
		cbSync(catgName, reply.Data, &ret)
		return ret, nil
	} else {
		log.WithFields(log.Fields{"error": err}).Error("rpc sync error")
		return 0, err
	}
}

func reqSync(target, catgName string) int {
	log.WithFields(log.Fields{"target": target, "sync": catgName}).Info()

	ret, err := reqSyncGrpc(target, catgName)
	if st, ok := status.FromError(err); ok {
		if st.Code() == codes.ResourceExhausted {
			return syncRxErrorCluster
		}
	}
	return ret
}

// Better to be atomic but it is fine not to be so precise here
var syncInProcess bool
var syncInitDone bool

const syncRetryMax int = 3

func ctrlSyncFromTarget(target string) int {
	log.WithFields(log.Fields{"target": target}).Info()

	syncInProcess = true
	defer func() {
		syncInProcess = false
	}()

	var pos int = 0
	var retry int = 0
	for pos < len(syncCatgArray) {
		catgName := syncCatgArray[pos].catgName
		err := reqSync(target, catgName)
		if err == syncRxErrorRetry {
			if retry < syncRetryMax {
				retry++
				log.WithFields(log.Fields{"sync": catgName}).Error("request failed - will retry")
				continue
			} else {
				log.WithFields(log.Fields{"sync": catgName, "error": err}).Error("max number of retry reached - give up")
			}
		} else if err != syncRxErrorNone {
			log.WithFields(log.Fields{"sync": catgName, "error": err}).Error("request fail - ignored")
		}

		retry = 0
		pos++
	}

	return 0
}

const controllerStableThreshold = time.Duration(time.Second * 30)

// Return the sync target and if it is self.
func getSyncTargetLeader(force bool) (string, bool) {
	if cacher.leadAddr == "" {
		return "", false
	} else if force {
		return cacher.leadAddr, isLeader()
	} else if time.Since(cacher.leaderElectedAt) > controllerStableThreshold {
		return cacher.leadAddr, isLeader()
	} else {
		return "", isLeader()
	}
}

// Return the sync target and if it is self.
func getSyncTargetOldest(all []*share.CLUSController) (string, bool) {
	var oldest *share.CLUSController
	for _, c := range all {
		if oldest == nil || c.StartedAt.Before(oldest.StartedAt) {
			oldest = c
		}
	}

	if oldest != nil && oldest.ID != cctx.LocalDev.Ctrler.ID &&
		time.Since(oldest.StartedAt) < controllerStableThreshold {
		oldest = nil
	}

	if oldest == nil {
		return cacher.leadAddr, isLeader()
	} else {
		return oldest.ClusterIP, oldest.ID == cctx.LocalDev.Ctrler.ID
	}
}

func SyncFromLeader() {
	if syncInitDone && !syncInProcess {
		if target, self := getSyncTargetLeader(false); target == "" || self {
			log.WithFields(log.Fields{"target": target, "self": self}).Info("skip sync")
		} else {
			go ctrlSyncFromTarget(target)
		}
	}
}

func SyncInit(isNewCluster bool) {
	log.WithFields(log.Fields{"new-cluster": isNewCluster}).Info()

	defer func() {
		syncInitDone = true
	}()

	// When cluster lose lead, anyone can be elected as the new lead, could be the one
	// just started, not necessarily the oldest one who possesses the full graph and
	// events. So, instead of syncing from the lead, sync from the oldest.
	// Will not give up until sync succeed at init
	for {
		ctrls := syncMemberStateFromCluster()
		if ctrls != nil {
			var target string
			var self bool
			// When cluster lose lead, anyone can be elected as the new lead, not necessarily
			// the oldest one who possesses the full graph and events. So, instead of syncing
			// from the lead, sync from the oldest.
			if isNewCluster {
				target, self = getSyncTargetLeader(false)
			} else {
				target, self = getSyncTargetOldest(ctrls)
			}
			if target == "" || self {
				log.WithFields(log.Fields{"target": target, "self": self}).Info("skip sync")
				break
			} else if ctrlSyncFromTarget(target) == 0 {
				break
			}
		}

		time.Sleep(time.Second * 2)
	}
}

// All controller can get here
func CtrlFailRecovery() {
	if syncInitDone {
		ctrls := syncMemberStateFromCluster()
		if ctrls != nil {
			// When cluster lose lead, anyone can be elected as the new lead, not necessarily
			// the oldest one who possesses the full graph and events. So, instead of syncing
			// from the lead, sync from the oldest.
			if target, self := getSyncTargetLeader(false); target == "" || self {
				log.WithFields(log.Fields{"target": target, "self": self}).Info("skip sync")
			} else {
				ctrlSyncFromTarget(target)
			}
		}

		pruneHost()
	}
}

func CheckPolicySyncStatus() *share.CLUSPolicySyncStatus {
	ss := share.CLUSPolicySyncStatus{
		Leader: isLeader(),
	}
	// Leader does not need to compare the rules
	checkGraphSyncState(&ss, !ss.Leader)
	return &ss
}

const ctrlSyncDelay = time.Duration(time.Second * 20)

var currResyncFilters []ctrlResyncFilter = make([]ctrlResyncFilter, 0)
var resyncMutex sync.Mutex

func queueHotSyncRequest(filter []ctrlResyncFilter) {
	log.WithFields(log.Fields{"filter": filter}).Debug()
	resyncMutex.Lock()
	if len(currResyncFilters) == 0 {
		ctrlSyncTimer.Reset(ctrlSyncDelay)
	}
	for _, f := range filter {
		var dup bool = false
		for _, e := range currResyncFilters {
			if f.ctrlID == e.ctrlID {
				dup = true
				break
			}
		}
		if !dup {
			currResyncFilters = append(currResyncFilters, f)
		}
	}
	resyncMutex.Unlock()
}

func putHotSyncRequest() int {
	resyncMutex.Lock()
	defer resyncMutex.Unlock()

	log.WithFields(log.Fields{"filter": currResyncFilters}).Debug()

	if len(currResyncFilters) == 0 {
		log.Error("No resync filter")
		return 0
	}

	var syncFilter *ctrlResyncFilter
	var target string
	var targetPort uint16
	var i int
	var f ctrlResyncFilter

	cacheMutexRLock()
	for i, f = range currResyncFilters {
		if cache, ok := ctrlCacheMap[f.ctrlID]; ok &&
			cache.state == api.StateOnline && !cache.ctrl.Leader {
			syncFilter = &currResyncFilters[i]
			target = cache.ctrl.ClusterIP
			targetPort = cache.ctrl.RPCServerPort
			break
		}
	}
	cacheMutexRUnlock()

	currResyncFilters = currResyncFilters[i+1:]

	if syncFilter != nil {
		if err := rpc.TriggerSync(target, targetPort); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("sync request error, will retry")
			currResyncFilters = append(currResyncFilters, *syncFilter)
		} else {
			log.Debug("sync request succeed")
		}
	}

	if len(currResyncFilters) > 0 {
		ctrlSyncTimer.Reset(ctrlSyncDelay)
	}
	return 0
}

var lastSyncAt time.Time

const GraphNodeCountSmall uint32 = 500
const GraphNodeCountMedium uint32 = 1500
const GraphNodeCountLarge uint32 = 3000
const GraphNodeCountSuper uint32 = 5000

const syncFreqSmall = time.Duration(time.Minute * 10)
const syncFreqMedium = time.Duration(time.Minute * 20)
const syncFreqLarge = time.Duration(time.Minute * 30)
const syncFreqSuper = time.Duration(time.Minute * 40)
const syncFreqMax = time.Duration(time.Minute * 60)

func syncCheck(isLeader bool) {
	if !syncInitDone {
		return
	}

	ctrls := syncMemberStateFromCluster()
	pruneHost()

	if isLeader {
		// leader only sync the cluster members, but not the data
		return
	}

	ss := CheckPolicySyncStatus()
	// A rough way to fix learned policy sync issue
	if len(ss.Mismatches) > 0 && !syncInProcess {

		log.WithFields(log.Fields{
			"graphcnt":   ss.GraphNodeCount,
			"lastSyncAt": api.RESTTimeString(lastSyncAt),
			"now":        api.RESTTimeString(time.Now().UTC()),
		}).Debug("")
		//sync consumes large memory, when cluster has large number of
		//groups it affects cluster ramping up performance, so we ratelimit
		//sync frequence based on number of GraphNodeCount
		if !lastSyncAt.IsZero() {
			if ss.GraphNodeCount <= GraphNodeCountSmall {
				if time.Since(lastSyncAt) < syncFreqSmall {
					log.Debug("skip sync small")
					return
				}
			} else if ss.GraphNodeCount <= GraphNodeCountMedium {
				if time.Since(lastSyncAt) < syncFreqMedium {
					log.Debug("skip sync medium")
					return
				}
			} else if ss.GraphNodeCount <= GraphNodeCountLarge {
				if time.Since(lastSyncAt) < syncFreqLarge {
					log.Debug("skip sync large")
					return
				}
			} else if ss.GraphNodeCount <= GraphNodeCountSuper {
				if time.Since(lastSyncAt) < syncFreqSuper {
					log.Debug("skip sync super")
					return
				}
			} else {
				if time.Since(lastSyncAt) < syncFreqMax {
					log.Debug("skip sync max")
					return
				}
			}
		}
		log.WithFields(log.Fields{"ss": ss}).Error("Detected sync error")

		if ctrls != nil {
			// When cluster lose lead, anyone can be elected as the new lead, not necessarily
			// the oldest one who possesses the full graph and events. So, instead of syncing
			// from the lead, sync from the oldest.
			if target, self := getSyncTargetLeader(false); target == "" || self {
				log.WithFields(log.Fields{"target": target, "self": self}).Info("skip sync")
			} else {
				lastSyncAt = time.Now().UTC()
				ctrlSyncFromTarget(target)
			}
		}
	}
}

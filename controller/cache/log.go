package cache

// #include "../../defs.h"
import "C"

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	nvsysadmission "github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg/admission"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
)

const logCacheSize int = 4096
const maxSyslogMsg int32 = 256
const logDescriptionLength int = 256

var syslogMutex sync.RWMutex
var syslogMsgCount int32
var syslogLastConnKey string // a string to identify the connection criteria
var syslogOverflowAt, syslogLastFailAt time.Time

func syslogMutexLock() {
	cctx.MutexLog.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("Acquire ...")
	syslogMutex.Lock()
}

func syslogMutexUnlock() {
	syslogMutex.Unlock()
	cctx.MutexLog.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("Released")
}

type logConnect struct {
	hostID    string
	ingress   bool
	localPeer bool
	ipproto   uint8
	srcIP     net.IP
	dstIP     net.IP
	srcPort   uint16
	dstPort   uint16
}

var activityCache []*api.Event = make([]*api.Event, logCacheSize)
var curActivityIndex int = 0
var eventCache []*api.Event = make([]*api.Event, logCacheSize)
var curEventIndex int = 0
var thrtMap map[string]*api.Threat = make(map[string]*api.Threat)
var thrtCache []*api.Threat = make([]*api.Threat, logCacheSize)
var curThrtIndex int = 0
var vioCache []*api.Violation = make([]*api.Violation, logCacheSize)
var curVioIndex int = 0
var incidentCache []*api.Incident = make([]*api.Incident, logCacheSize)
var curIncidentIndex int = 0
var auditCache []*api.Audit = make([]*api.Audit, logCacheSize)
var curAuditIndex int = 0

// This is currently used to record policy voilation logs. It's not really a traffic log,
// but an aggregated record.
func (m CacheMethod) GetViolations(acc *access.AccessControl) []*api.Violation {
	logs := make([]*api.Violation, 0)
	for i := 0; i < curVioIndex; i++ {
		vio := vioCache[curVioIndex-i-1]
		if !acc.Authorize(vio, nil) {
			continue
		}
		logs = append(logs, vio)
	}

	return logs
}

func (m CacheMethod) GetViolationCount(acc *access.AccessControl) int {
	if acc.HasGlobalPermissions(share.PERM_SECURITY_EVENTS_BASIC, 0) {
		return curVioIndex
	} else {
		var count int
		for i := 0; i < curVioIndex; i++ {
			vio := vioCache[curVioIndex-i-1]
			if !acc.Authorize(vio, nil) {
				continue
			}
			count++
		}
		return count
	}
}

func (m CacheMethod) GetActivities(acc *access.AccessControl) []*api.Event {
	users := clusHelper.GetAllUsers(acc)

	logs := make([]*api.Event, 0)
	for i := 0; i < curActivityIndex; i++ {
		ev := activityCache[curActivityIndex-i-1]
		if !acc.Authorize(ev, func(u string) share.AccessObject {
			if user, ok := users[u]; ok {
				return user
			} else {
				return nil
			}
		}) {
			continue
		}
		logs = append(logs, ev)
	}

	return logs
}

func (m CacheMethod) GetActivityCount(acc *access.AccessControl) int {
	if acc.HasGlobalPermissions(share.PERM_EVENTS, 0) {
		return curActivityIndex
	} else {
		users := clusHelper.GetAllUsers(acc)

		var count int
		for i := 0; i < curActivityIndex; i++ {
			ev := activityCache[curActivityIndex-i-1]
			if !acc.Authorize(ev, func(u string) share.AccessObject {
				if user, ok := users[u]; ok {
					return user
				} else {
					return nil
				}
			}) {
				continue
			}
			count++
		}
		return count
	}
}

func (m CacheMethod) GetEvents(caller string, acc *access.AccessControl) []*api.Event {
	// caller being "" means follow permission only
	users := clusHelper.GetAllUsers(acc)

	logs := make([]*api.Event, 0)
	for i := 0; i < curEventIndex; i++ {
		ev := eventCache[curEventIndex-i-1]
		if !acc.Authorize(ev, func(u string) share.AccessObject {
			if user, ok := users[u]; ok {
				return user
			} else {
				return nil
			}
		}) {
			if caller == "" || caller != ev.User { // every user is allowed to see his/her own events
				continue
			}
		}
		logs = append(logs, ev)
	}

	return logs
}

func (m CacheMethod) GetEventCount(caller string, acc *access.AccessControl) int {
	// caller being "" means follow permission only
	if acc.HasGlobalPermissions(share.PERM_EVENTS, 0) {
		return curEventIndex
	} else {
		users := clusHelper.GetAllUsers(acc)

		var count int
		for i := 0; i < curEventIndex; i++ {
			ev := eventCache[curEventIndex-i-1]
			if !acc.Authorize(ev, func(u string) share.AccessObject {
				if user, ok := users[u]; ok {
					return user
				} else {
					return nil
				}
			}) {
				if caller == "" || caller != ev.User { // every user is allowed to see his/her own events
					continue
				}
			}
			count++
		}
		return count
	}
}

func (m CacheMethod) GetThreats(acc *access.AccessControl) []*api.Threat {
	logs := make([]*api.Threat, 0)
	for i := 0; i < curThrtIndex; i++ {
		thrt := thrtCache[curThrtIndex-i-1]
		if !acc.Authorize(thrt, nil) {
			continue
		}
		logs = append(logs, thrt)
	}

	return logs
}

func (m CacheMethod) GetThreat(id string, acc *access.AccessControl) (*api.Threat, error) {
	if thrt, ok := thrtMap[id]; ok {
		if !acc.Authorize(thrt, nil) {
			return nil, common.ErrObjectAccessDenied
		}
		return thrt, nil
	}
	return nil, common.ErrObjectNotFound
}

func (m CacheMethod) GetThreatCount(acc *access.AccessControl) int {
	if acc.HasGlobalPermissions(share.PERM_SECURITY_EVENTS_BASIC, 0) {
		return curThrtIndex
	} else {
		var count int
		for i := 0; i < curThrtIndex; i++ {
			thrt := thrtCache[curThrtIndex-i-1]
			if !acc.Authorize(thrt, nil) {
				continue
			}
			count++
		}
		return count
	}
}

func (m CacheMethod) GetIncidents(acc *access.AccessControl) []*api.Incident {
	logs := make([]*api.Incident, 0)
	for i := 0; i < curIncidentIndex; i++ {
		incd := incidentCache[curIncidentIndex-i-1]
		if !acc.Authorize(incd, nil) {
			continue
		}
		logs = append(logs, incd)
	}

	return logs
}

func (m CacheMethod) GetIncidentCount(acc *access.AccessControl) int {
	if acc.HasGlobalPermissions(share.PERM_SECURITY_EVENTS_BASIC, 0) {
		return curIncidentIndex
	} else {
		var count int
		for i := 0; i < curIncidentIndex; i++ {
			incd := incidentCache[curIncidentIndex-i-1]
			if !acc.Authorize(incd, nil) {
				continue
			}
			count++
		}
		return count
	}
}

func (m CacheMethod) GetAudits(acc *access.AccessControl) []*api.Audit {
	syncRLock(syncCatgAuditIdx)
	defer syncRUnlock(syncCatgAuditIdx)
	logs := make([]*api.Audit, 0)
	for i := 0; i < curAuditIndex; i++ {
		incd := auditCache[curAuditIndex-i-1]
		if !acc.Authorize(incd, nil) {
			continue
		}
		logs = append(logs, incd)
	}

	return logs
}

func (m CacheMethod) GetAuditCount(acc *access.AccessControl) int {
	syncRLock(syncCatgAuditIdx)
	defer syncRUnlock(syncCatgAuditIdx)

	if acc.HasGlobalPermissions(share.PERM_AUDIT_EVENTS, 0) {
		return curAuditIndex
	} else {
		var count int
		for i := 0; i < curAuditIndex; i++ {
			incd := auditCache[curAuditIndex-i-1]
			if !acc.Authorize(incd, nil) {
				continue
			}
			count++
		}
		return count
	}
}

func recordViolation(rlog *api.Violation) {
	log.WithFields(log.Fields{"client": rlog.ClientName, "server": rlog.ServerName}).Debug("")

	if curVioIndex == logCacheSize {
		_, vioCache = vioCache[0], vioCache[1:]
		vioCache = append(vioCache, rlog)
	} else {
		vioCache[curVioIndex] = rlog
		curVioIndex++
	}
}

func recordActivity(rlog *api.Event) {
	log.WithFields(log.Fields{"name": rlog.Name}).Debug("")

	if curActivityIndex == logCacheSize {
		_, activityCache = activityCache[0], activityCache[1:]
		activityCache = append(activityCache, rlog)
	} else {
		activityCache[curActivityIndex] = rlog
		curActivityIndex++
	}
}

func recordEvent(rlog *api.Event) {
	log.WithFields(log.Fields{"name": rlog.Name}).Debug("")

	if curEventIndex == logCacheSize {
		_, eventCache = eventCache[0], eventCache[1:]
		eventCache = append(eventCache, rlog)
	} else {
		eventCache[curEventIndex] = rlog
		curEventIndex++
	}
}

func recordIncident(rlog *api.Incident) {
	log.WithFields(log.Fields{"name": rlog.Name}).Debug("")

	if curIncidentIndex == logCacheSize {
		_, incidentCache = incidentCache[0], incidentCache[1:]
		incidentCache = append(incidentCache, rlog)
	} else {
		incidentCache[curIncidentIndex] = rlog
		curIncidentIndex++
	}
}

func recordThreat(rlog *api.Threat) {
	log.WithFields(log.Fields{"name": rlog.Name}).Debug("")

	if curThrtIndex == logCacheSize {
		var pop *api.Threat
		pop, thrtCache = thrtCache[0], thrtCache[1:]
		thrtCache = append(thrtCache, rlog)
		delete(thrtMap, pop.ID)
		thrtMap[rlog.ID] = rlog
	} else {
		thrtCache[curThrtIndex] = rlog
		thrtMap[rlog.ID] = rlog
		curThrtIndex++
	}
}

func recordAudit(rlog *api.Audit) {
	log.WithFields(log.Fields{"name": rlog.Name, "level": rlog.Level}).Debug("")

	auditSuppressSetIdRpts(rlog)
	if curAuditIndex == logCacheSize {
		_, auditCache = auditCache[0], auditCache[1:]
		auditCache = append(auditCache, rlog)
	} else {
		auditCache[curAuditIndex] = rlog
		curAuditIndex++
	}
}

func getWebhookCache(ruleID int, whName string) *webhookCache {
	var whc *webhookCache
	if ruleID > api.StartingFedAdmRespRuleID {
		whc, _ = fedWebhookCacheMap[whName]
	} else {
		whc, _ = webhookCacheMap[whName]
	}

	return whc
}

func getWebhookProxy(whc *webhookCache) *share.CLUSProxy {
	if !whc.useProxy {
		return nil
	}

	if strings.HasPrefix(whc.url, "http://") {
		proxy := systemConfigCache.RegistryHttpProxy
		if !proxy.Enable {
			return nil
		} else {
			return &proxy
		}
	} else if strings.HasPrefix(whc.url, "https://") {
		proxy := systemConfigCache.RegistryHttpsProxy
		if !proxy.Enable {
			return nil
		} else {
			return &proxy
		}
	}

	return nil
}

func webhookActivity(act *actionDesc, arg interface{}) {
	rlog := arg.(*api.Event)
	rlog.ResponseRuleID = int(act.id)
	if isLeader() && len(act.webhooks) > 0 {
		title := fmt.Sprintf("%s", rlog.Name)
		for _, w := range act.webhooks {
			if whc := getWebhookCache(rlog.ResponseRuleID, w); whc != nil {
				proxy := getWebhookProxy(whc)
				whc.c.Notify(rlog, rlog.Level, api.CategoryEvent, rlog.ClusterName, title, act.comment, proxy)
			}
		}
	}
}

func webhookEvent(act *actionDesc, arg interface{}) {
	rlog := arg.(*api.Event)
	rlog.ResponseRuleID = int(act.id)
	if isLeader() && len(act.webhooks) > 0 {
		title := fmt.Sprintf("%s", rlog.Name)
		for _, w := range act.webhooks {
			if whc := getWebhookCache(rlog.ResponseRuleID, w); whc != nil {
				proxy := getWebhookProxy(whc)
				whc.c.Notify(rlog, rlog.Level, api.CategoryEvent, rlog.ClusterName, title, act.comment, proxy)
			}
		}
	}
}

func webhookViolation(act *actionDesc, arg interface{}) {
	rlog := arg.(*api.Violation)
	rlog.ResponseRuleID = int(act.id)
	if isLeader() && len(act.webhooks) > 0 {
		title := fmt.Sprintf("%s -> %s", rlog.ClientName, rlog.ServerName)
		for _, w := range act.webhooks {
			if whc := getWebhookCache(rlog.ResponseRuleID, w); whc != nil {
				proxy := getWebhookProxy(whc)
				whc.c.Notify(rlog, rlog.Level, api.CategoryViolation, rlog.ClusterName, title, act.comment, proxy)
			}
		}
	}
}

func webhookThreat(act *actionDesc, arg interface{}) {
	rlog := arg.(*api.Threat)
	rlog.ResponseRuleID = int(act.id)
	if isLeader() && len(act.webhooks) > 0 {
		var title string
		if rlog.Target == api.TargetServer {
			title = fmt.Sprintf("%s -> %s", rlog.Name, rlog.ServerWLName)
		} else {
			title = fmt.Sprintf("%s -> %s", rlog.Name, rlog.ClientWLName)
		}
		len, pkt := rlog.CapLen, rlog.Packet
		rlog.CapLen, rlog.Packet = 0, ""
		for _, w := range act.webhooks {
			if whc := getWebhookCache(rlog.ResponseRuleID, w); whc != nil {
				proxy := getWebhookProxy(whc)
				whc.c.Notify(rlog, rlog.Level, api.CategoryThreat, rlog.ClusterName, title, act.comment, proxy)
			}
		}
		rlog.CapLen, rlog.Packet = len, pkt
	}
}

func webhookIncident(act *actionDesc, arg interface{}) {
	rlog := arg.(*api.Incident)
	rlog.ResponseRuleID = int(act.id)
	if isLeader() && len(act.webhooks) > 0 {
		title := fmt.Sprintf("%s at %s", rlog.Name, rlog.WorkloadName)
		for _, w := range act.webhooks {
			if whc := getWebhookCache(rlog.ResponseRuleID, w); whc != nil {
				proxy := getWebhookProxy(whc)
				whc.c.Notify(rlog, rlog.Level, api.CategoryIncident, rlog.ClusterName, title, act.comment, proxy)
			}
		}
	}
}

func webhookAudit(act *actionDesc, arg interface{}) {
	rlog := arg.(*api.Audit)
	rlog.ResponseRuleID = int(act.id)
	if isLeader() && len(act.webhooks) > 0 {
		var title string
		if rlog.Name == api.EventNameComplianceContainerBenchViolation ||
			rlog.Name == api.EventNameComplianceHostBenchViolation ||
			rlog.Name == api.EventNameComplianceContainerCustomCheckViolation ||
			rlog.Name == api.EventNameComplianceHostCustomCheckViolation ||
			rlog.Name == api.EventNameAwsLambdaScan ||
			rlog.Name == api.EventNameAdmCtrlK8sReqAllowed ||
			rlog.Name == api.EventNameAdmCtrlK8sReqViolation ||
			rlog.Name == api.EventNameAdmCtrlK8sReqDenied {
			title = fmt.Sprintf("%s", rlog.Name)
		} else if rlog.Level != api.LogLevelERR {
			title = fmt.Sprintf("%s: critical: %d high %d medium %d", rlog.Name,
				rlog.CriticalCnt, rlog.HighCnt, rlog.MediumCnt)
		} else {
			title = fmt.Sprintf("%s error:  %s", rlog.Name, rlog.Error)
		}
		for _, w := range act.webhooks {
			if whc := getWebhookCache(rlog.ResponseRuleID, w); whc != nil {
				proxy := getWebhookProxy(whc)
				whc.c.Notify(rlog, rlog.Level, api.CategoryAudit, rlog.ClusterName, title, act.comment, proxy)
			}
		}
	}
}

func sendSyslog(elog interface{}, level, cat, header string) {
	// In the case syslog server is not configured correctly, send() call could take long time
	// to timeout. A lot of goroutines wait to grab the lock and consume large amount of memory.
	// Set a limit to prevent this situation.
	c := atomic.AddInt32(&syslogMsgCount, 1)
	defer atomic.AddInt32(&syslogMsgCount, -1)

	if c >= maxSyslogMsg {
		if time.Since(syslogOverflowAt) > time.Minute*time.Duration(30) {
			syslogOverflowAt = time.Now()
			log.Error("Maximum concurrent syslog message reached. Check syslog server settings.")
		}
		return
	}

	syslogMutexLock()
	defer syslogMutexUnlock()

	if syslogger != nil {
		if err := syslogger.Send(elog, level, cat, header); err != nil {
			connKey := syslogger.Identifier()
			if time.Since(syslogLastFailAt) > time.Minute*time.Duration(30) || syslogLastConnKey != connKey {
				if syslogLastConnKey != connKey {
					syslogOverflowAt = time.Time{} // set to zero
				}
				syslogLastConnKey = connKey
				syslogLastFailAt = time.Now()
				log.WithFields(log.Fields{"error": err}).Error()
			}
		}
	}
}

func logActivity(arg interface{}) {
	rlog := arg.(*api.Event)
	recordActivity(rlog)
	if isLeader() {
		go sendSyslog(rlog, rlog.Level, api.CategoryEvent, "activity")
	}
}

func logEvent(arg interface{}) {
	rlog := arg.(*api.Event)
	recordEvent(rlog)
	if isLeader() {
		go sendSyslog(rlog, rlog.Level, api.CategoryEvent, "event")
	}
}

func logViolation(arg interface{}) {
	rlog := arg.(*api.Violation)
	recordViolation(rlog)
	if isLeader() {
		go sendSyslog(rlog, rlog.Level, api.CategoryViolation, "violation")
	}
}

func logThreat(arg interface{}) {
	rlog := arg.(*api.Threat)
	recordThreat(rlog)
	if isLeader() {
		go func() {
			len, pkt := rlog.CapLen, rlog.Packet
			rlog.CapLen, rlog.Packet = 0, ""
			sendSyslog(rlog, rlog.Level, api.CategoryThreat, "threat")
			rlog.CapLen, rlog.Packet = len, pkt
		}()
	}
}

func logIncident(arg interface{}) {
	rlog := arg.(*api.Incident)
	recordIncident(rlog)
	if isLeader() {
		go sendSyslog(rlog, rlog.Level, api.CategoryIncident, "incident")
	}
}

func fillVulAudit(l *api.Audit, cve string) {
	v, ok := l.Vuls[cve]
	if ok {
		l.Packages = []string{v.PackageName}
		l.PackageVersion = v.PackageVersion
		l.FixedVersion = v.FixedVersion
		l.Link = v.Link
		l.Score = v.Score
		l.ScoreV3 = v.ScoreV3
		l.Vectors = v.Vectors
		l.VectorsV3 = v.VectorsV3
		l.Published = v.PublishedDate
		l.LastMod = v.FixedVersion
		if len(v.Description) > logDescriptionLength {
			l.Description = fmt.Sprintf("%s...", v.Description[:logDescriptionLength])
		} else {
			l.Description = v.Description
		}
	}
}

func logAudit(arg interface{}) {
	rlog := arg.(*api.Audit)
	recordAudit(rlog)
	if isLeader() {
		if systemConfigCache.SingleCVEPerSyslog &&
			(rlog.Name == api.EventNameContainerScanReport ||
				rlog.Name == api.EventNameHostScanReport ||
				rlog.Name == api.EventNameRegistryScanReport ||
				rlog.Name == api.EventNamePlatformScanReport) &&
			(len(rlog.CriticalVuls) > 0 || len(rlog.HighVuls) > 0 || len(rlog.MediumVuls) > 0) {
			go func() {
				for _, v := range rlog.CriticalVuls {
					l := *rlog
					l.CriticalVuls = []string{v}
					l.HighVuls = []string{}
					l.MediumVuls = []string{}
					l.CriticalCnt = 1
					l.HighCnt = 0
					l.MediumCnt = 0
					fillVulAudit(&l, v)
					sendSyslog(&l, l.Level, api.CategoryAudit, "audit")
				}
				for _, v := range rlog.HighVuls {
					l := *rlog
					l.CriticalVuls = []string{}
					l.HighVuls = []string{v}
					l.MediumVuls = []string{}
					l.CriticalCnt = 0
					l.HighCnt = 1
					l.MediumCnt = 0
					fillVulAudit(&l, v)
					sendSyslog(&l, l.Level, api.CategoryAudit, "audit")
				}
				for _, v := range rlog.MediumVuls {
					l := *rlog
					l.CriticalVuls = []string{}
					l.HighVuls = []string{}
					l.MediumVuls = []string{v}
					l.CriticalCnt = 0
					l.HighCnt = 0
					l.MediumCnt = 1
					fillVulAudit(&l, v)
					sendSyslog(&l, l.Level, api.CategoryAudit, "audit")
				}
			}()
		} else {
			go sendSyslog(rlog, rlog.Level, api.CategoryAudit, "audit")
		}

		if systemConfigCache.SyslogCVEInLayers &&
			(rlog.Name == api.EventNameContainerScanReport ||
				rlog.Name == api.EventNameHostScanReport ||
				rlog.Name == api.EventNameRegistryScanReport ||
				rlog.Name == api.EventNamePlatformScanReport) {
			go func() {
				for _, llog := range rlog.Layers {
					if len(llog.CriticalVuls) > 0 || len(llog.HighVuls) > 0 || len(llog.MediumVuls) > 0 {
						// copy the fields of the layer
						rlog.ImageLayerDigest = llog.ImageLayerDigest
						rlog.Cmds = llog.Cmds
						rlog.CriticalVuls = llog.CriticalVuls
						rlog.HighVuls = llog.HighVuls
						rlog.MediumVuls = llog.MediumVuls
						rlog.CriticalCnt = llog.CriticalCnt
						rlog.HighCnt = llog.HighCnt
						rlog.MediumCnt = llog.MediumCnt
						if systemConfigCache.SingleCVEPerSyslog {
							for _, v := range rlog.CriticalVuls {
								l := *rlog
								l.CriticalVuls = []string{v}
								l.HighVuls = []string{}
								l.MediumVuls = []string{}
								l.CriticalCnt = 1
								l.HighCnt = 0
								l.MediumCnt = 0
								fillVulAudit(&l, v)
								sendSyslog(&l, l.Level, api.CategoryAudit, "audit")
							}
							for _, v := range rlog.HighVuls {
								l := *rlog
								l.CriticalVuls = []string{}
								l.HighVuls = []string{v}
								l.MediumVuls = []string{}
								l.CriticalCnt = 0
								l.HighCnt = 1
								l.MediumCnt = 0
								fillVulAudit(&l, v)
								sendSyslog(&l, l.Level, api.CategoryAudit, "audit")
							}
							for _, v := range rlog.MediumVuls {
								l := *rlog
								l.CriticalVuls = []string{}
								l.HighVuls = []string{}
								l.MediumVuls = []string{v}
								l.CriticalCnt = 0
								l.HighCnt = 0
								l.MediumCnt = 1
								fillVulAudit(&l, v)
								sendSyslog(&l, l.Level, api.CategoryAudit, "audit")
							}
						} else {
							sendSyslog(rlog, rlog.Level, api.CategoryAudit, "audit")
						}
					}
				}
			}()
		}
	}
}

func eventLogUpdate(nType cluster.ClusterNotifyType, key string, value []byte, modifyIdx uint64) {
	log.WithFields(log.Fields{"type": cluster.ClusterNotifyName[nType], "key": key}).Debug("")

	// Use event sync lock for both event and activity
	if checkModifyIdx(syncCatgEventIdx, modifyIdx) == false {
		return
	}
	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		uzb := utils.GunzipBytes(value)
		if uzb == nil {
			log.Error("Failed to unzip data")
			return
		}

		var evs []share.CLUSEventLog
		err := json.Unmarshal(uzb, &evs)
		if err != nil || len(evs) == 0 {
			log.WithFields(log.Fields{
				"error": err, "uzb": uzb, "value": value,
			}).Error("Cannot decode event")
			return
		}

		syncLock(syncCatgEventIdx)
		defer syncUnlock(syncCatgEventIdx)
		defer setModifyIdx(syncCatgEventIdx, modifyIdx)

		for _, ev := range evs {
			if ev.Event == share.CLUSEvAgentStop {
				agentStopEventHandler(&ev)
			}

			var rlog *api.Event
			if ev.Event >= share.CLUSEvAdmCtrlK8sConfigured && ev.Event <= share.CLUSEvAdmCtrlK8sConfigFailed {
				rlog = admCtrlLog2API(&ev)
			} else {
				rlog = eventLog2API(&ev)
			}
			if rlog != nil {
				var desc eventDesc

				if ev.Event >= share.CLUSEvWorkloadStart && ev.Event <= share.CLUSEvWorkloadUnsecured_UNUSED {
					desc = eventDesc{id: rlog.WorkloadID, event: share.EventActivity,
						name: rlog.Name, level: rlog.Level, arg: rlog}
				} else {
					desc = eventDesc{id: rlog.WorkloadID, event: share.EventEvent,
						name: rlog.Name, groupName: ev.GroupName, level: rlog.Level, arg: rlog}
				}
				responseRuleLookup(&desc)
			}
		}
	}
}

func violationUpdate(conn *share.CLUSConnection, server uint32) {
	rlog := conn2Violation(conn, server)
	desc := eventDesc{id: rlog.ClientWL, name: common.NetworkViolation, event: share.EventViolation,
		level: rlog.Level, arg: rlog}
	if rlog.ClientImage == "" {
		// Meaning this is not a managed workload. Use server's workload
		// for response rule lookup instead but no quarantine of the server
		desc.id = rlog.ServerWL
		desc.noQuar = true
	}
	responseRuleLookup(&desc)

	if isLeader() && conn.LogUID != "" {
		f := api.IBMSAFinding{
			ID:          conn.LogUID,
			Name:        rlog.Name,
			Level:       rlog.Level,
			EventType:   desc.event,
			At:          time.Unix(int64(conn.LastSeenAt), 0).UTC(),
			ClientIP:    rlog.ClientIP,
			ClientPort:  uint16(conn.ClientPort),
			ServerIP:    rlog.ServerIP,
			ServerPort:  rlog.ServerPort,
			Protocol:    rlog.IPProto,
			ServerBytes: int32(conn.Bytes),
		}
		if conn.Ingress {
			f.Direction = "ingress"
		} else {
			f.Direction = "egress"
		}
		var param interface{} = &f
		cctx.StartStopFedPingPollFunc(share.PostToIBMSA, 0, param)
	}
}

func threatLogUpdate(nType cluster.ClusterNotifyType, key string, value []byte, modifyIdx uint64) {
	log.WithFields(log.Fields{"type": cluster.ClusterNotifyName[nType], "key": key}).Debug("")

	if checkModifyIdx(syncCatgThreatIdx, modifyIdx) == false {
		return
	}

	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		uzb := utils.GunzipBytes(value)
		if uzb == nil {
			log.Error("Failed to unzip data")
			return
		}

		var thrts []share.CLUSThreatLog
		json.Unmarshal(uzb, &thrts)

		syncLock(syncCatgThreatIdx)
		defer syncUnlock(syncCatgThreatIdx)
		defer setModifyIdx(syncCatgThreatIdx, modifyIdx)

		for _, thrt := range thrts {
			lc := &logConnect{
				hostID:    thrt.HostID,
				localPeer: thrt.LocalPeer,
				ingress:   thrt.PktIngress,
				ipproto:   thrt.IPProto,
				srcIP:     thrt.SrcIP,
				dstIP:     thrt.DstIP,
				srcPort:   thrt.SrcPort,
				dstPort:   thrt.DstPort,
			}
			id, port := preProcessLogConnect(lc)

			if rlog := threatLog2API(&thrt, id, port); rlog != nil {
				desc := eventDesc{id: thrt.WorkloadID, event: share.EventThreat,
					name: rlog.Name, level: rlog.Level, arg: rlog}
				if !isDlpThreatID(thrt.ThreatID) && !isWafThreatID(thrt.ThreatID) {
					//this logic apply to non-dlp threat
					if (rlog.Target == api.TargetServer && desc.id == rlog.ServerWL) ||
						(rlog.Target == api.TargetClient && desc.id == rlog.ClientWL) {
						// Victim of the threat should not be quarantined
						desc.noQuar = true
					}
				}

				responseRuleLookup(&desc)

				if isLeader() {
					// even when rlog.Count > 1, we only send one occurrence to IBM SA
					f := api.IBMSAFinding{
						ID:         rlog.ID,
						Name:       rlog.Name,
						Level:      rlog.Level,
						EventType:  desc.event,
						At:         thrt.ReportedAt,
						ClientIP:   rlog.ClientIP,
						ClientPort: rlog.ClientPort,
						ServerIP:   rlog.ServerIP,
						ServerPort: rlog.ServerPort,
						Protocol:   rlog.IPProto,
					}
					if thrt.SessIngress {
						f.Direction = "ingress"
					} else {
						f.Direction = "egress"
					}
					var param interface{} = &f
					cctx.StartStopFedPingPollFunc(share.PostToIBMSA, 0, param)
				}
			}
		}
	}
}

func incidentLogUpdate(nType cluster.ClusterNotifyType, key string, value []byte, modifyIdx uint64) {
	log.WithFields(log.Fields{"type": cluster.ClusterNotifyName[nType], "key": key}).Debug("")

	if checkModifyIdx(syncCatgIncidentIdx, modifyIdx) == false {
		return
	}
	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		uzb := utils.GunzipBytes(value)
		if uzb == nil {
			log.Error("Failed to unzip data")
			return
		}

		var incds []share.CLUSIncidentLog
		err := json.Unmarshal(uzb, &incds)
		if err != nil || len(incds) == 0 {
			log.WithFields(log.Fields{
				"error": err, "uzb": uzb, "value": value,
			}).Error("Cannot decode incident")
			return
		}

		syncLock(syncCatgIncidentIdx)
		defer syncUnlock(syncCatgIncidentIdx)
		defer setModifyIdx(syncCatgIncidentIdx, modifyIdx)

		log.WithFields(log.Fields{"incidents": len(incds)}).Debug("incident log")
		for _, incd := range incds {
			var id string
			var port uint16
			if incd.LocalIP != nil && incd.RemoteIP != nil {
				var lc *logConnect
				if incd.ConnIngress {
					lc = &logConnect{
						hostID:    incd.HostID,
						localPeer: incd.LocalPeer,
						ingress:   incd.ConnIngress,
						ipproto:   incd.IPProto,
						srcIP:     incd.RemoteIP,
						dstIP:     incd.LocalIP,
						srcPort:   incd.RemotePort,
						dstPort:   incd.LocalPort,
					}
				} else {
					lc = &logConnect{
						hostID:    incd.HostID,
						localPeer: incd.LocalPeer,
						ingress:   incd.ConnIngress,
						ipproto:   incd.IPProto,
						srcIP:     incd.LocalIP,
						dstIP:     incd.RemoteIP,
						srcPort:   incd.LocalPort,
						dstPort:   incd.RemotePort,
					}
				}

				id, port = preProcessLogConnect(lc)
			}

			if rlog := incidentLog2API(&incd, id, port); rlog != nil {
				desc := eventDesc{id: incd.WorkloadID, event: share.EventIncident,
					name: rlog.Name, level: rlog.Level, proc: rlog.ProcName, arg: rlog}
				responseRuleLookup(&desc)

				if isLeader() && incd.LogUID != "" {
					// even when rlog.Count > 1, we only send one occurrence to IBM SA
					f := api.IBMSAFinding{
						ID:         incd.LogUID,
						Name:       rlog.Name,
						Level:      rlog.Level,
						EventType:  desc.event,
						At:         incd.StartAt,
						ClientIP:   rlog.ClientIP,
						ClientPort: rlog.ClientPort,
						ServerIP:   rlog.ServerIP,
						ServerPort: rlog.ServerPort,
						Protocol:   rlog.IPProto,
					}
					if incd.LocalIP == nil || incd.RemoteIP == nil {
						f.ProtoName = "N/A"
					} else {
						if rlog.ConnIngress {
							f.Direction = "ingress"
						} else {
							f.Direction = "egress"
						}
					}
					var param interface{} = &f
					cctx.StartStopFedPingPollFunc(share.PostToIBMSA, 0, param)
				}

				if isLeader() && scanCfg.AutoScan {
					if incd.ID == share.CLUSIncidHostPackageUpdated {
						cacher.ScanHost(incd.HostID, access.NewReaderAccessControl())
					} else if incd.ID == share.CLUSIncidContainerPackageUpdated {
						cacher.ScanWorkload(incd.WorkloadID, access.NewReaderAccessControl())
					}
				}
			}
		}
	}
}

func auditLogUpdate(nType cluster.ClusterNotifyType, key string, value []byte, modifyIdx uint64) {
	log.WithFields(log.Fields{"type": cluster.ClusterNotifyName[nType], "key": key}).Debug("")

	if checkModifyIdx(syncCatgAuditIdx, modifyIdx) == false {
		return
	}
	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		uzb := utils.GunzipBytes(value)
		if uzb == nil {
			log.Error("Failed to unzip data")
			return
		}

		var audits []share.CLUSAuditLog
		err := json.Unmarshal(uzb, &audits)
		if err != nil || len(audits) == 0 {
			log.WithFields(log.Fields{
				"error": err, "uzb": uzb, "value": value,
			}).Error("Cannot decode audit")
			return
		}

		syncLock(syncCatgAuditIdx)
		defer syncUnlock(syncCatgAuditIdx)
		defer setModifyIdx(syncCatgAuditIdx, modifyIdx)

		for _, audit := range audits {
			if rlog := auditLog2API(&audit); rlog != nil {
				switch audit.ID {
				case share.CLUSAuditAdmCtrlK8sReqAllowed, share.CLUSAuditAdmCtrlK8sReqViolation, share.CLUSAuditAdmCtrlK8sReqDenied:
					admCtrlUpdate(share.EventAdmCtrl, rlog)
				case share.CLUSAuditAwsLambdaScanWarning, share.CLUSAuditAwsLambdaScanNormal:
					serverlessUpdate(share.EventServerless, rlog)
				default:
					benchUpdate(share.EventCompliance, rlog)
				}
			}
		}
	}
}

func benchUpdate(event string, clog *api.Audit) {
	if clog = filterComplianceLog(clog); clog == nil {
		return
	}

	desc := eventDesc{event: event,
		name: clog.Name, level: clog.Level,
		items: clog.Items, arg: clog,
	}

	switch clog.Name {
	case api.EventNameComplianceContainerBenchViolation, api.EventNameComplianceContainerCustomCheckViolation, api.EventNameComplianceContainerFileBenchViolation:
		desc.id = clog.WorkloadID
	case api.EventNameComplianceImageBenchViolation:
		desc.id = clog.ImageID
		desc.noQuar = true
	case api.EventNameComplianceHostBenchViolation, api.EventNameComplianceHostCustomCheckViolation:
		desc.id = clog.HostID
		desc.noQuar = true
	default:
		return
	}
	responseRuleLookup(&desc)
}

func serverlessUpdate(event string, clog *api.Audit) {
	desc := eventDesc{event: event, name: clog.Name, level: clog.Level,
		id: clog.WorkloadID, items: clog.Items, arg: clog}
	desc.noQuar = true
	responseRuleLookup(&desc)
}

func admCtrlUpdate(event string, clog *api.Audit) {
	desc := eventDesc{event: event, name: clog.Name, level: clog.Level, items: clog.Items, arg: clog}
	desc.noQuar = true
	responseRuleLookup(&desc)
}

func auditUpdate(id, event string, objType share.ScanObjectType, clog *api.Audit, vuls utils.Set, fixedCriticalsInfo []scanUtils.FixedVulInfo, fixedHighsInfo []scanUtils.FixedVulInfo) {
	desc := eventDesc{id: id, event: event,
		name: clog.Name, level: clog.Level, vuls: vuls,
		cve_critical: clog.CriticalCnt, cve_high: clog.HighCnt, cve_med: clog.MediumCnt, cve_critical_fixed_info: fixedCriticalsInfo, cve_high_fixed_info: fixedHighsInfo,
		items: clog.Items, arg: clog}
	if objType != share.ScanObjectType_CONTAINER {
		desc.noQuar = true
	}
	responseRuleLookup(&desc)
}

// Check from local container. Return if client is local, and ID if local container can be found.
func logConnectFromLocal(lc *logConnect) (bool, string) {
	local, wl, _ := getWorkloadFromIPOnHost(lc.srcIP, lc.hostID)
	return local, wl
}

// Check from global IP. We already know the IP is of Global scope. Return container ID.
func logConnectFromGlobal(lc *logConnect) string {
	wl, _ := getWorkloadFromGlobalIP(lc.srcIP)
	return wl
}

// Given hostID and mapped port on the host, locate the container on the host.
func logConnectToManagedHost(lc *logConnect, hostID string) (string, uint16) {
	wl, wlPort, _ := getWorkloadFromHostIDIPPort(hostID, lc.ipproto, lc.dstPort)
	return wl, wlPort
}

// Handle to host IP connection. We know the IP is on the host subnet (NAT scope).
func logConnectToHost(lc *logConnect) (string, uint16) {
	if remote := getHostIDFromHostIP(lc.dstIP); remote != "" {
		return logConnectToManagedHost(lc, remote)
	} else {
		// Unmanaged host
		return "", 0
	}
}

// Check to local container. Return if server is local, and ID if local container can be found.
func logConnectToLocal(lc *logConnect) (bool, string) {
	// This function also checks if container is on the host's local subnets (172.x.x.x).
	local, wl, _ := getWorkloadFromIPOnHost(lc.dstIP, lc.hostID)
	return local, wl
}

// Check to global IP. We already know the IP is of Global scope.
func logConnectToGlobal(lc *logConnect) string {
	wl, _ := getWorkloadFromGlobalIP(lc.dstIP)
	return wl
}

func preProcessLogConnect(lc *logConnect) (string, uint16) {
	var id string
	wlPort := lc.dstPort

	// LocalPeer: IP is a host local IP
	if lc.ingress {
		if lc.localPeer {
			// We cannot tell if an ingress connection is from a host process, or from a
			// local container, source IP in both case are docker0's IP
			id = lc.srcIP.String()
		} else if isHostTunnelIP(lc.srcIP) {
			id = specialEPName(api.LearnedWorkloadPrefix, api.EndpointIngress)
		} else if local, wl := logConnectFromLocal(lc); local {
			if wl == "" {
				id = lc.srcIP.String()
			} else {
				id = wl
			}
		} else {
			switch getIPAddrScope(lc.srcIP) {
			case "":
				// Not on internal subnets - external
				id = api.LearnedExternal
			case share.CLUSIPAddrScopeNAT:
				// Source is on the host subnet (NAT scope)
				id = lc.srcIP.String()
			case share.CLUSIPAddrScopeGlobal:
				if wl := logConnectFromGlobal(lc); wl == "" {
					id = lc.srcIP.String()
				} else {
					id = wl
				}
			default:
				id = lc.srcIP.String()
			}
		}
	} else {
		// egress
		if lc.localPeer {
			if wl, port := logConnectToManagedHost(lc, lc.hostID); wl == "" {
				id = lc.dstIP.String()
			} else {
				id = wl
				wlPort = port
			}
		} else {
			if svcgrp := getSvcAddrGroupName(lc.dstIP, lc.dstPort); svcgrp != "" {
				id = svcgrp
			} else if local, wl := logConnectToLocal(lc); local {
				if wl == "" {
					id = lc.dstIP.String()
				} else {
					id = wl
				}
			} else {
				switch getIPAddrScope(lc.dstIP) {
				case "":
					// Not on internal subnets - external
					id = api.LearnedExternal
				case share.CLUSIPAddrScopeNAT:
					// Dest is on the host subnet (NAT scope)
					if wl, port := logConnectToHost(lc); wl == "" {
						id = lc.dstIP.String()
					} else {
						id = wl
						wlPort = port
					}
				case share.CLUSIPAddrScopeGlobal:
					if wl := logConnectToGlobal(lc); wl == "" {
						id = lc.dstIP.String()
					} else {
						id = wl
					}
				default:
					id = lc.dstIP.String()
				}
			}
		}
	}

	return id, wlPort
}

func syncActivityTx() *syncDataMsg {
	msg := syncDataMsg{CatgName: syncCatgActivity}

	// Use event sync lock for both event and activity
	syncLock(syncCatgEventIdx)
	if curActivityIndex > 0 {
		acts := activityCache[0:curActivityIndex]
		msg.Data, _ = json.Marshal(acts)
	}
	msg.ModifyIdx = getModifyIdx(syncCatgEventIdx)
	syncUnlock(syncCatgEventIdx)
	return &msg
}

func syncEventTx() *syncDataMsg {
	msg := syncDataMsg{CatgName: syncCatgEvent}

	syncLock(syncCatgEventIdx)
	if curEventIndex > 0 {
		events := eventCache[0:curEventIndex]
		msg.Data, _ = json.Marshal(events)
	}
	msg.ModifyIdx = getModifyIdx(syncCatgEventIdx)
	syncUnlock(syncCatgEventIdx)
	return &msg
}

func syncThreatTx() *syncDataMsg {
	msg := syncDataMsg{CatgName: syncCatgThreat}
	syncLock(syncCatgThreatIdx)
	if curThrtIndex > 0 {
		threats := thrtCache[0:curThrtIndex]
		msg.Data, _ = json.Marshal(threats)
	}
	msg.ModifyIdx = getModifyIdx(syncCatgThreatIdx)
	syncUnlock(syncCatgThreatIdx)
	return &msg
}

func syncIncidentTx() *syncDataMsg {
	msg := syncDataMsg{CatgName: syncCatgIncident}
	syncLock(syncCatgIncidentIdx)
	if curIncidentIndex > 0 {
		incidents := incidentCache[0:curIncidentIndex]
		msg.Data, _ = json.Marshal(incidents)
	}
	msg.ModifyIdx = getModifyIdx(syncCatgIncidentIdx)
	syncUnlock(syncCatgIncidentIdx)
	return &msg
}

func syncAuditTx() *syncDataMsg {
	msg := syncDataMsg{CatgName: syncCatgAudit}
	syncLock(syncCatgAuditIdx)
	if curAuditIndex > 0 {
		audits := auditCache[0:curAuditIndex]
		msg.Data, _ = json.Marshal(audits)
	}
	msg.ModifyIdx = getModifyIdx(syncCatgAuditIdx)
	syncUnlock(syncCatgAuditIdx)
	return &msg
}

func syncActivityRx(msg *syncDataMsg) int {
	// Use event sync lock for both event and activity
	syncLock(syncCatgEventIdx)
	if validateModifyIdx(syncCatgEventIdx, msg.ModifyIdx) == false {
		syncUnlock(syncCatgEventIdx)
		// Introduce a delay before retry
		time.Sleep(time.Second)
		return syncRxErrorRetry
	}

	if msg.Data != nil {
		var acts []*api.Event
		if err := json.Unmarshal(msg.Data, &acts); err != nil {
			log.WithFields(log.Fields{"size": len(msg.Data)}).Error("unmarshal error")
			syncUnlock(syncCatgEventIdx)
			return syncRxErrorFailed
		} else {
			curActivityIndex = len(acts)
			for i, act := range acts {
				act.Level = api.UpgradeLogLevel(act.Level)
				activityCache[i] = act
			}
		}
	} else {
		curActivityIndex = 0
	}
	setModifyIdx(syncCatgEventIdx, msg.ModifyIdx)
	syncUnlock(syncCatgEventIdx)
	return syncRxErrorNone
}

func syncEventRx(msg *syncDataMsg) int {
	syncLock(syncCatgEventIdx)
	if validateModifyIdx(syncCatgEventIdx, msg.ModifyIdx) == false {
		syncUnlock(syncCatgEventIdx)
		// Introduce a delay before retry
		time.Sleep(time.Second)
		return syncRxErrorRetry
	}

	if msg.Data != nil {
		var events []*api.Event
		if err := json.Unmarshal(msg.Data, &events); err != nil {
			log.WithFields(log.Fields{"size": len(msg.Data)}).Error("unmarshal error")
			syncUnlock(syncCatgEventIdx)
			return syncRxErrorFailed
		} else {
			curEventIndex = len(events)
			for i, evt := range events {
				evt.Level = api.UpgradeLogLevel(evt.Level)
				eventCache[i] = evt
			}
		}
	} else {
		curEventIndex = 0
	}
	setModifyIdx(syncCatgEventIdx, msg.ModifyIdx)
	syncUnlock(syncCatgEventIdx)
	return syncRxErrorNone
}

func syncThreatRx(msg *syncDataMsg) int {
	syncLock(syncCatgThreatIdx)
	if validateModifyIdx(syncCatgThreatIdx, msg.ModifyIdx) == false {
		syncUnlock(syncCatgThreatIdx)
		// Introduce a delay before retry
		time.Sleep(time.Second)
		return syncRxErrorRetry
	}

	if msg.Data != nil {
		var threats []*api.Threat
		if err := json.Unmarshal(msg.Data, &threats); err != nil {
			log.WithFields(log.Fields{"size": len(msg.Data)}).Error("unmarshal error")
			syncUnlock(syncCatgThreatIdx)
			return syncRxErrorFailed
		} else {
			curThrtIndex = len(threats)
			thrtMap = make(map[string]*api.Threat)
			for i, thrt := range threats {
				thrt.Level = api.UpgradeLogLevel(thrt.Level)
				thrtMap[thrt.ID] = thrt
				thrtCache[i] = thrt
			}
		}
	} else {
		curThrtIndex = 0
	}
	setModifyIdx(syncCatgThreatIdx, msg.ModifyIdx)
	syncUnlock(syncCatgThreatIdx)
	return syncRxErrorNone
}

func syncIncidentRx(msg *syncDataMsg) int {
	syncLock(syncCatgIncidentIdx)
	if validateModifyIdx(syncCatgIncidentIdx, msg.ModifyIdx) == false {
		syncUnlock(syncCatgIncidentIdx)
		// Introduce a delay before retry
		time.Sleep(time.Second)
		return syncRxErrorRetry
	}

	if msg.Data != nil {
		var incidents []*api.Incident
		if err := json.Unmarshal(msg.Data, &incidents); err != nil {
			log.WithFields(log.Fields{"size": len(msg.Data)}).Error("unmarshal error")
			syncUnlock(syncCatgIncidentIdx)
			return syncRxErrorFailed
		} else {
			curIncidentIndex = len(incidents)
			for i, incd := range incidents {
				incd.Level = api.UpgradeLogLevel(incd.Level)
				incidentCache[i] = incd
			}
		}
	} else {
		curIncidentIndex = 0
	}
	setModifyIdx(syncCatgIncidentIdx, msg.ModifyIdx)
	syncUnlock(syncCatgIncidentIdx)
	return syncRxErrorNone
}

func syncAuditRx(msg *syncDataMsg) int {
	syncLock(syncCatgAuditIdx)
	if !validateModifyIdx(syncCatgAuditIdx, msg.ModifyIdx) {
		syncUnlock(syncCatgAuditIdx)
		// Introduce a delay before retry
		time.Sleep(time.Second)
		return syncRxErrorRetry
	}

	if msg.Data != nil {
		var audits []*api.Audit
		if err := json.Unmarshal(msg.Data, &audits); err != nil {
			log.WithFields(log.Fields{"size": len(msg.Data)}).Error("unmarshal error")
			syncUnlock(syncCatgAuditIdx)
			return syncRxErrorFailed
		} else {
			num := 0
			for _, audit := range audits {
				if audit == nil {
					continue
				}
				audit.Level = api.UpgradeLogLevel(audit.Level)
				auditSuppressSetIdRpts(audit)
				auditCache[num] = audit
				num++
			}
			curAuditIndex = num
		}
	} else {
		curAuditIndex = 0
	}
	setModifyIdx(syncCatgAuditIdx, msg.ModifyIdx)
	syncUnlock(syncCatgAuditIdx)
	return syncRxErrorNone
}

func eventLog2API(ev *share.CLUSEventLog) *api.Event {
	var rlog api.Event
	var info common.LogEventInfo
	var ok bool

	if info, ok = common.LogEventMap[ev.Event]; !ok {
		log.WithFields(log.Fields{"ev": ev}).Error("Cannot parse event")
		return nil
	}

	// It's possible that workload exists when ev is generated, but it's gone
	// when ev is handled here.
	wln := getWorkloadNameForLogging(ev.WorkloadID)

	rlog.Name = info.Name
	rlog.Category = info.Category
	rlog.Level = info.Level
	rlog.ClusterName = systemConfigCache.ClusterName
	rlog.HostID = ev.HostID
	if ev.HostName == "" {
		rlog.HostName = getHostName(ev.HostName)
	} else {
		rlog.HostName = ev.HostName
	}
	rlog.AgentID = ev.AgentID
	rlog.AgentName = getAgentName(ev.AgentID)
	if rlog.AgentName == "" {
		rlog.AgentName = ev.AgentName
	}
	rlog.ControllerID = ev.ControllerID
	rlog.ControllerName = getControllerName(ev.ControllerID)
	if rlog.ControllerName == "" {
		rlog.ControllerName = ev.ControllerName
	}
	rlog.WorkloadID = ev.WorkloadID
	rlog.WorkloadName = wln.name
	rlog.WorkloadDomain = wln.domain
	rlog.WorkloadImage = wln.image
	rlog.WorkloadService = wln.service
	rlog.User = ev.User
	rlog.UserRoles = ev.UserRoles
	rlog.UserAddr = ev.UserAddr
	rlog.UserSession = ev.UserSession
	rlog.RESTMethod = ev.RESTMethod
	rlog.RESTRequest = ev.RESTRequest
	rlog.RESTBody = ev.RESTBody
	if !ev.LicenseExpire.IsZero() {
		rlog.LicenseExpire = ev.LicenseExpire.Format("2006-01-02")
	}
	rlog.EnforcerLimit = ev.EnforcerLimit
	if ev.Msg != "" {
		rlog.Msg = ev.Msg
	} else {
		rlog.Msg = info.Name
	}
	rlog.ReportedAt = api.RESTTimeString(ev.ReportedAt)
	rlog.ReportedTimeStamp = ev.ReportedAt.Unix()

	return &rlog
}

func threatLog2API(thrt *share.CLUSThreatLog, id string, port uint16) *api.Threat {
	var rlog api.Threat

	wln := getWorkloadNameForLogging(thrt.WorkloadID)
	rwln := getWorkloadNameForLogging(id)

	rlog.ID = thrt.ID
	if isDlpThreatID(thrt.ThreatID) {
		rname, sname, grpname := getDlpThreatNameSensorGroup(thrt.ThreatID)
		rlog.Name = rname
		rlog.Sensor = sname
		if grpname != nil {
			rlog.Group = getWorkloadDlpGrp(thrt.WorkloadID, grpname)
		}
	} else if isWafThreatID(thrt.ThreatID) {
		rname, sname, grpname := getWafThreatNameSensorGroup(thrt.ThreatID)
		rlog.Name = rname
		rlog.Sensor = sname
		if grpname != nil {
			rlog.Group = getWorkloadDlpGrp(thrt.WorkloadID, grpname)
		}
	} else {
		rlog.Name = common.ThreatName(thrt.ThreatID)
	}
	rlog.ThreatID = thrt.ThreatID
	rlog.Count = thrt.Count
	rlog.ClusterName = systemConfigCache.ClusterName
	rlog.HostID = thrt.HostID
	rlog.HostName = thrt.HostName
	rlog.AgentID = thrt.AgentID
	rlog.AgentName = getAgentName(thrt.AgentID)
	if rlog.AgentName == "" {
		rlog.AgentName = thrt.AgentName
	}
	if thrt.SessIngress {
		rlog.ClientWL = id
		rlog.ClientWLName = rwln.name
		rlog.ClientWLDomain = rwln.domain
		rlog.ClientWLImage = rwln.image
		rlog.ClientWLService = rwln.service
		rlog.ServerWL = thrt.WorkloadID
		rlog.ServerWLName = wln.name
		rlog.ServerWLDomain = wln.domain
		rlog.ServerWLImage = wln.image
		rlog.ServerWLService = wln.service
	} else {
		rlog.ClientWL = thrt.WorkloadID
		rlog.ClientWLName = wln.name
		rlog.ClientWLDomain = wln.domain
		rlog.ClientWLImage = wln.image
		rlog.ClientWLService = wln.service
		rlog.ServerWL = id
		rlog.ServerWLName = rwln.name
		rlog.ServerWLDomain = rwln.domain
		rlog.ServerWLImage = rwln.image
		rlog.ServerWLService = rwln.service
	}
	rlog.EtherType = thrt.EtherType
	rlog.IPProto = thrt.IPProto

	var srcIP, dstIP string
	switch thrt.EtherType {
	case syscall.ETH_P_IP:
		if thrt.SrcIP != nil {
			srcIP = thrt.SrcIP.To4().String()
		}
		if thrt.DstIP != nil {
			dstIP = thrt.DstIP.To4().String()
		}
	case syscall.ETH_P_IPV6:
		if thrt.SrcIP != nil {
			srcIP = thrt.SrcIP.To16().String()
		}
		if thrt.DstIP != nil {
			dstIP = thrt.DstIP.To16().String()
		}
	default:
		if thrt.SrcIP != nil {
			srcIP = thrt.SrcIP.String()
		}
		if thrt.DstIP != nil {
			dstIP = thrt.DstIP.String()
		}
	}
	if thrt.PktIngress == thrt.SessIngress {
		// detection and session are of the same direction
		rlog.Target = api.TargetServer
		rlog.ClientIP = srcIP
		rlog.ClientPort = thrt.SrcPort
		rlog.ServerIP = dstIP
		if thrt.SessIngress {
			rlog.ServerPort = thrt.DstPort
			rlog.ServerConnPort = thrt.DstPort
		} else {
			rlog.ServerPort = port
			rlog.ServerConnPort = thrt.DstPort
		}
	} else {
		rlog.Target = api.TargetClient
		rlog.ClientIP = dstIP
		rlog.ClientPort = thrt.DstPort
		rlog.ServerIP = srcIP
		if thrt.SessIngress {
			rlog.ServerPort = thrt.SrcPort
			rlog.ServerConnPort = thrt.SrcPort
		} else {
			rlog.ServerPort = port
			rlog.ServerConnPort = thrt.SrcPort
		}
	}
	rlog.ICMPType = thrt.ICMPType
	rlog.ICMPCode = thrt.ICMPCode
	rlog.Application = common.AppNameMap[thrt.Application]
	rlog.Monitor = thrt.Tap
	if thrt.Msg != "" {
		rlog.Msg = thrt.Msg
	} else {
		rlog.Msg = rlog.Name
	}
	rlog.Packet = thrt.Packet
	rlog.CapLen = thrt.CapLen

	rlog.Severity, rlog.Level = common.SeverityString(thrt.Severity)
	if thrt.Tap {
		rlog.Action = api.ThreatActionMonitor
	} else {
		switch thrt.Action {
		case C.DPI_ACTION_ALLOW, C.DPI_ACTION_BYPASS:
			if isDlpThreatID(thrt.ThreatID) {
				rlog.Action = api.ThreatActionMonitor
			} else if isWafThreatID(thrt.ThreatID) {
				rlog.Action = api.ThreatActionMonitor
			} else {
				rlog.Action = api.ThreatActionAllow
			}
		case C.DPI_ACTION_RESET:
			rlog.Action = api.ThreatActionReset
		case C.DPI_ACTION_DROP, C.DPI_ACTION_BLOCK:
			rlog.Action = api.ThreatActionBlock
		}
	}

	rlog.ReportedAt = api.RESTTimeString(thrt.ReportedAt)
	rlog.ReportedTimeStamp = thrt.ReportedAt.Unix()

	return &rlog
}

func incidentLog2API(incd *share.CLUSIncidentLog, id string, port uint16) *api.Incident {
	var rlog api.Incident
	var info common.LogIncidentInfo
	var ok bool

	if info, ok = common.LogIncidentMap[incd.ID]; !ok {
		log.WithFields(log.Fields{"incd": incd}).Error("Cannot parse event")
		return nil
	}

	wln := getWorkloadNameForLogging(incd.WorkloadID)
	rwln := getWorkloadNameForLogging(id)

	rlog.ID = incd.LogUID
	rlog.Name = info.Name
	rlog.Level = info.Level
	rlog.ClusterName = systemConfigCache.ClusterName
	rlog.HostID = incd.HostID
	rlog.HostName = incd.HostName
	rlog.AgentID = incd.AgentID
	rlog.AgentName = getAgentName(incd.AgentID)
	if rlog.AgentName == "" {
		rlog.AgentName = incd.AgentName
	}
	rlog.WorkloadID = incd.WorkloadID
	rlog.WorkloadName = wln.name
	rlog.WorkloadDomain = wln.domain
	rlog.WorkloadImage = wln.image
	rlog.WorkloadService = wln.service
	rlog.RemoteWL = id
	rlog.RemoteWLName = rwln.name
	rlog.RemoteWLDomain = rwln.domain
	rlog.RemoteWLImage = rwln.image
	rlog.RemoteWLService = rwln.service
	rlog.ProcName = incd.ProcName
	rlog.ProcPath = incd.ProcPath
	rlog.ProcCmd = utils.JoinCommand(incd.ProcCmds)
	rlog.ProcRealUID = incd.ProcRealUID
	rlog.ProcEffUID = incd.ProcEffUID
	rlog.ProcRealUser = incd.ProcRealUser
	rlog.ProcEffUser = incd.ProcEffUser
	rlog.FilePath = incd.FilePath
	rlog.Files = incd.Files
	rlog.EtherType = incd.EtherType
	rlog.IPProto = incd.IPProto
	rlog.ConnIngress = incd.ConnIngress
	rlog.ProcPName = incd.ProcPName
	rlog.ProcPPath = incd.ProcPPath
	rlog.Action = incd.Action
	rlog.Group = incd.Group
	rlog.Count = incd.Count
	rlog.AggregationFrom = incd.StartAt.Unix()
	rlog.RuleID = incd.RuleID

	if rlog.Action == share.PolicyActionDeny {
		rlog.Level = api.LogLevelCRIT
	}

	if incd.LocalIP != nil && incd.RemoteIP != nil {
		var localIP, remoteIP string
		switch incd.EtherType {
		case syscall.ETH_P_IP:
			localIP = incd.LocalIP.To4().String()
			remoteIP = incd.RemoteIP.To4().String()
		case syscall.ETH_P_IPV6:
			localIP = incd.LocalIP.To16().String()
			remoteIP = incd.RemoteIP.To16().String()
		default:
			localIP = incd.LocalIP.String()
			remoteIP = incd.RemoteIP.String()
		}
		if rlog.ConnIngress {
			rlog.ClientIP = remoteIP
			rlog.ServerIP = localIP
			rlog.ClientPort = incd.RemotePort
			rlog.ServerPort = incd.LocalPort
			rlog.ServerConnPort = incd.LocalPort
		} else {
			rlog.ClientIP = localIP
			rlog.ServerIP = remoteIP
			rlog.ClientPort = incd.LocalPort
			rlog.ServerPort = port
			rlog.ServerConnPort = incd.RemotePort
		}
	}

	if incd.Msg != "" {
		rlog.Msg = incd.Msg
	} else {
		rlog.Msg = info.Name
	}
	rlog.ReportedAt = api.RESTTimeString(incd.ReportedAt)
	rlog.ReportedTimeStamp = incd.ReportedAt.Unix()

	return &rlog
}

func auditLog2API(audit *share.CLUSAuditLog) *api.Audit {
	var rlog api.Audit
	var info common.LogAuditInfo
	var ok bool

	if info, ok = common.LogAuditMap[audit.ID]; !ok {
		log.WithFields(log.Fields{"audit": audit}).Error("Cannot parse event")
		return nil
	}

	rlog.Name = info.Name
	rlog.Level = info.Level
	rlog.ClusterName = systemConfigCache.ClusterName
	if audit.ID >= share.CLUSAuditAdmCtrlK8sReqAllowed && audit.ID <= share.CLUSAuditAdmCtrlK8sReqDenied {
		rlog.Count = audit.Count
		for k, v := range audit.Props {
			switch k {
			case nvsysadmission.AuditLogPropMessage:
				rlog.Message = v
			case nvsysadmission.AuditLogPropUser:
				rlog.User = v
			case nvsysadmission.AuditLogPropImage:
				rlog.WorkloadImage = v
			case nvsysadmission.AuditLogPropNamespace:
				rlog.WorkloadDomain = v
			case nvsysadmission.AuditLogPropImageID:
				rlog.ImageID = v
			case nvsysadmission.AuditLogPropRegistry:
				rlog.Registry = v
			case nvsysadmission.AuditLogPropRepository:
				rlog.Repository = v
			case nvsysadmission.AuditLogPropTag:
				rlog.Tag = v
			case nvsysadmission.AuditLogPropBaseOS:
				rlog.BaseOS = v
			case nvsysadmission.AuditLogPropFirstLogAt:
				if t, err := time.Parse(api.RESTTimeFomat, v); err == nil {
					rlog.AggregationFrom = t.Unix()
				}
			case nvsysadmission.AuditLogPropCriticalVulsCnt:
				rlog.CriticalCnt, _ = strconv.Atoi(v)
			case nvsysadmission.AuditLogPropHighVulsCnt:
				rlog.HighCnt, _ = strconv.Atoi(v)
			case nvsysadmission.AuditLogPropMedVulsCnt:
				rlog.MediumCnt, _ = strconv.Atoi(v)
			case nvsysadmission.AuditLogPropPVCName:
				rlog.PVCName = v
			case nvsysadmission.AuditLogPVCStorageClassName:
				rlog.PVCStorageClassName = v
			}
		}
	} else if audit.ID >= share.CLUSAuditAwsLambdaScanWarning && audit.ID <= share.CLUSAuditAwsLambdaScanNormal {
		// HostID --- CVEDBVERSION   --  rlog.CVEDBVersion
		// AgentID -- PermitLevel --   rlog.Level
		// WorkLoadName -- functionName:version -- rlog.name
		// WordLoadID   -- functionArn -- rlog.WorkloadID
		rlog.ProjectName = audit.ProjectName
		rlog.Region = audit.Region
		rlog.WorkloadName = audit.WorkloadName
		rlog.WorkloadID = audit.WorkloadID

		for k, v := range audit.Props {
			if v == share.VulnSeverityCritical {
				rlog.CriticalCnt++
				rlog.CriticalVuls = append(rlog.CriticalVuls, k)
			} else if v == share.VulnSeverityHigh {
				rlog.HighCnt++
				rlog.HighVuls = append(rlog.HighVuls, k)
			} else if v == share.VulnSeverityMedium {
				rlog.MediumCnt++
				rlog.MediumVuls = append(rlog.MediumVuls, k)
			}
		}
		rlog.CVEDBVersion = audit.HostID
		rlog.Name = api.EventNameAwsLambdaScan
		if audit.ID == share.CLUSAuditAwsLambdaScanWarning {
			rlog.Level = api.LogLevelWARNING
		} else {
			rlog.Level = api.LogLevelINFO
		}
		for _, v := range audit.Items {
			rlog.Items = append(rlog.Items, v.Msg)
		}
	} else {
		rlog.Items = make([]string, len(audit.Items))
		wln := getWorkloadNameForLogging(audit.WorkloadID)

		rlog.HostID = audit.HostID
		rlog.HostName = audit.HostName
		rlog.AgentID = audit.AgentID
		rlog.AgentName = getAgentName(audit.AgentID)
		if rlog.AgentName == "" {
			rlog.AgentName = audit.AgentName
		}
		rlog.WorkloadID = audit.WorkloadID
		rlog.WorkloadName = wln.name
		rlog.WorkloadDomain = wln.domain
		rlog.WorkloadImage = wln.image
		rlog.WorkloadService = wln.service

		for i, itm := range audit.Items {
			var item string
			if itm.Group != "" {
				// Used in custom check. The response rule name criteria is having group/check_name format
				item = fmt.Sprintf("%s/%s %s - %s", itm.Group, itm.TestNum, itm.Level, itm.Msg)
			} else {
				item = fmt.Sprintf("%s %s - %s", itm.TestNum, itm.Level, itm.Msg)
			}
			rlog.Items[i] = item
			if itm.Level == "HIGH" {
				rlog.Level = api.LogLevelCRIT
			}
		}
	}
	rlog.ReportedAt = api.RESTTimeString(audit.ReportedAt)
	rlog.ReportedTimeStamp = audit.ReportedAt.Unix()

	return &rlog
}

func scanReport2BenchLog(id string, objType share.ScanObjectType, report *share.CLUSScanReport, regName string) *api.Audit {
	clog := api.Audit{
		LogCommon: api.LogCommon{
			ReportedAt:        api.RESTTimeString(report.ScannedAt),
			ReportedTimeStamp: report.ScannedAt.Unix(),
			ClusterName:       systemConfigCache.ClusterName,
		},
		BaseOS: report.Namespace,
	}

	if objType == share.ScanObjectType_IMAGE {
		clog.Name = api.EventNameComplianceImageBenchViolation
		clog.Level = api.LogLevelWARNING
		clog.ImageID = id
		clog.Registry = report.Registry
		clog.RegistryName = regName
		clog.Repository = report.Repository
		clog.Tag = report.Tag
	}

	_, metaMap := scanUtils.GetImageBenchMeta()
	runAsRoot, hasADD, hasHEALTHCHECK := scanUtils.ParseImageCmds(report.Cmds)

	clog.Items = make([]string, 0)
	if runAsRoot {
		testNum := "I.4.1"
		if c, ok := metaMap[testNum]; ok {
			item := fmt.Sprintf("%s %s - %s", testNum, share.BenchLevelWarn, c.Description)
			clog.Items = append(clog.Items, item)
		}
	}
	if hasADD {
		testNum := "I.4.9"
		if c, ok := metaMap[testNum]; ok {
			item := fmt.Sprintf("%s %s - %s", testNum, share.BenchLevelWarn, c.Description)
			clog.Items = append(clog.Items, item)
		}
	}
	if !hasHEALTHCHECK {
		testNum := "I.4.6"
		if c, ok := metaMap[testNum]; ok {
			item := fmt.Sprintf("%s %s - %s", testNum, share.BenchLevelWarn, c.Description)
			clog.Items = append(clog.Items, item)
		}
	}
	if report.Secrets != nil && len(report.Secrets.Logs) > 0 {
		testNum := "I.4.10"
		for _, s := range report.Secrets.Logs {
			item := fmt.Sprintf("%s %s - File %s contains %s", testNum, share.BenchLevelWarn, s.File, s.Type)
			clog.Items = append(clog.Items, item)
		}
	}
	if len(report.SetIdPerms) > 0 {
		testNum := "I.4.8"
		for _, s := range report.SetIdPerms {
			item := fmt.Sprintf("%s %s - File %s has %s mode", testNum, share.BenchLevelWarn, s.File, s.Type)
			clog.Items = append(clog.Items, item)
		}
	}

	return &clog
}

func scanReport2ScanLog(id string, objType share.ScanObjectType, report *share.CLUSScanReport, criticals, highs, meds []string, layerCriticals, layerHighs, layerMeds map[string][]string, regName string) *api.Audit {
	clog := api.Audit{
		LogCommon: api.LogCommon{
			ReportedAt:        api.RESTTimeString(report.ScannedAt),
			ReportedTimeStamp: report.ScannedAt.Unix(),
			ClusterName:       systemConfigCache.ClusterName,
		},
		BaseOS:          report.Namespace,
		CVEDBVersion:    report.Version,
		CriticalVuls:    make([]string, 0),
		HighVuls:        make([]string, 0),
		MediumVuls:      make([]string, 0),
		Platform:        report.Platform,
		PlatformVersion: report.PlatformVersion,
	}

	if objType == share.ScanObjectType_CONTAINER {
		clog.Name = api.EventNameContainerScanReport
		clog.WorkloadID = id

		wln := getWorkloadNameForLogging(id)
		clog.WorkloadName = wln.name
		clog.WorkloadDomain = wln.domain
		clog.WorkloadImage = wln.image
		clog.WorkloadService = wln.service
		if c := getWorkloadCache(id); c != nil {
			clog.Image = c.workload.Image
			clog.ImageID = c.workload.ImageID
			clog.HostName = c.workload.HostName
			clog.HostID = c.workload.HostID
			clog.AgentID = c.workload.AgentID
			clog.AgentName = getAgentName(c.workload.AgentID)
		}
	} else if objType == share.ScanObjectType_HOST {
		clog.Name = api.EventNameHostScanReport
		clog.HostID = id
		if c := getHostCache(id); c != nil {
			clog.HostName = c.host.Name
			agents := c.agents.ToStringSlice()
			if len(agents) > 0 {
				clog.AgentID = agents[0]
				clog.AgentName = getAgentName(agents[0])
			}
		}
	} else if objType == share.ScanObjectType_IMAGE {
		clog.Name = api.EventNameRegistryScanReport
		clog.ImageID = id
		clog.Registry = report.Registry
		clog.RegistryName = regName
		clog.Repository = report.Repository
		clog.Tag = report.Tag
	} else if objType == share.ScanObjectType_PLATFORM {
		clog.Name = api.EventNamePlatformScanReport
	}

	clog.CriticalVuls = criticals
	clog.HighVuls = highs
	clog.MediumVuls = meds
	clog.CriticalCnt = len(criticals)
	clog.HighCnt = len(highs)
	clog.MediumCnt = len(meds)
	if systemConfigCache.SingleCVEPerSyslog {
		// if only reporting one cve per event, we will add the vulnerabile info.
		// the vul. list will not be included in the log
		for _, v := range report.Vuls {
			scanUtils.FillVul(v)
		}
		clog.Vuls = make(map[string]*share.ScanVulnerability)
		for _, v := range report.Vuls {
			clog.Vuls[v.Name] = v
		}
	}
	if systemConfigCache.SyslogCVEInLayers {
		clog.Layers = make([]api.Audit, len(report.Layers))
		for i, l := range report.Layers {
			var lc api.Audit
			lc.ImageLayerDigest = l.Digest
			lc.Cmds = l.Cmds
			if h, ok := layerCriticals[l.Digest]; ok {
				lc.CriticalVuls = h
				lc.CriticalCnt = len(h)
			}
			if h, ok := layerHighs[l.Digest]; ok {
				lc.HighVuls = h
				lc.HighCnt = len(h)
			}
			if m, ok := layerMeds[l.Digest]; ok {
				lc.MediumVuls = m
				lc.MediumCnt = len(m)
			}
			if systemConfigCache.SingleCVEPerSyslog {
				for _, v := range lc.Vuls {
					scanUtils.FillVul(v)
				}
				lc.Vuls = make(map[string]*share.ScanVulnerability)
				for _, v := range lc.Vuls {
					lc.Vuls[v.Name] = v
				}
			}
			clog.Layers[i] = lc
		}
	}

	// mask not support error
	if report.Error == share.ScanErrorCode_ScanErrNotSupport {
		clog.Level = api.LogLevelINFO
	} else if report.Error != share.ScanErrorCode_ScanErrNone {
		clog.Level = api.LogLevelERR
		clog.Error = scanUtils.ScanErrorToStr(report.Error)
	} else if clog.HighCnt > 0 || clog.CriticalCnt > 0 {
		clog.Level = api.LogLevelCRIT
	} else if clog.MediumCnt > 0 {
		clog.Level = api.LogLevelWARNING
	} else {
		clog.Level = api.LogLevelINFO
	}

	return &clog
}

func admCtrlLog2API(ev *share.CLUSEventLog) *api.Event {
	var rlog api.Event
	var info common.LogEventInfo
	var ok bool

	if info, ok = common.LogEventMap[ev.Event]; !ok {
		log.WithFields(log.Fields{"ev": ev}).Error("Cannot parse admission control event")
		return nil
	}

	rlog.Name = info.Name
	rlog.Category = info.Category
	rlog.Level = info.Level
	rlog.ClusterName = systemConfigCache.ClusterName
	rlog.ReportedAt = api.RESTTimeString(ev.ReportedAt)
	rlog.ReportedTimeStamp = ev.ReportedAt.Unix()
	rlog.User = ev.User
	rlog.Msg = ev.Msg

	return &rlog
}

func auditSuppressSetIdRpts(rlog *api.Audit) {
	matchDTag := false
	tag := "I"
	switch rlog.Name {
	default:
		return
	case api.EventNameComplianceContainerFileBenchViolation: // bench check
		// for example: "nv.mtop/D.4.8 WARN - ...... has setuid mode"
		matchDTag = true
		tag = "D"
	case api.EventNameRegistryScanReport: // registry
	case api.EventNameComplianceImageBenchViolation: // bench violation
	case api.EventNameAwsLambdaScan: // serverless
		// for example: "I.4.8 WARN - ...... has setuid mode"
	}

	setgidCnt := 0
	setuidCnt := 0
	items := make([]string, 0)
	for _, item := range rlog.Items {
		// Checking 'total' to prevent re-aggregating in sync case
		if (strings.HasPrefix(item, "I.4.8") || (matchDTag && strings.Contains(item, "D.4.8 WARN - "))) &&
			!strings.Contains(item, "Total") {
			if strings.HasSuffix(item, "setgid mode") {
				setgidCnt++
			} else if strings.HasSuffix(item, "setuid mode") {
				setuidCnt++
			}
		} else {
			items = append(items, item)
		}
	}

	// Add 'Total' to distinguish aggregated entries from unaggregated ones
	if setgidCnt > 0 {
		m := "s have"
		if setgidCnt == 1 {
			m = " has"
		}
		items = append(items, fmt.Sprintf("%s.4.8 WARN - Total %d file%s setgid mode", tag, setgidCnt, m))
	}

	if setuidCnt > 0 {
		m := "s have"
		if setgidCnt == 1 {
			m = " has"
		}
		items = append(items, fmt.Sprintf("%s.4.8 WARN - Total %d file%s setuid mode", tag, setuidCnt, m))
	}

	rlog.Items = items
}

func checkDefAdminPwd(throttleMinutes uint) {
	acc := access.NewReaderAccessControl()
	if u, _, _ := clusHelper.GetUserRev(common.DefaultAdminUser, acc); u != nil {
		if hash := utils.HashPassword(common.DefaultAdminPass); hash == u.PasswordHash {
			var evtsTime share.CLUSThrottledEvents
			id := share.CLUSEvAuthDefAdminPwdUnchanged
			key := share.CLUSThrottledEventStore + "events"
			value, rev, _ := cluster.GetRev(key)
			if value != nil {
				json.Unmarshal(value, &evtsTime)
			}
			if evtsTime.LastReportTime == nil {
				evtsTime.LastReportTime = make(map[share.TLogEvent]int64)
			}
			update := true
			now := time.Now().UTC()
			if lastTimestamp, ok := evtsTime.LastReportTime[id]; ok {
				lastTime := time.Unix(lastTimestamp, 0).UTC()
				if diff := now.Sub(lastTime); diff.Minutes() < float64(throttleMinutes) {
					update = false
				}
			}
			if update {
				CacheEvent(id, "Default admin user's default password is not changed yet.")
				evtsTime.LastReportTime[id] = now.Unix()
				value, _ := json.Marshal(&evtsTime)
				if rev == 0 {
					cluster.Put(key, value)
				} else {
					cluster.PutRev(key, value, rev)
				}
			}
		}
	}
}

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/cache"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/rest"
	"github.com/neuvector/neuvector/controller/scan"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/utils"
)

var ClusterConnected bool = false

var selfRejoin bool = false
var clusterFailed bool = false
var leadFailTime time.Time

const recoveryThreshold = time.Duration(time.Second * 6)
const clusterCheckInterval time.Duration = time.Second * 2
const clusterCheckRetryMax = 150

func recordLeadChangeEvent(ev share.TLogEvent, newLead, oldLead string) {
	var msg string

	switch ev {
	case share.CLUSEvControllerLeadLost:
		msg = fmt.Sprintf("Controller lead lost. Old Lead: %s", oldLead)
	case share.CLUSEvControllerLeadElect:
		if oldLead == "" {
			// initial lead
			msg = fmt.Sprintf("New controller lead elected. New Lead: %s", newLead)
		} else {
			// lost lead then re-elected
			msg = fmt.Sprintf("New controller lead elected. New Lead: %s; Old Lead: %s", newLead, oldLead)
		}
	default:
		return
	}

	clog := share.CLUSEventLog{
		Event:          ev,
		ControllerID:   Ctrler.ID,
		ControllerName: Ctrler.Name,
		ReportedAt:     time.Now().UTC(),
		Msg:            msg,
	}
	evqueue.Append(&clog)
}

func setConfigLoaded() {
	log.Info("Set config loaded flag.")
	clusHelper := kv.GetClusterHelper()
	for {
		if err := clusHelper.SetCtrlState(share.CLUSCtrlConfigLoadedKey); err == nil {
			break
		} else {
			time.Sleep(time.Second)
		}
	}
}

func waitConfigLoaded(isNewCluster bool) {
	log.Info("Wait config loaded flag ...")
	clusHelper := kv.GetClusterHelper()
	for {
		if ok := clusHelper.GetCtrlState(share.CLUSCtrlConfigLoadedKey); ok {
			log.Info("Got config loaded flag.")
			break
		} else if !isNewCluster {
			// In case that we upgrade from the version has no config-loaded flag, ignore the check.
			log.Info("Skip checking config loaded flag.")
			break
		} else {
			time.Sleep(time.Second)
		}
	}
}

func leadChangeHandler(newLead, oldLead string) {
	var isNewLead bool
	if newLead != "" {
		isNewLead = (newLead == Ctrler.ClusterIP)
	}
	log.WithFields(log.Fields{"isNewLead": isNewLead, "newLead": newLead, "oldLead": oldLead, "exiting": exitingFlag}).Info()

	if atomic.LoadInt32(&exitingFlag) != 0 {
		return
	}

	Ctrler.Leader = isNewLead
	if newLead == "" {
		leadFailTime = time.Now()
		clusterFailed = true
		cluster.PauseAllWatchers(true)

		cache.LeadChangeNotify(false, "")
		cache.ScannerChangeNotify(false)
		scan.LeadChangeNotify(false)
		scan.ScannerChangeNotify(false)
		orchConnector.LeadChangeNotify(false)
		rest.LeadChangeNotify(false)

		// It is possible that the lead is gone, so everyone has to report lead lost event.
		recordLeadChangeEvent(share.CLUSEvControllerLeadLost, "", oldLead)
	} else {
		// update self ctrl key
		connStatus, connLastError := GetOrchConnStatus()

		value, _ := json.Marshal(share.CLUSController{
			CLUSDevice:        Ctrler.CLUSDevice,
			Leader:            Ctrler.Leader,
			OrchConnStatus:    connStatus,
			OrchConnLastError: connLastError,
			ReadPrimeConfig:   Ctrler.ReadPrimeConfig,
		})
		key := share.CLUSControllerKey(Host.ID, Ctrler.ID)
		if err := cluster.Put(key, value); err != nil {
			log.WithFields(log.Fields{"error": err}).Error()
		}

		if Ctrler.Leader {
			emptyKvFound := false
			if ver := kv.GetControlVersion(); ver.CtrlVersion == "" && ver.KVVersion == "" {
				emptyKvFound = true
				log.WithFields(log.Fields{"emptyKvFound": emptyKvFound}).Info()
			}

			if emptyKvFound {
				if _, _, restored, restoredKvVersion, err := kv.GetConfigHelper().Restore(); restored && err == nil {
					clog := share.CLUSEventLog{
						Event:          share.CLUSEvKvRestored,
						HostID:         Host.ID,
						HostName:       Host.Name,
						ControllerID:   Ctrler.ID,
						ControllerName: Ctrler.Name,
						ReportedAt:     time.Now().UTC(),
						Msg:            fmt.Sprintf("Restored kv version: %s", restoredKvVersion),
					}
					evqueue.Append(&clog)
				}
				kv.ValidateWebhookCert()
				setConfigLoaded()
			} else {
				// This is used when upgrade from version that has no config-loaded flag
				setConfigLoaded()
				rest.HandleAdminUserUpdate()

				// Only the lead backup config to the disk. When self becomes lead, run a full backup.
				kv.GetConfigHelper().BackupAll()
			}
		}

		cache.LeadChangeNotify(Ctrler.Leader, newLead)
		cache.ScannerChangeNotify(Ctrler.Leader)
		scan.LeadChangeNotify(Ctrler.Leader)
		scan.ScannerChangeNotify(Ctrler.Leader)
		orchConnector.LeadChangeNotify(Ctrler.Leader)
		rest.LeadChangeNotify(Ctrler.Leader)

		if clusterFailed {
			// We will need to sync data from the oldest controller, not simply from the lead.
			if time.Since(leadFailTime) > recoveryThreshold {
				// Fail recovery is costy to do. Assume short lost of connection is due
				// to network instability and skip recovery for now. Will need
				// a lightweight method to check if recovery is needed later
				cache.CtrlFailRecovery()
			}
			leadFailTime = time.Time{}
			cluster.ResumeAllWatchers()
		}
		clusterFailed = false

		if Ctrler.Leader {
			recordLeadChangeEvent(share.CLUSEvControllerLeadElect, newLead, oldLead)
			//for rolling upgrade case, especially with mixed version controller,
			//old still use 16bit loose factor for mask while new use 8bit loose
			//factor, here we push internal subnet to enforcer after lead change
			cache.PutInternalIPNetToCluseterUpgrade()
			//make sure xff_enabled=true or DisableNetPolicy=true or DetectUnmanagedWl=true is updated in enforcer
			kv.EnforceNetSysConfig()
		}
	}
}

func ctlrMemberUpdateHandler(nType cluster.ClusterNotifyType, memberAddr string, member string) {
	log.WithFields(log.Fields{
		"type": cluster.ClusterNotifyName[nType], "member": memberAddr,
	}).Info()

	if nType == cluster.ClusterNotifyAdd {
		if !ClusterConnected {
			ClusterConnected = true
		}

		if selfRejoin && Ctrler.ClusterIP == memberAddr {
			log.Info("Rejoin")

			time.Sleep(time.Second)
			selfRejoin = false

			ctlrPutLocalInfo()
			logController(share.CLUSEvControllerJoin)
		}
	} else if nType == cluster.ClusterNotifyDelete {
		if Ctrler.ClusterIP == memberAddr {
			log.Info("Left")

			ClusterConnected = false
			selfRejoin = true
		} else {
			cache.ClusterMemberStateUpdateHandler(nType, member, "")
		}
	}
}

func clusterStart(clusterCfg *cluster.ClusterConfig) (string, string, error) {
	if err := cluster.FillClusterAddrs(clusterCfg, global.SYS); err != nil {
		return "", "", err
	}

	lead, err := cluster.StartCluster(clusterCfg)
	if err != nil {
		log.WithFields(log.Fields{
			"error": err, "waited": clusterCheckInterval * clusterCheckRetryMax,
		}).Error("Cluster failed")
		os.Exit(-1)
	}

	ClusterConnected = true
	return cluster.GetSelfAddress(), lead, nil
}

func logController(ev share.TLogEvent) {
	clog := share.CLUSEventLog{
		Event:          ev,
		HostID:         Host.ID,
		HostName:       Host.Name,
		ControllerID:   Ctrler.ID,
		ControllerName: Ctrler.Name,
	}
	switch ev {
	case share.CLUSEvControllerStart:
		clog.ReportedAt = ctrlEnv.startsAt
	default:
		clog.ReportedAt = time.Now().UTC()
	}

	evqueue.Append(&clog)
}

var snapshotIndex int

func memorySnapshot(usage uint64) {
	if ctrlEnv.autoProfieCapture > 0 {
		log.WithFields(log.Fields{"usage": usage}).Debug()
		if usage > ctrlEnv.peakMemoryUsage {
			ctrlEnv.peakMemoryUsage = usage + ctrlEnv.snapshotMemStep // level up

			label := "p" // peak

			if snapshotIndex < 4 { // keep atmost 4 copies + an extra peak copy
				snapshotIndex++
				label = strconv.Itoa(snapshotIndex)
			}
			log.WithFields(log.Fields{"label": label, "next": ctrlEnv.peakMemoryUsage}).Debug()
			utils.PerfSnapshot(1, ctrlEnv.memoryLimit, ctrlEnv.autoProfieCapture, usage, share.SnaphotFolder, Ctrler.ID, "ctl.", label)
		}
	}
}

var curMemoryPressure uint64

func memoryPressureNotification(rpt *system.MemoryPressureReport) {
	log.WithFields(log.Fields{"rpt": rpt}).Info()
	if rpt.Level >= 2 { // cap its maximum
		rpt.Level = 2
		memorySnapshot(rpt.Stats.WorkingSet)
	}

	if rpt.Level == curMemoryPressure {
		return // skip report
	}

	// launch falling-edge watcher, there is not actual level=0 event
	if curMemoryPressure == 0 {
		go func() {
			var err error
			var mStats *system.CgroupMemoryStats

			acc := 0
			for acc < 7 {
				time.Sleep(time.Minute * 1)
				if mStats, err = global.SYS.GetContainerMemoryStats(); err != nil {
					log.WithFields(log.Fields{"error": err}).Error("mem stat")
					continue
				}

				limit := mStats.Usage.Limit
				if mStats.Usage.Limit == 0 { // it's hitting node's limit
					limit = uint64(Host.Memory)
				}

				ratio := uint64(rpt.Stats.WorkingSet * 100 / limit)
				// log.WithFields(log.Fields{"ratio": ratio, "acc": acc, "limit": limit}).Debug()
				if ratio <= 50 { // what is the reasonable threshold?
					acc++
				} else {
					acc = 0
				}
			}

			rptt := &system.MemoryPressureReport{
				Level: 0, // assumption
				Stats: *mStats,
			}

			putMemoryPressureEvent(rptt, false)
			curMemoryPressure = 0 // reset
		}()
	}

	curMemoryPressure = rpt.Level

	//
	putMemoryPressureEvent(rpt, true)
}

func putMemoryPressureEvent(rpt *system.MemoryPressureReport, setRisingEdge bool) {
	var description string
	if rpt.Stats.Usage.Limit == 0 {
		// it's hitting node's limit
		ratio := uint64(rpt.Stats.WorkingSet * 100 / uint64(Host.Memory))
		if setRisingEdge {
			description = fmt.Sprintf("Memory usage[%s] is more than %d %% of the node memory[%s]", utils.DisplayBytes(int64(rpt.Stats.WorkingSet)), ratio, utils.DisplayBytes(int64(Host.Memory)))
		} else {
			description = fmt.Sprintf("Memory usage[%s] is normal, %d %% of the node memory[%s]", utils.DisplayBytes(int64(rpt.Stats.WorkingSet)), ratio, utils.DisplayBytes(int64(Host.Memory)))
		}
	} else {
		ratio := uint64(rpt.Stats.WorkingSet * 100 / rpt.Stats.Usage.Limit)
		if setRisingEdge {
			description = fmt.Sprintf("Memory usage[%s] is more than %d %% of the container memory limit[%s]", utils.DisplayBytes(int64(rpt.Stats.WorkingSet)), ratio, utils.DisplayBytes(int64(rpt.Stats.Usage.Limit)))
		} else {
			description = fmt.Sprintf("Memory usage[%s] is normal, %d %% of the container memory limit[%s]", utils.DisplayBytes(int64(rpt.Stats.WorkingSet)), ratio, utils.DisplayBytes(int64(rpt.Stats.Usage.Limit)))
		}
	}

	report := map[string]interface{}{
		"Description":  description,
		"Level":        rpt.Level,
		"UsageLimit":   rpt.Stats.Usage.Limit,
		"NetUsage":     rpt.Stats.WorkingSet,
		"MaxUsage":     rpt.Stats.Usage.MaxUsage,
		"ActiveAnon":   rpt.Stats.Stats["active_anon"],
		"InactiveAnon": rpt.Stats.Stats["inactive_anon"],
		"Cache":        rpt.Stats.Stats["cache"],
		"PageFaults":   rpt.Stats.Stats["pgfault"],
		"RSS":          rpt.Stats.Stats["rss"],
		"Failcnt":      rpt.Stats.Usage.Failcnt,
	}

	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(report)
	msg := b.String()

	// log.WithFields(log.Fields{"msg": msg}).Debug()

	clog := share.CLUSEventLog{
		Event:          share.CLUSEvMemoryPressureController,
		ControllerID:   Ctrler.ID,
		ControllerName: Ctrler.Name,
		ReportedAt:     time.Now().UTC(),
		Msg:            msg,
	}
	evqueue.Append(&clog)
}

func ctlrPutLocalInfo() {
	log.Debug("")

	Ctrler.JoinedAt = time.Now().UTC()
	var value []byte
	var key string

	// Don't report host for controller
	/*
		value, _ = json.Marshal(Host)
		key = share.CLUSHostKey(Host.ID, "controller")
		if err := cluster.Put(key, value); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("")
		}
	*/
	connStatus, connLastError := GetOrchConnStatus()

	value, _ = json.Marshal(share.CLUSController{
		CLUSDevice:        Ctrler.CLUSDevice,
		Leader:            Ctrler.Leader,
		OrchConnStatus:    connStatus,
		OrchConnLastError: connLastError,
		ReadPrimeConfig:   Ctrler.ReadPrimeConfig,
	})
	key = share.CLUSControllerKey(Host.ID, Ctrler.ID)
	if err := cluster.Put(key, value); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
	}
}

func ctrlDeleteLocalInfo() {
	log.Debug("")

	var key string

	key = share.CLUSControllerKey(Host.ID, Ctrler.ID)
	if err := cluster.Delete(key); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
	}
	key = share.CLUSUniconfControllerKey(Ctrler.ID, Ctrler.ID)
	if err := cluster.Delete(key); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
	}

	clusHelper := kv.GetClusterHelper()
	clusHelper.DeleteScanner(Ctrler.ID)
}

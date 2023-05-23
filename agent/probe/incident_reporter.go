package probe

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/fsmon"
	"github.com/neuvector/neuvector/share/utils"
)

//////////////////////
type probeMsgAggregate struct {
	// state machine
	triggerCnt int
	expireCnt  int
	count      int
	eventKey   string // optional: reference
	startTime  time.Time

	// data section
	bFsMonMsg bool // default (false): probe msg
	pid       int  // not for fsmon
	msg       *ProbeMessage
	fsMsg     *fsmon.MonitorMessage
}

// design: 5 seoneds per tick
// prevent from aligning current timer, +1
const triggerCountdown = 12 + 1 // 1 minute : triggered in 60-65 sec
const expireCountdown = 4 + 1   // 5 seconds: triggered in 20-25 sec

func genUniqEventKey(msgtype, pid int, id string) string {
	keyString := fmt.Sprintf("%d:%d:%s:%v", msgtype, pid, id, time.Now())
	// log.WithFields(log.Fields{"keyString": keyString}).Debug("PROC:")
	b := md5.Sum([]byte(keyString))
	return hex.EncodeToString(b[:])
}

func genEscalReportKey(msgtype int, pmsg *ProbeEscalation) string {
	keyString := fmt.Sprintf("%d:%d:%d:%s:%s:%s", msgtype, pmsg.RUid, pmsg.EUid, pmsg.RealUser, pmsg.EffUser, pmsg.ID)
	b := md5.Sum([]byte(keyString))
	return string(b[:])
}

func genProcessReportKey(msgtype int, pmsg *ProbeProcess) string {
	keyString := fmt.Sprintf("%d:%s:%s:%v:%s", msgtype, pmsg.Name, pmsg.Path, pmsg.Cmds, pmsg.ID)
	// log.WithFields(log.Fields{"keyString": keyString}).Debug("PROC:")
	b := md5.Sum([]byte(keyString))
	return hex.EncodeToString(b[:])
}

func genFsMonReportKey(msgtype int, pmsg *fsmon.MonitorMessage) (string, string) {
	keyString := fmt.Sprintf("%d:%s:%s:%s", msgtype, pmsg.ID, pmsg.Path, pmsg.Msg)
	// log.WithFields(log.Fields{"keyString": keyString}).Debug("PROC:")
	b := md5.Sum([]byte(keyString))
	return hex.EncodeToString(b[:]), genUniqEventKey(msgtype, pmsg.ProcPid, pmsg.ID)
}

func generateReportKey(pmsg *ProbeMessage) (int, string, string) {
	switch pmsg.Type {
	case PROBE_REPORT_ESCALATION:
		return pmsg.Escalation.Pid, genEscalReportKey(pmsg.Type, pmsg.Escalation), genUniqEventKey(pmsg.Type, pmsg.Escalation.Pid, pmsg.Escalation.ID)
	case PROBE_REPORT_SUSPICIOUS:
		return pmsg.Process.Pid, genProcessReportKey(pmsg.Type, pmsg.Process), genUniqEventKey(pmsg.Type, pmsg.Process.Pid, pmsg.Process.ID)
	case PROBE_REPORT_TUNNEL:
		return pmsg.Process.Pid, genProcessReportKey(pmsg.Type, pmsg.Process), genUniqEventKey(pmsg.Type, pmsg.Process.Pid, pmsg.Process.ID)
	case PROBE_REPORT_FILE_MODIFIED: // obsolated ?
		return pmsg.Process.Pid, genProcessReportKey(pmsg.Type, pmsg.Process), genUniqEventKey(pmsg.Type, pmsg.Process.Pid, pmsg.Process.ID)
	case PROBE_REPORT_PROCESS_VIOLATION:
		return pmsg.Process.Pid, genProcessReportKey(pmsg.Type, pmsg.Process), genUniqEventKey(pmsg.Type, pmsg.Process.Pid, pmsg.Process.ID)
	case PROBE_REPORT_PROCESS_DENIED:
		return pmsg.Process.Pid, genProcessReportKey(pmsg.Type, pmsg.Process), genUniqEventKey(pmsg.Type, pmsg.Process.Pid, pmsg.Process.ID)
	}

	log.WithFields(log.Fields{"msg": pmsg}).Error("PROC: unknown report type")
	return 0, "", "" // should not be here
}

func (p *Probe) patchProcessHistoryForDeniedReport(alert *ProbeProcess) {
	/// put it into process history
	proc := &procInternal{
		name:      alert.Name,
		pname:     alert.PName,
		pid:       alert.Pid,
		path:      alert.Path,
		ppath:     alert.PPath,
		startTime: time.Now(),
		action:    share.PolicyActionDeny,
	}

	// best effort, no comdline is found
	proc.cmds = append(proc.cmds, proc.pname)
	proc.cmds = append(proc.cmds, proc.path)

	go p.addProcHistory(alert.ID, proc, false)
}

func (p *Probe) SendAggregateProbeReport(pmsg *ProbeMessage, bExtOp bool) bool {

	pid, key, uniqeKey := generateReportKey(pmsg)
	pmsg.StartAt = time.Now().UTC()

	// localized mutex to reduce the interactions with others
	p.msgAggregatesMux.Lock()
	defer p.msgAggregatesMux.Unlock()

	if pmsga, ok := p.pMsgAggregates[key]; ok {
		if pmsga.pid == pid {
			log.WithFields(log.Fields{"key": pmsga.eventKey, "msg": pmsg}).Debug("PROC: duplicated")
			return false
		}

		pmsga.pid = pid
		pmsga.expireCnt = expireCountdown
		pmsga.count++
		//log.WithFields(log.Fields{"report_a": pmsga, "msg": pmsg}).Debug("PROC: accumulated")
		return false // hold the event for further events
	}

	/// new message store into hostory and send it immediately
	pNewMsgA := &probeMsgAggregate{
		triggerCnt: triggerCountdown,
		expireCnt:  expireCountdown,
		count:      1,
		pid:        pid,
		eventKey:   uniqeKey,
		startTime:  time.Now().UTC(),
		msg:        pmsg,
	}

	p.pMsgAggregates[key] = pNewMsgA
	// log.WithFields(log.Fields{"key": pNewMsgA.eventKey}).Debug("PROC: new entry")
	if pmsg.Type == PROBE_REPORT_ESCALATION {
		log.WithFields(log.Fields{"escalation": pmsg.Escalation}).Debug("PROC:")
	} else {
		log.WithFields(log.Fields{"process": pmsg.Process}).Debug("PROC:")
	}

	go p.sendProbeReport(*pmsg, 1, pNewMsgA.startTime)

	////
	if bExtOp && pmsg.Type == PROBE_REPORT_PROCESS_DENIED {
		p.patchProcessHistoryForDeniedReport(pmsg.Process)
	}
	return true // send immediately
}

/////
// dpkg[ubuntu, debian], yum[centos,fedora] , dnf[centos, coreos,fedora], rpm[redhat], apk[busybox], zypper[bci]
var pkgCmds utils.Set = utils.NewSet("dpkg", "yum", "dnf", "rpm", "apk", "zypper")

const (
	fsPackageUpdate = "Software packages were updated."
	fsComboAction   = "Files were modified or deleted."
)

/////
func (p *Probe) SendAggregateFsMonReport(pmsg *fsmon.MonitorMessage) bool {
	key, uniqeKey := genFsMonReportKey(PROBE_REPORT_FILE_MODIFIED, pmsg) // borrow

	// localized mutex to reduce the interactions with others
	p.msgAggregatesMux.Lock()
	defer p.msgAggregatesMux.Unlock()

	if pmsga, ok := p.pMsgAggregates[key]; ok {
		pmsga.expireCnt = expireCountdown

		if pmsg.ProcPid != 0 && pmsga.pid == 0 {
			pmsg.ProcPid = pmsg.ProcPid
			pmsga.fsMsg = pmsg // updated
		} else {
			pmsga.count++
			pmsga.fsMsg.Path = pmsg.Path // restored
		}
		mLog.WithFields(log.Fields{"report_a": pmsga, "msg": pmsga.fsMsg, "pmsg": pmsg}).Debug("PROC: accumulated")
		return false // hold the event for further events
	}

	// aggregare reports with the same Pid but could be different operations
	// searching the installation event with the same container ID
	bHasPackageInstalled := false
	for key, pmsga := range p.pMsgAggregates {
		if pmsga.bFsMonMsg {
			if pmsga.fsMsg.ID != pmsg.ID { // excludes other containers
				continue
			}

			// make a predition
			bPackageOpInProgress := pkgCmds.Contains(pmsga.fsMsg.ProcName)
			bPackageOp := pkgCmds.Contains(pmsg.ProcName)
			if !bHasPackageInstalled {
				bHasPackageInstalled = bPackageOpInProgress
			}

			if pmsga.pid == 0 && pmsga.fsMsg.Package && bPackageOp {
				// An inotify event at first:
				// (1) Periodically scanning for package installation (Package=true)
				// (2) Unreliable timing: the report could be either at the start or the end
				// (3) Looking any non-expired installation event by processes (bPackageOpInProgress)
				if !strings.Contains(pmsga.fsMsg.Path, pmsg.Path) {
					pmsg.Path = fmt.Sprintf("%s, %s", pmsga.fsMsg.Path, pmsg.Path)
				}
				pmsga.pid = pmsg.ProcPid
				pmsga.fsMsg = nil
				pmsga.fsMsg = pmsg // replaced
				pmsga.fsMsg.Package = true
				// log.WithFields(log.Fields{"Path": pmsga.fsMsg.Path}).Debug("PROC: update")
				p.pMsgAggregates[key] = pmsga
				return false
			} else {
				if pmsga.pid == pmsg.ProcPid && pmsg.ProcPid != 0 { // same process
					if pmsga.fsMsg.Msg != fsComboAction && pmsga.fsMsg.Msg != pmsg.Msg {
						pmsga.fsMsg.Msg = fsComboAction
					}

					// reset counters
					if bPackageOpInProgress {
						// wait longer
						pmsga.triggerCnt = triggerCountdown + 7
						pmsga.expireCnt = expireCountdown + 7
					} else {
						pmsga.count += 1
						pmsga.triggerCnt = triggerCountdown
						pmsga.expireCnt = expireCountdown
					}

					// update Package Installation status
					if pmsg.Package {
						pmsga.fsMsg.Package = true
					}

					if pmsga.fsMsg.Path == "" {
						// previous report has sent
						pmsga.fsMsg.Path = pmsg.Path
					} else if !strings.Contains(pmsga.fsMsg.Path, pmsg.Path) {
						pmsga.fsMsg.Path = fmt.Sprintf("%s, %s", pmsga.fsMsg.Path, pmsg.Path)
					}

					///
					p.pMsgAggregates[key] = pmsga
					mLog.WithFields(log.Fields{"Path": pmsga.fsMsg.Path}).Debug("PROC: add")
					return false
				} else {
					// not the same Pid, but possible in the same operation
					if bPackageOpInProgress && (bPackageOp || pmsg.Package) {
						if pmsg.Package {
							pmsga.fsMsg.Package = true
						}

						if !strings.Contains(pmsga.fsMsg.Path, pmsg.Path) {
							pmsga.fsMsg.Path = fmt.Sprintf("%s, %s", pmsga.fsMsg.Path, pmsg.Path)
						}
						// log.WithFields(log.Fields{"Path": pmsga.fsMsg.Path}).Debug("PROC: append")
						p.pMsgAggregates[key] = pmsga
						return false
					}
				}
			}
		}
	}

	/// new message store into hostory and send it immediately
	pNewMsgA := &probeMsgAggregate{
		triggerCnt: triggerCountdown,
		expireCnt:  expireCountdown,
		count:      1,
		pid:        pmsg.ProcPid, // pid: could be zero, not reliable
		eventKey:   uniqeKey,
		startTime:  time.Now().UTC(),
		bFsMonMsg:  true,
		fsMsg:      pmsg,
	}

	log.WithFields(log.Fields{"key": pNewMsgA.eventKey, "msg": pmsg}).Debug("PROC: new entry")
	if pNewMsgA.pid != 0 && !pkgCmds.Contains(pNewMsgA.fsMsg.ProcName) {
		go p.sendFsMonReport(*pmsg, 1, pNewMsgA.startTime)
		// Reset: erase the path to accumulate other files
		pNewMsgA.fsMsg.Path = ""
	}
	p.pMsgAggregates[key] = pNewMsgA
	return true // send immediately
}

/// aggregate worker
func (p *Probe) processAggregateProbeReports() int {
	var cnt int

	// localized mutex to reduce the interactions with others
	p.msgAggregatesMux.Lock()
	defer p.msgAggregatesMux.Unlock()

	for key, pmsga := range p.pMsgAggregates {
		pmsga.triggerCnt--
		pmsga.expireCnt--
		if pmsga.expireCnt == 0 {
			if pmsga.count > 1 {
				go p.sendReport(*pmsga)
				cnt++
			} else if pmsga.bFsMonMsg && pmsga.count > 1 {	// no more adding entry
				go p.sendReport(*pmsga)
				cnt++
			}

			// delete the entry
			mLog.WithFields(log.Fields{"key": pmsga.eventKey, "trigger": pmsga.triggerCnt, "expire": pmsga.expireCnt, "count": pmsga.count}).Debug("PROC: delete entry")
			delete(p.pMsgAggregates, key)
			continue
		}

		if pmsga.triggerCnt == 0 {
			if pmsga.count <= 1 {
				// should not be here, it should meet the expireCnt before this
				mLog.WithFields(log.Fields{"key": pmsga.eventKey, "trigger": pmsga.triggerCnt, "expire": pmsga.expireCnt, "count": pmsga.count}).Debug("PROC: TODO, meet trigger")
			} else {
				go p.sendReport(*pmsga)
				if pmsga.bFsMonMsg {
					// log.WithFields(log.Fields{"pmsga": pmsga, "msg": pmsga.fsMsg}).Debug()
					pmsga.fsMsg.Path = ""
				}

				// send report again and reset the counter
				pmsga.startTime = time.Now() // reset
				pmsga.triggerCnt = triggerCountdown
				pmsga.expireCnt = expireCountdown // optional: remove it for a shorter live detetion time
				pmsga.count = 1
				cnt++
				p.pMsgAggregates[key] = pmsga
			}
		}
	}
	return cnt // reference only
}

func (p *Probe) sendProbeReport(pmsg ProbeMessage, count int, start time.Time) {
	pmsg.Count = count
	pmsg.StartAt = start
	p.notifyTaskChan <- &pmsg
	log.WithFields(log.Fields{"report": pmsg}).Debug("PROC:")
}

func (p *Probe) sendFsMonReport(fsMsg fsmon.MonitorMessage, count int, start time.Time) {
	fsMsg.Count = count
	fsMsg.StartAt = start

	// update package msg
	if fsMsg.Package {
		fsMsg.Msg = fsPackageUpdate
	}

	p.notifyFsTaskChan <- &fsMsg
	log.WithFields(log.Fields{"report": fsMsg}).Debug("PROC:")
}

func (p *Probe) sendReport(pmsga probeMsgAggregate) {
	if pmsga.bFsMonMsg {
		p.sendFsMonReport(*pmsga.fsMsg, pmsga.count-1, pmsga.startTime)
	} else {
		p.sendProbeReport(*pmsga.msg, pmsga.count-1, pmsga.startTime)
	}
}

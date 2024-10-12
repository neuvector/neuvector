package probe

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/fsmon"
	"github.com/neuvector/neuvector/share/utils"
)

// ////////////////////
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

// ///
// dpkg[ubuntu, debian], yum[centos,fedora] , dnf[centos, coreos,fedora], rpm[redhat], apk[busybox], zypper[bci]
var pkgCmds utils.Set = utils.NewSet("dpkg", "yum", "dnf", "rpm", "apk", "zypper")

const (
	fsPackageUpdate      = "Software packages were updated."
	fsComboAction        = "Files were modified or deleted."
	fsNvProtectAlert     = "NV.Protect: Files were modified."
	fsNvProtectProcAlert = "NV.Protect: Process alert"
)

// ///
func (p *Probe) SendAggregateFsMonReport(pmsg *fsmon.MonitorMessage) bool {
	if pmsg.Msg == fsNvProtectProcAlert {
		p.sendFsmonNVProtectProbeReport(pmsg)
		return false
	}

	key1, uniqeKey := genFsMonReportKey(PROBE_REPORT_FILE_MODIFIED, pmsg) // borrow
	pmsg.Package = pmsg.Package || pkgCmds.Contains(pmsg.ProcName) || pkgCmds.Contains(filepath.Base(pmsg.ProcPath))
	mLog.WithFields(log.Fields{"pmsg": pmsg, "key1": key1}).Debug()

	// localized mutex to reduce the interactions with others
	p.msgAggregatesMux.Lock()
	defer p.msgAggregatesMux.Unlock()
	bUpdated := false
	if pmsga, ok := p.pMsgAggregates[key1]; ok {
		pmsga.expireCnt = expireCountdown // extend expiration
		if pmsg.ProcPid > 0 {             // fanotify
			if pmsga.pid == 0 { // inotify before
				pmsga.expireCnt = 2 // quick response: update the process information
				pmsga.pid = pmsg.ProcPid
				pmsga.fsMsg = pmsg // updated
				bUpdated = true
				mLog.WithFields(log.Fields{"fsMsg": pmsga.fsMsg, "pid": pmsga.pid}).Debug("updated")
			}
		} else {
			mLog.WithFields(log.Fields{"pmsg": pmsg}).Debug("ignored")
			return false
		}
	}

	for key, pmsga := range p.pMsgAggregates {
		if !pmsga.bFsMonMsg || pmsga.fsMsg.ID != pmsg.ID { // excludes other containers
			continue
		}

		// package installation in progress
		if pmsga.fsMsg.Package || pmsg.Package {
			pmsga.fsMsg.Package = pmsga.fsMsg.Package || pmsg.Package

			// aggregare file package operations
			if pmsga.fsMsg.Path == "" {
				// previous report has sent
				pmsga.fsMsg.Path = pmsg.Path
			} else if !strings.Contains(pmsga.fsMsg.Path, pmsg.Path) {
				pmsga.fsMsg.Path = fmt.Sprintf("%s, %s", pmsga.fsMsg.Path, pmsg.Path)
			}

			// reset counters: wait longer
			pmsga.expireCnt = expireCountdown + 7
			if key1 != key {
				delete(p.pMsgAggregates, key1) // removed, keep one existing entry
			}
			mLog.WithFields(log.Fields{"report_a": pmsga, "fsMsg": pmsga.fsMsg}).Debug("package update")
			bUpdated = true
			continue
		}

		if pmsg.ProcPid > 0 {
			// aggregare file paths
			if pmsga.pid == pmsg.ProcPid {
				pmsga.count++
				// aggregare file operations
				if pmsga.fsMsg.Msg != fsComboAction && pmsga.fsMsg.Msg != pmsg.Msg {
					pmsga.fsMsg.Msg = fsComboAction
				}

				if pmsga.fsMsg.Path == "" {
					// previous report has sent
					pmsga.fsMsg.Path = pmsg.Path
				} else if !strings.Contains(pmsga.fsMsg.Path, pmsg.Path) {
					pmsga.fsMsg.Path = fmt.Sprintf("%s, %s", pmsga.fsMsg.Path, pmsg.Path)
				}

				pmsga.count++
				pmsga.expireCnt = expireCountdown
				if key1 != key {
					delete(p.pMsgAggregates, key1) // removed, keep one existing entry
				}
				mLog.WithFields(log.Fields{"report_a": pmsga}).Debug("accumulated")
				bUpdated = true
				continue
			}
		} else { // pid == 0
			if strings.Contains(pmsga.fsMsg.Path, pmsg.Path) {
				mLog.WithFields(log.Fields{"path": pmsg.Path}).Debug("no pid, duplicated")
				bUpdated = true
				continue
			}
		}
	}

	if bUpdated {
		return false
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

	mLog.WithFields(log.Fields{"key1": key1, "msg": pmsg}).Debug("new entry")
	if pNewMsgA.pid != 0 && !pkgCmds.Contains(pNewMsgA.fsMsg.ProcName) {
		go p.sendFsMonReport(*pmsg, 1, pNewMsgA.startTime)
		// Reset: erase the path to accumulate other files
		pNewMsgA.fsMsg.Path = ""
	}
	p.pMsgAggregates[key1] = pNewMsgA
	return true // send immediately
}

// / aggregate worker
func (p *Probe) processAggregateProbeReports() int {
	var cnt int

	// localized mutex to reduce the interactions with others
	p.msgAggregatesMux.Lock()
	defer p.msgAggregatesMux.Unlock()

	for key, pmsga := range p.pMsgAggregates {
		pmsga.triggerCnt--
		pmsga.expireCnt--
		if pmsga.expireCnt == 0 {
			if pmsga.count > 1 || (pmsga.bFsMonMsg && pmsga.count != 0 && pmsga.fsMsg.Path != "") {
				go p.sendReport(*pmsga)
				cnt++
			}

			// delete the entry
			mLog.WithFields(log.Fields{"key": key, "trigger": pmsga.triggerCnt, "expire": pmsga.expireCnt, "count": pmsga.count}).Debug("delete entry")
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

func (p *Probe) sendFsnJavaPkgReport(id string, files []string, bAdd bool) {
	group, _, _ := p.getServiceGroupName(id)
	fsMsg := fsmon.MonitorMessage{
		ID:      id,
		Path:    strings.Join(files, ", "),
		Group:   group,
		Package: true,
		Msg:     fsPackageUpdate,
		Action:  share.PolicyActionViolate,
		StartAt: time.Now().UTC(),
	}

	if bAdd { // inofrmative
		fsMsg.Path += " (added)"
	} else {
		fsMsg.Path += " (removed)"
	}

	p.notifyFsTaskChan <- &fsMsg
	log.WithFields(log.Fields{"report": fsMsg}).Debug("PROC:")
}

func (p *Probe) sendFsnNvProtectReport(id string, files []string) {
	fsMsg := fsmon.MonitorMessage{
		ID:      id,
		Path:    strings.Join(files, ", "),
		Group:   share.GroupNVProtect,
		Package: false,
		Msg:     fsNvProtectAlert,
		Action:  share.PolicyActionViolate,
		StartAt: time.Now().UTC(),
	}

	p.notifyFsTaskChan <- &fsMsg
	log.WithFields(log.Fields{"report": fsMsg}).Debug("PROC:")
}

func (p *Probe) sendFsmonNVProtectProbeReport(fmsg *fsmon.MonitorMessage) {
	proc := &procInternal{
		ppid:  fmsg.ProcPPid,
		pname: filepath.Base(fmsg.ProcPPath),
		ppath: fmsg.ProcPPath,
		pid:   fmsg.ProcPid, // assuming
		name:  filepath.Base(fmsg.ProcPath),
		path:  fmsg.ProcPath,
	}

	p.sendProcessIncident(true, fmsg.ID, share.CLUSReservedUuidNotAlllowed, fmsg.Group, share.GroupNVProtect, proc)
	log.WithFields(log.Fields{"proc": proc, "fmsg": fmsg}).Debug("PROC:")
}

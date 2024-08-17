package probe

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/agent/probe/netlink"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/osutil"
)

type netlinkProcEvent struct {
	Event   uint32
	Pid     int
	UParam1 int
	UParam2 int
}

const procMonitorSocketSize uint = 1024 * 208

func (p *Probe) openProcMonitor() (*netlink.NetlinkSocket, error) {
	// group as CN_IDX_PROC (1) for process monitor
	ns, err := netlink.NewNetlinkSocket(syscall.NETLINK_CONNECTOR, procMonitorSocketSize, netlink.CN_IDX_PROC)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to create socket for proc")
		return nil, err
	}

	req := netlink.NewNetlinkRequest(syscall.NLMSG_DONE, 0)
	op := netlink.PROC_CN_MCAST_LISTEN
	req.AddData(netlink.NewCnMsg())
	req.AddData(&op)

	err = ns.Write(req)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Unable to send mcast msg to proc connector")
		ns.Close()
		return nil, err
	}

	/*
		// Reduce thread operations
		err = ns.SetFilter(ProcFilters)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Unable to set socket filter")
		}
	*/
	return ns, nil
}

func (p *Probe) killProcess(pid int) {
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		log.WithFields(log.Fields{"pid": pid, "error": err}).Debug("PROC: can not signal")
	}
}

// Establish netlink communication
func (p *Probe) establishNetLinkProcCommunication() error {
	var err error
	if p.nsProc, err = p.openProcMonitor(); err != nil {
		return err
	}

	if err = p.checkProcessNetlinkSocket(); err != nil {
		req := netlink.NewNetlinkRequest(syscall.NLMSG_DONE, 0)
		op := netlink.PROC_CN_MCAST_IGNORE
		req.AddData(netlink.NewCnMsg())
		req.AddData(&op)
		p.nsProc.Write(req)
		p.nsProc.Close()
		return err
	}
	return nil
}

func (p *Probe) checkProcessNetlinkSocket() error {
	// inspect the first 4 packets, timeout interval=1sec
	for i := 0; i < 4; i++ {
		msgs, from, err := p.nsProc.EPollReceiveFrom(&syscall.Timeval{1, 0})
		if err != nil {
			return err
		}

		if msgs == nil || from == nil {
			//	log.WithFields(log.Fields{"msgs": msgs, "from": from}).Debug("timeout")
			continue // timeout-ed and retry
		}

		// only allowed messages from the kernel, Pid = 0
		if sockaddrNl, ok := from.(*syscall.SockaddrNetlink); !ok || sockaddrNl.Pid != 0 {
			log.WithFields(log.Fields{"Pid": sockaddrNl.Pid}).Info("")
			continue
		}

		// exam the incoming packets, the response should be None
		for _, msg := range msgs {
			switch msg.Header.Type {
			case syscall.NLMSG_DONE:
				cnmsg := (*netlink.CnMsg)(unsafe.Pointer(&msg.Data[0])) // connector message header
				msgLen := unsafe.Sizeof(*cnmsg)
				hdr := (*netlink.ProcEvent)(unsafe.Pointer(&msg.Data[msgLen]))
				if hdr.What == netlink.PROC_EVENT_NONE {
					msgLen += unsafe.Sizeof(*hdr)
					e := (*netlink.ProcEventAck)(unsafe.Pointer(&msg.Data[msgLen]))
					log.WithFields(log.Fields{"ack": e.Err}).Debug("Set netlink mcast listener OK")
					return nil
				} else if hdr.What <= netlink.PROC_EVENT_SID {
					// PROC_EVENT_FORK, PROC_EVENT_EXEC, PROC_EVENT_UID, PROC_EVENT_GID, PROC_EVENT_SID
					// ==> received a valid process event. the listener was registered, Pass test ??
					log.WithFields(log.Fields{"hdr": fmt.Sprintf("0x%x", hdr.What)}).Info("netlink listener OK")
					return nil
				} else {
					// PROC_EVENT_PTRACE, PROC_EVENT_COMM, PROC_EVENT_COREDUMP, PROC_EVENT_EXIT
					log.WithFields(log.Fields{"i": i, "hdr": fmt.Sprintf("0x%x", hdr.What)}).Info("netlink msgHdr: ignored")
				}
			case syscall.NLMSG_ERROR:
				return errors.New("Error in netlink message")
			default:
				// NLMSG_OVERRUN: 1, NLMSG_NOOP: 2
				log.WithFields(log.Fields{"i": i, "type": msg.Header.Type}).Info("netlink msgType")
			}
		}
	}

	return errors.New("Receive mcast fails")
}

func (p *Probe) netLinkHandler(e *netlinkProcEvent) {
	// log.WithFields(log.Fields{"event": e}).Debug()
	p.lockProcMux() // minimum section lock
	switch e.Event {
	case netlink.PROC_EVENT_FORK:
		p.handleProcFork(e.Pid, e.UParam1, "") // pid, ppid
	case netlink.PROC_EVENT_EXEC:
		p.handleProcExec(e.Pid, false) // pid
	case netlink.PROC_EVENT_EXIT:
		p.handleProcExit(e.Pid)
	case netlink.PROC_EVENT_UID:
		p.handleProcUIDChange(e.Pid, e.UParam1, e.UParam2) // pid, ruid, euid
	}
	p.unlockProcMux() // minimum section lock
}

func (p *Probe) parseNetLinkProcEvent(msg *syscall.NetlinkMessage) *netlinkProcEvent {
	// preventing index out of range, or invalid "Data" buffer (len==0)
	if msg.Header.Len <= (syscall.NLMSG_HDRLEN + netlink.SizeofCnMsg) {
		log.WithFields(log.Fields{"nlmsghdr": msg.Header}).Debug("PROC: no proc event header")
		return nil
	}

	cnmsg := (*netlink.CnMsg)(unsafe.Pointer(&msg.Data[0])) // connector message header
	msgLen := unsafe.Sizeof(*cnmsg)
	hdr := (*procEventHdr)(unsafe.Pointer(&msg.Data[msgLen]))
	msgLen += unsafe.Sizeof(*hdr)
	switch hdr.what {
	case netlink.PROC_EVENT_FORK:
		e := (*netlink.ProcEventFork)(unsafe.Pointer(&msg.Data[msgLen]))
		if e.ChildTgid == e.ChildPid { // in case if filter failed
			return &netlinkProcEvent{
				Event:   hdr.what,
				Pid:     int(e.ChildPid),
				UParam1: int(e.ParentTgid), // ppid
			}
		}
	case netlink.PROC_EVENT_EXEC:
		e := (*netlink.ProcEventExec)(unsafe.Pointer(&msg.Data[msgLen]))
		if e.ProcessTgid == e.ProcessPid { // always
			return &netlinkProcEvent{
				Event: hdr.what,
				Pid:   int(e.ProcessPid), // pid
			}
		}
	case netlink.PROC_EVENT_EXIT:
		e := (*netlink.ProcEventExit)(unsafe.Pointer(&msg.Data[msgLen]))
		if e.ProcessTgid == e.ProcessPid { // in case if filter failed
			return &netlinkProcEvent{
				Event: hdr.what,
				Pid:   int(e.ProcessPid), // pid
			}
		}
	case netlink.PROC_EVENT_UID:
		e := (*netlink.ProcEventUid)(unsafe.Pointer(&msg.Data[msgLen]))
		return &netlinkProcEvent{
			Event:   hdr.what,
			Pid:     int(e.ProcessPid),
			UParam1: int(e.RUid), // ruid
			UParam2: int(e.EUid), // euid
		}
	}
	return nil
}

func (p *Probe) cleanupProc() {
	pidSetNew := osutil.GetAllProcesses()
	p.lockProcMux()
	defer p.unlockProcMux()
	for pid, _ := range p.pidProcMap {
		if !pidSetNew.Contains(pid) {
			p.handleProcExit(pid) // w/ netlink
		}
	}
}

func (p *Probe) reBuiltProcessTables() {
	p.lockProcMux()
	defer p.unlockProcMux()

	log.Info("PROC:")
	p.containerMap = make(map[string]*procContainer) // reset
	p.pidContainerMap = make(map[int]*procContainer) // reset

	pidSet := osutil.GetAllProcesses()
	p.pidProcMap = p.buildProcessMap(pidSet)
	for _, proc := range p.pidProcMap {
		p.addContainerCandidate(proc, true)
	}
}

func (p *Probe) patchProcessTables() {
	p.lockProcMux()
	defer p.unlockProcMux()

	log.Info("PROC:")
	pidSet := osutil.GetAllProcesses()

	// exit processes
	for pid, _ := range p.pidProcMap {
		if !pidSet.Contains(pid) {
			p.handleProcExit(pid) // exit
		}
	}

	// new processes and re-exam host proc
	for itr := range pidSet.Iter() {
		pid := itr.(int)
		if procE, ok := p.pidProcMap[pid]; !ok {
			proc := &procInternal{
				pid:       pid,
				startTime: time.Now(), // best guess
				action:    share.PolicyActionAllow,
			}

			p.updateProcess(proc)
			proc.pname, _, _, _ = osutil.GetProcessUIDs(proc.ppid)
			proc.path, _ = global.SYS.GetFilePath(proc.pid) // exe path
			proc.cmds, _ = global.SYS.ReadCmdLine(proc.pid)
			if c, ok := p.addContainerCandidateFromProc(proc); ok {
				p.addProcHistory(c.id, proc, true)
			}
		} else if c, ok := p.pidContainerMap[pid]; ok && c.id == "" {
			if !global.RT.IsRuntimeProcess(procE.name, nil) {
				if c1, ok := p.addContainerCandidateFromProc(procE); ok && c1.id != "" {
					mLog.WithFields(log.Fields{"name": procE.name, "pid": procE.pid, "id": c1.id}).Debug("PROC: patch")
					p.addProcHistory(c1.id, procE, true)
				}
			}
		}
	}
}

// Dedicate to netlink process worker
func (p *Probe) netlinkProcMonitor() {
	var counter int64
	var rebuildCounter int64 = -1
	const ticker_unit_in_seconds = 2
	const cleanupCounter = 10 * 60 / ticker_unit_in_seconds // 10 minutes
	ticker := time.Tick(time.Second * ticker_unit_in_seconds)
	log.Info("PROC: Start real-time process listener")
	for {
		select {
		case <-ticker:
			counter++
			p.processContainerAppPortChanges()
			if counter%5 == 0 {
				p.monitorProcessChanges() // every 2*5 seconds
			}
			if counter > cleanupCounter {
				// In case we miss some events, we should periodically clean up process map
				p.cleanupProc()
				counter = 0 // reset here
			}

			// time consuming process, reducing its usage
			if p.resetProcTbl {
				p.resetProcTbl = false
				if p.deferCStartRpt { // crio: timimg is critical
					rebuildCounter = counter + 1 // quick recovery: 2 sec
				} else {
					rebuildCounter = counter + 10 // delay 20 sec for normal condition
				}
			}

			if counter == rebuildCounter {
				rebuildCounter = -1
				p.patchProcessTables()
				// p.reBuiltProcessTables()
				// p.profileFuncTime(p.reBuiltProcessTables, 100)
			}
		}
	}
}

func (p *Probe) netlinkProcWorker() {
	const procEventSize = 4096
	procEventQueue := make(chan *netlinkProcEvent, procEventSize) // increase to avoid underflow
	go func() {
		var ok bool
		var event *netlinkProcEvent
		for {
			if !p.pidNetlink {
				break
			}

			if event, ok = <-procEventQueue; ok {
				p.netLinkHandler(event)
				for i := 0; i < len(procEventQueue); i++ {
					if i > 256 || !p.pidNetlink { // yield every 256 events
						break
					}

					if event, ok = <-procEventQueue; ok {
						p.netLinkHandler(event)
					}
				}
			}
		}
		log.Info("PROC: reader exits")
	}()

	lastReceiveTime := time.Now()
	skipCnt := 0
	for {
		if !p.pidNetlink {
			close(procEventQueue) // end channel at writer
			break
		}

		msgs, from, err := p.nsProc.ReceiveFrom()
		if err != nil {
			if strings.Contains(err.Error(), "bad file descriptor") {
				log.WithFields(log.Fields{"error": err}).Error("Fatal: netlink failed")
				break
			}

			if !errors.Is(err, syscall.EAGAIN) {
				timeSkipped := time.Since(lastReceiveTime)
				if timeSkipped > time.Duration(time.Millisecond*100) {
					p.resetProcTbl = true
					log.WithFields(log.Fields{"error": err, "TimeSkipped": timeSkipped}).Error("PROC: Receive error")
				}
			}
			continue
		}

		lastReceiveTime = time.Now()
		if msgs == nil || from == nil {
			continue
		}

		// only allowed messages from the kernel, Pid = 0
		if sockaddrNl, ok := from.(*syscall.SockaddrNetlink); !ok || sockaddrNl.Pid != 0 {
			log.WithFields(log.Fields{"pid": sockaddrNl.Pid}).Error("PROC: Wrong sender")
			continue
		}

		for _, msg := range msgs {
			if len(procEventQueue) == procEventSize {
				skipCnt++
				break
			}
			if event := p.parseNetLinkProcEvent(&msg); event != nil {
				procEventQueue <- event
				if skipCnt > 0 {
					// log.WithFields(log.Fields{"skipCnt": skipCnt}).Debug("PROC:")
					skipCnt = 0
				}
			}
		}
	}
	log.Info("PROC: exit")
}

package probe

import (
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/agent/dp"
	"github.com/neuvector/neuvector/agent/probe/netlink"
	"github.com/neuvector/neuvector/agent/probe/ringbuffer"
	"github.com/neuvector/neuvector/agent/workerlet"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/fsmon"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/osutil"
	"github.com/neuvector/neuvector/share/utils"
)

// //
var mLog *log.Logger = log.New()

const delayExitThreshold = time.Duration(time.Second * 1)

type procDelayExit struct {
	pid  int
	id   string
	last time.Time
}

type Probe struct {
	bProfileEnable       bool // default: true
	agentPid             int
	agentMntNsId         uint64
	dpTaskCallback       dp.DPTaskCallback
	notifyTaskChan       chan *ProbeMessage
	notifyFsTaskChan     chan *fsmon.MonitorMessage
	pidNetlink           bool // use netlink to listen to pid update
	monitorConnection    bool // monitor socket connection
	containerInContainer bool // container-in-container
	policyLookupFunc     func(conn *dp.Connection) (uint32, uint8, bool)
	procPolicyLookupFunc func(id, riskType, pname, ppath string, pid, pgid, shellCmd int, proc *share.CLUSProcessProfileEntry) (string, string, string, string, bool, error)
	bK8sGroupWithProbe   func(svcGroup string) bool
	reportLearnProc      func(svcGroup string, proc *share.CLUSProcessProfileEntry)
	isNeuvectorContainer func(id string) (string, bool)
	disableNvProtect     bool
	bKubePlatform        bool
	kubeFlavor           string
	walkerTask           *workerlet.Tasker
	nsProc               *netlink.NetlinkSocket
	nsInet               *netlink.NetlinkSocket

	procMux         sync.Mutex
	containerMap    map[string]*procContainer
	pidContainerMap map[int]*procContainer
	pidProcMap      map[int]*procInternal
	newProcesses    utils.Set
	inspectProcess  utils.Set
	chanEvalAppPid  chan int // pid
	selfID          string   // enforcer/allinone container id
	agentSessionID  int      // session processs ID for agent/container process launcher
	resetIoNodes    bool
	resetProcTbl    bool //  patch netlink overflow and lost packets
	deferCStartRpt  bool // defer start container report

	//	containerNews  utils.Set // temp. holding id for containers that have not got root pid yet.
	containerStops utils.Set // temp. holding id for exited containers in the last cycle
	pidSet         utils.Set // used for proc_scan to find differences in processes

	// Socket monitor
	sessionTable map[string]*session
	sessionMux   sync.Mutex

	// Interface monitor
	intfMonMux      sync.Mutex
	intfMonMap      map[string]chan struct{}
	getContainerPid func(id string) int
	rerunKubeBench  func(string, string)
	inodesMap       map[uint32]*inodeEntry

	// helper: statistics
	profileMaxGortn       int
	profileMaxChanEvalCnt int

	// helper: process blocker
	fAccessCtl           *FileAccessCtrl
	getEstimateProcGroup func(id, name, path string) (string, string)
	getServiceGroupName  func(id string) (string, bool, bool)

	// helper: file monitor
	fMonitorCtl *fsmon.FileWatch
	FaEndChan   chan bool

	// helper: process event history
	getAllContainerList func() utils.Set
	procHistoryMap      map[string]*ringbuffer.RingBuffer // per container
	pMsgAggregates      map[string]*probeMsgAggregate
	msgAggregatesMux    sync.Mutex
	fsnCtr              *FileNotificationCtr // anchor profile helper
	exitProcSlices      []*procDelayExit
	IsNvProtectAlerted  bool
}

func (p *Probe) cbOpenNetlinkSockets(param interface{}) {
	var err error

	// netlink: diagnostic socket
	if p.nsInet, err = p.openSocketMonitor(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Unable to open diagnostic netlink socket")
		return
	}

	// netlink: process connector(4 chances)
	if p.pidNetlink {
		i := 0
		for {
			i++
			err = p.establishNetLinkProcCommunication()
			if err == nil {
				return
			}

			log.WithFields(log.Fields{"error": err, "i": i}).Error("error: proc monitor communication")
			if i > 4 {
				break
			}
			time.Sleep(time.Second * 3)
		}
		p.pidNetlink = false
		log.WithFields(log.Fields{"error": err}).Error("Failed to establish proc monitor communication")
	}
}

func (p *Probe) StartMonitorConnection() {
	p.monitorConnection = true
}

func (p *Probe) IsConnectionMonitored() bool {
	return p.monitorConnection
}

func (p *Probe) SetFileMonitor(fm *fsmon.FileWatch) {
	p.fMonitorCtl = fm
}

func (p *Probe) lockProcMux() {
	//	log.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("PROC: ", p.myCaller())
	p.procMux.Lock()
}

func (p *Probe) unlockProcMux() {
	p.procMux.Unlock()
	//	log.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("PROC: ", p.myCaller())
}

func (p *Probe) getChangedContainers(pidSetNew utils.Set) {
	//process scan mode
	pidFork := pidSetNew.Difference(p.pidSet)
	pidExit := p.pidSet.Difference(pidSetNew)

	p.lockProcMux()
	defer p.unlockProcMux()
	if pidFork.Cardinality() != 0 || pidExit.Cardinality() != 0 {
		// Handle new processes first, otherwise we might remove a container accidentally.
		if pidFork.Cardinality() > 0 {
			p.scanNewProcess(pidFork)
		}
		for pid := range pidExit.Iter() {
			proc := p.handleProcExit(pid.(int)) // w/o netlink
			if proc != nil {
				p.newProcesses.Remove(proc)
			}
		}
		//remove the processes we didn't handle. so we will handle them in next turn.
		p.pidSet = pidSetNew.Difference(pidFork)
	}
	p.walkNewProcesses()

	pidFork.Clear()
	pidExit.Clear()
	pidFork, pidExit = nil, nil
}

func (p *Probe) processContainerAppPortChanges() {

	p.lockProcMux()
	defer p.unlockProcMux()

	changes := utils.NewSet()
	for id, c := range p.containerMap {
		if c.rootPid == 0 {
			c.rootPid = p.getContainerPid(id)
			if id == p.selfID {
				c.children.Add(c.rootPid)
				c.children.Add(p.agentPid)
			}
		}

		if id != "" && id != p.selfID && c.rootPid != 0 {
			// Check whether the container has port or app changed
			if p.checkProcAppPorts(c, true) {
				changes.Add(id)
			}
		}
	}

	// Send a message one at a time to prevent us from spending too long handling one event
	if changes.Cardinality() > 0 {
		msg := ProbeMessage{Type: PROBE_PROCESS_CHANGE, ContainerIDs: changes}
		p.notifyTaskChan <- &msg
	}
}

// scan mode only
func (p *Probe) processContainerChanges(pidSetNew utils.Set) {
	p.getChangedContainers(pidSetNew)
}

func (p *Probe) monitorProcessChanges() {
	// netlink proc: avoid deadlocks
	// keep an eye on the launched applications
	p.inspectNewProcesses(false) // Evaluations
	// p.processContainerAppPortChanges()
}

func (p *Probe) loop() {
	scanTicker := time.Tick(time.Second * 1)
	purgeHistoryTicker := time.Tick(time.Second * 60)
	aggregateReportTicker := time.Tick(time.Second * 5)
	var scan bool
	var pidSetNew utils.Set
	for {
		select {
		case <-scanTicker:
			p.removeDelayExitProc()
			if p.monitorConnection { // for network==host mode containers
				conns := p.getNewConnections()
				if len(conns) > 0 {
					task := dp.DPTask{Task: dp.DP_TASK_HOST_CONNECTION, Connects: conns}
					p.dpTaskCallback(&task)
				}
			}

			// only active when netlink is not avaialable
			if !p.pidNetlink {
				if !scan {
					pidSetNew = osutil.GetAllProcesses()
				} else {
					p.processContainerChanges(pidSetNew)
					p.monitorProcessChanges()
					p.processContainerAppPortChanges()
				}
				scan = !scan
			}

		case <-purgeHistoryTicker:
			p.purgeProcHistory()

		case <-aggregateReportTicker:
			p.processAggregateProbeReports()
		}
	}
}

// a dedicated service for reporting system
func (p *Probe) delayProcReportService() {
	for {
		pid := <-p.chanEvalAppPid // serialize in the occuring sequence
		p.evalNewRunningApp(pid)
	}
}

func New(pc *ProbeConfig, logLevel string) (*Probe, error) {
	log.Info()
	p := &Probe{
		bProfileEnable:       pc.ProfileEnable,
		agentPid:             pc.Pid,
		dpTaskCallback:       pc.DpTaskCallback,
		notifyTaskChan:       pc.NotifyTaskChan,
		notifyFsTaskChan:     pc.NotifyFsTaskChan,
		pidNetlink:           pc.PidMode == "host",
		policyLookupFunc:     pc.PolicyLookupFunc,
		procPolicyLookupFunc: pc.ProcPolicyLookupFunc,
		bK8sGroupWithProbe:   pc.IsK8sGroupWithProbe,
		reportLearnProc:      pc.ReportLearnProc,
		isNeuvectorContainer: pc.IsNeuvectorContainer,
		containerInContainer: pc.ContainerInContainer,
		getContainerPid:      pc.GetContainerPid,
		getAllContainerList:  pc.GetAllContainerList,
		rerunKubeBench:       pc.RerunKubeBench,
		getEstimateProcGroup: pc.GetEstimateProcGroup,
		getServiceGroupName:  pc.GetServiceGroupName,
		FaEndChan:            pc.FAEndChan,
		deferCStartRpt:       pc.DeferContStartRpt,
		bKubePlatform:        pc.KubePlatform,
		kubeFlavor:           pc.KubeFlavor,
		walkerTask:           pc.WalkHelper,
		agentMntNsId:         global.SYS.GetMntNamespaceId(pc.Pid),

		containerMap:    make(map[string]*procContainer),
		newProcesses:    utils.NewSet(),
		inspectProcess:  utils.NewSet(),
		pidContainerMap: make(map[int]*procContainer),
		pidProcMap:      make(map[int]*procInternal),
		//	containerNews:   utils.NewSet(),
		containerStops: utils.NewSet(),
		pidSet:         utils.NewSet(),
		sessionTable:   make(map[string]*session),
		intfMonMap:     make(map[string]chan struct{}),
		inodesMap:      make(map[uint32]*inodeEntry),
		chanEvalAppPid: make(chan int, 2048),
		procHistoryMap: make(map[string]*ringbuffer.RingBuffer),
		pMsgAggregates: make(map[string]*probeMsgAggregate),
	}

	// for process
	mLog.Out = os.Stdout
	mLog.Level = share.CLUSGetLogLevel(logLevel)
	mLog.Formatter = &utils.LogFormatter{Module: "AGT"}
	if pc.EnableTrace {
		mLog.SetLevel(log.DebugLevel)
	}

	if !p.bProfileEnable {
		log.Info("Process profiler is disabled")
	}

	p.selfID = global.RT.GetSelfID()
	p.agentSessionID = osutil.GetSessionId(p.agentPid)
	//log.WithFields(log.Fields{"sessionID": p.agentSessionID, "container ID": p.selfID}).Info("PROC: ")

	// p.pidNetlink = false // for test scan mode
	if err := global.SYS.CallNetNamespaceFunc(1, p.cbOpenNetlinkSockets, nil); err != nil {
		return nil, err
	}

	// Process blocker is disabled and process killer is an optional replacement
	bAufsDriver := global.RT.GetStorageDriver() == "aufs"
	if bAufsDriver {
		log.WithFields(log.Fields{"runtime": global.RT.String(), "storage driver": global.RT.GetStorageDriver()}).Info("PROC: ")
	} else if p.bProfileEnable {
		var ok bool
		if p.fAccessCtl, ok = NewFileAccessCtrl(p); !ok {
			log.Info("PROC: Process control is not supported")
		}
	}

	// no process access blocker
	if p.fAccessCtl == nil {
		p.FaEndChan <- true
	}

	// NV Protect is always on even if the the process profile is disabled
	var ok bool
	if p.fsnCtr, ok = NewFsnCenter(p, global.RT.GetStorageDriver()); !ok {
		log.Error("FSN: failed")
	}

	// build current process maps, host container is established here
	runKube := p.initReadProcesses()
	if !runKube {
		p.rerunKubeBench("", "")
	}

	if p.pidNetlink {
		go p.netlinkProcWorker()  // socket event worker
		go p.netlinkProcMonitor() // routine monitor
	} else {
		log.Info("PROC: Enter process scan mode")
	}

	go p.loop()
	go p.delayProcReportService()
	return p, nil
}

func (p *Probe) Close() {
	log.Info()

	if p.bProfileEnable {
		if p.fAccessCtl != nil {
			p.fAccessCtl.Close()
		}
		p.fsnCtr.Close()
	}

	p.nsInet.Close()

	if p.pidNetlink {
		req := netlink.NewNetlinkRequest(syscall.NLMSG_DONE, 0)
		op := netlink.PROC_CN_MCAST_IGNORE
		req.AddData(netlink.NewCnMsg())
		req.AddData(&op)

		err := p.nsProc.Write(req)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Unable to send ignore msg to netlink socket")
		}

		p.nsProc.Close()
		p.pidNetlink = false
		log.Info("closing netlink")
	}

	p.intfMonMux.Lock()
	for id, ch := range p.intfMonMap {
		delete(p.intfMonMap, id)
		close(ch)
	}
	p.intfMonMux.Unlock()
	log.Info("done")
}

func (p *Probe) getDockerCpInfo(pid int, id, containerName string,
	toContainer bool) (path string, dockerCmds []string, user string, euid int, found bool) {
	if cmds, _ := global.SYS.ReadCmdLine(pid); len(cmds) > 3 {
		if cmds[0] == "docker" && cmds[1] == "cp" {
			var pathStr string
			if toContainer {
				pathStr = cmds[3]
			} else {
				pathStr = cmds[2]
			}
			i := strings.Index(pathStr, ":")
			if i < 0 {
				return
			}
			cname := pathStr[:i]
			if cname != containerName && !strings.Contains(id, cname) {
				return
			}
			path = pathStr[i+1:]
			if _, _, _, euid = osutil.GetProcessUIDs(pid); euid > 0 {
				user = p.getUserName(1, euid)
			}
			dockerCmds = cmds
			found = true
		}
	}
	return
}

func (p *Probe) ReportDockerCp(id, containerName string, toContainer bool) {
	var dockerPid int
	var user, path, msg string
	var cmds []string
	var euid int
	var found bool

	pidSetNew := osutil.GetAllProcesses()
	pidFork := pidSetNew.Difference(p.pidSet)
	defer pidFork.Clear()

	// search the new process list
	for itr := range pidFork.Iter() {
		pid := itr.(int)
		path, cmds, user, euid, found = p.getDockerCpInfo(pid, id, containerName, toContainer)
		if found {
			dockerPid = pid
			break
		}
	}

	// not found the process in the new list
	// search in the previous all process map
	if !found {
		p.lockProcMux()
		for pid, proc := range p.pidProcMap {
			if proc.name != "" && proc.name != "docker" {
				continue
			}
			path, cmds, user, euid, found = p.getDockerCpInfo(pid, id, containerName, toContainer)
			if found {
				dockerPid = pid
				break
			}
		}
		p.unlockProcMux()
	}

	if !found {
		return
	}

	go func() {
		if toContainer {
			msg = "docker copy to container"
		} else {
			msg = "docker copy from container"
		}

		s := &ProbeProcess{
			ID:     id,
			Cmds:   cmds,
			Path:   path,
			Name:   "docker cp",
			Pid:    dockerPid,
			EUid:   euid,
			EUser:  user,
			RuleID: share.CLUSReservedUuidDockerCp,
			Msg:    msg,
		}
		rpt := ProbeMessage{Type: PROBE_REPORT_SUSPICIOUS, Process: s}
		p.SendAggregateProbeReport(&rpt, false)
	}()
}

// /// by policy order
func (p *Probe) addProcessControl(id, setting, svcGroup string, pid int, ppe_list []*share.CLUSProcessProfileEntry) {
	if p.fAccessCtl != nil {
		for _, ppe := range ppe_list {
			mLog.WithFields(log.Fields{"name": ppe.Name, "path": ppe.Path, "action": ppe.Action}).Debug("PROC:")
		}

		if !osutil.IsPidValid(pid) {
			log.WithFields(log.Fields{"id": id, "Pid": pid}).Error("FA: invalid Pid")
			return
		}

		if !p.fAccessCtl.AddContainerControlByPolicyOrder(id, setting, svcGroup, pid, ppe_list) {
			log.WithFields(log.Fields{"id": id, "pid": pid}).Debug("PROC: failed")
		}
	} else {
		mLog.WithFields(log.Fields{"id": id}).Debug("PROC: service is not available")
	}
}

// ///
func (p *Probe) RemoveProcessControl(id string) {
	if p.fAccessCtl != nil {
		if p.fAccessCtl.RemoveContainerControl(id) {
			mLog.WithFields(log.Fields{"id": id}).Debug("PROC: ")
		}
	}
}

/* removed by golint
func (p *Probe) addContainerFAccessBlackList(id string, list []string) {
	if p.fAccessCtl != nil {
		p.fAccessCtl.AddBlackListOnTheFly(id, list)
	}
}
*/

const skipJarEventPeriod = time.Duration(time.Second * 30)

func (p *Probe) ProcessFsnEvent(id string, files []string, finfo fileInfo) {
	if finfo.bExec || finfo.bJavaPkg {
		mLog.WithFields(log.Fields{"id": id, "files": files, "finfo": finfo}).Debug("FSN:")
		p.lockProcMux()
		c, ok := p.containerMap[id]
		p.unlockProcMux()
		if ok {
			if time.Since(c.startAt) < skipJarEventPeriod {
				mLog.WithFields(log.Fields{"start": c.startAt}).Debug("FSN: Skip jar")
				return
			}
		}

		if finfo.bJavaPkg && (finfo.fileType == file_added || finfo.fileType == file_deleted) {
			p.sendFsnJavaPkgReport(id, files, finfo.fileType == file_added)
		}
	}

	mLog.WithFields(log.Fields{"id": id, "files": files}).Info()
	if !p.disableNvProtect {
		if role, ok := p.isNeuvectorContainer(id); ok {
			// NV Protect alerts
			var violated []string
			for _, f := range files {
				if strings.HasPrefix(f, "/bin/") || strings.HasPrefix(f, "/sbin/") || strings.HasPrefix(f, "/usr/bin/") || strings.HasPrefix(f, "/usr/sbin/") {
					violated = append(violated, f)
					continue
				}

				if strings.HasPrefix(f, "/usr/local/bin/") {
					if strings.Contains(role, "manager") {
						// exclude CLI path
						if strings.HasPrefix(f, "/usr/local/bin/prog/") {
							continue
						}
					}
					violated = append(violated, f)
					continue
				}
			}

			if len(violated) > 0 {
				mLog.WithFields(log.Fields{"id": id, "violated": violated, "role": role}).Info("FSN: NV.Protect, no more script tests")
				p.IsNvProtectAlerted = true
				p.sendFsnNvProtectReport(id, violated)
			}
		}
	}
}

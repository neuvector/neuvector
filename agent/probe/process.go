package probe

import (
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/agent/probe/ringbuffer"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/fsmon"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/osutil"
	"github.com/neuvector/neuvector/share/utils"
)

const retryReadProcMax int = 1

const (
	escalatReported uint = 1 << iota
	reversShReported
	reversShConfirmed
	suspicReported
	dnsTunnelReported
	profileReported
	historyReported
)

type procEventHdr struct {
	what          uint32
	cpu           uint32
	timeStampNano uint64
}

type userNs struct {
	users  map[int]string
	root   int
	uidMin int
}

type procContainer struct {
	id       string
	rootPid  int
	children utils.Set // pid pool from rootPid (major)
	outsider utils.Set // pid pool from outside
	newBorn  int
	userns   *userNs
	startAt  time.Time
	//map of port listened by multiple processes
	portsMap         map[osutil.SocketInfo]*procApp
	checkRemovedPort uint
	fInfo            map[string]*fileInfo
	bPrivileged      bool
	healthCheck      []string
}

type procInternal struct {
	pname        string
	ppath        string
	name         string
	path         string
	cmds         []string
	user         string
	pid          int
	ppid         int
	sid          int
	pgid         int
	ruid         int
	euid         int
	retry        int
	inspectTimes uint
	startTime    time.Time
	lastScanTime time.Time
	scanTimes    uint
	reported     uint
	action       string
	riskyChild   bool
	riskType     string
	execScanDone bool // scan mode only
}

type suspicProcInfo struct {
	ingress bool
	msg     string
}

var suspicProcMap map[string]*suspicProcInfo = map[string]*suspicProcInfo{
	"nmap":       {false, "Port Scanner"},
	"nc":         {false, "netcat process"},
	"ncat":       {false, "netcat process"},
	"netcat":     {false, "netcat process"},
	"sshd":       {true, "ssh from remote"},
	"ssh":        {false, "ssh to remote"},
	"scp":        {false, "Secure copy"},
	"telnet":     {false, "telnet to remote"},
	"in.telnetd": {true, "telnet from remote"},
	"iodine":     {false, "dns tunneling"},
	"iodined":    {true, "dns tunneling"},
	"dnscat":     {false, "dns tunneling"},
	"dns2tcpc":   {false, "dns tunneling"},
	"dns2tcpd":   {true, "dns tunneling"},
}

var kubeProcs map[string]int = map[string]int{
	"kubelet":        1,
	"kube-apiserver": 1,
	"hyperkube":      1,
	"k3s":            1, // check if in k3s env
}

//var linuxShells utils.Set = utils.NewSet("sh", "dash", "bash", "rbash")

// Can be called with process that has exited
func (p *Probe) proc2CLUS(proc *procInternal) *share.CLUSProcess {
	var euser string
	ppid, gid, sid, status, _ := osutil.GetProcessPIDs(proc.pid)
	if ppid != -1 {
		euser = p.getUserName(proc.pid, proc.euid)
	} else {
		euser = proc.user
		status = "Exited"
	}

	output := &share.CLUSProcess{
		Name:    proc.name,
		Pid:     uint32(proc.pid),
		PPid:    uint32(proc.ppid),
		PGid:    uint32(gid),
		PSid:    uint32(sid),
		RUid:    uint32(proc.ruid),
		EUid:    uint32(proc.euid),
		Root:    proc.euid == 0,
		Cmds:    proc.cmds,
		User:    euser,
		Status:  status,
		StartAt: proc.startTime.UTC().Unix(),
		Action:  proc.action,
	}

	return output
}

func clearContainerProcesses(c *procContainer) {
	c.children.Clear()
	c.outsider.Clear()
}

func isContainerProcess(c *procContainer, pid int) bool {
	return c.children.Contains(pid) || c.outsider.Contains(pid)
}

// check if the process is assigned to host before. if so, remove from host
func (p *Probe) removeHostPool(pid int) {
	if c, ok := p.containerMap[""]; ok {
		c.children.Remove(pid)
	}
}

func (p *Probe) addProcessPool(pid, ppid int) (*procContainer, bool) {
	if c, ok := p.pidContainerMap[ppid]; ok && c.id != "" {
		if c.children.Contains(ppid) {
			c.children.Add(pid)
		} else {
			c.outsider.Add(pid)
		}
		p.removeHostPool(pid)
		return c, true
	}
	return nil, false
}

// ///
func (p *Probe) isDockerDaemonProcess(proc *procInternal, id string) bool {
	if id == "" { // host porcesses
		if global.RT.IsRuntimeProcess(proc.pname, nil) {
			// skip: runtime processes
			return true
		}

		if p.bKubePlatform {
			if _, ok := kubeProcs[proc.pname]; ok {
				// skip: kube processes
				return true
			}
		}
	}
	return proc.name == global.RT.String() || proc.pname == global.RT.String()
}

// //
// scan at timestamp: 0, 2, 4, 8, 16, 24, 32
// after 1 minute, it scans once every minute
const udpSessionQualification uint = 20         //seconds
const procReexamCycle uint = 60                 //repeat re-exam every 60 seconds
var scanAt = [...]uint{0, 2, 4, 8, 16, 24, 32}  //during the initial time of a new process
var procReexamMaxTimes uint = uint(len(scanAt)) //Max scan times before scanning every procReexamCycle
func shouldScanProc(proc *procInternal) bool {
	var scan bool
	if proc.scanTimes == 0 {
		scan = true
		proc.scanTimes++
		proc.lastScanTime = time.Now() // reset, trigger a faster scanning port action
	} else {
		gap := uint(time.Since(proc.lastScanTime).Seconds())
		if proc.scanTimes < procReexamMaxTimes {
			if gap > scanAt[proc.scanTimes] {
				scan = true
				proc.scanTimes++
			}
		} else {
			//rescan process every procReexamCycle
			if gap > procReexamCycle {
				scan = true
				proc.lastScanTime = time.Now() // keep the 1 min cycle
			}
		}

		//	if scan {
		//		log.WithFields(log.Fields{"pid": proc.pid, "next": proc.scanTimes, "gap": gap}).Debug()
		//	}
	}
	return scan
}

// to check whether the processes in a container ports have changed
// UDP session: report only long-lasting UDP sessions (qualification: 20 second).
//
//	It's impossible to distinguish a server or a client from /proc/net/udp[udp6]
//
// server case:
//
//		(s1) create a udp socket => no entry in the /proc/net/udp
//		(s2) bind()sk_state=TCP_ESTABLISH => shown with inode in the /proc/net/udp
//		(s3) socket closed => the entry is deleted in the /proc/net/udp
//
//		client case (for example, nslookup, its default timeout is 5+ sec):
//		(c1) create a udp socket => no entry in the /proc/net/udp
//		(c2) send dns query (short and fast), sk_state=TCP_ESTABLISH => shown with inode in the /proc/net/udp
//		(c3) wait for response, sk_state=TCP_CLOSE => still shown with inode in the /proc/net/udp
//		(c4) receive the reposnse (can not find the sk_state changes)
//		(c5) socket closed => the entry is deleted in the /proc/net/udp
//
//	 When (c3) or (c4) takes too long, we have this false-positive cases.
//	 Also, it is impossible to catch the (c2) event by a polling method.
func (p *Probe) checkProcAppPorts(c *procContainer, rateLimit bool) bool {
	var addPort, notify bool
	var socketTbl map[uint32]osutil.SocketInfo

	// remove closed socket ports
	c.checkRemovedPort++
	if c.checkRemovedPort > 4 { // every 10 = 5 x 2 seconds
		c.checkRemovedPort = 0
		//active socket table for a container: /proc/1/net/<tcp, tcp6, udp, udp6>
		socketTbl = osutil.GetContainerSocketTable(c.rootPid)

		// the obsoleted sockets and treat them as the closed ports
		for pport, papp := range c.portsMap {
			if _, ok := socketTbl[pport.INode]; !ok {
				if papp.DelConfirmed { // gone
					log.WithFields(log.Fields{"pport": pport}).Debug("delete: done")
					delete(c.portsMap, pport)
					notify = true
				} else {
					papp.DelConfirmed = true
					if !papp.AddConfirmed {
						// log.WithFields(log.Fields{"pport": pport}).Debug("delete: not confirmed yet")
						delete(c.portsMap, pport)
					} else {
						// some servers might recover their services very soon.
						// wait for another cycle to avoid too many workload updates.
						log.WithFields(log.Fields{"pport": pport, "papp": papp}).Debug("delete: wait")
					}
				}
			}
		}

		// no session: skip below add probes
		if len(socketTbl) == 0 {
			return notify
		}
	}

	// add active socket ports
	// probing all children in this container
	pids := c.children.Union(c.outsider)
	for pid := range pids.Iter() {
		if proc := p.pidProcMap[pid.(int)]; proc != nil {
			if rateLimit && !shouldScanProc(proc) {
				// log.WithFields(log.Fields{"pid": proc.pid, "root": c.rootPid}).Debug("skip")
				continue
			}

			//active (socket) inodes for a process: /proc/<pid>/fd/<number> -> socket[<inode>]
			inodes, err := osutil.GetProcessSocketInodes(proc.pid)
			if err != nil || inodes.Cardinality() == 0 {
				continue
			}

			// retrive while the probe is set
			if socketTbl == nil {
				socketTbl = osutil.GetContainerSocketTable(c.rootPid)
				// no session: skip below all probes
				if len(socketTbl) == 0 {
					return notify
				}
			}

			// search the protocol-type/port from the container's socketTable
			for fd := range inodes.Iter() {
				if pport, ok := socketTbl[fd.(uint32)]; ok {
					// is a tcp listener or a meaningful udp session
					if papp, ok := c.portsMap[pport]; ok {
						papp.Pids.Add(pid)
						papp.DelConfirmed = false // reset
						// log.WithFields(log.Fields{"pport": pport,  "since": time.Since(papp.SessionInitTime)}).Debug("continuous session")
						if !papp.AddConfirmed {
							// For a valid udp session, it must last for a qualication period
							if uint(time.Since(papp.SessionInitTime).Seconds()) > udpSessionQualification {
								papp.AddConfirmed = true
								addPort = true
								notify = true
								log.WithFields(log.Fields{"pid": pid, "pport": pport, "since": time.Since(papp.SessionInitTime)}).Debug("confirm: udp session")
							}
						}
					} else {
						papp := &procApp{Pids: utils.NewSet(pid), SessionInitTime: time.Now()}
						c.portsMap[pport] = papp
						proc.scanTimes = 0 // scan more aggressively
						if pport.IPProto == syscall.IPPROTO_UDP {
							log.WithFields(log.Fields{"pid": pid, "pport": pport}).Debug("wait: udp session")
						} else {
							log.WithFields(log.Fields{"pid": pid, "pport": pport}).Debug("add: tcp listener")
							papp.AddConfirmed = true
							addPort = true
							notify = true
						}
					}
				}
			}
		}
	}

	//get port's application
	if addPort {
		getAppMap(c.portsMap)
	}
	return notify
}

// get a container's listen ports and application map
func (p *Probe) GetContainerAppPorts(id string) (utils.Set, map[share.CLUSProtoPort]*share.CLUSApp) {
	appMap := make(map[share.CLUSProtoPort]*share.CLUSApp)
	listensAll := utils.NewSet()

	p.lockProcMux()
	defer p.unlockProcMux()

	if c, ok := p.containerMap[id]; ok {
		//return all listened ports in a container
		for k, papp := range c.portsMap {
			port := share.CLUSProtoPort{IPProto: k.IPProto, Port: k.Port}
			if !papp.AddConfirmed {
				continue
			}
			listensAll.Add(port)
			if papp.App.Port != 0 {
				appMap[port] = &papp.App
			}
		}
	}
	return listensAll, appMap
}

func (p *Probe) GetContainerProcs(id string) []*share.CLUSProcess {
	p.lockProcMux()
	defer p.unlockProcMux()

	if c, ok := p.containerMap[id]; ok {
		pids := c.children.Union(c.outsider)
		procs := make([]*share.CLUSProcess, 0, pids.Cardinality())
		for pid := range pids.Iter() {
			if proc := p.pidProcMap[pid.(int)]; proc != nil {
				procs = append(procs, p.proc2CLUS(proc))
			}
		}
		return procs
	} else {
		return make([]*share.CLUSProcess, 0)
	}
}

func (p *Probe) GetContainerProcHistory(id string) []*share.CLUSProcess {
	p.lockProcMux()
	defer p.unlockProcMux()

	if r, ok := p.procHistoryMap[id]; ok {
		history := r.DumpExt()
		procs := make([]*share.CLUSProcess, len(history))
		for i, proc := range history {
			procs[i] = p.proc2CLUS(proc.(*procInternal))
		}
		return procs
	} else {
		return make([]*share.CLUSProcess, 0)
	}
}

// put all host processes in a virtual container, id=="". so we can handle host process same as other container
func (p *Probe) addHost(pid int) {
	c := &procContainer{
		id:       "",
		children: utils.NewSet(pid),
		outsider: utils.NewSet(), // empty
		rootPid:  1,
		newBorn:  0,
		userns:   &userNs{users: make(map[int]string), uidMin: osutil.UserUidMin},
		portsMap: make(map[osutil.SocketInfo]*procApp),
		fInfo:    make(map[string]*fileInfo),
		startAt:  time.Now(),
	}

	p.containerMap[""] = c
	p.pidContainerMap[pid] = c

	//load the users from host
	if root, min, err := osutil.GetAllUsers(c.rootPid, c.userns.users); err == nil {
		c.userns.root = root
		c.userns.uidMin = min
	}
}

func (p *Probe) inspectFirstContainerProc(proc *procInternal) {
	if proc.user == "" {
		proc.user = p.getUserName(proc.pid, proc.euid)
	}
	if proc.path == "" {
		proc.path, _ = global.SYS.GetFilePath(proc.pid)
	}
	if proc.name == "" {
		proc.name, _, _, _ = osutil.GetProcessUIDs(proc.pid)
	}

	ppid, _, _, _, _ := osutil.GetProcessPIDs(proc.pid)
	if ppid > 1 {
		proc.ppid = ppid
		proc.pname, _, _, _ = osutil.GetProcessUIDs(proc.ppid)
		proc.ppath, _ = global.SYS.GetFilePath(proc.ppid)
	}
}

func (p *Probe) addContainer(id string, proc *procInternal, scanMode bool) {
	var pid int = proc.pid
	c := &procContainer{
		id: id,
		//	rootPid:  pid, 	// must rely on external api, like docker
		children: utils.NewSet(pid),
		outsider: utils.NewSet(), // empty
		newBorn:  1,
		userns:   &userNs{users: make(map[int]string), uidMin: osutil.UserUidMin},
		portsMap: make(map[osutil.SocketInfo]*procApp),
		fInfo:    make(map[string]*fileInfo),
		startAt:  time.Now(),
	}

	if p.containerStops.Contains(c.id) {
		p.containerStops.Remove(c.id)
	}

	p.containerMap[id] = c
	delete(p.pidContainerMap, pid) // update
	p.pidContainerMap[pid] = c
	p.resetIoNodes = true // JW

	//load the users from container
	if root, min, err := osutil.GetAllUsers(pid, c.userns.users); err == nil {
		c.userns.root = root
		c.userns.uidMin = min
	}

	if scanMode {
		p.inspectFirstContainerProc(proc)
	} else {
		// check if the process is assigned to host before. if so, remove from host
		if c1, ok := p.containerMap[""]; ok && c1.children.Contains(proc.pid) {
			c1.children.Remove(proc.pid)
		}
	}
	log.WithFields(log.Fields{"pid": pid, "id": id, "cnt": len(p.containerMap) - 2}).Debug("PROC: New container")
}

func (p *Probe) addContainerProcess(c *procContainer, pid int) {
	p.pidContainerMap[pid] = c

	// check if the process is assigned to host before. if so, remove from host
	if c.id != "" {
		//	log.WithFields(log.Fields{"pid": pid, "id": c.id}).Debug("")
		if c1, ok := p.containerMap[""]; ok {
			if c1.children.Contains(pid) {
				c1.children.Remove(pid) // nodes has one pool
			}
		}

		if c.id == p.selfID {
			if proc, ok := p.pidProcMap[pid]; ok && isFamilyProcess(c.children, proc) {
				c.children.Add(pid) // make an early decision
			}
		} else {
			c.outsider.Add(pid) // temporary: c.children
		}
	} else {
		c.children.Add(pid) // nodes only has a pool
	}
}

func (p *Probe) cleanupProcessInContainer(id string) {
	// clean up
	if c, ok := p.containerMap[id]; ok {
		for ps := range c.outsider.Union(c.children).Iter() {
			pid := ps.(int)
			if !osutil.IsPidValid(pid) {
				c.children.Remove(pid)
				c.outsider.Remove(pid)
				delete(p.pidProcMap, pid) // bottom-line
				delete(p.pidContainerMap, pid)
			}
		}
	}
}

func (p *Probe) removeProcessInContainer(pid int, id string) {
	containerRemoved := false
	if c, ok := p.containerMap[id]; ok {
		if c.id == "" {
			c.children.Remove(pid)
			return
		}

		// retrive the rootPid
		if c.rootPid == 0 {
			c.rootPid = p.getContainerPid(c.id)
			if id == p.selfID {
				c.children.Add(c.rootPid)
				c.children.Add(p.agentPid)
			}
		}

		if c.rootPid != 0 && c.rootPid == pid { // rootPid exited, remove this container
			containerRemoved = true
		} else {
			c.children.Remove(pid) // it should belong to either one of pools
			c.outsider.Remove(pid)
			if c.children.Cardinality() == 0 && c.outsider.Cardinality() == 0 { // check the pools
				// No process is in this container so we can remove the container
				containerRemoved = true
				if c.rootPid != 0 {
					if _, exist := p.pidProcMap[c.rootPid]; exist {
						// The root process is still alive but has not been learned from the process monitor, we could remove
						// the container accidentally. The following logic is to prevent this.
						log.WithFields(log.Fields{"root": c.rootPid}).Info("PROC: add root process to container")
						p.addContainerProcess(c, c.rootPid)
						containerRemoved = false
					}
				} else {
					// no valid rootPid: it could be a "flash" container, delete it
					// for example: "docker run ubuntu echo 123"
					mLog.WithFields(log.Fields{"pid": pid}).Debug("PROC: orphan container")
				}
			}
		}

		// the container has exited, clean up
		if containerRemoved {
			clearContainerProcesses(c)
			// p.containerStops.Add(c.id)
			delete(p.containerMap, c.id)
			log.WithFields(log.Fields{"pid": pid, "id": c.id, "cnt": len(p.containerMap) - 2}).Debug("PROC: Container remove")
		} else {
			if (c.children.Cardinality() + c.outsider.Cardinality()) > 32 {
				p.cleanupProcessInContainer(id)
			}
		}

		// TODO: what if the container was removed, does it need to remove all netwroking references?
		for _, papp := range c.portsMap {
			if papp.Pids.Contains(pid) {
				papp.Pids.Remove(pid)
			}
		}
	}
}

func unexpectedAgentProcess(name string) bool {
	if global.RT.IsRuntimeProcess(name, nil) {
		return true
	}
	if _, ok := suspicProcMap[name]; ok {
		return true
	}
	return false
}

func (p *Probe) isEnforcerChildren(proc *procInternal, id string) bool {
	if id == p.selfID { // might be too early to get the empty id
		if c, ok := p.containerMap[id]; ok {
			if isFamilyProcess(c.children, proc) {
				return true
			}

			// log.WithFields(log.Fields{"children": c.children.String(), "rootPid": c.rootPid, "oursider": c.outsider.String()}).Debug("PROC:")
			if p.isAgentChild(proc) {
				c.children.Add(proc.pid)
				return true
			}
		}
	}
	return false
}

/* removed by golint
func (p *Probe) evaluateRuncTrigger(id string, proc *procInternal) {
	if id == "" {
		if strings.HasSuffix(proc.path, "/runc") {
			trigger := false
			// runc [global options] command [command options] [arguments...]
			for i, param := range proc.cmds {
				if i == 0 {
					if !strings.Contains(param, "runc") {
						break
					}
					continue
				}

				if strings.HasPrefix(param, "--") { // skip name and global option
					continue
				}

				if param == "start" || param == "kill" {
					trigger = true
				}
				break
			}

			////
			if trigger {
				log.WithFields(log.Fields{
					"parent": proc.pname,
					"ppath":  proc.ppath,
					"name":   proc.name,
					"path":   proc.path,
					"cmd":    proc.cmds,
				}).Debug("PROC: runc trigger")
			}
		}
	}
}
*/

func (p *Probe) evaluateRuntimeCmd(proc *procInternal) bool {
	if global.RT.IsRuntimeProcess(filepath.Base(proc.ppath), nil) {
		if global.RT.IsRuntimeProcess(filepath.Base(proc.path), nil) {
			return true
		}

		// runc [global options] command [command options] [arguments...]
		for i, cmd := range proc.cmds {
			switch i {
			case 0:
				if !global.RT.IsRuntimeProcess(filepath.Base(cmd), nil) {
					return false
				}
			case 1:
				return cmd == "init"
			}
		}
	}
	return false
}

func truncateStrSlices(strs []string, length int) string {
	str := strings.Join(strs, " ")
	if length > 0 {
		if len(str) > length {
			str = str[:length]
			str += "..."
		}
	}
	return str
}

// Debug purpose:
func (p *Probe) printProcReport(id string, proc *procInternal) {
	var s string
	if id == "" {
		s = "[host]"
		// return
	} else if p.isEnforcerChildren(proc, id) {
		// s = "[self]"
		return // hide all information
	} else {
		s = fmt.Sprintf("[%s]", id[:4])
	}

	mLog.WithFields(log.Fields{"id": s,
		"pid":      proc.pid,
		"ppid":     proc.ppid,
		"sid":      proc.sid,
		"pgid":     proc.pgid,
		"user":     proc.user,
		"parent":   proc.pname,
		"ppath":    proc.ppath,
		"name":     proc.name,
		"path":     proc.path,
		"cmd":      truncateStrSlices(proc.cmds, 32),
		"action":   proc.action,
		"riskType": proc.riskType,
	}).Debug("PROC:")

	//  Test sample for performance evaluations
	//	p.sleepTestCounter(proc, c.id)
}

func (p *Probe) isSuspiciousProcess(proc *procInternal, id string) (*suspicProcInfo, bool) {
	if id == "" && proc.name == "sshd" { // exclude sshd from group nodes
		proc.riskType = "" // reset
		return nil, false
	}

	// normal process
	if info, ok := suspicProcMap[proc.name]; ok {
		/// new finding
		proc.riskType = proc.name                // updated
		proc.action = share.PolicyActionCheckApp // tag it
		return info, ok
	} else {
		// keep tracing on target suspicous tree
		if proc.action == share.PolicyActionCheckApp { // parent is suspicious
			proc.riskyChild = true
			return suspicProcMap[proc.riskType], true
		}
		if info, ok = suspicProcMap[proc.pname]; !ok {
			return nil, false
		}

		// children
		proc.riskType = proc.pname               // updated
		proc.action = share.PolicyActionCheckApp // tag it
		proc.riskyChild = true
		return info, ok
	}
}

/*
	 patchRuntimeUser - Patches the process' username on the following condition:
		* If the process' parent is the container daemon, this will update the process' username

The reasoning is:
1. Fixes the bug found in NVSHAS-7054
  - We get a violation report but the effective user reported is the host machine's username
    and not the one in the container.
    2. We're trying to avoid always patching the username because getUserName() will access
    /etc/passwd and we're trying to reduce file accesses.
*/
func (p *Probe) patchRuntimeUser(proc *procInternal) {
	/*
		Don't use the `proc.ppid` because it probably already exited by the time I'm checking.
		We're going to use `proc.pname` instead to check that is from the container daemon.
		Note that `IsRuntimeProcess` only checks the name of the process and not the path, so it might
		still be possible to spoof.

		When i run pstree - i get the actual parent which is containrd-shim which is a RuntimeProcess.
		```
		$ pstree -s -p -a 860138
		systemd,1 splash
		  └─containerd-shim,680237 -namespace moby -idd0c005eb42a045efc1
		      └─top,860138
		```
	*/
	if global.RT.IsRuntimeProcess(proc.pname, nil) {
		if user := p.getUserName(proc.pid, proc.euid); user != proc.user {
			proc.user = user
			mLog.WithFields(log.Fields{"name": proc.name, "pname": proc.pname, "pid": proc.pid, "uid": proc.euid, "user": proc.user}).Debug("Patching user from exec")
		}
	}
}

// TODO, improved it with snapshot, passing by reference for all structures
func (p *Probe) evalNewRunningApp(pid int) {
	p.lockProcMux() // minimum section lock
	c := p.pidContainerMap[pid]
	proc, ok := p.pidProcMap[pid] // bottom-line
	if ok {
		// the same pid might go throuth here twice, do not change its tag
		if proc.action != share.PolicyActionCheckApp {
			if pproc, okp := p.pidProcMap[proc.ppid]; okp {
				proc.riskyChild = pproc.action == share.PolicyActionCheckApp
				proc.action = pproc.action     // put the initial action as same as parent
				proc.riskType = pproc.riskType // then, it will go through the policy screening later
			}
		}

		//// NV5430: possible memory panic condition resulted by "delete(p.pidProcMap, pid)"
		//// clone the proc by a deep-copy
		prc := *proc
		if len(proc.cmds) > 0 {
			prc.cmds = make([]string, len(proc.cmds))
			copy(prc.cmds, proc.cmds)
		}
		proc = &prc
	}
	p.unlockProcMux() // minimum section lock

	if !ok || c == nil {
		// disappeared, short-live application
		return
	}

	// last chance to update fields
	if c.id != "" { // container processes only, skip host processes

		// NVSHAS-7054
		// If an admin did `docker exec` or `kubectl exec` - the child process inherits
		// the parent's /etc/passwd which resides on the host. Since we are in the container
		// (we're doing a check above) - we need to make sure we point to the right /etc/passwd.
		// If we don't point it to the correct one, the alert payload will include the wrong
		// username because we point to the wrong passwd file.
		p.lockProcMux() // minimum section lock
		p.patchRuntimeUser(proc)
		p.unlockProcMux() // minimum section lock

		if proc.cmds != nil && proc.cmds[0] != "sshd:" {
			cmds, _ := global.SYS.ReadCmdLine(proc.pid)
			if cmds != nil && cmds[0] != "" {
				proc.cmds = cmds // caught the last movement
			}
		}

		if path, err := global.SYS.GetFilePath(proc.pid); err == nil { // the latest exe path
			if path != "" && path != "/" {
				proc.path = path // avoid the false condition with not-existed exec path
			}
		}

		if proc.name != "" {
			if proc.action != share.PolicyActionCheckApp { // preserve the suspicious process name
				if _, ok := p.isSuspiciousProcess(proc, c.id); !ok {
					proc.name, _, _, _ = osutil.GetProcessUIDs(proc.pid)
				}
			}
		} else {
			proc.name, _, _, _ = osutil.GetProcessUIDs(proc.pid)
		}
	}

	///////////// Normal decision path  /////////////////
	p.lockProcMux() // minimum section lock
	p.evaluateApplication(proc, c.id, false)

	// update its results
	if _, ok := p.pidProcMap[pid]; ok {
		p.pidProcMap[pid] = proc
	}
	p.unlockProcMux() // minimum section lock
}

func (p *Probe) addContainerCandidateFromProc(proc *procInternal) (*procContainer, bool) {
	c, res := p.addContainerCandidate(proc, false)
	if res == 1 {
		//	log.WithFields(log.Fields{"pid": proc.pid}).Info("PROC: Found new container from process")
		return c, true
	} else if res == 0 { // new container process
		return c, true
	}
	return nil, false
}

// root escalation check
func (p *Probe) rootEscalationCheck(proc *procInternal, c *procContainer) {
	if parent, ok := p.pidProcMap[proc.ppid]; ok {
		// p.updateProcess(proc)
		grandParent, ok := p.pidProcMap[parent.ppid]
		if !ok {
			// some process might change the parent pid, reload it
			p.updateProcess(parent)
			grandParent, ok = p.pidProcMap[parent.ppid]
		}
		if ok {
			//if c is empty, it's host process. check whether the process is inside container,
			//because the user map is different. the root process of a container's parent is host process.
			//make sure the parent and grand parent are in same container(or host)
			if isContainerProcess(c, parent.ppid) {
				//grand parent uid exclude system user < 1000
				if (grandParent.euid-c.userns.root) >= c.userns.uidMin &&
					parent.euid == c.userns.root &&
					proc.euid == c.userns.root {
					if rUser, eUser, notAuth := p.checkUserGroup(grandParent, c); notAuth {
						go p.evalRootEscal(proc, grandParent, c.id, rUser, eUser, c.userns.root)
					}
				}
			}
		}
	}
}

// pidNetlink: authorization from real user
func (p *Probe) checkUserGroup_uidChange(escalProc *procInternal, c *procContainer) (string, string, bool) {
	// verify the user authority
	rUser := p.getUserName(escalProc.pid, escalProc.ruid) // real user
	eUser := p.getUserName(escalProc.pid, escalProc.euid) // effective user

	// should check the "real user" whether it is in the adm, root, sudo groups
	if rUser == "" {
		log.WithFields(log.Fields{"ruid": escalProc.ruid, "euid": escalProc.euid}).Error("Get User name fail")
		return "", "", true
	}

	if auth, err := osutil.CheckUidAuthority(rUser, escalProc.pid); err != nil {
		log.WithFields(log.Fields{"err": err}).Error("Check user authority fail")
		return "", "", true
	} else if auth {
		return "", "", false
	}
	return rUser, eUser, true
}

func (p *Probe) isSudo(pid int) (*procInternal, bool) {
	p.lockProcMux()
	defer p.unlockProcMux()
	if proc, ok := p.pidProcMap[pid]; ok {
		return proc, proc.name == "sudo" || filepath.Base(proc.path) == "sudo"
	}
	return nil, false
}

func (p *Probe) isSudoChild(proc *procInternal) bool {
	if _, ok := p.isSudo(proc.pgid); ok {
		return true
	}

	if _, ok := p.isSudo(proc.sid); ok {
		return true
	}

	ppid := proc.pid          // include itself
	for i := 0; i < 10; i++ { // look up 10 ancesters
		if pp, ok := p.isSudo(ppid); ok {
			return true
		} else {
			if pp == nil { // no more upstream
				break
			}
			if global.RT.IsRuntimeProcess(pp.name, nil) {
				// end of search
				break
			}
			ppid = pp.ppid // next parent
			if ppid == 1 {
				break
			}
		}
	}
	return false
}

// pidNetlink: root escalation check
func (p *Probe) rootEscalationCheck_uidChange(proc *procInternal, c *procContainer) {
	p.lockProcMux() // minimum section lock
	parent, ok := p.pidProcMap[proc.ppid]
	if !ok { // parent has not been caught
		if !osutil.IsPidValid(proc.ppid) {
			log.WithFields(log.Fields{"ppid": proc.ppid, "pid": proc.pid}).Debug("PROC: parent exited")
			p.unlockProcMux() // minimum section lock
			return
		}

		now := time.Now()
		parent = &procInternal{
			pid:          proc.ppid,
			ppid:         proc.ppid,
			sid:          proc.sid,
			pgid:         proc.pgid,
			startTime:    now,
			lastScanTime: now,
			action:       share.PolicyActionAllow,
		}

		// construct parent process
		p.updateProcess(parent)                              // get name, ppid, ruid, euid
		parent.user = p.getUserName(parent.pid, parent.euid) // get parent's username
		parent.path, _ = global.SYS.GetFilePath(parent.pid)  // get parent's executable name
		p.pidProcMap[parent.pid] = parent
		p.addContainerProcess(c, parent.pid) // add parent
		log.WithFields(log.Fields{"pid": parent.pid, "ruid": parent.ruid}).Debug("PROC: patch parent")
	}
	p.unlockProcMux() // minimum section lock

	if (parent.reported & escalatReported) > 0 {
		return
	}

	if proc.ruid == parent.ruid { // no change by real user id
		return
	}

	// Wait 100ms and see if euid drops to normal user
	time.Sleep(time.Millisecond * 100)
	if !osutil.IsPidValid(proc.pid) {
		log.WithFields(log.Fields{"proc": proc}).Debug("skip short-lived")
		return
	}

	p.updateProcess(proc)
	if proc.ruid == parent.ruid { // no change by real user id
		return
	}

	// log.WithFields(log.Fields{"parent": parent, "c.userns": c.userns}).Debug("PROC:")
	log.WithFields(log.Fields{"parent": parent.ruid, "current": proc.ruid}).Debug("PROC:")
	// ruid_rebased >= uidMin  && euid == root
	if (parent.ruid-c.userns.root) >= c.userns.uidMin && // valid user range
		proc.ruid == c.userns.root { // user at root privilege level
		p.updateProcess(parent) // obtain latest parent data

		p.lockProcMux() // minimum section lock
		_, _, notAuth := p.checkUserGroup_uidChange(parent, c)
		p.unlockProcMux() // minimum section lock

		if notAuth {
			if len(parent.cmds) == 0 {
				parent.cmds, _ = global.SYS.ReadCmdLine(proc.ppid)
			}

			if p.isSudoChild(proc) {
				return
			}

			// skip: "-bash" is a command when: (1) "a sshd session" (2) "sudo -i" in the ssh session (filtered above)
			if parent.pname == "sshd" {
				if len(parent.cmds) > 0 && parent.cmds[0] == "-bash" {
					// log.Debug("PROC: skip sshd")
					return
				}
			}

			// report its grand parent (useful for user to find the root cause)
			if parent.pid != parent.ppid { // not from the lost parent link
				var gp *procInternal
				p.lockProcMux() // minimum section lock
				gp, ok = p.pidProcMap[parent.ppid]
				p.unlockProcMux() // minimum section lock
				if ok {
					if len(gp.cmds) == 0 {
						gp.cmds, _ = global.SYS.ReadCmdLine(gp.pid)
					}

					// filter false-positive cases: grandparent is root
					if gp.ruid == 0 {
						mLog.WithFields(log.Fields{"grandparent": gp}).Debug()
						return
					}

					// found it
					log.WithFields(log.Fields{"grandparent": gp}).Debug("PROC: ")
					log.WithFields(log.Fields{"parent": parent}).Debug("PROC: ")
					log.WithFields(log.Fields{"proc": proc}).Debug("PROC: ")
					// uid tuple: (euid, ruid)
					// userapp(user, user) -> shell cmd(user, user) [report] -> children(root, root)
					p.reportEscalation(c.id, parent, gp)
				}
			}
		}
	}
}

func (p *Probe) handleProcFork(pid, ppid int, name string) (inContainer bool, pc *procInternal, pp *procInternal) {
	var insideContainer bool
	now := time.Now()

	// log.Debug("PROC: fork: ", ppid, "->", pid)
	p.addProcessPool(pid, ppid)

	// dynamic allocation
	proc := &procInternal{
		name:         name,
		pid:          pid,
		ppid:         ppid,
		sid:          osutil.GetSessionId(pid),
		pgid:         osutil.GetProcessGroupId(pid),
		startTime:    now,
		lastScanTime: now,
		action:       share.PolicyActionAllow,
	}

	if parent, ok := p.pidProcMap[proc.ppid]; ok {
		// Inherit parent's information
		proc.pname = parent.name
		proc.ppath = parent.path

		proc.user = parent.user
		proc.ruid = parent.ruid // assumed, if modified, it should be updated by UID change event
		proc.euid = parent.euid

		// tag the child
		if parent.action == share.PolicyActionCheckApp {
			proc.action = parent.action
			proc.riskType = parent.riskType
		}

		// pick up the late information
		if proc.user == "" {
			proc.user = p.getUserName(proc.ppid, proc.euid) // get parent's username
		}
		if proc.pname == "" {
			proc.pname, _, _, _ = osutil.GetProcessUIDs(proc.ppid) // get parent's name
		}
		if proc.ppath == "" {
			proc.ppath, _ = global.SYS.GetFilePath(proc.ppid) // get parent's executable name
		}

		if exist, ok := p.pidProcMap[proc.pid]; ok {
			// state machine acts like a LIFO or realigned mode?, EXEC before FORK event
			if c, ok := p.pidContainerMap[proc.pid]; ok {
				insideContainer = c.id != ""
				proc.ppid = ppid
			} else {
				if c1, ok := p.addContainerCandidateFromProc(proc); ok {
					insideContainer = c1.id != ""
				} else { // a hole by reBuiltProcessTables
					//	log.WithFields(log.Fields{"pid": pid, "ppid": ppid}).Debug("PROC: Process not in conatiner map")
					insideContainer = false // assume
				}
			}

			proc.action = exist.action
			proc.reported = exist.reported
			p.pidProcMap[proc.pid] = proc
			return insideContainer, proc, nil
		} else {
			p.pidProcMap[proc.pid] = proc // new into process map
			p.inspectProcess.Add(proc)
		}

		if c, ok := p.pidContainerMap[proc.ppid]; ok {
			insideContainer = c.id != ""
			// If parent is in the container, the child is too
			p.addContainerProcess(c, proc.pid)
		}
	} else {
		// log.WithFields(log.Fields{"pid": pid, "ppid": ppid, "name": name}).Debug("Process parent not in map")
		// dynamic allocations
		proc_p := &procInternal{
			pid:          ppid,
			ppid:         ppid,
			sid:          proc.sid,
			startTime:    now,
			lastScanTime: now,
			action:       share.PolicyActionAllow,
		}

		// construct parent process
		p.updateProcess(proc_p)                              // get name, ppid, ruid, euid
		proc_p.user = p.getUserName(proc_p.pid, proc_p.euid) // get parent's username
		proc_p.path, _ = global.SYS.GetFilePath(ppid)        // get parent's executable name

		// current child proc
		proc.user = proc_p.user
		proc.pname = proc_p.name
		proc.ppath = proc_p.path
		proc.ruid = proc_p.ruid
		proc.euid = proc_p.euid

		/////
		p.pidProcMap[proc_p.pid] = proc_p
		p.pidProcMap[proc.pid] = proc
		p.inspectProcess.Add(proc_p)
		p.inspectProcess.Add(proc)

		// check parent if the /proc/xxx/cgroup exists
		var id string
		if c1, ok := p.addContainerCandidateFromProc(proc_p); ok {
			insideContainer = true
			id = c1.id // just copy id
		}

		if c, ok := p.containerMap[id]; ok {
			p.addContainerProcess(c, proc_p.pid) // add parent
			p.addContainerProcess(c, proc.pid)   // add child
		} else { // should not occur
			log.WithFields(log.Fields{"pid": pid, "ppid": ppid, "id": id}).Debug("Process not in a map: map not found")
		}
		return insideContainer, proc, proc_p
	}

	//// for loop thread
	return insideContainer, proc, nil
}

func (p *Probe) handleProcExec(pid int, bInit bool) (bKubeProc bool) {
	// log.Debug("PROC: exec: ", pid)
	var proc *procInternal
	var c, c1 *procContainer
	var id string = ""
	var ok, bEvalFlag bool

	if proc, ok = p.pidProcMap[pid]; ok {
		if c, ok = p.pidContainerMap[pid]; ok {

			//escalation check
			if !p.pidNetlink {
				p.rootEscalationCheck(proc, c)
			}

			id = c.id
			if p.pidNetlink && id == "" { // for docker run
				// patch for older docker version realtime event glitches
				// Older docker (re)assigns cgroup attributes for all worker
				// after its "setkey" operations
				if c1, ok = p.addContainerCandidateFromProc(proc); ok {
					id = c1.id // just copy id
				}
			}

			if path, err := global.SYS.GetFilePath(proc.pid); err == nil { // the latest exe path
				if path != "" && path != "/" {
					proc.path = path // avoid the false condition with not-existed exec path
				}
			}

			if proc.cmds == nil {
				proc.cmds, _ = global.SYS.ReadCmdLine(proc.pid)
			}

			if proc.name != "" {
				if _, ok := p.isSuspiciousProcess(proc, id); !ok {
					proc.name, _, _, _ = osutil.GetProcessUIDs(proc.pid)
				}
			} else {
				proc.name, _, _, _ = osutil.GetProcessUIDs(proc.pid)
			}

			bEvalFlag = !p.isDockerDaemonProcess(proc, id)
		}
	} else { // for docker exec at container creations
		if p.pidNetlink {
			now := time.Now()
			proc = &procInternal{
				pid:          pid,
				ppid:         pid, // assume
				sid:          osutil.GetSessionId(pid),
				startTime:    now,
				lastScanTime: now,
				action:       share.PolicyActionAllow,
			}

			if c1, ok = p.addContainerCandidateFromProc(proc); ok {
				id = c1.id // just copy id
				p.pidProcMap[proc.pid] = proc
				proc.user = p.getUserName(proc.ppid, proc.euid) // get parent's username
				proc.path, _ = global.SYS.GetFilePath(proc.pid) // exe path
				proc.cmds, _ = global.SYS.ReadCmdLine(proc.pid)
				proc.name, _, _, _ = osutil.GetProcessUIDs(proc.pid)
				bEvalFlag = !p.isDockerDaemonProcess(proc, id)
			}
		} else {
			// no valid proc instance
			return false
		}

	}

	if proc.path != "" && proc.path != "/" {
		p.addProcHistory(id, proc, true) // every detected exec events
	}

	// avoid locks
	if bEvalFlag && proc.name != "" {
		//		if proc.path != "" && proc.path != "/"{
		//			p.addProcHistory(id, proc, true) // every detected exec events
		//		}

		if bInit {
			go p.evalNewRunningApp(proc.pid) // no sequential issue
		} else {
			cur := len(p.chanEvalAppPid)
			if cur == cap(p.chanEvalAppPid) {
				log.WithFields(log.Fields{"id": id, "proc": proc.name}).Error("PROC: chan overflow, ignore")
			} else {
				p.chanEvalAppPid <- proc.pid
				cur++ // added
				if cur > p.profileMaxChanEvalCnt {
					p.profileMaxChanEvalCnt = cur
				}
			}
		}
	}

	//////
	if proc != nil {
		if p.isKubeProcess(proc) {
			return p.informKubeBench(proc)
		}
	}
	return false
}

func (p *Probe) removeDelayExitProc() {
	p.lockProcMux()
	defer p.unlockProcMux()
	index := -1
	count := 0
	for i, dep := range p.exitProcSlices {
		if time.Since(dep.last) < delayExitThreshold {
			index = i
			break
		}
		count++
		delete(p.pidProcMap, dep.pid)
		p.removeProcessInContainer(dep.pid, dep.id)
		delete(p.pidContainerMap, dep.pid)
	}

	if index == -1 {
		if count > 0 {
			p.exitProcSlices = nil
		}
	} else {
		p.exitProcSlices = p.exitProcSlices[index:]
	}
}

func (p *Probe) handleProcExit(pid int) *procInternal {
	// log.Debug("PROC: exit: ", pid)
	if proc, ok := p.pidProcMap[pid]; ok {
		if c, ok := p.pidContainerMap[pid]; !ok {
			delete(p.pidProcMap, pid)
			delete(p.pidContainerMap, pid)
		} else if c.id == "" { // exclude host processes
			delete(p.pidProcMap, pid)
			p.removeProcessInContainer(pid, c.id)
			delete(p.pidContainerMap, pid)
		} else {
			p.exitProcSlices = append(p.exitProcSlices, &procDelayExit{pid: pid, id: c.id, last: time.Now()})
		}
		return proc
	}
	return nil
}

// after FORK event but before EXEC
func (p *Probe) handleProcUIDChange(pid, ruid, euid int) {
	if !p.bProfileEnable {
		return
	}
	if proc, ok := p.pidProcMap[pid]; ok {
		if (proc.reported & escalatReported) > 0 {
			return
		}

		if proc.ruid == ruid && proc.euid == euid {
			// no change, skip further comparisons
			return
		}

		proc.user = p.getUserName(pid, euid)
		proc.ruid = ruid
		proc.euid = euid
		if c, ok := p.pidContainerMap[pid]; ok {
			p.printProcReport(c.id, proc)
			go p.rootEscalationCheck_uidChange(proc, c)
		}
	}
}

// updateUserNames - Updates the username map by going to /etc/passwd
func (p *Probe) getUpdatedUsername(pid int, uid int) string {
	// Get the container for our pid
	if c, ok := p.pidContainerMap[pid]; ok {
		// Update the usernames map
		if root, min, err := osutil.GetAllUsers(c.rootPid, c.userns.users); err == nil {
			c.userns.root = root
			c.userns.uidMin = min
			return c.userns.users[uid]
		}
	}

	return ""
}

func (p *Probe) getUserName(pid, uid int) (user string) {
	if c, ok := p.pidContainerMap[pid]; ok {
		var ok bool
		if user, ok = c.userns.users[uid]; !ok {
			if root, min, err := osutil.GetAllUsers(pid, c.userns.users); err == nil {
				user = c.userns.users[uid]
				c.userns.root = root
				c.userns.uidMin = min
			}
		}
	}
	return
}

// Note: c can be empty, then it's a host process
func (p *Probe) checkUserGroup(escalProc *procInternal, c *procContainer) (string, string, bool) {
	// verify the user authority
	rUser := p.getUserName(escalProc.pid, escalProc.ruid)
	eUser := p.getUserName(escalProc.pid, escalProc.euid)

	if eUser == "" {
		log.WithFields(log.Fields{"ruid": escalProc.ruid, "euid": escalProc.euid}).Error("Get User name fail")
		return "", "", false
	}

	if auth, err := osutil.CheckUidAuthority(eUser, escalProc.pid); err != nil {
		log.WithFields(log.Fields{"err": err}).Error("Check user authority fail")
		return "", "", false
	} else if auth {
		return "", "", false
	}
	return rUser, eUser, true
}

// Not pidNetlink: escalProc is the grandparent of proc.
func (p *Probe) evalRootEscal(proc, escalProc *procInternal, id, rUser, eUser string, root int) {
	var cmds, escalCmds []string
	var err error
	retry := 0
	for retry < 10 {
		cmds, err = global.SYS.ReadCmdLine(proc.ppid)
		if err != nil {
			time.Sleep(time.Millisecond * 100)
		} else {
			break
		}
		retry++
	}

	// check the parent process whether it is sudo/su
	// user -> sudo(root) -> program(root)
	if len(cmds) == 0 || cmds[0] == "" || cmds[0] == "su" || cmds[0] == "sudo" {
		return
	}

	// We've seen a case where the grantparent process has a sudo in the command line but user is not root
	//    Command="sudo /home/ec2-user/dns_check_eddie.sh" Effective-user=ec2-user
	// So we double check the grand parent whether it is sudo/su
	// sudo(user) -> program(root)->program(root)
	if escalCmds, err = global.SYS.ReadCmdLine(escalProc.pid); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Read escalation command line fail")
		return
	}

	if len(escalCmds) == 0 || escalCmds[0] == "" || escalCmds[0] == "su" || escalCmds[0] == "sudo" {
		return
	}

	// Wait 500ms and see if euid drops to normal user
	time.Sleep(time.Millisecond * 500)

	// proc euid info is read from /proc/ file, it's very unlikely we happen to hit the
	// window when a process is just created with root privilege before it drops.
	// proc.euid is still right. If we did hit that window, we could have fp and fn.
	if _, ppid, _, euid := osutil.GetProcessUIDs(proc.pid); ppid > 0 &&
		(euid-root) == 0 {
		p.reportEscalation(id, escalProc, proc)
	}
}

func (p *Probe) reportEscalation(id string, proc, parent *procInternal) {
	if (proc.reported & escalatReported) > 0 {
		return
	}

	p.lockProcMux()
	effective_user := p.getUserName(proc.pid, proc.euid)
	p.unlockProcMux()

	e := &ProbeEscalation{
		ID:       id,
		Pid:      proc.pid,
		Name:     proc.name,
		Path:     proc.path,
		Cmds:     proc.cmds,
		RUid:     proc.ruid,
		EUid:     proc.euid,
		RealUser: proc.user,
		EffUser:  effective_user,

		// parent info
		ParentPid:  parent.pid,
		ParentName: parent.name,
		ParentPath: parent.path,
		ParentCmds: parent.cmds,

		Msg: "Unauthorized root privilege escalation!",
	}

	rpt := ProbeMessage{Type: PROBE_REPORT_ESCALATION, Escalation: e, ContainerIDs: utils.NewSet(id)}
	p.SendAggregateProbeReport(&rpt, false)
	proc.reported |= escalatReported
	log.WithFields(log.Fields{"pid": proc.pid, "ppid": proc.ppid}).Info("Root escalation!")
}

func (p *Probe) updateProcess(proc *procInternal) {
	if name, ppid, ruid, euid := osutil.GetProcessUIDs(proc.pid); ppid >= 0 {
		proc.name = name
		proc.ppid = ppid
		proc.ruid = ruid
		proc.euid = euid
	}

	// undefined
	if proc.sid == 0 {
		proc.sid = osutil.GetSessionId(proc.pid)
		proc.pgid = osutil.GetProcessGroupId(proc.pid)
	}
}

func (p *Probe) informKubeBench(proc *procInternal) bool {
	log.WithFields(log.Fields{"proc": proc.name, "pid": proc.pid}).Debug()
	if proc.name == "hyperkube" {
		if cmds, err := global.SYS.ReadCmdLine(proc.pid); err == nil && len(cmds) > 1 {
			if cmds[1] == "kubelet" || cmds[1] == "kube-apiserver" { // not for kube-proxy (ibm) and other system pods from hyperkube
				p.rerunKubeBench(cmds[1], proc.name+" "+cmds[1])
				return true
			}
		}
	} else {
		p.rerunKubeBench(proc.name, proc.name)
		return true
	}
	return false
}

func (p *Probe) buildProcessMap(pids utils.Set) map[int]*procInternal {
	procMap := make(map[int]*procInternal)
	for pid := range pids.Iter() {
		if name, ppid, ruid, euid := osutil.GetProcessUIDs(pid.(int)); ppid >= 0 {
			//not set start time, because it already start long time
			cmds, _ := global.SYS.ReadCmdLine(pid.(int))
			path, _ := global.SYS.GetFilePath(pid.(int))
			procMap[pid.(int)] = &procInternal{
				name:      name,
				pid:       pid.(int),
				sid:       osutil.GetSessionId(pid.(int)),
				ppid:      ppid,
				ruid:      ruid,
				euid:      euid,
				path:      path,
				cmds:      cmds,
				action:    share.PolicyActionAllow,
				startTime: time.Now(), // best offer
				scanTimes: 0,          // For preexisting containers, still scan multiple times
			}
		} else {
			// Parent cannot be found means child's /proc directory is not ready yet,
			// remove from PID set, so we can pick it up next time.
			pids.Remove(pid)
		}
	}
	return procMap
}

func (p *Probe) isKubeProcess(proc *procInternal) bool {
	// TODO: Need to use cmdline or exe name to distinguish the process, not process name
	executable := filepath.Base(proc.path)
	if _, ok := kubeProcs[proc.name]; ok {
		return true
	}

	if _, ok := kubeProcs[executable]; ok {
		return true
	}
	return false
}

// at the beginning, build the container process tree once by snapshot
func (p *Probe) initReadProcesses() bool {
	log.Debug("")
	var foundKube bool

	p.pidSet = osutil.GetAllProcesses()
	p.pidProcMap = p.buildProcessMap(p.pidSet)
	for _, proc := range p.pidProcMap {
		p.newProcesses.Add(proc)
		if p.isKubeProcess(proc) {
			foundKube = p.informKubeBench(proc)
		} else {
			p.inspectProcess.Add(proc)
		}
	}
	p.walkNewProcesses()
	p.inspectNewProcesses(true) // catch existing processes
	return foundKube
}

func (p *Probe) addContainerCandidate(proc *procInternal, scanMode bool) (*procContainer, int) {
	var c *procContainer
	var ok bool

	// check if the /proc/xxx/cgroup exists
	id, containerInContainer, err, found := global.SYS.GetContainerIDByPID(proc.pid)
	if !found {
		if osutil.IsPidValid(proc.pid) {
			log.WithFields(log.Fields{"error": err}).Debug()
		}
		return nil, -1 // not ready
	}

	// In container-in-container enviroment, the id should be container-in-container type.
	if p.containerInContainer && !containerInContainer {
		//put parent container processes into host
		id = ""
	}

	// container process
	c, ok = p.containerMap[id]
	if ok {
		p.addContainerProcess(c, proc.pid) // add container process for scan mode only
		return c, 0                        // previous
	}

	if id == "" {
		p.addHost(proc.pid)
	} else {
		p.addContainer(id, proc, scanMode)
	}
	return p.containerMap[id], 1
}

// walk through the new processes, check which container it belongs to
func (p *Probe) walkNewProcesses() {
	for pc := range p.newProcesses.Iter() {
		proc := pc.(*procInternal)
		_, res := p.addContainerCandidate(proc, true)
		if res == -1 {
			if proc.retry >= retryReadProcMax { // 3-4 sec span
				p.newProcesses.Remove(proc)
			}
			proc.retry++
			continue
		}
		p.newProcesses.Remove(proc)
	}
}

// process scan mode, find out parent first, and then their children
// simulate behavial of the netlink mode, create parent process first and then children
func (p *Probe) scanNewProcess(pids utils.Set) {
	var proc *procInternal
	var finish, ok bool

	///
	newsMap := make(map[int]*procInternal)
	//scan new process top to bottom, from parent to child
	for !finish && pids.Cardinality() > 0 {
		finish = true

		for itr := range pids.Iter() {
			pid := itr.(int)
			var ppid, ruid, euid int
			var name string
			if proc, ok = newsMap[pid]; !ok {
				if name, ppid, ruid, euid = osutil.GetProcessUIDs(pid); ppid < 0 {
					//if the ppid < 0, the process might have disappeared, or not ready
					//do not remove it here, and keep it in fork. let the upper layer to remove it
					//if we remove it here, we will miss a process, if it is not ready
					continue
				} else {
					proc = &procInternal{
						name: name,
						pid:  pid,
						ppid: ppid,
						sid:  osutil.GetSessionId(pid),
						ruid: ruid,
						euid: euid,
					}
					newsMap[pid] = proc
				}
			}

			//if its parent in the pidProcMap, handle and remove it, otherwise wait for next round
			if _, ok = p.pidProcMap[proc.ppid]; ok {
				insideContainer, proc_c, proc_p := p.handleProcFork(pid, proc.ppid, name)

				//// for host processes
				if !insideContainer {
					p.newProcesses.Add(proc_c)
					if proc_p != nil {
						p.newProcesses.Add(proc_p)
					}
				}

				p.handleProcUIDChange(pid, proc.ruid, proc.euid)
				pids.Remove(pid)
				delete(newsMap, pid)
				finish = false
			}
		}
	}
}

// Trigger when stdin and stdout are redirected to socket and have the same inode
func (p *Probe) checkReverseShell(pid int) *osutil.Connection {
	inodeStdin, err := osutil.GetFDSocketInode(pid, 0)
	if err != nil {
		return nil
	}
	inodeStdout, err := osutil.GetFDSocketInode(pid, 1)
	if err != nil {
		return nil
	}
	if inodeStdin != inodeStdout || inodeStdin == 0 {
		return nil
	}
	return osutil.GetProcessConnection(pid, nil, utils.NewSet(inodeStdin))
}

const suspicProcInspectTimes uint = 2

func (p *Probe) skipSuspicious(id string, proc *procInternal) (bool, bool) {
	//scp will be logged twice, one is ssh, the other is scp
	//for sshd, remove the daemon and tmp sshd from the list
	var bSshdDashD bool
	//ssh has three layers: daemon --> backend "sshd -D -R" or "sshd: [accepted]")--> sshd session
	//we only need to report the sshd session, skip those middle processes.
	if proc.name == "sshd" {
		// "-R" is a replicate of sshd
		for _, cmd := range proc.cmds {
			if cmd == "-R" {
				return true, true
			}

			if cmd == "-D" {
				bSshdDashD = true
			}
		}

		//
		if len(proc.cmds) == 1 {
			if strings.HasPrefix(proc.cmds[0], "sshd:") { // skip sshd status(optional): username, pts, etc.
				// log.WithFields(log.Fields{"cmds": proc.cmds}).Debug("PROC: sshd status")
				return true, true
			}
			// Skip execute itself without a parameter
			// log.WithFields(log.Fields{"cmds": proc.cmds, "len": len(proc.cmds)}).Debug("PROC: sshd len=1")
			return proc.cmds[0] == proc.name, true
		}
	} else if proc.name == "nc" || proc.name == "ncat" || proc.name == "netcat" { // possible health check application
		if id == "" { // The health check is not valid for the node(host)
			return false, false
		}
		bHasLocalAddr := false
		bHasTimeoutOption := false
		for _, cmd := range proc.cmds {
			// log.WithFields(log.Fields{"cmd": cmd}).Debug("PROC:")
			if cmd == "-l" { // listening mode: nc server
				return false, false
			}

			if cmd == "localhost" || cmd == "127.0.0.1" { // local host or loopback interface
				bHasLocalAddr = true
			}

			if strings.HasPrefix(cmd, "-w") { // connection timeout: the health check needs a timeout to report the condition
				bHasTimeoutOption = true
			}
		}
		return bHasLocalAddr && bHasTimeoutOption, true
	}

	// Not to log host's sshd children as risky
	if id == "" && proc.riskType == "sshd" && !bSshdDashD {
		// log.WithFields(log.Fields{"cmds": proc.cmds}).Debug("PROC: sshd skip")
		return true, false
	}

	// "process name" keeps changing and is not good for a reference
	if proc.path != proc.ppath || proc.name != proc.pname {
		if proc.riskType == "sshd" && proc.cmds[0] != "sshd:" { // for sshd only
			proc.cmds = append([]string{"sshd:"}, proc.cmds...)
		}
		return false, false // a new executable
	}

	// Check whether its suspicious parent has been allowed by rules.
	ppid := proc.ppid
	for i := 0; i < 10; i++ { // lookup 10 ancestries
		if pproc, ok := p.pidProcMap[ppid]; !ok {
			break // no parent process for reference
		} else {
			if global.RT.IsRuntimeProcess(pproc.name, nil) {
				mLog.WithFields(log.Fields{"name": pproc.name, "id": id}).Debug("PROC: not child")
				break
			}

			if pproc.name == proc.riskType {
				if action, ok := p.procProfileEval(id, pproc, true); ok && action == share.PolicyActionAllow {
					// parent has been allowed
					mLog.WithFields(log.Fields{"name": pproc.name, "id": id}).Debug("PROC: allowed")
					return true, false //
				}
				mLog.WithFields(log.Fields{"name": pproc.name, "id": id}).Debug("PROC: not allowed")
				break
			}
			ppid = pproc.ppid
			if ppid == 1 && id == "" {
				break
			}
		}
	}
	return true, false
}

// Application event handler: locked by calling functions
func (p *Probe) evaluateApplication(proc *procInternal, id string, bKeepAlive bool) {
	if !p.bProfileEnable {
		return
	}

	if proc.path == "" || proc.path == "/" {
		// path is required, it can not be either "" or "/".
		// log.WithFields(log.Fields{"proc": proc}).Debug("PROC: ignored, no path")
		return
	}

	// only allowing the NS op from the agent's root session
	if p.isEnforcerChildren(proc, id) {
		// log.WithFields(log.Fields{"proc": proc, "id": id}).Debug("PROC: ignored")
		return
	}

	if id != "" && p.evaluateRuntimeCmd(proc) {
		return
	}

	p.printProcReport(id, proc)
	// p.evaluateRuncTrigger(id, proc)
	riskyReported := (proc.reported & (suspicReported | profileReported)) != 0 // could be reported as profile/risky event

	// use the executable as the name
	proc.name = strings.TrimSpace(proc.name)
	if proc.name == "" {
		proc.name = filepath.Base(proc.path) // path is not an empty string
		if proc.name == "busybox" {          // it could be a subcommand
			if proc.cmds != nil {
				if subcmd := filepath.Base(proc.cmds[0]); subcmd != "." && subcmd != "/" { // not an empty pathqq
					proc.name = subcmd
					// log.WithFields(log.Fields{"name": proc.name, "pid": proc.pid}).Debug("PROC: patch busybox")
				}
			}
		}
	}

	if proc.name == "" {
		log.WithFields(log.Fields{"proc": proc}).Debug("PROC: empty name")
		return
	}

	if proc.cmds == nil || proc.cmds[0] == "" {
		if proc.cmds == nil {
			proc.cmds = append(proc.cmds, proc.name)
		}

		if proc.cmds[0] == "" {
			proc.cmds[0] = proc.name
		}
	}

	// NVSHAS-7054
	// If an admin did `docker exec` or `kubectl exec` - the child process inherits
	// the parent's /etc/passwd which resides on the host. Since we are in the container
	// (we're doing a check above) - we need to make sure we point to the right /etc/passwd.
	// If we don't point it to the correct one, the alert payload will include the wrong
	// username because we point to the wrong passwd file.
	p.patchRuntimeUser(proc)

	var action string
	var bSkipReport, ok, bSkipEval bool
	if !riskyReported {
		// evaluate every unreported process
		_, ok := p.isSuspiciousProcess(proc, id)
		if ok {
			bSkipReport, bSkipEval = p.skipSuspicious(id, proc)
			log.WithFields(log.Fields{"name": proc.name, "pid": proc.pid, "bSkipReport": bSkipReport, "bSkipEval": bSkipEval}).Debug("PROC: Risky app detected")
			if bSkipReport && bSkipEval {
				return // no need to evaluate or reporting
			}
		}
	}

	risky := proc.action == share.PolicyActionCheckApp
	if action, ok = p.procProfileEval(id, proc, bKeepAlive); !ok {
		return // policy is not ready
	}

	// the very first parent, update a decision (allow or checkApp),
	// (1) "checkApp" behaves the same reponding action as the "deny" among different policy modes
	// (2) "checkApp" (including children) will not enter the "learned" process group.
	// it lasts for its whole life until the calling updateCurrentRiskyAppRule() from upper layer
	if risky && action == share.PolicyActionAllow {
		proc.action = share.PolicyActionAllow // updated with Allow
		risky = false
	}
	mLog.WithFields(log.Fields{"name": proc.name, "pid": proc.pid, "path": proc.path, "action": action, "risky": risky}).Debug("PROC: Result")

	// it has not been reported as a profile/risky event
	riskyReported = (proc.reported & (suspicReported | profileReported)) != 0
	if risky && !riskyReported {

		proc.user = p.getUpdatedUsername(proc.pid, proc.euid)

		riskInfo := suspicProcMap[proc.riskType]
		if riskInfo == nil {
			mLog.WithFields(log.Fields{"pid": proc.pid, "riskType": proc.riskType}).Debug("PROC: risky info missing")
		}

		if riskInfo != nil {
			proc.reported |= suspicReported // do it once
			if bSkipReport {
				mLog.WithFields(log.Fields{"name": proc.name, "pid": proc.pid, "ppid": proc.ppid, "cmds": truncateStrSlices(proc.cmds, 32)}).Debug("PROC: Skip report suspicious application")
				return
			}

			go func() {
				msg := "Risky application: " + riskInfo.msg
				ingress := riskInfo.ingress
				p.reportRiskyApp(id, proc, msg, ingress)
				log.WithFields(log.Fields{"name": proc.name, "pid": proc.pid, "ppid": proc.ppid}).Info("Report suspicious application")
			}()
		}
	}

}

func (p *Probe) checkReversedShellProcess(id string, proc *procInternal) bool {
	insideContainer := id != ""
	// check reverse shell
	// to avoid detect "sshd -R" as reverse shell, take two-step check, set report flag first, then confirm.
	if ((proc.reported&reversShReported) == 0 ||
		(proc.reported&reversShConfirmed) == 0) &&
		proc.name != "sshd" {
		if conn := p.checkReverseShell(proc.pid); conn != nil {
			if (proc.reported & reversShReported) == 0 { // reported
				proc.reported |= reversShReported
				log.WithFields(log.Fields{"name": proc.name, "pid": proc.pid}).Debug("Initial report reverse shell")
			} else { // confirmed
				if proc.cmds == nil {
					proc.cmds, _ = global.SYS.ReadCmdLine(proc.pid)
				}

				go func() {
					group, _, _ := p.getServiceGroupName(id)
					s := p.makeProcessReport(id, proc, "Tunnel detected: reverse shell", conn, false, group, share.CLUSReservedUuidTunnelProc)
					rpt := ProbeMessage{Type: PROBE_REPORT_TUNNEL, Process: s, ContainerIDs: utils.NewSet(id)}
					p.SendAggregateProbeReport(&rpt, false)
					log.WithFields(log.Fields{"name": proc.name, "pid": proc.pid}).Info("Confirm report reverse shell")
				}()

				proc.reported |= reversShConfirmed
				return true
			}
		}
	}

	// keep it for reverse shell incident monitor
	proc.inspectTimes++
	// sshd has a transit process (sometimes with command line as 'sshd -R') that matches the reverse shell check,
	// so we wait more cycles to mitigate this false-positive.
	// Apply the same logic if process name is empty, or as 'runc', which can also be a transit state.
	if (proc.reported&reversShReported) == reversShReported ||
		proc.name == "" ||
		(insideContainer && global.RT.IsRuntimeProcess(proc.name, nil)) {
		if proc.inspectTimes >= (suspicProcInspectTimes + 2) {
			return true
		}
	} else if proc.inspectTimes > suspicProcInspectTimes {
		return true
	}
	return false
}

func (p *Probe) inspectNewProcesses(bInit bool) {
	p.lockProcMux()
	defer p.unlockProcMux()

	//move suspicious process check after walkNewProcesses, so we can know which container the process belonging to.
	for itr := range p.inspectProcess.Iter() {
		proc := itr.(*procInternal)
		if c, ok := p.pidContainerMap[proc.pid]; ok {
			insideContainer := c.id != ""
			if proc.user == "" {
				proc.user = p.getUserName(proc.pid, proc.euid)
			}

			if proc.path == "" {
				proc.path, _ = global.SYS.GetFilePath(proc.pid)
			}

			if proc.name == "" || (insideContainer && global.RT.IsRuntimeProcess(proc.name, nil)) {
				proc.name, _, _, _ = osutil.GetProcessUIDs(proc.pid)
			}

			// scan mode and initial setup only, avoid duplicate report
			if !p.pidNetlink || bInit {
				// enter decision procedure
				if proc.name != "" && proc.path != "" {
					if !proc.execScanDone {
						proc.execScanDone = true
						if p.handleProcExec(proc.pid, true) {
							p.inspectProcess.Remove(itr)
						}
					}
				}
			}

			if proc.path != "" {
				// update user name
				proc.user = p.getUserName(proc.pid, proc.euid)
			}

			if p.checkReversedShellProcess(c.id, proc) {
				p.inspectProcess.Remove(itr) // either reported or expired
			}
		} else {
			p.inspectProcess.Remove(itr) // disappeared
			p.newProcesses.Remove(itr)
		}
	}
}

func (p *Probe) makeProcessReport(id string, proc *procInternal, msg string, conn *osutil.Connection, ingress bool, group, ruleID string) *ProbeProcess {
	s := &ProbeProcess{
		ID:          id,
		Cmds:        proc.cmds,
		Path:        proc.path,
		Name:        proc.name,
		Pid:         proc.pid,
		EUid:        proc.euid,
		EUser:       proc.user,
		PPid:        proc.ppid,
		PName:       proc.pname,
		PPath:       proc.ppath,
		Connection:  conn,
		ConnIngress: ingress,
		RuleID:      ruleID,
		Group:       group,
		Msg:         msg,
	}
	return s
}

func (p *Probe) reportRiskyApp(id string, proc *procInternal, msg string, ingress bool) {
	var conn *osutil.Connection
	retry := 0
	for retry <= 3 {
		if conn == nil {
			conn = osutil.GetProcessConnection(proc.pid, nil, nil)
			if conn != nil {
				break
			}
			time.Sleep(time.Second)
			retry++
		}
	}

	group, _, _ := p.getServiceGroupName(id)
	s := p.makeProcessReport(id, proc, msg, conn, ingress, group, share.CLUSReservedUuidRiskyApp)
	rpt := ProbeMessage{Type: PROBE_REPORT_SUSPICIOUS, Process: s, ContainerIDs: utils.NewSet(id)}
	p.SendAggregateProbeReport(&rpt, false)
}

func (p *Probe) CheckDNSTunneling(ids []string, clientPort share.CLUSProtoPort, locIp, remIp net.IP, locPort, remPort uint16) bool {
	p.lockProcMux()
	defer p.unlockProcMux()

	for _, id := range ids {
		log.WithFields(log.Fields{"id": id, "port": clientPort.Port}).Debug("Check DNS tunneling")
		if c, ok := p.containerMap[id]; ok {
			for port, pa := range c.portsMap {
				if port.IPProto != clientPort.IPProto ||
					port.Port != clientPort.Port {
					continue
				}

				// matched:
				for pid := range pa.Pids.Iter() {
					if ok, tun := osutil.CheckProcessOpenDevTun(pid.(int)); ok {
						if proc, ok := p.pidProcMap[pid.(int)]; ok && (proc.reported&dnsTunnelReported) == 0 {
							msg := "Tunnel detected: dns tunneling with openning " + tun
							if proc.user == "" {
								proc.user = p.getUserName(proc.pid, proc.euid)
							}
							if proc.cmds == nil {
								proc.cmds, _ = global.SYS.ReadCmdLine(proc.pid)
							}
							if conn := osutil.GetProcessConnection(proc.pid, &clientPort, nil); conn != nil {
								go func() {
									conn.LocIP = locIp
									conn.RemIP = remIp
									conn.LocPort = locPort
									conn.RemPort = remPort
									group, _, _ := p.getServiceGroupName(id)
									s := p.makeProcessReport(c.id, proc, msg, conn, false, group, share.CLUSReservedUuidTunnelProc)
									rpt := ProbeMessage{Type: PROBE_REPORT_TUNNEL, Process: s, ContainerIDs: utils.NewSet(id)}
									p.SendAggregateProbeReport(&rpt, false)
								}()
								proc.reported |= dnsTunnelReported
								return true
							}
						}
					}
				}
			}
		}
	}
	return false
}

func (p *Probe) GetProbeSummary() *share.CLUSProbeSummary {
	var summary *share.CLUSProbeSummary
	if !p.bProfileEnable {
		return summary
	}

	p.lockProcMux()
	defer p.unlockProcMux()

	// general information
	summary = &share.CLUSProbeSummary{
		ContainerMap:      uint32(len(p.containerMap)),
		PidContainerMap:   uint32(len(p.pidContainerMap)),
		PidProcMap:        uint32(len(p.pidProcMap)),
		NewProcesses:      uint32(p.newProcesses.Cardinality()),
		NewSuspicProc:     uint32(p.inspectProcess.Cardinality()),
		ContainerStops:    uint32(p.containerStops.Cardinality()),
		PidSet:            uint32(p.pidSet.Cardinality()),
		SessionTable:      uint32(len(p.sessionTable)),
		MaxEvalChanQueued: uint32(p.profileMaxChanEvalCnt),
		MaxGoroutines:     uint32(p.profileMaxGortn),
	}

	// process blocker
	if p.fAccessCtl != nil {
		probeData_fa := p.fAccessCtl.GetProbeData()
		summary.ProcBlockRoots = uint32(probeData_fa.nRoots)
		summary.ProcBlockMarks = uint32(probeData_fa.nMarks)
		summary.ProcBlockEntryCnt = uint32(probeData_fa.nEntryCnt)
		summary.ProcBlockDirMonCnt = uint32(probeData_fa.nDirMonCnt)
	}

	// file monitor
	if p.fMonitorCtl != nil {
		probeData_fm := p.fMonitorCtl.GetProbeData()
		summary.FileMonEvents = uint32(probeData_fm.NFileEvents)
		summary.FileMonGroups = uint32(probeData_fm.NGroups)
		summary.FileMonFaRoots = uint32(probeData_fm.Fan.NRoots)
		summary.FileMonFaMntRoots = uint32(probeData_fm.Fan.NMntRoots)
		summary.FileMonFaDirMarks = uint32(probeData_fm.Fan.NDirMarks)
		summary.FileMonFaRules = uint32(probeData_fm.Fan.NRules)
		summary.FileMonFaPaths = uint32(probeData_fm.Fan.NPaths)
		summary.FileMonFaDirs = uint32(probeData_fm.Fan.NDirs)
		summary.FileMonInWds = uint32(probeData_fm.Ino.NWds)
		summary.FileMonInPaths = uint32(probeData_fm.Ino.NPaths)
		summary.FileMonInDirs = uint32(probeData_fm.Ino.NDirs)
	}

	return summary
}

func (p *Probe) GetProcessMap() []*share.CLUSProbeProcess {
	p.lockProcMux()
	defer p.unlockProcMux()

	procs := make([]*share.CLUSProbeProcess, len(p.pidProcMap))
	i := 0
	for pid, proc := range p.pidProcMap {
		var id string
		if c, ok := p.pidContainerMap[proc.pid]; ok {
			id = c.id
		}
		procs[i] = &share.CLUSProbeProcess{
			Pid:       int32(pid),
			Ppid:      int32(proc.ppid),
			Name:      proc.name,
			Ruid:      uint32(proc.ruid),
			Euid:      uint32(proc.euid),
			ScanTimes: uint32(proc.scanTimes),
			StartTime: uint64(proc.startTime.Second()),
			Reported:  uint32(proc.reported),
			Container: id,
		}
		i++
	}
	return procs
}

func (p *Probe) GetContainerMap() []*share.CLUSProbeContainer {
	p.lockProcMux()
	defer p.unlockProcMux()

	cons := make([]*share.CLUSProbeContainer, len(p.containerMap))
	i := 0
	for id, c := range p.containerMap {
		var portsMap string
		children := c.children.Union(c.outsider).ToInt32Slice()
		sort.Slice(children, func(i, j int) bool { return children[i] < children[j] })
		for port, papp := range c.portsMap {
			var protocol string
			if port.IPProto == syscall.IPPROTO_TCP {
				protocol = "TCP"
			} else {
				protocol = "UDP"
			}
			portsMap += fmt.Sprintf("[%d/%s] server=%d, app=%d, apps:%v\n",
				port.Port,
				protocol,
				papp.App.Server, papp.App.Application, papp.Pids.ToInt32Slice())
		}
		cons[i] = &share.CLUSProbeContainer{
			Id:       id,
			Pid:      int32(c.rootPid),
			Children: children,
			PortsMap: portsMap,
		}
		i++
	}
	return cons
}

func (p *Probe) isAgentChild(proc *procInternal) bool {
	ppid := proc.ppid
	sid := proc.sid
	pgid := proc.pgid
	for i := 0; i < 4; i++ { // upto 4 ancestors
		if global.SYS.IsToolProcess(sid, pgid) {
			return true
		}

		if ppid == p.agentPid {
			return true
		}

		pp, ok := p.pidProcMap[ppid]
		if !ok || unexpectedAgentProcess(pp.name) {
			break
		}
		ppid = pp.ppid
		sid = pp.sid
		pgid = pp.pgid
	}
	return false
}

func (p *Probe) isAllowIpRuntimeCommand(cmds []string) bool {
	pass := false // allowing READ operations
	// it could be like "ip -a -o link"
	for i, cmd := range cmds {
		if i == 0 {
			if cmd != "ip" {
				break
			}

			if len(cmds) <= 2 { // show commands, like "ip addr"
				pass = true
				break
			}
			continue
		}

		switch cmd {
		case "-o", "-oneline", "-r", "-resolve", "-V", "-Version", "-s", "-stats", "-statistics", "show", "list", "get":
			pass = true
		case "del", "add", "flush", "set", "change", "append", "replace", "update", "deleteall": // operators
			pass = false
		}
	}
	return pass
}

// Reducing false-positive cases
// Allowing all CNI files under the /opt/cni/bin, not from its sub-directories
// var azureCniProcMap = utils.NewSet(
//
//	"azure-vnet", "host-local", "azure-vnet-ipam", "ipvlan", "azure-vnet-ipamv6", "loopback",
//	"azure-vnet-telemetry", "macvlan", "portmap", "bridge", "ptp", "dhcp", "sample", "flannel",
//	"tuning", "host-device", "vlan")
func (p *Probe) isAllowCniCommand(path string) bool {
	if p.bKubePlatform {
		return filepath.Dir(path) == "/opt/cni/bin"
	}
	return false
}

func (p *Probe) isAllowCalicoCommand(proc *procInternal, bRtProcP bool) bool {
	if p.bKubePlatform {
		if bRtProcP {
			return proc.path == "/usr/bin/calico-node" && (len(proc.cmds) > 0 && filepath.Base(proc.cmds[0]) == "calico-node")
		}
		return proc.ppath == "/usr/bin/calico-node" && filepath.Dir(proc.path) == "/usr/local/bin"
	}
	return false
}

// a runc building-command during "docker run" (not from root process but exists parallelly)
func (p *Probe) isAllowRuncInitCommand(path string, cmds []string) bool {
	// in-memory execution: cmd=[docker-runc init ] name=5 parent=docker-runc path=/memfd:runc_cloned:/proc/self/ex ppath=/run/torcx/unpack/docker/bin/runc
	if filepath.Base(path) == "runc" || strings.HasPrefix(path, "/memfd:runc_cloned") {
		for i, cmd := range cmds {
			if i == 0 && !global.RT.IsRuntimeProcess(filepath.Base(cmds[0]), nil) {
				break
			}

			if i > 0 {
				switch cmd {
				case "init", "create":
					return true
				}
			}
		}
	}
	return false
}

func (p *Probe) isProcessException(proc *procInternal, group, id string, bParentHostProc, bZeroDrift bool) bool {
	if proc.riskyChild && proc.riskType != "" {
		return false
	}

	// the parent name is not ready
	if proc.pname == "" {
		proc.pname, _, _, _ = osutil.GetProcessUIDs(proc.ppid)
	}

	bRtProc := global.RT.IsRuntimeProcess(proc.name, nil)
	bRtProcP := global.RT.IsRuntimeProcess(proc.pname, nil)
	if proc.pname == "" {
		bRtProcP = true // not trace-able
	}

	// both names are in the runtime list
	if bRtProc && bRtProcP {
		log.WithFields(log.Fields{"name": proc.name, "path": proc.path}).Debug("PROC:")
		return true
	}

	// parent: matching only from binary
	pname := filepath.Base(proc.ppath)
	if p.bKubePlatform {
		switch pname {
		case "pod", "kubelet":
			return true
		}

		// oc specific
		if p.kubeFlavor == share.FlavorOpenShift {
			switch pname {
			case "hyperkube", "coreutils":
				return true
			case "openshift-sdn-node":
				name := filepath.Base(proc.path)
				return name == "sh" || name == "bash"
			}
		}
	}

	// network plug-in: calico-node
	if p.isAllowCalicoCommand(proc, bRtProcP) {
		log.WithFields(log.Fields{"name": proc.name, "path": proc.path, "pname": proc.pname}).Debug("PROC:")
		return true
	}

	// maintainance jobs running from runtime engine
	if bRtProcP {
		switch proc.name {
		case "busybox":
			// exception: ps and its parent is a runtime process
			if len(proc.cmds) > 0 && (filepath.Base(proc.cmds[0]) == "ps") {
				return true
			}
		case "ps":
			// Exception for process where the parent is a runtime process.
			// Some CNI daemons will call `ps` and we will get false positives without the exception.
			return true
		case "mount", "lsof", "getent", "adduser", "useradd": // from AWS
			return true
		default:
			if p.isAllowRuncInitCommand(proc.path, proc.cmds) {
				return true
			}
		}

		if p.isAllowCniCommand(proc.path) {
			mLog.WithFields(log.Fields{"group": group, "name": proc.name, "path": proc.path}).Debug("PROC:")
			return true
		}
	}

	// NV4856
	if p.isAllowIpRuntimeCommand(proc.cmds) {
		mLog.WithFields(log.Fields{"group": group, "name": proc.name, "cmds": truncateStrSlices(proc.cmds, 32)}).Debug("PROC:")
		return true
	}

	// maintainance jobs running from node
	if bParentHostProc {
		// CNI commands from node
		if p.isAllowCniCommand(proc.ppath) {
			switch proc.name {
			case "portmap", "containerd", "sleep", "uptime", "nice":
				return true
			}
			if p.isAllowCniCommand(proc.path) {
				mLog.WithFields(log.Fields{"group": group, "name": proc.name, "path": proc.path}).Debug("PROC:")
				return true
			}
		}

		switch proc.pname {
		case "udisksd":
			return proc.name == "dumpe2fs"
		case "qualys-cloud-agent":
			if filepath.Dir(proc.ppath) == "/usr/local/qualys/cloud-agent/bin" {
				return true
			}
		}
	}

	// nv containers only: allowing copy-out action for "kubectl cp"
	if group == share.GroupNVProtect {
		if p.disableNvProtect {
			// allowed but output the traces
			log.WithFields(log.Fields{"group": group, "name": proc.name, "cmds": truncateStrSlices(proc.cmds, 32), "path": proc.path}).Info("")
			return true
		}

		if bRtProcP && len(proc.cmds) >= 3 {
			if proc.cmds[0] == "tar" && proc.cmds[1] == "cf" {
				// from "k8s.io/pkg/kubectl/cmd/cp.go" : copyFromPod()
				// matched to its exact Command:  []string{"tar", "cf", "-", src.File}
				mLog.WithFields(log.Fields{"group": group, "name": proc.name, "cmds": truncateStrSlices(proc.cmds, 32)}).Debug("PROC:")
				return true
			}
		}

		// hidden: relaxing the restrictions for future implementation
		if p.isAgentChild(proc) {
			//log.WithFields(log.Fields{"group": group, "name": proc.name, "pname": proc.pname, "cmds" : proc.cmds}).Debug("PROC: Parent is allowed, relaxing")
			return true
		}
	}
	return false
}

func (p *Probe) procProfileEval(id string, proc *procInternal, bKeepAlive bool) (string, bool) {
	if filepath.Base(proc.path) != proc.name {
		if proc.action != share.PolicyActionCheckApp { // preserve the suspicious process name
			// update name
			if name, ppid, _, _ := osutil.GetProcessUIDs(proc.pid); ppid > 0 && len(name) > 0 {
				proc.name = name
			} else {
				proc.name = filepath.Base(proc.path)
			}
		}
	}

	pp := &share.CLUSProcessProfileEntry{
		Name:   proc.name,
		User:   proc.user,
		Uid:    int32(proc.euid),
		Path:   proc.path,
		Action: proc.action, // following the previous decision
	}

	nShellCmd := p.isShellScript(id, proc)
	mode, baseline, derivedGroup, svcGroup, allowSuspicious, err := p.procPolicyLookupFunc(id, proc.riskType, proc.pname, proc.ppath, proc.pid, proc.pgid, nShellCmd, pp)
	if err != nil {
		// add conatiner task has not established yet
		// log.WithFields(log.Fields{"name": proc.name, "error": err}).Debug("PROC:")
		return share.PolicyActionAllow, false // assuming it is allowed so far
	}

	if id == "" && proc.riskType == "sshd" {

	} else {
		if proc.riskType != "" || proc.riskyChild {
			if allowSuspicious {
				if pp.Action != share.PolicyActionAllow {
					// consider it as an intruder processes unless users whitelist it
					mLog.WithFields(log.Fields{"proc": proc, "id": id}).Debug("PROC: Risky session")
					pp.Action = negativeResByMode(mode)
					pp.Uuid = share.CLUSReservedUuidNotAlllowed
				}
			} else {
				// user has not opened the door
				switch mode {
				case share.PolicyModeLearn:
					// suspicious children are still suspicious
					pp.Action = share.PolicyActionCheckApp
				case share.PolicyModeEvaluate:
					pp.Action = share.PolicyActionViolate
				case share.PolicyModeEnforce:
					pp.Action = share.PolicyActionDeny
				}
			}
		}
	}

	//	proc.action = pp.Action
	// NVSHAS-7501 - Adding check for our mode.
	// If we are in protect mode, we should ignore the reported flag to determine the next actions.
	// We don't need to report the violations more often, but we should make sure that if we
	// transition from monitor -> protect, we ignore the reported flag to control determine actions.
	if (proc.reported&profileReported) == 0 || mode == share.PolicyModeEnforce {
		bZeroDrift := baseline == share.ProfileZeroDrift
		if bZeroDrift {
			if pass := p.IsAllowedShieldProcess(id, mode, svcGroup, proc, pp, true); pass {
				switch pp.Action {
				case share.PolicyActionLearn, share.PolicyActionCheckApp: // exclude these two actions
				default:
					pp.Action = share.PolicyActionAllow
					if !allowSuspicious && proc.action == share.PolicyActionCheckApp {
						switch mode {
						case share.PolicyModeLearn:
							pp.Action = share.PolicyActionCheckApp
						case share.PolicyModeEvaluate:
							pp.Action = share.PolicyActionViolate
						case share.PolicyModeEnforce:
							pp.Action = share.PolicyActionDeny
						}
					}
				}
			} else {
				bKeepAlive = false
			}
		}
		if pp.Action == share.PolicyActionViolate || pp.Action == share.PolicyActionDeny {
			if pp.Uuid != share.CLUSReservedUuidAnchorMode || svcGroup == share.GroupNVProtect {
				var bParentHostProc bool
				if c, ok := p.pidContainerMap[proc.ppid]; ok {
					bParentHostProc = c.id == ""
				}
				if p.isProcessException(proc, svcGroup, id, bParentHostProc, bZeroDrift) {
					pp.Action = share.PolicyActionAllow // can not be learned
				}
			}
		}

		switch pp.Action {
		case share.PolicyActionViolate:
			proc.reported |= profileReported
			proc.action = pp.Action
			go p.sendProcessIncident(false, id, pp.Uuid, svcGroup, derivedGroup, proc)
		case share.PolicyActionDeny: // Protect mode only
			proc.reported |= profileReported
			go p.sendProcessIncident(true, id, pp.Uuid, svcGroup, derivedGroup, proc)
			if !bKeepAlive { // bKeepAlive action : keep its original decision for existing process
				p.killProcess(proc.pid)
				proc.action = pp.Action
				log.WithFields(log.Fields{"name": proc.name, "pid": proc.pid}).Debug("PROC: Denied and killed")
			}
		}
	}

	// multiple learn process event are okay because they are merged at controllers.
	if pp.Action == share.PolicyActionLearn {
		p.reportLearnProc(svcGroup, pp)
	}

	mLog.WithFields(log.Fields{"name": proc.name, "pid": proc.pid, "action": pp.Action, "riskType": proc.riskType, "svcGroup": svcGroup}).Debug("PROC:")
	return pp.Action, true
}

func (p *Probe) sendProcessIncident(bDenied bool, id, uuid, group, derivedGroup string, proc *procInternal) {
	var s *ProbeProcess

	p.lockProcMux()
	proc.user = p.getUpdatedUsername(proc.pid, proc.euid)
	p.unlockProcMux()

	switch uuid {
	case share.CLUSReservedUuidAnchorMode: // zero-drift incident
		s = p.makeProcessReport(id, proc, "Process profile violation, not from an image file", nil, false, group, uuid)
	case share.CLUSReservedUuidShieldMode: // zero-drift incident
		s = p.makeProcessReport(id, proc, "Process profile violation, not from its root process", nil, false, group, uuid)
	default: // rules-based incident
		s = p.makeProcessReport(id, proc, "Process profile violation", nil, false, derivedGroup, uuid)
	}

	incidentType := PROBE_REPORT_PROCESS_VIOLATION
	if bDenied {
		incidentType = PROBE_REPORT_PROCESS_DENIED
		s.Msg += ": execution denied"
	}

	rpt := ProbeMessage{Type: incidentType, Process: s, ContainerIDs: utils.NewSet(id)}
	p.SendAggregateProbeReport(&rpt, false)
}

func (p *Probe) ProcessLookup(pid int) *fsmon.ProcInfo {
	p.lockProcMux()
	defer p.unlockProcMux()
	if c, ok := p.pidContainerMap[pid]; ok {
		pInfo := &fsmon.ProcInfo{RootPid: c.rootPid}
		if proc := p.pidProcMap[pid]; proc != nil {
			if proc.path == "" {
				proc.path, _ = global.SYS.GetFilePath(proc.pid)
			}
			if proc.name == "" {
				proc.name, _, _, _ = osutil.GetProcessUIDs(proc.pid)
			}
			pInfo.Cmds = proc.cmds
			pInfo.Path = proc.path
			pInfo.Name = proc.name
			pInfo.Pid = proc.pid
			pInfo.EUid = proc.euid
			pInfo.EUser = proc.user
			pInfo.PPid = proc.ppid
			pInfo.PName = proc.pname
			pInfo.PPath = proc.ppath
		}

		return pInfo
	}
	return nil
}

// ///////////////////////////////////////////////////////////////////
/* removed by golint
func printLastProcElements(list []*procInternal, nLastItems int) {
	start := 0
	length := len(list)
	if nLastItems == -1 || nLastItems > length {
		// all
	} else if nLastItems <= length {
		start = length - nLastItems
	}

	// log.WithFields(log.Fields{"nLastItems": nLastItems, "length": length, "start": start}).Debug("PROC:")

	for i := start; i < length; i++ {
		log.WithFields(log.Fields{"i": i, "cmds": list[i].cmds}).Debug("PROC:")
	}
}
*/

// ////// only from netlink monitor, already guarded by procMux
func (p *Probe) addProcHistory(id string, proc *procInternal, bFromMonitor bool) {
	var histProc *ringbuffer.RingBuffer
	var ok bool

	// no history for host
	if id == "" {
		return
	}

	// avoid duplicated entries
	if (proc.reported & historyReported) == historyReported {
		return
	}
	proc.reported |= historyReported

	// from outside of the realtime monitor, need to be gaurded by procMux
	if !bFromMonitor {
		p.lockProcMux()
		defer p.unlockProcMux()
	}

	if histProc, ok = p.procHistoryMap[id]; !ok {
		histProc = ringbuffer.New(400) // TODO: more ?
		p.procHistoryMap[id] = histProc
	}

	histProc.Write(proc)

	// Verification section, test only
	// log.WithFields(log.Fields{"path": proc.path, "id": id, "cnt": histProc.Length()}).Debug("PROC: ")
	// if histProc.Length()() == 400 {
	//		var list []*procInternal
	//		elements := histProc.DumpExt()
	//		for i := 0; i < len(elements); i++ {
	//			list = append(list, elements[i].(*procInternal))
	//		}
	//		printLastProcElements(list, 10)
	//	}
}

// Patch for newly created conatiners, not for host
func (p *Probe) PutBeginningProcEventsBackToWork(id string) int {
	var cnt int
	// log.Debug("PROC:")
	// TODO:check the calling function, should be guarded only by procMux
	p.lockProcMux()
	defer p.unlockProcMux()

	if histProc, ok := p.procHistoryMap[id]; ok {
		elements := histProc.DumpExt()
		for i := 0; i < len(elements); i++ {
			proc := elements[i].(*procInternal)

			// filter the docker run events since the path is not in the containers
			if global.RT.IsRuntimeProcess(proc.name, nil) {
				// skip: runtime processes,  filter it out
				continue
			}

			// log.WithFields(log.Fields{"proc": proc, "id": id}).Debug("PROC:")
			//  Skip the inherted actions from parents.
			//  These processes has not been justified by policy, all the actions and riskinfo are default values
			//  assume no ousiders during the initial stage, only justify insider processes
			if pp, ok := p.pidProcMap[proc.pid]; ok {
				p.evaluateApplication(pp, id, true)
			} else { // process was gone
				p.evaluateApplication(proc, id, true)
			}
			cnt++
		}
	}

	p.cleanupProcessInContainer(id) // remove dead processes
	return cnt
}

// / garbage collection : reference the actual removal events at container engine
func (p *Probe) purgeProcHistory() int {
	var cnt int

	containerList := p.getAllContainerList() // still reside in the runtime engine

	p.lockProcMux()
	defer p.unlockProcMux()
	for id, histProc := range p.procHistoryMap {
		if !containerList.Contains(id) {
			// purge it out of list
			histProc.Clear()
			delete(p.procHistoryMap, id)
			cnt++
			log.WithFields(log.Fields{"id": id}).Debug("PROC:")
		}
	}
	return cnt // reference only
}

func (p *Probe) alterRiskyAction(pid int, riskapp map[string]string) {
	if proc := p.pidProcMap[pid]; proc != nil {
		if action, ok := riskapp[proc.riskType]; ok {
			proc.action = action
			mLog.WithFields(log.Fields{"pid": pid, "type": proc.riskType, "action": action}).Debug("PROC: update")
		}
	}
}

// //
func (p *Probe) updateCurrentRiskyAppRule(id string, pg *share.CLUSProcessProfile) {
	var riskType string
	riskapp := make(map[string]string)
	for _, pp := range pg.Process {
		// It is based on the NAME only and could create a mismatched condition for discovery/monitor mode
		// for example, the serveal sshd binaries in different folders but we release the chains here
		// however, during Protect mode, the process blocker/killer will have the correction by the restrained path rules.
		if pp.Path == "" || pp.Path == "*" || strings.HasSuffix(pp.Path, "/*") {
			// wildcard syntax
			riskType = pp.Name
		} else {
			// regular
			index := strings.LastIndex(pp.Path, "/")
			riskType = pp.Path[index+1:]
		}

		// exclude sshd from group nodes
		if id == "" && riskType == "sshd" {
			continue
		}

		//	log.WithFields(log.Fields{"app": name, "name": pp.Name, "path": pp.Path, "action": pp.Action}).Debug("PROC:")
		if _, ok := suspicProcMap[riskType]; ok {
			riskapp[riskType] = pp.Action // name as riskType
		}
	}

	// fill the non-existing items
	for riskType = range suspicProcMap {
		if _, ok := riskapp[riskType]; !ok {
			riskapp[riskType] = share.PolicyActionCheckApp
		}
	}

	//	log.WithFields(log.Fields{"riskapp": riskapp}).Debug("PROC: changes")
	// update existing processes as needed,
	p.lockProcMux()
	defer p.unlockProcMux()
	if c, ok := p.containerMap[id]; ok {
		for pid := range c.children.Iter() {
			p.alterRiskyAction(pid.(int), riskapp)
		}
		for pid := range c.outsider.Iter() {
			p.alterRiskyAction(pid.(int), riskapp)
		}
	}
	mLog.WithFields(log.Fields{"id": id}).Debug("PROC: done")
}

// under parent's lock
func (p *Probe) evaluateApp(pid int, id string, bReScanCgroup bool) {
	if proc, ok := p.pidProcMap[pid]; ok {
		if osutil.IsPidValid(proc.pid) {
			proc.name, proc.ppid, _, _ = osutil.GetProcessUIDs(proc.pid)
			if !global.RT.IsRuntimeProcess(proc.name, nil) {
				if proc.cmds != nil && proc.cmds[0] != "sshd:" {
					proc.cmds, _ = global.SYS.ReadCmdLine(proc.pid)
				}
				proc.path, _ = global.SYS.GetFilePath(proc.pid)
				proc.pname, _, _, _ = osutil.GetProcessUIDs(proc.ppid)
				proc.ppath, _ = global.SYS.GetFilePath(proc.ppid)
				idn := id
				if bReScanCgroup {
					if c1, ok := p.addContainerCandidateFromProc(proc); ok && c1.id != "" {
						mLog.WithFields(log.Fields{"name": proc.name, "pid": proc.pid, "id": c1.id}).Debug("PROC: patch")
						p.addProcHistory(c1.id, proc, true)
						idn = c1.id // could be a hole, since it is not detected in the process monitor
					}
				}

				// No need to inhert parent's action. Done at the evalNewRunningApp()
				p.evaluateApplication(proc, idn, true)
			}
		}
	}
}

func (p *Probe) evaluateLiveApps(id string) {
	bReScanCgroup := p.deferCStartRpt && (id == "") // crio cases
	p.lockProcMux()
	defer p.unlockProcMux()
	if c, ok := p.containerMap[id]; ok {
		for pid := range c.children.Iter() {
			p.evaluateApp(pid.(int), id, bReScanCgroup)
		}
		for pid := range c.outsider.Iter() {
			p.evaluateApp(pid.(int), id, bReScanCgroup)
		}
	}
}

func (p *Probe) processProfileReeval(id string, pg *share.CLUSProcessProfile, bAddContainer bool) {
	go p.evaluateLiveApps(id)

	// update riskApp by current policy
	p.updateCurrentRiskyAppRule(id, pg)
}

func (p *Probe) applyProcessBlockingPolicy(id string, pid int, pg *share.CLUSProcessProfile, bBlocking bool) bool {
	log.WithFields(log.Fields{"mode": pg.Mode, "baseline": pg.Baseline, "id": id}).Debug("PROC")
	if bBlocking {
		p.addProcessControl(id, pg.Baseline, pg.Group, pid, pg.Process) // serial operation, no go routine
	} else {
		p.RemoveProcessControl(id) // serial operation, no go routine
	}
	return true
}

// ////
func (p *Probe) HandleProcessPolicyChange(id string, pid int, pg *share.CLUSProcessProfile, bAddContainer, bBlocking bool) {
	if p.bProfileEnable {
		p.processProfileReeval(id, pg, bAddContainer)
		p.applyProcessBlockingPolicy(id, pid, pg, bBlocking)
	}
}

func (p *Probe) SetMonitorTrace(bEnable bool, logLevel string) {
	if bEnable {
		mLog.Level = log.DebugLevel
	} else {
		mLog.Level = share.CLUSGetLogLevel(logLevel)
	}
}

func (p *Probe) SetNvProtect(bDisable bool) {
	p.disableNvProtect = bDisable
	log.WithFields(log.Fields{"state": !p.disableNvProtect, "IsNvProtectAlerted": p.IsNvProtectAlerted}).Info("PROC")
	if p.disableNvProtect {
		p.IsNvProtectAlerted = false // reset
	}
}

// // Modern shell commands and their paths
// // handle the real path later as needed
var commonShellName map[string]string = map[string]string{
	"bash": "/bin/bash",
	"sh":   "/bin/sh",
	"ash":  "/bin/ash",
	"dash": "/bin/dash",
	"csh":  "/bin/csh",
	"tcsh": "/bin/tcsh",
}

func (p *Probe) isShellScript(id string, proc *procInternal) int {
	if id != "" { // TODO: could remove and apply to all conatiners later
		return 0
	}

	// a shell command ?
	appname := filepath.Base(proc.path)
	_, ok := commonShellName[appname] // subpath
	if !ok {
		// Two expected escaping shell script cases (false-negative, no harm):
		// (1) 	>> bash psloop.sh
		// 		cmd=[bash psloop.sh ] name=bash path=/bin/bash
		//    	It will be recorded as {"bash", "/bin/bash"}
		// (2) 	>> sh psloops.sh
		// 		cmd=[sh psloop.sh ] name=sh path=/bin/dash
		// 		It will be recorded as {"sh", "/bin/dash"}
		return 0
	}

	// log.WithFields(log.Fields{"path": proc.path, "name": proc.name}).Debug()
	// log.WithFields(log.Fields{"cmd": proc.cmds}).Debug()

	// sample from "Microsoft System Center - Operations Manager"
	// cmd=[/bin/bash server=$1 if [ `systemctl list-unit-files | grep -i "atomic-openshift-master-api.service" | wc -l` -gt 0 ] then /etc/opt/microsoft/scx/conf/tmpdir/scxuPiwXl ocpmaster5102.rbgooe.at ]
	// id=[host] name=scxuPiwXl  path=/usr/bin/bash
	// parent=sudo ppath=/usr/bin/sudo
	for i, cmd := range proc.cmds {
		// log.WithFields(log.Fields{"i": i, "cmd": cmd}).Debug("")
		if i == 0 {
			filename := filepath.Base(cmd)
			if _, ok := commonShellName[filename]; !ok { // not a shell cmd
				return 0 // reject at first entry
			}
			// entering 2nd screening
			// cmd=[/bin/sh ./1.sh ] name=1.sh path=/bin/dash
			// log.WithFields(log.Fields{"filename": filename}).Debug("")
		} else {
			// could be in any entry, exclude excessive unique names
			// it could be called by: execl(<script-path>, <script-name>, (char *)0);
			if strings.Contains(cmd, proc.name) {
				log.WithFields(log.Fields{"shell": proc.path, "script": cmd}).Debug("found")
				return 1
			}
		}
	}
	return 0
}

// PatchContainerProcess()
// Fixed the missing process table, caused by the netlink recv errors, no process record is available.
// Current patch is only for important init-process of a container
func (p *Probe) PatchContainerProcess(pid int, bEval bool) bool {
	p.lockProcMux()
	defer p.unlockProcMux()
	if _, ok := p.pidProcMap[pid]; !ok {
		now := time.Now()
		proc := &procInternal{
			pid:          pid,
			ppid:         pid, // assume
			sid:          osutil.GetSessionId(pid),
			startTime:    now,
			lastScanTime: now,
			action:       share.PolicyActionAllow,
		}

		// is it a process inside a cgroup
		if c, ok := p.addContainerCandidateFromProc(proc); ok {
			p.updateProcess(proc)
			proc.user = p.getUserName(proc.ppid, proc.euid) // get parent's username
			proc.path, _ = global.SYS.GetFilePath(proc.pid) // exe path
			proc.cmds, _ = global.SYS.ReadCmdLine(proc.pid)
			proc.pname, _, _, _ = osutil.GetProcessUIDs(proc.ppid)
			p.pidProcMap[proc.pid] = proc
			p.addProcHistory(c.id, proc, true)

			if bEval && !p.isDockerDaemonProcess(proc, c.id) {
				go p.evalNewRunningApp(proc.pid) // no sequential issue
			}
			log.WithFields(log.Fields{"proc": proc, "id": c.id}).Debug()
			return true
		}
	}
	return false
}

func isFamilyProcess(family utils.Set, proc *procInternal) bool {
	return family.Contains(proc.pid) || family.Contains(proc.ppid) || family.Contains(proc.pgid) || family.Contains(proc.sid)
}

func negativeResByMode(mode string) string {
	if mode == share.PolicyModeEnforce {
		return share.PolicyActionDeny
	}
	return share.PolicyActionViolate
}

func (p *Probe) IsAllowedShieldProcess(id, mode, svcGroup string, proc *procInternal, ppe *share.CLUSProcessProfileEntry, bFromPmon bool) bool {
	var bPass, bImageFile, bModified bool
	if !p.bProfileEnable {
		return true
	}

	if id == "" { // nodes
		return true
	}

	if !bFromPmon {
		// from file-access worker
		p.lockProcMux()
		defer p.unlockProcMux()
	}

	c, ok := p.containerMap[id]
	if !ok {
		// the container was exited before we investigate into it
		mLog.WithFields(log.Fields{"proc": proc, "id": id}).Debug("SHD: Unknown ID")
		return true
	}

	// container is gone
	if !osutil.IsPidValid(c.rootPid) {
		return true
	}

	if proc.pid == c.rootPid {
		mLog.WithFields(log.Fields{"id": id, "rootPid": proc.pid}).Debug("SHD: rootPid")
		return true
	}

	bNotImageButNewlyAdded := false
	bImageFile = true
	if yes, mounted := global.SYS.IsNotContainerFile(c.rootPid, ppe.Path); yes || mounted {
		// We will not monitor files under the mounted folder
		// The mounted condition: utils.IsContainerMountFile(c.rootPid, ppe.Path)
		if c.bPrivileged {
			mLog.WithFields(log.Fields{"file": ppe.Path, "id": id}).Debug("SHD: priviiged system pod")
		} else if mounted {
			mLog.WithFields(log.Fields{"file": ppe.Path, "id": id}).Debug("SHD: mounted")
		} else { // yes: not a container file
			bFromPrivilegedPod := false
			ppid := 0
			cID := ""
			// The process (like "setns") is from a privileged pod (like enforcer)
			if proc.ppid == p.agentPid {
				ppid = p.agentPid
				cID = p.selfID
			} else if pContainer, ok := p.pidContainerMap[proc.ppid]; ok && pContainer.id != "" && pContainer.bPrivileged {
				ppid = pContainer.rootPid
				cID = pContainer.id
			}

			// need to validate it from the calling pod
			if ppid != 0 {
				if yes, _ = global.SYS.IsNotContainerFile(ppid, ppe.Path); yes {
					bFromPrivilegedPod = true
					log.WithFields(log.Fields{"file": ppe.Path, "id": cID, "ppid": ppid}).Debug("SHD: calling from a priviiged pod")
				}
			}

			if !bFromPrivilegedPod {
				// this file is not existed
				bImageFile = false
				mLog.WithFields(log.Fields{"file": ppe.Path, "pid": c.rootPid}).Debug("SHD: not in image")
			}
		}

		// from docker run, v20.10.7
		bRtProcP := global.RT.IsRuntimeProcess(proc.pname, nil)
		if bRtProcP && p.isAllowRuncInitCommand(proc.path, proc.cmds) {
			// mlog.WithFields(log.Fields{"id": id}).Debug("SHD: runc init")
			return true
		}
	} else {
		if finfo, ok := p.fsnCtr.GetUpperFileInfo(id, ppe.Path); ok && finfo.bExec && finfo.length > 0 {
			bImageFile = false
			if fi, ok := c.fInfo[ppe.Path]; ok {
				bModified = (fi.length != finfo.length) || (fi.hashValue != finfo.hashValue)
				if ppe.Action == share.PolicyActionAllow && fi.fileType == file_not_exist { // not from image
					bNotImageButNewlyAdded = true
					c.fInfo[ppe.Path] = finfo // updated
				}
				mLog.WithFields(log.Fields{"file": ppe.Path, "fi": fi, "finfo": finfo}).Debug("SHD:")
			} else {
				mLog.WithFields(log.Fields{"file": ppe.Path, "finfo": finfo}).Debug("SHD: new file")
				bModified = true
			}
		}
	}

	bCanBeLearned := true
	bRuncChild := false
	if ppe.Action != share.PolicyActionViolate && (p.bK8sGroupWithProbe(svcGroup) || len(c.healthCheck) > 0) {
		// allowing "kubctl exec ...", adpot the binary path to resolve the name
		bRuncChild = global.RT.IsRuntimeProcess(proc.pname, nil)
		if !bRuncChild {
			pid := proc.pid
			for i := 0; i < 4; i++ { // upto 4 ancestors
				// ppid could be updated, read it again
				if _, ppid, err := global.SYS.GetProcessName(pid); err != nil || ppid <= 1 {
					if i == 0 && err != nil { // process left, pstree failed, trace back 8 entries, could be more restrictive
						for j := 1; j <= 8; j++ {
							ppid = proc.ppid - j
							if ppid == c.rootPid {
								mLog.WithFields(log.Fields{"pid": ppid}).Debug("SHD: rootPid")
								break
							}
							if pp, ok := p.pidProcMap[ppid]; ok && len(pp.name) > 1 { // "" or "."
								if c, ok := p.pidContainerMap[ppid]; ok && c.id == "" { // only node process
									bRuncChild = global.RT.IsRuntimeProcess(pp.name, nil)
									if bRuncChild {
										mLog.WithFields(log.Fields{"pid": ppid, "name": pp.name}).Debug("SHD:")
										break
									}
								}
							}
						}
					}
					break
				} else {
					var name string
					if ppid == c.rootPid {
						mLog.WithFields(log.Fields{"ppid": ppid}).Debug("SHD: rootPid")
						break
					}

					if p, ok := p.pidProcMap[ppid]; ok && len(p.name) > 1 { // "" or "."
						name = p.name
					} else if path, err := global.SYS.GetFilePath(ppid); err == nil { // exe path
						name = filepath.Base(path)
					}

					bRuncChild = global.RT.IsRuntimeProcess(name, nil)
					if bRuncChild {
						mLog.WithFields(log.Fields{"ppid": ppid, "pname": name}).Debug("SHD:")
						break
					}
					pid = ppid // next ancestor
				}
			}
		}

		//if bRuncChild {
		//	bCanBeLearned = false
		//}

		//  TODO: meet the qualifications
		// if ppe.Name == proc.name && len(ppe.ProbeCmds) > 0 {
		//	if bRuncChild {
		//	norm := strings.TrimSuffix(strings.Join(proc.cmds, ","), ",")
		//	for _, cmd := range ppe.ProbeCmds {
		//		if strings.Contains(norm, cmd) {
		//			// matched up to its grandparent process
		//          bCanBeLearned = false
		//			c.outsider.Remove(proc.pid)
		//			c.children.Add(proc.pid)
		//			mLog.WithFields(log.Fields{"id": id, "pid": proc.pid}).Debug()
		//			break
		//		}
		//	}
		//	}
		//}
	}

	mLog.WithFields(log.Fields{"ppe": ppe, "pid": proc.pid, "id": id}).Debug("SHD:")
	// ZeroDrift: allow a family member of the root process
	if isFamilyProcess(c.children, proc) || bRuncChild {
		// a family member
		if bFromPmon {
			c.outsider.Remove(proc.pid)
			c.children.Add(proc.pid)
		}

		switch ppe.Action {
		case share.PolicyActionLearn, share.PolicyActionOpen:
			bPass = true
			if !bImageFile && !bNotImageButNewlyAdded {
				bPass = false
				ppe.Action = negativeResByMode(mode)
				ppe.Uuid = share.CLUSReservedUuidAnchorMode
			} else if !bCanBeLearned {
				// allowed but will not be learned
				ppe.Action = share.PolicyActionAllow
				mLog.WithFields(log.Fields{"ppe": ppe, "pid": proc.pid, "svcGroup": svcGroup}).Debug()
			}
		case share.PolicyActionAllow, share.PolicyActionViolate:
			if ppe.Action == share.PolicyActionViolate {
				if ppe.Uuid != share.CLUSReservedUuidNotAlllowed {
					// a real deny rule
					break
				}

				if proc.riskType != "" || proc.riskyChild {
					mLog.WithFields(log.Fields{"proc": proc, "id": id}).Debug("SHD: rissky session")
					break
				}

			}

			bPass = true
			ppe.Action = share.PolicyActionAllow
			if ppe.CfgType > share.Learned {
				// user allows the process manually
			} else {
				if !ppe.AllowFileUpdate && !bNotImageButNewlyAdded {
					if bModified || (ppe.CfgType == 0 && !bImageFile) {
						bPass = false
						ppe.Action = negativeResByMode(mode)
						ppe.Uuid = share.CLUSReservedUuidAnchorMode
					}
				}
			}
		case share.PolicyActionDeny:
			if svcGroup == share.GroupNVProtect {
				if bImageFile {
					bPass = true
					ppe.Action = share.PolicyActionAllow
				}
			} else {
				ppe.Uuid = share.CLUSReservedUuidNotAlllowed
			}
		}
	} else {
		switch ppe.Action {
		case share.PolicyActionLearn, share.PolicyActionOpen:
			ppe.Action = share.PolicyActionViolate
			ppe.Uuid = share.CLUSReservedUuidShieldMode
		case share.PolicyActionAllow:
			bPass = true
			if ppe.CfgType == share.Learned { // user needs to allow the process manually
				// TODO: how about the learned rule's translation from GroundCfg-CRD?
				bPass = false
				ppe.Action = negativeResByMode(mode)
				ppe.Uuid = share.CLUSReservedUuidShieldMode
			} else if !ppe.AllowFileUpdate && !bNotImageButNewlyAdded {
				if bModified {
					bPass = false
					ppe.Action = negativeResByMode(mode)
					ppe.Uuid = share.CLUSReservedUuidAnchorMode
				}
			}
		}
	}
	mLog.WithFields(log.Fields{"bModified": bModified, "bImageFile": bImageFile, "bNotImageButNewlyAdded": bNotImageButNewlyAdded}).Debug("SHD:")
	mLog.WithFields(log.Fields{"children": c.children.String(), "outsider": c.outsider.String(), "bPass": bPass}).Debug("SHD:")
	return bPass
}

func (p *Probe) BuildProcessFamilyGroups(id string, rootPid int, bSandboxPod, bPrivileged bool, healthCheck []string) {
	//log.WithFields(log.Fields{"id": id, "pid": rootPid}).Debug("SHD:")
	if !p.bProfileEnable {
		return
	}

	p.lockProcMux()
	defer p.unlockProcMux()

	c, ok := p.containerMap[id]
	if !ok {
		if bSandboxPod {
			// some reused sandbox will not have a new prcesses
			c = &procContainer{
				id:       id,
				children: utils.NewSet(rootPid),
				outsider: utils.NewSet(), // empty
				rootPid:  rootPid,
				newBorn:  0,
				userns:   &userNs{users: make(map[int]string), uidMin: osutil.UserUidMin},
				portsMap: make(map[osutil.SocketInfo]*procApp),
				fInfo:    make(map[string]*fileInfo),
				startAt:  time.Now(),
			}
			p.containerMap[id] = c
		} else {
			log.WithFields(log.Fields{"id": id}).Error("SHD: Unknown ID")
			return
		}
	}

	p.cleanupProcessInContainer(id) // remove dead processes

	c.rootPid = rootPid
	c.bPrivileged = bPrivileged
	if healthCheck != nil {
		c.healthCheck = healthCheck // no override
	}
	allPids := c.outsider.Union(c.children)
	allPids.Add(rootPid) // all collections: add rootPid as a pivot point
	c.outsider.Clear()   // reset
	c.children.Clear()
	if allPids.Cardinality() == 1 { // only a root pid
		c.children.Add(rootPid)
		return
	}

	if proc, ok := p.pidProcMap[rootPid]; ok {
		if proc.ppid > 0 { // exclude its runtime init process
			allPids.Remove(proc.ppid)
		}
	}

	// (1) make a sorting slice of the outsiders
	pids := allPids.ToInt32Slice()
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] }) //sorting in increasing order

	// (2) Usually the parent's pid is smaller and the first Pid in the sorted list
	index := sort.Search(len(pids), func(i int) bool { return rootPid <= int(pids[i]) })
	if index != 0 {
		// Pid: Wrap-around case: re-arrange all slices, started with the rootPid
		pidsn := pids[index:]
		pidsn = append(pidsn, pids[:index]...)
		pids = pidsn
	}

	// (3) rebuild two sets
	c.children.Add(rootPid) // from the beginning
	for _, pid := range pids {

		if proc, ok := p.pidProcMap[int(pid)]; ok {
			if isFamilyProcess(c.children, proc) {
				c.children.Add(int(pid))
			} else {
				c.outsider.Add(int(pid))
			}
		}
	}
	mLog.WithFields(log.Fields{"id": id, "pid": rootPid, "children": c.children.String(), "outsider": c.outsider.String()}).Debug("SHD:")
}

func (p *Probe) HandleAnchorModeChange(bAdd bool, id, cPath string, rootPid int) {
	if !p.bProfileEnable {
		return
	}
	if bAdd {
		if rootPid != 0 {
			if ok, files := p.fsnCtr.AddContainer(id, cPath, "", rootPid); !ok {
				log.WithFields(log.Fields{"id": id, "cPath": cPath}).Debug("AN: add failed")
			} else {
				p.lockProcMux()
				if c, ok := p.containerMap[id]; ok {
					for file, info := range files {
						if info.bExec || info.length == -1 { // +deleted files from its first snapshot
							log.WithFields(log.Fields{"file": file, "info": info}).Debug("AN: add")
							c.fInfo[file] = info
						}
					}
				}
				p.unlockProcMux()
			}
		}
	} else { // Removed
		if ok := p.fsnCtr.RemoveContainer(id, cPath); !ok {
			log.WithFields(log.Fields{"id": id, "cPath": cPath}).Debug("AN: remove failed")
		}

		// should remove all data for this container
		p.lockProcMux()
		if c, ok := p.containerMap[id]; ok {
			clearContainerProcesses(c)
			delete(p.containerMap, id)
		}
		p.unlockProcMux()
	}
}

func (p *Probe) HandleAnchorNvProtectChange(bAdd bool, id, cPath, role string, rootPid int) {
	// log.WithFields(log.Fields{"bAdd": bAdd,"id": id, "cPath": cPath, "rootPid": rootPid}).Debug()
	if bAdd {
		if rootPid != 0 {
			if ok, _ := p.fsnCtr.AddContainer(id, cPath, role, rootPid); !ok {
				log.WithFields(log.Fields{"id": id, "cPath": cPath}).Debug("AN: add failed")
			}
		}
	} else { // Removed
		if ok := p.fsnCtr.RemoveContainer(id, cPath); !ok {
			log.WithFields(log.Fields{"id": id, "cPath": cPath}).Debug("AN: remove failed")
		}
	}
}

func (p *Probe) UpdateFromAllowRule(id, path string) {
	if !p.bProfileEnable {
		return
	}

	p.lockProcMux()
	if c, ok := p.containerMap[id]; ok {
		if _, ok = c.fInfo[path]; ok {
			// this file is already in the file map
			p.unlockProcMux()
			return
		}
	}
	p.unlockProcMux()

	path = strings.TrimPrefix(path, "/")
	if finfo, ok := p.fsnCtr.IsNotExistingImageFile(id, path); ok {
		// it is normal for file_not_exist because our process rules are pod-based
		// this rule could apply to any containers in this pod.
		// the file is not in the image file
		if finfo.fileType == file_not_exist {
			// mLog.WithFields(log.Fields{"id": id, "path": path, "finfo": finfo}).Debug("FSN: not image file")
			p.lockProcMux()
			if c, ok := p.containerMap[id]; ok {
				c.fInfo[path] = finfo
			}
			p.unlockProcMux()
		}
	}
}

func (p *Probe) GetProcessInfo(pid int) (*procInternal, bool) {
	p.lockProcMux()
	defer p.unlockProcMux()
	if proc, ok := p.pidProcMap[pid]; ok {
		mLog.WithFields(log.Fields{"name": proc.name, "pname": proc.pname, "pid": pid}).Debug("FA:")
		return proc, true
	}
	mLog.WithFields(log.Fields{"pid": pid}).Debug("FA:")
	return nil, false
}

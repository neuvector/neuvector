package probe

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/neuvector/neuvector/agent/workerlet"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/fsmon"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/osutil"
	"github.com/neuvector/neuvector/share/utils"
)

const procSelfFd = "/proc/self/fd/%d"
const procRootMountPoint = "/proc/%d/root"
const (
	rule_not_defined         = -1
	rule_denied              = 0
	rule_allowed             = 1 // allowed without condition
	rule_allowed_image       = 2 // allowed with conditions
	rule_allowed_updateAlert = 3
)

type faProcGrpRef struct {
	name string // parent name
	path string // parent path
	ppid int
}

// whitelist per container
type rootFd struct {
	pid            int
	id             string
	setting        string
	whlst          map[string]int // not set: -1, deny: 0, allow: 1
	dirMonitorList []string
	allowProcList  []faProcGrpRef        // allowed process group
	permitProcGrps map[int]*faProcGrpRef // permitted pgid and ppid
}

// global control data
type FileAccessCtrl struct {
	bEnabled      bool
	prober        *Probe
	ctrlMux       sync.Mutex
	fanfd         *fsmon.NotifyFD
	roots         map[string]*rootFd // container id, invidual control list
	lastReportPid int                // filtering reppeated report
	marks         int                // monitor total aloocated marks
}

type FileAccessProbeData struct {
	nRoots     int
	nMarks     int
	nEntryCnt  int
	nDirMonCnt int
}

func (fa *FileAccessCtrl) lockMux() {
	// log.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("FA: ")
	fa.ctrlMux.Lock()
}

func (fa *FileAccessCtrl) unlockMux() {
	fa.ctrlMux.Unlock()
	// log.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("FA: ")
}

// unixIsEAGAIN reports whether err is a syscall.EAGAIN wrapped in a PathError.
// See golang.org/issue/9205
func unixIsEAGAIN(err error) bool {
	if pe, ok := err.(*os.PathError); ok {
		if errno, ok := pe.Err.(syscall.Errno); ok && errno == syscall.EAGAIN {
			return true
		}
	}
	return false
}

/////
func appendDirPath(dirs []string, path string) []string {
	// append monitor directory
	dir := filepath.Dir(path)
	bFound := false
	for _, v := range dirs {
		if v == dir {
			bFound = true
			break
		}
	}

	if !bFound {
		//	log.WithFields(log.Fields{"dir": dir}).Debug("FA: add dir ==>")
		dirs = append(dirs, dir)
	}

	return dirs
}

/////
func (fa *FileAccessCtrl) enumExecutables(rootpid int, id string) (map[string]int, []string) {
	var dirs []string
	execs := make(map[string]int)

	rootPath := fmt.Sprintf(procRootMountPoint, rootpid)

	///
	res := workerlet.WalkPathResult{
		Dirs:  make([]*workerlet.DirData, 0),
		Files: make([]*workerlet.FileData, 0),
	}

	// Prevent from enumerating a huge sized "GigaBytes" container and it takes too much time
	// If it hits timeout, the enum function will return an incomplete map.
	// Thus, we can make partial protections here and leave other processes into process monitor
	// The 4 sec timeout (by design) is commonly enough for 160,000 files and 4 GB container
	req := workerlet.WalkPathRequest{
		Pid:     rootpid,
		Path:    "/",
		Timeout: time.Duration(4 * time.Second),
	}

	bytesValue, _, err := fa.prober.walkerTask.RunWithTimeout(req, id, req.Timeout)
	if err == nil {
		err = json.Unmarshal(bytesValue, &res)
	}

	if err != nil {
		log.WithFields(log.Fields{"path": rootPath, "error": err}).Error("FA:")
	}

	for _, f := range res.Files {
		if f.IsExec {
			execs[f.File] = rule_not_defined // default: unset and black list
			// append monitor directory
			dirs = appendDirPath(dirs, f.File)
			// log.WithFields(log.Fields{"file": f.File}).Debug("FA: add file")
		}
	}
	log.WithFields(log.Fields{"path": rootPath, "execs": len(execs), "dirs": len(dirs)}).Debug("FA: done")
	return execs, dirs
}

////////////
func NewFileAccessCtrl(p *Probe) (*FileAccessCtrl, bool) {
	log.Debug("FA: ")
	fa := &FileAccessCtrl{
		bEnabled: false,
		roots:    make(map[string]*rootFd),
		prober:   p,
	}

	// docker cp (file changes) might change the polling behaviors,
	// remove the non-block io to controller the polling timeouts
	flags := fsmon.FAN_CLOEXEC | fsmon.FAN_CLASS_CONTENT | fsmon.FAN_UNLIMITED_MARKS
	fn, err := fsmon.Initialize(flags, os.O_RDONLY|syscall.O_LARGEFILE)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("FA: Initialize")
		return nil, false
	}

	// fill in
	fa.bEnabled = true
	fa.fanfd = fn

	// default: test the availability of open_permissions
	if !fa.isSupportOpenPerm() {
		fa.bEnabled = false // reset it back
		return nil, false
	}

	go fa.monitorFilePermissionEvents()
	return fa, true
}

/////
func (fa *FileAccessCtrl) addDirMarks(pid int, dirs []string) (bool, int) {
	ppath := fmt.Sprintf(procRootMountPoint, pid)
	for _, dir := range dirs {
		path := ppath + dir
		err := fa.fanfd.Mark(fsmon.FAN_MARK_ADD, fsmon.FAN_OPEN_PERM|fsmon.FAN_EVENT_ON_CHILD, unix.AT_FDCWD, path)
		if err != nil {
			log.WithFields(log.Fields{"path": path, "error": err}).Error("FA: ")
		} else {
			log.WithFields(log.Fields{"path": path}).Debug("FA: ")
		}
	}
	return true, len(dirs)
}

///// remove all marks even if we did not mark it (whitelist) before
//  note: ibm cloud does not support the FAN_MARK_FLUSH flag
func (fa *FileAccessCtrl) removeDirMarks(pid int, dirs []string) int {
	ppath := fmt.Sprintf(procRootMountPoint, pid)
	for _, dir := range dirs {
		path := ppath + dir
		fa.fanfd.Mark(fsmon.FAN_MARK_REMOVE, fsmon.FAN_OPEN_PERM|fsmon.FAN_EVENT_ON_CHILD, unix.AT_FDCWD, path)
	}
	return len(dirs)
}

/////
func (fa *FileAccessCtrl) isSupportOpenPerm() bool {
	path := fmt.Sprintf(procRootMountPoint, 1)
	err := fa.fanfd.Mark(fsmon.FAN_MARK_ADD, fsmon.FAN_OPEN_PERM, unix.AT_FDCWD, path)
	fa.fanfd.Mark(fsmon.FAN_MARK_REMOVE, fsmon.FAN_OPEN_PERM, unix.AT_FDCWD, path)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("FA: not supported")
		return false
	}
	return true
}

/////
func (fa *FileAccessCtrl) monitorExit() {
	if fa.fanfd != nil {
		fa.fanfd.Close()
	}

	if fa.prober != nil {
		fa.prober.FaEndChan <- true
	}
}

/////
func (fa *FileAccessCtrl) Close() {
	log.Debug("FA:")
	if !fa.bEnabled {
		log.Debug("FA: not supported")
		return
	}

	fa.lockMux()
	defer fa.unlockMux()

	for _, cRoot := range fa.roots {
		fa.removeDirMarks(cRoot.pid, cRoot.dirMonitorList)
		cRoot.dirMonitorList = nil
		cRoot.allowProcList = nil
		cRoot.permitProcGrps = make(map[int]*faProcGrpRef, 0)
	}
	fa.bEnabled = false

	//// backup plan : 5 seconds
	go func() {
		time.Sleep(5 * time.Second)
		fa.monitorExit()
		log.Info("FMON: exit2")
	}()
}

/////
func (fa *FileAccessCtrl) isRecursiveDirectoryList(root *rootFd, name, path string, bAllow, updateAlert bool) bool {
	if name == "*" && strings.HasSuffix(path, "/*") {
		dir := path
		i := strings.LastIndex(dir, "/")
		if i >= 0 {
			dir = dir[0:i]
		}

		// log.WithFields(log.Fields{"dir": dir, "path": path, "allow": bAllow}).Debug("FA:")
		for p, _ := range root.whlst {
			if strings.HasPrefix(p, dir) && root.whlst[p] == rule_not_defined { // "" is an impossible entry here
				if bAllow {
					if updateAlert {
						root.whlst[p] = rule_allowed_updateAlert
					} else {
						root.whlst[p] = rule_allowed
					}
				} else {
					root.whlst[path] = rule_denied
				}
				log.WithFields(log.Fields{"path": p, "allow": bAllow}).Debug("FA:")
			}
		}
		return true
	}
	return false
}

/////  application match for applications
func (fa *FileAccessCtrl) isApplicationMatched(root *rootFd, name, path string, bAllow, updateAlert bool) bool {
	if name != "*" && (strings.HasSuffix(path, "*") || path == "") {
		dir := path
		i := strings.LastIndex(path, "/")
		if i >= 0 { // recursive directory
			dir = dir[0:i]
		} else if path == "*" || path == "" { // matching all
			dir = "/"
		}

		for p, _ := range root.whlst {
			i := strings.LastIndex(p, "/")
			n := p[i+1:]
			if strings.HasPrefix(p, dir) && n == name && root.whlst[p] == rule_not_defined {
				if bAllow {
					if updateAlert {
						root.whlst[p] = rule_allowed_updateAlert
					} else {
						root.whlst[p] = rule_allowed
					}
				} else {
					root.whlst[p] = rule_denied
				}
				log.WithFields(log.Fields{"path": p, "name": n, "allow": bAllow}).Debug("FA:")
			}
		}
		return true
	}
	return false
}

///// regular or user defined, adding it into list
func (fa *FileAccessCtrl) addToMonitorList(root *rootFd, path string, bAllow, updateAlert bool) {
	if state, ok := root.whlst[path]; ok {
		if state != rule_not_defined {
			return // existing and set
		}
		log.WithFields(log.Fields{"path": path, "allow": bAllow}).Debug("FA: ")
	} else {
		log.WithFields(log.Fields{"path": path, "allow": bAllow}).Debug("FA: user-defined")
		root.dirMonitorList = appendDirPath(root.dirMonitorList, path)
	}

	//
	if bAllow {
		if updateAlert {
			root.whlst[path] = rule_allowed_updateAlert
		} else {
			root.whlst[path] = rule_allowed
		}
	} else {
		root.whlst[path] = rule_denied
	}
}

/////// Merge Monitor Lists
func (fa *FileAccessCtrl) mergeMonitorRuleList(root *rootFd, list []string, bAllow, updateAlert bool) {
	if len(list) > 0 {
		if list[0] == "*:*" {
			// allow all applications
			for p, _ := range root.whlst {
				if root.whlst[p] == rule_not_defined {
					if bAllow {
						if updateAlert {
							root.whlst[p] = rule_allowed_updateAlert
						} else {
							root.whlst[p] = rule_allowed
						}
					} else {
						root.whlst[p] = rule_denied
					}
				}
			}
			return
		}

		////// merged
		for _, path := range list {
			if path == "" {
				continue
			}

			// log.WithFields(log.Fields{"path": path, "allow": bAllow}).Debug("FA:")
			i := strings.LastIndex(path, ":")
			if i > 0 { //
				n := path[0:i]
				p := path[i+1:]

				if bAllow && strings.HasSuffix(n, "/*") {
					n = strings.TrimSuffix(n, "/*") // allowed parent name
					item := faProcGrpRef{name: n, path: p}
					root.allowProcList = append(root.allowProcList, item)
					log.WithFields(log.Fields{"allow": bAllow, "item": item}).Debug("FA: allowed parent")
				}

				// log.WithFields(log.Fields{"path": p, "name": n}).Debug("FA:")
				// application match for applications
				if fa.isApplicationMatched(root, n, p, bAllow, updateAlert) {
					continue
				}

				// recursive white list
				if fa.isRecursiveDirectoryList(root, n, p, bAllow, updateAlert) {
					continue
				}
			} else if i == -1 {
				// regular cases
				fa.addToMonitorList(root, path, bAllow, updateAlert)
			}
		}
	}
}

/////
func (fa *FileAccessCtrl) AddContainerControlByPolicyOrder(id, setting string, rootpid int, process []*share.CLUSProcessProfileEntry) bool {
	if !fa.bEnabled {
		log.Debug("FA: not supported")
		return false
	}

	execs, dirs := fa.enumExecutables(rootpid, id)

	fa.lockMux()
	defer fa.unlockMux()

	//// existing entry, remove its marks at first
	if cRoot, ok := fa.roots[id]; ok {
		cnt := fa.removeDirMarks(cRoot.pid, cRoot.dirMonitorList)
		cRoot.dirMonitorList = nil
		cRoot.allowProcList = nil
		cRoot.permitProcGrps = nil
		fa.marks -= cnt
		delete(fa.roots, id)
	}

	//// create host cRoot
	root := &rootFd{
		pid:            rootpid,
		id:             id,
		setting:        setting,
		whlst:          execs,
		dirMonitorList: dirs,
		allowProcList:  make([]faProcGrpRef, 0),
		permitProcGrps: make(map[int]*faProcGrpRef),
	}

	//
	var list []string
	for _, proc := range process {
		// log.WithFields(log.Fields{"name": proc.Name, "path": proc.Path, "action": proc.Action, "id": id}).Debug("FA: ")
		if proc.Path != "" {
			clean := filepath.Clean(proc.Path)
			if clean == "." || clean == "/" {
				log.WithFields(log.Fields{"name": proc.Name, "path": proc.Path, "clean": clean, "id": id}).Debug("FA: invalid path")
				continue
			}

			if clean != proc.Path {
				log.WithFields(log.Fields{"name": proc.Name, "path": proc.Path, "clean": clean, "id": id}).Debug("FA: clean path")
			}

			proc.Path = clean
		}

		list = nil
		if proc.Name == "*" && (proc.Path == "*" || proc.Path == "/*") {
			// special entry: all files
			list = append(list, "*:*")
		} else if proc.Path == "" || strings.HasSuffix(proc.Path, "*") || strings.HasSuffix(proc.Name, "/*") {
			// recursive case + app matching
			list = append(list, fmt.Sprintf("%s:%s", proc.Name, proc.Path))
		} else {
			list = append(list, proc.Path)
		}
		fa.mergeMonitorRuleList(root, list, proc.Action == share.PolicyActionAllow, proc.AllowFileUpdate == false)
	}

	////
	ok, cnt := fa.addDirMarks(root.pid, root.dirMonitorList)
	if !ok {
		log.Debug("FA: failed")
		return false
	}

	fa.marks += cnt
	fa.roots[id] = root // put the entry
	log.WithFields(log.Fields{"marks": cnt, "total_marks": fa.marks, "exec_cnt": len(execs)}).Debug("FA: add marks")
	return true
}

func (fa *FileAccessCtrl) RemoveContainerControl(id string) bool {
	if !fa.bEnabled {
		log.Debug("FA: not supported")
		return false
	}

	// log.Debug("FA:")

	fa.lockMux()
	defer fa.unlockMux()

	if cRoot, ok := fa.roots[id]; ok {
		cnt := fa.removeDirMarks(cRoot.pid, cRoot.dirMonitorList)
		cRoot.dirMonitorList = nil
		cRoot.allowProcList = nil
		cRoot.permitProcGrps = make(map[int]*faProcGrpRef, 0)
		fa.marks -= cnt
		log.WithFields(log.Fields{"id": id, "marks": cnt, "total_marks": fa.marks}).Debug("FA:")
		for k := range cRoot.whlst { // clean up
			delete(cRoot.whlst, k)
		}
		cRoot = nil // clean up, let garbage collector to clean it
		delete(fa.roots, id)
	}
	return true
}

/////
func (fa *FileAccessCtrl) AddBlackListOnTheFly(id string, list []string) bool {
	if !fa.bEnabled {
		log.Debug("FA: not supported")
		return false
	}

	////
	fa.lockMux()
	defer fa.unlockMux()

	/////
	cRoot, ok := fa.roots[id]
	if !ok {
		// log.WithFields(log.Fields{"id": id}).Debug("FA: not found")
		return false
	}

	//// Do not access files after lock, it could cause deadlocks among file accesses and  Fanotify
	cur := len(cRoot.dirMonitorList) // reference
	for _, path := range list {
		// check it whether is an allowed rule
		if res, ok := cRoot.whlst[path]; ok && res > rule_denied {
			// res=1: allowed
			// res=3: allowed with not AllowFileUpdate
			// log.WithFields(log.Fields{"path": path}).Debug("FA: allowed")
			fa.addToMonitorList(cRoot, path, true, (res == rule_allowed_updateAlert))
			continue
		}
		// log.WithFields(log.Fields{"path": path}).Debug("FA: denied")
		fa.addToMonitorList(cRoot, path, false, false)
	}

	if cur == len(cRoot.dirMonitorList) { // not adding new marks
		log.WithFields(log.Fields{"total_marks": fa.marks}).Debug("FA:")
		return true
	}

	ok, cnt := fa.addDirMarks(cRoot.pid, cRoot.dirMonitorList[cur:])
	if !ok {
		log.Debug("FA: failed")
		return false
	}

	fa.marks += cnt
	log.WithFields(log.Fields{"marks": cnt, "total_marks": fa.marks}).Debug("FA:")
	return true
}

func (fa *FileAccessCtrl) isAllowedByParentApp(cRoot *rootFd, pid int) (bool, string, string, int) {
	if len(cRoot.allowProcList) == 0 {
		return false, "", "", 0
	}

	// the pgid id was created at a shell command to run a shell script
	// it will pass down into all following processes
	// for example,
	//   (0) pid=71865: cmd=[/bin/bash ] name=bash parent=docker-containerd-shim path=/bin/bash ppath=/usr/bin/docker-containerd-shim
	//       ** tagging script: a.sh
	//   (1) pgid=79117, pid=79117: cmd=[/bin/bash ./a.sh ] name=a.sh parent=bash path=/bin/bash  ppath=/bin/bash ppid=71865
	//   (2) pgid=79117, pid=79118: cmd=[sleep 1 ] id=[9884] name=sleep parent=a.sh path=/bin/sleep ppath=/bin/bash ppid=79117
	//       ** following script: b.sh
	//   (4) pgid=79117 pid=79119:cmd=[/bin/bash ./b.sh ] name=b.sh parent=a.sh path=/bin/bash ppath=/bin/bash ppid=79117
	//   (5) pgid=79117 pid=79120: cmd=[sleep 2 ] name=sleep parent=b.sh path=/bin/sleep ppath=/bin/bash ppid=79119
	//       ** same pgid for all children and grandchildren, and so on
	pgid := osutil.GetProcessGroupId(pid)
	if pgid > 0 {
		if ref, ok := cRoot.permitProcGrps[pgid]; ok {
			ppid, _, _, _, _ := osutil.GetProcessPIDs(pgid)
			if ref.ppid == ppid { // verify the ppid
				return true, ref.name, ref.path, pgid
			} else {
				// invalid match, reset record
				delete(cRoot.permitProcGrps, pgid)
				ref = nil
			}
		}
	}

	// calling process is the parent script, tagging the process (1)
	var allowed bool
	var path string
	name, _, _, _ := osutil.GetProcessUIDs(pgid) // official name ... sync-ed to probe

	// log.WithFields(log.Fields{name": name, "pgid": pgid, "ppid": ppid, "pid": pid}).Debug("FA:")
	for _, s := range cRoot.allowProcList {
		if name == s.name {
			path, _ = global.SYS.GetFilePath(pgid)
			if s.path == "" || s.path == "*" || s.path == "/*" {
				allowed = true
			}

			if !allowed && strings.HasSuffix(s.path, "/*") {
				p := strings.TrimSuffix(s.path, "/*")
				allowed = strings.HasPrefix(path, p)
			}

			if !allowed {
				allowed = (path == s.path)
			}
		}

		if allowed {
			ppid, _, _, _, _ := osutil.GetProcessPIDs(pgid)
			ref := &faProcGrpRef{name: s.name, path: s.path, ppid: ppid}
			cRoot.permitProcGrps[pgid] = ref
			log.WithFields(log.Fields{"session": ref, "pgid": pgid}).Debug("FA: found allowed parent")
			break
		}
	}
	return allowed, name, path, pgid
}

func (fa *FileAccessCtrl) checkAllowedShieldProcess(id, path string, pid, res int) (bool, *share.CLUSProcessProfileEntry) {
	if fa.prober == nil {
		return false, nil
	}
	name := filepath.Base(path) // open app
	sid, pgid := osutil.GetSessionId(pid), osutil.GetProcessGroupId(pid)
	proc := &procInternal{pid: pid, name: name, path: path, ppid: pid, sid: sid, pgid: pgid}
	group, _, _ := fa.prober.getServiceGroupName(id)
	ppe := &share.CLUSProcessProfileEntry{Name: name, Path: path, DerivedGroup: group}
	switch res {
	case rule_not_defined:
		ppe.Action = share.PolicyActionOpen // no defined rule
	case rule_denied:
		ppe.Action = share.PolicyActionDeny
	case rule_allowed:
		ppe.Action = share.PolicyActionAllow
	case rule_allowed_image, rule_allowed_updateAlert: // add checking
		ppe.Action = share.PolicyActionAllow
		ppe.AllowFileUpdate = false
	}

	pass := fa.prober.IsAllowedShieldProcess(id, share.PolicyModeEnforce, proc, ppe, false)
	return pass, ppe // permitted ?
}

func (fa *FileAccessCtrl) whiteListCheck(path string, pid int) (string, string, int) {
	res := rule_allowed // allowed all
	profileSetting := share.ProfileBasic
	// check if the /proc/xxx/cgroup exists
	id, _, _, found := global.SYS.GetContainerIDByPID(pid)
	if id == fa.prober.selfID {
		// log.WithFields(log.Fields{"id": id}).Debug("FA: agent, pass")
		return id, profileSetting, res // allow agent operations
	}

	// Pass any request to avoid the blocked file open
	if !fa.bEnabled {
		return id, profileSetting, res
	}

	// log.WithFields(log.Fields{"id": id, "found": found, "path": path}).Debug("FA: ")

	if found {
		fa.lockMux()
		defer fa.unlockMux()
		cRoot, ok := fa.roots[id] // enforcer is not in the list
		if ok {
			profileSetting = cRoot.setting
			if ok, pname, ppath, pgid := fa.isAllowedByParentApp(cRoot, pid); ok {
				log.WithFields(log.Fields{"pname": pname, "ppath": ppath, "pid": pid, "pgid": pgid}).Debug("FA: allowed by parent")
				return id, profileSetting, res
			}

			if rres, ok := cRoot.whlst[path]; ok {
				// log.WithFields(log.Fields{"res": res}).Debug("FA: ")
				///// suspicious exec : skip for common health check
				if strings.HasSuffix(path, "/nc") || strings.HasSuffix(path, "/ncat") || strings.HasSuffix(path, "/netcat") {
					if rres != 0 { // only check denied case
						rres = rule_not_defined
					}
				}
				return id, profileSetting, rres
			} else {
				//	log.Debug("FA: not in the whtlst")
			}
		}
	}
	return id, profileSetting, res
}

func (fa *FileAccessCtrl) processEvent(ev *fsmon.EventMetadata) {
	if (ev.Mask & fsmon.FAN_OPEN_PERM) > 0 {
		var ppe *share.CLUSProcessProfileEntry
		var pass bool
		var ppath, pname string

		res := -1 // undefined

		// read fd from my process
		pid := (int)(ev.Pid)
		path, err := os.Readlink(fmt.Sprintf(procSelfFd, ev.File.Fd()))
		name := filepath.Base(path) // estimated

		// obtain parent process information
		if fa.prober != nil {
			if proc, ok := fa.prober.GetProcessInfo(pid); ok {
				pname = proc.name
				ppath = proc.path
				if ppath == "" && pname == proc.pname {
					ppath = proc.ppath // runc: copy from its parent
				}
				// mLog.Debug("from db")
			}
		}

		if pname == "" || ppath == "" {
			// mLog.WithFields(log.Fields{"pname": pname, "ppath": ppath, "pid": pid}).Debug("not in db")
			ppath, _ = global.SYS.GetFilePath(pid)
			pname, _, _, _ = osutil.GetProcessUIDs(pid)
		}

		// mLog.WithFields(log.Fields{"name": name, "path": path, "pname": pname, "ppath": ppath, "pid": pid}).Debug("FA:")
		// Let the RT apps pass here
		// (no idea which symbolic-link app is going to run at next, like "ps in the busybox shell").
		// Definitively, we want to bypass "ps" here and screen them at the process killer
		// For example, the "ps" commands (opening "/bin/busybox") for runtime services:
		//     openshift uses "docker-runc-current", but docker-native uses "docker"
		if err == nil && !fa.isParentProcessException(pname, ppath, name, path) {
			var id, profileSetting string
			// cmds, _ := global.SYS.ReadCmdLine(pid)
			id, profileSetting, res = fa.whiteListCheck(path, pid)
			// mLog.WithFields(log.Fields{"path": path, "pid": pid, "id": id, "profileSetting": profileSetting, "res": res}).Debug("FA:")
			if res != rule_denied && res != rule_allowed && profileSetting == share.ProfileZeroDrift { // not match any rule
				pass, ppe = fa.checkAllowedShieldProcess(id, path, pid, res)
				if pass {
					res = rule_allowed_image // image file only
					log.WithFields(log.Fields{"id": id, "ppe": ppe}).Debug("SHD: allowed")
				} else {
					res = rule_not_defined // reject it
				}
			}

			if res < rule_allowed {
				// the same event with the same pid will come into the routine twice
				if fa.lastReportPid != pid { // it solve 80% case, let the aggregater to filter out the same pid's reports
					go func() {
						var msg string
						if ppe != nil && ppe.Uuid == share.CLUSReservedUuidAnchorMode {
							msg = "Process profile violation, this file has been modified: execution denied"
						} else {
							msg = "Process profile violation: execution denied"
						}

						alert := &ProbeProcess{
							ID:    id,
							Pid:   pid,
							Path:  path,
							Name:  name,
							PPath: ppath,
							PName: pname,
							Msg:   msg,
						}

						if fa != nil {
							if ppe == nil {
								alert.Group, alert.RuleID = fa.prober.getEstimateProcGroup(alert.ID, alert.Name, alert.Path)
							} else {
								alert.Group, alert.RuleID = ppe.DerivedGroup, ppe.Uuid
							}
							// log.WithFields(log.Fields{"id": id, "alert": *alert}).Info("FA: Process denied")
							rpt := ProbeMessage{Type: PROBE_REPORT_PROCESS_DENIED, Process: alert, ContainerIDs: utils.NewSet(id)}
							fa.prober.SendAggregateProbeReport(&rpt, true)
						}
					}()

					fa.lastReportPid = pid // it is incremental and wrapped-around
				}
			}
		}

		err = fa.fanfd.Response(ev, res > rule_denied)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Error("FA: response fail")
		}

		///////
		if res > rule_denied {
			//	mLog.WithFields(log.Fields{"path": linkPath}).Debug("FA: allowed")
		} else {
			log.WithFields(log.Fields{"path": path}).Debug("FA: denied")
		}
	}
}

func (fa *FileAccessCtrl) handleEvents() {
	for {
		ev, err := fa.fanfd.GetEvent()
		if err != nil {
			// if !strings.HasSuffix(err, "resource temporarily unavailable") {
			if !unixIsEAGAIN(err) {
				log.WithFields(log.Fields{"err": err}).Error("FA:")
			}
			return
		}

		fa.processEvent(ev)
		ev.File.Close()
	}
}

// main worker: goroutine
func (fa *FileAccessCtrl) monitorFilePermissionEvents() {
	waitCnt := 0
	pfd := make([]unix.PollFd, 1)
	pfd[0].Fd = fa.fanfd.GetFd()
	pfd[0].Events = unix.POLLIN
	log.Info("FA: start")
	for {
		n, err := unix.Poll(pfd, 1000)       // wait 1 sec
		if err != nil && err != unix.EINTR { // not interrupted by a signal
			log.WithFields(log.Fields{"err": err}).Error("FA: poll returns error")
			break
		}
		if n <= 0 {
			if n == 0 && !fa.bEnabled { // timeout at exit stage
				waitCnt += 1
				if waitCnt > 1 { // two chances
					break
				}
			}
			continue
		}

		if (pfd[0].Revents & unix.POLLIN) != 0 {
			fa.handleEvents()
			waitCnt = 0
		}
	}

	fa.monitorExit()
	log.Info("FA: exit")
}

/////
func (fa *FileAccessCtrl) GetProbeData() *FileAccessProbeData {
	var probeData FileAccessProbeData

	if !fa.bEnabled {
		log.Debug("FA: not supported")
		return &probeData
	}

	fa.lockMux()
	defer fa.unlockMux()

	probeData.nRoots = len(fa.roots)
	probeData.nMarks = fa.marks
	for _, cRoot := range fa.roots {
		probeData.nEntryCnt += len(cRoot.whlst)           // include black and white entries
		probeData.nDirMonCnt += len(cRoot.dirMonitorList) // the number should match marks
	}

	return &probeData
}

func (fa *FileAccessCtrl) isParentProcessException(pname, ppath, name, path string) bool {
	// mLog.WithFields(log.Fields{"pname": pname, "path": ppath}).Debug("FA:")
	if name == "ps" {
		return true // common service call
	}

	if ppath == "/usr/bin/pod" && pname == "pod" { // pod services
		return true
	}

	// runtime or cni commands
	if global.RT.IsRuntimeProcess(pname, nil) || filepath.Dir(ppath) == "/opt/cni/bin" {
		switch name {
		case "portmap", "containerd", "sleep", "uptime", "ip": // NV4856
			return true
		case "mount", "lsof", "getent", "adduser", "useradd": // from AWS
			return true
		}
	}
	return false
}

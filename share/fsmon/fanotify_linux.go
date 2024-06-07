package fsmon

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/utils"
)

const procSelfFd = "/proc/self/fd/%d"
const procRootMountPoint = "/proc/%d/root"

type PidLookupCallback func(pid int) *ProcInfo

type rootFd struct {
	accessMonitor bool
	permControl   bool
	capBlock      bool
	bNeuVectorSvc bool
	pid           int
	dirMonitorMap map[string]uint64    // mask:
	rules         map[string]utils.Set // allowed processes

	// references
	paths map[string]*IFile
	dirs  map[string]*IFile
}

type FaNotify struct {
	fNotify
	bEnabled   bool
	configPerm bool
	agentPid   int
	ourRootPid int
	fa         *NotifyFD
	roots      map[int]*rootFd
	mntRoots   map[uint64]*rootFd
	pidLookup  PidLookupCallback
	sys        *system.SystemTools
	endChan    chan bool
}

const faInitFlags = FAN_CLOEXEC | FAN_CLASS_CONTENT | FAN_UNLIMITED_MARKS
const faMarkAddFlags = FAN_MARK_ADD
const faMarkDelFlags = FAN_MARK_REMOVE
const faMarkMask = FAN_CLOSE_WRITE | FAN_MODIFY
const faMarkMaskDir = FAN_ONDIR | FAN_EVENT_ON_CHILD

func NewFaNotify(endFaChan chan bool, cb PidLookupCallback, sys *system.SystemTools) (*FaNotify, error) {
	// log.Debug("FMON: ")
	fa, err := Initialize(faInitFlags, os.O_RDONLY|syscall.O_LARGEFILE)
	if err != nil {
		return nil, err
	}
	in := FaNotify{
		fa:        fa,
		pidLookup: cb,
		sys:       sys,
		roots:     make(map[int]*rootFd),
		mntRoots:  make(map[uint64]*rootFd),
		agentPid:  os.Getpid(),
		endChan:   endFaChan,
		bEnabled:  true,
	}
	in.configPerm = in.checkConfigPerm()
	return &in, nil
}

func (fn *FaNotify) checkConfigPerm() bool {
	tmpDir, err := os.MkdirTemp(os.TempDir(), "fan_test")
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("FMON: Create temp directory fail")
		return false
	}
	defer os.RemoveAll(tmpDir)

	mask := uint64(FAN_OPEN_PERM | FAN_ONDIR)
	err = fn.fa.Mark(faMarkAddFlags, mask, 0, tmpDir)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("FMON: not supported")
		return false
	}

	err = fn.fa.Mark(faMarkDelFlags, mask, 0, tmpDir)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Debug("delete mark fail")
	}
	return true
}

// set file monitor policy mode. but not update the watches. the upper layer need to re-add the watches.
func (fn *FaNotify) SetMode(rootPid int, access, perm, capBlock, bNeuvectorSvc bool) {
	if !fn.bEnabled {
		return
	}

	log.WithFields(log.Fields{"rootPid": rootPid, "access": access, "perm": perm, "capBlock": capBlock}).Debug("FMON:")
	fn.mux.Lock()
	defer fn.mux.Unlock()

	if cRoot, ok := fn.roots[rootPid]; ok {
		//// TODO: existing entry, remove its marks HERE
		cRoot.dirMonitorMap = nil
		cRoot.paths = nil
		cRoot.dirs = nil
		delete(fn.roots, rootPid)
	}

	r := &rootFd{
		pid:           rootPid,
		paths:         make(map[string]*IFile),
		dirs:          make(map[string]*IFile),
		dirMonitorMap: make(map[string]uint64), // mask per directory
		accessMonitor: access,
		permControl:   perm,
		capBlock:      capBlock,
		bNeuVectorSvc: bNeuvectorSvc,
	}

	fn.roots[rootPid] = r
	fn.mntRoots[fn.sys.GetMntNamespaceId(rootPid)] = r
}

func (fn *FaNotify) GetWatches() []*share.CLUSFileMonitorFile {
	// not support
	return make([]*share.CLUSFileMonitorFile, 0)
}

//////
func (fn *FaNotify) RemoveMonitorFile(path string) {
	log.WithFields(log.Fields{"path": path}).Debug("FMON:")
	fn.mux.Lock()
	defer fn.mux.Unlock()
	rootPid, rPath, err := ParseMonitorPath(path)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Debug("parse path fail")
		return
	}

	if r, ok := fn.roots[rootPid]; ok {
		if ifd, exist := r.paths[rPath]; exist {
			// if the file removed, the mark will be removed automaticly
			err := fn.fa.Mark(faMarkDelFlags, ifd.mask, unix.AT_FDCWD, path)
			if err != nil {
				log.WithFields(log.Fields{"path": ifd.path, "err": err}).Debug("file")
			}
			delete(r.paths, rPath)
			return
		}

		if ifd, exist := r.dirs[rPath]; exist {
			err := fn.fa.Mark(faMarkDelFlags, ifd.mask, unix.AT_FDCWD, path)
			if err != nil {
				log.WithFields(log.Fields{"path": ifd.path, "err": err}).Debug("dir")
			}
			delete(r.dirs, rPath)
			return
		}

		// the file might be a file in one dir
		dirPath := filepath.Dir(rPath)
		if ifd, exist := r.dirs[dirPath]; exist {
			log.WithFields(log.Fields{"file": filepath.Base(rPath)}).Debug("remove file from dir")
			delete(ifd.files, filepath.Base(rPath))
		}

	} else {
		log.WithFields(log.Fields{"rootPid": rootPid}).Debug("container not found")
	}
}

//////
//  note: ibm cloud does not support the FAN_MARK_FLUSH flag
func (fn *FaNotify) removeMarks(r *rootFd) {
	// guarded by its calling function
	// log.WithFields(log.Fields{"rootPid": rootPid}).Debug("FMON: cleanup")
	ppath := fmt.Sprintf(procRootMountPoint, r.pid)
	for dir, mask := range r.dirMonitorMap {
		path := ppath + dir
		fn.fa.Mark(FAN_MARK_REMOVE, mask, unix.AT_FDCWD, path)
	}

	files := []string{"/etc/hosts", "/etc/hostname", "/etc/resolv.conf"}
	for _, file := range files {
		if ifile, ok := r.paths[file]; ok {
			path := ppath + file
			mask := ifile.mask
			fn.fa.Mark(FAN_MARK_REMOVE, mask, unix.AT_FDCWD, path)
		}
	}
}

func (fn *FaNotify) ContainerCleanup(rootPid int) {
	fn.mux.Lock()
	defer fn.mux.Unlock()
	if r, ok := fn.roots[rootPid]; ok {
		fn.removeMarks(r)
		r.paths = nil
		r.dirs = nil
		r.dirMonitorMap = nil
		delete(fn.roots, rootPid)
	}

	for k, m := range fn.mntRoots {
		if m.pid == rootPid {
			//	log.WithFields(log.Fields{"mntRoots": rootPid}).Debug("FMON: clean up")
			delete(fn.mntRoots, k)
		}
	}
}

/////
func (fn *FaNotify) monitorExit() {
	if fn.fa != nil {
		fn.fa.Close()
	}

	if fn.endChan != nil {
		fn.endChan <- true
	}
}

/////
func (fn *FaNotify) Close() {
	log.Debug("FMON: ")
	if !fn.bEnabled {
		return
	}

	fn.mux.Lock()
	defer fn.mux.Unlock()

	// remove all marks
	for _, r := range fn.roots {
		fn.removeMarks(r)
	}

	fn.bEnabled = false

	//// backup plan: 5 seocnds for some docker cp cases
	go func() {
		time.Sleep(5 * time.Second)
		fn.monitorExit()
		log.Info("FMON: exit2")
	}()
}

func (fn *FaNotify) GetWatchFileList(rootPid int) []*share.CLUSFileMonitorFile {
	log.WithFields(log.Fields{"rootPid": rootPid}).Debug("FMON:")
	watches := make([]*share.CLUSFileMonitorFile, 0)
	fn.mux.Lock()
	defer fn.mux.Unlock()
	if r, ok := fn.roots[rootPid]; ok {
		for path, fl := range r.paths {
			file := &share.CLUSFileMonitorFile{
				Path:    path,
				Mask:    fl.mask,
				IsDir:   false,
				Protect: fl.protect,
				Files:   make([]string, 0),
			}
			watches = append(watches, file)
		}
		for path, dir := range r.dirs {
			file := &share.CLUSFileMonitorFile{
				Path:    path,
				Mask:    dir.mask,
				IsDir:   true,
				Protect: dir.protect,
				Files:   make([]string, 0),
			}
			for fl, _ := range dir.files {
				file.Files = append(file.Files, fl)
			}
			watches = append(watches, file)
		}
	}
	return watches
}

// use the path prefix for container index
func ParseMonitorPath(path string) (int, string, error) {
	if a := strings.Index(path, "/root/"); a > 0 {
		if b := strings.LastIndex(path[:a], "/"); b > 0 {
			if pid, err := strconv.ParseInt(path[b+1:a], 10, 32); err == nil {
				return int(pid), path[a+5:], nil
			}
		}
	}
	return 0, "", fmt.Errorf("Invalid path")
}

/////
func (fn *FaNotify) addDirPath(r *rootFd, path string, bDir bool, mask uint64) {
	// append monitor directory
	dir := path
	if !bDir {
		index := strings.LastIndex(path, "/")
		if index < 0 {
			log.WithFields(log.Fields{"path": path}).Error("FMON: illegal path, skip")
			return
		}
		dir = path[0:index]
	}

	if _, ok := r.dirMonitorMap[dir]; ok {
		r.dirMonitorMap[dir] |= mask
	} else {
		r.dirMonitorMap[dir] = mask
	}

	r.dirMonitorMap[dir] |= faMarkMaskDir // always directory
	// log.WithFields(log.Fields{"dir": dir, "dirMon": fmt.Sprintf("0x%08x", r.dirMonitorMap[dir]), "mask": fmt.Sprintf("0x%08x", mask)}).Debug("FMON:")
	return
}

////
func (fn *FaNotify) AddMonitorFile(path string, filter interface{}, protect, userAdded bool, cb NotifyCallback, params interface{}) bool {
	if !fn.bEnabled {
		return false
	}
	return fn.addFile(path, filter, protect, false, userAdded, nil, cb, params)
}

/////
func (fn *FaNotify) AddMonitorDirFile(path string, filter interface{}, protect, userAdded bool, files map[string]interface{}, cb NotifyCallback, params interface{}) bool {
	if !fn.bEnabled {
		return false
	}
	return fn.addFile(path, filter, protect, true, userAdded, files, cb, params)
}

//// TODO
func (fn *FaNotify) AddMonitorFileOnTheFly(path string, filter interface{}, protect, userAdded bool, cb NotifyCallback, params interface{}) bool {
	if !fn.bEnabled {
		return false
	}

	if fn.addFile(path, filter, protect, false, userAdded, nil, cb, params) {
		// TODO: fn.addSingleFile(r *rootFd, path string, mask uint64)
	}
	return false
}

////
func (fn *FaNotify) addSingleFile(r *rootFd, path string, mask uint64) bool {
	if !fn.bEnabled {
		return false
	}

	if err := fn.fa.Mark(faMarkAddFlags, mask, unix.AT_FDCWD, path); err != nil {
		log.WithFields(log.Fields{"path": path, "error": err}).Debug("FMON:")
		return false
	}

	// log.WithFields(log.Fields{"path": path, "mask": fmt.Sprintf("0x%08x", mask)}).Debug("FMON:")
	return true
}

////
func (fn *FaNotify) addHostNetworkFilesCopiedFiles(r *rootFd) {
	// only for /etc/ now: hosts, hostname, and resolv.conf
	files := []string{"/etc/hosts", "/etc/hostname", "/etc/resolv.conf"}
	ppath := fmt.Sprintf(procRootMountPoint, r.pid)
	for _, file := range files {
		if ifile, ok := r.paths[file]; ok {
			path := ppath + file
			mask := ifile.mask
			if !fn.addSingleFile(r, path, mask) {
				//	log.WithFields(log.Fields{"path": path}).Debug("FMON:")
			}
		}
	}
}

/////
func (fn *FaNotify) StartMonitor(rootPid int) bool {
	if !fn.bEnabled {
		return false
	}

	// log.WithFields(log.Fields{"rootPid": rootPid}).Debug("FMON:")
	fn.mux.Lock()
	defer fn.mux.Unlock()

	r, ok := fn.roots[rootPid]
	if !ok {
		log.WithFields(log.Fields{"rootPid": rootPid}).Debug("FMON: not found")
		return false
	}

	//	for filepath, ifile := range r.paths {
	//		log.WithFields(log.Fields{"filepath": filepath, "ifile": ifile}).Debug("FMON: mFile")
	//	}

	//	for dir, ifile := range r.dirs {
	//		log.WithFields(log.Fields{"dir": dir, "ifile": ifile}).Debug("FMON: mDir")
	//	}

	ppath := fmt.Sprintf(procRootMountPoint, rootPid)
	for dir, mask := range r.dirMonitorMap {
		path := ppath + dir
		if err := fn.fa.Mark(faMarkAddFlags, mask, unix.AT_FDCWD, path); err != nil {
			log.WithFields(log.Fields{"path": path, "error": err}).Debug("FMON:")
		} else {
			mLog.WithFields(log.Fields{"path": path, "mask": fmt.Sprintf("0x%08x", mask)}).Debug("FMON:")
		}
	}

	//
	fn.addHostNetworkFilesCopiedFiles(r)
	return ok
}

//////
func (fn *FaNotify) addFile(path string, filter interface{}, protect, isDir, userAdded bool, files map[string]interface{}, cb NotifyCallback, params interface{}) bool {
	if !fn.bEnabled {
		return false
	}

	rootPid, rPath, err := ParseMonitorPath(path)
	if err != nil {
		log.WithFields(log.Fields{"err": err, "file": path}).Debug("")
		return false
	}

	fn.mux.Lock()
	defer fn.mux.Unlock()
	r, ok := fn.roots[rootPid]
	if !ok {
		log.WithFields(log.Fields{"rootPid": rootPid}).Error("FMON: not found")
		return false
	}

	var mask uint64 = faMarkMask
	if userAdded || protect { // user-defined or protected: including access control
		if r.permControl { // protect mode
			if fn.configPerm { // system-wise : access control is available
				mask |= FAN_OPEN_PERM
			} else {
				mask |= FAN_OPEN
			}
		} else {
			mask |= FAN_OPEN
		}
	}

	var file *IFile
	if isDir {
		mask |= faMarkMaskDir
		if file, ok = r.dirs[rPath]; ok {
			// merge the files
			for k, v := range files {
				file.files[k] = v
			}
			// check dir existing
			for name, _ := range file.files {
				fpath := file.path + "/" + name
				if _, err := os.Stat(fpath); os.IsNotExist(err) {
					delete(file.files, name)
				}
			}
			return true
		} else {
			file = &IFile{
				mask:    mask,
				path:    path,
				params:  params,
				cb:      cb,
				dir:     true,
				files:   files,
				filter:  filter.(*filterRegex),
				protect: protect,         // access control
				learnt:  r.accessMonitor, // discover mode
				userAdd: userAdded,
			}
			r.dirs[rPath] = file
		}

	} else {
		if _, ok = r.paths[rPath]; ok {
			return false
		}
		file = &IFile{
			path:    path,
			mask:    mask,
			params:  params,
			cb:      cb,
			filter:  filter.(*filterRegex),
			protect: protect,         // access control
			learnt:  r.accessMonitor, // discover mode
			userAdd: userAdded,
		}

		r.paths[rPath] = file
	}

	fn.addDirPath(r, rPath, isDir, mask)
	// log.WithFields(log.Fields{"rPath": rPath, "isDir": isDir, "protect": protect, "permCtl": r.permControl, "userAdded": userAdded}).Debug("FMON: ")
	return true
}

/////
func (fn *FaNotify) MonitorFileEvents() {
	waitCnt := 0
	pfd := make([]unix.PollFd, 1)
	pfd[0].Fd = fn.fa.GetFd()
	pfd[0].Events = unix.POLLIN
	log.Info("FMON: start")
	for {
		n, err := unix.Poll(pfd, 1000) // wait 1 sec
		if err != nil && err != unix.EINTR {
			log.WithFields(log.Fields{"err": err}).Error("FMON: poll")
			break
		}
		if n <= 0 {
			if n == 0 && !fn.bEnabled { // timeout at exit stage
				// log.WithFields(log.Fields{"waitCnt": waitCnt}).Debug("FMON: timeout")
				waitCnt += 1
				if waitCnt > 1 { // two chances
					break
				}
			}
			continue
		}

		if (pfd[0].Revents & unix.POLLIN) != 0 {
			if err := fn.handleEvents(); err != nil {
				log.WithFields(log.Fields{"err": err}).Error("FMON: handle")
				break
			}
			waitCnt = 0
		}
	}

	fn.monitorExit()
	log.Info("FMON: exit")
}

//////
func (fn *FaNotify) handleEvents() error {
	if events, err := fn.fa.GetEvents(); err == nil {
		for _, ev := range events {
			// log.WithFields(log.Fields{"pid": pid, "fmask": fmt.Sprintf("0x%08x", fmask), "fd": fd}).Debug("FMON:")
			pid := int(ev.Pid)
			fd := int(ev.File.Fd())
			fmask := uint64(ev.Mask)
			perm := (fmask & (FAN_OPEN_PERM | FAN_ACCESS_PERM)) > 0

			resp, mask, ifile, pInfo := fn.calculateResponse(pid, fd, fmask, perm)
			if perm {
				fn.fa.Response(ev, resp)
			}
			ev.File.Close()

			if ifile == nil {
				continue // nothing to justify
			}

			change := (fmask & FAN_CLOSE_WRITE) > 0
			// log.WithFields(log.Fields{"ifile": ifile, "pInfo": pInfo, "Resp": resp, "Change": change, "Perm": perm}).Debug("FMON:")

			var bReporting bool
			if ifile.learnt { // discover mode
				bReporting = ifile.userAdd // learn app for customer-added entry
			} else { // monitor or protect mode
				allowRead := resp && !change
				bReporting = (allowRead == false) // allowed app by block_access
			}

			if bReporting || change { // report changed file
				ifile.cb(ifile.path, mask, ifile.params, pInfo)
			}
		}
	}
	return nil
}

func (fn *FaNotify) calculateResponse(pid, fd int, fmask uint64, perm bool) (bool, uint32, *IFile, *ProcInfo) {
	// allowed all to avoid blocked calls
	if !fn.bEnabled {
		return true, 0, nil, nil
	}

	// skip agent's read
	if pid == fn.agentPid {
		return true, 0, nil, nil
	}

	// get file path
	linkPath, err := os.Readlink(fmt.Sprintf(procSelfFd, fd))
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("FMON: Read link fail")
		return true, 0, nil, nil
	}

	// log.WithFields(log.Fields{"path": linkPath}).Debug("FMON:")
	// lookup the root pid
	r, pInfo := fn.lookupContainer(pid)
	if r == nil {
		// "docker cp agent" case ???
		log.WithFields(log.Fields{"rootPid": pInfo.RootPid, "path": linkPath, "pid": pid}).Debug("FMON: not found")
		return true, 0, nil, nil
	}

	// skip our containers, host runc, system containers
	if (pInfo.RootPid == 1 || !r.capBlock) && perm {
		return true, 0, nil, nil
	}

	ifile, _, mask := fn.lookupFile(r, linkPath, pInfo)
	if ifile == nil {
		return true, mask, nil, nil
	}

	if r.bNeuVectorSvc {
		log.WithFields(log.Fields{"linkPath": linkPath}).Debug("FMON:")
		if strings.HasPrefix(linkPath, "/usr/local/bin/scripts/") {
			pid := pInfo.Pid
			path := pInfo.Path
			for i := 0; i < 5; i++ {
				if filepath.Dir(path) == "/usr/local/bin" {
					switch filepath.Base(path) {
					case "agent", "monitor", "controller", "nstools", "workerlet", "dp":
						return true, 0, nil, nil
					}
				}
				// find the parent
				if _, pid, err = fn.sys.GetProcessName(pid); err != nil {
					break
				}
				path, _ = fn.sys.GetFilePath(pid)
			}
			return false, mask, nil, nil
		}
		return true, 0, nil, nil
	}

	// log.WithFields(log.Fields{"protect": ifile.protect, "perm": perm, "path": linkPath, "ifile": ifile, "evMask": fmt.Sprintf("0x%08x", fmask)}).Debug("FMON:")

	// permition decision
	resp := true
	if ifile.protect { // always verify app for block-access
		resp = fn.lookupRule(r, ifile, pInfo, linkPath)
		// log.WithFields(log.Fields{"resp": resp}).Debug("FMON:")
	}

	if (fmask & FAN_MODIFY) > 0 {
		mask |= syscall.IN_MODIFY
		log.WithFields(log.Fields{"path": linkPath}).Debug("FMON: modified")
	} else if (fmask & FAN_CLOSE_WRITE) > 0 {
		mask |= syscall.IN_CLOSE_WRITE
		log.WithFields(log.Fields{"path": linkPath}).Debug("FMON: cls_wr")
	} else {
		mask |= syscall.IN_ACCESS
		//	log.WithFields(log.Fields{"path": linkPath}).Debug("FMON: read")
		if fn.isFileException(false, linkPath, pInfo, mask) {
			resp = true
			mask &^= syscall.IN_ACCESS
		}
	}

	if perm && !resp {
		pInfo.Deny = true
		log.WithFields(log.Fields{"path": linkPath, "app": pInfo.Path}).Debug("FMON: denied")
	}
	return resp, mask, ifile, pInfo
}

func (fn *FaNotify) lookupRule(r *rootFd, ifile *IFile, pInfo *ProcInfo, linkPath string) bool {
	fn.mux.Lock()
	defer fn.mux.Unlock()

	// if the process name or path empty, cannot check permision
	if r.rules == nil || pInfo.Path == "" {
		log.WithFields(log.Fields{"path": linkPath, "procPath": pInfo.Path}).Debug("FMON: no rule")
		return true
	}

	if apps, ok := r.rules[ifile.filter.path]; ok {
		if apps.Contains(pInfo.Path) || apps.Contains(filepath.Base(pInfo.Path)) ||
			(pInfo.Name != "" && apps.Contains(pInfo.Name)) {
			pInfo.InProfile = true
			return true
		} else {
			return false
		}
	}
	return false
}

func (fn *FaNotify) lookupFile(r *rootFd, linkPath string, pInfo *ProcInfo) (*IFile, bool, uint32) {
	var ifile IFile
	var isDir bool
	var mask uint32

	// ignore the runtime files for NV containers
	if fn.isFileException(r.bNeuVectorSvc, linkPath, nil, 0) {
		return nil, false, 0
	}

	// log.WithFields(log.Fields{"path": linkPath, "Dir": path.Dir(linkPath)}).Debug("FMON:")
	fn.mux.Lock()
	defer fn.mux.Unlock()
	if file, ok := r.paths[linkPath]; ok {
		ifile = *file
	} else if dir, ok := r.dirs[path.Dir(linkPath)]; ok {
		filename := path.Base(linkPath)
		if strings.HasSuffix(dir.path, "/") {
			ifile.path = dir.path + filename
		} else {
			ifile.path = dir.path + "/" + filename
		}
		ifile.cb = dir.cb
		ifile.filter = dir.filter
		ifile.learnt = dir.learnt
		ifile.protect = dir.protect
		ifile.userAdd = dir.userAdd
		if fi, ok := dir.files[filename]; ok {
			ifile.params = fi
		} else if dir.filter != nil && dir.filter.regex != nil && dir.filter.regex.MatchString(linkPath) {
			ifile.params = dir.params
			mask = syscall.IN_CREATE
			if fn.isFileException(r.bNeuVectorSvc, linkPath, nil, mask) {
				return nil, false, 0
			}
			log.WithFields(log.Fields{"file": linkPath}).Debug("FMON: new file")
		} else {
			// the files in dir, but not in the filter
			// log.WithFields(log.Fields{"file": linkPath, "dir": dir, "filename": filename}).Debug("FMON: not in dir files")
			return nil, false, 0
		}
	} else {
		// log.WithFields(log.Fields{"file": linkPath}).Debug("FMON: not found")
		return nil, false, 0
	}
	return &ifile, isDir, mask
}

func (fn *FaNotify) lookupContainer(pid int) (r *rootFd, pInfo *ProcInfo) {
	pInfo = fn.pidLookup(pid)
	if pInfo != nil {
		fn.mux.RLock()
		r, _ = fn.roots[pInfo.RootPid]
		fn.mux.RUnlock()
	} else {
		// TODO: (agent ???) not in probe proc db, use the mnt to lookup
		pInfo = &ProcInfo{}
		mntId := fn.sys.GetMntNamespaceId(pid)
		if mntId == 0 {
			return
		}
		fn.mux.RLock()
		r, _ = fn.mntRoots[mntId]
		fn.mux.RUnlock()
		pInfo.Name, pInfo.PPid, _ = fn.sys.GetProcessName(pid)
		pInfo.Path, _ = fn.sys.GetFilePath(pid)
		pInfo.PPath, _ = fn.sys.GetFilePath(pInfo.PPid)
		pInfo.Cmds, _ = fn.sys.ReadCmdLine(pid)
		if len(pInfo.Cmds) > 0 {
			pInfo.Name = pInfo.Cmds[0]
		}
		if r != nil {
			pInfo.RootPid = r.pid
		} else {
		}
	}
	if pInfo.Pid == 0 {
		pInfo.Pid = pid
	}
	return
}

func (fn *FaNotify) UpdateAccessRule(rootPid int, conf *share.CLUSFileAccessRule) error {
	if !fn.bEnabled {
		return nil
	}

	fn.mux.Lock()
	defer fn.mux.Unlock()
	r, ok := fn.roots[rootPid]
	if !ok {
		log.Error("Container root pid not found")
		return fmt.Errorf("Container root pid not found")
	}
	r.rules = make(map[string]utils.Set)
	for flt, rule := range conf.Filters {
		if rule.CustomerAdd {
			applyRules := utils.NewSet()
			for _, app := range rule.Apps {
				applyRules.Add(app)
			}
			r.rules[flt] = applyRules
		}
	}
	return nil
}

////////
func (fn *FaNotify) GetProbeData(m *FaMonProbeData) {
	fn.mux.Lock()
	defer fn.mux.Unlock()

	m.NRoots = len(fn.roots)
	m.NMntRoots = len(fn.mntRoots)
	for _, r := range fn.roots {
		m.NDirMarks += len(r.dirMonitorMap)
		m.NRules += len(r.rules)
		m.NPaths += len(r.paths)
		m.NDirs += len(r.dirs)
	}
}

func (fn *FaNotify) isFileException(bNeuvectorSvc bool, path string, pInfo *ProcInfo, mask uint32) bool {
	if bNeuvectorSvc {
		dir := filepath.Dir(path)
		ext := filepath.Ext(path)
		// log.WithFields(log.Fields{"path": path, "mask": mask}).Info("FMON:")
		if mask == 0 || (mask&syscall.IN_CREATE) != 0 {
			if (path == "/etc/neuvector/certs/internal/ca.cert") ||
				(path == "/etc/neuvector/certs/internal/cert.key") ||
				(path == "/etc/neuvector/certs/internal/cert.pem") {
				log.WithFields(log.Fields{"path": path}).Info("FMON: important files")
				return false // warnings
			}

			if dir == "/etc/neuvector/certs" || dir == "/etc/neuvector/certs/internal" {
				if ext == ".key" || ext == ".cert" || ext == ".pem" {
					// log.WithFields(log.Fields{"path": path}).Debug("FMON:")
					return true // allowed
				}
			}
		}

		if (mask & syscall.IN_CREATE) != 0 {
			if dir == "/usr/local/bin/prog" && ext == ".pyc" {
				// log.WithFields(log.Fields{"path": path}).Debug("FMON:")
				return true
			}
		}
	}

	if pInfo != nil {
		if (mask & syscall.IN_ACCESS) != 0 {
			// exceptions: common file access(open-read-close)
			// skip incident reports ans allow accesses during Protect mode, even when setting its block-access rule
			if (path == "/etc/passwd" && pInfo.Name == "ps") || (path == "/etc/group" && pInfo.Name == "ls") {
				log.WithFields(log.Fields{"path": path, "proc": pInfo.Name}).Debug("FMON: ignore read")
				return true
			}
		}
	}
	return false
}

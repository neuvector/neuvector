package fsmon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/agent/workerlet"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/osutil"
	"github.com/neuvector/neuvector/share/utils"
)

////
var mLog *log.Logger = log.New()

const inodeChangeMask = syscall.IN_CLOSE_WRITE |
	syscall.IN_DELETE |
	syscall.IN_DELETE_SELF |
	syscall.IN_MOVE |
	syscall.IN_MOVE_SELF |
	syscall.IN_MOVED_TO

const inodeMovedMask = syscall.IN_MOVE | syscall.IN_MOVE_SELF | syscall.IN_MOVED_TO

var packageFile utils.Set = utils.NewSet(
	"/var/lib/dpkg/status",
	"/var/lib/rpm/Packages",
	"/var/lib/rpm/Packages.db",
	"/lib/apk/db/installed")

type SendAggregateReportCallback func(fsmsg *MonitorMessage) bool

var ImportantFiles []share.CLUSFileMonitorFilter = []share.CLUSFileMonitorFilter{
	share.CLUSFileMonitorFilter{Behavior: share.FileAccessBehaviorMonitor, Path: "/var/lib/dpkg/status", Regex: ""},
	share.CLUSFileMonitorFilter{Behavior: share.FileAccessBehaviorMonitor, Path: "/var/lib/rpm/Packages", Regex: ""},
	share.CLUSFileMonitorFilter{Behavior: share.FileAccessBehaviorMonitor, Path: "/lib/apk/db/installed", Regex: ""},
	share.CLUSFileMonitorFilter{Behavior: share.FileAccessBehaviorMonitor, Path: "/var/lib/rpm/Packages.db", Regex: ""},
	share.CLUSFileMonitorFilter{Behavior: share.FileAccessBehaviorMonitor, Path: "/etc/hosts", Regex: ""},
	share.CLUSFileMonitorFilter{Behavior: share.FileAccessBehaviorMonitor, Path: "/etc/passwd", Regex: ""},
	share.CLUSFileMonitorFilter{Behavior: share.FileAccessBehaviorMonitor, Path: "/etc/shadow", Regex: ""},
	share.CLUSFileMonitorFilter{Behavior: share.FileAccessBehaviorMonitor, Path: "/etc/resolv\\.conf", Regex: ""},
	share.CLUSFileMonitorFilter{Behavior: share.FileAccessBehaviorMonitor, Path: "/home/.*/\\.ssh", Regex: ".*"},
	share.CLUSFileMonitorFilter{Behavior: share.FileAccessBehaviorMonitor, Path: "/lib", Regex: "ld-linux\\..*", Recursive: true},
	share.CLUSFileMonitorFilter{Behavior: share.FileAccessBehaviorMonitor, Path: "/lib", Regex: "libc\\..*", Recursive: true},
	share.CLUSFileMonitorFilter{Behavior: share.FileAccessBehaviorMonitor, Path: "/lib", Regex: "libpthread.*", Recursive: true},
	share.CLUSFileMonitorFilter{Behavior: share.FileAccessBehaviorMonitor, Path: "/lib64", Regex: "ld-linux.*", Recursive: true},
	share.CLUSFileMonitorFilter{Behavior: share.FileAccessBehaviorMonitor, Path: "/lib64", Regex: "libc\\..*", Recursive: true},
	share.CLUSFileMonitorFilter{Behavior: share.FileAccessBehaviorMonitor, Path: "/lib64", Regex: "libpthread.*", Recursive: true},
	share.CLUSFileMonitorFilter{Behavior: share.FileAccessBehaviorMonitor, Path: "/bin", Regex: ".*", Recursive: true},
	share.CLUSFileMonitorFilter{Behavior: share.FileAccessBehaviorMonitor, Path: "/sbin", Regex: ".*", Recursive: true},
	share.CLUSFileMonitorFilter{Behavior: share.FileAccessBehaviorMonitor, Path: "/usr/bin", Regex: ".*", Recursive: true},
	share.CLUSFileMonitorFilter{Behavior: share.FileAccessBehaviorMonitor, Path: "/usr/sbin", Regex: ".*", Recursive: true},
	share.CLUSFileMonitorFilter{Behavior: share.FileAccessBehaviorMonitor, Path: "/usr/local/bin", Regex: ".*", Recursive: true},
	share.CLUSFileMonitorFilter{Behavior: share.FileAccessBehaviorMonitor, Path: "/usr/local/sbin", Regex: ".*", Recursive: true},
}

var DefaultContainerConf share.CLUSFileMonitorProfile = share.CLUSFileMonitorProfile{
	Filters: ImportantFiles,
}

const (
	imonitorFileDelay = 10
)

const (
	fileEventAttr uint32 = (1 << iota)
	fileEventDirAttr
	fileEventCreate
	fileEventModified
	fileEventRemoved
	fileEventSymCreate
	fileEventSymModified
	fileEventDirSymCreate
	fileEventDirSymModified
	fileEventReplaced
	fileEventDirCreate
	fileEventDirRemoved
	fileEventAccessed
	fileEventDenied
	fileEventMovedFrom
	fileEventMovedTo
	fileEventDirMovedFrom
	fileEventDirMovedTo
)

var fileEventMsg = map[uint32]string{
	fileEventAttr:           "File attribute is changed.",
	fileEventDirAttr:        "Directory attribute is changed.",
	fileEventModified:       "File was modified.",
	fileEventReplaced:       "File was replaced.",
	fileEventCreate:         "File created in watched directory.",
	fileEventRemoved:        "File deleted from watched directory.",
	fileEventSymCreate:      "File symlink was created.",
	fileEventSymModified:    "File symlink was modified.",
	fileEventDirSymCreate:   "Directory symlink was created.",
	fileEventDirSymModified: "Directory symlink was modified.",
	fileEventDirCreate:      "Directory was created.",
	fileEventDirRemoved:     "Directory was deleted.",
	fileEventAccessed:       "File was accessed.",
	fileEventDenied:         "File access was denied.",
	fileEventMovedFrom:      "File was moved from.",
	fileEventMovedTo:        "File was moved to.",
	fileEventDirMovedFrom:   "Directory was moved from.",
	fileEventDirMovedTo:     "Directory was moved to.",
}

type SendFileAccessRuleCallback func(rules []*share.CLUSFileAccessRuleReq) error
type EstimateRuleSrcCallback func(id, path string, bBlocked bool) string

type fileMod struct {
	mask  uint32
	delay int
	finfo *osutil.FileInfoExt
	pInfo []*ProcInfo
}

type groupInfo struct {
	bNeuvector bool
	profile    *share.CLUSFileMonitorProfile
	mode       string
	applyRules map[string]utils.Set
	learnRules map[string]utils.Set
	startAt    time.Time
}

type FileWatch struct {
	mux        sync.Mutex
	bEnable    bool // profile function is enabled, default: true
	aufs       bool
	bNVProtect bool
	fanotifier *FaNotify
	inotifier  *Inotify
	fileEvents map[string]*fileMod
	groups     map[int]*groupInfo
	sendrpt    SendAggregateReportCallback
	sendRule   SendFileAccessRuleCallback
	estRuleSrc EstimateRuleSrcCallback
	walkerTask *workerlet.Tasker
}

type MonitorMessage struct {
	ID        string
	Path      string
	Package   bool
	ProcName  string
	ProcPath  string
	ProcCmds  []string
	ProcPid   int
	ProcEUid  int
	ProcEUser string
	ProcPPid  int
	ProcPName string
	ProcPPath string
	Group     string
	Msg       string
	Count     int
	StartAt   time.Time
	Action    string
}

type ProcInfo struct {
	RootPid   int
	Name      string
	Path      string
	Cmds      []string
	Pid       int
	EUid      int
	EUser     string
	PPid      int
	PName     string
	PPath     string
	Deny      bool
	InProfile bool
}

type FaMonProbeData struct {
	NRoots    int
	NMntRoots int
	NDirMarks int
	NRules    int
	NPaths    int
	NDirs     int
}

type IMonProbeData struct {
	NWds   int
	NPaths int
	NDirs  int
}

type FmonProbeData struct {
	NFileEvents int
	NGroups     int
	Fan         FaMonProbeData
	Ino         IMonProbeData
}

type FsmonConfig struct {
	Profile *share.CLUSFileMonitorProfile
	Rule    *share.CLUSFileAccessRule
}

type FileMonitorConfig struct {
	ProfileEnable  bool
	IsAufs         bool
	EnableTrace    bool
	NVProtect      bool
	EndChan        chan bool
	WalkerTask     *workerlet.Tasker
	PidLookup      PidLookupCallback
	SendReport     SendAggregateReportCallback
	SendAccessRule SendFileAccessRuleCallback
	EstRule        EstimateRuleSrcCallback
}

func NewFileWatcher(config *FileMonitorConfig, logLevel string) (*FileWatch, error) {
	// for file monitor
	mLog.Out = os.Stdout
	mLog.Level = share.CLUSGetLogLevel(logLevel)
	mLog.Formatter = &utils.LogFormatter{Module: "AGT"}
	if config.EnableTrace {
		mLog.SetLevel(log.DebugLevel)
	}

	fw := &FileWatch{
		bEnable:    config.ProfileEnable,
		aufs:       config.IsAufs,
		fileEvents: make(map[string]*fileMod),
		groups:     make(map[int]*groupInfo),
		sendrpt:    config.SendReport,
		sendRule:   config.SendAccessRule,
		estRuleSrc: config.EstRule,
		walkerTask: config.WalkerTask,
		bNVProtect: config.NVProtect,
	}

	if !fw.bEnable {
		log.Info("File monitor is disabled")
		config.EndChan <- true
		return fw, nil
	}

	n, err := NewFaNotify(config.EndChan, config.PidLookup, fw.SendNVProcessAlert, global.SYS, fw.bNVProtect)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Open fanotify fail")
		return nil, err
	}

	ni, err := NewInotify()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Open inotify fail")
		return nil, err
	}

	go n.MonitorFileEvents()
	go ni.MonitorFileEvents()

	fw.fanotifier = n
	fw.inotifier = ni

	go fw.loop()
	return fw, nil
}

func (w *FileWatch) sendMsg(cid string, path string, event uint32, pInfo []*ProcInfo, mode string) {
	eventMsg, ok := fileEventMsg[event]
	if !ok {
		log.WithFields(log.Fields{"path": path, "event": eventMsg}).Error("FMON: Unkown event")
		return
	}

	log.WithFields(log.Fields{"path": path, "event": eventMsg, "proc": pInfo}).Debug("FMON:")

	if pInfo == nil {
		msg := MonitorMessage{
			ID:      cid,
			Path:    path,
			Group:   w.estRuleSrc(cid, path, event == fileEventDenied),
			Package: osutil.IsPackageLib(path),
			Msg:     eventMsg,
			Action:  share.PolicyActionViolate,
		}

		w.sendrpt(&msg)
		//	log.WithFields(log.Fields{"file": path, "container": cid}).Debug("File modified catched")
		return
	}
	// check whether the file was modified by same process.
	for i, pi := range pInfo {
		if i == 0 || !reflect.DeepEqual(pInfo[i-1], pi) {
			msg := MonitorMessage{
				ID:      cid,
				Path:    path,
				Group:   w.estRuleSrc(cid, path, event == fileEventDenied),
				Package: osutil.IsPackageLib(path),
				Msg:     eventMsg,
				Action:  share.PolicyActionViolate,
			}
			if pi != nil {
				msg.ProcName = pi.Name
				msg.ProcPath = pi.Path
				msg.ProcCmds = pi.Cmds
				msg.ProcPid = pi.Pid
				msg.ProcEUid = pi.EUid
				msg.ProcEUser = pi.EUser
				msg.ProcPPid = pi.PPid
				msg.ProcPName = pi.PName
				msg.ProcPPath = pi.PPath
				if pi.Deny {
					msg.Action = share.PolicyActionDeny
					msg.Msg = fileEventMsg[fileEventDenied]
				}
			}

			w.sendrpt(&msg)
			//	log.WithFields(log.Fields{"file": path, "container": cid}).Debug("File modified catched")
		} else {
			log.WithFields(log.Fields{"file": path, "container": cid, "pInfo": pi}).Debug("duplicate File modified")
		}
	}
}

func (w *FileWatch) loop() {
	msgTicker := time.Tick(time.Second * 4)
	// every 10s send learning rules to controller
	learnTicker := time.Tick(time.Second * 10)

	for {
		select {
		case <-msgTicker:
			w.HandleWatchedFiles()
		case <-learnTicker:
			w.reportLearningRules()
		}
	}
}

func (w *FileWatch) reportLearningRules() {
	learnRules := make([]*share.CLUSFileAccessRuleReq, 0)
	w.mux.Lock()
	for _, grp := range w.groups {
		if len(grp.learnRules) > 0 {
			for flt, rule := range grp.learnRules {
				group := grp.profile.Group
				// It enables to correlate its derived groups, like federal groups
				//for _, fltp := range grp.profile.Filters {
				//	if fltp.CustomerAdd && flt == filterIndexKey(fltp) {
				//		group = fltp.DerivedGroup
				//		mLog.WithFields(log.Fields{"group": group}).Debug("FMON:")
				//		break
				//	}
				//}

				for itr := range rule.Iter() {
					prf := itr.(string)
					rl := &share.CLUSFileAccessRuleReq{
						GroupName: group,
						Filter:    flt,
						Path:      prf,
					}
					learnRules = append(learnRules, rl)
				}
			}
			grp.learnRules = make(map[string]utils.Set) // reset
		}
	}
	w.mux.Unlock()
	if len(learnRules) > 0 {
		w.sendRule(learnRules)
	}
}

func filterIndexKey(filter share.CLUSFileMonitorFilter) string {
	return fmt.Sprintf("%s/%s", filter.Path, filter.Regex)
}

func filterPathMatch(path string, flt share.CLUSFileMonitorFilter) bool {
	if flt.Regex == "" {
		return flt.Path == path
	} else {
		fstr := fmt.Sprintf("%s/%s", filepath.Dir(path), flt.Regex)
		log.WithFields(log.Fields{"fstr": fstr}).Debug("FMON: fstr")
		if regx, err := regexp.Compile(fmt.Sprintf("^%s$", fstr)); err == nil {
			return regx.MatchString(path)
		}
	}
	return false
}

func addLearnedRules(grp *groupInfo, flt share.CLUSFileMonitorFilter, pInfo []*ProcInfo) {
	index := filterIndexKey(flt)
	if applyRules, ok := grp.applyRules[index]; ok {
		learnRules, ok := grp.learnRules[index]
		if !ok {
			learnRules = utils.NewSet()
		}
		for _, pf := range pInfo {
			// only use the process name/path as profile
			if pf != nil && pf.Path != "" {
				if !applyRules.Contains(pf.Path) && !learnRules.Contains(pf.Path) {
					learnRules.Add(pf.Path)
				}
			}
		}

		if learnRules.Cardinality() > 0 {
			grp.learnRules[index] = learnRules // update grp
		}
	} else {
		log.WithFields(log.Fields{"index": index}).Debug("FMON: no access rules")
	}
}

func (w *FileWatch) learnFromEvents(rootPid int, fmod fileMod, path string, event uint32) {
	// mLog.WithFields(log.Fields{"rootpid": rootPid, "path": path, "event": event}).Debug()
	w.mux.Lock()
	grp, ok := w.groups[rootPid]
	if !ok {
		log.WithFields(log.Fields{"rootPid": rootPid}).Debug("FMON: group not found")
		w.mux.Unlock()
		return
	}
	mode := grp.mode
	if mode == share.PolicyModeLearn && len(fmod.pInfo) > 0 { // inotify has no process info
		for _, flt := range grp.profile.Filters {
			if flt.CustomerAdd && filterPathMatch(path, flt) {
				addLearnedRules(grp, flt, fmod.pInfo)
			}
		}

		for _, flt := range grp.profile.FiltersCRD {
			if flt.CustomerAdd && filterPathMatch(path, flt) {
				addLearnedRules(grp, flt, fmod.pInfo)
			}
		}
	}
	w.mux.Unlock()

	// it depends on the init conditions by runtime engine
	if isRunTimeAddedFile(filepath.Join("/root", path)) {
		if event == fileEventAccessed || time.Since(grp.startAt) < time.Duration(time.Second*60) {
			return
		}
	}

	if event != fileEventAccessed ||
		(mode == share.PolicyModeEnforce || mode == share.PolicyModeEvaluate) {
		if fmod.finfo.Link != "" {
			path = fmod.finfo.Link
			if index := strings.Index(path, "/root/"); index > 0 {
				path = path[index+5:]
			}
		}
		w.sendMsg(fmod.finfo.ContainerId, path, event, fmod.pInfo, mode)
	}
}

func (w *FileWatch) UpdateAccessRules(name string, rootPid int, conf *share.CLUSFileAccessRule) {
	if !w.bEnable {
		return
	}

	// log.WithFields(log.Fields{"name": name}).Debug("FMON:")
	w.mux.Lock()

	grp, ok := w.groups[rootPid]
	if !ok {
		log.WithFields(log.Fields{"name": name, "rules": conf}).Debug("FMON: Group not found")
		w.mux.Unlock()
		return
	}
	grp.applyRules = make(map[string]utils.Set)
	for idx, rule := range conf.Filters {
		if rule.CustomerAdd {
			applyRules := utils.NewSet()
			for _, app := range rule.Apps {
				applyRules.Add(app)
			}
			grp.applyRules[idx] = applyRules
		}
	}
	w.mux.Unlock()

	w.fanotifier.UpdateAccessRule(rootPid, conf)
}

func (w *FileWatch) Close() {
	log.Info()
	if !w.bEnable {
		return
	}

	if w.fanotifier != nil {
		w.fanotifier.Close()
	}
	if w.inotifier != nil {
		w.inotifier.Close()
	}
}

func (w *FileWatch) cbNotify(filePath string, mask uint32, params interface{}, pInfo *ProcInfo) {
	//ignore the container remove event. they are too many
	if (mask&syscall.IN_IGNORED) != 0 || (mask&syscall.IN_UNMOUNT) != 0 {
		w.removeFile(filePath)
		return
	}

	w.mux.Lock()
	defer w.mux.Unlock()
	if fm, ok := w.fileEvents[filePath]; ok {
		fm.mask |= mask
		fm.delay = 0
		if pInfo != nil {
			var found bool
			for _, p := range fm.pInfo {
				if p.Pid == pInfo.Pid {
					found = true
					break
				}
			}
			if !found {
				fm.pInfo = append(fm.pInfo, pInfo)
			}
		}
	} else {
		fmod := &fileMod{
			mask:  mask,
			finfo: params.(*osutil.FileInfoExt),
		}
		if pInfo != nil {
			fmod.pInfo = append(fmod.pInfo, pInfo)
		}
		w.fileEvents[filePath] = fmod
	}
}

func (w *FileWatch) addFile(bIncInotify bool, finfo *osutil.FileInfoExt) {
	if !w.bEnable {
		return
	}

	w.fanotifier.AddMonitorFile(finfo.Path, finfo.Filter, finfo.Protect, finfo.UserAdded, w.cbNotify, finfo)
	//if _, path := global.SYS.ParseContainerFilePath(finfo.Path); packageFile.Contains(path) {
	flt := finfo.Filter.(*filterRegex)
	if bIncInotify && !strings.HasSuffix(flt.path, "/.*") { // this wildcard has established its directory for all
		w.inotifier.AddMonitorFile(finfo.Path, w.cbNotify, finfo)
	}
}

func (w *FileWatch) removeFile(fullpath string) {
	w.fanotifier.RemoveMonitorFile(fullpath) // should not
	w.inotifier.RemoveMonitorFile(fullpath)
}

func (w *FileWatch) addDir(bIncInotify bool, finfo *osutil.FileInfoExt, files map[string]*osutil.FileInfoExt) {
	if !w.bEnable {
		return
	}

	ff := make(map[string]interface{})
	for fpath, fi := range files {
		ff[fpath] = fi
	}

	w.fanotifier.AddMonitorDirFile(finfo.Path, finfo.Filter, finfo.Protect, finfo.UserAdded, ff, w.cbNotify, finfo)
	if bIncInotify {
		w.inotifier.AddMonitorDirFile(finfo.Path, nil, w.cbNotify, finfo)
	}
}

func (w *FileWatch) getDirAndFileList(pid int, path, regx, cid string, filter *filterRegex, recur, protect, userAdded bool,
	dirList map[string]*osutil.FileInfoExt) []*osutil.FileInfoExt {
	dirs, singles := w.getDirFileList(pid, path, regx, cid, filter, recur, protect, userAdded)
	for _, di := range dirs {
		if diExist, ok := dirList[di.Path]; ok {
			diExist.Children = append(diExist.Children, di.Children...)
		} else {
			dirList[di.Path] = di
		}
	}
	return singles
}

func (w *FileWatch) getCoreFile(cid string, pid int, profile *share.CLUSFileMonitorProfile) (map[string]*osutil.FileInfoExt, []*osutil.FileInfoExt) {
	dirList := make(map[string]*osutil.FileInfoExt)
	singleFiles := make([]*osutil.FileInfoExt, 0)

	// get files and dirs from all filters
	for _, filter := range profile.Filters {
		flt := &filterRegex{path: filterIndexKey(filter), recursive: filter.Recursive}
		flt.regex, _ = regexp.Compile(fmt.Sprintf("^%s$", flt.path))
		bBlockAccess := filter.Behavior == share.FileAccessBehaviorBlock
		bUserAdded := filter.CustomerAdd
		if strings.Contains(filter.Path, "*") {
			subDirs := w.getSubDirList(pid, filter.Path, cid)
			for _, sub := range subDirs {
				singles := w.getDirAndFileList(pid, sub, filter.Regex, cid, flt, filter.Recursive, bBlockAccess, bUserAdded, dirList)
				singleFiles = append(singleFiles, singles...)
			}
		} else {
			singles := w.getDirAndFileList(pid, filter.Path, filter.Regex, cid, flt, filter.Recursive, bBlockAccess, bUserAdded, dirList)
			singleFiles = append(singleFiles, singles...)
		}
	}

	// get files and dirs from all filters
	for _, filter := range profile.FiltersCRD {
		flt := &filterRegex{path: filterIndexKey(filter), recursive: filter.Recursive}
		flt.regex, _ = regexp.Compile(fmt.Sprintf("^%s$", flt.path))
		bBlockAccess := filter.Behavior == share.FileAccessBehaviorBlock
		bUserAdded := filter.CustomerAdd
		if strings.Contains(filter.Path, "*") {
			subDirs := w.getSubDirList(pid, filter.Path, cid)
			for _, sub := range subDirs {
				singles := w.getDirAndFileList(pid, sub, filter.Regex, cid, flt, filter.Recursive, bBlockAccess, bUserAdded, dirList)
				singleFiles = append(singleFiles, singles...)
			}
		} else {
			singles := w.getDirAndFileList(pid, filter.Path, filter.Regex, cid, flt, filter.Recursive, bBlockAccess, bUserAdded, dirList)
			singleFiles = append(singleFiles, singles...)
		}
	}
	return dirList, singleFiles
}

//
func isRunTimeAddedFile(path string) bool {
	return strings.HasSuffix(path, "/root/etc/hosts") ||
		strings.HasSuffix(path, "/root/etc/hostname") ||
		strings.HasSuffix(path, "/root/etc/resolv.conf")
}

func (w *FileWatch) addCoreFile(bIncINotify bool, cid string, dirList map[string]*osutil.FileInfoExt, singleFiles []*osutil.FileInfoExt) {
	// add files
	for _, finfo := range singleFiles {
		// need to move the cross link files to dirs
		di, ok := dirList[filepath.Dir(finfo.Path)]
		if ok && !isRunTimeAddedFile(finfo.Path) {
			finfo.Filter = di.Filter
			di.Children = append(di.Children, finfo)
		} else {
			finfo.ContainerId = cid
			w.addFile(bIncINotify, finfo)
		}
	}

	// add directories
	for _, dir := range dirList {
		if dir == nil {
			continue
		}
		files := make(map[string]*osutil.FileInfoExt)
		for _, file := range dir.Children {
			if file == nil {
				continue
			}
			file.ContainerId = cid
			files[filepath.Base(file.Path)] = file
		}
		dir.ContainerId = cid
		w.addDir(bIncINotify, dir, files)
	}
}

func (w *FileWatch) StartWatch(id string, rootPid int, conf *FsmonConfig, capBlock, bNeuvectorSvc bool) {
	if !w.bEnable {
		return
	}

	log.WithFields(log.Fields{"id": id, "group": conf.Profile.Group, "Pid": rootPid, "mode": conf.Profile.Mode}).Debug("FMON:")
	// log.WithFields(log.Fields{"File": conf.Profile}).Debug("FMON:")
	// log.WithFields(log.Fields{"Access": conf.Rule}).Debug("FMON:")
	//// no access rules for neuvector and host
	if !osutil.IsPidValid(rootPid) {
		log.WithFields(log.Fields{"id": id, "Pid": rootPid}).Debug("FMON: invalid Pid")
		return
	}

	if conf.Profile.Mode == "" {
		conf.Profile.Mode = share.PolicyModeLearn
	}
	var access, perm bool
	if conf.Profile.Mode == share.PolicyModeEnforce && !w.aufs && capBlock { // system containers will be limited at monitor mode
		perm = true
	} else {
		if rootPid == 1 || bNeuvectorSvc {
			// skip learn host and our container. only notify on modified
			access = false
		} else {
			if conf.Profile.Mode == share.PolicyModeLearn { // only for discover mode
				access = true
			}
		}
	}
	dirs, files := w.getCoreFile(id, rootPid, conf.Profile)

	w.fanotifier.SetMode(rootPid, access, perm, capBlock, bNeuvectorSvc)

	w.addCoreFile(!bNeuvectorSvc, id, dirs, files)

	w.fanotifier.StartMonitor(rootPid)

	w.mux.Lock()
	grp, ok := w.groups[rootPid]
	if !ok {
		grp = &groupInfo{
			bNeuvector: bNeuvectorSvc,
			learnRules: make(map[string]utils.Set),
			applyRules: make(map[string]utils.Set),
			startAt:    time.Now(),
		}
		w.groups[rootPid] = grp
	}
	grp.profile = conf.Profile
	grp.mode = conf.Profile.Mode
	w.mux.Unlock()

	//// no access rules for neuvector and host
	if bNeuvectorSvc || rootPid == 1 {
		return
	}

	if conf.Rule != nil {
		w.UpdateAccessRules(conf.Profile.Group, rootPid, conf.Rule)
	}
}

func (w *FileWatch) HandleWatchedFiles() {
	events := make(map[string]fileMod)

	// clone events
	w.mux.Lock()
	for filePath, fmod := range w.fileEvents {
		events[filePath] = *fmod
	}
	w.fileEvents = make(map[string]*fileMod) // reset
	w.mux.Unlock()

	for fullPath, fmod := range events {
		pid, path := global.SYS.ParseContainerFilePath(fullPath)
		// mLog.WithFields(log.Fields{"pid": pid, "path": path}).Debug()
		//to avoid false alarm of /etc/hosts and /etc/resolv.conf, check whether the container is still exist
		//these two files has attribute changed when the container leave
		//this maybe miss some events file changed right before container leave. But for these kind of event,
		//it is not useful if the container already leave
		if osutil.IsPidValid(pid) { // for alive process
			var event uint32
			info, _ := os.Lstat(fullPath)
			if fmod.finfo.FileMode.IsDir() || (info != nil && info.IsDir()) {
				event = w.handleDirEvents(fmod, info, fullPath, path, pid)
			} else {
				event = w.handleFileEvents(fmod, info, fullPath, pid)
			}

			if event != 0 {
				w.learnFromEvents(pid, fmod, path, event)
			}
		}
	}
}

// Decide the directory event priority here
func (w *FileWatch) handleDirEvents(fmod fileMod, info os.FileInfo, fullPath, path string, pid int) uint32 {
	var event uint32
	// handle files inside directory
	// log.WithFields(log.Fields{"info": info, "fullPath": fullPath, "path": path, "fmod": fmod}).Debug()
	if info != nil {
		bIsDir := info.IsDir()
		if (fmod.mask & (syscall.IN_MOVED_TO | syscall.IN_CREATE)) > 0 {
			if (fmod.mask & syscall.IN_MOVED_TO) > 0 {
				if bIsDir {
					event = fileEventDirMovedTo
				} else {
					event = fileEventMovedTo
				}
			} else {
				if bIsDir {
					event = fileEventDirCreate
					fmod.finfo.Path = fullPath // new subdir
					fmod.finfo.FileMode = info.Mode()
					flt := fmod.finfo.Filter.(*filterRegex)
					if !flt.recursive {
						log.WithFields(log.Fields{"id": fmod.finfo.ContainerId, "path": path}).Info("not recursive monitoring")
						return event
					}
				} else {
					if info.Mode()&os.ModeSymlink != 0 {
						// a new symbolic link
						event = fileEventSymCreate
						if link_to, err := os.Readlink(fullPath); err == nil {
							if filepath.IsAbs(link_to) {
								link_to = filepath.Join(fmt.Sprintf("/proc/%d/root", pid), link_to)
							} else {
								link_to = filepath.Join(filepath.Dir(fullPath), link_to)
							}
							mLog.WithFields(log.Fields{"link_to": link_to, "file": path}).Debug()
							if finfo, err := os.Stat(link_to); err == nil {
								mLog.WithFields(log.Fields{"finfo": finfo}).Debug()
								if finfo.IsDir() {
									event = fileEventDirSymCreate
								}
							}
						}
					} else {
						w.addFile(false, fmod.finfo)
						return fileEventCreate
					}
				}
			}

			// add the new file to monitor
			dirFiles := make(map[string]*osutil.FileInfoExt)
			if files := osutil.GetFileInfoExtFromPath(pid, fullPath, fmod.finfo.Filter, fmod.finfo.Protect, fmod.finfo.UserAdded); files != nil {
				for _, file := range files {
					file.ContainerId = fmod.finfo.ContainerId
					dirFiles[filepath.Base(path)] = file
				}
			}
			w.addDir(true, fmod.finfo, dirFiles)
		} else if (fmod.mask & syscall.IN_ATTRIB) > 0 {
			if bIsDir {
				event = fileEventDirAttr
			} else {
				event = fileEventAttr
			}
			// fmod.finfo.FileMode: keep its original flag
			return event
		} else if (fmod.mask & (syscall.IN_ACCESS | syscall.IN_CLOSE_WRITE | syscall.IN_MODIFY)) > 0 {
			event = fileEventAccessed
			if !bIsDir {
				if hash, err := osutil.GetFileHash(fullPath); err == nil {
					if hash != fmod.finfo.Hash {
						event = fileEventModified
						fmod.finfo.Hash = hash
					}
				} else if (fmod.mask & syscall.IN_MODIFY) > 0 {
					event = fileEventModified
				}
			}
		} else {
			log.WithFields(log.Fields{"fullPath": fullPath, "mask": fmod.mask}).Debug("directory event not found")
		}
	} else {
		// the path is itself means the directory was removed
		if fullPath == fmod.finfo.Path {
			event = fileEventDirRemoved
		} else {
			if (fmod.mask & inodeMovedMask) > 0 {
				if (fmod.mask & syscall.IN_ISDIR) > 0 {
					event = fileEventDirMovedFrom
				} else {
					event = fileEventMovedFrom
				}
			} else {
				event = fileEventRemoved
			}
			w.removeFile(fullPath)
		}
	}
	return event
}

// Decide the file event priority here
func (w *FileWatch) handleFileEvents(fmod fileMod, info os.FileInfo, fullPath string, pid int) uint32 {
	var event uint32
	if info != nil {
		log.WithFields(log.Fields{"fullPath": fullPath, "fmod": fmod, "finfo": fmod.finfo}).Debug()
		if (fmod.mask & inodeMovedMask) > 0 {
			log.WithFields(log.Fields{"fullPath": fullPath, "finfo": fmod.finfo}).Debug()
			event = fileEventMovedTo
			w.addFile(true, fmod.finfo) // follow up ?
		} else if (fmod.mask & syscall.IN_ATTRIB) > 0 {
			//attribute is changed
			event = fileEventAttr
			fmod.finfo.FileMode = info.Mode()
		} else if (fmod.mask & (syscall.IN_ACCESS | syscall.IN_CLOSE_WRITE | syscall.IN_MODIFY)) > 0 {
			// check the hash existing and match
			event = fileEventAccessed
			if hash, err := osutil.GetFileHash(fullPath); err == nil {
				if hash != fmod.finfo.Hash {
					event = fileEventModified
					fmod.finfo.Hash = hash
				}
			} else if (fmod.mask & syscall.IN_MODIFY) > 0 {
				event = fileEventModified
			}
		} else {
			log.WithFields(log.Fields{"fullPath": fullPath, "mask": fmod.mask}).Debug("file event not found")
		}
	} else {
		//file is removed
		if (fmod.mask & inodeMovedMask) > 0 {
			log.WithFields(log.Fields{"fullPath": fullPath, "finfo": fmod.finfo}).Debug()
			event = fileEventMovedFrom
		} else {
			event = fileEventRemoved
			w.removeFile(fullPath)
		}
	}
	return event
}

func (w *FileWatch) ContainerCleanup(rootPid int, bLeave bool) {
	if !w.bEnable {
		return
	}
	w.fanotifier.ContainerCleanup(rootPid)
	w.inotifier.ContainerCleanup(rootPid)

	w.mux.Lock()
	defer w.mux.Unlock()
	for path, _ := range w.fileEvents {
		if pid, _ := global.SYS.ParseContainerFilePath(path); pid == rootPid {
			delete(w.fileEvents, path)
		}
	}

	if grp, ok := w.groups[rootPid]; ok {
		if bLeave {
			delete(w.groups, rootPid)
		} else {
			// reset lists
			grp.learnRules = make(map[string]utils.Set)
			grp.applyRules = make(map[string]utils.Set)
		}
	}
}

func (w *FileWatch) GetWatchFileList(rootPid int) []*share.CLUSFileMonitorFile {
	if !w.bEnable {
		return nil
	}
	return w.fanotifier.GetWatchFileList(rootPid)
}

func (w *FileWatch) GetAllFileMonitorFile() []*share.CLUSFileMonitorFile {
	if !w.bEnable {
		return nil
	}
	return w.fanotifier.GetWatches()
}

////////
func (w *FileWatch) GetProbeData() *FmonProbeData {
	var probeData FmonProbeData
	if !w.bEnable {
		return nil
	}

	w.mux.Lock()
	probeData.NFileEvents = len(w.fileEvents)
	probeData.NGroups = len(w.groups)
	w.mux.Unlock()

	if w.fanotifier != nil {
		w.fanotifier.GetProbeData(&probeData.Fan)
	}

	if w.inotifier != nil {
		w.inotifier.GetProbeData(&probeData.Ino)
	}

	return &probeData
}

func (w *FileWatch) SetMonitorTrace(bEnable bool, logLevel string) {
	if bEnable {
		mLog.Level = log.DebugLevel
	} else {
		mLog.Level = share.CLUSGetLogLevel(logLevel)
	}
}

//////////////////////
const (
	dirIterTimeout  = time.Second * 8
	rootIterTimeout = time.Second * 16
)

// generic get a directory file list
func (w *FileWatch) getDirFileList(pid int, base, regexStr, cid string, flt interface{}, recur, protect, userAdded bool) (map[string]*osutil.FileInfoExt, []*osutil.FileInfoExt) {
	if !w.bEnable {
		return nil, nil
	}

	dirList := make(map[string]*osutil.FileInfoExt)
	singleFiles := make([]*osutil.FileInfoExt, 0)

	tmOut := dirIterTimeout
	if base == "" {
		base += "/"
		tmOut = rootIterTimeout
	}
	base = strings.Replace(base, "\\.", ".", -1)
	dirs := utils.NewSet(base)

	// for recursive directory
	for dirs.Cardinality() > 0 {
		any := dirs.Any()
		absPath := any.(string)
		realPath := global.SYS.ContainerFilePath(pid, absPath)
		finfo, err := os.Stat(realPath)
		if err != nil {
			dirs.Remove(any)
			continue
		}

		// the path in the filter is single file
		if !finfo.IsDir() {
			if files := osutil.GetFileInfoExtFromPath(pid, realPath, flt, protect, userAdded); files != nil {
				// file and it's possible link
				singleFiles = append(singleFiles, files...)
			}
			dirs.Remove(any)
			continue
		}

		// directory and its files
		dirInfo := &osutil.FileInfoExt{
			FileMode:  finfo.Mode(),
			Path:      realPath,
			Filter:    flt,
			Protect:   protect,
			UserAdded: userAdded,
		}
		dirList[realPath] = dirInfo

		// log.WithFields(log.Fields{"realPath": realPath, "absPath": absPath}).Debug()
		res := workerlet.WalkPathResult{
			Dirs:  make([]*workerlet.DirData, 0),
			Files: make([]*workerlet.FileData, 0),
		}

		req := workerlet.WalkPathRequest{
			Pid:     pid,
			Path:    absPath,
			Timeout: tmOut,
		}

		bytesValue, _, err := w.walkerTask.RunWithTimeout(req, cid, req.Timeout)
		if err == nil {
			err = json.Unmarshal(bytesValue, &res)
		}

		if err != nil {
			log.WithFields(log.Fields{"req": req, "error": err, "regexStr": regexStr, "any": any}).Error()
			dirs.Remove(any)
			continue
		}

		for _, d := range res.Dirs {
			path := filepath.Join(realPath, d.Dir)
			if realPath != path && regexStr == ".*" {
				// log.WithFields(log.Fields{"dir": path}).Debug()
				dinfo := &osutil.FileInfoExt{
					FileMode:  finfo.Mode(), // ??
					Path:      path,
					Filter:    flt,
					Protect:   protect,
					UserAdded: userAdded,
				}
				dirList[path] = dinfo
			}
		}

		for _, f := range res.Files {
			path := filepath.Join(realPath, f.File)
			if !recur && realPath != filepath.Dir(path) {
				continue
			}

			fstr := fmt.Sprintf("%s/%s", filepath.Dir(path), regexStr)
			regx, err := regexp.Compile(fmt.Sprintf("^%s$", fstr))
			if err != nil {
				log.WithFields(log.Fields{"error": err, "str": fstr}).Debug("regexp parse fail")
				continue
			}

			if regx.MatchString(path) {
				// log.WithFields(log.Fields{"path": path, "fstr": fstr}).Debug()
				if files := osutil.GetFileInfoExtFromPath(pid, path, flt, protect, userAdded); files != nil {
					// check whether the files are in the directory, some file link to other position
					for _, file := range files {
						singleFiles = append(singleFiles, file)
						dirPath := filepath.Dir(file.Path)
						if di, ok := dirList[dirPath]; ok {
							di.Children = append(di.Children, file)
						} else {
							singleFiles = append(singleFiles, file)
						}
					}
				}
			}
		}
		dirs.Remove(any)

		if !recur { // only 1st layer of directory
			break
		}
	}
	return dirList, singleFiles
}

func (w *FileWatch) getSubDirList(pid int, base, cid string) []string {
	dirList := make([]string, 0)
	fstr := global.SYS.ContainerFilePath(pid, base)
	regxDir, err := regexp.Compile(fstr)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "str": fstr}).Debug("directory regexp parse fail")
		return dirList
	}
	baseStr := strings.Split(base, "/")
	var startDir string
	for i, dd := range baseStr {
		if strings.Contains(dd, "*") {
			break
		}
		if i > 0 {
			startDir += "/" + dd
		}
	}
	basePath := global.SYS.ContainerFilePath(pid, "")
	realPath := global.SYS.ContainerFilePath(pid, startDir)

	// log.WithFields(log.Fields{"startDir": startDir, "realPath": realPath, "basePath": basePath}).Debug()
	res := workerlet.WalkPathResult{
		Dirs:  make([]*workerlet.DirData, 0),
		Files: make([]*workerlet.FileData, 0),
	}

	req := workerlet.WalkPathRequest{
		Pid:     pid,
		Path:    startDir,
		Timeout: dirIterTimeout,
	}

	bytesValue, _, err := w.walkerTask.RunWithTimeout(req, cid, req.Timeout)
	if err == nil {
		err = json.Unmarshal(bytesValue, &res)
	}

	if err != nil {
		log.WithFields(log.Fields{"path": startDir, "error": err}).Error()
	}

	for _, d := range res.Dirs {
		path := filepath.Join(realPath, d.Dir)
		if regxDir.MatchString(path) {
			absPath := path[len(basePath):]
			// log.WithFields(log.Fields{"absPath": absPath, "path": path}).Debug()
			dirList = append(dirList, absPath)
		}
	}
	return dirList
}

////////////
const (
	fsNvProtectProcAlert = "NV.Protect: Process alert"
)

func (w *FileWatch) SendNVProcessAlert(rootPid, ppid int, cid, path, ppath string) {
	w.mux.Lock()
	grp, ok := w.groups[rootPid]
	w.mux.Unlock()
	if !ok {
		log.WithFields(log.Fields{"rootPid": rootPid, "path": path}).Error()
		return
	}
	var groupName string
	if grp.profile != nil {
		groupName = grp.profile.Group
	}

	rpt := &MonitorMessage{
		ID:        cid,
		Path:      path,
		ProcPid:   ppid, // assuming
		ProcPath:  path,
		ProcPPid:  ppid,
		ProcPPath: ppath,
		Group:     groupName,
		Msg:       fsNvProtectProcAlert,
		Action:    share.PolicyActionDeny,
	}
	w.sendrpt(rpt)
	log.WithFields(log.Fields{"rpt": rpt}).Debug("FMON:")
}

func (w *FileWatch) SetNVProtectFlag(bEnabled bool) {
	log.WithFields(log.Fields{"bEnabled": bEnabled}).Info()
	w.bNVProtect = bEnabled
	w.fanotifier.bNVProtect = bEnabled
}

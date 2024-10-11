package probe

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/agent/workerlet"
	"github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
)

const hostRootMountPoint = "/proc/1/root"
const waitFileActionCompleteSteps int = 16

const (
	drv_overlayfs = iota
	drv_aufs
	drv_btrfs
)

// used by the snapshot to distinguish it from the current file
const (
	file_image = iota
	file_added
	file_deleted
	file_changed
	file_not_exist // exclude deleted case
)

// reference list
type fileInfo struct {
	fileType  uint32 // referred by snapshots only
	bExec     bool
	bJavaPkg  bool
	hashValue uint32
	length    int64
}

type fsnRootFd struct {
	id        string
	role      string
	cLayer    string // on the local node's path
	cLayerLen int
	imgLayer  string // btrfs: image folder
	pid       int
	dirs      utils.Set            // keep a record of marked directories
	files     map[string]*fileInfo // new files: [path]= bExec, hashValue
}

// global control data
type FileNotificationCtr struct {
	bEnabled   bool
	storageDrv int
	prober     *Probe
	ctrlMux    sync.Mutex
	watcher    *fsnotify.Watcher
	compLength int
	roots      map[string]*fsnRootFd // index: rootPath by compLength
	rootsByID  map[string]*fsnRootFd // index: container id (ref by probe)
}

// ///
func calculateFileInfo(fi os.FileInfo, path string) (bool, bool, int64, uint32) {
	var hash uint32

	bExec := utils.IsExecutable(fi, path)
	bJavaPkg := scan.IsJava(path)
	length := fi.Size()
	if bExec && length > 0 { // focus on executables now
		hash = utils.FileHashCrc32(path, length)
	}
	return bExec, bJavaPkg, length, hash
}

// //////////
func NewFsnCenter(p *Probe, rtStorageDriver string) (*FileNotificationCtr, bool) {
	log.WithFields(log.Fields{"driver": rtStorageDriver}).Debug("FSN:")
	fsn := &FileNotificationCtr{
		bEnabled:  false,
		roots:     make(map[string]*fsnRootFd),
		rootsByID: make(map[string]*fsnRootFd),
		prober:    p,
	}

	switch strings.ToLower(rtStorageDriver) {
	case "overlay", "overlay2", "overlayfs":
		fsn.storageDrv = drv_overlayfs
	case "aufs":
		fsn.storageDrv = drv_aufs
	case "btrfs":
		fsn.storageDrv = drv_btrfs
	default:
		log.WithFields(log.Fields{"driver": rtStorageDriver}).Error("FSN: not support")
		fsn.storageDrv = drv_overlayfs // assume
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("FSN: Initialize")
		return fsn, false
	}

	// fill in
	fsn.bEnabled = true
	fsn.watcher = watcher
	go fsn.monitorEvents()
	return fsn, true
}

// // No recursive dir mark is for inotify
// // Add all sub-directories from the top layers
func (fsn *FileNotificationCtr) enumFiles(rootPath, id string, bInit bool) (utils.Set, map[string]*fileInfo) {
	dirs := utils.NewSet()
	files := make(map[string]*fileInfo)
	dirs.Add(rootPath)

	///
	res := workerlet.WalkPathResult{
		Dirs:  make([]*workerlet.DirData, 0),
		Files: make([]*workerlet.FileData, 0),
	}

	req := workerlet.WalkPathRequest{
		Pid:  1,
		Path: strings.TrimPrefix(rootPath, hostRootMountPoint),
	}

	bytesValue, _, err := fsn.prober.walkerTask.Run(req, id)
	if err == nil {
		err = json.Unmarshal(bytesValue, &res)
	}

	if err != nil {
		log.WithFields(log.Fields{"path": rootPath, "error": err}).Error("FSN: ")
	}

	for _, d := range res.Dirs {
		path := filepath.Join(rootPath, d.Dir)
		if fsn.storageDrv == drv_aufs && strings.HasPrefix(filepath.Base(path), ".wh..wh.") {
			log.WithFields(log.Fields{"path": path[len(rootPath):]}).Debug("FSN: skip AUFS folder")
		} else {
			dirs.Add(path)
		}
	}

	if bInit {
		for _, f := range res.Files {
			file := f.File
			name := filepath.Base(file)
			switch {
			case f.Info.Mode.IsRegular():
				if fsn.storageDrv == drv_aufs && name != ".wh..wh.aufs" && strings.HasPrefix(name, ".wh.") && f.Info.Mode.Perm() == 0444 { // read-only
					name = name[len(".wh."):]
					file = filepath.Join(filepath.Dir(file), name)
					log.WithFields(log.Fields{"file": file}).Debug("FSN: deleted file")
					files[file] = &fileInfo{
						fileType: file_deleted, // aufs: deleted image file
						bExec:    true,         // unknown
					}
				} else {
					// any file in the uppder directory
					files[file] = &fileInfo{
						fileType:  file_added,
						bExec:     f.IsExec,
						hashValue: f.Hash,
						length:    f.Info.Size}
				}
			case f.Info.Mode == (os.ModeDevice | os.ModeCharDevice):
				log.WithFields(log.Fields{"file": file}).Debug("FSN: deleted file")
				files[file] = &fileInfo{
					fileType: file_deleted, // overlay: deleted image file
					bExec:    true,         // unknown
				}
			}
		}
	}

	log.WithFields(log.Fields{"path": rootPath, "fCount": len(files), "dCount": dirs.Cardinality(), "error": err}).Debug("FSN: ")
	return dirs, files
}

func (fsn *FileNotificationCtr) lockMux() {
	// log.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("FSN: ")
	fsn.ctrlMux.Lock()
}

func (fsn *FileNotificationCtr) unlockMux() {
	fsn.ctrlMux.Unlock()
	// log.WithFields(log.Fields{"goroutine": utils.GetGID()}).Debug("FSN: ")
}

/* removed by golint
func (fsn *FileNotificationCtr) dumpDebugData(r *fsnRootFd) {
	log.WithFields(log.Fields{"id": r.id, "cLayer": r.cLayer, "cLayerLen": r.cLayerLen}).Debug("FSN:")
	for dir := range r.dirs.Iter() {
		log.WithFields(log.Fields{"dir": dir.(string)}).Debug("FSN: \t")
	}

	for file, finfo := range r.files {
		log.WithFields(log.Fields{"file": file, "finfo": finfo}).Debug("FSN: \t")
	}
}
*/

func (fsn *FileNotificationCtr) addDir(dir string) error {
	// log.WithFields(log.Fields{"dir": dir}).Debug("FSN:")
	if fsn.bEnabled {
		return fsn.watcher.Add(dir)
	}
	return nil
}

func (fsn *FileNotificationCtr) removeDir(dir string) error {
	// log.WithFields(log.Fields{"dir": dir}).Debug("FSN:")
	if fsn.bEnabled {
		return fsn.watcher.Remove(dir)
	}
	return nil
}

func (fsn *FileNotificationCtr) rootIndex(path string) string {
	if len(path) < fsn.compLength {
		return path
	}
	return path[:fsn.compLength]
}

func (fsn *FileNotificationCtr) updateFileInfo(index string, file, path string) {
	var err error
	var fi os.FileInfo

	fsn.lockMux()
	defer fsn.unlockMux()

	root, ok := fsn.roots[index]
	if !ok {
		// the container might be removed
		// log.WithFields(log.Fields{"index": index}).Debug("FSN: no root")
		return
	}

	if fi, err = os.Stat(path); err != nil {
		// log.WithFields(log.Fields{"file": file, "id": root.id, "error": err}).Error("FSN:")
		return
	}

	// Wait for the completion of the "copy" operation.
	size := fi.Size()
	for i := 0; i < waitFileActionCompleteSteps; i++ { // TODO: is it enough?
		time.Sleep(time.Millisecond * time.Duration(2*(i+1)))
		if fi, err = os.Stat(path); err != nil {
			// log.WithFields(log.Fields{"file": file, "id": root.id, "error": err, "i": i}).Error("FSN:")
			return
		}

		if fi.Size() == size { // assuming it is stable
			break
		}
		size = fi.Size()                            // wait for the next run
		if i == (waitFileActionCompleteSteps - 1) { // still ongoing, give up, it reports anyway.
			log.WithFields(log.Fields{"file": file, "id": root.id, "error": err, "size": size}).Debug("FSN: incomplete file")
		}
	}

	// calculations
	bExec, bJavaPkg, length, hash := calculateFileInfo(fi, path)

	// updating record
	var bUpdated, bNewFile bool
	finfo, ok := root.files[file]
	if ok {
		bUpdated = (length != finfo.length) || (hash != finfo.hashValue) || (bExec != finfo.bExec) || (finfo.bJavaPkg != bJavaPkg)
	} else {
		bUpdated = true
		bNewFile = true
	}

	if !bUpdated {
		return
	}

	finfo = &fileInfo{bExec: bExec, bJavaPkg: bJavaPkg, hashValue: hash, length: length, fileType: file_changed}
	if bNewFile {
		finfo.fileType = file_added
	}
	root.files[file] = finfo

	// reporting events
	// log.WithFields(log.Fields{"id": root.id, "file": file, "finfo": finfo}).Debug("FSN:")
	go fsn.prober.ProcessFsnEvent(root.id, []string{file}, *finfo)
}

// already locked
func (fsn *FileNotificationCtr) handleRemoveEvent(op string, root *fsnRootFd, path, file string) {
	// mLog.WithFields(log.Fields{"op": op, "path": path}).Debug("FSN:")
	if root.dirs.Contains(path) {
		if dbgError := fsn.removeDir(path); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
		var execs, jars []string
		for p, fi := range root.files {
			if fi.bExec {
				execs = append(execs, p)
			}
			if fi.bJavaPkg {
				jars = append(jars, p)
			}
			delete(root.files, p)
		}
		mLog.WithFields(log.Fields{"dir": file, "execs": execs, "jars": jars}).Debug("FSN: remove dir")
		if len(execs) > 0 {
			go fsn.prober.ProcessFsnEvent(root.id, execs, fileInfo{bExec: true, fileType: file_deleted})
		}
		if len(jars) > 0 {
			go fsn.prober.ProcessFsnEvent(root.id, jars, fileInfo{bJavaPkg: true, fileType: file_deleted})
		}
		root.dirs.Remove(path)
	} else {
		// mLog.WithFields(log.Fields{"file": file}).Debug("FSN: remove file")
		if fi, ok := root.files[file]; ok && fi.bJavaPkg {
			go fsn.prober.ProcessFsnEvent(root.id, []string{file}, fileInfo{bJavaPkg: true, fileType: file_deleted})
		}
		delete(root.files, file)
	}
}

func (fsn *FileNotificationCtr) handleEvent(event fsnotify.Event) {
	// mLog.WithFields(log.Fields{"event": event}).Debug("FSN:")
	index := fsn.rootIndex(event.Name)

	fsn.lockMux()
	defer fsn.unlockMux()

	root, ok := fsn.roots[index]
	if !ok {
		// the container might be removed
		// mLog.WithFields(log.Fields{"index": index, "event": event}).Debug("FSN: no root")
		return
	}

	path := event.Name
	if len(path) <= root.cLayerLen {
		// mLog.WithFields(log.Fields{"path": path, "len": len(path), "headerLength": root.cLayerLen}).Debug()
		return
	}

	file := event.Name[root.cLayerLen:]
	// Op: fsnotify.[Create, Write, Remove, Rename, Chmod]
	// mLog.WithFields(log.Fields{"file": file, "op": event.Op}).Debug("FSN:")
	if (event.Op & (fsnotify.Remove | fsnotify.Rename)) != 0 {
		fsn.handleRemoveEvent(event.Op.String(), root, path, file)
		return
	}

	if path == "" || fsn.skipPathByRole(root.role, file) { // ignore root's operation
		return
	}

	time.Sleep(time.Millisecond * 2) // avoid reading an incomplete change
	fi, err := os.Stat(path)
	if err != nil {
		// mLog.WithFields(log.Fields{"file": file}).Error("FSN: stat")
		return
	}

	if (event.Op & fsnotify.Create) != 0 {
		switch {
		case fi.IsDir():
			dirs, _ := fsn.enumFiles(path, root.id, false)
			// sample: mkdir -p /tmp/test/bin, only "/tmp" was reported.
			for d := range dirs.Iter() {
				dir := d.(string)
				if fsn.skipPathByRole(root.role, dir[root.cLayerLen:]) {
					continue
				}
				// mLog.WithFields(log.Fields{"rdir": dir[root.cLayerLen:]}).Debug("FSN: new dir")
				if dbgError := fsn.addDir(dir); dbgError != nil {
					log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
				}
				root.dirs.Add(dir)
			}
		case fi.Mode().IsRegular():
			// mLog.WithFields(log.Fields{"file": file, "path": path}).Debug("FSN: new file")
			name := filepath.Base(file)
			if fsn.storageDrv == drv_aufs && name != ".wh..wh.aufs" && strings.HasPrefix(name, ".wh.") && fi.Mode().Perm() == 0444 { // read-only
				name = name[len(".wh."):]
				file = filepath.Join(filepath.Dir(file), name)
				// mLog.WithFields(log.Fields{"file": file}).Debug("FSN: deleted file")
				if scan.IsJava(path) {
					go fsn.prober.ProcessFsnEvent(root.id, []string{file}, fileInfo{bJavaPkg: true, fileType: file_deleted})
				}
			} else {
				go fsn.updateFileInfo(index, file, path)
			}
		case fi.Mode() == (os.ModeDevice | os.ModeCharDevice):
			// mLog.WithFields(log.Fields{"file": file}).Debug("FSN: deleted file")
			if scan.IsJava(path) {
				go fsn.prober.ProcessFsnEvent(root.id, []string{file}, fileInfo{bJavaPkg: true, fileType: file_deleted})
			}
		}
	} else if (event.Op & (fsnotify.Chmod | fsnotify.Write)) != 0 {
		if fi.Mode().IsRegular() {
			// mLog.WithFields(log.Fields{"file": file, "op": event.Op}).Debug("FSN: file modfied")
			go fsn.updateFileInfo(index, file, path)
		}
	}
}

// main worker: goroutine
func (fsn *FileNotificationCtr) monitorEvents() {
	defer fsn.Close()
	defer log.Info("FSN: exit")
	for {
		if !fsn.bEnabled {
			break
		}

		select {
		case event, ok := <-fsn.watcher.Events:
			if !ok {
				return
			}
			fsn.handleEvent(event)
		case err, ok := <-fsn.watcher.Errors:
			if !ok && err == nil {
				// exited
				return
			}
			log.WithFields(log.Fields{"error": err, "ok": ok}).Error("FSN: ")
		}
	}
}

func (fsn *FileNotificationCtr) Close() {
	if !fsn.bEnabled {
		return
	}

	log.Debug("FSN:")
	fsn.lockMux()
	defer fsn.unlockMux()

	fsn.bEnabled = false
	if fsn.watcher != nil {
		fsn.watcher.Close()
	}
}

func (fsn *FileNotificationCtr) skipPathByRole(role, path string) bool {
	switch role {
	case "controller+enforcer+manager":
		if strings.HasPrefix(path, "/supervisord.log") {
			return true
		}
		fallthrough
	case "enforcer", "scanner":
		if strings.HasPrefix(path+"/", "/tmp/") {
			return true
		}
	}
	return false
}

func (fsn *FileNotificationCtr) AddContainer(id, cPath, role string, pid int) (bool, map[string]*fileInfo) {
	if !fsn.bEnabled {
		return false, nil
	}

	path := filepath.Join(hostRootMountPoint, cPath)
	if path == hostRootMountPoint {
		log.WithFields(log.Fields{"id": id, "cPath": cPath}).Error("FSN: invaild cPath")
		return false, nil
	}

	fsn.lockMux()
	defer fsn.unlockMux()

	// update the compared length if it is not set
	if fsn.compLength == 0 {
		fsn.compLength = len(path)
		//	log.WithFields(log.Fields{"compLength": fsn.compLength}).Debug("FSN: set")
	}

	index := fsn.rootIndex(path)
	// log.WithFields(log.Fields{"id": id, "index": index}).Debug("FSN:")

	//// existing entry, remove its marks at first
	if r, ok := fsn.roots[index]; ok {
		for dir := range r.dirs.Iter() {
			if dbgError := fsn.removeDir(dir.(string)); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
		}
		r.files = nil
		r.dirs.Clear()
		delete(fsn.roots, index)
		delete(fsn.rootsByID, id)
	}

	//// create root records
	root := &fsnRootFd{
		id:        id,
		role:      role,
		cLayer:    path,
		cLayerLen: len(path),
		pid:       pid,
		dirs:      utils.NewSet(),             // temporary
		files:     make(map[string]*fileInfo), // temporary
	}

	// construct the initial file map
	if fsn.storageDrv == drv_btrfs {
		// It is composed of the image files and the new created files
		// differentiate the "..._init" folder to filter out the image files
		root.dirs, root.files, root.imgLayer = fsn.enumBtrfsInitFiles(path, id)
	} else {
		root.dirs, root.files = fsn.enumFiles(path, id, true)
	}

	for d := range root.dirs.Iter() {
		dir := d.(string)
		// log.WithFields(log.Fields{"dir": dir}).Debug("FSN: ")
		if fsn.skipPathByRole(role, dir[root.cLayerLen:]) {
			continue
		}

		if err := fsn.addDir(dir); err != nil {
			log.WithFields(log.Fields{"dir": dir, "id": id, "error": err}).Debug("FSN: failed")
		}
	}

	// put the reference entries
	fsn.roots[index] = root
	fsn.rootsByID[id] = root
	//log.WithFields(log.Fields{"cLayer": root.cLayer, "id": id, "index": index}).Debug("FSN:")
	files := make(map[string]*fileInfo) // a storage kept in the prober
	for path, pInfo := range root.files {
		files[path] = &fileInfo{
			fileType:  pInfo.fileType,
			bExec:     pInfo.bExec,
			hashValue: pInfo.hashValue,
			length:    pInfo.length,
		}
	}
	return true, files
}

func (fsn *FileNotificationCtr) RemoveContainer(id, cPath string) bool {
	if !fsn.bEnabled {
		return false
	}

	index := fsn.rootIndex(filepath.Join(hostRootMountPoint, cPath))
	// log.WithFields(log.Fields{"cPath": cPath, "id": id, "index": index}).Debug("FSN:")

	fsn.lockMux()
	defer fsn.unlockMux()
	root, ok := fsn.roots[index]
	if !ok {
		log.WithFields(log.Fields{"cPath": cPath}).Debug("FSN: no exist")
		return false
	}

	for dir := range root.dirs.Iter() {
		if dbgError := fsn.removeDir(dir.(string)); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
	}

	root.dirs.Clear()
	root.files = nil
	delete(fsn.roots, index)
	delete(fsn.rootsByID, id)
	return true
}

// must be valid as a new file
func (fsn *FileNotificationCtr) GetUpperFileInfo(id, file string) (*fileInfo, bool) {
	finfo := &fileInfo{}
	if fsn.bEnabled {
		// mLog.WithFields(log.Fields{"id": id, "file": file}).Debug("FSN:")
		fsn.lockMux()
		defer fsn.unlockMux()
		if root, ok := fsn.rootsByID[id]; ok {
			// fsn.dumpDebugData(root)
			if finfo, ok := root.files[file]; ok {
				return finfo, true
			}

			procPath := fmt.Sprintf("/proc/%d/root", root.pid)
			// a mounted path?
			if utils.IsMountPoint(filepath.Join(procPath, filepath.Dir(file))) {
				// mLog.WithFields(log.Fields{"id": id, "file": file}).Debug("FSN: mounted")
				finfo.bExec = true // assume that it was an exec and will rejected at its caller
				return finfo, true
			}

			fpath := filepath.Join(root.cLayer, file)
			if fi, err := os.Stat(fpath); err == nil {
				finfo.bExec, finfo.bJavaPkg, finfo.length, finfo.hashValue = calculateFileInfo(fi, fpath)
				if fsn.storageDrv == drv_btrfs {
					ipath := filepath.Join(root.imgLayer, file)
					if ifi, err := os.Stat(ipath); err == nil {
						bExec, bJavaPkg, length, hashValue := calculateFileInfo(ifi, ipath)
						if (finfo.bExec == bExec || finfo.bJavaPkg == bJavaPkg) &&
							finfo.length == length && finfo.hashValue == hashValue {
							// no update
							return finfo, false // image layers: return safe
						}
					}
				}

				finfo.fileType = file_added
				if root.files != nil {
					root.files[file] = finfo
				}
				// mLog.WithFields(log.Fields{"id": id, "file": file}).Debug("FSN: patch")
				return finfo, true // patch missing event
			}

			// possible image file
			// mLog.WithFields(log.Fields{"id": id, "file": file}).Debug("FSN: image")
		}
	}
	// mLog.WithFields(log.Fields{"id": id, "file": file}).Debug("FSN: not exist")
	return finfo, false // image layers: return safe
}

func (fsn *FileNotificationCtr) IsNotExistingImageFile(id, file string) (*fileInfo, bool) {
	finfo := &fileInfo{}
	if fsn.bEnabled {
		// mLog.WithFields(log.Fields{"id": id, "file": file}).Debug("FSN:")
		fsn.lockMux()
		defer fsn.unlockMux()
		if root, ok := fsn.rootsByID[id]; ok {
			// existed at the upper layer? including the deleted file
			if finfo, ok := root.files[file]; ok {
				return finfo, true
			}

			procPath := fmt.Sprintf("/proc/%d/root", root.pid)
			// a mounted path?
			if utils.IsMountPoint(filepath.Join(procPath, filepath.Dir(file))) {
				// mLog.WithFields(log.Fields{"id": id, "file": file}).Debug("FSN: mounted")
				finfo.bExec = true // assume that it was an exec and will rejected at its caller
				return finfo, false
			}

			// existed at the image layers?
			// Stat: returns a FileInfo describing the named "target" file.
			// Lstat: If the file is a symbolic link, the returned FileInfodescribes the symbolic link. Lstat makes no attempt to follow the link
			if _, err := os.Stat(filepath.Join(procPath, file)); os.IsNotExist(err) {
				// mLog.WithFields(log.Fields{"id": id, "file": file}).Debug("FSN: not the in image")
				finfo.fileType = file_not_exist
				finfo.bExec = true
				return finfo, true // not existed in image layers
			}
			finfo.fileType = file_image
			return finfo, false // image layers
		}
	}
	return finfo, false
}

func (fsn *FileNotificationCtr) enumBtrfsInitFiles(rootPath, id string) (utils.Set, map[string]*fileInfo, string) {
	var err error
	var bytesValue []byte

	dirs := utils.NewSet()
	files := make(map[string]*fileInfo)
	fileMap := make(map[string]*workerlet.FileData)
	fileMapInit := make(map[string]*workerlet.FileData)
	dirs.Add(rootPath)

	///
	res := workerlet.WalkPathResult{
		Dirs:  make([]*workerlet.DirData, 0),
		Files: make([]*workerlet.FileData, 0),
	}

	resInit := workerlet.WalkPathResult{
		Dirs:  make([]*workerlet.DirData, 0),
		Files: make([]*workerlet.FileData, 0),
	}

	/// container layer (new files + image files)
	req := workerlet.WalkPathRequest{
		Pid:  1,
		Path: strings.TrimPrefix(rootPath, hostRootMountPoint),
	}

	if bytesValue, _, err = fsn.prober.walkerTask.Run(req, id); err == nil {
		err = json.Unmarshal(bytesValue, &res)
	}

	if err != nil {
		log.WithFields(log.Fields{"path": rootPath, "error": err}).Error("FSN:")
	}

	for _, d := range res.Dirs {
		dirs.Add(filepath.Join(rootPath, d.Dir))
	}

	// having an utility map
	for _, f := range res.Files {
		fileMap[f.File] = f
	}

	/// image layer (init)
	initPath := rootPath + "-init"
	if _, err := os.Stat(filepath.Join("/proc/1/root", initPath)); os.IsNotExist(err) {
		path := strings.TrimSuffix(rootPath, "/") // remove appending "/" if it exists
		subvol := filepath.Base(path)
		path = filepath.Dir(path)
		if imageLayer, err := fsn.lookupBtrfsLayerFile(path, subvol); err == nil {
			initPath = filepath.Join(path, imageLayer)
		}
		// log.WithFields(log.Fields{"path": initPath, "subvol": subvol}).Debug("FSN:")
	}

	req = workerlet.WalkPathRequest{
		Pid:  1,
		Path: strings.TrimPrefix(initPath, hostRootMountPoint),
	}

	if bytesValue, _, err = fsn.prober.walkerTask.Run(req, id); err == nil {
		err = json.Unmarshal(bytesValue, &resInit)
	}

	if err != nil {
		log.WithFields(log.Fields{"path": initPath, "error": err}).Error("FSN:")
	}

	// having an utility map
	for _, f := range resInit.Files {
		fileMapInit[f.File] = f
	}

	/////// differentiate files
	for _, f := range resInit.Files {
		if fData, ok := fileMap[f.File]; ok {
			if fData.Hash != f.Hash {
				// modified
				log.WithFields(log.Fields{"file": f.File}).Debug("FSN: modified")
				files[f.File] = &fileInfo{
					fileType:  file_added,
					bExec:     fData.IsExec,
					hashValue: fData.Hash,
					length:    fData.Info.Size,
				}
				delete(fileMapInit, f.File) // remove it from image file list
			}
		} else {
			// deleted
			log.WithFields(log.Fields{"file": f.File}).Debug("FSN: deleted")
			files[f.File] = &fileInfo{
				fileType: file_deleted, // deleted image file
				bExec:    true,         // unknown
			}
			delete(fileMapInit, f.File) // remove it from image file list
		}
	}

	for _, f := range res.Files {
		if _, ok := fileMapInit[f.File]; !ok {
			log.WithFields(log.Fields{"file": f.File}).Debug("FSN: added")
			files[f.File] = &fileInfo{
				fileType:  file_added,
				bExec:     f.IsExec,
				hashValue: f.Hash,
				length:    f.Info.Size,
			}
		}
	}
	log.WithFields(log.Fields{"path": rootPath, "fCount": len(files), "dCount": dirs.Cardinality(), "imgLayer": initPath, "error": err}).Debug("FSN:")
	return dirs, files, initPath
}

// /////////////////////
type BtrfsLayerData struct {
	ID      string    `json:"id"`
	Parent  string    `json:"parent"`
	Names   []string  `json:"names"`
	Created time.Time `json:"created"`
}

func (fsn *FileNotificationCtr) lookupBtrfsLayerFile(rootPath, sublayer string) (string, error) {
	// go up 2 layers, then find the "layers.json"
	file := filepath.Join("/proc/1/root", filepath.Dir(filepath.Dir(rootPath)), "btrfs-layers", "layers.json")
	value, err := os.ReadFile(file)
	if err == nil {
		var layers []BtrfsLayerData
		if err = json.Unmarshal(value, &layers); err == nil {
			for _, layer := range layers {
				// log.WithFields(log.Fields{"layer": layer}).Debug("FSN:")
				if layer.ID == sublayer {
					return layer.Parent, nil
				}
			}
		}
	}
	log.WithFields(log.Fields{"error": err, "file": file}).Error("FSN:")
	return "", err
}

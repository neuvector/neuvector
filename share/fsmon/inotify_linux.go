package fsmon

import (
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	imonitorFileMask = syscall.IN_ATTRIB |
		syscall.IN_MODIFY |
		syscall.IN_CLOSE_WRITE |
		syscall.IN_DELETE |
		syscall.IN_DELETE_SELF |
		syscall.IN_MOVE |
		syscall.IN_MOVE_SELF
	imonitorDirMask = imonitorFileMask | syscall.IN_MOVED_TO | syscall.IN_CREATE
)

type Inotify struct {
	fNotify
	bEnabled bool
	fd       int
	wds      map[int]*IFile
	paths    map[string]*IFile
	dirs     map[string]*IFile
}

func NewInotify() (*Inotify, error) {
	fd, err := syscall.InotifyInit()
	if err != nil {
		return nil, err
	}
	in := Inotify{
		fd:    fd,
		wds:   make(map[int]*IFile),
		paths: make(map[string]*IFile),
		dirs:  make(map[string]*IFile),
	}
	return &in, nil
}

func (n *Inotify) GetWatchCount() uint32 {
	return uint32(len(n.wds))
}

func (n *Inotify) GetWatches() []string {
	n.mux.Lock()
	defer n.mux.Unlock()
	files := make([]string, len(n.paths)+len(n.dirs))
	i := 0
	for path, _ := range n.paths {
		files[i] = path
		i++
	}
	for dir, _ := range n.dirs {
		files[i] = dir
		i++
	}
	return files
}

func (n *Inotify) CheckMonitorFileExist(path string) (interface{}, bool) {
	n.mux.Lock()
	defer n.mux.Unlock()
	if ifl, exist := n.paths[path]; exist {
		return ifl.params, true
	} else {
		return nil, false
	}
}

func (n *Inotify) RemoveMonitorFile(path string) {
	log.WithFields(log.Fields{"path": path}).Debug("")
	n.mux.Lock()
	defer n.mux.Unlock()
	if ifl, ok := n.paths[path]; ok {
		syscall.InotifyRmWatch(n.fd, uint32(ifl.wd))
		delete(n.wds, ifl.wd)
		delete(n.paths, path)
	}
	if ifl, ok := n.dirs[path]; ok {
		syscall.InotifyRmWatch(n.fd, uint32(ifl.wd))
		delete(n.wds, ifl.wd)
		delete(n.dirs, path)
	}
	// the file might be a file in one dir
	dirPath := filepath.Dir(path)
	if ifd, exist := n.dirs[dirPath]; exist {
		log.WithFields(log.Fields{"file": filepath.Base(path)}).Debug("remove file from dir")
		delete(ifd.files, filepath.Base(path))
	}
}

func (n *Inotify) GetWatchFileList(rootPid int) []string {
	log.WithFields(log.Fields{"rootPid": rootPid}).Debug("")
	watches := make([]string, 0)
	n.mux.Lock()
	defer n.mux.Unlock()
	for path, _ := range n.paths {
		if strings.Contains(path, fmt.Sprintf("/proc/%d/root/", rootPid)) {
			if a := strings.Index(path, "/root/"); a > 0 {
				watches = append(watches, path[a+6:])
			}
		}
	}
	for path, ifl := range n.dirs {
		if strings.Contains(path, fmt.Sprintf("/proc/%d/root/", rootPid)) {
			if a := strings.Index(path, "/root/"); a > 0 {
				watches = append(watches, path[a+6:])
			}
			for name, _ := range ifl.files {
				if a := strings.Index(path, "/root/"); a > 0 {
					watches = append(watches, path[a+6:]+"/"+name)
				}
			}
		}
	}
	return watches
}

func (n *Inotify) ContainerCleanup(rootPid int) {
	log.WithFields(log.Fields{"rootPid": rootPid}).Debug("")
	n.mux.Lock()
	defer n.mux.Unlock()
	for path, ifl := range n.paths {
		if strings.Contains(path, fmt.Sprintf("/proc/%d/root/", rootPid)) {
			syscall.InotifyRmWatch(n.fd, uint32(ifl.wd))
			delete(n.wds, ifl.wd)
			delete(n.paths, path)
			log.WithFields(log.Fields{"path": path}).Debug("Delete file path")
		}
	}
	for path, ifl := range n.dirs {
		if strings.Contains(path, fmt.Sprintf("/proc/%d/root/", rootPid)) {
			syscall.InotifyRmWatch(n.fd, uint32(ifl.wd))
			delete(n.wds, ifl.wd)
			delete(n.dirs, path)
			log.WithFields(log.Fields{"path": path}).Debug("Delete dir path")
		}
	}
}

func (n *Inotify) AddMonitorFile(path string, cb NotifyCallback, params interface{}) bool {
	n.mux.Lock()
	defer n.mux.Unlock()
	if _, ok := n.paths[path]; ok {
		return false
	}
	wd, err := syscall.InotifyAddWatch(n.fd, path, imonitorFileMask)
	if err != nil {
		log.WithFields(log.Fields{"err": err, "file": path}).Debug("Add Inotify watch fail")
		return false
	}
	file := IFile{
		path:   path,
		params: params,
		cb:     cb,
		wd:     wd,
	}
	n.wds[wd] = &file
	n.paths[path] = &file
	log.WithFields(log.Fields{"path": path}).Debug("")
	return true
}

func (n *Inotify) AddMonitorDirFile(path string, files map[string]interface{},
	cb NotifyCallback, params interface{}) bool {
	n.mux.Lock()
	defer n.mux.Unlock()
	file, ok := n.dirs[path]
	if !ok {
		wd, err := syscall.InotifyAddWatch(n.fd, path, imonitorDirMask)
		if err != nil {
			log.WithFields(log.Fields{"err": err, "path": path}).Debug("Add Inotify directory watch fail")
			return false
		}
		file = &IFile{
			path:   path,
			params: params,
			cb:     cb,
			wd:     wd,
			dir:    true,
			files:  files,
		}
		n.wds[wd] = file
		n.dirs[path] = file
		log.WithFields(log.Fields{"path": path, "files": len(files)}).Debug("")
	} else {
		file.files = files
	}
	log.WithFields(log.Fields{"wds": len(n.wds), "paths": len(n.paths), "dirs": len(n.dirs), "path": path}).Debug("")
	return true
}

func (n *Inotify) MonitorFileEvents() {
	buffer := make([]byte, syscall.SizeofInotifyEvent*128)
	n.bEnabled = true
	for {
		if !n.bEnabled {
			break
		}

		bytesRead, err := syscall.Read(n.fd, buffer)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Error("Read Inotify Error")
			if strings.Contains(err.Error(), "bad file descriptor") {
				return
			}
			continue
		}
		if bytesRead < syscall.SizeofInotifyEvent {
			continue
		}
		offset := 0
		for offset <= bytesRead-syscall.SizeofInotifyEvent {
			event := (*syscall.InotifyEvent)(unsafe.Pointer(&buffer[offset]))

			var cbFile *IFile
			n.mux.Lock()
			if file, found := n.wds[int(event.Wd)]; found {
				if (event.Mask&imonitorDirMask) > 0 || (event.Mask&syscall.IN_IGNORED) > 0 {
					if file.dir {
						nameLen := uint32(event.Len)
						if nameLen > 0 {
							bytes := (*[unix.PathMax]byte)(unsafe.Pointer(&buffer[offset+unix.SizeofInotifyEvent]))
							filename := strings.TrimRight(string(bytes[0:nameLen]), "\000")
							log.WithFields(log.Fields{"path": file.path, "file": filename}).Debug("Directory file modified")

							if fi, ok := file.files[filename]; ok {
								cbFile = &IFile{
									path:   file.path + "/" + filename,
									cb:     file.cb,
									params: fi,
								}
							} else if (event.Mask & (syscall.IN_MOVED_TO | syscall.IN_CREATE)) > 0 {
								cbFile = &IFile{
									path:   file.path + "/" + filename,
									cb:     file.cb,
									params: file.params,
								}
							}
						} else {
							log.WithFields(log.Fields{"path": file.path}).Debug("Directory removed")
							// remove dir
							cbFile = file
						}
					} else {
						log.WithFields(log.Fields{"path": file.path}).Debug("notify")
						cbFile = file
						syscall.InotifyRmWatch(n.fd, uint32(event.Wd))
						delete(n.wds, int(event.Wd))
						delete(n.paths, file.path)
					}
				}
			}
			n.mux.Unlock()
			//put the callback outside the mux lock, to avoid dead lock
			if cbFile != nil {
				cbFile.cb(cbFile.path, event.Mask, cbFile.params, nil)
			}

			offset += syscall.SizeofInotifyEvent + int(event.Len)
		}
	}
	log.Info("FMON: exit")
}

func (n *Inotify) Close() {
	n.mux.Lock()
	defer n.mux.Unlock()
	for wd, _ := range n.wds {
		syscall.InotifyRmWatch(n.fd, uint32(wd))
	}
	syscall.Close(n.fd)
	n.bEnabled = false
}

////////
func (n *Inotify) GetProbeData(m *IMonProbeData) {
	n.mux.Lock()
	defer n.mux.Unlock()

	m.NWds = len(n.wds)
	m.NPaths = len(n.paths)
	m.NDirs = len(n.dirs)
}

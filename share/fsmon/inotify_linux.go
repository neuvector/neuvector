package fsmon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/neuvector/neuvector/share/osutil"
)

const (
	imonitorFileMask = syscall.IN_ATTRIB |
		syscall.IN_MODIFY |
		syscall.IN_CLOSE_WRITE |
		syscall.IN_DELETE |
		syscall.IN_DELETE_SELF |
		syscall.IN_MOVE |
		syscall.IN_MOVE_SELF
	imonitorDirMask    = imonitorFileMask | syscall.IN_MOVED_TO | syscall.IN_CREATE
	imonitorRemoveMask = syscall.IN_DELETE | syscall.IN_DELETE_SELF | syscall.IN_MOVE | syscall.IN_MOVE_SELF
)

type Inotify struct {
	fNotify
	bEnabled    bool
	fd          int
	wds         map[int]*IFile
	paths       map[string]*IFile
	dirs        map[string]*IFile
	inotifyFile *os.File
}

func NewInotify() (*Inotify, error) {
	// Need to set nonblocking mode for SetDeadline to work, otherwise blocking
	// I/O operations won't terminate on close.
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, err
	}
	in := Inotify{
		fd:          fd,
		inotifyFile: os.NewFile(uintptr(fd), ""),
		wds:         make(map[int]*IFile),
		paths:       make(map[string]*IFile),
		dirs:        make(map[string]*IFile),
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
	for path := range n.paths {
		files[i] = path
		i++
	}
	for dir := range n.dirs {
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
		if _, err := syscall.InotifyRmWatch(n.fd, uint32(ifl.wd)); err != nil {
			log.WithFields(log.Fields{"err": err, "path": path}).Error()
		}
		delete(n.wds, ifl.wd)
		delete(n.paths, path)
	}
	if ifl, ok := n.dirs[path]; ok {
		if _, err := syscall.InotifyRmWatch(n.fd, uint32(ifl.wd)); err != nil {
			log.WithFields(log.Fields{"err": err, "dir": path}).Error()
		}
		delete(n.wds, ifl.wd)
		delete(n.dirs, path)
	}
	// the file might be a subdir in the watched dir
	dirPath := filepath.Dir(path)
	if ifd, exist := n.dirs[dirPath]; exist {
		mLog.WithFields(log.Fields{"dir": filepath.Base(path)}).Debug("remove subdir from dir")
		delete(ifd.files, filepath.Base(path))
	}
}

func (n *Inotify) GetWatchFileList(rootPid int) []string {
	log.WithFields(log.Fields{"rootPid": rootPid}).Debug("")
	watches := make([]string, 0)
	n.mux.Lock()
	defer n.mux.Unlock()
	for path := range n.paths {
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
			for name := range ifl.files {
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
			if _, err := syscall.InotifyRmWatch(n.fd, uint32(ifl.wd)); err != nil {
				log.WithFields(log.Fields{"err": err, "path": path}).Error()
			}
			delete(n.wds, ifl.wd)
			delete(n.paths, path)
			mLog.WithFields(log.Fields{"path": path}).Debug("Delete file path")
		}
	}
	for path, ifl := range n.dirs {
		if strings.Contains(path, fmt.Sprintf("/proc/%d/root/", rootPid)) {
			if _, err := syscall.InotifyRmWatch(n.fd, uint32(ifl.wd)); err != nil {
				log.WithFields(log.Fields{"err": err, "dir": path}).Error()
			}
			delete(n.wds, ifl.wd)
			delete(n.dirs, path)
			mLog.WithFields(log.Fields{"path": path}).Debug("Delete dir path")
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
	mLog.WithFields(log.Fields{"count": len(n.paths), "path": path}).Debug()
	return true
}

// Without Lock
func (n *Inotify) addMonitorDir(path string, files map[string]interface{}, cb NotifyCallback, params interface{}) bool {
	if ifile, ok := n.dirs[path]; ok {
		// mLog.WithFields(log.Fields{"path": path}).Debug()
		ifile.files = files
	} else {
		wd, err := syscall.InotifyAddWatch(n.fd, path, imonitorDirMask)
		if err != nil {
			log.WithFields(log.Fields{"err": err, "path": path}).Debug("Add Inotify directory watch fail")
			return false
		}
		ifile = &IFile{
			path:   path,
			params: params,
			cb:     cb,
			wd:     wd,
			dir:    true,
			files:  files,
		}
		n.wds[wd] = ifile
		n.dirs[path] = ifile
		mLog.WithFields(log.Fields{"counts": len(n.dirs), "dir": path}).Debug()
	}
	return true
}

func (n *Inotify) AddMonitorDirFile(path string, files map[string]interface{}, cb NotifyCallback, params interface{}) bool {
	n.mux.Lock()
	defer n.mux.Unlock()
	return n.addMonitorDir(path, files, cb, params)
}

func (n *Inotify) MonitorFileEvents() {
	buffer := make([]byte, syscall.SizeofInotifyEvent*4096) // Buffer for a maximum of 4096 raw events
	n.bEnabled = true
	for {
		if !n.bEnabled {
			break
		}

		bytesRead, err := n.inotifyFile.Read(buffer[:])
		// bytesRead, err := syscall.Read(n.fd, buffer)
		if err != nil || bytesRead < syscall.SizeofInotifyEvent {
			if errors.Unwrap(err) == os.ErrClosed || strings.Contains(err.Error(), "bad file descriptor") {
				log.WithFields(log.Fields{"err": err}).Error("Read Inotify")
				break
			}
			log.WithFields(log.Fields{"err": err}).Error()
			continue
		}

		offset := 0
		for offset <= bytesRead-syscall.SizeofInotifyEvent {
			event := (*syscall.InotifyEvent)(unsafe.Pointer(&buffer[offset]))
			var cbFile *IFile
			n.mux.Lock()
			if ifile, found := n.wds[int(event.Wd)]; found {
				if (event.Mask & (imonitorDirMask | syscall.IN_IGNORED)) > 0 {
					if ifile.dir { // under a watch directory
						path := ifile.path
						nameLen := uint32(event.Len)
						if nameLen > 0 {
							bytes := (*[unix.PathMax]byte)(unsafe.Pointer(&buffer[offset+unix.SizeofInotifyEvent]))
							path = filepath.Join(ifile.path, strings.TrimRight(string(bytes[0:nameLen]), "\000"))
						}

						if (event.Mask & syscall.IN_ISDIR) > 0 {
							mLog.WithFields(log.Fields{"dir": path, "mask": strconv.FormatUint(uint64(event.Mask), 16), "nameLen": nameLen}).Debug("dir: altered")
							if (event.Mask & (syscall.IN_CREATE | syscall.IN_MOVED_TO)) > 0 {
								cbFile = &IFile{path: path, cb: ifile.cb, params: ifile.params}

								// new dir
								if info, err := os.Stat(path); err == nil {
									finfo := ifile.params.(*osutil.FileInfoExt) // original FileInfoExt
									flt := finfo.Filter.(*filterRegex)
									if flt.recursive {
										ff := make(map[string]interface{})
										dirInfo := &osutil.FileInfoExt{
											ContainerId: finfo.ContainerId,
											FileMode:    info.Mode(),
											Path:        path,
											Filter:      finfo.Filter,
											Protect:     finfo.Protect,
											UserAdded:   finfo.UserAdded,
										}
										n.addMonitorDir(path, ff, ifile.cb, dirInfo)
									}
								}
							} else if (event.Mask & syscall.IN_ATTRIB) > 0 {
								if nameLen == 0 {
									// skip directory meta changed
									// mLog.WithFields(log.Fields{"dir": path}).Debug("dir: meta")
									cbFile = &IFile{path: path, cb: ifile.cb, params: ifile.params}
								}
							} else if (event.Mask & (syscall.IN_DELETE | syscall.IN_MOVED_FROM)) > 0 {
								// mLog.WithFields(log.Fields{"dir": path}).Debug("dir: deleted/moved")
								cbFile = &IFile{path: path, cb: ifile.cb, params: ifile.params}
							} else {
								mLog.WithFields(log.Fields{"dir": path}).Debug("dir: not handled")
							}
						} else { // a file under a watched directory
							mLog.WithFields(log.Fields{"path": path, "mask": strconv.FormatUint(uint64(event.Mask), 16)}).Debug("dir: changed")
							cbFile = &IFile{path: path, cb: ifile.cb, params: ifile.params}
						}
					} else { // a watched file
						if (event.Mask & imonitorRemoveMask) > 0 {
							log.WithFields(log.Fields{"path": ifile.path}).Debug("file: remove")
							if _, err := syscall.InotifyRmWatch(n.fd, uint32(event.Wd)); err != nil {
								log.WithFields(log.Fields{"err": err, "path": ifile.path}).Error()
							}
							cbFile = ifile
							delete(n.wds, int(event.Wd))
							delete(n.paths, ifile.path)
						} else {
							if (time.Now().Unix() - ifile.lastChg) > 180 { // reduce report cases
								log.WithFields(log.Fields{"path": ifile.path}).Debug("file: change")
								ifile.lastChg = time.Now().Unix()
								cbFile = ifile
							}
						}
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
	for wd := range n.wds {
		if _, err := syscall.InotifyRmWatch(n.fd, uint32(wd)); err != nil {
			log.WithFields(log.Fields{"err": err, "wd": uint32(wd)}).Error()
		}
	}
	syscall.Close(n.fd)
	n.bEnabled = false
}

// //////
func (n *Inotify) GetProbeData(m *IMonProbeData) {
	n.mux.Lock()
	defer n.mux.Unlock()

	m.NWds = len(n.wds)
	m.NPaths = len(n.paths)
	m.NDirs = len(n.dirs)
}

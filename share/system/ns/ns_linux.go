//go:build linux
// +build linux

package namespace

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
)

// SYS_SETNS syscall allows changing the namespace of the current process.
var SYS_SETNS = map[string]uintptr{
	"386":     346,
	"amd64":   308,
	"arm64":   268,
	"arm":     375,
	"ppc64":   350,
	"ppc64le": 350,
	"s390x":   339,
}[runtime.GOARCH]

// Setns sets namespace using syscall. Note that this should be a method
// in syscall but it has not been added.
func setns(fd int, nstype int) (err error) {
	_, _, e1 := syscall.RawSyscall(SYS_SETNS, uintptr(fd), uintptr(nstype), 0)
	if e1 != 0 {
		err = e1
	}
	return
}

// Set sets the current network namespace to the namespace represented
// by NsHandle.
func Set(ns *NsHandle) (err error) {
	switch ns.nstype {
	case NSMNT:
		return setns(ns.fd, syscall.CLONE_NEWNS)
	case NSUTS:
		return setns(ns.fd, syscall.CLONE_NEWUTS)
	case NSIPC:
		return setns(ns.fd, syscall.CLONE_NEWIPC)
	case NSUSER:
		return setns(ns.fd, syscall.CLONE_NEWUSER)
	case NSPID:
		return setns(ns.fd, syscall.CLONE_NEWPID)
	case NSNET:
		return setns(ns.fd, syscall.CLONE_NEWNET)
	default:
		return ErrNotImplemented
	}
}

// Get gets a handle to the current threads namespace.
func get(nstype string) (int, error) {
	return getFromThread(nstype, os.Getpid(), syscall.Gettid())
}

// getFromPath gets a handle to a namespace identified by the path
func getFromPath(path string) (int, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY, 0)
	if err != nil {
		return -1, err
	}
	return fd, nil
}

func getPathFromPid(nstype string, proc string, pid int) string {
	return fmt.Sprintf("%s%d/ns/%s", proc, pid, nstype)
}

// GetFromPid gets a handle to the namespace of a given pid.
func getFromPid(nstype string, proc string, pid int) (int, error) {
	return getFromPath(getPathFromPid(nstype, proc, pid))
}

// getFromThread gets a handle to the namespace of a given pid and tid.
func getFromThread(nstype string, pid, tid int) (int, error) {
	return getFromPath(fmt.Sprintf("/proc/%d/task/%d/ns/%s", pid, tid, nstype))
}

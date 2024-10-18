package namespace

import (
	"errors"
	"fmt"
	"syscall"
)

const (
	NSMNT    = "mnt"
	NSUTS    = "uts"
	NSIPC    = "ipc"
	NSUSER   = "user"
	NSPID    = "pid"
	NSNET    = "net"
	NSCGROUP = "cgroup"
)

var (
	ErrNotImplemented = errors.New("not implemented")
)

// NsHandle is a handle to a network namespace. It can be cast directly
// to an int and used as a file descriptor.
type NsHandle struct {
	nstype string
	fd     int
}

func GetPathFromPid(nstype string, proc string, pid int) string {
	return getPathFromPid(nstype, proc, pid)
}

func NewNsHandle(nstype string, proc string, pid int) (*NsHandle, error) {
	fd, err := getFromPid(nstype, proc, pid)
	if err != nil {
		return nil, err
	}

	return &NsHandle{nstype: nstype, fd: fd}, nil
}

func CurNsHandle(nstype string) (*NsHandle, error) {
	fd, err := get(nstype)
	if err != nil {
		return nil, err
	}

	return &NsHandle{nstype: nstype, fd: fd}, nil
}

func (ns *NsHandle) String() string {
	if ns.fd == -1 {
		return "NS(None)"
	}
	return fmt.Sprintf("NS(%v: %s)", ns.fd, ns.nstype)
}

// IsOpen returns true if Close() has not been called.
func (ns *NsHandle) IsOpen() bool {
	return ns.fd != -1
}

// Close closes the NsHandle and resets its file descriptor to -1.
// It is not safe to use an NsHandle after Close() is called.
func (ns *NsHandle) Close() error {
	if ns.fd == -1 {
		return nil
	}
	if err := syscall.Close(ns.fd); err != nil {
		return err
	}
	ns.fd = -1
	return nil
}

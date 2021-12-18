// +build !linux

package namespace

import (
	"errors"
)

func Set(ns *NsHandle) (err error) {
	return ErrNotImplemented
}

func get(nstype string) (NsHandle, error) {
	return -1, ErrNotImplemented
}

func getFromPid(nstype string, proc string, pid int) (NsHandle, error) {
	return -1, ErrNotImplemented
}

func getFromThread(nstype string, pid, tid int) (int, error) {
	return -1, ErrNotImplemented
}

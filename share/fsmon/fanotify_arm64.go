package fsmon

import (
	"syscall"
	"unsafe"
)

// Add/Delete/Modify an Fanotify mark
func (nd *NotifyFD) Mark(flags int, mask uint64, dfd int, path string) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_FANOTIFY_MARK, uintptr(nd.f.Fd()), uintptr(flags), uintptr(mask), uintptr(dfd), uintptr(unsafe.Pointer(syscall.StringBytePtr(path))), 0)

	var err error
	if errno != 0 {
		err = errno
	}

	return err
}

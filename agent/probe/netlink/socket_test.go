package netlink

import (
	"encoding/binary"
	"errors"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func nlmsgerr(code int32) syscall.NetlinkMessage {
	data := make([]byte, 4+syscall.NLMSG_HDRLEN)
	binary.NativeEndian.PutUint32(data, uint32(code))
	return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: syscall.NLMSG_ERROR}, Data: data}
}

func TestMessageError(t *testing.T) {
	for _, c := range []struct {
		name  string
		errno syscall.Errno
	}{
		{"EBUSY", unix.EBUSY},
		{"EPERM", unix.EPERM},
		{"ENOENT", unix.ENOENT},
	} {
		err := MessageError(nlmsgerr(-int32(c.errno)))
		if !errors.Is(err, c.errno) {
			t.Errorf("%s: errors.Is is false, got %v", c.name, err)
		}
		if !strings.Contains(err.Error(), c.name) {
			t.Errorf("%s: name missing from %q", c.name, err.Error())
		}
	}

	if err := MessageError(nlmsgerr(0)); err == nil || !strings.Contains(err.Error(), "acknowledgement") {
		t.Errorf("errno 0: want an acknowledgement error, got %v", err)
	}

	short := syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: syscall.NLMSG_ERROR}, Data: []byte{0xf0}}
	if err := MessageError(short); err == nil || errors.Is(err, unix.EBUSY) {
		t.Errorf("short payload: want a plain error, got %v", err)
	}

	done := syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: syscall.NLMSG_DONE}}
	if err := MessageError(done); err != nil {
		t.Errorf("NLMSG_DONE: want nil, got %v", err)
	}
}

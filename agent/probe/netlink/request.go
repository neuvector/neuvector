package netlink

import (
	"os"
	"sync/atomic"
	"syscall"
	"unsafe"
)

type NetlinkRequestData interface {
	Len() int
	Serialize() []byte
}

// linux/netlink.h
type NetlinkRequest struct {
	syscall.NlMsghdr
	Data []NetlinkRequestData
}

var nextSeqNr uint32

func (req *NetlinkRequest) Serialize() []byte {
	length := syscall.SizeofNlMsghdr
	dataBytes := make([][]byte, len(req.Data))
	for i, data := range req.Data {
		dataBytes[i] = data.Serialize()
		length = length + len(dataBytes[i])
	}
	req.Len = uint32(length)
	b := make([]byte, length)
	hdr := (*(*[syscall.SizeofNlMsghdr]byte)(unsafe.Pointer(req)))[:]
	next := syscall.SizeofNlMsghdr
	copy(b[0:next], hdr)
	for _, data := range dataBytes {
		for _, dataByte := range data {
			b[next] = dataByte
			next = next + 1
		}
	}
	return b
}

func (req *NetlinkRequest) AddData(data NetlinkRequestData) {
	if data != nil {
		req.Data = append(req.Data, data)
	}
}

func NewNetlinkRequest(nlmsg, flags int) *NetlinkRequest {
	return &NetlinkRequest{
		NlMsghdr: syscall.NlMsghdr{
			Len:   uint32(syscall.SizeofNlMsghdr),
			Type:  uint16(nlmsg),
			Flags: syscall.NLM_F_REQUEST | uint16(flags),
			Seq:   atomic.AddUint32(&nextSeqNr, 1),
			Pid:   uint32(os.Getpid()),
		},
	}
}

package netlink

import (
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

type NetlinkProtocol int

type NetlinkSocket struct {
	fd       int
	protocol NetlinkProtocol
	groups   uint32
	buf      []byte
}

func NewNetlinkSocket(protocol NetlinkProtocol, bufSize uint, groups ...uint) (*NetlinkSocket, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, int(protocol))
	if err != nil {
		return nil, err
	}

	var option int = 1
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, option)
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}

	sockaddr := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Pid:    0,
	}
	if protocol == syscall.NETLINK_CONNECTOR {
		sockaddr.Groups = uint32(groups[0])
		sockaddr.Pid = uint32(os.Getpid()) // identifier
	} else {
		for _, g := range groups {
			sockaddr.Groups |= (1 << (g - 1))
		}
	}

	err = syscall.Bind(fd, sockaddr)
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}

	ns := &NetlinkSocket{
		fd:       fd,
		protocol: protocol,
		groups:   sockaddr.Groups,
		buf:      make([]byte, bufSize),
	}
	return ns, nil
}

func (ns *NetlinkSocket) Close() {
	//syscall.Shutdown(ns.fd, syscall.SHUT_RDWR)
	//syscall.SetNonblock(ns.fd, true)
	syscall.Close(ns.fd)
}

func (ns *NetlinkSocket) Send(request *NetlinkRequest) error {
	sockaddr := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Pid:    0,
		Groups: ns.groups,
	}
	if err := syscall.Sendto(ns.fd, request.Serialize(), 0, sockaddr); err != nil {
		return err
	}
	return nil
}

func (ns *NetlinkSocket) Write(request *NetlinkRequest) error {
	// no Send() function in library but using Write() for a bound socket
	if _, err := syscall.Write(ns.fd, request.Serialize()); err != nil {
		return err
	}
	return nil
}

func (ns *NetlinkSocket) SetFilter(filters []bpf.Instruction) error {
	var err error
	var assembled []bpf.RawInstruction
	if assembled, err = bpf.Assemble(filters); err != nil {
		return err
	}

	var program = unix.SockFprog{
		Len:    uint16(len(assembled)),
		Filter: (*unix.SockFilter)(unsafe.Pointer(&assembled[0])),
	}

	var b = (*[unix.SizeofSockFprog]byte)(unsafe.Pointer(&program))[:unix.SizeofSockFprog]
	if _, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT,
		uintptr(ns.fd), uintptr(syscall.SOL_SOCKET), uintptr(syscall.SO_ATTACH_FILTER),
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0); errno != 0 {
		return errno
	}

	return nil
}

func (ns *NetlinkSocket) SetTimeout(timeout time.Duration) error {
	t := syscall.Timeval{Sec: int64(timeout / time.Second)}
	return syscall.SetsockoptTimeval(ns.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &t)
}

func (ns *NetlinkSocket) Receive() ([]syscall.NetlinkMessage, error) {
	nr, err := syscall.Read(ns.fd, ns.buf)
	if err != nil {
		return nil, err
	}
	if nr < syscall.NLMSG_HDRLEN {
		return nil, fmt.Errorf("Got short response from netlink")
	}
	return syscall.ParseNetlinkMessage(ns.buf[:nr])
}

func (ns *NetlinkSocket) ReceiveFrom() ([]syscall.NetlinkMessage, syscall.Sockaddr, error) {
	nr, from, err := syscall.Recvfrom(ns.fd, ns.buf, 0)
	if err != nil {
		return nil, from, err
	}
	if nr < syscall.NLMSG_HDRLEN {
		return nil, from, fmt.Errorf("Got short response from netlink")
	}

	msg, err := syscall.ParseNetlinkMessage(ns.buf[:nr])
	return msg, from, err
}

// /////
func (ns *NetlinkSocket) EPollReceive(tv *syscall.Timeval) ([]syscall.NetlinkMessage, error) {
	const MaxEpollEvents = 16
	var n int
	var event syscall.EpollEvent
	var events [MaxEpollEvents]syscall.EpollEvent

	epfd, err := syscall.EpollCreate1(0)
	if err != nil {
		return nil, fmt.Errorf("epoll_create1: %v", err)
	}
	defer syscall.Close(epfd)

	event.Events = syscall.EPOLLIN
	event.Fd = int32(ns.fd)
	if err = syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, ns.fd, &event); err != nil {
		return nil, fmt.Errorf("epoll_ctl: %v", err)
	}

	// convert timeout to ms
	timeout := int(tv.Nano() / 1000000)
	n, err = syscall.EpollWait(epfd, events[:], timeout)
	if err != nil {
		return nil, err
	} else if n > 0 {
		return ns.Receive()
	}
	return nil, nil // timeout-ed
}

// /////
func (ns *NetlinkSocket) EPollReceiveFrom(tv *syscall.Timeval) ([]syscall.NetlinkMessage, syscall.Sockaddr, error) {
	const MaxEpollEvents = 16
	var n int
	var event syscall.EpollEvent
	var events [MaxEpollEvents]syscall.EpollEvent

	epfd, err := syscall.EpollCreate1(0)
	if err != nil {
		return nil, nil, fmt.Errorf("epoll_create1: %v", err)
	}
	defer syscall.Close(epfd)

	event.Events = syscall.EPOLLIN
	event.Fd = int32(ns.fd)
	if err = syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, ns.fd, &event); err != nil {
		return nil, nil, fmt.Errorf("epoll_ctl: %v", err)
	}

	// convert timeout to ms
	timeout := int(tv.Nano() / 1000000)
	n, err = syscall.EpollWait(epfd, events[:], timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("epoll_wait: %v", err)
	} else if n > 0 {
		return ns.ReceiveFrom()
	}
	return nil, nil, nil // timeout-ed
}

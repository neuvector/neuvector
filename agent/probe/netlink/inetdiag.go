package netlink

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

const (
	SizeofInetDiagReqV2 = 0x38
)

const (
	SOCK_DIAG_BY_FAMILY = 20 // linux/sock_diag.h
)

// netinet/tcp.h
const (
	_               = iota
	TCP_ESTABLISHED = iota
	TCP_SYN_SENT
	TCP_SYN_RECV
	TCP_FIN_WAIT1
	TCP_FIN_WAIT2
	TCP_TIME_WAIT
	TCP_CLOSE
	TCP_CLOSE_WAIT
	TCP_LAST_ACK
	TCP_LISTEN
	TCP_CLOSING
)

const (
	TCP_ALL = 0xFFF
)

var TcpStatesMap = map[uint8]string{
	TCP_ESTABLISHED: "established",
	TCP_SYN_SENT:    "syn_sent",
	TCP_SYN_RECV:    "syn_recv",
	TCP_FIN_WAIT1:   "fin_wait1",
	TCP_FIN_WAIT2:   "fin_wait2",
	TCP_TIME_WAIT:   "time_wait",
	TCP_CLOSE:       "close",
	TCP_CLOSE_WAIT:  "close_wait",
	TCP_LAST_ACK:    "last_ack",
	TCP_LISTEN:      "listen",
	TCP_CLOSING:     "closing",
}

var DiagFamilyMap = map[uint8]string{
	syscall.AF_INET:  "tcp",
	syscall.AF_INET6: "tcp6",
}

type be16 [2]byte
type be32 [4]byte

// linux/inet_diag.h
type InetDiagSockId struct {
	IDiagSPort  be16
	IDiagDPort  be16
	IDiagSrc    [4]be32
	IDiagDst    [4]be32
	IDiagIf     uint32
	IDiagCookie [2]uint32
}

func (id *InetDiagSockId) SrcIPv4() net.IP {
	return ipv4(id.IDiagSrc[0])
}

func (id *InetDiagSockId) DstIPv4() net.IP {
	return ipv4(id.IDiagDst[0])
}

func (id *InetDiagSockId) SrcIPv6() net.IP {
	return ipv6(id.IDiagSrc)
}

func (id *InetDiagSockId) DstIPv6() net.IP {
	return ipv6(id.IDiagDst)
}

func (id *InetDiagSockId) SrcIP() net.IP {
	return ip(id.IDiagSrc)
}

func (id *InetDiagSockId) DstIP() net.IP {
	return ip(id.IDiagDst)
}

func ip(bytes [4]be32) net.IP {
	if isIpv6(bytes) {
		return ipv6(bytes)
	} else {
		return ipv4(bytes[0])
	}
}

func isIpv6(original [4]be32) bool {
	for i := 1; i < 4; i++ {
		for j := 0; j < 4; j++ {
			if original[i][j] != 0 {
				return true
			}
		}
	}
	return false
}

func ipv4(original be32) net.IP {
	return net.IPv4(original[0], original[1], original[2], original[3])
}

func ipv6(original [4]be32) net.IP {
	ip := make(net.IP, net.IPv6len)
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			ip[4*i+j] = original[i][j]
		}
	}
	return ip
}

func (id *InetDiagSockId) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d", id.SrcIP().String(), id.IDiagSPort, id.DstIP().String(), id.IDiagDPort)
}

type InetDiagReqV2 struct {
	SDiagFamily   uint8
	SDiagProtocol uint8
	IDiagExt      uint8
	Pad           uint8
	IDiagStates   uint32
	Id            InetDiagSockId
}

func (req *InetDiagReqV2) Serialize() []byte {
	return (*(*[SizeofInetDiagReqV2]byte)(unsafe.Pointer(req)))[:]
}

func (req *InetDiagReqV2) Len() int {
	return SizeofInetDiagReqV2
}

func NewInetDiagReqV2(family, protocol uint8, states uint32) *InetDiagReqV2 {
	return &InetDiagReqV2{
		SDiagFamily:   family,
		SDiagProtocol: protocol,
		IDiagStates:   states,
	}
}

type InetDiagMsg struct {
	IDiagFamily  uint8
	IDiagState   uint8
	IDiagTimer   uint8
	IDiagRetrans uint8
	Id           InetDiagSockId
	IDiagExpires uint32
	IDiagRqueue  uint32
	IDiagWqueue  uint32
	IDiagUid     uint32
	IDiagInode   uint32
}

func (msg *InetDiagMsg) String() string {
	return fmt.Sprintf("%s, %s, %s", DiagFamilyMap[msg.IDiagFamily], TcpStatesMap[msg.IDiagState], msg.Id.String())
}

func ParseInetDiagMsg(data []byte) *InetDiagMsg {
	return (*InetDiagMsg)(unsafe.Pointer(&data[0]))
}

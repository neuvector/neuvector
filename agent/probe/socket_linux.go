package probe

import (
	"fmt"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/agent/probe/netlink"
	"github.com/neuvector/neuvector/share/utils"
)

const inetMonitorSocketSize uint = 1024 * 5
const INET_DIAG_INFO = 2

/* removed by go-lint
func (p *Probe) isSocketIPv4(d *netlink.InetDiagMsg) bool {
	if d.IDiagFamily == syscall.AF_INET6 {
		if utils.IsIPv6(d.Id.SrcIPv6()) || utils.IsIPv6(d.Id.DstIPv6()) {
			return false
		}
	}

	return true
}
*/

func (p *Probe) inetGetSockets(family, proto uint8, state uint32) ([]*socket, []*socket, error) {
	req := netlink.NewNetlinkRequest(netlink.SOCK_DIAG_BY_FAMILY, syscall.NLM_F_DUMP)
	{
		msg := netlink.NewInetDiagReqV2(family, proto, state)
		msg.IDiagExt |= (1 << (INET_DIAG_INFO - 1))
		req.AddData(msg)
	}

	if err := p.nsInet.Send(req); err != nil {
		return nil, nil, err
	}

	listenList := make([]*socket, 0)
	connectList := make([]*socket, 0)
	for {
		msgs, err := p.nsInet.Receive()
		if err != nil {
			return nil, nil, err
		}

		for _, msg := range msgs {
			if msg.Header.Type == syscall.NLMSG_DONE {
				return listenList, connectList, nil
			}
			if msg.Header.Type == syscall.NLMSG_ERROR {
				return nil, nil, fmt.Errorf("Error in netlink message")
			}

			// IPv4 only for connected socket. Keep all listen ports on IPv4 and v6.
			k := p.convertInetDiag(netlink.ParseInetDiagMsg(msg.Data), proto)
			if p.isListenState(k) {
				listenList = append(listenList, k)
			} else if utils.IsIPv4(k.src) {
				connectList = append(connectList, k)
			}
		}
	}

	// return listenList, connectList, nil
}

func (p *Probe) convertInetDiag(d *netlink.InetDiagMsg, protocol uint8) *socket {
	s := &socket{
		family:   d.IDiagFamily,
		protocol: protocol,
		srcPort:  uint16(d.Id.IDiagSPort[0])<<8 + uint16(d.Id.IDiagSPort[1]),
		dstPort:  uint16(d.Id.IDiagDPort[0])<<8 + uint16(d.Id.IDiagDPort[1]),
		state:    d.IDiagState,
		inode:    d.IDiagInode,
	}
	if d.IDiagFamily == syscall.AF_INET {
		s.src = d.Id.SrcIPv4()
		s.dst = d.Id.DstIPv4()
	} else {
		s.src = d.Id.SrcIPv6()
		s.dst = d.Id.DstIPv6()
	}
	return s
}

func (p *Probe) getAllSockets() ([]*socket, []*socket, error) {
	var tcpStateMask uint32 = netlink.TCP_ALL &^ (1 << netlink.TCP_SYN_SENT)
	var udpStateMask uint32 = netlink.TCP_ALL

	t4l, t4c, err := p.inetGetSockets(syscall.AF_INET, syscall.IPPROTO_TCP, tcpStateMask)
	if err != nil {
		return nil, nil, err
	}
	u4l, u4c, err := p.inetGetSockets(syscall.AF_INET, syscall.IPPROTO_UDP, udpStateMask)
	if err != nil {
		return nil, nil, err
	}
	t6l, t6c, err := p.inetGetSockets(syscall.AF_INET6, syscall.IPPROTO_TCP, tcpStateMask)
	if err != nil {
		return nil, nil, err
	}
	u6l, u6c, err := p.inetGetSockets(syscall.AF_INET6, syscall.IPPROTO_UDP, udpStateMask)
	if err != nil {
		return nil, nil, err
	}

	listens := make([]*socket, 0, len(t4l)+len(u4l)+len(t6l)+len(u6l))
	connects := make([]*socket, 0, len(t4c)+len(u4c)+len(t6c)+len(u6c))

	listens = append(listens, t4l...)
	listens = append(listens, u4l...)
	listens = append(listens, t6l...)
	listens = append(listens, u6l...)
	connects = append(connects, t4c...)
	connects = append(connects, u4c...)
	connects = append(connects, t6c...)
	connects = append(connects, u6c...)

	return listens, connects, nil
}

func (p *Probe) openSocketMonitor() (*netlink.NetlinkSocket, error) {
	ns, err := netlink.NewNetlinkSocket(syscall.NETLINK_INET_DIAG, inetMonitorSocketSize, 0)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to create socket for inet")
		return nil, err
	} else {
		return ns, nil
	}
}

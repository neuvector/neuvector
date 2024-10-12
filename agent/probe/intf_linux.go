package probe

import (
	"syscall"
	"unsafe"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/agent/probe/netlink"
	"github.com/neuvector/neuvector/share/global"
)

const (
	RTMGRP_LINK        uint32 = 0x1
	RTMGRP_IPV4_IFADDR uint32 = 0x10
	RTMGRP_IPV6_IFADDR uint32 = 0x100
)

const intfMonitorSocketSize uint = 1024 * 5

type netlinkIntfMonitor struct {
	ns *netlink.NetlinkSocket
}

type addrMsg struct {
	family    uint8 /* Address type */
	prefixlen uint8 /* Prefixlength of address */
	flags     uint8 /* Address flags */
	scope     uint8 /* Address scope */
	index     int32 /* Interface index */
}

type rtMsg struct {
	family  uint8 /* Address family of route */
	dst_len uint8 /* Length of destination */
	src_len uint8 /* Length of source */
	tos     uint8 /* TOS filter */

	table    uint8 /* Routing table ID */
	protocol uint8 /* Routing protocol */
	scope    uint8
	rtype    uint8
	flags    uint32
}

func cbOpenIntfSockets(param interface{}) {
	ns, err := netlink.NewNetlinkSocket(syscall.NETLINK_ROUTE, intfMonitorSocketSize,
		syscall.RTNLGRP_IPV4_IFADDR, syscall.RTNLGRP_IPV4_ROUTE)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Open netlink socket fail")
		return
	}
	nsp := param.(**netlink.NetlinkSocket)
	*nsp = ns
}

func (p *Probe) openIntfMonitor(pid int) intfMonitorInterface {
	var ns *netlink.NetlinkSocket
	if err := global.SYS.CallNetNamespaceFunc(pid, cbOpenIntfSockets, &ns); err != nil {
		return nil
	}
	if ns == nil {
		return nil
	}
	return &netlinkIntfMonitor{ns: ns}
}

func (m *netlinkIntfMonitor) WaitAddrChange(intval *syscall.Timeval) (bool, error) {
	for {
		// select() changes timer value, so reinitiate every time.
		tv := *intval
		if msgs, err := m.ns.EPollReceive(&tv); err != nil {
			if err == syscall.EINTR || err == syscall.EAGAIN { // interrupted by a signal, return, make a yield
				// log.WithFields(log.Fields{"error": err}).Debug("Receive signal")
				return false, nil
			}
			log.WithFields(log.Fields{"error": err}).Debug("Receive error")
			return false, err
		} else if len(msgs) == 0 {
			// timeout
			return false, nil
		} else {
			var chg bool
			for _, msg := range msgs {
				switch msg.Header.Type {
				case syscall.RTM_NEWADDR:
					m := (*addrMsg)(unsafe.Pointer(&msg.Data[0]))
					log.WithFields(log.Fields{"family": m.family, "index": m.index}).Debug("New address")
					chg = true
				case syscall.RTM_NEWROUTE:
					m := (*rtMsg)(unsafe.Pointer(&msg.Data[0]))
					log.WithFields(log.Fields{"family": m.family, "table": m.table}).Debug("New route")
					chg = true
				default:
					// log.WithFields(log.Fields{"type": msg.Header.Type}).Debug()
					// ignore other msgs such as DELADDR and DELROUTE and select again
				}
			}
			if chg {
				return true, nil
			}
		}
	}
}

// obsolete
// use netlink.LinkUpdate and netlink.AddrUpdate
func (m *netlinkIntfMonitor) WaitHostAddrChange(intval *syscall.Timeval) (bool, error) {
	for {
		// select() changes timer value, so reinitiate every time.
		tv := *intval
		if msgs, err := m.ns.EPollReceive(&tv); err != nil {
			if err == syscall.EINTR || err == syscall.EAGAIN { // interrupted by a signal, return, make a yield
				// log.WithFields(log.Fields{"error": err}).Debug("Receive signal")
				return false, nil
			}
			log.WithFields(log.Fields{"error": err}).Debug("Receive error")
			return false, err
		} else if len(msgs) == 0 {
			// timeout
			return false, nil
		} else {
			var chg bool
			for _, msg := range msgs {
				switch msg.Header.Type {
				case syscall.RTM_NEWADDR:
					m := (*addrMsg)(unsafe.Pointer(&msg.Data[0]))
					log.WithFields(log.Fields{"family": m.family, "index": m.index}).Debug("New address")
					chg = true
				default:
					// log.WithFields(log.Fields{"type": msg.Header.Type}).Debug()
					// ignore other msgs such as NEWROUTE, DELADDR and DELROUTE and select again
				}
			}
			if chg {
				return true, nil
			}
		}
	}
}

func (m *netlinkIntfMonitor) Close() {
	m.ns.Close()
}

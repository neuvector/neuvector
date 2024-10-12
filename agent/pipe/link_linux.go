package pipe

import (
	"fmt"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

var native = nl.NativeEndian()

func ensureIndex(link *netlink.LinkAttrs) {
	if link != nil && link.Index == 0 {
		newlink, _ := netlink.LinkByName(link.Name)
		if newlink != nil {
			link.Index = newlink.Attrs().Index
		}
	}
}

// LinkAdd adds a new link device. The type and features of the device
// are taken fromt the parameters in the link object.
// Equivalent to: `ip link add $link`
func vethAdd(link netlink.Link) error {
	// TODO: set mtu and hardware address
	// TODO: support extra data for macvlan
	base := link.Attrs()

	if base.Name == "" {
		return fmt.Errorf("LinkAttrs.Name cannot be empty!")
	}

	req := nl.NewNetlinkRequest(syscall.RTM_NEWLINK, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL|syscall.NLM_F_ACK)

	msg := nl.NewIfInfomsg(syscall.AF_UNSPEC)
	msg.Index = int32(base.Index)
	// TODO: make it shorter
	if base.Flags&net.FlagUp != 0 {
		msg.Change = syscall.IFF_UP
		msg.Flags = syscall.IFF_UP
	}
	if base.Flags&net.FlagBroadcast != 0 {
		msg.Change |= syscall.IFF_BROADCAST
		msg.Flags |= syscall.IFF_BROADCAST
	}
	if base.Flags&net.FlagLoopback != 0 {
		msg.Change |= syscall.IFF_LOOPBACK
		msg.Flags |= syscall.IFF_LOOPBACK
	}
	if base.Flags&net.FlagPointToPoint != 0 {
		msg.Change |= syscall.IFF_POINTOPOINT
		msg.Flags |= syscall.IFF_POINTOPOINT
	}
	if base.Flags&net.FlagMulticast != 0 {
		msg.Change |= syscall.IFF_MULTICAST
		msg.Flags |= syscall.IFF_MULTICAST
	}
	req.AddData(msg)

	if base.ParentIndex != 0 {
		b := make([]byte, 4)
		native.PutUint32(b, uint32(base.ParentIndex))
		data := nl.NewRtAttr(syscall.IFLA_LINK, b)
		req.AddData(data)
	} else if link.Type() == "ipvlan" {
		return fmt.Errorf("Can't create ipvlan link without ParentIndex")
	}

	nameData := nl.NewRtAttr(syscall.IFLA_IFNAME, nl.ZeroTerminated(base.Name))
	req.AddData(nameData)

	if base.MTU > 0 {
		mtu := nl.NewRtAttr(syscall.IFLA_MTU, nl.Uint32Attr(uint32(base.MTU)))
		req.AddData(mtu)
	}

	if base.TxQLen >= 0 {
		qlen := nl.NewRtAttr(syscall.IFLA_TXQLEN, nl.Uint32Attr(uint32(base.TxQLen)))
		req.AddData(qlen)
	}

	if base.Namespace != nil {
		var attr *nl.RtAttr
		switch base.Namespace.(type) {
		case netlink.NsPid:
			val := nl.Uint32Attr(uint32(base.Namespace.(netlink.NsPid)))
			attr = nl.NewRtAttr(syscall.IFLA_NET_NS_PID, val)
		case netlink.NsFd:
			val := nl.Uint32Attr(uint32(base.Namespace.(netlink.NsFd)))
			attr = nl.NewRtAttr(unix.IFLA_NET_NS_FD, val)
		}

		req.AddData(attr)
	}

	linkInfo := nl.NewRtAttr(syscall.IFLA_LINKINFO, nil)
	linkInfo.AddRtAttr(nl.IFLA_INFO_KIND, nl.NonZeroTerminated(link.Type()))
	if veth, ok := link.(*linkVeth); ok {
		data := linkInfo.AddRtAttr(nl.IFLA_INFO_DATA, nil)
		peer := data.AddRtAttr(nl.VETH_INFO_PEER, nil)
		peerMsg := nl.NewIfInfomsgChild(peer, syscall.AF_UNSPEC)
		peerMsg.Index = int32(veth.PeerIndex)
		peer.AddRtAttr(syscall.IFLA_IFNAME, nl.ZeroTerminated(veth.PeerName))
		if base.TxQLen >= 0 {
			peer.AddRtAttr(syscall.IFLA_TXQLEN, nl.Uint32Attr(uint32(base.TxQLen)))
		}
		if base.MTU > 0 {
			peer.AddRtAttr(syscall.IFLA_MTU, nl.Uint32Attr(uint32(base.MTU)))
		}
	}

	req.AddData(linkInfo)

	_, err := req.Execute(syscall.NETLINK_ROUTE, 0)
	if err != nil {
		return err
	}

	ensureIndex(base)

	// can't set master during create, so set it afterwards
	if base.MasterIndex != 0 {
		// TODO: verify MasterIndex is actually a bridge?
		return netlink.LinkSetMasterByIndex(link, base.MasterIndex)
	}
	return nil
}

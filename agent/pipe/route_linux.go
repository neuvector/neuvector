package pipe

import (
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

func getRouteList() ([]netlink.Route, error) {
	family := netlink.FAMILY_V4
	routeFilter := &netlink.Route{
		Type: syscall.RTN_UNICAST,
	}
	return getRouteListFiltered(family, routeFilter, netlink.RT_FILTER_TYPE)
}

func getRouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error) {
	req := nl.NewNetlinkRequest(syscall.RTM_GETROUTE, syscall.NLM_F_DUMP)
	infmsg := nl.NewIfInfomsg(family)
	req.AddData(infmsg)

	msgs, err := req.Execute(syscall.NETLINK_ROUTE, syscall.RTM_NEWROUTE)
	if err != nil {
		return nil, err
	}

	var res []netlink.Route
	for _, m := range msgs {
		msg := nl.DeserializeRtMsg(m)
		if msg.Flags&syscall.RTM_F_CLONED != 0 {
			// Ignore cloned routes
			continue
		}
		route, err := deserializeRoute(m)
		if err != nil {
			return nil, err
		}

		if filter != nil {
			switch {
			case filterMask&netlink.RT_FILTER_TABLE != 0 && route.Table != filter.Table:
				continue
			case filterMask&netlink.RT_FILTER_PROTOCOL != 0 && route.Protocol != filter.Protocol:
				continue
			case filterMask&netlink.RT_FILTER_SCOPE != 0 && route.Scope != filter.Scope:
				continue
			case filterMask&netlink.RT_FILTER_TYPE != 0 && route.Type != filter.Type:
				continue
			case filterMask&netlink.RT_FILTER_TOS != 0 && route.Tos != filter.Tos:
				continue
			case filterMask&netlink.RT_FILTER_OIF != 0 && route.LinkIndex != filter.LinkIndex:
				continue
			case filterMask&netlink.RT_FILTER_IIF != 0 && route.ILinkIndex != filter.ILinkIndex:
				continue
			case filterMask&netlink.RT_FILTER_GW != 0 && !route.Gw.Equal(filter.Gw):
				continue
			case filterMask&netlink.RT_FILTER_SRC != 0 && !route.Src.Equal(filter.Src):
				continue
			case filterMask&netlink.RT_FILTER_DST != 0 && filter.Dst != nil:
				if route.Dst == nil {
					continue
				}
				aMaskLen, aMaskBits := route.Dst.Mask.Size()
				bMaskLen, bMaskBits := filter.Dst.Mask.Size()
				if !(route.Dst.IP.Equal(filter.Dst.IP) && aMaskLen == bMaskLen && aMaskBits == bMaskBits) {
					continue
				}
			}
		}
		res = append(res, route)
	}
	return res, nil
}

// deserializeRoute decodes a binary netlink message into a Route struct
func deserializeRoute(m []byte) (netlink.Route, error) {
	msg := nl.DeserializeRtMsg(m)
	attrs, err := nl.ParseRouteAttr(m[msg.Len():])
	if err != nil {
		return netlink.Route{}, err
	}
	route := netlink.Route{
		Scope:    netlink.Scope(msg.Scope),
		Protocol: int(msg.Protocol),
		Table:    int(msg.Table),
		Type:     int(msg.Type),
		Tos:      int(msg.Tos),
		Flags:    int(msg.Flags),
	}

	native := nl.NativeEndian()
	for _, attr := range attrs {
		switch attr.Attr.Type {
		case syscall.RTA_GATEWAY:
			route.Gw = net.IP(attr.Value)
		case syscall.RTA_PREFSRC:
			route.Src = net.IP(attr.Value)
		case syscall.RTA_DST:
			route.Dst = &net.IPNet{
				IP:   attr.Value,
				Mask: net.CIDRMask(int(msg.Dst_len), 8*len(attr.Value)),
			}
		case syscall.RTA_OIF:
			route.LinkIndex = int(native.Uint32(attr.Value[0:4]))
		case syscall.RTA_IIF:
			route.ILinkIndex = int(native.Uint32(attr.Value[0:4]))
		case syscall.RTA_PRIORITY:
			route.Priority = int(native.Uint32(attr.Value[0:4]))
		case syscall.RTA_TABLE:
			route.Table = int(native.Uint32(attr.Value[0:4]))
		}
	}
	return route, nil
}

func compareIPNet(in1 *net.IPNet, in2 *net.IPNet) bool {
	if in1 == nil && in2 == nil {
		return true
	}
	if in1 != nil && in2 != nil && in1.String() == in2.String() {
		return true
	}
	return false
}

func compareRouteIgnoreIdx(r1 netlink.Route, r2 netlink.Route) bool {
	return compareIPNet(r1.Dst, r2.Dst) &&
		r1.Src.Equal(r2.Src) &&
		r1.Gw.Equal(r2.Gw) &&
		r1.Type == r2.Type &&
		r1.Scope == r2.Scope &&
		r1.Protocol == r2.Protocol &&
		r1.Priority == r2.Priority &&
		r1.Table == r2.Table &&
		r1.Tos == r2.Tos
}

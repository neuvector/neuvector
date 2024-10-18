package sidekick

import (
	"errors"
	"net"
	"syscall"

	"github.com/neuvector/neuvector/share/utils"
	"github.com/vishvananda/netlink"
)

type NetAddr struct {
	IPNet net.IPNet `json:"ipnet"`
	Scope int       `json:"scope"`
}

type NetIface struct {
	Name  string    `json:"name"`
	Type  string    `json:"type"`
	Mtu   int       `json:"mtu"`
	Flags net.Flags `json:"flags"`
	Addrs []NetAddr `json:"addrs"`
}

type NetLinkAttrs struct {
	Index     int    `json:"index"`
	Name      string `json:"name"`
	OperState bool   `json:"OperState"`
}

func GetGlobalAddrs() map[string]NetIface {
	ifaces := make(map[string]NetIface)

	links, err := netlink.LinkList()
	if err != nil {
		return ifaces
	}

	for _, link := range links {
		if link == nil || link.Attrs() == nil {
			continue
		}

		attrs := link.Attrs()

		iface := NetIface{
			Name:  attrs.Name,
			Type:  link.Type(),
			Mtu:   attrs.MTU,
			Flags: attrs.Flags,
			Addrs: make([]NetAddr, 0),
		}

		//log.WithFields(log.Fields{"link": attrs.Name, "type": link.Type()}).Debug("")

		addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			// Don't check addr.flags, such as PERMANENT, interface flags on vagrant VM maybe different
			if addr.Scope == syscall.RT_SCOPE_UNIVERSE || (addr.Scope == syscall.RT_SCOPE_LINK && utils.IsIPv4(addr.IPNet.IP)) {
				iface.Addrs = append(iface.Addrs, NetAddr{IPNet: *addr.IPNet, Scope: addr.Scope})
				//log.WithFields(log.Fields{"link": attrs.Name, "ip": addr.IP}).Debug("Add")
			}
		}

		ifaces[attrs.Name] = iface
	}

	return ifaces
}

// Return route's link name and ip
func GetRouteIfaceAddr(ip net.IP) (string, *net.IPNet, error) {
	routes, err := netlink.RouteGet(ip)
	if err != nil {
		return "", nil, err
	}
	if len(routes) <= 0 {
		return "", nil, errors.New("no route to address")
	}

	link, err := netlink.LinkByIndex(routes[0].LinkIndex)
	if err != nil {
		return "", nil, err
	}
	if link == nil || link.Attrs() == nil {
		return "", nil, errors.New("no link to address")
	}
	if link.Attrs().Flags&net.FlagLoopback != 0 {
		// If route is resolved to loopback interface, then it's a local IP
		return link.Attrs().Name, &net.IPNet{IP: ip, Mask: net.CIDRMask(0, 128)}, nil
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return "", nil, err
	}
	if len(addrs) <= 0 {
		return "", nil, errors.New("no IP address assigned")
	}

	return link.Attrs().Name, addrs[0].IPNet, nil
}

func GetNetLinkAttrs() map[string]NetLinkAttrs {
	linkAttrs := make(map[string]NetLinkAttrs)

	links, err := netlink.LinkList()
	if err != nil {
		return linkAttrs
	}

	for _, link := range links {
		if link == nil || link.Attrs() == nil {
			continue
		}

		attrs := link.Attrs()

		linkAttr := NetLinkAttrs{
			Index:     attrs.Index,
			Name:      attrs.Name,
			OperState: attrs.OperState == netlink.OperUp,
		}

		linkAttrs[attrs.Name] = linkAttr
	}

	return linkAttrs
}

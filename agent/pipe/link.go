package pipe

import (
	"github.com/vishvananda/netlink"
)

// Veth devices must specify PeerName on create
type linkVeth struct {
	netlink.LinkAttrs
	PeerName  string // veth on create only
	PeerIndex int    // veth on create only
}

func (veth *linkVeth) Attrs() *netlink.LinkAttrs {
	return &veth.LinkAttrs
}

func (veth *linkVeth) Type() string {
	return "veth"
}

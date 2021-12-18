package pipe

import (
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func getPermanentNeighList(links []netlink.Link) ([]netlink.Neigh, error) {
	neighs := make([]netlink.Neigh, 0)
	for _, link := range links {
		attrs := link.Attrs()
		nlist, err := netlink.NeighList(attrs.Index, netlink.FAMILY_V4)
		if err != nil {
			log.WithFields(log.Fields{"link": attrs.Name, "error": err}).Error("Error in reading neighs")
			continue
		}

		for _, n := range nlist {
			if (n.State & netlink.NUD_PERMANENT) > 0 {
				neighs = append(neighs, n)
			}
		}
	}

	return neighs, nil
}

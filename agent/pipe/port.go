package pipe

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/codeskyblue/go-sh"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/utils"
)

func shell(cmd string) ([]byte, error) {
	// log.Printf("shell: %v\n", cmd)
	c := strings.Split(cmd, " ")
	return sh.Command(c[0], c[1:]).Output()
}

func shellCombined(cmd string) ([]byte, error) {
	// log.Printf("shell: %v\n", cmd)
	c := strings.Split(cmd, " ")
	return sh.Command(c[0], c[1:]).CombinedOutput()
}

func nap() {
	time.Sleep(time.Second / 4)
}

// --
const (
	CNET_DEFAULT = "default"
	CNET_MACVLAN = "macvlan"
)

const (
	PIPE_TC   = "tc"
	PIPE_OVS  = "ovs"
	PIPE_NOTC = "no_tc"
	PIPE_CLM  = "clm"
)

var ErrNoDefaultRoute = errors.New("No default route")

type InterceptPair struct {
	index  int
	Port   string
	Peer   string
	inPort string
	exPort string
	tap    bool
	MAC    net.HardwareAddr
	BCMAC  net.HardwareAddr
	UCMAC  net.HardwareAddr
	Addrs  []share.CLUSIPAddr
	Vxlan  bool
}

func (m *InterceptPair) InPort() string {
	return m.inPort
}

func (m *InterceptPair) ExPort() string {
	return m.exPort
}

type pipeInterface interface {
	Connect(jumboframe bool)
	Cleanup()
	AttachPortPair(pair *InterceptPair) (net.HardwareAddr, net.HardwareAddr)
	DetachPortPair(pair *InterceptPair)
	TapPortPair(pid int, pair *InterceptPair)
	FwdPortPair(pid int, pair *InterceptPair)
	ResetPortPair(pid int, pair *InterceptPair)
	GetPortPairRules(pair *InterceptPair) (string, string, string)
}

var piper pipeInterface

type pipeConfig struct {
	workingPid int
	cnet_type  string
}

var cfg pipeConfig

const inPortIndexBase int = 10000000
const localPortIndexBase int = 100
const nvVthPortName string = "vth-neuv"
const nvVbrPortName string = "vbr-neuv"
const exPortPrefix string = "vex"
const inPortPrefix string = "vin"

func waitLinkReady(port string) (netlink.Link, uint) {
	// wait max. 8s
	for i := 0; i < 32; i++ {
		if link, err := netlink.LinkByName(port); err == nil {
			return link, uint(link.Attrs().Index)
		} else {
			log.WithFields(log.Fields{"err": err, "port": port}).Error("Cannot find port")
		}
		nap()
	}
	return nil, 0
}

func createNVPorts(jumboframe bool) {
	// Create port with large ifindex so it won't be in the same range of container ports
	link, _ := netlink.LinkByName(nvVbrPortName)
	if link == nil {
		veth := &linkVeth{
			LinkAttrs: netlink.LinkAttrs{
				Name:  nvVbrPortName,
				Index: inPortIndexBase,
			},
			PeerName:  nvVthPortName,
			PeerIndex: inPortIndexBase + 1,
		}
		if jumboframe {
			veth.LinkAttrs.MTU = share.NV_VBR_PORT_MTU_JUMBO
		} else {
			veth.LinkAttrs.MTU = share.NV_VBR_PORT_MTU
		}
		if err := vethAdd(veth); err != nil {
			log.WithFields(log.Fields{"error": err, "veth": *veth}).Error("Error in creating veth pair")
		}
		nap()
	}
	link, _ = waitLinkReady(nvVbrPortName)
	if link != nil {
		if dbgError := netlink.LinkSetUp(link); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
	}
	link, _ = waitLinkReady(nvVthPortName)
	if link != nil {
		if dbgError := netlink.LinkSetUp(link); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
	}
}

func getIntcpPortNames(pid int, port string) (exPort, inPort string) {
	suffix := fmt.Sprintf("%x-%s", pid, port)
	return exPortPrefix + suffix, inPortPrefix + suffix
}

// func disableOffload(port string) {
func DisableOffload(port string) {
	log.WithFields(log.Fields{"port": port}).Debug("")
	if _, dbgError := shell(fmt.Sprintf("ethtool -K %v tx off", port)); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	nap()
	if _, dbgError := shell(fmt.Sprintf("ethtool -K %v rx off", port)); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	nap()
}

func getVethPeer(port string) int {
	out, err := sh.Command("ethtool", "-S", port).Command("grep", "peer_ifindex:").Output()
	if err != nil || len(out) == 0 {
		return 0
	}

	id, err := strconv.Atoi(strings.TrimSpace(strings.Split(string(out[:]), ":")[1]))
	if err != nil {
		return 0
	}

	return id
}

// 1. Rename, remove IP and MAC of original port, link
// 1. Create a veth pair, local and peer
// 2. Switch IP and MAC address between link and local port
// 3. Move link and peer to service container
func pullContainerPort(
	link netlink.Link, addrs []netlink.Addr, pid, dstNs int, localPortIndex, inPortIndex int,
) (int, error) {
	var err error

	attrs := link.Attrs()
	exPortName, inPortName := getIntcpPortNames(pid, attrs.Name)

	log.WithFields(log.Fields{"port": attrs.Name, "index": attrs.Index, "from": pid}).Debug("")

	defer func() {
		if err != nil {
			if dbgError := netlink.LinkSetName(link, attrs.Name); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
			if dbgError := netlink.LinkSetHardwareAddr(link, attrs.HardwareAddr); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
			if dbgError := netlink.LinkSetUp(link); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
		}
	}()

	// Down the link
	if err = netlink.LinkSetDown(link); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in disabling port")
		return 0, err
	}
	// Change link name to exPortName.
	if err = netlink.LinkSetName(link, exPortName); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in changing name")
		return 0, err
	}
	// Get link again as name is changed.
	if link1, err := netlink.LinkByName(exPortName); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Cannot find port")
		return 0, err
	} else {
		link = link1
	}
	// Remove IP addresses
	for _, addr := range addrs {
		if dbgError := netlink.AddrDel(link, &addr); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
	}
	// Temp. set MAC address
	tmp, _ := net.ParseMAC("00:01:02:03:04:05")
	if err = netlink.LinkSetHardwareAddr(link, tmp); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in changing MAC")
		return 0, err
	}

	log.WithFields(log.Fields{"inPort": inPortName}).Debug("Create internal pair")

	// Create a new veth pair: one end is the original port name, the other is inPortName
	veth := &linkVeth{
		LinkAttrs: netlink.LinkAttrs{
			Name:   attrs.Name,
			TxQLen: attrs.TxQLen,
			MTU:    attrs.MTU,
			Index:  localPortIndex,
		},
		PeerName:  inPortName,
		PeerIndex: inPortIndex,
	}
	if err = vethAdd(veth); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in creating veth pair")
		return 0, err
	}
	defer func() {
		if err != nil {
			if dbgError := netlink.LinkDel(veth); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
		}
	}()

	log.WithFields(log.Fields{"port": attrs.Name}).Debug("Setting up local port")

	// Get the local link of the veth pair
	var local netlink.Link
	var localMAC net.HardwareAddr
	if local, err = netlink.LinkByName(attrs.Name); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Cannot find port")
		return 0, err
	}
	if err = netlink.LinkSetDown(local); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in disabling port")
		return 0, err
	}

	if cfg.cnet_type == CNET_MACVLAN {
		// Duplicate the local mac, for Container network  like macvlan, mac in host need persistent, so same mac on vex and container eth0
		localMAC = attrs.HardwareAddr
	} else {
		localMAC = local.Attrs().HardwareAddr
	}

	if err = netlink.LinkSetHardwareAddr(local, attrs.HardwareAddr); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in setting MAC")
		return 0, err
	}
	// TODO: For some reason, there always is an extra IPv6 address that cannot be removed,
	//       the external port _sometimes_ also has an extra IPv6 address left.
	// Get all addresses of the local link
	var localAddrs []netlink.Addr
	if localAddrs, err = netlink.AddrList(local, netlink.FAMILY_ALL); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in getting address")
		return 0, err
	}
	for _, addr := range localAddrs {
		log.WithFields(log.Fields{"addr": addr}).Debug("Delete address")
		if dbgError := netlink.AddrDel(local, &addr); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
	}
	for _, addr := range addrs {
		log.WithFields(log.Fields{"addr": addr}).Debug("Add address")
		if dbgError := netlink.AddrAdd(local, &addr); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
	}
	// Set local link up
	if err = netlink.LinkSetUp(local); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in enabling port")
		return 0, err
	}
	// Set customer container intf seg/chksum off
	DisableOffload(attrs.Name)
	log.WithFields(log.Fields{"port": inPortName}).Debug("Setting up inPort")

	// Get the peer link
	var peer netlink.Link
	if peer, err = netlink.LinkByName(inPortName); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Cannot find port")
		return 0, err
	}
	if err = netlink.LinkSetDown(peer); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in disabling port")
		return 0, err
	}
	// Move the peer to the service container
	if err = netlink.LinkSetNsFd(peer, dstNs); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in moving namespace")
		return 0, err
	}

	log.WithFields(log.Fields{"port": exPortName}).Debug("Setting up exPort")

	// Set the original port MAC to local port MAC
	if err = netlink.LinkSetHardwareAddr(link, localMAC); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in changing MAC")
		return 0, err
	}
	// Move the original port to service container namespace
	if err = netlink.LinkSetNsFd(link, dstNs); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in moving namespace")
		return 0, err
	}

	return local.Attrs().Index, nil
}

func portExists(dstLinks []netlink.Link, portName string) bool {
	for _, link := range dstLinks {
		attrs := link.Attrs()
		if attrs.Name == portName {
			return true
		}
	}
	return false
}

/* removed by golint
func hasInternalVethPair(name string, links []netlink.Link) bool {
	idx := getVethPeer(name)
	if idx == 0 {
		return false
	}

	for _, link := range links {
		if idx == link.Attrs().Index {
			log.WithFields(log.Fields{
				"port": name, "index": idx, "peer": link.Attrs().Index,
			}).Debug("Internal veth pair")
			return true
		}
	}

	return false
}
*/

func getMaxIfindex(links []netlink.Link) int {
	var max int
	var attrs *netlink.LinkAttrs
	for _, link := range links {
		attrs = link.Attrs()
		if attrs.Index > max {
			max = attrs.Index
		}
	}
	return max
}

func getIfindexSet(links []netlink.Link) utils.Set {
	s := utils.NewSet()
	for _, link := range links {
		s.Add(link.Attrs().Index)
	}
	return s
}

func getAvailableInPortIndex(ifIndexSet utils.Set) int {
	var idx int
	for idx = inPortIndexBase; ifIndexSet.Contains(idx); idx++ {
	}
	return idx
}

func readLinkIPRoute() ([]netlink.Link, map[netlink.Link][]netlink.Addr, []netlink.Route, []netlink.Neigh, error) {
	var err error
	var hasIPv4, hasDefaultRoute bool
	var linkMap map[netlink.Link][]netlink.Addr
	var links []netlink.Link
	var routes []netlink.Route

	// Read containers interface
	links, err = netlink.LinkList()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in getting ports")
		return nil, nil, nil, nil, err
	}

	linkMap = make(map[netlink.Link][]netlink.Addr)
	for _, link := range links {
		log.WithFields(log.Fields{"link": link}).Debug("")
		attrs := link.Attrs()
		if len(attrs.HardwareAddr) == 0 {
			continue
		}

		if addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL); err == nil {
			// Skip IPv6 address
			ipv4s := make([]netlink.Addr, 0)
			for _, addr := range addrs {
				if utils.IsIPv4(addr.IPNet.IP) {
					ipv4s = append(ipv4s, addr)
					hasIPv4 = true
				}
			}
			// Only ports with ipv4 addresses are added to the map
			if len(ipv4s) > 0 {
				linkMap[link] = ipv4s
			}
		}
	}

	if !hasIPv4 {
		log.Debug("No IPv4 address")
		return nil, nil, nil, nil, fmt.Errorf("No IPv4 address")
	}

	// Read all routes
	routes, err = getRouteList()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in reading routes")
		return nil, nil, nil, nil, err
	}

	for _, route := range routes {
		log.WithFields(log.Fields{"route": route}).Debug("")
		if route.Dst == nil || route.Dst.IP.Equal(net.IPv4zero) {
			hasDefaultRoute = true
			//break
		}
	}

	if !hasDefaultRoute {
		log.Debug("No IPv4 default route")
		return nil, nil, nil, nil, ErrNoDefaultRoute
	}

	// Read all neigh
	neighs, _ := getPermanentNeighList(links)
	for _, neigh := range neighs {
		log.WithFields(log.Fields{"neigh": neigh}).Debug("")
	}

	return links, linkMap, routes, neighs, nil
}

func recoverNeighs(neighs []netlink.Neigh, portIdxMap map[int]int) error {
	var err error
	for _, neigh := range neighs {
		if idx, ok := portIdxMap[neigh.LinkIndex]; ok {
			neigh.LinkIndex = idx
			if err = netlink.NeighSet(&neigh); err != nil {
				log.WithFields(log.Fields{"neigh": neigh, "error": err}).Error("Error in set neigh")
			}
		}
	}
	return nil
}

func recoverRoutes(routes []netlink.Route, portIdxMap map[int]int) error {
	routesAfter, err := getRouteList()
	if err == nil {
		for _, r1 := range routesAfter {
			var exist bool
			var i int
			var r2 netlink.Route
			for i, r2 = range routes {
				if compareRouteIgnoreIdx(r1, r2) {
					exist = true
					break
				}
			}
			if exist {
				idx1 := r1.LinkIndex
				idx2 := r2.LinkIndex
				if idx1 == idx2 {
					log.WithFields(log.Fields{"old": r2}).Debug("route unchanged")
				} else if id, ok := portIdxMap[idx2]; ok {
					if id == idx1 {
						log.WithFields(log.Fields{"new": r1, "old": r2}).Debug("route already updated")
					} else {
						log.WithFields(log.Fields{"new": r1, "old": r2}).Debug("route exists with different idx")
					}
				} else {
					log.WithFields(log.Fields{"new": r1, "old": r2}).Debug("route idx changed!")
				}
				routes = append(routes[0:i], routes[i+1:]...)
			} else {
				log.WithFields(log.Fields{"r1": r1}).Debug("new route, keep")
			}
		}
	} else {
		log.WithFields(log.Fields{"err": err}).Error("Error to get routes")
	}

	var retry int = 0
	for len(routes) > 0 && retry < 3 {
		var needNap bool = false
		failed := make([]netlink.Route, 0)
		for _, route := range routes {
			if retry == 0 {
				// Replace the port index in route entries
				if id, ok := portIdxMap[route.LinkIndex]; ok {
					route.LinkIndex = id
				}
			}

			log.WithFields(log.Fields{"route": route, "try": retry}).Debug("Add route")
			if err = netlink.RouteAdd(&route); err != nil {
				log.WithFields(log.Fields{"route": route, "error": err, "try": retry}).Debug("Add route error")
				failed = append(failed, route)
				if err.Error() == "invalid argument" {
					needNap = true
				}
			}
		}
		routes = failed
		retry++
		if needNap {
			nap()
		}
	}
	return nil
}

// It's already in container namespace
// 1. ..
// 2. Move the data port to the service container;
// 3. Create a port pair and move the peer to the service container;
func pullAllContainerPorts(
	pid, dstNs int, existPairs map[string]*InterceptPair, exLinks []netlink.Link,
) ([]*InterceptPair, bool, error) {
	log.WithFields(log.Fields{"pid": pid}).Debug("")

	links, linkMap, routes, neighs, err := readLinkIPRoute()
	if err != nil {
		return nil, false, err
	}

	intcpPairs := make([]*InterceptPair, 0)
	// Map the original port's index to injected port's index in order to rebuild route
	var portIdxMap map[int]int = make(map[int]int)
	var pulled bool = false

	// We want to create veth pair with specified ifindex. Get the max existing ifindex in the container,
	// this will be the ifindex of ports stay in the container. Make sure they are not in the same range of
	// ifindex of original veth pair.
	localIfindex := getMaxIfindex(links) + localPortIndexBase
	agentIfindexSet := getIfindexSet(exLinks)

	// Keep link order
	var hasVlan bool
	for _, link := range links {
		// Link is not in the map is probably because it has no IPv4 address.
		addrs, ok := linkMap[link]
		if !ok {
			continue
		}

		attrs := link.Attrs()

		// Only support a single vlan per container for now, and assume the link order is consistent
		// so that the same vlan interface is kept for repeated calls
		if link.Type() == "vlan" {
			if !hasVlan {
				hasVlan = true
			} else {
				log.WithFields(log.Fields{"link": link}).Error("Skip as only one vlan is allowed")
				continue
			}
		}
		var pair InterceptPair
		existPair := existPairs[attrs.Name]

		exPortName, inPortName := getIntcpPortNames(pid, attrs.Name)
		if portExists(exLinks, exPortName) || portExists(exLinks, inPortName) {
			if existPair == nil {
				// Ports exist so it's already pulled. Maybe we are recovering from a crash.
				// Index here is not the original port index, but it's not really used.
				// TODO: recover peer name
				pair = InterceptPair{
					Port: attrs.Name, index: attrs.Index,
					inPort: inPortName, exPort: exPortName,
					MAC: attrs.HardwareAddr, tap: false,
				}
			} else {
				// The port has been pulled, only need to update addresses
				log.WithFields(log.Fields{"port": attrs.Name, "mac": attrs.HardwareAddr, "pair": existPair}).Debug("Already pulled")

				pair = *existPair
				pair.inPort = inPortName
				pair.exPort = exPortName
				pair.MAC = attrs.HardwareAddr // mac can change
				pair.Addrs = nil
				pair.tap = false
			}
		} else if existPair != nil && !existPair.tap {
			// Ports are pulled but not able to be found, something is very wrong.
			// NOTE: pair can exist if we are changing policy mode
			log.WithFields(log.Fields{"port": attrs.Name, "pair": existPair}).Error("Pulled port cannot be found")
			pair = *existPair
			pair.Addrs = nil
		} else {
			log.WithFields(log.Fields{"port": attrs.Name, "mac": attrs.HardwareAddr}).Debug("Newly pulled")

			// The only reason we want to control index of newly created pair (container <-> enforcer) is,
			// in OpenShift, when a container is stopped, OpenShift ovs plugin does following things,
			// 1. enter container network namespace;
			// 2. call 'ethtool -S port' to get peer ifindex, which is the port in the host network namespace;
			// 3. remove the peer port from ovs switch and openflow rules.
			//
			// If we don't specify index when creating the pair, either the plugin cannot locate the peer
			// in the host, or it finds a wrong port. So, when pulling the port, we try to assign
			// inPort's index to be the same as the peer port in the host network namespace. This way,
			// when the container stops, the OpenShift plugin will get the same ifindex and locate
			// the original peer port.
			//
			// There is a possible issues here, when the port in the container is pulled as exPort,
			// it will try to retain its original index, but if a port of the same index already
			// exists, its index will change and we cannot control what index it will be. Will it change
			// to an index that will conflict with the future inPort of other ports in the same container
			// or ports of another container?
			//
			// If veth pair is created in the host network namespace when a container is created,
			// at the time the inPort and exPort are moved into enforcer's network namespace, they
			// should have the same index as the pair is created at the first place. There shouldn't
			// be conflict. However in OpenShift (and calico at least), container the veth pair
			// is created in the container's namespace, so their can be conflict when ports are
			// pulled. We allocate a large number for inPort in that case to prevent the network
			// plugin from removing other ports, and we call ovs to cleanup port and flows in ovs
			// bridge.

			// --
			// hostPort might be used when the container is stopped. We may not be able to get
			// the port name on the host at that time, so read it here.
			var hostPort string
			peerIndex := getVethPeer(attrs.Name)
			dbgError := global.SYS.CallNetNamespaceFuncWithoutLock(1, func(params interface{}) {
				if peerLink, err := netlink.LinkByIndex(peerIndex); err == nil {
					hostPort = peerLink.Attrs().Name
				}
			}, nil)
			if dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
			// If the index conflicts with the port in the enforcer, assign a big index.
			if agentIfindexSet.Contains(peerIndex) {
				peerIndex = getAvailableInPortIndex(agentIfindexSet)
				log.WithFields(log.Fields{"index": peerIndex}).Debug("inPort index conflict")
			}

			// Make sure ifindex of the pair to be created are not same. Openshift has only one port in container,
			// so it won't conflict with other ports. Other platforms don't care about ifindex.
			if localIfindex == peerIndex {
				localIfindex++
			}

			ctnrPortIdx, err := pullContainerPort(link, addrs, pid, dstNs, localIfindex, peerIndex)
			if err != nil {
				continue
			}

			// ctnrPortIdx should be same as localIfindex
			portIdxMap[attrs.Index] = ctnrPortIdx
			agentIfindexSet.Add(peerIndex)
			localIfindex++
			pulled = true

			pair = InterceptPair{
				Port: attrs.Name, index: attrs.Index, Peer: hostPort,
				inPort: inPortName, exPort: exPortName,
				MAC: attrs.HardwareAddr, tap: false,
			}
		}

		// Record addresses
		pair.Addrs = make([]share.CLUSIPAddr, 0)
		for _, addr := range addrs {
			// Not to report IPv6 interface for now
			if utils.IsIPv4(addr.IPNet.IP) {
				pair.Addrs = append(pair.Addrs, share.CLUSIPAddr{
					IPNet: *addr.IPNet,
					Scope: share.CLUSIPAddrScopeLocalhost,
				})
			}
		}

		log.WithFields(log.Fields{"port": attrs.Name, "pair": pair}).Debug("")

		intcpPairs = append(intcpPairs, &pair)
	}

	// Refresh routes if needed
	if pulled {
		if dbgError := recoverRoutes(routes, portIdxMap); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
		if dbgError := recoverNeighs(neighs, portIdxMap); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
	}
	return intcpPairs, pulled, nil
}

// 1. Enter the container network namespace;
// 2. 3. ...
// 4. Return to the original container namespace
// 5.
func InterceptContainerPorts(pid int, existPairs []*InterceptPair) ([]*InterceptPair, error) {
	log.WithFields(log.Fields{"pid": pid, "to": cfg.workingPid}).Debug("")

	// Construct set of existing port names
	existPairMap := make(map[string]*InterceptPair, len(existPairs))
	for _, pair := range existPairs {
		existPairMap[pair.Port] = pair
	}

	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Remember current NS
	curNs, err := netns.Get()
	if err != nil {
		return nil, err
	}
	defer curNs.Close()

	// Get container NS
	var containerNs netns.NsHandle
	netns_path := global.SYS.GetNetNamespacePath(pid)
	if containerNs, err = netns.GetFromPath(netns_path); err != nil {
		return nil, err
	}
	defer containerNs.Close()

	// Get destination NS
	var dstNs netns.NsHandle
	netns_path = global.SYS.GetNetNamespacePath(cfg.workingPid)
	if dstNs, err = netns.GetFromPath(netns_path); err != nil {
		return nil, err
	}
	defer dstNs.Close()

	// Switch to working NS
	log.WithFields(log.Fields{"ns": dstNs, "pid": pid}).Debug("Switch to working ns")
	if err = netns.Set(dstNs); err != nil {
		return nil, err
	}

	// Read all links in our namespace
	exLinks, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}

	// Switch to container NS
	log.WithFields(log.Fields{"ns": containerNs, "pid": pid}).Debug("Switch to container ns")
	if err = netns.Set(containerNs); err != nil {
		return nil, err
	}

	intcpPairs, pulled, err := pullAllContainerPorts(pid, int(dstNs), existPairMap, exLinks)
	if err != nil {

		if dbgError := netns.Set(curNs); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
		log.WithFields(log.Fields{"pairs": intcpPairs, "pid": pid}).Debug("Pull failed")
		return intcpPairs, err
	}

	if pulled {
		// New ports added or switching from tap to inline. Switch to destination NS
		log.WithFields(log.Fields{"ns": dstNs, "pid": pid}).Debug("Switch to dst ns")
		if err = netns.Set(dstNs); err != nil {
			if dbgError := netns.Set(curNs); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
			if dbgError := RestoreContainer(pid, intcpPairs); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
			return intcpPairs, err
		}

		// Up newly pulled ports
		for _, pair := range intcpPairs {
			if existPair, ok := existPairMap[pair.Port]; !ok || existPair.tap {
				// Here the driver should make sure port pair does exist
				pair.UCMAC, pair.BCMAC = piper.AttachPortPair(pair)
				if link, _ := waitLinkReady(pair.exPort); link != nil {
					if dbgError := netlink.LinkSetUp(link); dbgError != nil {
						log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
					}
				}
				if link, _ := waitLinkReady(pair.inPort); link != nil {
					if dbgError := netlink.LinkSetUp(link); dbgError != nil {
						log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
					}
				}
			}
		}

		// Wait a bit if new ports are pulled; otherwise,
		// sometimes AF_PACKET socket is not mapped correctly.
		nap()
	} else {
		// If we recover from a crash, ports exist but they need to be "reattached"
		nsChged := false

		for _, pair := range intcpPairs {
			if existPair, ok := existPairMap[pair.Port]; !ok || existPair.tap {
				if !nsChged {
					log.WithFields(log.Fields{"ns": dstNs, "pid": pid}).Debug("Switch to dst ns")
					if err = netns.Set(dstNs); err != nil {
						if dbgError := netns.Set(curNs); dbgError != nil {
							log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
						}
						if dbgError := RestoreContainer(pid, intcpPairs); dbgError != nil {
							log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
						}
						return intcpPairs, err
					}
					nsChged = true
				}

				pair.UCMAC, pair.BCMAC = piper.AttachPortPair(pair)
			}
		}
	}

	// Switch back to original NS
	log.WithFields(log.Fields{"ns": curNs}).Debug("Restore ns")
	err = netns.Set(curNs)

	return intcpPairs, err
}

// It's already in container namespace
// 1. ..
// 2. Read address
func readAllContainerPorts(pid int, existPairs map[string]*InterceptPair) ([]*InterceptPair, error) {
	log.WithFields(log.Fields{"pid": pid}).Debug("")

	// Read containers interface
	links, err := netlink.LinkList()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in getting ports")
		return nil, err
	}

	// Used to notify data-path process
	intcpPairs := make([]*InterceptPair, 0)
	hasVxlan := false

	// TODO: handle MACVLAN port
	for _, link := range links {
		attrs := link.Attrs()
		if len(attrs.HardwareAddr) == 0 {
			continue
		}

		addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			continue
		}

		log.WithFields(log.Fields{"addrs": addrs}).Debug("Link address")

		var pair InterceptPair
		existPair, ok := existPairs[attrs.Name]
		if ok && existPair.tap {
			log.WithFields(log.Fields{"port": attrs.Name, "mac": attrs.HardwareAddr, "pair": existPair}).Debug("Already read")
			pair = *existPair
			pair.MAC = attrs.HardwareAddr // mac can change
			pair.Addrs = nil
		} else {
			log.WithFields(log.Fields{"port": attrs.Name, "mac": attrs.HardwareAddr}).Debug("Newly read")

			var peer string
			peerIndex := getVethPeer(attrs.Name)
			dbgError := global.SYS.CallNetNamespaceFuncWithoutLock(1, func(params interface{}) {
				if peerLink, err := netlink.LinkByIndex(peerIndex); err == nil {
					peer = peerLink.Attrs().Name
				}
			}, nil)
			if dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
			pair = InterceptPair{Port: attrs.Name, index: attrs.Index, Peer: peer, MAC: attrs.HardwareAddr, tap: true}
		}

		// Record addresses
		pair.Addrs = make([]share.CLUSIPAddr, 0)
		for _, addr := range addrs {
			// Not to report IPv6 interface for now
			if utils.IsIPv4(addr.IPNet.IP) {
				pair.Addrs = append(pair.Addrs, share.CLUSIPAddr{
					IPNet: *addr.IPNet,
					Scope: share.CLUSIPAddrScopeLocalhost,
				})
			}
		}

		if link.Type() == "vxlan" {
			hasVxlan = true
			log.Debug("Container has vxlan interface.")
		}
		// Ignore ports that have no IPv4 address, to be consistent with interception logic
		if len(pair.Addrs) == 0 {
			continue
		}

		log.WithFields(log.Fields{"port": attrs.Name, "pair": pair}).Debug()

		intcpPairs = append(intcpPairs, &pair)
	}
	//container has vxlan
	if hasVxlan {
		for _, pair := range intcpPairs {
			pair.Vxlan = true
		}
	}

	return intcpPairs, nil
}

// 1. Enter the container network namespace;
// 2. 3. ...
// 4. Return to the original container namespace
// 5.
func InspectContainerPorts(pid int, existPairs []*InterceptPair) ([]*InterceptPair, error) {
	log.WithFields(log.Fields{"pid": pid, "to": cfg.workingPid}).Debug("")

	// Construct set of existing port names
	existPairMap := make(map[string]*InterceptPair, len(existPairs))
	for _, pair := range existPairs {
		existPairMap[pair.Port] = pair
	}

	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Remember current NS
	curNs, err := netns.Get()
	if err != nil {
		return nil, err
	}
	defer curNs.Close()

	// Get container NS
	var containerNs netns.NsHandle
	netns_path := global.SYS.GetNetNamespacePath(pid)
	if containerNs, err = netns.GetFromPath(netns_path); err != nil {
		return nil, err
	}
	defer containerNs.Close()

	// Switch to container NS
	log.WithFields(log.Fields{"ns": containerNs, "pid": pid}).Debug("Switch to container ns")
	if err = netns.Set(containerNs); err != nil {
		return nil, err
	}

	var intcpPairs []*InterceptPair
	intcpPairs, _ = readAllContainerPorts(pid, existPairMap)

	// Switch back to original NS
	log.WithFields(log.Fields{"ns": curNs}).Debug("Restore ns")
	err = netns.Set(curNs)

	return intcpPairs, err
}

func pushContainerPort(pair *InterceptPair) (int, int, error) {
	log.WithFields(log.Fields{"port": pair.Port}).Debug("")

	link, err := netlink.LinkByName(pair.Port)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Cannot find port")
		return 0, 0, err
	}

	localPortIdx := link.Attrs().Index

	// Read port addresses
	localMAC := link.Attrs().HardwareAddr
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in reading address")
		return localPortIdx, 0, err
	}

	log.WithFields(log.Fields{"port": pair.Port}).Debug("Remove port")

	if dbgError := netlink.LinkSetDown(link); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	if dbgError := netlink.LinkDel(link); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}

	log.WithFields(log.Fields{"port": pair.Port}).Debug("Modify port")

	// Get moved-in port. The port is already down
	if link, _ = waitLinkReady(pair.exPort); link == nil {
		log.WithFields(log.Fields{"error": err}).Error("Cannot find port")
		return localPortIdx, 0, err
	}

	if err = netlink.LinkSetDown(link); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in disabling port")
		return localPortIdx, 0, err
	}

	newPortIdx := link.Attrs().Index

	// Change to its original name
	if err = netlink.LinkSetName(link, pair.Port); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in changing name")
		return localPortIdx, newPortIdx, err
	}

	// Get the link again as name is changed.
	if link, _ = waitLinkReady(pair.Port); link == nil {
		log.WithFields(log.Fields{"error": err}).Error("Cannot find port")
		return localPortIdx, newPortIdx, err
	}

	// Recover addresses
	if err = netlink.LinkSetHardwareAddr(link, localMAC); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in changing MAC")
		return localPortIdx, newPortIdx, err
	}
	var exAddrs []netlink.Addr
	if exAddrs, err = netlink.AddrList(link, netlink.FAMILY_ALL); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in getting address")
		return localPortIdx, newPortIdx, err
	}
	for _, addr := range exAddrs {
		log.WithFields(log.Fields{"addr": addr}).Debug("Delete address")
		if dbgError := netlink.AddrDel(link, &addr); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
	}
	for _, addr := range addrs {
		log.WithFields(log.Fields{"addr": addr}).Debug("Add address")
		if dbgError := netlink.AddrAdd(link, &addr); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
	}

	// Set link up
	if err = netlink.LinkSetUp(link); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in enabling port")
		return localPortIdx, newPortIdx, err
	}

	return localPortIdx, newPortIdx, nil
}

// It's already in container namespace
// 1. ..
// 2. Remove the port pair in the container
// 3. Rename the moved-in port to original port;
func pushAllContainerPorts(pid int, pairs []*InterceptPair) error {
	log.Debug("")

	links, err := netlink.LinkList()
	if err != nil {
		return err
	}

	// Map the inside port's index to moved-in port's index
	var portIdxMap map[int]int = make(map[int]int)

	// Read all routes and neighbors
	routes, err := getRouteList()
	if err != nil {
		return err
	}
	neighs, err := getPermanentNeighList(links)
	if err != nil {
		return err
	}

	for _, pair := range pairs {
		oldPortIdx, newPortIdx, err := pushContainerPort(pair)
		if err != nil {
			continue
		}

		portIdxMap[oldPortIdx] = newPortIdx
	}

	if dbgError := recoverRoutes(routes, portIdxMap); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}

	if dbgError := recoverNeighs(neighs, portIdxMap); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}

	return nil
}

// Agent exiting, we need put ports back to container, and clean flows in our namespace
func RestoreContainer(pid int, pairs []*InterceptPair) error {
	log.WithFields(log.Fields{"pid": pid, "from": cfg.workingPid}).Debug("")

	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Remember current NS
	curNs, err := netns.Get()
	if err != nil {
		return err
	}
	defer curNs.Close()

	// Get container NS
	var containerNs netns.NsHandle
	netns_path := global.SYS.GetNetNamespacePath(pid)
	if containerNs, err = netns.GetFromPath(netns_path); err != nil {
		return err
	}
	defer containerNs.Close()

	// Get source NS
	var srcNs netns.NsHandle
	netns_path = global.SYS.GetNetNamespacePath(cfg.workingPid)
	if srcNs, err = netns.GetFromPath(netns_path); err != nil {
		return err
	}
	defer srcNs.Close()

	// Switch to namespace where ports are
	log.WithFields(log.Fields{"ns": srcNs, "pid": cfg.workingPid}).Debug("Switch to src ns")
	if err = netns.Set(srcNs); err != nil {
		return err
	}

	exLinks, err := netlink.LinkList()
	if err != nil {
		return err
	}

	// Move exPort into container
	for _, pair := range pairs {
		if portExists(exLinks, pair.exPort) && portExists(exLinks, pair.inPort) {
			piper.ResetPortPair(pid, pair)
			piper.DetachPortPair(pair)

			log.WithFields(log.Fields{"port": pair.exPort}).Debug("Move port")

			// Move the exPort to the container
			var link netlink.Link
			if link, err = netlink.LinkByName(pair.exPort); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Cannot find port")
				continue
			}
			if err = netlink.LinkSetDown(link); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Error in disabling port")
				continue
			}
			if err = netlink.LinkSetNsFd(link, int(containerNs)); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Error in changing namespace")
				continue
			}
		}
	}

	// Switch to container NS
	log.WithFields(log.Fields{"ns": containerNs, "pid": pid}).Debug("Switch to container ns")
	if err = netns.Set(containerNs); err != nil {
		return err
	}

	if dbgError := pushAllContainerPorts(pid, pairs); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}

	// Switch back to original NS
	log.WithFields(log.Fields{"ns": curNs}).Debug("Restore ns")
	err = netns.Set(curNs)

	return err
}

// Continer stops, we only need to clean-up ports and flows in our namespace
func CleanupContainer(pid int, intcpPairs []*InterceptPair) error {
	log.WithFields(log.Fields{"pid": pid}).Debug("")

	hostPorts := make(map[string][]share.CLUSIPAddr)

	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Switch to namespace where ports are
	dbgError := global.SYS.CallNetNamespaceFuncWithoutLock(cfg.workingPid, func(params interface{}) {
		log.WithFields(log.Fields{"pid": cfg.workingPid}).Debug("Switch to src ns")

		// Remove ports and rules
		for _, pair := range intcpPairs {
			piper.ResetPortPair(pid, pair)
			piper.DetachPortPair(pair)

			if link, err := netlink.LinkByName(pair.exPort); err == nil {
				if dbgError := netlink.LinkSetDown(link); dbgError != nil {
					log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
				}
				if dbgError := netlink.LinkDel(link); dbgError != nil {
					log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
				}

				if pair.Peer != "" {
					hostPorts[pair.Peer] = pair.Addrs
				}
			}
			if link, err := netlink.LinkByName(pair.inPort); err == nil {
				if dbgError := netlink.LinkSetDown(link); dbgError != nil {
					log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
				}
				if dbgError := netlink.LinkDel(link); dbgError != nil {
					log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
				}
			}
		}
	}, nil)

	if dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	if dbgError := global.ORCH.CleanupHostPorts(hostPorts); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}

	return nil
}

const nvInputChain string = "NV_INPUT_PROXYMESH"
const nvOutputChain string = "NV_OUTPUT_PROXYMESH"

/*
 * 1. disassociate OUTPUT/INPUT with NV_OUTPUT/NV_INPUT
 * iptables -D OUTPUT -j NV_OUTPUT
 * iptables -D INPUT -j NV_INPUT
 * 2. flush custom chain of its rules
 * iptables -F NV_OUTPUT
 * iptables -F NV_INPUT
 * 3. delete custom chain
 * iptables -X NV_OUTPUT
 * iptables -X NV_INPUT
 */
func resetIptablesNvRules() {
	var cmd string
	//disassociate OUTPUT/INPUT with NV_OUTPUT/NV_INPUT
	cmd = fmt.Sprintf("iptables -D OUTPUT -j %v", nvOutputChain)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	cmd = fmt.Sprintf("iptables -D INPUT -j %v", nvInputChain)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}

	//flush custom chain of its rules
	cmd = fmt.Sprintf("iptables -F %v", nvOutputChain)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	cmd = fmt.Sprintf("iptables -F %v", nvInputChain)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}

	//delete custom chain
	cmd = fmt.Sprintf("iptables -X %v", nvOutputChain)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	cmd = fmt.Sprintf("iptables -X %v", nvInputChain)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
}

const nvInputQuarChain string = "NV_INPUT_QUAR_PROXYMESH"
const nvOutputQuarChain string = "NV_OUTPUT_QUAR_PROXYMESH"

func deleteIptablesNvQuarRules() {
	var cmd string
	//disassociate OUTPUT/INPUT with NV_OUTPUT/NV_INPUT
	cmd = fmt.Sprintf("iptables -D OUTPUT -j %v", nvOutputQuarChain)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	cmd = fmt.Sprintf("iptables -D INPUT -j %v", nvInputQuarChain)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}

	//flush custom chain of its rules
	cmd = fmt.Sprintf("iptables -F %v", nvOutputQuarChain)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	cmd = fmt.Sprintf("iptables -F %v", nvInputQuarChain)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}

	//delete custom chain
	cmd = fmt.Sprintf("iptables -X %v", nvOutputQuarChain)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	cmd = fmt.Sprintf("iptables -X %v", nvInputQuarChain)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
}

func createIptablesNvQuarRules() {
	var cmd string
	//create custom chains
	cmd = fmt.Sprintf("iptables -N %v", nvInputQuarChain)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	cmd = fmt.Sprintf("iptables -N %v", nvOutputQuarChain)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	//append drop rule
	cmd = fmt.Sprintf("iptables -I %v -j DROP", nvInputQuarChain)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	cmd = fmt.Sprintf("iptables -I %v -j DROP", nvOutputQuarChain)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	//associate NV_OUTPUT_QUAR/NV_INPUT_QUAR with OUTPUT/INPUT chain
	cmd = fmt.Sprintf("iptables -I INPUT -j %v", nvInputQuarChain)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	cmd = fmt.Sprintf("iptables -I OUTPUT -j %v", nvOutputQuarChain)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
}

func insertIptablesNvRules(intf string, isloopback bool, qno int, appMap map[share.CLUSProtoPort]*share.CLUSApp) {
	var cmd string
	if appMap == nil || len(appMap) <= 0 {
		cmd = fmt.Sprintf("iptables -I %v -t filter -i %v -j NFQUEUE --queue-num %d --queue-bypass", nvInputChain, intf, qno)
		if _, dbgError := shellCombined(cmd); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
		cmd = fmt.Sprintf("iptables -I %v -t filter -o %v -j NFQUEUE --queue-num %d --queue-bypass", nvOutputChain, intf, qno)
		if _, dbgError := shellCombined(cmd); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
		return
	}

	for p := range appMap {
		if p.IPProto == syscall.IPPROTO_TCP { //tcp
			//insert to top of rule list in filter table INPUT and OUTPUT chain
			if isloopback {
				cmd = fmt.Sprintf("iptables -I %v -t filter -i %v -p tcp --sport %d -j NFQUEUE --queue-num %d --queue-bypass", nvInputChain, intf, p.Port, qno)
			} else {
				cmd = fmt.Sprintf("iptables -I %v -t filter -i %v -p tcp --dport %d -j NFQUEUE --queue-num %d --queue-bypass", nvInputChain, intf, p.Port, qno)
			}
			if _, dbgError := shellCombined(cmd); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
			if isloopback {
				cmd = fmt.Sprintf("iptables -I %v -t filter -o %v -p tcp --dport %d -j NFQUEUE --queue-num %d --queue-bypass", nvOutputChain, intf, p.Port, qno)
			} else {
				cmd = fmt.Sprintf("iptables -I %v -t filter -o %v -p tcp --sport %d -j NFQUEUE --queue-num %d --queue-bypass", nvOutputChain, intf, p.Port, qno)
			}
			if _, dbgError := shellCombined(cmd); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
		} else if p.IPProto == syscall.IPPROTO_UDP { //udp
			//insert to top of rule list in filter table INPUT and OUTPUT chain
			if isloopback {
				cmd = fmt.Sprintf("iptables -I %v -t filter -i %v -p udp --sport %d -j NFQUEUE --queue-num %d --queue-bypass", nvInputChain, intf, p.Port, qno)
			} else {
				cmd = fmt.Sprintf("iptables -I %v -t filter -i %v -p udp --dport %d -j NFQUEUE --queue-num %d --queue-bypass", nvInputChain, intf, p.Port, qno)
			}
			if _, dbgError := shellCombined(cmd); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
			if isloopback {
				cmd = fmt.Sprintf("iptables -I %v -t filter -o %v -p udp --dport %d -j NFQUEUE --queue-num %d --queue-bypass", nvOutputChain, intf, p.Port, qno)
			} else {
				cmd = fmt.Sprintf("iptables -I %v -t filter -o %v -p udp --sport %d -j NFQUEUE --queue-num %d --queue-bypass", nvOutputChain, intf, p.Port, qno)
			}
			if _, dbgError := shellCombined(cmd); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
		}
	}
}

func checkInsertIptablesNvRules(intf string, isloopback bool, qno int, appMap map[share.CLUSProtoPort]*share.CLUSApp) {
	var cmd string
	if appMap == nil || len(appMap) <= 0 {
		cmd = fmt.Sprintf("iptables -C %v -t filter -i %v -j NFQUEUE --queue-num %d --queue-bypass", nvInputChain, intf, qno)
		if _, err := shellCombined(cmd); err != nil {
			cmd = fmt.Sprintf("iptables -I %v -t filter -i %v -j NFQUEUE --queue-num %d --queue-bypass", nvInputChain, intf, qno)
			if _, dbgError := shellCombined(cmd); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
		}
		cmd = fmt.Sprintf("iptables -C %v -t filter -o %v -j NFQUEUE --queue-num %d --queue-bypass", nvOutputChain, intf, qno)
		if _, err := shellCombined(cmd); err != nil {
			cmd = fmt.Sprintf("iptables -I %v -t filter -o %v -j NFQUEUE --queue-num %d --queue-bypass", nvOutputChain, intf, qno)
			if _, dbgError := shellCombined(cmd); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
		}
		return
	}

	for p := range appMap {
		if p.IPProto == syscall.IPPROTO_TCP { //tcp
			//check existence of rule before insert it
			if isloopback {
				cmd = fmt.Sprintf("iptables -C %v -t filter -i %v -p tcp --sport %d -j NFQUEUE --queue-num %d --queue-bypass", nvInputChain, intf, p.Port, qno)
			} else {
				cmd = fmt.Sprintf("iptables -C %v -t filter -i %v -p tcp --dport %d -j NFQUEUE --queue-num %d --queue-bypass", nvInputChain, intf, p.Port, qno)
			}
			if _, err := shellCombined(cmd); err != nil {
				//insert to top of rule list in filter table INPUT and OUTPUT chain
				if isloopback {
					cmd = fmt.Sprintf("iptables -I %v -t filter -i %v -p tcp --sport %d -j NFQUEUE --queue-num %d --queue-bypass", nvInputChain, intf, p.Port, qno)
				} else {
					cmd = fmt.Sprintf("iptables -I %v -t filter -i %v -p tcp --dport %d -j NFQUEUE --queue-num %d --queue-bypass", nvInputChain, intf, p.Port, qno)
				}
				if _, dbgError := shellCombined(cmd); dbgError != nil {
					log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
				}
			}
			//check existence of rule before insert it
			if isloopback {
				cmd = fmt.Sprintf("iptables -C %v -t filter -o %v -p tcp --dport %d -j NFQUEUE --queue-num %d --queue-bypass", nvOutputChain, intf, p.Port, qno)
			} else {
				cmd = fmt.Sprintf("iptables -C %v -t filter -o %v -p tcp --sport %d -j NFQUEUE --queue-num %d --queue-bypass", nvOutputChain, intf, p.Port, qno)
			}
			if _, err := shellCombined(cmd); err != nil {
				//insert to top of rule list in filter table INPUT and OUTPUT chain
				if isloopback {
					cmd = fmt.Sprintf("iptables -I %v -t filter -o %v -p tcp --dport %d -j NFQUEUE --queue-num %d --queue-bypass", nvOutputChain, intf, p.Port, qno)
				} else {
					cmd = fmt.Sprintf("iptables -I %v -t filter -o %v -p tcp --sport %d -j NFQUEUE --queue-num %d --queue-bypass", nvOutputChain, intf, p.Port, qno)
				}
				if _, dbgError := shellCombined(cmd); dbgError != nil {
					log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
				}
			}
		} else if p.IPProto == syscall.IPPROTO_UDP { //udp
			//check existence of rule before insert it
			if isloopback {
				cmd = fmt.Sprintf("iptables -C %v -t filter -i %v -p udp --sport %d -j NFQUEUE --queue-num %d --queue-bypass", nvInputChain, intf, p.Port, qno)
			} else {
				cmd = fmt.Sprintf("iptables -C %v -t filter -i %v -p udp --dport %d -j NFQUEUE --queue-num %d --queue-bypass", nvInputChain, intf, p.Port, qno)
			}
			if _, err := shellCombined(cmd); err != nil {
				//insert to top of rule list in filter table INPUT and OUTPUT chain
				if isloopback {
					cmd = fmt.Sprintf("iptables -I %v -t filter -i %v -p udp --sport %d -j NFQUEUE --queue-num %d --queue-bypass", nvInputChain, intf, p.Port, qno)
				} else {
					cmd = fmt.Sprintf("iptables -I %v -t filter -i %v -p udp --dport %d -j NFQUEUE --queue-num %d --queue-bypass", nvInputChain, intf, p.Port, qno)
				}
				if _, dbgError := shellCombined(cmd); dbgError != nil {
					log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
				}
			}
			//check existence of rule before insert it
			if isloopback {
				cmd = fmt.Sprintf("iptables -C %v -t filter -o %v -p udp --dport %d -j NFQUEUE --queue-num %d --queue-bypass", nvOutputChain, intf, p.Port, qno)
			} else {
				cmd = fmt.Sprintf("iptables -C %v -t filter -o %v -p udp --sport %d -j NFQUEUE --queue-num %d --queue-bypass", nvOutputChain, intf, p.Port, qno)
			}
			if _, err := shellCombined(cmd); err != nil {
				//insert to top of rule list in filter table INPUT and OUTPUT chain
				if isloopback {
					cmd = fmt.Sprintf("iptables -I %v -t filter -o %v -p udp --dport %d -j NFQUEUE --queue-num %d --queue-bypass", nvOutputChain, intf, p.Port, qno)
				} else {
					cmd = fmt.Sprintf("iptables -I %v -t filter -o %v -p udp --sport %d -j NFQUEUE --queue-num %d --queue-bypass", nvOutputChain, intf, p.Port, qno)
				}
				if _, dbgError := shellCombined(cmd); dbgError != nil {
					log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
				}
			}
		}
	}
}

/*
 * 1. create custom chains
 * iptables -N NV_INPUT
 * iptables -N NV_OUTPUT
 * 2. append default rule first
 * iptables -A NV_INPUT -j RETURN
 * iptables -A NV_OUTPUT -j RETURN
 * 3. add nfq rules based on appMap
 * iptables -I INPUT -t filter -j NFQUEUE --queue-num 0 --queue-bypass
 * iptables -I OUTPUT -t filter -j NFQUEUE --queue-num 0 --queue-bypass
 * 4. associate NV_OUTPUT/NV_INPUT with OUTPUT/INPUT chain
 * iptables -I OUTPUT -j NV_OUTPUT
 * iptables -I INPUT -j NV_INPUT
 */
func createIptablesNvRules(intf string, isloopback bool, qno int, appMap map[share.CLUSProtoPort]*share.CLUSApp) {
	var cmd string
	//create custom chains
	cmd = fmt.Sprintf("iptables -N %v", nvInputChain)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	cmd = fmt.Sprintf("iptables -N %v", nvOutputChain)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	//append default rule first
	cmd = fmt.Sprintf("iptables -A %v -j RETURN", nvInputChain)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	cmd = fmt.Sprintf("iptables -A %v -j RETURN", nvOutputChain)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}

	insertIptablesNvRules(intf, isloopback, qno, appMap)

	//associate NV_OUTPUT/NV_INPUT with OUTPUT/INPUT chain
	cmd = fmt.Sprintf("iptables -A INPUT -j %v", nvInputChain)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	cmd = fmt.Sprintf("iptables -A OUTPUT -j %v", nvOutputChain)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
}

// setup iptable rules for quarantine
func CreateNfqQuarRules(pid int, create bool) error {
	log.WithFields(log.Fields{"pid": pid}).Debug("")

	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Remember current NS
	curNs, err := netns.Get()
	if err != nil {
		return err
	}
	defer curNs.Close()

	// Get container NS
	var containerNs netns.NsHandle
	netns_path := global.SYS.GetNetNamespacePath(pid)
	if containerNs, err = netns.GetFromPath(netns_path); err != nil {
		return err
	}
	defer containerNs.Close()

	// Switch to container NS
	log.WithFields(log.Fields{"ns": containerNs, "pid": pid}).Debug("Enter container ns")
	if err = netns.Set(containerNs); err != nil {
		return err
	}

	deleteIptablesNvQuarRules()
	if create {
		createIptablesNvQuarRules()
	}
	// Switch back to original NS
	log.WithFields(log.Fields{"ns": curNs}).Debug("Restore ns")
	err = netns.Set(curNs)

	return err
}

// setup iptable rules with NFQUEUE target
func CreateNfqRules(pid, qno int, create, isloopback bool, intf string, appMap map[share.CLUSProtoPort]*share.CLUSApp) error {
	log.WithFields(log.Fields{"pid": pid}).Debug("")

	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Remember current NS
	curNs, err := netns.Get()
	if err != nil {
		return err
	}
	defer curNs.Close()

	// Get container NS
	var containerNs netns.NsHandle
	netns_path := global.SYS.GetNetNamespacePath(pid)
	if containerNs, err = netns.GetFromPath(netns_path); err != nil {
		return err
	}
	defer containerNs.Close()

	// Switch to container NS
	log.WithFields(log.Fields{"ns": containerNs, "pid": pid}).Debug("Enter container ns")
	if err = netns.Set(containerNs); err != nil {
		return err
	}

	if create {
		//create iptable rules
		resetIptablesNvRules()
		createIptablesNvRules(intf, isloopback, qno, appMap)
	} else {
		checkInsertIptablesNvRules(intf, isloopback, qno, appMap)
	}

	// Switch back to original NS
	log.WithFields(log.Fields{"ns": curNs}).Debug("Restore ns")
	err = netns.Set(curNs)

	return err
}

// setup iptable rules with NFQUEUE target
func DeleteNfqRules(pid int) error {
	log.WithFields(log.Fields{"pid": pid}).Debug("")

	// Lock the OS Thread so we don't accidentally switch namespaces
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Remember current NS
	curNs, err := netns.Get()
	if err != nil {
		return err
	}
	defer curNs.Close()

	// Get container NS
	var containerNs netns.NsHandle
	netns_path := global.SYS.GetNetNamespacePath(pid)
	if containerNs, err = netns.GetFromPath(netns_path); err != nil {
		return err
	}
	defer containerNs.Close()

	// Switch to container NS
	log.WithFields(log.Fields{"ns": containerNs, "pid": pid}).Debug("Enter container ns")
	if err = netns.Set(containerNs); err != nil {
		return err
	}

	//delete iptable rules
	resetIptablesNvRules()
	deleteIptablesNvQuarRules()

	// Switch back to original NS
	log.WithFields(log.Fields{"ns": curNs}).Debug("Restore ns")
	err = netns.Set(curNs)

	return err
}

type pipeParam struct {
	pid  int
	pair *InterceptPair
}

func cbTapPortPair(param interface{}) {
	pp := param.(*pipeParam)
	piper.ResetPortPair(pp.pid, pp.pair)
	piper.TapPortPair(pp.pid, pp.pair)
}

func TapPortPair(pid int, pair *InterceptPair) {
	if dbgError := global.SYS.CallNetNamespaceFunc(cfg.workingPid, cbTapPortPair, &pipeParam{pid: pid, pair: pair}); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
}

func cbFwdPortPair(param interface{}) {
	pp := param.(*pipeParam)
	piper.ResetPortPair(pp.pid, pp.pair)
	piper.FwdPortPair(pp.pid, pp.pair)
}

func FwdPortPair(pid int, pair *InterceptPair) {
	if dbgError := global.SYS.CallNetNamespaceFunc(cfg.workingPid, cbFwdPortPair, &pipeParam{pid: pid, pair: pair}); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
}

func cbResetPortPair(param interface{}) {
	pp := param.(*pipeParam)
	piper.ResetPortPair(pp.pid, pp.pair)
}

func ResetPortPair(pid int, pair *InterceptPair) {
	if dbgError := global.SYS.CallNetNamespaceFunc(cfg.workingPid, cbResetPortPair, &pipeParam{pid: pid, pair: pair}); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
}

func GetPortPairDebug(pair *InterceptPair) *share.CLUSWorkloadInterceptPort {
	p := share.CLUSWorkloadInterceptPort{
		Port:   pair.Port,
		Peer:   pair.Peer,
		InPort: pair.inPort,
		ExPort: pair.exPort,
		MAC:    pair.MAC,
		UCMAC:  pair.UCMAC,
		BCMAC:  pair.BCMAC,
	}
	p.InPortRules, p.ExPortRules, p.EnforcerRules = piper.GetPortPairRules(pair)
	return &p
}

func Open(driver string, cnet_type *string, pid int, jumboframe bool) (string, string, error) {
	switch driver {
	case PIPE_OVS:
		piper = &ovsPipe
	case PIPE_TC:
		piper = &tcPipe
	case PIPE_NOTC:
		piper = &notcPipe
	case PIPE_CLM:
		piper = &clmPipe
	default:
		piper = &tcPipe
	}
	cfg.workingPid = pid
	if cnet_type != nil {
		cfg.cnet_type = *cnet_type
	} else {
		cfg.cnet_type = CNET_DEFAULT
	}
	piper.Connect(jumboframe)
	return nvVthPortName, nvVbrPortName, nil
}

func Close() {
	piper.Cleanup()
}

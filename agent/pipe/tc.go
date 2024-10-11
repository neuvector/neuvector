package pipe

import (
	"fmt"
	"net"
	"strings"

	"github.com/neuvector/neuvector/share/utils"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const tcPrefMax uint = 65536
const tcPrefBase uint = 10000

type tcPortInfo struct {
	idx  uint // port index in enforcer network namespace
	pref uint
}

type tcPipeDriver struct {
	prefs   utils.Set
	portMap map[string]*tcPortInfo
}

var tcPipe tcPipeDriver = tcPipeDriver{}

func (d *tcPipeDriver) getAvailablePref(portID uint) uint {
	pref := portID % tcPrefMax

	if !d.prefs.Contains(pref) {
		return pref
	}

	// Find the smallest
	for pref = 1; pref < tcPrefMax; pref++ {
		if !d.prefs.Contains(pref) {
			return pref
		}
	}

	return 0
}

// Sometimes port can be located by netlink, but not TC, so use TC command to wait for it.
func (d *tcPipeDriver) retryCmd(cmd string) error {
	var err error

	// wait max. 1s
	for i := 0; i < 4; i++ {
		if _, err := shell(cmd); err == nil {
			return nil
		}

		nap()
	}

	return err
}

func (d *tcPipeDriver) addQDisc(port string) {
	if _, dbgError := shell(fmt.Sprintf("tc qdisc add dev %v ingress", port)); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
}

func (d *tcPipeDriver) delQDisc(port string) {
	if _, dbgError := shell(fmt.Sprintf("tc qdisc del dev %v ingress", port)); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
}

func (d *tcPipeDriver) attachPort(port string) uint {
	_, idx := waitLinkReady(port)
	if idx == 0 {
		log.WithFields(log.Fields{"port": port}).Error("Cannot find port")
		return 0
	}
	pref := d.getAvailablePref(idx)
	if pref == 0 {
		log.WithFields(log.Fields{"port": port, "index": idx}).Error("Cannot find pref ID")
		return 0
	}

	d.prefs.Add(pref)
	d.portMap[port] = &tcPortInfo{idx: idx, pref: pref}

	d.addQDisc(port)
	return idx
}

func (d *tcPipeDriver) detachPort(port string) {
	if info, ok := d.portMap[port]; ok {
		d.prefs.Remove(info.pref)
		delete(d.portMap, port)
	}
	d.delQDisc(port)
}

func (d *tcPipeDriver) AttachPortPair(pair *InterceptPair) (net.HardwareAddr, net.HardwareAddr) {
	d.attachPort(pair.inPort)
	idx := d.attachPort(pair.exPort)

	// 4e:65:75:56 - NeuV
	var mac_str string
	mac_str = fmt.Sprintf("4e:65:75:56:%02x:%02x", (idx>>8)&0xff, idx&0xff)
	ucmac, _ := net.ParseMAC(mac_str)
	mac_str = fmt.Sprintf("ff:ff:ff:00:%02x:%02x", (idx>>8)&0xff, idx&0xff)
	bcmac, _ := net.ParseMAC(mac_str)
	return ucmac, bcmac
}

func (d *tcPipeDriver) DetachPortPair(pair *InterceptPair) {
	d.detachPort(pair.inPort)
	d.detachPort(pair.exPort)
}

func (d *tcPipeDriver) ResetPortPair(pid int, pair *InterceptPair) {
	log.WithFields(log.Fields{"inPort": pair.inPort, "exPort": pair.exPort}).Debug("")

	var cmd string
	var ok bool
	var inInfo, exInfo *tcPortInfo
	if inInfo, ok = d.portMap[pair.inPort]; !ok {
		log.WithFields(log.Fields{"inPort": pair.inPort}).Error("No pref for inPort")
		return
	}
	if exInfo, ok = d.portMap[pair.exPort]; !ok {
		log.WithFields(log.Fields{"exPort": pair.exPort}).Error("No pref for exPort")
		return
	}

	// Ingress --
	// cmd = fmt.Sprintf("tc filter del dev %v parent ffff: protocol all pref %v", pair.exPort, tcPrefBase)
	// shell(cmd)
	cmd = fmt.Sprintf("tc filter del dev %v parent ffff: protocol ip pref %v", pair.exPort, tcPrefBase+1)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	cmd = fmt.Sprintf("tc filter del dev %v parent ffff: protocol all pref %v", pair.exPort, tcPrefBase+2)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}

	// Egress --
	// cmd = fmt.Sprintf("tc filter del dev %v parent ffff: protocol all pref %v", pair.inPort, tcPrefBase)
	// shell(cmd)
	cmd = fmt.Sprintf("tc filter del dev %v parent ffff: protocol ip pref %v", pair.inPort, tcPrefBase+1)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	cmd = fmt.Sprintf("tc filter del dev %v parent ffff: protocol all pref %v", pair.inPort, tcPrefBase+2)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}

	cmd = fmt.Sprintf("tc filter del dev %v parent ffff: protocol all pref %v", nvVbrPortName, inInfo.pref)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	cmd = fmt.Sprintf("tc filter del dev %v parent ffff: protocol all pref %v", nvVbrPortName, exInfo.pref)
	if _, dbgError := shellCombined(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
}

func (d *tcPipeDriver) TapPortPair(pid int, pair *InterceptPair) {
	log.WithFields(log.Fields{"inPort": pair.inPort, "exPort": pair.exPort}).Debug("")

	var cmd string
	var ok bool
	var inInfo, exInfo *tcPortInfo
	if inInfo, ok = d.portMap[pair.inPort]; !ok {
		log.WithFields(log.Fields{"inPort": pair.inPort}).Error("No pref for inPort")
		return
	}
	if exInfo, ok = d.portMap[pair.exPort]; !ok {
		log.WithFields(log.Fields{"exPort": pair.exPort}).Error("No pref for exPort")
		return
	}

	// Ingress --
	// Bypass multicast
	// fmt.Sprintf("tc filter add dev %v pref %v parent ffff: protocol all "+
	// 	"u32 match u8 1 1 at -14 "+
	// 	"action mirred egress mirror dev %v", pair.exPort, tcPrefBase, pair.inPort)
	// shell(cmd)

	// TAP IP packet, forward unicast packet with DA to the workload
	cmd = fmt.Sprintf("tc filter add dev %v pref %v parent ffff: protocol ip "+
		"u32 match u8 0 1 at -14 "+
		"match u16 0x%02x%02x 0xffff at -14 match u32 0x%02x%02x%02x%02x 0xffffffff at -12 "+
		"action mirred egress mirror dev %v "+
		"action pedit munge offset -14 u16 set 0x%02x%02x munge offset -12 u32 set 0x%02x%02x%02x%02x pipe "+
		"action mirred egress mirror dev %v",
		pair.exPort, tcPrefBase+1,
		pair.MAC[0], pair.MAC[1], pair.MAC[2], pair.MAC[3], pair.MAC[4], pair.MAC[5],
		pair.inPort,
		pair.UCMAC[0], pair.UCMAC[1], pair.UCMAC[2], pair.UCMAC[3], pair.UCMAC[4], pair.UCMAC[5],
		nvVbrPortName)
	if err := d.retryCmd(cmd); err != nil {
		log.WithFields(log.Fields{"exPort": pair.exPort}).Error("Cannot find port")
		return
	}

	// Forward the rest
	cmd = fmt.Sprintf("tc filter add dev %v pref %v parent ffff: protocol all "+
		"u32 match u8 0 0 "+
		"action mirred egress mirror dev %v",
		pair.exPort, tcPrefBase+2, pair.inPort)
	if err := d.retryCmd(cmd); err != nil {
		log.WithFields(log.Fields{"exPort": pair.exPort}).Error("Cannot find port")
		return
	}

	// Egress --
	// Bypass multicast
	// fmt.Sprintf("tc filter add dev %v pref %v parent ffff: protocol all "+
	// 	"u32 match u8 1 1 at -14 "+
	// 	"action mirred egress mirror dev %v", pair.inPort, tcPrefBase, pair.exPort)

	// TAP IP packet, forward unicast packet with SA from the workload
	cmd = fmt.Sprintf("tc filter add dev %v pref %v parent ffff: protocol ip "+
		"u32 match u8 0 1 at -14 "+
		"match u32 0x%02x%02x%02x%02x 0xffffffff at -8 match u16 0x%02x%02x 0xffff at -4 "+
		"action mirred egress mirror dev %v "+
		"action pedit munge offset -8 u32 set 0x%02x%02x%02x%02x munge offset -4 u16 set 0x%02x%02x pipe "+
		"action mirred egress mirror dev %v",
		pair.inPort, tcPrefBase+1,
		pair.MAC[0], pair.MAC[1], pair.MAC[2], pair.MAC[3], pair.MAC[4], pair.MAC[5],
		pair.exPort,
		pair.UCMAC[0], pair.UCMAC[1], pair.UCMAC[2], pair.UCMAC[3], pair.UCMAC[4], pair.UCMAC[5],
		nvVbrPortName)
	if err := d.retryCmd(cmd); err != nil {
		log.WithFields(log.Fields{"inPort": pair.inPort}).Error("Cannot find port")
		return
	}

	// Forward the rest
	cmd = fmt.Sprintf("tc filter add dev %v pref %v parent ffff: protocol all "+
		"u32 match u8 0 0 "+
		"action mirred egress mirror dev %v",
		pair.inPort, tcPrefBase+2, pair.exPort)
	if err := d.retryCmd(cmd); err != nil {
		log.WithFields(log.Fields{"inPort": pair.inPort}).Error("Cannot find port")
		return
	}

	// Drop the packets from enforcer
	cmd = fmt.Sprintf("tc filter add dev %v pref %v parent ffff: protocol all "+
		"u32 match u16 0x%02x%02x 0xffff at -14 match u32 0x%02x%02x%02x%02x 0xffffffff at -12 "+
		"action drop",
		nvVbrPortName, exInfo.pref,
		pair.UCMAC[0], pair.UCMAC[1], pair.UCMAC[2], pair.UCMAC[3], pair.UCMAC[4], pair.UCMAC[5])
	if _, dbgError := shell(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	cmd = fmt.Sprintf("tc filter add dev %v pref %v parent ffff: protocol all "+
		"u32 match u32 0x%02x%02x%02x%02x 0xffffffff at -8 match u16 0x%02x%02x 0xffff at -4 "+
		"action drop",
		nvVbrPortName, inInfo.pref,
		pair.UCMAC[0], pair.UCMAC[1], pair.UCMAC[2], pair.UCMAC[3], pair.UCMAC[4], pair.UCMAC[5])
	if _, dbgError := shell(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
}

func (d *tcPipeDriver) FwdPortPair(pid int, pair *InterceptPair) {
	log.WithFields(log.Fields{"inPort": pair.inPort, "exPort": pair.exPort}).Debug("")
	var cmd string
	var ok bool
	var inInfo, exInfo *tcPortInfo
	if inInfo, ok = d.portMap[pair.inPort]; !ok {
		log.WithFields(log.Fields{"inPort": pair.inPort}).Error("No pref for inPort")
		return
	}
	if exInfo, ok = d.portMap[pair.exPort]; !ok {
		log.WithFields(log.Fields{"exPort": pair.exPort}).Error("No pref for exPort")
		return
	}

	// Ingress --
	// Bypass multicast
	// fmt.Sprintf("tc filter add dev %v pref %v parent ffff: protocol all "+
	// 	"u32 match u8 1 1 at -14 "+
	// 	"action mirred egress mirror dev %v", pair.exPort, tcPrefBase, pair.inPort)

	// Forward IP packet, forward unicast packet with DA to the workload
	cmd = fmt.Sprintf("tc filter add dev %v pref %v parent ffff: protocol ip "+
		"u32 match u8 0 1 at -14 "+
		"match u16 0x%02x%02x 0xffff at -14 match u32 0x%02x%02x%02x%02x 0xffffffff at -12 "+
		"action pedit munge offset -14 u16 set 0x%02x%02x munge offset -12 u32 set 0x%02x%02x%02x%02x pipe "+
		"action mirred egress mirror dev %v",
		pair.exPort, tcPrefBase+1,
		pair.MAC[0], pair.MAC[1], pair.MAC[2], pair.MAC[3], pair.MAC[4], pair.MAC[5],
		pair.UCMAC[0], pair.UCMAC[1], pair.UCMAC[2], pair.UCMAC[3], pair.UCMAC[4], pair.UCMAC[5],
		nvVbrPortName)
	if err := d.retryCmd(cmd); err != nil {
		log.WithFields(log.Fields{"exPort": pair.exPort}).Error("Cannot find port")
		return
	}

	// Forward the rest
	cmd = fmt.Sprintf("tc filter add dev %v pref %v parent ffff: protocol all "+
		"u32 match u8 0 0 "+
		"action mirred egress mirror dev %v",
		pair.exPort, tcPrefBase+2, pair.inPort)
	if err := d.retryCmd(cmd); err != nil {
		log.WithFields(log.Fields{"exPort": pair.exPort}).Error("Cannot find port")
		return
	}

	// Egress --
	// Bypass multicast
	// fmt.Sprintf("tc filter add dev %v pref %v parent ffff: protocol all "+
	// 	"u32 match u8 1 1 at -14 "+
	// 	"action mirred egress mirror dev %v", pair.inPort, tcPrefBase, pair.exPort)

	// Forward IP packet, forward unicast packet with SA from the workload
	cmd = fmt.Sprintf("tc filter add dev %v pref %v parent ffff: protocol ip "+
		"u32 match u8 0 1 at -14 "+
		"match u32 0x%02x%02x%02x%02x 0xffffffff at -8 match u16 0x%02x%02x 0xffff at -4 "+
		"action pedit munge offset -8 u32 set 0x%02x%02x%02x%02x munge offset -4 u16 set 0x%02x%02x pipe "+
		"action mirred egress mirror dev %v",
		pair.inPort, tcPrefBase+1,
		pair.MAC[0], pair.MAC[1], pair.MAC[2], pair.MAC[3], pair.MAC[4], pair.MAC[5],
		pair.UCMAC[0], pair.UCMAC[1], pair.UCMAC[2], pair.UCMAC[3], pair.UCMAC[4], pair.UCMAC[5],
		nvVbrPortName)
	if err := d.retryCmd(cmd); err != nil {
		log.WithFields(log.Fields{"inPort": pair.inPort}).Error("Cannot find port")
		return
	}

	// Forward the rest
	cmd = fmt.Sprintf("tc filter add dev %v pref %v parent ffff: protocol all "+
		"u32 match u8 0 0 "+
		"action mirred egress mirror dev %v",
		pair.inPort, tcPrefBase+2, pair.exPort)
	if err := d.retryCmd(cmd); err != nil {
		log.WithFields(log.Fields{"inPort": pair.inPort}).Error("Cannot find port")
		return
	}

	// Forward the packets from enforcer
	cmd = fmt.Sprintf("tc filter add dev %v pref %v parent ffff: protocol all "+
		"u32 match u16 0x%02x%02x 0xffff at -14 match u32 0x%02x%02x%02x%02x 0xffffffff at -12 "+
		"action pedit munge offset -14 u16 set 0x%02x%02x munge offset -12 u32 set 0x%02x%02x%02x%02x pipe "+
		"action mirred egress mirror dev %v",
		nvVbrPortName, exInfo.pref,
		pair.UCMAC[0], pair.UCMAC[1], pair.UCMAC[2], pair.UCMAC[3], pair.UCMAC[4], pair.UCMAC[5],
		pair.MAC[0], pair.MAC[1], pair.MAC[2], pair.MAC[3], pair.MAC[4], pair.MAC[5],
		pair.inPort)
	if _, dbgError := shell(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	cmd = fmt.Sprintf("tc filter add dev %v pref %v parent ffff: protocol all "+
		"u32 match u32 0x%02x%02x%02x%02x 0xffffffff at -8 match u16 0x%02x%02x 0xffff at -4 "+
		"action pedit munge offset -8 u32 set 0x%02x%02x%02x%02x munge offset -4 u16 set 0x%02x%02x pipe "+
		"action mirred egress mirror dev %v",
		nvVbrPortName, inInfo.pref,
		pair.UCMAC[0], pair.UCMAC[1], pair.UCMAC[2], pair.UCMAC[3], pair.UCMAC[4], pair.UCMAC[5],
		pair.MAC[0], pair.MAC[1], pair.MAC[2], pair.MAC[3], pair.MAC[4], pair.MAC[5],
		pair.exPort)
	if _, dbgError := shell(cmd); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
}

func (d *tcPipeDriver) GetPortPairRules(pair *InterceptPair) (string, string, string) {
	var cmd string
	var inEnfRules, exEnfRules []byte

	cmd = fmt.Sprintf("tc filter show dev %v parent ffff:", pair.inPort)
	inRules, _ := shellCombined(cmd)
	cmd = fmt.Sprintf("tc filter show dev %v parent ffff:", pair.exPort)
	exRules, _ := shellCombined(cmd)

	if inInfo, ok := d.portMap[pair.inPort]; ok {
		cmd = fmt.Sprintf("tc filter show dev %v pref %v parent ffff:", nvVbrPortName, inInfo.pref)
		inEnfRules, _ = shellCombined(cmd)
	}
	if exInfo, ok := d.portMap[pair.exPort]; ok {
		cmd = fmt.Sprintf("tc filter show dev %v pref %v parent ffff:", nvVbrPortName, exInfo.pref)
		exEnfRules, _ = shellCombined(cmd)
	}

	return strings.Replace(string(inRules[:]), "\t", "    ", -1),
		strings.Replace(string(exRules[:]), "\t", "    ", -1),
		strings.Replace(string(inEnfRules[:])+string(exEnfRules[:]), "\t", "    ", -1)
}

func (d *tcPipeDriver) Connect(jumboframe bool) {
	d.prefs = utils.NewSet()
	d.portMap = make(map[string]*tcPortInfo)

	link, _ := netlink.LinkByName(nvVbrPortName)
	if link != nil {
		d.delQDisc(nvVbrPortName)
		if dbgError := netlink.LinkSetDown(link); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
		if dbgError := netlink.LinkDel(link); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
		nap()
	}
	createNVPorts(jumboframe)
	d.addQDisc(nvVbrPortName)

	DisableOffload(nvVbrPortName)
}

func (d *tcPipeDriver) Cleanup() {
	link, _ := netlink.LinkByName(nvVbrPortName)
	if link != nil {
		d.delQDisc(nvVbrPortName)
		if dbgError := netlink.LinkSetDown(link); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
		if dbgError := netlink.LinkDel(link); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
	}
}

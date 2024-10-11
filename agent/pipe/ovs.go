package pipe

import (
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/codeskyblue/go-sh"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/neuvector/neuvector/share/libovsdb"
)

const defaultOVSSocket string = "/var/run/openvswitch/db.sock"
const defaultOVSRunTime string = "/var/run/openvswitch/"
const ovsBridgeName string = "br-neuv"

type ovsPipeDriver struct {
	ovsOFPort      uint
	ovsClient      *libovsdb.OvsdbClient
	ovsBridgeCache map[string]libovsdb.Row
	ovsPortCache   map[string]libovsdb.Row
	ovsIntfCache   map[string]libovsdb.Row
	ovsRootUUID    string
	ovsCacheMutex  sync.RWMutex
}

var ovsPipe ovsPipeDriver = ovsPipeDriver{}

func (d *ovsPipeDriver) ovsAttachPort(port string) uint {
	if !d.ovsPortExists(port) {
		if dbgError := d.ovsAddPort(ovsBridgeName, port, "veth"); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
	}

	ofPort := d.ovsGetOFPort(port)
	if ofPort == 0 {
		log.WithFields(log.Fields{
			"bridge": ovsBridgeName, "port": port,
		}).Error("Cannot find port")
	} else {
		log.WithFields(log.Fields{
			"bridge": ovsBridgeName, "port": port, "ofport": ofPort,
		}).Debug("Attached")
	}

	return ofPort
}

func (d *ovsPipeDriver) AttachPortPair(pair *InterceptPair) (net.HardwareAddr, net.HardwareAddr) {
	if !d.ovsPortExists(pair.inPort) {
		d.ovsAttachPort(pair.inPort)
	}
	if !d.ovsPortExists(pair.exPort) {
		d.ovsAttachPort(pair.exPort)
	}

	var ofPort uint
	ofPort = d.ovsGetOFPort(pair.inPort)
	if ofPort == 0 {
		log.WithFields(log.Fields{"port": pair.inPort}).Error("Failed to attach port")
	} else {
		log.WithFields(log.Fields{"port": pair.inPort, "ofport": ofPort}).Debug("Attached")
	}
	ofPort = d.ovsGetOFPort(pair.exPort)
	if ofPort == 0 {
		log.WithFields(log.Fields{"port": pair.exPort}).Error("Failed to attach port")
	} else {
		log.WithFields(log.Fields{"port": pair.exPort, "ofport": ofPort}).Debug("Attached")
	}

	// 4e:65:75:56 - NeuV
	var mac_str string
	ofport := d.ovsGetOFPort(pair.inPort)
	mac_str = fmt.Sprintf("4e:65:75:56:%02x:%02x", (ofport>>8)&0xff, ofport&0xff)
	ucmac, _ := net.ParseMAC(mac_str)
	mac_str = fmt.Sprintf("ff:ff:ff:00:%02x:%02x", (ofport>>8)&0xff, ofport&0xff)
	bcmac, _ := net.ParseMAC(mac_str)
	return ucmac, bcmac
}

func (d *ovsPipeDriver) DetachPortPair(pair *InterceptPair) {
	if dbgError := d.ovsDelPort(ovsBridgeName, pair.inPort); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	if dbgError := d.ovsDelPort(ovsBridgeName, pair.exPort); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
}

func (d *ovsPipeDriver) ResetPortPair(pid int, pair *InterceptPair) {
	log.WithFields(log.Fields{"inPort": pair.inPort, "exPort": pair.exPort}).Debug("")

	inOFPort := d.ovsGetOFPort(pair.inPort)
	exOFPort := d.ovsGetOFPort(pair.exPort)
	if inOFPort == 0 || exOFPort == 0 {
		log.Error("Unable to clear port pair flow.")
		return
	}

	d.ovsDelFlow(ovsBridgeName, fmt.Sprintf("table=0,in_port=%v", inOFPort))
	d.ovsDelFlow(ovsBridgeName, fmt.Sprintf("table=0,in_port=%v", exOFPort))

	d.ovsDelFlow(ovsBridgeName,
		fmt.Sprintf("table=0,in_port=%v,dl_src=%v", d.ovsOFPort, pair.UCMAC))
	d.ovsDelFlow(ovsBridgeName,
		fmt.Sprintf("table=0,in_port=%v,dl_dst=%v", d.ovsOFPort, pair.UCMAC))
}

func (d *ovsPipeDriver) TapPortPair(pid int, pair *InterceptPair) {
	log.WithFields(log.Fields{"inPort": pair.inPort, "exPort": pair.exPort}).Debug("")

	inOFPort := d.ovsGetOFPort(pair.inPort)
	exOFPort := d.ovsGetOFPort(pair.exPort)
	if inOFPort == 0 || exOFPort == 0 {
		log.Error("Unable to tap port pair.")
		return
	}

	/*
		// Egress broadcast
		// WL -> ff:ff:ff:ff:ff:ff ==> 00:00:00:[wl_BCMAC]-> ff:ff:ff:[wl_BCMAC]
		d.ovsAddFlow(ovsBridgeName, fmt.Sprintf("table=0,priority=20,cookie=%v,in_port=%v,"+
			"dl_dst=ff:ff:ff:ff:ff:ff,actions=%v,mod_dl_src:%v,mod_dl_dst:%v,%v",
			pid, pair.inOFPort, pair.exOFPort, pair.UCMAC, pair.BCMAC, d.ovsOFPort))
		// 00:00:00:[wl_BCMAC]-> ff:ff:ff:[wl_BCMAC] ==> drop
		d.ovsAddFlow(ovsBridgeName, fmt.Sprintf("table=0,priority=20,cookie=%v,in_port=%v,"+
			"dl_src=%v,dl_dst=%v,actions=",
			pid, d.ovsOFPort, pair.UCMAC, pair.mac))

		// Ingreee broadcast
		// X -> ff:ff:ff:ff:ff:ff ==> X -> ff:ff:ff:[wl_BCMAC]
		d.ovsAddFlow(ovsBridgeName, fmt.Sprintf("table=0,priority=20,cookie=%v,in_port=%v,"+
			"dl_dst=ff:ff:ff:ff:ff:ff,actions=%v,mod_dl_dst:%v,%v",
			pid, pair.exOFPort, pair.inOFPort, pair.BCMAC, d.ovsOFPort))
		// X -> ff:ff:ff:[wl_BCMAC] ==> drop
		d.ovsAddFlow(ovsBridgeName, fmt.Sprintf("table=0,priority=20,cookie=%v,in_port=%v,dl_dst=%v,"+
			"actions=",
			pid, d.ovsOFPort, pair.BCMAC))
	*/

	// Multicast, bypass dp
	d.ovsAddFlow(ovsBridgeName, fmt.Sprintf("table=0,priority=10,cookie=%v,in_port=%v,"+
		"dl_dst=01:00:00:00:00:00/01:00:00:00:00:00,actions=%v",
		pid, inOFPort, exOFPort))
	d.ovsAddFlow(ovsBridgeName, fmt.Sprintf("table=0,priority=10,cookie=%v,in_port=%v,"+
		"dl_dst=01:00:00:00:00:00/01:00:00:00:00:00,actions=%v",
		pid, exOFPort, inOFPort))

	// Egress unicast
	// WL -> X ==> 00:00:00:[wl_UCMAC] -> X
	d.ovsAddFlow(ovsBridgeName, fmt.Sprintf("table=0,priority=0,cookie=%v,in_port=%v,"+
		"actions=%v,mod_dl_src:%v,%v",
		pid, inOFPort, exOFPort, pair.UCMAC, d.ovsOFPort))
	// 00:00:00:[wl_UCMAC] -> X ==> drop
	d.ovsAddFlow(ovsBridgeName, fmt.Sprintf("table=0,priority=0,cookie=%v,in_port=%v,dl_src=%v,actions=",
		pid, d.ovsOFPort, pair.UCMAC))

	// Ingress unicast
	// X -> WL ==> X -> 00:00:00:[wl_UCMAC]
	// In case that docker bridge broadcast an IP packet, we only forward the packet with
	// matching MAC to us, otherwise, the session will mismatch IP and MAC
	d.ovsAddFlow(ovsBridgeName, fmt.Sprintf("table=0,priority=5,cookie=%v,in_port=%v,dl_dst=%v,"+
		"actions=%v,mod_dl_dst:%v,%v",
		pid, exOFPort, pair.MAC, inOFPort, pair.UCMAC, d.ovsOFPort))
	d.ovsAddFlow(ovsBridgeName, fmt.Sprintf("table=0,priority=0,cookie=%v,in_port=%v,actions=%v",
		pid, exOFPort, inOFPort))
	// X -> 00:00:00:[wl_UCMAC] ==> drop
	d.ovsAddFlow(ovsBridgeName, fmt.Sprintf("table=0,priority=0,cookie=%v,in_port=%v,dl_dst=%v,actions=",
		pid, d.ovsOFPort, pair.UCMAC))
}

func (d *ovsPipeDriver) FwdPortPair(pid int, pair *InterceptPair) {
	log.WithFields(log.Fields{"inPort": pair.inPort, "exPort": pair.exPort}).Debug("")

	inOFPort := d.ovsGetOFPort(pair.inPort)
	exOFPort := d.ovsGetOFPort(pair.exPort)
	if inOFPort == 0 || exOFPort == 0 {
		log.Error("Unable to forward port pair.")
		return
	}

	/*
		// Egress broadcast
		// WL -> ff:ff:ff:ff:ff:ff ==> 00:00:00:[wl_BCMAC]-> ff:ff:ff:[wl_BCMAC]
		d.ovsAddFlow(ovsBridgeName, fmt.Sprintf("table=0,priority=20,cookie=%v,in_port=%v,"+
			"dl_dst=ff:ff:ff:ff:ff:ff,actions=mod_dl_src:%v,mod_dl_dst:%v,%v",
			pid, pair.inOFPort, pair.UCMAC, pair.BCMAC, d.ovsOFPort))
		// 00:00:00:[wl_BCMAC]-> ff:ff:ff:[wl_BCMAC] ==> WL -> ff:ff:ff:ff:ff:ff
		d.ovsAddFlow(ovsBridgeName, fmt.Sprintf("table=0,priority=20,cookie=%v,in_port=%v,"+
			"dl_src=%v,dl_dst=%v,actions=mod_dl_src:%v,mod_dl_dst:ff:ff:ff:ff:ff:ff,%v",
			pid, d.ovsOFPort, pair.UCMAC, pair.pair.mac, pair.mac, pair.exOFPort))

		// Ingreee broadcast
		// X -> ff:ff:ff:ff:ff:ff ==> X -> ff:ff:ff:[wl_BCMAC]
		d.ovsAddFlow(ovsBridgeName, fmt.Sprintf("table=0,priority=20,cookie=%v,in_port=%v,"+
			"dl_dst=ff:ff:ff:ff:ff:ff,actions=mod_dl_dst:%v,%v",
			pid, pair.exOFPort, pair.BCMAC, d.ovsOFPort))
		// X -> ff:ff:ff:[wl_BCMAC] ==> X -> ff:ff:ff:ff:ff:ff
		d.ovsAddFlow(ovsBridgeName, fmt.Sprintf("table=0,priority=20,cookie=%v,in_port=%v,"+
			"dl_dst=%v,actions=mod_dl_dst:ff:ff:ff:ff:ff:ff,%v",
			pid, d.ovsOFPort, pair.BCMAC, pair.inOFPort))
	*/

	// Multicast, bypass dp
	d.ovsAddFlow(ovsBridgeName, fmt.Sprintf("table=0,priority=10,cookie=%v,in_port=%v,"+
		"dl_dst=01:00:00:00:00:00/01:00:00:00:00:00,actions=%v",
		pid, inOFPort, exOFPort))
	d.ovsAddFlow(ovsBridgeName, fmt.Sprintf("table=0,priority=10,cookie=%v,in_port=%v,"+
		"dl_dst=01:00:00:00:00:00/01:00:00:00:00:00,actions=%v",
		pid, exOFPort, inOFPort))

	// Egress unicast
	// WL -> X ==> 00:00:00:[wl_UCMAC] -> X
	d.ovsAddFlow(ovsBridgeName, fmt.Sprintf("table=0,priority=0,cookie=%v,in_port=%v,"+
		"actions=mod_dl_src:%v,%v",
		pid, inOFPort, pair.UCMAC, d.ovsOFPort))
	// 00:00:00:[wl_UCMAC] -> X ==> WL -> X
	d.ovsAddFlow(ovsBridgeName, fmt.Sprintf("table=0,priority=0,cookie=%v,in_port=%v,dl_src=%v,"+
		"actions=mod_dl_src:%v,%v",
		pid, d.ovsOFPort, pair.UCMAC, pair.MAC, exOFPort))

	// Ingress unicast
	// X -> WL ==> X -> 00:00:00:[wl_UCMAC]
	// In case that docker bridge broadcast an IP packet, we only forward the packet with
	// matching MAC to us, otherwise, the session will mismatch IP and MAC
	d.ovsAddFlow(ovsBridgeName, fmt.Sprintf("table=0,priority=5,cookie=%v,in_port=%v,dl_dst=%v,"+
		"actions=mod_dl_dst:%v,%v",
		pid, exOFPort, pair.MAC, pair.UCMAC, d.ovsOFPort))
	d.ovsAddFlow(ovsBridgeName, fmt.Sprintf("table=0,priority=0,cookie=%v,in_port=%v,actions=%v",
		pid, exOFPort, inOFPort))
	// X -> 00:00:00:[wl_UCMAC] ==> X -> WL
	d.ovsAddFlow(ovsBridgeName, fmt.Sprintf("table=0,priority=0,cookie=%v,in_port=%v,dl_dst=%v,"+
		"actions=mod_dl_dst:%v,%v",
		pid, d.ovsOFPort, pair.UCMAC, pair.MAC, inOFPort))
}

func (d *ovsPipeDriver) GetPortPairRules(pair *InterceptPair) (string, string, string) {
	return "", "", ""
}

// TODO: port name max length is 15. What if the original port has a long name.
func ovsKernelModuleLoaded() bool {
	output, err := sh.Command("lsmod").Command("grep", "openvswitch").Output()
	if err != nil || len(output) == 0 {
		log.Debug("OVS kenel module not loaded")
		return false
	}

	log.Debug("OVS kenel module loaded")
	return true
}

/* removed by golint
func ovsDaemonPid() (int, error) {
	output, err := shell("pgrep ovs-vswitchd")
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		return 0, err
	}

	s := strings.TrimSpace(string(output[:]))
	if len(s) == 0 {
		return 0, nil
	}

	return strconv.Atoi(s)
}
*/

func (d *ovsPipeDriver) ovsBridgeExists(br string) bool {
	d.ovsCacheMutex.RLock()
	defer d.ovsCacheMutex.RUnlock()

	for _, row := range d.ovsBridgeCache {
		if br == row.Fields["name"].(string) {
			return true
		}
	}
	return false
}

func (d *ovsPipeDriver) ovsPortExists(port string) bool {
	d.ovsCacheMutex.RLock()
	defer d.ovsCacheMutex.RUnlock()

	for _, row := range d.ovsIntfCache {
		if port == row.Fields["name"].(string) {
			return true
		}
	}
	return false
}

/* removed by golint
func (d *ovsPipeDriver) ovsGetUUIDByName(port string) string {
	for uuid, row := range d.ovsPortCache {
		if port == row.Fields["name"].(string) {
			return uuid
		}
	}
	return ""
}
*/

func (d *ovsPipeDriver) ovsGetRowOFPort(row *libovsdb.Row) uint {
	switch row.Fields["ofport"].(type) {
	case float64:
		return uint(row.Fields["ofport"].(float64))
	}

	return 0
}

func (d *ovsPipeDriver) ovsBridgeSocket(br string) string {
	return fmt.Sprintf("unix://%s%s.mgmt", defaultOVSRunTime, br)
}

func (d *ovsPipeDriver) ovsGetOFPortFromCache(port string) uint {
	for _, row := range d.ovsIntfCache {
		if row.Fields["name"] == port {
			if ofport := d.ovsGetRowOFPort(&row); ofport > 0 {
				return ofport
			}
		}
	}

	return 0
}

func (d *ovsPipeDriver) ovsGetOFPort(port string) uint {
	var ofPort uint

	// wait max. 8s
	for i := 0; i < 32; i++ {
		d.ovsCacheMutex.RLock()
		ofPort = d.ovsGetOFPortFromCache(port)
		d.ovsCacheMutex.RUnlock()
		if ofPort > 0 {
			return ofPort
		}
		nap()
	}
	return 0
}

func (d *ovsPipeDriver) ovsCreateBridge(bridgeName string) error {
	log.WithFields(log.Fields{"bridge": bridgeName}).Debug("")
	if _, dbgError := shell(fmt.Sprintf("ovs-vsctl add-br %v", bridgeName)); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	if !ovsKernelModuleLoaded() {
		if _, dbgError := shell(fmt.Sprintf("ovs-vsctl set bridge %v datapath_type=netdev", bridgeName)); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
	}
	return nil
}

func (d *ovsPipeDriver) ovsDelBridge(bridgeName string) error {
	log.WithFields(log.Fields{"bridge": bridgeName}).Debug("")
	if _, dbgError := shell(fmt.Sprintf("ovs-vsctl del-br %v", bridgeName)); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	return nil
}

func (d *ovsPipeDriver) ovsAddPort(bridgeName string, portName string, portType string) error {
	log.WithFields(log.Fields{
		"bridge": bridgeName, "port": portName, "portType": portType,
	}).Debug("")

	if portType == "internal" {
		if _, dbgError := shell(fmt.Sprintf("ovs-vsctl add-port %v %v -- set interface %v type=internal",
			bridgeName, portName, portName)); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
	} else {
		if _, dbgError := shell(fmt.Sprintf("ovs-vsctl add-port %v %v", bridgeName, portName)); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
	}
	return nil
}

func (d *ovsPipeDriver) ovsDelPort(bridgeName string, portName string) error {
	log.WithFields(log.Fields{"bridge": bridgeName, "port": portName}).Debug("")
	if _, dbgError := shell(fmt.Sprintf("ovs-vsctl del-port %v %v", bridgeName, portName)); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	return nil
}

func (d *ovsPipeDriver) ovsPopulateCache(updates *libovsdb.TableUpdates) {
	d.ovsCacheMutex.Lock()
	defer d.ovsCacheMutex.Unlock()

	empty := libovsdb.Row{}
	if update, ok := updates.Updates["Port"]; ok {
		for uuid, row := range update.Rows {
			if !reflect.DeepEqual(row.New, empty) {
				if _, ok := d.ovsPortCache[uuid]; !ok {
					log.WithFields(log.Fields{"port": row.New.Fields["name"]}).Debug("Update")
				}
				d.ovsPortCache[uuid] = row.New
			} else if row, ok := d.ovsPortCache[uuid]; ok {
				log.WithFields(log.Fields{"port": row.Fields["name"]}).Debug("Delete")
				delete(d.ovsPortCache, uuid)
			}
		}
	}
	if update, ok := updates.Updates["Interface"]; ok {
		for uuid, row := range update.Rows {
			if !reflect.DeepEqual(row.New, empty) {
				if old, ok := d.ovsIntfCache[uuid]; ok {
					// Sometimes "interface" update have an ofport=0 entry coming after non-zero
					// entry. Don't overwrite non-zero value.
					d.ovsIntfCache[uuid] = row.New
					ofport := d.ovsGetRowOFPort(&old)
					if ofport > 0 && d.ovsGetRowOFPort(&row.New) == 0 {
						d.ovsIntfCache[uuid].Fields["ofport"] = old.Fields["ofport"]
					}
				} else {
					d.ovsIntfCache[uuid] = row.New
					log.WithFields(log.Fields{
						"uuid":   uuid,
						"iface":  row.New.Fields["name"],
						"ofport": d.ovsGetOFPortFromCache(row.New.Fields["name"].(string)),
					}).Debug("Add")
				}
			} else if row, ok := d.ovsIntfCache[uuid]; ok {
				log.WithFields(log.Fields{"iface": row.Fields["name"]}).Debug("")
				delete(d.ovsIntfCache, uuid)
			}
		}
	}
	if update, ok := updates.Updates["Bridge"]; ok {
		for uuid, row := range update.Rows {
			if !reflect.DeepEqual(row.New, empty) {
				if _, ok := d.ovsBridgeCache[uuid]; !ok {
					log.WithFields(log.Fields{"bridge": row.New.Fields["name"]}).Debug("Update")
				}
				d.ovsBridgeCache[uuid] = row.New
			} else if row, ok := d.ovsBridgeCache[uuid]; ok {
				log.WithFields(log.Fields{"bridge": row.Fields["name"]}).Debug("Delete")
				delete(d.ovsBridgeCache, uuid)
			}
		}
	}
	if update, ok := updates.Updates["Open_vSwitch"]; ok {
		for uuid, row := range update.Rows {
			if !reflect.DeepEqual(row.New, empty) {
				d.ovsRootUUID = uuid
				break
			}
		}
	}
}

func (d *ovsPipeDriver) ovsSetup(jumboframe bool) {
	if d.ovsBridgeExists(ovsBridgeName) {
		if dbgError := d.ovsDelBridge(ovsBridgeName); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
	}

	if dbgError := d.ovsCreateBridge(ovsBridgeName); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	nap()
	nap()

	// Internal port doesn't seem to work in userspace OVS
	/*
		if link, _ := netlink.LinkByName(OVSInPortName); link != nil {
			if !ovsPortExists(OVSInPortName) {
				log.WithFields(log.Fields{
					"port": OVSInPortName,
				}).Error("Service port exist but not on the OVS bridge")
			}
		} else {
			OVSAddPort(ovsBridgeName, OVSInPortName, "internal")
		}

		if link, _ := netlink.LinkByName(OVSExPortName); link != nil {
			if !ovsPortExists(OVSExPortName) {
				log.WithFields(log.Fields{
					"port": OVSExPortName,
				}).Error("Service port exist but not on the OVS bridge")
			}
		} else {
			OVSAddPort(ovsBridgeName, OVSExPortName, "internal")
		}
	*/

	link, _ := netlink.LinkByName(nvVbrPortName)
	if link != nil {
		if dbgError := d.ovsDelPort(ovsBridgeName, nvVbrPortName); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
		if dbgError := netlink.LinkSetDown(link); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
		if dbgError := netlink.LinkDel(link); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
		nap()
	}
	createNVPorts(jumboframe)

	// Add to ovs
	if !d.ovsPortExists(nvVbrPortName) {
		if dbgError := d.ovsAddPort(ovsBridgeName, nvVbrPortName, "veth"); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
	}

	nap()

	DisableOffload(nvVbrPortName)

	d.ovsDelAllFlows(ovsBridgeName)
}

func (d *ovsPipeDriver) Cleanup() {
	link, _ := netlink.LinkByName(nvVbrPortName)
	if link != nil {
		if dbgError := d.ovsDelPort(ovsBridgeName, nvVbrPortName); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
		if dbgError := netlink.LinkSetDown(link); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
		if dbgError := netlink.LinkDel(link); dbgError != nil {
			log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
		}
	}
	if dbgError := d.ovsDelBridge(ovsBridgeName); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
}

func (d *ovsPipeDriver) ovsAddFlow(bridgeName string, flow string) {
	if _, dbgError := shell(fmt.Sprintf("ovs-ofctl add-flow %v %v", d.ovsBridgeSocket(bridgeName), flow)); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
}

func (d *ovsPipeDriver) ovsDelFlow(bridgeName string, flow string) {
	if _, dbgError := shell(fmt.Sprintf("ovs-ofctl del-flows %v %v", d.ovsBridgeSocket(bridgeName), flow)); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
}

func (d *ovsPipeDriver) ovsDelAllFlows(bridgeName string) {
	if _, dbgError := shell(fmt.Sprintf("ovs-ofctl del-flows %v", d.ovsBridgeSocket(bridgeName))); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
}

func (d *ovsPipeDriver) Connect(jumboframe bool) {
	log.Debug("Connecting to local OVS ...")

	d.ovsBridgeCache = make(map[string]libovsdb.Row)
	d.ovsPortCache = make(map[string]libovsdb.Row)
	d.ovsIntfCache = make(map[string]libovsdb.Row)

	var err error
	for d.ovsClient == nil {
		d.ovsClient, err = libovsdb.ConnectUnix(defaultOVSSocket)
		if err != nil {
			log.Errorf("error %v\n", err)
			time.Sleep(time.Second * 5)
		}
	}

	log.Debug("OVS connected")

	notifier := ovsNotifier{ovs: &ovsPipe}
	d.ovsClient.Register(notifier)

	initial, _ := d.ovsClient.MonitorAll("Open_vSwitch", "")
	d.ovsPopulateCache(initial)

	d.ovsSetup(jumboframe)

	for {
		d.ovsOFPort = d.ovsGetOFPort(nvVbrPortName)
		if d.ovsOFPort != 0 {
			log.WithFields(log.Fields{"port": nvVbrPortName, "index": d.ovsOFPort}).Debug("")
			break
		}

		log.WithFields(log.Fields{"port": nvVbrPortName, "index": d.ovsOFPort}).Error("Wait...")
		time.Sleep(time.Second * 2)
	}

	log.Debug("Listening for ovs updates ...")
}

type ovsNotifier struct {
	ovs *ovsPipeDriver
}

func (n ovsNotifier) Update(context interface{}, tableUpdates libovsdb.TableUpdates) {
	n.ovs.ovsPopulateCache(&tableUpdates)
}

func (n ovsNotifier) Disconnected(ovsClient *libovsdb.OvsdbClient) {
}

func (n ovsNotifier) Locked([]interface{}) {
}

func (n ovsNotifier) Stolen([]interface{}) {
}

func (n ovsNotifier) Echo([]interface{}) {
}

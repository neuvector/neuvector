package main

import (
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/global"
	sk "github.com/neuvector/neuvector/share/system/sidekick"
	"github.com/neuvector/neuvector/share/utils"
)

func getHostAddrs() map[string]sk.NetIface {
	var ifaces map[string]sk.NetIface

	dbgError := global.SYS.CallNetNamespaceFunc(1, func(params interface{}) {
		ifaces = sk.GetGlobalAddrs()
	}, nil)
	if dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}

	return ifaces
}

func getHostLinks() map[string]bool {
	var linkAttrs map[string]sk.NetLinkAttrs
	links := make(map[string]bool)

	dbgError := global.SYS.CallNetNamespaceFunc(1, func(params interface{}) {
		linkAttrs = sk.GetNetLinkAttrs()
	}, nil)
	if dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}

	for name, linkAttr := range linkAttrs {
		links[name] = linkAttr.OperState
	}

	return links
}

/*
With Azure advanced networking plugin:
 link - link=eth0 type=device
 link - link=docker0 type=bridge
 Switch - ipnet={IP:172.17.0.1 Mask:ffff0000} link=docker0
 link - link=enP1p0s2 type=device
 link - link=azure0 type=bridge
 Switch - ipnet={IP:10.240.0.35 Mask:ffff0000} link=azure0
 link - link=azv1769de20eea type=veth
 link - link=lo type=device

 2: eth0: <BROADCAST,UP,LOWER_UP> mtu 1500 qdisc mq master azure0 state UP qlen 1000
 5: azure0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP qlen 1000
*/

func parseHostAddrs(ifaces map[string]sk.NetIface, platform, flavor, network string) (map[string][]share.CLUSIPAddr, utils.Set, bool, bool) {
	devs := make(map[string][]share.CLUSIPAddr)
	ips := utils.NewSet()
	maxMTU := 0
	ciliumCNI := false

	for name, iface := range ifaces {
		log.WithFields(log.Fields{"link": name, "type": iface.Type, "mtu": iface.Mtu, "flags": iface.Flags}).Info("link")

		if strings.HasPrefix(name, "cilium") {
			ciliumCNI = true
		}

		if iface.Mtu <= share.NV_VBR_PORT_MTU_JUMBO && maxMTU < iface.Mtu {
			maxMTU = iface.Mtu
		}
		if iface.Type == "device" || iface.Type == "bond" || iface.Type == "vlan" {
			for _, addr := range iface.Addrs {
				if utils.IsIPv4(addr.IPNet.IP) {
					log.WithFields(log.Fields{"link": name, "ipnet": addr.IPNet}).Info("Global")
					devs[name] = append(devs[name], share.CLUSIPAddr{
						IPNet: addr.IPNet,
						Scope: share.CLUSIPAddrScopeNAT,
					})
					ips.Add(addr.IPNet.IP.String())
				}
			}
		} else if iface.Type == "bridge" || iface.Type == "openvswitch" {
			if iface.Type == "openvswitch" && (flavor != share.FlavorOpenShift || name != "br-ex") {
				continue
			}
			if platform == share.PlatformKubernetes && strings.HasPrefix(name, "cni") {
				continue
			}
			//kube-router CNI
			if platform == share.PlatformKubernetes && name == "kube-bridge" {
				continue
			}

			for _, addr := range iface.Addrs {
				if utils.IsIPv4(addr.IPNet.IP) && !addr.IPNet.IP.IsLinkLocalUnicast() { //169.254.x.x IP should not be included
					log.WithFields(log.Fields{"link": name, "ipnet": addr.IPNet}).Info("Switch")
					if name == "azure0" || name == "mgmt-br" || (iface.Type == "openvswitch" && name == "br-ex") {
						devs[name] = append(devs[name], share.CLUSIPAddr{
							IPNet: addr.IPNet,
							Scope: share.CLUSIPAddrScopeNAT,
						})
					}
					ips.Add(addr.IPNet.IP.String())
				}
			}
		}
	}
	log.WithFields(log.Fields{"maxMTU": maxMTU, "ciliumCNI": ciliumCNI}).Info("")
	if maxMTU > share.NV_VBR_PORT_MTU { //jumbo frame mtu
		return devs, ips, true, ciliumCNI
	} else {
		return devs, ips, false, ciliumCNI
	}
}

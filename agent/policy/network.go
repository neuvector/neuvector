package policy

// #include "../../defs.h"
import "C"

import (
	"encoding/json"
	"bytes"
	"fmt"
	"net"
	"reflect"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/neuvector/neuvector/agent/dp"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

type fqdnInfo struct {
	ips  []net.IP
	used bool
}

var fqdnMap map[string]*fqdnInfo = make(map[string]*fqdnInfo)

func isWorkloadFqdn(wl string) bool {
	return strings.HasPrefix(wl, share.CLUSWLFqdnPrefix)
}

func getFqdnName(wl string) string {
	//fqdn domain name should be case insensitive
	return strings.ToLower(wl[len(share.CLUSWLFqdnPrefix):])
}

func getFqdnIP(name string) []net.IP {
	if info, ok := fqdnMap[name]; ok {
		info.used = true
		return info.ips
	}

	ret := make([]net.IP, 0)
	if strings.HasPrefix(name, "*") {
		ret = append(ret, net.IPv4zero)
	} else {
		ips, err := utils.ResolveIP(name)
		if err != nil || ips == nil {
			log.WithFields(log.Fields{"domain": name, "err": err}).Error("Fail to resolve")
			// Put a zero entry as place holder
			ret = append(ret, net.IPv4zero)
		} else {
			for _, ip := range ips {
				if utils.IsIPv4(ip) {
					ret = append(ret, ip)
				}
			}
		}
	}
	fqdnMap[name] = &fqdnInfo{ips: ret, used: true}
	return ret
}

func isWorkloadIP(wl string) bool {
	if strings.HasPrefix(wl, share.CLUSLearnedWorkloadPrefix) {
		if names := strings.Split(wl, share.CLUSLearnedWorkloadPrefix); len(names) == 2 {
			if names[1] != share.CLUSEndpointIngress && net.ParseIP(names[1]) != nil {
				return true
			}
		}
	}
	return false
}

func isHostRelated(addr *share.CLUSWorkloadAddr) bool {
	if strings.HasPrefix(addr.WlID, share.CLUSLearnedHostPrefix) {
		return true
	} else if addr.NatPortApp != nil && len(addr.NatPortApp) > 0 {
		return true
	}
	return false
}

func isSameHostEP(wl, hid string) bool {
	return wl == fmt.Sprintf("%s%s", share.CLUSLearnedHostPrefix, hid)
}

func fqdnInfoPrePolicyCalc() {
	for _, info := range fqdnMap {
		info.used = false
	}
}

func fqdnInfoPostPolicyCalc(hid string) {
	del := make([]string, 0)
	for name, info := range fqdnMap {
		if info.used == false {
			del = append(del, name)
		}
	}
	if len(del) > 0 && dp.DPCtrlDeleteFqdn(del) == 0 {
		for _, name := range del {
			if strings.HasPrefix(name, "*") {//wildcard
				rule_key := share.CLUSFqdnIpKey(hid, name)
				if cluster.Exist(rule_key) {
					cluster.Delete(rule_key)
				}
			}
			delete(fqdnMap, name)
		}
	}

	if len(fqdnMap) > C.DP_POLICY_FQDN_MAX_ENTRIES {
		// Todo: trigger event logging
		log.WithFields(log.Fields{
			"capcity": C.DP_POLICY_FQDN_MAX_ENTRIES, "used": len(fqdnMap),
		}).Error("Domain exceeds capacity")
	}
}

func getDerivedAppRule(port string, appRule *dp.DPPolicyApp) *dp.DPPolicyApp {

	/*
	 * for some app, we cannot reliablely identify the app from packet
	 * loose the rule to unknown app as well
	 */
	// Now this is done at control - 09/25/2017
	/*
		if appRule.App == C.DPI_APP_CONSUL && strings.Contains(port, "any") == false {
			derivedAppRule := &dp.DPPolicyApp{
				App:    C.DP_POLICY_APP_UNKNOWN,
				Action: appRule.Action,
				RuleID: appRule.RuleID,
			}
			return derivedAppRule
		}
	*/
	return nil
}

type ruleContext struct {
	ingress bool
	id      uint32
	fqdn    string
}

func createIPRule(from, to, fromR, toR net.IP, portApps []share.CLUSPortApp, action uint8,
	pInfo *WorkloadIPPolicyInfo, ctx *ruleContext) {

	id := ctx.id

	/*
		log.WithFields(log.Fields{
			"id": id, "from": from, "to": to, "fromR": fromR, "toR": toR,
			"portApps": portApps, "action": action, "domain": ctx.fqdn,
		}).Debug("")
	*/
	if portApps == nil {
		/*log.WithFields(log.Fields{
			"id": id, "from": from, "to": to, "portApps": "nil",
		}).Debug("invalid rule!")*/
		return
	}

	for _, portApp := range portApps {
		ports := portApp.Ports
		portList := strings.Split(ports, ",")
		for _, ap := range portList {
			var key string
			if ctx.ingress == true {
				key = fmt.Sprintf("%v%v%s%s%d", from, to, ap, ctx.fqdn, 1)
			} else {
				key = fmt.Sprintf("%v%v%s%s%d", from, to, ap, ctx.fqdn, 0)
			}
			if fromR != nil {
				key = fmt.Sprintf("%s%v", key, fromR)
			}
			if toR != nil {
				key = fmt.Sprintf("%s%v", key, toR)
			}

			if existRule, ok := pInfo.RuleMap[key]; ok {
				// rule already exists, merge if needed
				if existRule.Action != C.DP_POLICY_ACTION_CHECK_APP {
					continue
				}
				if id != 0 {
					var found bool = false
					for _, app := range existRule.Apps {
						if app.App == portApp.Application {
							found = true
							break
						}
					}
					if found == false {
						appRule := &dp.DPPolicyApp{
							App:    portApp.Application,
							Action: action,
							RuleID: id,
						}
						existRule.Apps = append(existRule.Apps, appRule)
						derivedAppRule := getDerivedAppRule(ap, appRule)
						if derivedAppRule != nil {
							existRule.Apps = append(existRule.Apps, derivedAppRule)
						}
					}
					continue
				}
			}

			proto, p, pr, err := utils.ParsePortRangeLink(ap)
			if err != nil {
				log.WithFields(log.Fields{
					"id": id, "from": from, "to": to, "ports": ap,
				}).Error("Fail to parse!")
				continue
			}
			rule := dp.DPPolicyIPRule{
				ID:      id,
				SrcIP:   from,
				DstIP:   to,
				SrcIPR:  fromR,
				DstIPR:  toR,
				Port:    p,
				PortR:   pr,
				IPProto: proto,
				Action:  action,
				Ingress: ctx.ingress,
				Fqdn:    ctx.fqdn,
			}

			// For host mode container, only check ports, not applications.
			if !pInfo.HostMode && portApp.CheckApp == true {
				appRule := &dp.DPPolicyApp{
					App:    portApp.Application,
					Action: action,
					RuleID: id,
				}
				rule.Apps = append(rule.Apps, appRule)
				derivedAppRule := getDerivedAppRule(ap, appRule)
				if derivedAppRule != nil {
					rule.Apps = append(rule.Apps, derivedAppRule)
				}
				rule.Action = C.DP_POLICY_ACTION_CHECK_APP
			}
			pInfo.Policy.IPRules = append(pInfo.Policy.IPRules, &rule)
			pInfo.RuleMap[key] = &rule
		}
	}
}

func adjustAction(action uint8, from, to *share.CLUSWorkloadAddr, id uint32) uint8 {
	var adjustedAction uint8 = action
	fromMode := from.PolicyMode
	toMode := to.PolicyMode

	switch fromMode {
	case share.PolicyModeLearn:
		if action == C.DP_POLICY_ACTION_DENY {
			adjustedAction = C.DP_POLICY_ACTION_VIOLATE
		} else if id >= share.PolicyLearnedIDBase && id < share.PolicyFedRuleIDBase {
			adjustedAction = C.DP_POLICY_ACTION_LEARN
		}
	case share.PolicyModeEvaluate:
		if action == C.DP_POLICY_ACTION_DENY {
			adjustedAction = C.DP_POLICY_ACTION_VIOLATE
		} else if toMode == share.PolicyModeLearn && id >= share.PolicyLearnedIDBase && id < share.PolicyFedRuleIDBase {
			// Assume learn rule action is always ALLOW, so the original action
			// is not checked here
			adjustedAction = C.DP_POLICY_ACTION_LEARN
		}
	case share.PolicyModeEnforce:
		if toMode == share.PolicyModeLearn && id >= share.PolicyLearnedIDBase && id < share.PolicyFedRuleIDBase {
			adjustedAction = C.DP_POLICY_ACTION_LEARN
		}
	case "":
		// src has no policy mode - meaning it's not a managed container
		switch toMode {
		case share.PolicyModeLearn:
			if action == C.DP_POLICY_ACTION_DENY {
				adjustedAction = C.DP_POLICY_ACTION_VIOLATE
			} else if id >= share.PolicyLearnedIDBase && id < share.PolicyFedRuleIDBase {
				adjustedAction = C.DP_POLICY_ACTION_LEARN
			}
		case share.PolicyModeEvaluate:
			if action == C.DP_POLICY_ACTION_DENY {
				adjustedAction = C.DP_POLICY_ACTION_VIOLATE
			}
		case share.PolicyModeEnforce:
		case "":
			log.WithFields(log.Fields{
				"id": id, "from": from.WlID, "to": to.WlID,
			}).Error("Missing policy mode for both src and dst!")
		default:
			log.WithFields(log.Fields{"id": id, "to": *to}).Error("Invalid policy mode!")
		}
	default:
		log.WithFields(log.Fields{"id": id, "from": *from}).Error("Invalid policy mode!")
	}
	//log.WithFields(log.Fields{"id": id, "from": *from, "to": *to, "action": action,
	//           "adjustedAction": adjustedAction,}).Debug("")
	return adjustedAction
}

func (e *Engine) createWorkloadRule(from, to *share.CLUSWorkloadAddr, policy *share.CLUSGroupIPPolicy,
	pInfo *WorkloadIPPolicyInfo, ingress, sameHost bool) {

	action := adjustAction(policy.Action, from, to, policy.ID)

	// deny cannot be enforced for non-interceptable container
	if !pInfo.CapIntcp && action == C.DP_POLICY_ACTION_DENY {
		action = C.DP_POLICY_ACTION_VIOLATE
	}

	ctx := &ruleContext{ingress: ingress, id: policy.ID}
	if ingress == false && isWorkloadFqdn(to.WlID) {
		ctx.fqdn = getFqdnName(to.WlID)
	} else if ingress == true && isWorkloadFqdn(from.WlID) {
		ctx.fqdn = getFqdnName(from.WlID)
	}

	if ingress == false {
		var fromIPList []net.IP

		if pInfo.HostMode {
			// for host mode container, we will not check src ip
			if len(from.NatIP) == 0 {
				// Supress the log, a host mode container in the exit state can trigger this forever
				// log.WithFields(log.Fields{"from": from.WlID}).Debug("Missing ip for host mode container!")
				return
			}
			fromIPList = from.NatIP[:1]
		} else {
			fromIPList = from.LocalIP
		}

		for _, ipFrom := range fromIPList {
			if sameHost {
				for _, ipTo := range to.LocalIP {
					createIPRule(ipFrom, ipTo, nil, nil, to.LocalPortApp, action, pInfo, ctx)
				}
			}

			// For host mode container, the address will be set to NatIP even though the system
			// can be a global ip system (such as k8s).  So add the rule from the host
			// ip to global here as well.
			if pInfo.HostMode {
				for _, ipTo := range to.GlobalIP {
					createIPRule(ipFrom, ipTo, nil, nil, to.LocalPortApp, action, pInfo, ctx)
				}
			}

			if to.NatPortApp == nil {
				continue
			}

			if to.WlID == share.CLUSWLAddressGroup || to.WlID == share.CLUSHostAddrGroup {
				for i := 0; i < len(to.NatIP); i += 2 {
					createIPRule(ipFrom, to.NatIP[i], nil, to.NatIP[i+1], to.NatPortApp, action, pInfo, ctx)
				}
				if to.WlID == share.CLUSHostAddrGroup {
					//NVSHAS-5205, destination is 'nodes', for local host
					//add the rule to all other local/bridge ip as well
					for _, addr := range e.HostIPs.ToSlice() {
						createIPRule(ipFrom, net.ParseIP(addr.(string)), nil, nil, to.NatPortApp,
							action, pInfo, ctx)
					}
				}
			} else {
				for _, ipTo := range to.NatIP {
					createIPRule(ipFrom, ipTo, nil, nil, to.NatPortApp, action, pInfo, ctx)
					ipToStr := ipTo.String()
					if sameHost {
						//destination is on local host, add the rule to all other local/bridge ip as well
						for _, addr := range e.HostIPs.ToSlice() {
							if addr.(string) == ipToStr {
								continue
							}
							createIPRule(ipFrom, net.ParseIP(addr.(string)), nil, nil, to.NatPortApp,
								action, pInfo, ctx)
						}
						if pInfo.HostMode {
							createIPRule(ipFrom, utils.IPv4Loopback, nil, nil, to.NatPortApp,
								action, pInfo, ctx)
						}
						//no need to continue the loop as all ip on this local host is already included above
						break
					}
				}
			}
		}
	} else {
		var toIPList []net.IP
		var toPortApp []share.CLUSPortApp

		if pInfo.HostMode {
			// for host mode container, we will not check dst ip
			if len(to.NatIP) == 0 {
				// Supress the log, a host mode container in the exit state can trigger this forever
				// log.WithFields(log.Fields{"to": to.WlID}).Debug("Missing ip for host mode container!")
				return
			}
			toIPList = to.NatIP[:1]
			//(NVSHAS-4175) for host mode container we also need
			//to include LocalPortApp to create ip rule. For host
			//mode workload we do not check application but only
			//check ports, only add LocalPortApp when there is
			//service port(NatPortApp) open
			if (to.NatPortApp != nil && len(to.NatPortApp) > 0)	&&
				(to.LocalPortApp != nil && len(to.LocalPortApp) > 0) {
				toPortApp = append(toPortApp, to.LocalPortApp...)
			}
			toPortApp = append(toPortApp, to.NatPortApp...)
		} else {
			toIPList = to.LocalIP
			toPortApp = to.LocalPortApp
		}

		if toPortApp != nil {
			for _, ipTo := range toIPList {
				if sameHost {
					for _, ipFrom := range from.LocalIP {
						createIPRule(ipFrom, ipTo, nil, nil, toPortApp, action, pInfo, ctx)
					}
				}

				if from.WlID == share.CLUSWLAddressGroup  || from.WlID == share.CLUSHostAddrGroup {
					for i := 0; i < len(from.NatIP); i += 2 {
						createIPRule(from.NatIP[i], ipTo, from.NatIP[i+1], nil, toPortApp, action, pInfo, ctx)
						if pInfo.HostMode && from.NatIP[i].Equal(utils.IPv4Loopback) {
							// address group with loopback ip as member, we know it's the "nodes" group.
							// Add 127.0.0.1 -> 127.0.0.1 rule
							createIPRule(from.NatIP[i], utils.IPv4Loopback, nil, nil, toPortApp, action, pInfo, ctx)
						}
					}
					if from.WlID == share.CLUSHostAddrGroup {
						//NVSHAS-5205, source is 'nodes', for local host
						//add the rule from all other local/bridge ip as well
						for _, addr := range e.HostIPs.ToSlice() {
							createIPRule(net.ParseIP(addr.(string)), ipTo, nil, nil, toPortApp,
								action, pInfo, ctx)
						}
					}
				} else {
					for _, ipFrom := range from.NatIP {
						createIPRule(ipFrom, ipTo, nil, nil, toPortApp, action, pInfo, ctx)
						ipFromStr := ipFrom.String()
						if sameHost && isHostRelated(from) {
							//source is on local host, add the rule from all other local/bridge ip as well
							for _, addr := range e.HostIPs.ToSlice() {
								if addr.(string) == ipFromStr {
									continue
								}
								createIPRule(net.ParseIP(addr.(string)), ipTo, nil, nil, toPortApp,
									action, pInfo, ctx)
							}
							//no need to continue the loop as all ip on this local host is already included above
							break
						}
					}

					// For host mode container, the address will be set to NatIP even though the system
					// can be a global ip system (such as k8s). So add the rule from the global address to
					// NatIP here as well.
					if pInfo.HostMode {
						for _, ipFrom := range from.GlobalIP {
							createIPRule(ipFrom, ipTo, nil, nil, toPortApp, action, pInfo, ctx)
						}
					}
				}
			}
		}
	}

	for _, ipFrom := range from.GlobalIP {
		for _, ipTo := range to.GlobalIP {
			if policy.ID == 0 && ipFrom.Equal(ipTo) {
				continue
			}
			createIPRule(ipFrom, ipTo, nil, nil, to.LocalPortApp, action, pInfo, ctx)
		}
		// OpenShift workload to host-mode workload
		if to.WlID != share.CLUSWLAddressGroup && to.WlID != share.CLUSHostAddrGroup {
			for _, ipTo := range to.NatIP {
				createIPRule(ipFrom, ipTo, nil, nil, to.NatPortApp, action, pInfo, ctx)
			}
		}
	}

	if sameHost {
		// For rancher, traffic can go from global to local address if they are on the
		// same host. Add the rule here.
		for _, ipFrom := range from.GlobalIP {
			for _, ipTo := range to.LocalIP {
				createIPRule(ipFrom, ipTo, nil, nil, to.LocalPortApp, action, pInfo, ctx)
			}
		}

		for _, ipFrom := range from.LocalIP {
			for _, ipTo := range to.GlobalIP {
				createIPRule(ipFrom, ipTo, nil, nil, to.LocalPortApp, action, pInfo, ctx)
			}
		}
	}

	// If policy mode is empty, the workload is not a container. Then although the address is
	// written into nat ip list, they are also global address and can be talked to from other
	// global address. Adding the rule here.
	// share.CLUSWLAddressGroup is not subject to this assumption
	if to.WlID == share.CLUSWLAddressGroup || to.WlID == share.CLUSHostAddrGroup {
		for _, ipFrom := range from.GlobalIP {
			for i := 0; i < len(to.NatIP); i += 2 {
				createIPRule(ipFrom, to.NatIP[i], nil, to.NatIP[i+1], to.NatPortApp, action, pInfo, ctx)
			}
		}
	} else if to.PolicyMode == "" {
		for _, ipFrom := range from.GlobalIP {
			for _, ipTo := range to.NatIP {
				createIPRule(ipFrom, ipTo, nil, nil, to.NatPortApp, action, pInfo, ctx)
			}
		}
	}

	if from.WlID == share.CLUSWLAddressGroup  || from.WlID == share.CLUSHostAddrGroup {
		for _, ipTo := range to.GlobalIP {
			for i := 0; i < len(from.NatIP); i += 2 {
				createIPRule(from.NatIP[i], ipTo, from.NatIP[i+1], nil, to.LocalPortApp, action, pInfo, ctx)
			}
		}
	} else if from.PolicyMode == "" {
		for _, ipTo := range to.GlobalIP {
			for _, ipFrom := range from.NatIP {
				createIPRule(ipFrom, ipTo, nil, nil, to.LocalPortApp, action, pInfo, ctx)
			}
		}
	}
}

func fillWorkloadAddress(addr *share.CLUSWorkloadAddr, addrMap map[string]*share.CLUSWorkloadAddr) {
	if a, ok := addrMap[addr.WlID]; ok {
		addr.PolicyMode = a.PolicyMode
		addr.LocalIP = a.LocalIP
		addr.GlobalIP = a.GlobalIP
		addr.NatIP = a.NatIP
	} else if isWorkloadFqdn(addr.WlID) {
		addr.NatIP = getFqdnIP(getFqdnName(addr.WlID))
	}
}

func getPortsForApplicationAg(appMap map[share.CLUSProtoPort]*share.CLUSApp, application uint32) string {
	var ports string = ""
	for protoPort, app := range appMap {
		if app.Application == application || app.Proto == application {
			if ports == "" {
				ports = fmt.Sprintf("%d", protoPort.Port)
			} else {
				ports = fmt.Sprintf("%s,%d", ports, protoPort.Port)
			}
		}
	}
	return ports
}

func getMappedPortAg(portMap map[share.CLUSProtoPort]*share.CLUSMappedPort, ports string) string {
	var pp string = ""
	portList := strings.Split(ports, ",")
	for _, ap := range portList {
		proto, pl, ph, err := utils.ParsePortRangeLink(ap)
		if err != nil {
			// log.WithFields(log.Fields{"port": ap}).Error("Fail to parse")
			continue
		}
		for _, mp := range portMap {
			// seems the mapping is not ip specific, so ip is ignored in mapping search
			if (mp.IPProto == proto || proto == 0) && (mp.Port >= pl && mp.Port <= ph) {
				if pp == "" {
					pp = utils.GetPortLink(mp.IPProto, mp.HostPort)
				} else {
					pp = fmt.Sprintf("%s,%s", pp, utils.GetPortLink(mp.IPProto, mp.HostPort))
				}
			}
		}
	}
	return pp
}

func fillPortsForWorkloadAddressAg(wlAddr *share.CLUSWorkloadAddr, apps []share.CLUSPortApp, pInfo *WorkloadIPPolicyInfo) {
	var pp string

	//log.WithFields(log.Fields{"pInfo": pInfo, "apps": apps}).Debug("")
	if apps != nil && len(apps) != 0 {
		wlAddr.LocalPortApp = make([]share.CLUSPortApp, 0)
		wlAddr.NatPortApp = make([]share.CLUSPortApp, 0)
		for _, app := range apps {
			if app.Ports == "" {
				pp = "any"
			} else {
				pp = app.Ports
			}
			wlAddr.LocalPortApp = append(wlAddr.LocalPortApp,
				share.CLUSPortApp{
					Ports:       pp,
					Application: app.Application,
					CheckApp:    app.CheckApp,
				})
			mapp := getMappedPortAg(pInfo.PortMap, pp)
			if mapp != "" {
				wlAddr.NatPortApp = append(wlAddr.NatPortApp,
					share.CLUSPortApp{
						Ports:       mapp,
						Application: app.Application,
						CheckApp:    app.CheckApp,
					})
			}

			// For some app, we may not always reliablely identify them.
			// So we utilize the recognized ports. If the app
			// is not identified on these ports, we handle them the same as
			// the specified app
			if app.CheckApp && app.Application >= C.DPI_APP_PROTO_MARK {
				appPorts := getPortsForApplicationAg(pInfo.AppMap, app.Application)
				if app.Ports == "" {
					pp = appPorts
				} else {
					pp = utils.GetCommonPorts(appPorts, app.Ports)
				}
				if pp != "" {
					wlAddr.LocalPortApp = append(wlAddr.LocalPortApp,
						share.CLUSPortApp{
							Ports:       pp,
							Application: C.DP_POLICY_APP_UNKNOWN,
							CheckApp:    true,
						})

					mapp := getMappedPortAg(pInfo.PortMap, pp)
					if mapp != "" {
						wlAddr.NatPortApp = append(wlAddr.NatPortApp,
							share.CLUSPortApp{
								Ports:       mapp,
								Application: C.DP_POLICY_APP_UNKNOWN,
								CheckApp:    true,
							})
					}
				}
			}
		}
	}
}

func getRelevantWorkload(addrs []*share.CLUSWorkloadAddr,
	pMap map[string]*WorkloadIPPolicyInfo, isto bool) ([]*share.CLUSWorkloadAddr, []*WorkloadIPPolicyInfo) {

	wlList := make([]*share.CLUSWorkloadAddr, 0)
	pInfoList := make([]*WorkloadIPPolicyInfo, 0)
	for _, addr := range addrs {
		if addr.WlID == share.CLUSWLModeGroup {
			if (polAppDir&C.DP_POLICY_APPLY_EGRESS > 0 && !isto) ||
				(polAppDir&C.DP_POLICY_APPLY_INGRESS > 0 && isto) {
				for id, pInfo := range pMap {
					mode := pInfo.Policy.Mode
					if strings.Contains(addr.PolicyMode, mode) {
						wlList = append(wlList, &share.CLUSWorkloadAddr{WlID: id,
							LocalPortApp: addr.LocalPortApp, NatPortApp: addr.NatPortApp})
						pInfoList = append(pInfoList, pInfo)
					}
				}
			}
		} else if addr.WlID == share.CLUSWLAllContainer {
			for id, pInfo := range pMap {
				wlAddr := share.CLUSWorkloadAddr{
					WlID: id,
					PolicyMode: pInfo.Policy.Mode,
				}
				if isto {
					fillPortsForWorkloadAddressAg(&wlAddr, addr.LocalPortApp, pInfo)
				}
				wlList = append(wlList, &wlAddr)
				pInfoList = append(pInfoList, pInfo)
			}
		} else {
			if pInfo, ok := pMap[addr.WlID]; ok {
				wlList = append(wlList, addr)
				pInfoList = append(pInfoList, pInfo)
			}
		}
	}
	return wlList, pInfoList
}

func getWorkload(addrs []*share.CLUSWorkloadAddr,
	wlMap map[string]*share.CLUSWorkloadAddr, isto bool) []*share.CLUSWorkloadAddr {

	wlList := make([]*share.CLUSWorkloadAddr, 0)
	for _, addr := range addrs {
		if addr.WlID == share.CLUSWLModeGroup {
			if (polAppDir&C.DP_POLICY_APPLY_EGRESS > 0 && isto) ||
				(polAppDir&C.DP_POLICY_APPLY_INGRESS > 0 && !isto) {
				for id, wl := range wlMap {
					if strings.Contains(addr.PolicyMode, wl.PolicyMode) {
						if addr.NatPortApp == nil  || len(addr.NatPortApp) <= 0 {//PAI
							wlList = append(wlList, &share.CLUSWorkloadAddr{WlID: id,
									LocalPortApp: addr.LocalPortApp, NatPortApp: addr.NatPortApp})
						} else {
							wlList = append(wlList, &share.CLUSWorkloadAddr{WlID: id,
									LocalPortApp: addr.LocalPortApp, NatPortApp: wl.NatPortApp})
						}
					}
				}
			}
		} else if addr.WlID == share.CLUSWLAllContainer {
			if (polAppDir&C.DP_POLICY_APPLY_EGRESS > 0 && isto) ||
				(polAppDir&C.DP_POLICY_APPLY_INGRESS > 0 && !isto) {
				for id, wl := range wlMap {
					wlAddr := share.CLUSWorkloadAddr{
						WlID: id,
						PolicyMode: wl.PolicyMode,
					}
					wlList = append(wlList, &wlAddr)
				}
			}
		} else {
			wlList = append(wlList, addr)
		}
	}
	return wlList

}

func mixedModeSameWl(pp *share.CLUSGroupIPPolicy, from, to *share.CLUSWorkloadAddr) bool {

	if pp.ID == 0 && from.WlID == to.WlID {
		return true
	}
	return false
}

func addPolicyAddrIPNet(subnets map[string]share.CLUSSubnet, ipnet *net.IPNet, scope string) bool {
	subnet := utils.IPNet2Subnet(ipnet)
	if _, ok := subnets[subnet.String()]; !ok {
		snet := share.CLUSSubnet{Subnet: *subnet, Scope: scope}
		return utils.MergeSubnet(subnets, snet)
	}
	return false
}

func addWlLocalAddrToPolicyAddrMap(from *share.CLUSWorkloadAddr, newPolicyAddrMap map[string]share.CLUSSubnet) {
	for _, lip := range from.LocalIP {
		lipnet := &net.IPNet{IP: lip, Mask: net.CIDRMask(32, 32)}
		//log.WithFields(log.Fields{"ip": lipnet.IP.String(), "mask": lipnet.Mask.String()}).Debug("add local ip")
		addPolicyAddrIPNet(newPolicyAddrMap, lipnet, share.CLUSIPAddrScopeLocalhost)
	}
}

func addWlGlobalAddrToPolicyAddrMap(from *share.CLUSWorkloadAddr, newPolicyAddrMap map[string]share.CLUSSubnet) {
	for _, gip := range from.GlobalIP {
		gipnet := &net.IPNet{IP: gip, Mask: net.CIDRMask(32, 32)}
		//log.WithFields(log.Fields{"ip": gipnet.IP.String(), "mask": gipnet.Mask.String()}).Debug("add global ip")
		addPolicyAddrIPNet(newPolicyAddrMap, gipnet, share.CLUSIPAddrScopeGlobal)
	}
}

func (e *Engine) parseGroupIPPolicy(p []share.CLUSGroupIPPolicy, workloadPolicyMap map[string]*WorkloadIPPolicyInfo,
	newPolicyAddrMap map[string]share.CLUSSubnet) {
	addrMap := make(map[string]*share.CLUSWorkloadAddr)
	for i, pp := range p {
		// The first rule is the default rule that contains all container
		if i == 0 {
			for _, from := range pp.From {
				addrMap[from.WlID] = from
				//add wl global/nat address to policy address map
				//these address will be pushed to DP
				if from.PolicyMode == share.PolicyModeEvaluate ||
					from.PolicyMode == share.PolicyModeEnforce {
					addWlGlobalAddrToPolicyAddrMap(from, newPolicyAddrMap)
				}
				if pInfo, ok := workloadPolicyMap[from.WlID]; ok {
					pInfo.Configured = true
					pInfo.Policy.Mode = from.PolicyMode
					pInfo.Policy.DefAction = policyModeToDefaultAction(from.PolicyMode, pInfo.CapIntcp)
					//only add workload local address relevant to this enforcer
					//to policy address map, these address will be pushed to DP
					if from.PolicyMode == share.PolicyModeEvaluate ||
						from.PolicyMode == share.PolicyModeEnforce {
						addWlLocalAddrToPolicyAddrMap(from, newPolicyAddrMap)
					}
				}
			}
			continue
		}

		/* create egress rules */
		wlList, pInfoList := getRelevantWorkload(pp.From, workloadPolicyMap, false)
		wlToList := getWorkload(pp.To, addrMap, true)
		for i, from := range wlList {
			pInfo := pInfoList[i]
			for _, to := range wlToList {
				if pInfo.Policy.ApplyDir&C.DP_POLICY_APPLY_EGRESS > 0 {
					var sameHost bool = false
					if isSameHostEP(to.WlID, e.HostID) {
						sameHost = true
					} else if _, ok := workloadPolicyMap[to.WlID]; ok {
						sameHost = true
					}
					fillWorkloadAddress(from, addrMap)
					fillWorkloadAddress(to, addrMap)
					if mixedModeSameWl(&pp, from, to) {
						continue
					}
					e.createWorkloadRule(from, to, &pp, pInfo, false, sameHost)
				} else {
					// Only configure egress rule to external, as east-west egress traffic
					// will be automatically allowed at DP
					if to.WlID == share.CLUSWLExternal || to.WlID == share.CLUSWLAddressGroup ||
						to.WlID == share.CLUSHostAddrGroup || isWorkloadFqdn(to.WlID) || isWorkloadIP(to.WlID) {
						fillWorkloadAddress(from, addrMap)
						fillWorkloadAddress(to, addrMap)
						e.createWorkloadRule(from, to, &pp, pInfo, false, false)
					} else if isHostRelated(to) {
						var sameHost bool = false
						if isSameHostEP(to.WlID, e.HostID) {
							sameHost = true
						} else if _, ok := workloadPolicyMap[to.WlID]; ok {
							sameHost = true
						}
						fillWorkloadAddress(from, addrMap)
						fillWorkloadAddress(to, addrMap)
						e.createWorkloadRule(from, to, &pp, pInfo, false, sameHost)
					}
				}
			}
		}

		/* create ingress rules */
		wlList, pInfoList = getRelevantWorkload(pp.To, workloadPolicyMap, true)
		wlFromList := getWorkload(pp.From, addrMap, false)
		for i, to := range wlList {
			pInfo := pInfoList[i]
			for _, from := range wlFromList {
				if pInfo.Policy.ApplyDir&C.DP_POLICY_APPLY_INGRESS > 0 {
					var sameHost bool = false
					if isSameHostEP(from.WlID, e.HostID) {
						sameHost = true
					} else if _, ok := workloadPolicyMap[from.WlID]; ok {
						sameHost = true
					}
					fillWorkloadAddress(from, addrMap)
					fillWorkloadAddress(to, addrMap)
					if mixedModeSameWl(&pp, from, to) {
						continue
					}
					e.createWorkloadRule(from, to, &pp, pInfo, true, sameHost)
				} else {
					// Only configure ingress rule from external, as east-west ingress traffic
					// will be automatically allowed at DP
					if from.WlID == share.CLUSWLExternal || from.WlID == share.CLUSWLAddressGroup ||
						from.WlID == share.CLUSHostAddrGroup || isWorkloadFqdn(from.WlID) || isWorkloadIP(from.WlID) {
						fillWorkloadAddress(from, addrMap)
						fillWorkloadAddress(to, addrMap)
						e.createWorkloadRule(from, to, &pp, pInfo, true, false)
					}
				}
			}
		}
	}
	return
}

func policyModeToDefaultAction(mode string, capIntcp bool) uint8 {
	switch mode {
	case share.PolicyModeLearn:
		return C.DP_POLICY_ACTION_LEARN
	case share.PolicyModeEvaluate:
		return C.DP_POLICY_ACTION_VIOLATE
	case share.PolicyModeEnforce:
		if capIntcp {
			return C.DP_POLICY_ACTION_DENY
		} else {
			return C.DP_POLICY_ACTION_VIOLATE
		}
	}
	//for a wl whose mode is empty/unknown
	//set default action to OPEN to reduce
	//false violations
	return C.DP_POLICY_ACTION_OPEN
}

func ipMatch(ip, ipL, ipR net.IP, external bool) bool {
	if external && bytes.Compare(ipL, net.IPv4zero) == 0 {
		return true
	}
	s := bytes.Compare(ip, ipL)
	if s == 0 {
		return true
	} else if ipR == nil {
		return false
	}
	if s > 0 && bytes.Compare(ip, ipR) <= 0 {
		return true
	}
	return false
}

func hostPolicyMatch(r *dp.DPPolicyIPRule, conn *dp.Connection) (bool, uint32, uint8) {
	if r.Ingress != conn.Ingress {
		return false, 0, 0
	}

	if r.Ingress {
		if ipMatch(conn.ClientIP, r.SrcIP, r.SrcIPR, conn.ExternalPeer) == false {
			return false, 0, 0
		}
	} else if ipMatch(conn.ServerIP, r.DstIP, r.DstIPR, conn.ExternalPeer) == false {
		return false, 0, 0
	}
	if conn.ServerPort < r.Port || conn.ServerPort > r.PortR {
		return false, 0, 0
	}
	if r.IPProto > 0 && conn.IPProto != r.IPProto {
		return false, 0, 0
	}

	if r.Action == C.DP_POLICY_ACTION_CHECK_APP {
		for _, app := range r.Apps {
			if app.App == C.DP_POLICY_APP_ANY || app.App == conn.Application {
				return true, app.RuleID, app.Action
			}
		}
		return false, 0, 0
	}

	return true, r.ID, r.Action
}

func (e *Engine) HostNetworkPolicyLookup(wl string, conn *dp.Connection) (uint32, uint8, bool) {
	e.Mutex.Lock()
	pInfo := e.NetworkPolicy[wl]
	e.Mutex.Unlock()

	if pInfo == nil || !pInfo.Configured {
		return 0, C.DP_POLICY_ACTION_OPEN, false
	}

	if conn.Ingress {
		if !conn.ExternalPeer &&
			(pInfo.Policy.ApplyDir&C.DP_POLICY_APPLY_INGRESS == 0) {
			return 0, C.DP_POLICY_ACTION_OPEN, false
		}

		for _, p := range pInfo.Policy.IPRules {
			if !p.Ingress {
				continue
			}
			if match, id, action := hostPolicyMatch(p, conn); match {
				return id, action, action > C.DP_POLICY_ACTION_CHECK_APP
			}
		}
	} else {
		if !conn.ExternalPeer &&
			(pInfo.Policy.ApplyDir&C.DP_POLICY_APPLY_EGRESS == 0) {
			return 0, C.DP_POLICY_ACTION_OPEN, false
		}

		for _, p := range pInfo.Policy.IPRules {
			if p.Ingress {
				continue
			}

			if match, id, action := hostPolicyMatch(p, conn); match {
				return id, action, action > C.DP_POLICY_ACTION_CHECK_APP
			}
		}
	}
	action := policyModeToDefaultAction(pInfo.Policy.Mode, pInfo.CapIntcp)
	return 0, action, action > C.DP_POLICY_ACTION_CHECK_APP
}

func (e *Engine) UpdateNetworkPolicy(ps []share.CLUSGroupIPPolicy,
	newPolicy map[string]*WorkloadIPPolicyInfo) utils.Set {

	fqdnInfoPrePolicyCalc()

	newPolicyAddrMap := make(map[string]share.CLUSSubnet)
	e.parseGroupIPPolicy(ps, newPolicy, newPolicyAddrMap)

	dpConnected := dp.Connected()

	if dpConnected {
		fqdnInfoPostPolicyCalc(e.HostID)
	}

	// For host mode containers, we need to notify probe the policy change
	hostPolicyChangeSet := utils.NewSet()
	for id, pInfo := range newPolicy {
		// release the ruleMap as it is not needed anymore
		pInfo.RuleMap = nil

		// For workload that is not configured, policy is not calculated yet.
		// Don't send policy to DP so that DP will bypass the traffic
		if pInfo.Configured == false {
			continue
		}

		if pInfo.SkipPush {
			continue
		}

		if old, ok := e.NetworkPolicy[id]; !ok {
			if pInfo.HostMode {
				hostPolicyChangeSet.Add(id)
			} else if dpConnected {
				//simulateAddLargeNumIPRules(&pInfo.Policy, pInfo.Policy.ApplyDir)
				dp.DPCtrlConfigPolicy(&pInfo.Policy, C.CFG_ADD)
			}
		} else if pInfo.Configured != old.Configured ||
			reflect.DeepEqual(&pInfo.Policy, &old.Policy) != true {
			if pInfo.HostMode {
				hostPolicyChangeSet.Add(id)
			} else if dpConnected {
				//simulateAddLargeNumIPRules(&pInfo.Policy, pInfo.Policy.ApplyDir)
				dp.DPCtrlConfigPolicy(&pInfo.Policy, C.CFG_MODIFY)
			}
		}
	}
	//always push policy address map at the end after all policy has
	//been pushed to DP, so that if there is early traffic at the DP
	//if wl ip is not in addr map we know that policy is not yet pushed
	//to DP so we can let action be OPEN
	if reflect.DeepEqual(e.PolicyAddrMap, newPolicyAddrMap) == false {
		dp.DPCtrlConfigPolicyAddr(newPolicyAddrMap)
	}
	// we don't do policy delete here as it only happens when workload is gone
	// Policy at DP will be deleted automatically for this case
	e.Mutex.Lock()
	e.NetworkPolicy = newPolicy
	e.PolicyAddrMap = newPolicyAddrMap
	e.Mutex.Unlock()

	return hostPolicyChangeSet
}

func (e *Engine) GetNetworkPolicy() map[string]*WorkloadIPPolicyInfo {
	e.Mutex.Lock()
	defer e.Mutex.Unlock()

	return e.NetworkPolicy
}

func (e *Engine) GetPolicyAddrMap() map[string]share.CLUSSubnet {
	e.Mutex.Lock()
	defer e.Mutex.Unlock()

	return e.PolicyAddrMap
}

func (e *Engine) DeleteNetworkPolicy(id string) {
	e.Mutex.Lock()
	defer e.Mutex.Unlock()

	delete(e.NetworkPolicy, id)
}

func (e *Engine) PushNetworkPolicyToDP() {
	log.Debug("")
	np := e.GetNetworkPolicy()
	for _, pInfo := range np {
		if pInfo.Configured == false {
			continue
		}
		if pInfo.SkipPush {
			continue
		}
		dp.DPCtrlConfigPolicy(&pInfo.Policy, C.CFG_ADD)
	}
	policyAddr := e.GetPolicyAddrMap()
	dp.DPCtrlConfigPolicyAddr(policyAddr)
}

func (e *Engine) PushFqdnInfoToDP() {
	fqdn_key := fmt.Sprintf("%s%s/", share.CLUSFqdnIpStore, e.HostID)
	allKeys, _ := cluster.GetStoreKeys(fqdn_key)
	for _, key := range allKeys {
		if value, _ := cluster.Get(key); value != nil {
			uzb := utils.GunzipBytes(value)
			if uzb != nil {
				var fqdnip share.CLUSFqdnIp
				json.Unmarshal(uzb, &fqdnip)
				dp.DPCtrlSetFqdnIp(&fqdnip)
			}
		}
	}
}

//dlp
func (e *Engine) GetNetworkDlpWorkloadRulesInfo() map[string]*dp.DPWorkloadDlpRule {
	e.Mutex.Lock()
	defer e.Mutex.Unlock()

	return e.DlpWlRulesInfo
}

func (e *Engine) GetNetworkDlpBuildInfo() *DlpBuildInfo {
	e.Mutex.Lock()
	defer e.Mutex.Unlock()

	return e.DlpBldInfo
}

func (e *Engine) PushNetworkDlpToDP() {
	log.Debug("config and build dlp")
	e.Mutex.Lock()

	wlDlpInfo := e.DlpWlRulesInfo
	//endpoint does not associate with any dlp rules which means we
	//do not need to push any info to DP
	if wlDlpInfo == nil || len(wlDlpInfo) == 0 {
		log.Debug("endpoint does not associate with any dlp rules")
		e.Mutex.Unlock()
		return
	}

	for _, wldre := range wlDlpInfo {
		dp.DPCtrlConfigDlp(wldre)
	}

	dlpbldinfo := e.DlpBldInfo
	//no dlp rules to build detection tree
	if dlpbldinfo.DlpRulesInfo == nil || len(dlpbldinfo.DlpRulesInfo) == 0 {
		log.Debug("no dlp rules to build detection tree")
		e.Mutex.Unlock()
		return
	}
	dp.DPCtrlBldDlp(dlpbldinfo.DlpRulesInfo, dlpbldinfo.DlpDpMacs, nil, dlpbldinfo.ApplyDir)

	e.Mutex.Unlock()

	log.Debug("dlp config and build done")
}

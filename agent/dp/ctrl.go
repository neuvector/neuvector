package dp

// #include "../../defs.h"
import "C"

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
	log "github.com/sirupsen/logrus"
)

// TODO: The workflow need to be reworked.
//  1. Disconnect condition of both sides should be handled.
const dpClient string = "/tmp/dp_client.%d"
const ctrlServer string = "/tmp/ctrl_listen.sock"

const defaultDPMsgTimeout int = 2
const dpConnJamRetryMax int = 16

var dpConn *net.UnixConn
var dpClientMutex sync.Mutex

const dpKeepAliveInterval time.Duration = (time.Second * 2)

var keepAliveSeq uint32
var dpAliveMsgCnt uint = 0

var taskCallback DPTaskCallback
var statusChan chan bool
var restartChan chan interface{}

func dpClientLock() {
	// log.Info("")
	dpClientMutex.Lock()
}

func dpClientUnlock() {
	// log.Info("")
	dpClientMutex.Unlock()
}

// With lock hold
func dpSendMsgExSilent(msg []byte, timeout int, cb DPCallback, param interface{}) int {
	if dpConn == nil {
		log.Error("Data path not connected")
		if cb != nil && param != nil {
			cb(nil, param)
		}
		return -1
	}

	if dbgError := dpConn.SetWriteDeadline(time.Now().Add(time.Second * 2)); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}

	_, err := dpConn.Write(msg)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Send error")
		// Let keep alive to close dp to avoid reentry
		// closeDP()
		// debug.PrintStack()
		if cb != nil && param != nil {
			cb(nil, param)
		}
		return -1
	}

	if cb != nil && param != nil {
		if timeout == 0 {
			timeout = defaultDPMsgTimeout
		}

		var done bool
		var buf []byte = make([]byte, C.DP_MSG_SIZE)

		for !done {
			if dbgError := dpConn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(timeout))); dbgError != nil {
				log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
			}
			n, err := dpConn.Read(buf)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Read error")
				cb(nil, param)
				// Time out could be because DP is busy. Don't close DP yet.
				// Let keep alive cb to close dp later if dp is really gone
				// closeDP()
				return -1
			} else {
				done = cb(buf[:n], param)
			}
		}
	}
	dpAliveMsgCnt++
	return 0
}

func dpSendMsgEx(msg []byte, timeout int, cb DPCallback, param interface{}) int {
	//log.WithFields(log.Fields{"msg": string(msg), "size": len(msg)}).Debug("")

	// The cb call is inside the dp lock, so be careful if you need to grab
	// another lock in cb
	dpClientLock()
	defer dpClientUnlock()
	return dpSendMsgExSilent(msg, timeout, cb, param)
}

func dpSendMsg(msg []byte) int {
	return dpSendMsgEx(msg, 0, nil, nil)
}

// -- DP message functions

func DPCtrlAddTapPort(netns, iface string, epmac net.HardwareAddr) {
	log.WithFields(log.Fields{"netns": netns, "iface": iface}).Debug("")

	data := DPAddTapPortReq{
		AddPort: &DPTapPort{
			NetNS: netns,
			Iface: iface,
			EPMAC: epmac.String(),
		},
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

func DPCtrlDelTapPort(netns, iface string) {
	log.WithFields(log.Fields{"netns": netns, "iface": iface}).Debug("")

	data := DPDelTapPortReq{
		DelPort: &DPTapPort{
			NetNS: netns,
			Iface: iface,
		},
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

func DPCtrlAddNfqPort(netns, iface string, qno int, epmac net.HardwareAddr, jumboframe *bool) {
	log.WithFields(log.Fields{"netns": netns, "iface": iface}).Debug("")

	data := DPAddNfqPortReq{
		AddNfqPort: &DPNfqPort{
			NetNS: netns,
			Iface: iface,
			Qnum:  qno,
			EPMAC: epmac.String(),
		},
	}
	if jumboframe != nil {
		data.AddNfqPort.JumboFrame = jumboframe
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

func DPCtrlDelNfqPort(netns, iface string) {
	log.WithFields(log.Fields{"netns": netns, "iface": iface}).Debug("")

	data := DPDelNfqPortReq{
		DelNfqPort: &DPNfqPort{
			NetNS: netns,
			Iface: iface,
		},
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

func DPCtrlAddSrvcPort(iface string, jumboframe *bool) {
	log.WithFields(log.Fields{"iface": iface}).Debug("")

	data := DPAddSrvcPortReq{
		AddPort: &DPSrvcPort{
			Iface: iface,
		},
	}
	if jumboframe != nil {
		data.AddPort.JumboFrame = jumboframe
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

func DPCtrlDelSrvcPort(iface string) {
	log.WithFields(log.Fields{"iface": iface}).Debug("")

	data := DPDelSrvcPortReq{
		DelPort: &DPSrvcPort{
			Iface: iface,
		},
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

func DPCtrlSetSysConf(xffenabled *bool) {
	log.WithFields(log.Fields{"xffenabled": *xffenabled}).Debug("")

	data := DPSysConfReq{
		Sysconf: &DPSysConf{
			XffEnabled: xffenabled,
		},
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

func DPCtrlSetDisableNetPolicy(disableNetPolicy *bool) {
	log.WithFields(log.Fields{"disableNetPolicy": *disableNetPolicy}).Debug("")

	data := DPDisableNetPolicyReq{
		DisableNetPolicyConf: &DPDisableNetPolicy{
			DisableNetPolicy: disableNetPolicy,
		},
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

func DPCtrlSetDetectUnmanagedWl(detectUnmanagedWl *bool) {

	data := DPDetectUnmanagedWlReq{
		DetectUnmanagedWlConf: &DPDetectUnmanagedWl{
			DetectUnmanagedWl: detectUnmanagedWl,
		},
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

func DPCtrlSetEnableIcmpPolicy(enableIcmpPolicy *bool) {

	data := DPEnableIcmpPolicyReq{
		EnableIcmpPolicyConf: &DPEnableIcmpPolicy{
			EnableIcmpPolicy: enableIcmpPolicy,
		},
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

func DPCtrlAddMAC(iface string, mac, ucmac, bcmac, oldmac, pmac net.HardwareAddr, pips []net.IP) {
	log.WithFields(log.Fields{"mac": mac, "iface": iface}).Debug("")

	tpips := make([]DPMacPip, 0, len(pips))
	for _, addr := range pips {
		pip := DPMacPip{
			IP: addr,
		}
		tpips = append(tpips, pip)
	}

	data := DPAddMACReq{
		AddMAC: &DPAddMAC{
			Iface:  iface,
			MAC:    mac.String(),
			UCMAC:  ucmac.String(),
			BCMAC:  bcmac.String(),
			OldMAC: oldmac.String(),
			PMAC:   pmac.String(),
			PIPS:   tpips,
		},
	}
	if pips == nil || len(pips) <= 0 {
		data.AddMAC.PIPS = nil
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

func DPCtrlDelMAC(iface string, mac net.HardwareAddr) {
	log.WithFields(log.Fields{"mac": mac}).Debug("")

	data := DPDelMACReq{
		DelMAC: &DPDelMAC{
			Iface: iface,
			MAC:   mac.String(),
		},
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

func DPCtrlRefreshApp() {
	log.Debug("")

	data := DPRefreshAppReq{
		RefreshApp: &DPRefreshApp{},
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

func DPCtrlConfigMAC(MACs []string, tap *bool, appMap map[share.CLUSProtoPort]*share.CLUSApp) {
	data := DPConfigMACReq{
		Cfg: &DPMacConfig{
			MACs: MACs,
		},
	}
	if tap != nil {
		data.Cfg.Tap = tap
	}
	if len(appMap) > 0 {
		apps := make([]DPProtoPortApp, len(appMap))
		i := 0
		for p, app := range appMap {
			apps[i] = DPProtoPortApp{
				IPProto: p.IPProto, Port: p.Port,
				Application: app.Application,
				Server:      app.Server,
			}
			i++
		}
		data.Cfg.Apps = &apps
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

func DPCtrlConfigNBE(MACs []string, nbe *bool) {
	data := DPConfigNbeReq{
		Cfg: &DPNbeConfig{
			MACs: MACs,
		},
	}
	if nbe != nil {
		data.Cfg.Nbe = nbe
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

func DPCtrlAddPortPair(vex_iface, vin_iface string, epmac net.HardwareAddr, quar *bool) {
	data := DPAddPortPairReq{
		AddPortPair: &DPPortPair{
			IfaceVex: vex_iface,
			IfaceVin: vin_iface,
			EPMAC:    epmac.String(),
		},
	}
	if quar != nil {
		data.AddPortPair.Quar = quar
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

func DPCtrlDelPortPair(vex_iface, vin_iface string) {
	data := DPDelPortPairReq{
		DelPortPair: &DPPortPair{
			IfaceVex: vex_iface,
			IfaceVin: vin_iface,
		},
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

func DPCtrlStatsMAC(macs []*net.HardwareAddr, cb DPCallback, param interface{}) {
	log.WithFields(log.Fields{"macs": macs}).Debug("")

	var dp_macs []string
	for _, mac := range macs {
		dp_macs = append(dp_macs, mac.String())
	}

	data := DPStatsMACReq{
		Stats: &DPMACArray{MACs: dp_macs},
	}
	msg, _ := json.Marshal(data)
	dpSendMsgEx(msg, 5, cb, param)
}

func DPCtrlStatsAgent(cb DPCallback, param interface{}) {
	log.Debug("")

	data := DPStatsAgentReq{
		Stats: &DPEmpty{},
	}
	msg, _ := json.Marshal(data)
	dpSendMsgEx(msg, 5, cb, param)
}

func DPCtrlCounterAgent(cb DPCallback, param interface{}) {
	log.Debug("")

	data := DPCounterAgentReq{
		Counter: &DPEmpty{},
	}
	msg, _ := json.Marshal(data)
	dpSendMsgEx(msg, 5, cb, param)
}

func DPCtrlConfigAgent(debug *DPDebug) {
	log.Debug("")

	data := DPSetDebugReq{
		Debug: debug,
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

func DPCtrlCountSession(cb DPCallback, param interface{}) {
	log.Debug("")

	data := DPCountSessionReq{
		CountSession: &DPEmpty{},
	}
	msg, _ := json.Marshal(data)
	dpSendMsgEx(msg, 5, cb, param)
}

func DPCtrlListSession(cb DPCallback, param interface{}) {
	log.Debug("")

	data := DPListSessionReq{
		ListSession: &DPEmpty{},
	}
	msg, _ := json.Marshal(data)
	dpSendMsgEx(msg, 5, cb, param)
}

func DPCtrlClearSession(id uint32) {
	log.Debug("")

	data := DPClearSessionReq{
		ClearSession: &DPClearSession{
			ID: id,
		},
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

func DPCtrlListMeter(cb DPCallback, param interface{}) {
	log.Debug("")

	data := DPListMeterReq{
		ListMeter: &DPEmpty{},
	}
	msg, _ := json.Marshal(data)
	dpSendMsgEx(msg, 5, cb, param)
}

func getDPCtrlClientAddr() string {
	return fmt.Sprintf(dpClient, os.Getpid())
}

const maxMsgSize int = 8120

func DPCtrlConfigPolicy(policy *DPWorkloadIPPolicy, cmd uint) int {
	var start, end int = 0, 0
	var first bool = true
	var rulesPerMsg int = 40

	num := len(policy.IPRules)
	log.WithFields(log.Fields{
		"workload": policy.WlID, "mac": policy.WorkloadMac, "num": num,
	}).Debug("")

	for num > 0 || first {
		var flag uint = 0

	retry:
		flag = 0
		if start == 0 {
			flag = C.MSG_START
		}
		if num <= rulesPerMsg {
			flag |= C.MSG_END
			end = start + num
		} else {
			end = start + rulesPerMsg
		}
		data := DPPolicyCfgReq{
			DPPolicyCfg: &DPPolicyCfg{
				Cmd:         cmd,
				Flag:        flag,
				DefAction:   policy.DefAction,
				ApplyDir:    policy.ApplyDir,
				WorkloadMac: policy.WorkloadMac,
				IPRules:     policy.IPRules[start:end],
			},
		}
		msg, _ := json.Marshal(data)
		sz := len(msg)
		if sz > maxMsgSize {
			// a very rough way to calculate rulesPerMsg
			newRulesPerMsg := maxMsgSize / (sz/(end-start) + 1)
			if newRulesPerMsg == rulesPerMsg {
				newRulesPerMsg--
			}
			if newRulesPerMsg == 0 {
				log.WithFields(log.Fields{
					"rule": policy.IPRules[start]},
				).Error("rule too large")
				return -1
			}
			rulesPerMsg = newRulesPerMsg
			goto retry
		}

		if dpSendMsg(msg) == -1 {
			return -1
		}
		num = num + start - end
		start = end
		first = false
	}
	return 0
}

func DPCtrlDeleteFqdn(names []string) int {
	var start, end int = 0, len(names)
	var namesPerMsg int = 20
	var req *DPFqdnDeleteReq

	for start < end {
		if start+namesPerMsg < end {
			req = &DPFqdnDeleteReq{Delete: &DPFqdnList{Names: names[start : start+namesPerMsg]}}
		} else {
			req = &DPFqdnDeleteReq{Delete: &DPFqdnList{Names: names[start:end]}}
		}
		start = start + namesPerMsg
		msg, _ := json.Marshal(req)
		if dpSendMsg(msg) < 0 {
			return -1
		}
	}
	return 0
}

func DPCtrlSetFqdnIp(fqdnip *share.CLUSFqdnIp) int {
	fips := make([]net.IP, 0, len(fqdnip.FqdnIP))
	for _, fip := range fqdnip.FqdnIP {
		if !utils.IsIPv4(fip) {
			continue
		}
		fips = append(fips, fip)
	}
	Vhost := fqdnip.Vhost
	data := DPFqdnIpSetReq{
		Fqdns: &DPFqdnIps{
			FqdnName: fqdnip.FqdnName,
			FqdnIps:  fips,
			Vhost:    &Vhost,
		},
	}
	msg, _ := json.Marshal(data)
	if dpSendMsg(msg) < 0 {
		return -1
	}
	return 0
}

func DPCtrlConfigPolicyAddr(subnets map[string]share.CLUSSubnet) {
	data_subnet := make([]DPSubnet, 0, len(subnets))
	for _, addr := range subnets {
		if !utils.IsIPv4(addr.Subnet.IP) {
			continue
		}
		subnet := DPSubnet{
			IP:   addr.Subnet.IP,
			Mask: net.IP(addr.Subnet.Mask),
		}
		data_subnet = append(data_subnet, subnet)
	}

	var start, end int = 0, 0
	var first bool = true
	var subnetPerMsg int = 600
	var msg []byte

	num := len(data_subnet)
	log.WithFields(log.Fields{"policy_address_num": num}).Debug("config policy address")

	for num > 0 || first {
		var flag uint = 0

	retry:
		flag = 0
		if start == 0 {
			flag = C.MSG_START
		}
		if num <= subnetPerMsg {
			flag |= C.MSG_END
			end = start + num
		} else {
			end = start + subnetPerMsg
		}
		data := DPPolicyAddressCfgReq{
			PolicyAddrCfg: &DPInternalSubnetCfg{
				Flag:    flag,
				Subnets: data_subnet[start:end],
			},
		}

		msg, _ = json.Marshal(data)
		sz := len(msg)
		if sz > maxMsgSize {
			// a very rough way to calculate rulesPerMsg
			newSubnetPerMsg := maxMsgSize / (sz/(end-start) + 1)
			if newSubnetPerMsg == subnetPerMsg {
				newSubnetPerMsg--
			}
			if newSubnetPerMsg == 0 {
				log.WithFields(log.Fields{"policy_address": data_subnet[start]}).Error("policy address too large")
				return
			}
			subnetPerMsg = newSubnetPerMsg
			goto retry
		}

		if dpSendMsg(msg) == -1 {
			log.Debug("dpSendMsg error")
			return
		}
		num = num + start - end
		start = end
		first = false
	}
}

func DPCtrlConfigInternalSubnet(subnets map[string]share.CLUSSubnet) {
	data_subnet := make([]DPSubnet, 0, len(subnets))
	for _, addr := range subnets {
		if !utils.IsIPv4(addr.Subnet.IP) {
			continue
		}
		subnet := DPSubnet{
			IP:   addr.Subnet.IP,
			Mask: net.IP(addr.Subnet.Mask),
		}
		data_subnet = append(data_subnet, subnet)
	}

	var start, end int = 0, 0
	var first bool = true
	var subnetPerMsg int = 600
	var msg []byte

	num := len(data_subnet)
	log.WithFields(log.Fields{"internal_subnet_num": num}).Debug("config internal subnet")

	for num > 0 || first {
		var flag uint = 0

	retry:
		flag = 0
		if start == 0 {
			flag = C.MSG_START
		}
		if num <= subnetPerMsg {
			flag |= C.MSG_END
			end = start + num
		} else {
			end = start + subnetPerMsg
		}
		data := DPInternalSubnetCfgReq{
			SubnetCfg: &DPInternalSubnetCfg{
				Flag:    flag,
				Subnets: data_subnet[start:end],
			},
		}

		msg, _ = json.Marshal(data)
		sz := len(msg)
		if sz > maxMsgSize {
			// a very rough way to calculate rulesPerMsg
			newSubnetPerMsg := maxMsgSize / (sz/(end-start) + 1)
			if newSubnetPerMsg == subnetPerMsg {
				newSubnetPerMsg--
			}
			if newSubnetPerMsg == 0 {
				log.WithFields(log.Fields{"internal_subnet": data_subnet[start]}).Error("internal subnet too large")
				return
			}
			subnetPerMsg = newSubnetPerMsg
			goto retry
		}

		if dpSendMsg(msg) == -1 {
			log.Debug("dpSendMsg error")
			return
		}
		num = num + start - end
		start = end
		first = false
	}
}

func DPCtrlConfigSpecialIPSubnet(subnets map[string]share.CLUSSpecSubnet) {
	data_subnet := make([]DPSpecSubnet, 0, len(subnets))
	for _, addr := range subnets {
		if !utils.IsIPv4(addr.Subnet.IP) {
			continue
		}
		subnet := DPSpecSubnet{
			IP:     addr.Subnet.IP,
			Mask:   net.IP(addr.Subnet.Mask),
			IpType: addr.IpType,
		}
		data_subnet = append(data_subnet, subnet)
	}

	var start, end int = 0, 0
	var first bool = true
	var subnetPerMsg int = 600

	num := len(data_subnet)
	log.WithFields(log.Fields{"special_net_num": num}).Debug("config special subnet")

	for num > 0 || first {
		var flag uint = 0

	retry:
		flag = 0
		if start == 0 {
			flag = C.MSG_START
		}
		if num <= subnetPerMsg {
			flag |= C.MSG_END
			end = start + num
		} else {
			end = start + subnetPerMsg
		}
		data := DPSpecialIPSubnetCfgReq{
			SubnetCfg: &DPSpecIPSubnetCfg{
				Flag:    flag,
				Subnets: data_subnet[start:end],
			},
		}

		msg, _ := json.Marshal(data)
		sz := len(msg)
		if sz > maxMsgSize {
			// a very rough way to calculate rulesPerMsg
			newSubnetPerMsg := maxMsgSize / (sz/(end-start) + 1)
			if newSubnetPerMsg == subnetPerMsg {
				newSubnetPerMsg--
			}
			if newSubnetPerMsg == 0 {
				log.WithFields(log.Fields{"specialIP_subnet": data_subnet[start]}).Error("special subnet too large")
				return
			}
			subnetPerMsg = newSubnetPerMsg
			goto retry
		}

		if dpSendMsg(msg) == -1 {
			log.Debug("dpSendMsg error")
			return
		}
		num = num + start - end
		start = end
		first = false
	}
}

func DPCtrlConfigDlp(wldlprule *DPWorkloadDlpRule) int {
	var start, end int = 0, 0
	var start1, end1 int = 0, 0
	var first bool = true
	var rulesPerMsg int = 40

	num := len(wldlprule.DlpRuleNames)
	num1 := len(wldlprule.WafRuleNames)
	total := num + num1
	log.WithFields(log.Fields{
		"workload": wldlprule.WlID, "mac": wldlprule.WorkloadMac,
		"policyids":  wldlprule.PolicyRuleIds,
		"polwafids":  wldlprule.PolWafRuleIds,
		"dlprulenum": num,
		"wafrulenum": num1,
		"total":      total,
	}).Debug("config dlp")

	for total > 0 || first {
		var flag uint = 0

	retry:
		flag = 0
		if start == 0 {
			flag = C.MSG_START
		}
		if total <= rulesPerMsg {
			flag |= C.MSG_END
			end = start + num
			end1 = start1 + num1
		} else {
			tlen := rulesPerMsg / 2
			if num <= tlen {
				end = start + num
				if num1 > (rulesPerMsg - num) {
					end1 = start1 + (rulesPerMsg - num)
				} else {
					end1 = start1 + num1
				}
			} else {
				end = start + tlen
				if num1 > (rulesPerMsg - tlen) {
					end1 = start1 + (rulesPerMsg - tlen)
				} else {
					end1 = start1 + num1
				}
			}
		}
		data := DPDlpCfgReq{
			DPWlDlpCfg: &DPDlpCfg{
				Flag:         flag,
				WorkloadMac:  wldlprule.WorkloadMac,
				DlpRuleNames: make([]*DPDlpRidSetting, 0),
				WafRuleNames: make([]*DPDlpRidSetting, 0),
				RuleIds:      wldlprule.PolicyRuleIds,
				WafRuleIds:   wldlprule.PolWafRuleIds,
				RuleType:     wldlprule.RuleType,
				WafRuleType:  wldlprule.WafRuleType,
			},
		}
		for _, drn := range wldlprule.DlpRuleNames[start:end] {
			drids := &DPDlpRidSetting{
				ID:     drn.ID,
				Action: drn.Action,
			}
			data.DPWlDlpCfg.DlpRuleNames = append(data.DPWlDlpCfg.DlpRuleNames, drids)
		}
		for _, wrn := range wldlprule.WafRuleNames[start1:end1] {
			wrids := &DPDlpRidSetting{
				ID:     wrn.ID,
				Action: wrn.Action,
			}
			data.DPWlDlpCfg.WafRuleNames = append(data.DPWlDlpCfg.WafRuleNames, wrids)
		}
		msg, _ := json.Marshal(data)
		sz := len(msg)
		if sz > maxMsgSize {
			// a very rough way to calculate rulesPerMsg
			newRulesPerMsg := maxMsgSize / (sz/((end-start)+(end1-start1)) + 1)
			if newRulesPerMsg == rulesPerMsg {
				newRulesPerMsg--
			}
			if newRulesPerMsg == 0 {
				log.WithFields(log.Fields{
					"DlpRuleNames": wldlprule.DlpRuleNames[start],
					"WafRuleNames": wldlprule.WafRuleNames[start1]},
				).Error("rulenames too large")
				return -1
			}
			rulesPerMsg = newRulesPerMsg
			goto retry
		}

		if dpSendMsg(msg) == -1 {
			log.Debug("dpSendMsg error")
			return -1
		}
		num = num + start - end
		start = end
		num1 = num1 + start1 - end1
		start1 = end1
		total = num + num1
		first = false
	}
	return 0
}

func DPCtrlBldDlp(dlpRulesInfo []*DPDlpRuleEntry, dlpDpMacs utils.Set, delmacs utils.Set, dlpApplyDir int) int {
	var start, end int = 0, 0
	var first bool = true
	var rulesPerMsg int = 40

	num := len(dlpRulesInfo)
	macNum := dlpDpMacs.Cardinality()
	delmacNum := 0
	if delmacs != nil {
		delmacNum = delmacs.Cardinality()
	}
	log.WithFields(log.Fields{
		"dlpRuleNum": num, "macNum": macNum, "delmacNum": delmacNum,
	}).Debug("build dlp")

	for num > 0 || first {
		var flag uint = 0

	retry:
		flag = 0
		if start == 0 {
			flag = C.MSG_START
		}
		if num <= rulesPerMsg {
			flag |= C.MSG_END
			end = start + num
		} else {
			end = start + rulesPerMsg
		}
		data := DPDlpBldReq{
			DPDlpBld: &DPDlpBuild{
				Flag:        flag,
				ApplyDir:    dlpApplyDir,
				DlpRules:    dlpRulesInfo[start:end],
				WorkloadMac: make([]string, 0),
				DelMac:      make([]string, 0),
			},
		}
		for mc := range dlpDpMacs.Iter() {
			data.DPDlpBld.WorkloadMac = append(data.DPDlpBld.WorkloadMac, mc.(string))
		}
		if delmacs != nil {
			for dmc := range delmacs.Iter() {
				data.DPDlpBld.DelMac = append(data.DPDlpBld.DelMac, dmc.(string))
			}
		}
		msg, _ := json.Marshal(data)
		sz := len(msg)
		if sz > maxMsgSize {
			// a very rough way to calculate rulesPerMsg
			newRulesPerMsg := maxMsgSize / (sz/(end-start) + 1)
			if newRulesPerMsg == rulesPerMsg {
				newRulesPerMsg--
			}
			if newRulesPerMsg == 0 {
				log.WithFields(log.Fields{
					"DlpRules": dlpRulesInfo[start]},
				).Error("rules too large")
				return -1
			}
			rulesPerMsg = newRulesPerMsg
			goto retry
		}

		if dpSendMsg(msg) == -1 {
			return -1
		}
		num = num + start - end
		start = end
		first = false
	}
	return 0
}

func DPCtrlBldDlpChgMac(oldmacs, addmacs, delmacs utils.Set) {

	data := DPDlpBldMACReq{
		DPDlpChgBldMac: &DPDlpBldMac{
			OldMac: make([]string, 0),
			AddMac: make([]string, 0),
			DelMac: make([]string, 0),
		},
	}
	for omac := range oldmacs.Iter() {
		data.DPDlpChgBldMac.OldMac = append(data.DPDlpChgBldMac.OldMac, omac.(string))
	}
	for amac := range addmacs.Iter() {
		data.DPDlpChgBldMac.AddMac = append(data.DPDlpChgBldMac.AddMac, amac.(string))
	}
	for dmac := range delmacs.Iter() {
		data.DPDlpChgBldMac.DelMac = append(data.DPDlpChgBldMac.DelMac, dmac.(string))
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

func DPCtrlDlpCfgChgMac(delmacs utils.Set) {

	data := DPDlpCfgMACReq{
		DPDlpChgCfgMac: &DPDlpCfgMac{
			DelMac: make([]string, 0),
		},
	}
	for dmac := range delmacs.Iter() {
		data.DPDlpChgCfgMac.DelMac = append(data.DPDlpChgCfgMac.DelMac, dmac.(string))
	}
	msg, _ := json.Marshal(data)
	if dpSendMsg(msg) == -1 {
		log.Debug("dpSendMsg send error")
	}
}

// --- keep alive

func cbKeepAlive(buf []byte, param interface{}) bool {
	if len(buf) == 0 {
		log.Error("Empty message, close dp socket")
		closeDP()
		return true
	}

	hdr := ParseDPMsgHeader(buf)
	if hdr == nil {
		log.Error("Invalid DP message header")
		return false
	} else if hdr.Kind != C.DP_KIND_KEEP_ALIVE {
		// Keep waiting
		log.Error("Not keep-alive message")
		return false
	}

	var received uint32
	offset := int(unsafe.Sizeof(*hdr))
	r := bytes.NewReader(buf[offset:])
	if dbgError := binary.Read(r, binary.BigEndian, &received); dbgError != nil {
		log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
	}
	if received == keepAliveSeq {
		// Matched response
		return true
	}

	// Keep waiting
	log.WithFields(log.Fields{
		"len": len(buf), "expect": keepAliveSeq, "received": received,
	}).Error("Receive mismatched reply")
	return false
}

func dpKeepAlive() {
	keepAliveSeq++
	seq := keepAliveSeq
	data := DPKeepAliveReq{
		Alive: &DPKeepAlive{SeqNum: seq},
	}
	msg, _ := json.Marshal(data)
	dpSendMsgExSilent(msg, 3, cbKeepAlive, &seq)
}

func monitorDP() {
	dpTicker := time.Tick(dpKeepAliveInterval)
	dpConnJamRetry := 0

	for {
		<-dpTicker
		// Connect to DP if not; keep alive is connected.
		if dpConn == nil {
			if dpConnJamRetry > dpConnJamRetryMax {
				log.WithFields(log.Fields{"retry": dpConnJamRetry}).Error("dp socket congestion.")
				// log.WithFields(log.Fields{"retry": dpConnJamRetry}).Error("dp socket congestion. Exit!")
				// restartChan <- nil
				// break
			}

			log.WithFields(log.Fields{"retry": dpConnJamRetry}).Info("Connecting to DP socket ...")
			newConn := connectDP()
			if newConn != nil {
				dpClientLock()
				dpConn = newConn
				// align msg with DP using keep alive
				dpKeepAlive()
				dpClientUnlock()

				if dpConn != nil {
					log.Info("DP Connected")
					dpConnJamRetry = 0
					statusChan <- true
				} else {
					// This is to detect communication socket congestion, so only increment when
					// connection is made.
					dpConnJamRetry++
				}
			} else {
				dpConnJamRetry = 0
			}
		} else if dpAliveMsgCnt == 0 {
			// Only a best effort to avoid unecessary keep alive.
			dpClientLock()
			dpKeepAlive()
			dpClientUnlock()

			// Cannot send notify in closeDP() as it holds dpClientMutex, at the same time docker
			// goroutine can send dp message but cannot get the mutex -> deadlock
			if dpConn == nil {
				statusChan <- false
			}
		} else {
			dpAliveMsgCnt = 0
		}
	}
}

func connectDP() *net.UnixConn {
	var conn *net.UnixConn
	var err error
	kind := "unixgram"
	lpath := getDPCtrlClientAddr()
	laddr := net.UnixAddr{Name: lpath, Net: kind}
	raddr := net.UnixAddr{Name: DPServer, Net: kind}

	conn, err = net.DialUnix(kind, &laddr, &raddr)
	if err != nil {
		os.Remove(lpath)
		return nil
	} else {
		return conn
	}
}

func closeDP() {
	if dpConn != nil {
		log.Info("DP Closed")
		dpConn.Close()
		dpConn = nil
	}
	os.Remove(getDPCtrlClientAddr())
}

func Open(cb DPTaskCallback, sc chan bool, ec chan interface{}) {
	log.Info("")

	taskCallback = cb
	statusChan = sc
	restartChan = ec

	go listenDP()
	go monitorDP()
}

func Close() {
	log.Info("")
	closeDP()
}

func Connected() bool {
	return (dpConn != nil)
}

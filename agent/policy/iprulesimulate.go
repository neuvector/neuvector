package policy

// #include "../../defs.h"
import "C"

import (
	"fmt"
	"net"
	"syscall"

	"github.com/neuvector/neuvector/agent/dp"
	"github.com/neuvector/neuvector/share"
	log "github.com/sirupsen/logrus"
)

// test a large number of ip rules being deployed in a single ep
const ENODEMAX int = 80       //number of nodes
const EWLPERNODEMAX int = 250 //number of wl per node
const SIMULATEFREQ int = 3    //every SIMULATEFREQ wl, add large number of ip rules
const UDPFREQ int = 25
const FQDNFREQ1 int = 15
const FQDNFREQ2 int = 35
const FQDNFREQ3 int = 45
const APPFREQ1 int = 12
const APPFREQ2 int = 13
const APPFREQ3 int = 14

var gSimCnt int = 0

func simulateAddLargeNumIPRules(policy *dp.DPWorkloadIPPolicy, applyDir int) {
	//log.WithFields(log.Fields{"simcnt": gSimCnt}).Debug("")
	if gSimCnt%SIMULATEFREQ == 0 {
		gSimCnt++
	} else {
		gSimCnt++
		return
	}
	var aIP, aIPR net.IP
	if applyDir&C.DP_POLICY_APPLY_EGRESS > 0 {
		for _, iprule := range policy.IPRules {
			if !iprule.Ingress {
				aIP = iprule.SrcIP
				aIPR = iprule.SrcIPR
				break
			}
		}
	} else if applyDir&C.DP_POLICY_APPLY_INGRESS > 0 {
		for _, iprule := range policy.IPRules {
			if iprule.Ingress {
				aIP = iprule.DstIP
				aIPR = iprule.DstIPR
				break
			}
		}
	}
	log.WithFields(log.Fields{"aip": aIP, "aipr": aIPR}).Debug("")

	var gip [4]byte
	var ipRuleMap map[string]*dp.DPPolicyIPRule = make(map[string]*dp.DPPolicyIPRule)
	for i := 0; i < ENODEMAX; i++ { //loop around node
		for j := 0; j < EWLPERNODEMAX; j++ { //loop around wl within a node
			gip[0] = 192
			gip[1] = 168
			gip[2] = byte((i + 1) % 255)
			gip[3] = byte((j + 1) % 255)
			tid := (i+1)*EWLPERNODEMAX + (j + 1) + (share.PolicyLearnedIDBase + 1000)
			rule := dp.DPPolicyIPRule{
				ID:      uint32(tid % share.PolicyGroundRuleIDMax),
				Port:    0,
				PortR:   65535,
				IPProto: syscall.IPPROTO_TCP,
				Action:  C.DP_POLICY_ACTION_LEARN,
			}
			if applyDir&C.DP_POLICY_APPLY_EGRESS > 0 {
				rule.SrcIP = aIP
				rule.SrcIPR = aIPR
				rule.DstIP = net.IPv4(gip[0], gip[1], gip[2], gip[3])
				rule.Ingress = false
			}
			if applyDir&C.DP_POLICY_APPLY_INGRESS > 0 {
				rule.DstIP = aIP
				rule.DstIPR = aIPR
				rule.SrcIP = net.IPv4(gip[0], gip[1], gip[2], gip[3])
				rule.Ingress = true
			}

			if ((i+1)*(j+1))%UDPFREQ == 0 {
				rule.IPProto = syscall.IPPROTO_UDP
			}

			if ((i+1)*(j+1))%FQDNFREQ1 == 0 {
				rule.SrcIP = aIP
				rule.SrcIPR = aIPR
				rule.DstIP = net.IPv4(0, 0, 0, 0)
				rule.Ingress = false
				rule.Fqdn = "*.google.com"
			}

			if ((i+1)*(j+1))%FQDNFREQ2 == 0 {
				rule.SrcIP = aIP
				rule.SrcIPR = aIPR
				rule.DstIP = net.IPv4(0, 0, 0, 0)
				rule.Ingress = false
				rule.Fqdn = "*.microsoftonline.com"
			}

			if ((i+1)*(j+1))%FQDNFREQ3 == 0 {
				rule.SrcIP = aIP
				rule.SrcIPR = aIPR
				rule.DstIP = net.IPv4(0, 0, 0, 0)
				rule.Ingress = false
				rule.Fqdn = "*.cntv.cn"
			}
			var key string
			if rule.Ingress {
				if rule.IPProto == syscall.IPPROTO_TCP {
					key = fmt.Sprintf("%v%v%s%s%d", rule.SrcIP, rule.DstIP, "tcp/any", rule.Fqdn, 1)
				}
				if rule.IPProto == syscall.IPPROTO_UDP {
					key = fmt.Sprintf("%v%v%s%s%d", rule.SrcIP, rule.DstIP, "udp/any", rule.Fqdn, 1)
				}
			} else {
				if rule.IPProto == syscall.IPPROTO_TCP {
					key = fmt.Sprintf("%v%v%s%s%d", rule.SrcIP, rule.DstIP, "tcp/any", rule.Fqdn, 0)
				}
				if rule.IPProto == syscall.IPPROTO_UDP {
					key = fmt.Sprintf("%v%v%s%s%d", rule.SrcIP, rule.DstIP, "udp/any", rule.Fqdn, 0)
				}
			}
			if rule.SrcIPR != nil {
				key = fmt.Sprintf("%s%v", key, rule.SrcIPR)
			}
			if rule.DstIPR != nil {
				key = fmt.Sprintf("%s%v", key, rule.DstIPR)
			}

			var application uint32 = 0

			if ((i+1)*(j+1))%APPFREQ1 == 0 {
				application = C.DPI_APP_HTTP
			}

			if ((i+1)*(j+1))%APPFREQ2 == 0 {
				application = C.DPI_APP_SSH
			}

			if ((i+1)*(j+1))%APPFREQ3 == 0 {
				application = C.DPI_APP_REDIS
			}

			if existRule, ok := ipRuleMap[key]; ok {
				if existRule.Action != C.DP_POLICY_ACTION_CHECK_APP {
					continue
				}
				var found bool = false
				for _, app := range existRule.Apps {
					if app.App == application {
						found = true
						break
					}
				}
				if !found {
					appRule := &dp.DPPolicyApp{
						App:    application,
						Action: C.DP_POLICY_ACTION_LEARN,
						RuleID: existRule.ID,
					}
					existRule.Apps = append(existRule.Apps, appRule)
				}
				continue
			}
			if application > 0 {
				appRule := &dp.DPPolicyApp{
					App:    application,
					Action: C.DP_POLICY_ACTION_LEARN,
					RuleID: rule.ID,
				}
				rule.Apps = append(rule.Apps, appRule)
				rule.Action = C.DP_POLICY_ACTION_CHECK_APP
			}

			//log.WithFields(log.Fields{"rule": rule}).Debug("")
			policy.IPRules = append(policy.IPRules, &rule)
			ipRuleMap[key] = &rule
		}
	}
	ipRuleMap = nil
}

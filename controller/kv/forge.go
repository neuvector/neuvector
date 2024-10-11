package kv

// #include "../../defs.h"
import "C"

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
)

func forgeKVData() {
	max := 10000

	for i := 0; i < max; i++ {
		var criteria []share.CLUSCriteriaEntry

		svc := fmt.Sprintf("svc.%d", i)
		domain := "default"

		criteria = append(criteria, share.CLUSCriteriaEntry{
			Key:   share.CriteriaKeyService,
			Value: svc,
			Op:    share.CriteriaOpEqual,
		})
		criteria = append(criteria, share.CLUSCriteriaEntry{
			Key:   share.CriteriaKeyDomain,
			Value: domain,
			Op:    share.CriteriaOpEqual,
		})

		cg := &share.CLUSGroup{
			Name:            "nv." + svc,
			CfgType:         share.Learned,
			Criteria:        criteria,
			PolicyMode:      share.PolicyModeLearn,
			ProfileMode:     share.PolicyModeLearn,
			Domain:          domain,
			Kind:            share.GroupKindContainer,
			CapIntcp:        true,
			BaselineProfile: share.ProfileZeroDrift, // for learned groups, default to zero-drift mode
		}

		if err := clusHelper.PutGroup(cg, true); err != nil {
			log.WithFields(log.Fields{"error": err, "group": cg.Name}).Error()
		}
	}

	for i := 0; i < max; i++ {
		j := i + 1
		if i == max-1 {
			j = 0
		}

		rule := share.CLUSPolicyRule{
			ID:           share.PolicyLearnedIDBase + uint32(i),
			From:         fmt.Sprintf("nv.svc.%d", i),
			To:           fmt.Sprintf("nv.svc.%d", j),
			Ports:        api.PolicyPortAny,
			Applications: make([]uint32, 0),
			Action:       share.PolicyActionAllow,
			CfgType:      share.Learned,
		}

		if err := clusHelper.PutPolicyRule(&rule); err != nil {
			log.WithFields(log.Fields{"error": err, "rule": rule.ID}).Error()
		}
	}

	crh := make([]*share.CLUSRuleHead, 0)
	for i := 0; i < max; i++ {
		crh = append(crh, &share.CLUSRuleHead{ID: share.PolicyLearnedIDBase + uint32(i), CfgType: share.Learned})
	}

	if err := clusHelper.PutPolicyRuleList(crh); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
	}
}

// to test policy calculation oversize issue
// adjust number of nodes(NODEMAX) and number
// of workloads per node(WLPERNODEMAX)
const NODEMAX int = 600
const WLPERNODEMAX int = 250

var FAKEWLID string = "9321f8a6951c550e2d1634b32b859ed6ed167752b8a8552f95dad7eb33de8e2a"
var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

func printOneGroupIPPolicyFake(p *share.CLUSGroupIPPolicy) {
	value, _ := json.Marshal(p)
	log.WithFields(log.Fields{"value": string(value)}).Debug("")
}

func StringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func getDefaultGroupPolicyFake() share.CLUSGroupIPPolicy {
	var gip [4]byte
	var hip [4]byte

	policy := share.CLUSGroupIPPolicy{
		ID: share.DefaultGroupRuleID,
	}

	policy.From = make([]*share.CLUSWorkloadAddr, 0, NODEMAX*WLPERNODEMAX)
	for i := 0; i < NODEMAX; i++ { //loop around node
		hip[0] = 10
		hip[1] = 1
		hip[2] = 6
		hip[3] = byte(i % 255)
		for j := 0; j < WLPERNODEMAX; j++ { //loop around wl within a node
			wlAddr := share.CLUSWorkloadAddr{
				WlID: StringWithCharset(len(FAKEWLID), FAKEWLID),
			}
			wlAddr.PolicyMode = share.PolicyModeLearn

			gip[0] = 192
			gip[1] = 168
			gip[2] = byte(i % 255)
			gip[3] = byte(j % 255)
			wlAddr.GlobalIP = append(wlAddr.GlobalIP, net.IPv4(gip[0], gip[1], gip[2], gip[3]))

			wlAddr.NatIP = append(wlAddr.NatIP, net.IPv4(hip[0], hip[1], hip[2], hip[3]))

			wlAddr.NatPortApp = []share.CLUSPortApp{
				{
					Ports:       "any",
					Application: C.DP_POLICY_APP_ANY,
				},
			}
			policy.From = append(policy.From, &wlAddr)
		}
	}
	//printOneGroupIPPolicyFake(&policy)
	return policy
}

func CalculateIPPolicyFromCacheFake() []share.CLUSGroupIPPolicy {
	groupIPPolicies := make([]share.CLUSGroupIPPolicy, 0, NODEMAX*WLPERNODEMAX+1)
	groupIPPolicies = append(groupIPPolicies, getDefaultGroupPolicyFake())

	var gip [4]byte
	var hip [4]byte

	for i := 0; i < NODEMAX; i++ { //loop around node
		hip[0] = 10
		hip[1] = 1
		hip[2] = 6
		hip[3] = byte(i % 255)
		for j := 0; j < WLPERNODEMAX; j++ { //loop around wl within a node
			policy := share.CLUSGroupIPPolicy{
				ID:     uint32(((i + 1) * (j + 1)) % share.PolicyGroundRuleIDMax),
				Action: C.DP_POLICY_ACTION_ALLOW,
			}
			wlAddrFrom := share.CLUSWorkloadAddr{
				WlID: StringWithCharset(len(FAKEWLID), FAKEWLID),
			}
			wlAddrFrom.PolicyMode = share.PolicyModeLearn

			gip[0] = 192
			gip[1] = 168
			gip[2] = byte((i + 1) % 255)
			gip[3] = byte((j + 1) % 255)
			wlAddrFrom.GlobalIP = append(wlAddrFrom.GlobalIP, net.IPv4(gip[0], gip[1], gip[2], gip[3]))
			wlAddrFrom.NatIP = append(wlAddrFrom.NatIP, net.IPv4(hip[0], hip[1], hip[2], hip[3]))

			policy.From = append(policy.From, &wlAddrFrom)
			//to
			wlAddrTo := share.CLUSWorkloadAddr{
				WlID: StringWithCharset(len(FAKEWLID), FAKEWLID),
			}
			wlAddrTo.PolicyMode = share.PolicyModeLearn

			gip[0] = 192
			gip[1] = 168
			gip[2] = byte((i + 2) % 255)
			gip[3] = byte((j + 1) % 255)

			wlAddrTo.GlobalIP = append(wlAddrTo.GlobalIP, net.IPv4(gip[0], gip[1], gip[2], gip[3]))

			wlAddrTo.NatIP = append(wlAddrTo.NatIP, net.IPv4(hip[0], hip[1], hip[2], hip[3]))

			wlAddrTo.NatPortApp = []share.CLUSPortApp{
				{
					Ports:       "any",
					Application: C.DP_POLICY_APP_ANY,
				},
			}
			policy.To = append(policy.To, &wlAddrTo)
			groupIPPolicies = append(groupIPPolicies, policy)
			//printOneGroupIPPolicyFake(&policy)
		}
	}
	return groupIPPolicies
}

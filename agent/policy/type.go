package policy

import (
	"sync"
	"net"

	"github.com/neuvector/neuvector/agent/dp"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

var polAppDir int

type GroupProcPolicyCallback func(id string) (*share.CLUSProcessProfile, bool)

type WorkloadIPPolicyInfo struct {
	RuleMap    map[string]*dp.DPPolicyIPRule
	AppMap     map[share.CLUSProtoPort]*share.CLUSApp
	PortMap    map[share.CLUSProtoPort]*share.CLUSMappedPort
	Policy     dp.DPWorkloadIPPolicy
	Configured bool
	SkipPush   bool
	HostMode   bool
	CapIntcp   bool
}

type DlpBuildInfo struct {
	DlpRulesInfo []*dp.DPDlpRuleEntry
	DlpDpMacs    utils.Set
	ApplyDir     int
}

type Engine struct {
	NetworkPolicy  map[string]*WorkloadIPPolicyInfo
	ProcessPolicy  map[string]*share.CLUSProcessProfile
	DlpWlRulesInfo map[string]*dp.DPWorkloadDlpRule
	DlpBldInfo     *DlpBuildInfo
	HostID         string
	HostIPs        utils.Set
	TunnelIP       []net.IPNet
	Mutex          sync.Mutex
	getGroupRule   GroupProcPolicyCallback
	PolicyAddrMap  map[string]share.CLUSSubnet
}

func (e *Engine) Init(HostID string, HostIPs utils.Set, TunnelIP []net.IPNet, cb GroupProcPolicyCallback, pad int) {
	e.HostID = HostID
	e.HostIPs = HostIPs
	e.TunnelIP = TunnelIP
	e.ProcessPolicy = make(map[string]*share.CLUSProcessProfile, 0)
	e.DlpWlRulesInfo = make(map[string]*dp.DPWorkloadDlpRule, 0)
	e.DlpBldInfo = &DlpBuildInfo{
		DlpRulesInfo: make([]*dp.DPDlpRuleEntry, 0),
		DlpDpMacs:    utils.NewSet(),
	}
	e.getGroupRule = cb
	e.PolicyAddrMap = make(map[string]share.CLUSSubnet)
	polAppDir = pad
}

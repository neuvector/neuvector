package dp

import (
	"net"
)

const DPServer string = "/tmp/dp_listen.sock"

type DPEmpty struct {
}

type DPKeepAlive struct {
	SeqNum uint32 `json:"seq_num"`
}

type DPKeepAliveReq struct {
	Alive *DPKeepAlive `json:"ctrl_keep_alive"`
}

type DPTapPort struct {
	NetNS string `json:"netns"`
	Iface string `json:"iface"`
	EPMAC string `json:"epmac"`
}

type DPAddTapPortReq struct {
	AddPort *DPTapPort `json:"ctrl_add_tap_port"`
}

type DPDelTapPortReq struct {
	DelPort *DPTapPort `json:"ctrl_del_tap_port"`
}

type DPNfqPort struct {
	NetNS      string `json:"netns"`
	Iface      string `json:"iface"`
	Qnum       int    `json:"qnum"`
	EPMAC      string `json:"epmac"`
	JumboFrame *bool  `json:"jumboframe,omitempty"`
}

type DPAddNfqPortReq struct {
	AddNfqPort *DPNfqPort `json:"ctrl_add_nfq_port"`
}

type DPDelNfqPortReq struct {
	DelNfqPort *DPNfqPort `json:"ctrl_del_nfq_port"`
}

type DPSrvcPort struct {
	Iface      string `json:"iface"`
	JumboFrame *bool  `json:"jumboframe,omitempty"`
}

type DPAddSrvcPortReq struct {
	AddPort *DPSrvcPort `json:"ctrl_add_srvc_port"`
}

type DPDelSrvcPortReq struct {
	DelPort *DPSrvcPort `json:"ctrl_del_srvc_port"`
}

type DPPortPair struct {
	IfaceVex string `json:"vex_iface"`
	IfaceVin string `json:"vin_iface"`
	EPMAC    string `json:"epmac"`
	Quar     *bool  `json:"quar,omitempty"`
}

type DPAddPortPairReq struct {
	AddPortPair *DPPortPair `json:"ctrl_add_port_pair"`
}

type DPDelPortPairReq struct {
	DelPortPair *DPPortPair `json:"ctrl_del_port_pair"`
}

type DPProtoPortApp struct {
	IPProto     uint8  `json:"ip_proto"`
	Port        uint16 `json:"port"`
	Application uint32 `json:"app"`
	Server      uint32 `json:"server"`
}

type DPMacPip struct {
	IP net.IP `json:"ip"`
}

type DPAddMAC struct {
	Iface  string     `json:"iface"`
	MAC    string     `json:"mac"`
	UCMAC  string     `json:"ucmac"`
	BCMAC  string     `json:"bcmac"`
	OldMAC string     `json:"oldmac"`
	PMAC   string     `json:"pmac"`
	PIPS   []DPMacPip `json:"pips"`
}

type DPAddMACReq struct {
	AddMAC *DPAddMAC `json:"ctrl_add_mac"`
}

type DPDelMAC struct {
	Iface string `json:"iface"`
	MAC   string `json:"mac"`
}

type DPMACArray struct {
	MACs []string `json:"macs"`
}

type DPDelMACReq struct {
	DelMAC *DPDelMAC `json:"ctrl_del_mac"`
}

type DPMacConfig struct {
	MACs []string          `json:"macs"`
	Tap  *bool             `json:"tap,omitempty"`
	Apps *[]DPProtoPortApp `json:"apps,omitempty"`
}

type DPConfigMACReq struct {
	Cfg *DPMacConfig `json:"ctrl_cfg_mac"`
}

type DPNbeConfig struct {
	MACs []string `json:"macs"`
	Nbe  *bool    `json:"nbe,omitempty"`
}

type DPConfigNbeReq struct {
	Cfg *DPNbeConfig `json:"ctrl_cfg_nbe"`
}

type DPRefreshApp struct {
}

type DPRefreshAppReq struct {
	RefreshApp *DPRefreshApp `json:"ctrl_refresh_app"`
}

type DPSysConf struct {
	XffEnabled *bool `json:"xff_enabled"`
}

type DPSysConfReq struct {
	Sysconf *DPSysConf `json:"ctrl_sys_conf"`
}

type DPDisableNetPolicy struct {
	DisableNetPolicy *bool `json:"disable_net_policy"`
}

type DPDisableNetPolicyReq struct {
	DisableNetPolicyConf *DPDisableNetPolicy `json:"ctrl_disable_net_policy"`
}

type DPDetectUnmanagedWl struct {
	DetectUnmanagedWl *bool `json:"detect_unmanaged_wl"`
}

type DPDetectUnmanagedWlReq struct {
	DetectUnmanagedWlConf *DPDetectUnmanagedWl `json:"ctrl_detect_unmanaged_wl"`
}

type DPEnableIcmpPolicy struct {
	EnableIcmpPolicy *bool `json:"enable_icmp_policy"`
}

type DPEnableIcmpPolicyReq struct {
	EnableIcmpPolicyConf *DPEnableIcmpPolicy `json:"ctrl_enable_icmp_policy"`
}

type DPStatsMACReq struct {
	Stats *DPMACArray `json:"ctrl_stats_macs"`
}

type DPStatsAgentReq struct {
	Stats *DPEmpty `json:"ctrl_stats_device"`
}

type DPCounterAgentReq struct {
	Counter *DPEmpty `json:"ctrl_counter_device"`
}

type DPCountSessionReq struct {
	CountSession *DPEmpty `json:"ctrl_count_session"`
}

type DPListSessionReq struct {
	ListSession *DPEmpty `json:"ctrl_list_session"`
}

type DPClearSession struct {
	ID uint32 `json:"filter_id"`
}

type DPClearSessionReq struct {
	ClearSession *DPClearSession `json:"ctrl_clear_session"`
}

type DPListMeterReq struct {
	ListMeter *DPEmpty `json:"ctrl_list_meter"`
}

type DPDebug struct {
	Categories []string `json:"categories"`
}

type DPSetDebugReq struct {
	Debug *DPDebug `json:"ctrl_set_debug"`
}

/*
type DPGetDebugReq struct {
	Debug *DPEmpty `json:"ctrl_get_debug"`
}

type DPGetDebugResp struct {
	Debug DPDebug `json:"dp_debug"`
}
*/

type DPPolicyApp struct {
	App    uint32 `json:"app"`
	Action uint8  `json:"action"`
	RuleID uint32 `json:"rid"`
}

type DPPolicyIPRule struct {
	ID      uint32         `json:"id"`
	SrcIP   net.IP         `json:"sip"`
	DstIP   net.IP         `json:"dip"`
	SrcIPR  net.IP         `json:"sipr,omitempty"`
	DstIPR  net.IP         `json:"dipr,omitempty"`
	Port    uint16         `json:"port"`
	PortR   uint16         `json:"portr"`
	IPProto uint8          `json:"proto"`
	Action  uint8          `json:"action"`
	Ingress bool           `json:"ingress"`
	Fqdn    string         `json:"fqdn,omitempty"`
	Vhost   bool           `json:"vhost,omitempty"`
	Apps    []*DPPolicyApp `json:"apps,omitempty"`
}

type DPWorkloadIPPolicy struct {
	WlID        string            `json:"wl_id"`
	Mode        string            `json:"mode"`
	DefAction   uint8             `json:"defact"`
	ApplyDir    int               `json:"apply_dir"`
	WorkloadMac []string          `json:"mac"`
	IPRules     []*DPPolicyIPRule `json:"policy_rules"`
}

type DPPolicyCfg struct {
	Cmd         uint              `json:"cmd"`
	Flag        uint              `json:"flag"`
	DefAction   uint8             `json:"defact"`
	ApplyDir    int               `json:"dir"`
	WorkloadMac []string          `json:"mac"`
	IPRules     []*DPPolicyIPRule `json:"rules"`
}

type DPPolicyCfgReq struct {
	DPPolicyCfg *DPPolicyCfg `json:"ctrl_cfg_policy"`
}

type DPFqdnList struct {
	Names []string `json:"names"`
}

type DPFqdnDeleteReq struct {
	Delete *DPFqdnList `json:"ctrl_cfg_del_fqdn"`
}

type DPFqdnIps struct {
	FqdnName string   `json:"fqdn_name"`
	FqdnIps  []net.IP `json:"fqdn_ips"`
	Vhost    *bool    `json:"vhost,omitempty"`
}

type DPFqdnIpSetReq struct {
	Fqdns *DPFqdnIps `json:"ctrl_cfg_set_fqdn"`
}

type DPSubnet struct {
	IP   net.IP `json:"ip"`
	Mask net.IP `json:"mask"`
}

type DPSpecSubnet struct {
	IP     net.IP `json:"ip"`
	Mask   net.IP `json:"mask"`
	IpType string `json:"iptype"`
}

type DPInternalSubnetCfg struct {
	Flag    uint       `json:"flag"`
	Subnets []DPSubnet `json:"subnet_addr"`
}

type DPInternalSubnetCfgReq struct {
	SubnetCfg *DPInternalSubnetCfg `json:"ctrl_cfg_internal_net"`
}

type DPSpecIPSubnetCfg struct {
	Flag    uint           `json:"flag"`
	Subnets []DPSpecSubnet `json:"subnet_addr"`
}

type DPSpecialIPSubnetCfgReq struct {
	SubnetCfg *DPSpecIPSubnetCfg `json:"ctrl_cfg_specip_net"`
}

type DPPolicyAddressCfgReq struct {
	PolicyAddrCfg *DPInternalSubnetCfg `json:"ctrl_cfg_policy_addr"`
}

// dlp
type DPDlpSetting struct {
	Name   string `json:"name"`
	ID     uint32 `json:"id"`
	Action uint8  `json:"action"`
}

type DPDlpRidSetting struct {
	ID     uint32 `json:"id"`
	Action uint8  `json:"action"`
}

type DPWorkloadDlpRule struct {
	WlID          string          `json:"wl_id"`
	Mode          string          `json:"mode"`
	DefAction     uint8           `json:"defact"`
	ApplyDir      int             `json:"apply_dir"`
	WorkloadMac   []string        `json:"mac"`
	DlpRuleNames  []*DPDlpSetting `json:"dlp_rule_names"`
	WafRuleNames  []*DPDlpSetting `json:"waf_rule_names"`
	PolicyRuleIds []uint32        `json:"policy_rule_ids"`
	PolWafRuleIds []uint32        `json:"polwaf_rule_ids"`
	RuleType      string          `json:"ruletype"`
	WafRuleType   string          `json:"wafruletype"`
}

type DPDlpRuleEntry struct {
	Name     string   `json:"name"`
	ID       uint32   `json:"id"`
	Patterns []string `json:"patterns"`
}

type DPDlpCfg struct {
	Flag         uint               `json:"flag"`
	WorkloadMac  []string           `json:"mac"`
	DlpRuleNames []*DPDlpRidSetting `json:"dlp_rule_names"`
	WafRuleNames []*DPDlpRidSetting `json:"waf_rule_names"`
	RuleIds      []uint32           `json:"rule_ids"`
	WafRuleIds   []uint32           `json:"waf_rule_ids"`
	RuleType     string             `json:"ruletype"`
	WafRuleType  string             `json:"wafruletype"`
}

type DPDlpCfgReq struct {
	DPWlDlpCfg *DPDlpCfg `json:"ctrl_cfg_dlp"`
}

type DPDlpBuild struct {
	Flag        uint              `json:"flag"`
	ApplyDir    int               `json:"dir"`
	DlpRules    []*DPDlpRuleEntry `json:"dlp_rules"`
	WorkloadMac []string          `json:"mac"`
	DelMac      []string          `json:"delmac"`
}

type DPDlpBldReq struct {
	DPDlpBld *DPDlpBuild `json:"ctrl_bld_dlp"`
}

type DPDlpBldMac struct {
	OldMac []string `json:"oldmac"`
	AddMac []string `json:"addmac"`
	DelMac []string `json:"delmac"`
}

type DPDlpBldMACReq struct {
	DPDlpChgBldMac *DPDlpBldMac `json:"ctrl_bld_dlpmac"`
}

type DPDlpCfgMac struct {
	DelMac []string `json:"delmac"`
}

type DPDlpCfgMACReq struct {
	DPDlpChgCfgMac *DPDlpCfgMac `json:"ctrl_cfg_dlpmac"`
}

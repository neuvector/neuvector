package rest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/rpc"
	"github.com/neuvector/neuvector/controller/ruleid"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

var cfgTypeMap2Api = map[share.TCfgType]string{
	share.Learned:       api.CfgTypeLearned,
	share.UserCreated:   api.CfgTypeUserCreated,
	share.GroundCfg:     api.CfgTypeGround,
	share.FederalCfg:    api.CfgTypeFederal,
	share.SystemDefined: api.CfgSystemDefined,
}

var cfgTypeMapping = map[string]share.TCfgType{
	api.CfgTypeLearned:     share.Learned,
	api.CfgTypeUserCreated: share.UserCreated,
	api.CfgTypeGround:      share.GroundCfg,
	api.CfgTypeFederal:     share.FederalCfg,
	api.CfgSystemDefined:   share.SystemDefined,
}

func compareRESTRules(r1, r2 *api.RESTPolicyRule) bool {
	e := *r1
	r := *r2
	e.CreatedTS = 0
	e.LastModTS = 0
	r.CreatedTS = 0
	r.LastModTS = 0
	return reflect.DeepEqual(e, r)
}

func compareCLUSRules(r1, r2 *share.CLUSPolicyRule) bool {
	e := *r1
	r := *r2
	e.CreatedAt = time.Time{}
	e.LastModAt = time.Time{}
	r.CreatedAt = time.Time{}
	r.LastModAt = time.Time{}
	return reflect.DeepEqual(e, r)
}

func isLearnedPolicyID(id uint32) bool {
	//return id >= api.PolicyLearnedIDBase && id < 0x7fffffff
	return id >= api.PolicyLearnedIDBase && id < api.PolicyFedRuleIDBase
}

func isSecurityPolicyID(id uint32) bool {
	return id >= api.PolicyGroundRuleIDBase
}

func isFedPolicyID(id uint32) bool {
	return id >= api.PolicyFedRuleIDBase && id < api.PolicyFedRuleIDMax
}

func handlerPolicyRuleList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	query := restParseQuery(r)
	scope := query.pairs[api.QueryScope] // empty string means fed & local rules

	var resp api.RESTPolicyRulesData
	resp.Rules = make([]*api.RESTPolicyRule, 0)
	rules := cacher.GetAllPolicyRules(scope, acc)

	// Filter
	if len(rules) <= query.start {
		restRespSuccess(w, r, &resp, acc, login, nil, "Get policy rule list")
		return
	}

	if query.limit == 0 {
		resp.Rules = rules[query.start:]
	} else {
		var end int
		if query.start+query.limit > len(rules) {
			end = len(rules)
		} else {
			end = query.start + query.limit
		}
		resp.Rules = rules[query.start:end]
	}
	for _, rule := range resp.Rules {
		if rule.Learned && rule.CfgType == "" {
			rule.CfgType = api.CfgTypeLearned
		}
	}

	log.WithFields(log.Fields{"entries": len(resp.Rules)}).Debug("Response")

	restRespSuccess(w, r, &resp, acc, login, nil, "Get policy rule list")
}

func handlerPolicyRuleShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id, err := strconv.Atoi(ps.ByName("id"))
	if err != nil || id <= 0 {
		log.WithFields(log.Fields{"id": id}).Error("Invalid ID")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	var resp api.RESTPolicyRuleData

	// Retrieve the policy rule
	rule, err := cacher.GetPolicyRule(uint32(id), acc)
	if rule == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}
	if rule.Learned && rule.CfgType == "" {
		rule.CfgType = api.CfgTypeLearned
	}

	resp.Rule = rule

	restRespSuccess(w, r, &resp, acc, login, nil, "Get policy rule detail")
}

type portRange struct {
	proto, low, high int
}

type portRangeSorter struct {
	ports []portRange
}

func (s *portRangeSorter) Len() int {
	return len(s.ports)
}

func (s *portRangeSorter) Swap(i, j int) {
	s.ports[i], s.ports[j] = s.ports[j], s.ports[i]
}

func (s *portRangeSorter) Less(i, j int) bool {
	if s.ports[i].proto < s.ports[j].proto {
		return true
	} else if s.ports[i].proto > s.ports[j].proto {
		return false
	} else if s.ports[i].low < s.ports[j].low {
		return true
	} else if s.ports[i].low > s.ports[j].low {
		return false
	} else if s.ports[i].high < s.ports[j].high {
		return true
	}

	return false
}

// Parse port string in "80, 8080, 8500-8508, tcp/443, tcp/3306-3307, udp/53"
func parseRange(s string) (int, int, error) {
	var low, high int
	var err error

	if dash := strings.Index(s, "-"); dash != -1 {
		if low, err = strconv.Atoi(s[:dash]); err != nil {
			return 0, 0, err
		}
		if high, err = strconv.Atoi(s[dash+1:]); err != nil {
			return 0, 0, err
		}
		return low, high, nil
	} else {
		if low, err = strconv.Atoi(s); err != nil {
			return 0, 0, err
		}
		return low, low, nil
	}
}

func normalizePorts(s string) (string, error) {
	s = strings.Trim(s, " ")

	if len(s) == 0 || strings.EqualFold(s, api.PolicyPortAny) {
		return api.PolicyPortAny, nil
	}

	// Split the string with , and space
	fs := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' '
	})

	var tcpAny, udpAny, icmp bool
	var err error

	ports := make([]portRange, 0)

	for _, f := range fs {
		var low, high int

		proto := syscall.IPPROTO_TCP
		if strings.HasPrefix(f, "tcp/") || strings.HasPrefix(f, "TCP/") {
			if strings.EqualFold(f[4:], api.PolicyPortAny) {
				tcpAny = true
				continue
			} else {
				low, high, err = parseRange(f[4:])
			}
		} else if strings.HasPrefix(f, "udp/") || strings.HasPrefix(f, "UDP/") {
			if strings.EqualFold(f[4:], api.PolicyPortAny) {
				udpAny = true
				continue
			} else {
				proto = syscall.IPPROTO_UDP
				low, high, err = parseRange(f[4:])
			}
		} else if f == "icmp" {
			icmp = true
			continue
		} else {
			if strings.EqualFold(f, api.PolicyPortAny) {
				tcpAny = true
				udpAny = true
				continue
			} else {
				low, high, err = parseRange(f)
			}
		}

		if err != nil {
			return "", err
		}

		if low < 0 || low > 65535 || high < 0 || high > 65535 || low > high {
			return "", errors.New("Invalid ports format")
		}

		ports = append(ports, portRange{proto: proto, low: low, high: high})
	}

	sorter := portRangeSorter{ports: make([]portRange, 0)}
	for _, port := range ports {
		if tcpAny && port.proto == syscall.IPPROTO_TCP {
			continue
		} else if udpAny && port.proto == syscall.IPPROTO_UDP {
			continue
		} else {
			sorter.ports = append(sorter.ports, port)
		}
	}

	sort.Sort(&sorter)

	// Join sorted port list
	strs := make([]string, 0)
	if icmp {
		strs = append(strs, "icmp")
	}
	if tcpAny && udpAny {
		strs = append(strs, api.PolicyPortAny)
	} else if tcpAny {
		strs = append(strs, fmt.Sprintf("tcp/%v", api.PolicyPortAny))
	} else if udpAny {
		strs = append(strs, fmt.Sprintf("udp/%v", api.PolicyPortAny))
	}
	for _, port := range sorter.ports {
		var proto string
		switch port.proto {
		case syscall.IPPROTO_TCP:
			proto = "tcp"
		case syscall.IPPROTO_UDP:
			proto = "udp"
		default:
			continue
		}
		if port.low == port.high {
			strs = append(strs, fmt.Sprintf("%v/%v", proto, port.low))
		} else {
			strs = append(strs, fmt.Sprintf("%v/%v-%v", proto, port.low, port.high))
		}
	}

	return strings.Join(strs, ","), nil
}

// Empty array means 'any' application
func appNames2IDs(apps []string) []uint32 {
	if len(apps) == 0 {
		return []uint32{}
	}

	var ids []uint32 = make([]uint32, 0)
	for _, app := range apps {
		if strings.EqualFold(app, api.PolicyAppAny) {
			return []uint32{}
		}
		if id := common.GetAppIDByName(app); id != 0 {
			ids = append(ids, id)
		}
	}

	return ids
}

// Empty string array means 'any' application
func normalizeApps(apps []string) ([]string, error) {
	if len(apps) == 0 {
		return []string{api.PolicyAppAny}, nil
	}

	appSet := utils.NewSet()
	for _, app := range apps {
		if strings.EqualFold(app, api.PolicyAppAny) {
			return []string{api.PolicyAppAny}, nil
		}
		if id := common.GetAppIDByName(app); id != 0 {
			if appSet.Contains(id) {
				return nil, fmt.Errorf("duplicated application name: %s", app)
			}
			appSet.Add(id)
		} else {
			return nil, fmt.Errorf("Unknonwn application name: %s", app)
		}
	}

	i := 0
	names := make([]string, appSet.Cardinality())
	for id := range appSet.Iter() {
		names[i] = common.AppNameMap[id.(uint32)]
		i++
	}

	sort.Strings(names)
	return names, nil
}

func validateGroupForPolicy(ruleCfgType share.TCfgType, group string, groupMap map[string]*share.CLUSGroup, hosts []*api.RESTHost, isFrom bool) (bool, string, error) {
	if group == api.LearnedExternal || group == api.AllHostGroup || (isFrom && group == api.WorkloadTunnelIF) {
		return true, "", nil
	}
	if group == api.AllContainerGroup && ruleCfgType != share.FederalCfg {
		return false, "", nil
	}
	if grp, ok := groupMap[group]; ok {
		if (ruleCfgType == share.FederalCfg && grp.CfgType != share.FederalCfg) || (ruleCfgType != share.FederalCfg && grp.CfgType == share.FederalCfg) {
			err := fmt.Errorf("Rule cannot be applied to group %s", group)
			return false, "", err
		}
	} else if strings.HasPrefix(group, api.LearnedHostPrefix) {
		if net.ParseIP(group[len(api.LearnedHostPrefix):]) != nil {
			return true, "", nil
		} else {
			for _, host := range hosts {
				if host.Name == group[len(api.LearnedHostPrefix):] {
					return true, host.ID, nil
				}
			}
			err := fmt.Errorf("Cannot find host %s", group[len(api.LearnedHostPrefix):])
			return true, "", err
		}
	} else if strings.HasPrefix(group, api.LearnedWorkloadPrefix) {
		if group[len(api.LearnedWorkloadPrefix):] == api.EndpointIngress {
			return true, "", nil
		} else if net.ParseIP(group[len(api.LearnedWorkloadPrefix):]) != nil {
			return true, "", nil
		} else {
			err := fmt.Errorf("Invalid workload format %s", group)
			return true, "", err
		}
	} else if _, ok := groupMap[group]; !ok {
		err := fmt.Errorf("Cannot find group %s", group)
		return false, "", err
	}

	return false, "", nil
}

// Validate a cluster policy rule; fill in host id information if the group is a managed host
func validateClusterPolicyRule(r *share.CLUSPolicyRule,
	groupMap map[string]*share.CLUSGroup, hosts []*api.RESTHost) error {
	if groupMap != nil {
		var fromSpecial, toSpecial bool
		var err error
		if fromSpecial, r.FromHost, err = validateGroupForPolicy(r.CfgType, r.From, groupMap, hosts, true); err != nil {
			log.WithFields(log.Fields{"id": r.ID, "from": r.From}).Error(err.Error())
			return err
			//} else if fromSpecial && r.From != api.LearnedExternal {
			//	err := fmt.Errorf("Policy rule from %s is not supported", r.From)
			//	return err
		}

		if toSpecial, r.ToHost, err = validateGroupForPolicy(r.CfgType, r.To, groupMap, hosts, false); err != nil {
			log.WithFields(log.Fields{"id": r.ID, "to": r.To}).Error(err.Error())
			return err
		} else if toSpecial && fromSpecial {
			err = errors.New("From/To group cannot both be special address group")
			log.WithFields(log.Fields{"id": r.ID}).Error(err.Error())
			return err
		}
	}
	return nil
}

// Validate rest policy rule config; normalize port and app
func validateRestPolicyRuleConfig(r *api.RESTPolicyRuleConfig) error {
	/*
		if r.ID == 0 {
			log.WithFields(log.Fields{"id": r.ID}).Error("Rule ID cannot be 0")
			return errors.New("Rule ID cannot be 0")
		}
	*/
	if r.Action != nil {
		if *r.Action != share.PolicyActionAllow && *r.Action != share.PolicyActionDeny {
			log.WithFields(log.Fields{"id": r.ID, "action": *r.Action}).Error("Invalid action")
			return errors.New("Invalid action")
		}
	}

	if r.Ports != nil {
		if ports, err := normalizePorts(*r.Ports); err == nil {
			*r.Ports = ports
		} else {
			log.WithFields(log.Fields{
				"id": r.ID, "ports": *r.Ports,
			}).Error("Invalid ports format")
			return errors.New("Invalid ports format")
		}
	}

	if r.Applications != nil {
		if apps, err := normalizeApps(*r.Applications); err == nil {
			*r.Applications = apps
		} else {
			log.WithFields(log.Fields{
				"id": r.ID, "error": err,
			}).Error("Invalid applications")
			return err
		}
	}

	if r.Priority != 0 {
		if r.Priority > 100 {
			log.WithFields(log.Fields{"id": r.ID, "Priority": r.Priority}).Error("Prioty out of range [0-100]")
			return errors.New("Priority out of range")
		}
	}

	return nil
}

func validateRestPolicyRule(r *api.RESTPolicyRule) error {
	fedPolicy := isFedPolicyID(r.ID)
	if (fedPolicy && r.CfgType != api.CfgTypeFederal) || (!fedPolicy && r.CfgType == api.CfgTypeFederal) {
		e := fmt.Sprintf("ID is reserved for federal rule. Use ID between %v and %v.", api.PolicyFedRuleIDBase, api.PolicyFedRuleIDMax)
		err := errors.New(e)
		log.WithFields(log.Fields{"id": r.ID}).Error(err)
		return err
	}
	rc := &api.RESTPolicyRuleConfig{
		ID:           r.ID,
		Action:       &r.Action,
		Ports:        &r.Ports,
		Applications: &r.Applications,
	}
	return validateRestPolicyRuleConfig(rc)
}

func policyRule2Cluster(r *api.RESTPolicyRule) *share.CLUSPolicyRule {
	rule := &share.CLUSPolicyRule{
		ID:           r.ID,
		Comment:      r.Comment,
		From:         r.From,
		To:           r.To,
		Ports:        r.Ports,
		Applications: appNames2IDs(r.Applications),
		Action:       r.Action,
		Disable:      r.Disable,
	}
	rule.CfgType = cfgTypeMapping[r.CfgType]
	return rule
}

// func policyRuleConf2Cluster(r *api.RESTPolicyRuleConfig) *share.CLUSPolicyRule {
// 	return &share.CLUSPolicyRule{
// 		ID:      r.ID,
// 		Comment: *r.Comment,
// 		From:    *r.From,
// 		To:      *r.To,
// 	}
// }

func deletePolicyRules(txn *cluster.ClusterTransact, dels utils.Set) {
	for id := range dels.Iter() {
		clusHelper.DeletePolicyRuleTxn(txn, id.(uint32))
	}
}

func writePolicyRules(txn *cluster.ClusterTransact, crs []*share.CLUSPolicyRule) {
	for _, cr := range crs {
		clusHelper.PutPolicyRuleTxn(txn, cr)
	}
}

// param crhs:    a list of existing CLUSRuleHead
// param after:   nil: last; 0: first; +id: after rule 'id'; -id: before rule 'id'
// param moveIDx: original idx of the moving item. < 0 if it's for insert op
// returns (location idx to use for the entry, _)
func locatePosition(crhs []*share.CLUSRuleHead, after *int, moveIDx int) (int, int) {
	var pos uint
	var before bool
	if after == nil {
		if moveIDx < 0 {
			return len(crhs), len(crhs) // the first new item will be after crhs
		} else {
			return len(crhs) - 1, len(crhs) - 1 // move the item to the end of crhs
		}
	} else if *after == 0 {
		return 0, 0
	} else if *after > 0 {
		pos = uint(*after)
	} else {
		before = true
		pos = uint(-*after)
	}

	for i, crh := range crhs {
		if crh.ID == uint32(pos) {
			if before {
				if moveIDx >= 0 && moveIDx < i {
					return i - 1, *after // moving downwards to before an item
				} else {
					return i, *after
				}
			} else {
				if moveIDx >= 0 && moveIDx < i {
					return i, *after // moving downwards to after an item
				} else {
					return i + 1, *after
				}
			}
		}
	}
	return -1, *after
}

// this function assumes crhs is already sorted by (1) federal rules (2) ground rules (3) others
// param id:          id of the existing item to move
// param ruleCfgType: CfgType of the existing item to move
// param after:       nil: last; 0: first; +id: after rule 'id'; -id: before rule 'id'
func moveRuleID(crhs []*share.CLUSRuleHead, id uint32, ruleCfgType share.TCfgType, after *int) error {
	var moveIdx int = -1   // original idx of the moving item
	var topIdx int = 0     // the top-most idx that the new location could be
	var bottomIdx int = -1 // the bottom-most idx that the new location could be
	for i, crh := range crhs {
		if crh.ID == id {
			if crh.CfgType == share.GroundCfg {
				e := "Can't move Base Rule"
				log.WithFields(log.Fields{"move": id}).Error(e)
				return fmt.Errorf("%s", e) // break from here if the moving item is ground rule. i.e. ground rule cannot be moved
			}
			moveIdx = i
		}
		if ruleCfgType == share.FederalCfg {
			// the moving item is a federal rule. it can be moved to any existing federal rule's position
			if crh.CfgType == share.FederalCfg {
				bottomIdx++
			}
		} else {
			// the moving item is not a federal/ground rule. it can be moved to any position after federal/ground rules
			if crh.CfgType == share.FederalCfg || crh.CfgType == share.GroundCfg {
				topIdx++
			}
		}
	}
	if moveIdx == -1 {
		e := "Rule to move doesn't exist"
		log.WithFields(log.Fields{"move": id}).Error(e)
		return fmt.Errorf("%s", e)
	}

	toIdx, af := locatePosition(crhs, after, moveIdx)
	if toIdx == -1 {
		e := "Move-to position cannot be found"
		log.WithFields(log.Fields{"after": af}).Error(e)
		return fmt.Errorf("%s", e)
	}
	if bottomIdx == -1 {
		bottomIdx = len(crhs) - 1
	}

	if toIdx < topIdx {
		toIdx = topIdx
	} else if toIdx > bottomIdx {
		toIdx = bottomIdx
	}
	if moveIdx == toIdx { // same location meaning no move
		return nil
	} else if moveIdx < toIdx { // move downwards
		mr := crhs[moveIdx]
		for i := moveIdx; i < toIdx; i++ {
			crhs[i] = crhs[i+1]
		}
		crhs[toIdx] = mr
	} else { // move upwards
		mr := crhs[moveIdx]
		for i := moveIdx; i > toIdx; i-- {
			crhs[i] = crhs[i-1]
		}
		crhs[toIdx] = mr
	}
	return nil
}

func movePolicyRule(w http.ResponseWriter, r *http.Request, move *api.RESTPolicyRuleMove,
	acc *access.AccessControl, login *loginSession) (error, share.TCfgType) {

	log.Debug("")

	crule, err := cacher.GetPolicyRuleCache(move.ID, acc)
	if crule == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return err, 0
	}

	// No need to authorize again as it's done in the GetPolicyRuleCache()

	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		e := "Failed to acquire cluster lock"
		log.WithFields(log.Fields{"error": err}).Error(e)
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, e)
		return err, 0
	}
	defer clusHelper.ReleaseLock(lock)

	// Read ID list from cluster
	crhs := clusHelper.GetPolicyRuleList()
	if len(crhs) == 0 {
		e := "Policy rule doesn't exist"
		log.WithFields(log.Fields{"move": move.ID}).Error(e)
		restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
		return fmt.Errorf("%s", e), 0
	}

	if move.After != nil && *move.After != 0 && *move.After == int(move.ID) {
		// move an item after/before itself means no move
		return nil, crule.CfgType
	}
	if err := moveRuleID(crhs, move.ID, crule.CfgType, move.After); err != nil {
		restRespErrorMessage(w, http.StatusNotFound, api.RESTErrObjectNotFound, err.Error())
		return err, 0
	}

	// Put policy rule heads
	if err := clusHelper.PutPolicyRuleList(crhs); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return err, 0
	}

	return nil, crule.CfgType
}

func isLocalReservedId(id uint32) error {
	var err error
	var ruleype string
	if isLearnedPolicyID(id) {
		ruleype = "learned"
	} else if isSecurityPolicyID(id) {
		ruleype = "ground"
	}
	if ruleype != "" {
		err = fmt.Errorf("ID is reserved for %s rule. Use ID between 1 and %v.", ruleype, api.PolicyLearnedIDBase)
	}
	return err
}

// this function assumes crhs is already sorted by (1) federal rules (2) ground rules (3) other rules
func insertPolicyRule(scope string, w http.ResponseWriter, r *http.Request, insert *api.RESTPolicyRuleInsert,
	acc *access.AccessControl, login *loginSession) error {
	var topIdx int    // the top-most idx that the first new item could be at
	var bottomIdx int // the bottom-most idx that the first new item could be at

	log.Debug("")

	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		e := "Failed to acquire cluster lock"
		log.WithFields(log.Fields{"error": err}).Error(e)
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, e)
		return err
	}
	defer clusHelper.ReleaseLock(lock)

	// Read ID list from cluster
	crhs := clusHelper.GetPolicyRuleList()

	ids := utils.NewSet()
	for _, crh := range crhs {
		ids.Add(crh.ID)
		if scope == share.ScopeFed {
			// the new items are federal rules. they could be inserted before any existing non-federal rule
			if crh.CfgType == share.FederalCfg {
				bottomIdx++
			}
		} else if scope == share.ScopeLocal {
			// the new items are not federal rules. they could be inserted after the last ground rule
			bottomIdx++
			if crh.CfgType == share.FederalCfg || crh.CfgType == share.GroundCfg {
				topIdx++
			}
		}
	}

	toIdx, after := locatePosition(crhs, insert.After, -1)
	if toIdx == -1 {
		e := "Insert position cannot be found"
		log.WithFields(log.Fields{"scope": scope, "after": after}).Error(e)
		restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
		return fmt.Errorf("%s", e)
	}

	if toIdx < topIdx {
		toIdx = topIdx
	} else if toIdx > bottomIdx {
		toIdx = bottomIdx
	}
	// Validate rules
	accReadAll := access.NewReaderAccessControl()
	groups := clusHelper.GetAllGroups(scope, accReadAll)
	hosts := cacher.GetAllHosts(accReadAll)
	newRules := make([]*share.CLUSPolicyRule, 0, len(insert.Rules))
	for _, rr := range insert.Rules {
		if rr == nil {
			continue
		} else if rr.CfgType == "" {
			if scope == share.ScopeFed {
				rr.CfgType = api.CfgTypeFederal
			} else {
				rr.CfgType = api.CfgTypeUserCreated
			}
		}
		cfgType := cfgTypeMapping[rr.CfgType]
		if (cfgType == share.FederalCfg && scope == share.ScopeLocal) || (cfgType != share.FederalCfg && scope == share.ScopeFed) {
			e := "Mismatched rule CfgType with request"
			log.WithFields(log.Fields{"id": rr.ID}).Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
			return fmt.Errorf("%s", e)
		}
		if ids.Contains(rr.ID) {
			e := "Duplicate rule ID"
			log.WithFields(log.Fields{"id": rr.ID}).Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
			return fmt.Errorf("%s", e)
		}
		if cfgType == share.Learned || cfgType == share.GroundCfg {
			e := "Cannot create learned/Base policy rule"
			log.WithFields(log.Fields{"id": rr.ID}).Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
			return fmt.Errorf("%s", e)
		}
		if e := isLocalReservedId(rr.ID); e != nil {
			log.WithFields(log.Fields{"id": rr.ID}).Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e.Error())
			return e
		}
		if rr.ID == api.PolicyAutoID {
			rr.ID = common.GetAvailablePolicyID(ids, cfgType)
			if rr.ID == 0 {
				e := "Failed to locate available rule ID"
				log.WithFields(log.Fields{"id": rr.ID}).Error(e)
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
				return err
			}
		}

		if err := validateRestPolicyRule(rr); err != nil {
			log.WithFields(log.Fields{"id": rr.ID, "error": err}).Error("")
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
			return err
		}

		cr := policyRule2Cluster(rr)
		cr.CreatedAt = time.Now().UTC()
		cr.LastModAt = cr.CreatedAt
		if err := validateClusterPolicyRule(cr, groups, hosts); err != nil {
			log.WithFields(log.Fields{"id": cr.ID, "error": err}).Error("")
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
			return err
		}

		if !acc.Authorize(cr, func(g string) share.AccessObject {
			if cg, ok := groups[g]; ok {
				return cg
			} else {
				return nil
			}
		}) {
			restRespAccessDenied(w, login)
			return common.ErrObjectAccessDenied
		}

		ids.Add(cr.ID)
		newRules = append(newRules, cr)
	}

	txn := cluster.Transact()
	defer txn.Close()

	writePolicyRules(txn, newRules)

	// Insert to policy rule heads
	var cfgType share.TCfgType = share.UserCreated
	if scope == share.ScopeFed {
		cfgType = share.FederalCfg
	}
	news := make([]*share.CLUSRuleHead, len(insert.Rules))
	for i, r := range insert.Rules {
		news[i] = &share.CLUSRuleHead{
			ID:      r.ID,
			CfgType: cfgType,
		}
	}

	crhs = append(crhs[:toIdx], append(news, crhs[toIdx:]...)...)

	// Put policy rule heads
	clusHelper.PutPolicyRuleListTxn(txn, crhs)

	if ok, err := txn.Apply(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return err
	} else if !ok {
		e := "Atomic write to the cluster failed"
		log.Error(e)
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster, e)
		return err
	}

	return nil
}

func checkReadOnlyRules(scope string, crhs []*share.CLUSRuleHead, rules []*api.RESTPolicyRule, accWrite *access.AccessControl) (int, int, utils.Set, utils.Set, []uint32) {
	var checkLocal, checkFed bool
	switch scope {
	case share.ScopeLocal:
		checkLocal = true
	case share.ScopeFed:
		checkFed = true
	default:
		return 0, 0, utils.NewSet(), utils.NewSet(), nil
	}

	var errorIDs []uint32 // IDs of read-only rules that are deleted/modified in the 'rules' payload
	var writableLearnedRules int
	var writableUserCreatedRules int

	readOnlyRuleIDs := utils.NewSet()
	writableRuleIDs := utils.NewSet()                  // id of rules (based on scope) that can be modified by the caller
	payloadRulesIDs := utils.NewSet()                  // all rules' id in rules param
	accRead := accWrite.NewWithOp(access.AccessOPRead) // for finding out what policies could be in the rules param
	for _, crh := range crhs {
		if (checkFed && crh.CfgType == share.FederalCfg) || (checkLocal && crh.CfgType != share.FederalCfg) {
			_, readable, writable := cacher.CheckPolicyRuleAccess(crh.ID, accRead, accWrite)
			if writable {
				writableRuleIDs.Add(crh.ID)
				if crh.CfgType == share.Learned {
					writableLearnedRules++
				} else if crh.CfgType == share.UserCreated {
					writableUserCreatedRules++
				}
			} else if readable {
				readOnlyRuleIDs.Add(crh.ID)
			}
		}
	}
	for _, r := range rules {
		if r.ID != api.PolicyAutoID {
			payloadRulesIDs.Add(r.ID)
		}
	}

	if readOnlyRuleIDs.Cardinality() > 0 {
		// Check whether some read-only rules are deleted in payload:
		if deletedIDs := readOnlyRuleIDs.Difference(payloadRulesIDs); deletedIDs.Cardinality() > 0 { // id in readOnlyRuleIDs but not in rulesIDs, meaning some read-only rules are deleted in payload
			errorIDs = make([]uint32, 0, deletedIDs.Cardinality()+8)
			for id := range deletedIDs.Iter() {
				errorIDs = append(errorIDs, id.(uint32))
			}
		}
		// Now check whether any read-only rule is modified in payload:
		for _, rr := range rules {
			if readOnlyRuleIDs.Contains(rr.ID) {
				if rr.From == "" && rr.To == "" && rr.CfgType == "" && rr.Applications == nil {
					// the rule is not modified. no need to compare
				} else {
					// the rule could be modified. need to compare to know the answer
					if oldcr, _ := clusHelper.GetPolicyRule(rr.ID); oldcr != nil {
						cachedRule := cacher.PolicyRule2REST(oldcr)
						if !compareRESTRules(rr, cachedRule) {
							errorIDs = append(errorIDs, rr.ID)
						}
					}
				}
			}
		}
	}

	return writableLearnedRules, writableUserCreatedRules, readOnlyRuleIDs, writableRuleIDs, errorIDs
}

// -------------------------------------------------------------------------------------------------------------------------------------------------------
// caller                   rules param                 ignored entries in rules param      note
// -------------------------------------------------------------------------------------------------------------------------------------------------------
// admin(scope=local)       all rules                   fed/ground rules                    fed/ground rules are not affected during replacement
// nsUser(scope=local)      rules this user can see     fed/ground rules                    namespace-user-non-accessible rules are not affected during replacement
// fedAdmin(scope=local)    all rules                   fed/ground rules                    fed/ground rules are not affected during replacement
// fedAdmin(scope=fed)      all rules                   ground/learned/user-created rules   ground/learned/user-created rules are not affected during replacement
// -------------------------------------------------------------------------------------------------------------------------------------------------------
// 1. rules param contains the whole (updated) rules list that this user can see/config. it's from GET("/v1/policy/rule") plus some update/delete/add operations
// 2. ground(crd) rules cannot be updated/deleted/added by this function
// 3. accessible learned rules can be deleted, but not updated, by this function
// 4. delRuleIDs param means ids of the learned rules to delete. nil/[] means do not delete any learned rule
func replacePolicyRule(scope string, w http.ResponseWriter, r *http.Request, rules []*api.RESTPolicyRule, delRuleIDs utils.Set,
	acc *access.AccessControl) error {

	log.Debug("")

	// Policy modification requires the permission on both From/To of the policy
	nsUser := false
	nsLearnedRules := 0
	nsUserCreatedRules := 0
	readOnlyRuleIDs := utils.NewSet()   // id of rules (based on scope) that can be viewed but not modified by the caller
	accessibleRuleIDs := utils.NewSet() // id of rules (based on scope) that can be modified by the caller

	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		e := "Failed to acquire cluster lock"
		log.WithFields(log.Fields{"error": err}).Error(e)
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, e)
		return err
	}
	defer clusHelper.ReleaseLock(lock)

	accReadAll := access.NewReaderAccessControl()
	groups := clusHelper.GetAllGroups(scope, accReadAll)
	hosts := cacher.GetAllHosts(accReadAll)

	// Read ID list from cluster
	crhs := clusHelper.GetPolicyRuleList()

	if !acc.HasGlobalPermissions(share.PERMS_RUNTIME_POLICIES, share.PERMS_RUNTIME_POLICIES) { // special treatment for namespace users
		nsUser = true

		var errorIDs []uint32
		// A namespace user with rt_policy:w permission may be able to read a policy but not to modify it (i.e. in Authorize() only one of d1/d2 passes the authz)
		// So it's possible those readable-but-not-writable policies are included in the rules param that we need to filter out those rules first before replacement with rules
		nsLearnedRules, nsUserCreatedRules, readOnlyRuleIDs, accessibleRuleIDs, errorIDs = checkReadOnlyRules(scope, crhs, rules, acc)
		if len(errorIDs) > 0 {
			err := fmt.Errorf("Some rules are read-only to current login user and cannot be updated")
			log.WithFields(log.Fields{"error": err, "ids": errorIDs}).Error("Request error")
			restRespErrorReadOnlyRules(w, http.StatusBadRequest, api.RESTErrReadOnlyRules, err.Error(), errorIDs)
			return err
		}
	}

	del := utils.NewSet()                              // rules to delete eventually, could contain learned/user-created/federal rules
	idInUse := utils.NewSet()                          // rest-created rule IDs in use (user-created rules when scope=local, federal rules when scope=fed)
	keep := make([]*share.CLUSRuleHead, 0, len(rules)) // existing rh to keep (contains federal/ground      rules when scope=local, contains local   rules when scope=fed)
	new := make([]*share.CLUSRuleHead, 0)              // changed  rh to use  (contains learned/userCreated rules when scope=local, contains federal rules when scope=fed)
	var accessibleLearnedSpotIndices []int             // all accessible learned rh spots' indices in keep slice for namespace user
	var accessibleUserSpotIndices []int                // all accessible user-created rhspots' indices in keep slice for namespace user
	var reusedLearnedSpotIndex, reusedUserSpotIndex int
	if nsUser {
		accessibleLearnedSpotIndices = make([]int, 0, nsLearnedRules)
		accessibleUserSpotIndices = make([]int, 0, nsUserCreatedRules)
	}

	// 1. stable sort on input rules so it's ordered in CfgTypeFederal -> CfgTypeGround -> (CfgTypeLearned | CfgTypeUserCreated) sequence in rules param
	for _, rr := range rules {
		if rr.CfgType == "" { // CfgType is not specified in new rule. deduce from scope
			if rr.From == "" && rr.To == "" {
				rr.CfgType = cfgTypeMap2Api[common.PolicyRuleIdToCfgType(rr.ID)]
			} else {
				if rr.Learned {
					rr.CfgType = api.CfgTypeLearned
				} else {
					if scope == share.ScopeFed {
						rr.CfgType = api.CfgTypeFederal
					} else {
						rr.CfgType = api.CfgTypeUserCreated
					}
				}
			}
		}
	}
	sort.SliceStable(rules, func(i, j int) bool {
		iCfgType := cfgTypeMapping[rules[i].CfgType]
		jCfgType := cfgTypeMapping[rules[j].CfgType]
		switch iCfgType {
		case share.FederalCfg:
			if jCfgType != share.FederalCfg {
				return true // switch
			}
		case share.GroundCfg:
			if jCfgType != share.FederalCfg && jCfgType != share.GroundCfg {
				return true // switch
			}
		}
		return false
	})

	// 2. get all IDs in rules param that need to referenced by auto ID generation, so auto ID generation will not create duplicate ID
	// for namespace user this is just a subset of the whole rules' IDs. we will keep adding IDs in-use to it when iterating existing crhs in step 3
	for _, rr := range rules {
		if rr.ID != api.PolicyAutoID {
			if (rr.CfgType == api.CfgTypeUserCreated && scope == share.ScopeLocal) || (rr.CfgType == api.CfgTypeFederal && scope == share.ScopeFed) {
				if idInUse.Contains(rr.ID) {
					e := "Duplicate rule ID"
					log.WithFields(log.Fields{"id": rr.ID}).Error(e)
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
					return fmt.Errorf("%s", e)
				} else {
					// for admin/fedAdmin, because they can see all rules, rules param contains all rest-created rules' IDs in use.
					// but for namespace user, because they cannot see all rules, rules param contains only subset of rest-created rules' IDs in use.
					idInUse.Add(rr.ID)
				}
			}
		}
	}

	// 3. crhs is ordered in the sequence: federal, ground, learned, userCreated
	// admin/fedAdmin users can see all rules. `keep` contains all fed/ground rhs that cannot be changed by user when scope=local
	//                                         `keep` contains all local rhs when scope=fed
	// namespace users can only see rules whose group's domain/createrDomain is those the user can access. `keep` contains all existing rules
	//	 so rules in payload can only apply to the permitted rules in `keep`, plus more added rules
	for _, crh := range crhs {
		if scope == share.ScopeLocal {
			if crh.CfgType == share.Learned {
				if !nsUser {
					// don't know whether this learned rule will be deleted in this call yet...
					del.Add(crh.ID) // add to 'del' for now. if it is in rules param, will remove it from 'del' and add it to 'new' later in step 4
				} else {
					keep = append(keep, crh) // add to 'keep' for now. if it is not in rules param, will remove it from 'keep' later(by accessibleRuleIDs/accessibleLearnedSpotIndices)
					if accessibleRuleIDs.Contains(crh.ID) || readOnlyRuleIDs.Contains(crh.ID) {
						// This rule can be seen by namespace user(as we allow moving read-only rule). Remember the spot in 'keep'. Later we will re-fill these spots with learned rules specified in rules param
						accessibleLearnedSpotIndices = append(accessibleLearnedSpotIndices, len(keep)-1)
						del.Add(crh.ID) // add to del for now. if it is in rules param, will remove it from 'del' and add it to 'new' later in step 4
					} // because user cannot create learned rule, there is no need to record the rule id here
				}
			} else if crh.CfgType == share.FederalCfg || crh.CfgType == share.GroundCfg {
				keep = append(keep, crh) // ground/fed rules cannot be touched when scope=local
			} else if crh.CfgType == share.UserCreated {
				if !nsUser {
					// don't know whether this user-created rule will be deleted in this call yet...
					del.Add(crh.ID) // add to 'del' for now. if it is in rules param, will remove it from 'del' and add it to 'new' later in step 4
				} else {
					keep = append(keep, crh) // add to 'keep' for now. if it is not in rules param, will remove it from 'keep' later(by accessibleRuleIDs/accessibleUserSpotIndices)
					if accessibleRuleIDs.Contains(crh.ID) || readOnlyRuleIDs.Contains(crh.ID) {
						// This rule can be seen by namespace user(as we allow moving read-only rule). Remember the spot in 'keep'. Later we will re-fill these spots with user-created rules specified in rules param
						accessibleUserSpotIndices = append(accessibleUserSpotIndices, len(keep)-1)
						del.Add(crh.ID) // add to del for now. if it is in rules param, will remove it from 'del' and add it to 'new' later in step 4
					} else {
						idInUse.Add(crh.ID) // namespace cannot see this rule(i.e. this rule is not in rules param). so we record the used rule id here
					}
				}
			}
		} else if scope == share.ScopeFed {
			if crh.CfgType == share.FederalCfg {
				// do not append to 'keep' here. Because all federal rules are in rules param, we can append later in step 4
				del.Add(crh.ID) // add to 'del' for now. if it is in rules param, will remove it from 'del' and add it to 'new' later in step 4
			} else {
				keep = append(keep, crh) // when replacing federal rules, keep all local rules
			}
		}
	}

	// Allocate on-demand, assume changed rules are not many.
	newRules := make([]*share.CLUSPolicyRule, 0)

	// 4. Validate rules
	for _, rr := range rules {
		var newRule, existingRule, modRule bool
		var modCreatedAt time.Time
		if rr.CfgType == api.CfgTypeLearned {
			if scope == share.ScopeLocal {
				if del.Contains(rr.ID) {
					del.Remove(rr.ID)
					existingRule = true
				} // else {
				// ignore new or unaccessible learned rules in rules param
				// }
			} // ignore learned rules when scope=fed
		} else if rr.CfgType == api.CfgTypeGround {
			// always ignore ground rules from rest api
		} else {
			if (rr.CfgType == api.CfgTypeUserCreated && scope == share.ScopeLocal) || (rr.CfgType == api.CfgTypeFederal && scope == share.ScopeFed) {
				if del.Contains(rr.ID) {
					del.Remove(rr.ID)
					if readOnlyRuleIDs.Contains(rr.ID) {
						// this is a read-only rule and we know it's not modified if we can reach here (trying to modify read-only-caller rules would trigger error earlier already)
						existingRule = true
					} else {
						if rr.From == "" && rr.To == "" && rr.Applications == nil {
							// the rule is not modified. no need to compare. just make sure it's existing rule
							if oldcr, _ := clusHelper.GetPolicyRule(rr.ID); oldcr != nil {
								existingRule = true
							}
						} else {
							// the rule could be modified. need to compare to know the answer
							if oldcr, _ := clusHelper.GetPolicyRule(rr.ID); oldcr != nil {
								// If the rule with same ID exists, only modify it if it's changed.
								existingRule = true
								cachedRule := cacher.PolicyRule2REST(oldcr)
								if !compareRESTRules(rr, cachedRule) {
									modRule = true
									modCreatedAt = oldcr.CreatedAt
								}
							} else {
								modRule = true // if rh is in head list but rule key is not found in kv, treat it as updating existing rule
								modCreatedAt = time.Now().UTC()
							}
						}
					}
				} else if nsUser && idInUse.Contains(rr.ID) {
					e := "User has no permission for rule"
					log.WithFields(log.Fields{"id": rr.ID}).Error(e)
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
					return errors.New(e)
				} else {
					newRule = true
				}
			}
			if err := isLocalReservedId(rr.ID); err != nil { // err != nil means the id is for learned/ground rules
				log.WithFields(log.Fields{"id": rr.ID}).Error(err)
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
				return err
			}
			if rr.ID == api.PolicyAutoID {
				cfgType := cfgTypeMapping[rr.CfgType]
				rr.ID = common.GetAvailablePolicyID(idInUse, cfgType)
				if rr.ID == 0 {
					err = fmt.Errorf("Failed to locate available rule ID")
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
					return err
				}
				idInUse.Add(rr.ID)
				newRule = true
			} else {
				if (rr.CfgType == api.CfgTypeUserCreated && rr.ID > api.PolicyLearnedIDBase) || (rr.CfgType == api.CfgTypeFederal && !isFedPolicyID(rr.ID)) {
					err = fmt.Errorf("The given id is invalid")
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
					return err
				}
			}
			// now rr.ID is non-zero
		}
		if newRule || existingRule {
			if !nsUser { // re-append learned/user-created rh if login user is admin/fedAdmin (we didn't append to 'keep' in step 3)
				new = append(new, &share.CLUSRuleHead{
					ID:      rr.ID,
					CfgType: cfgTypeMapping[rr.CfgType],
				})
			} else { // for namespace user (we did append to 'keep' already in step 3)
				if rr.CfgType == api.CfgTypeLearned { // if it's accessible learned rule, we re-use the accessible rh spots in 'keep'
					if reusedLearnedSpotIndex < len(accessibleLearnedSpotIndices) {
						keep[accessibleLearnedSpotIndices[reusedLearnedSpotIndex]].ID = rr.ID
						reusedLearnedSpotIndex++
					} // no else because learned rule cannot be created thru rest api
				} else if rr.CfgType == api.CfgTypeUserCreated { // if it's accessible user-created rule, we re-use the accessible rh spots in 'keep'
					if reusedUserSpotIndex < len(accessibleUserSpotIndices) {
						keep[accessibleUserSpotIndices[reusedUserSpotIndex]].ID = rr.ID
						reusedUserSpotIndex++
					} else {
						// use up all the accessible rh spots in keep. so append a new rh to 'new'
						new = append(new, &share.CLUSRuleHead{
							ID:      rr.ID,
							CfgType: cfgTypeMapping[rr.CfgType],
						})
					}
				}
			}
		}
		if newRule || modRule {
			if err := validateRestPolicyRule(rr); err != nil {
				log.WithFields(log.Fields{"error": err, "id": rr.ID}).Error("validate rule")
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
				return err
			}

			cr := policyRule2Cluster(rr)
			if newRule {
				cr.CreatedAt = time.Now().UTC()
				cr.LastModAt = cr.CreatedAt
			} else {
				cr.CreatedAt = modCreatedAt
				cr.LastModAt = time.Now().UTC()
			}
			if err := validateClusterPolicyRule(cr, groups, hosts); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("")
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
				return err
			}

			// check authorization in case fed rules are involved.
			authorized := true
			if cr.CfgType == share.FederalCfg && !acc.IsFedAdmin() {
				authorized = false
			} else if nsUser {
				if !acc.Authorize(cr, func(g string) share.AccessObject {
					if cg, ok := groups[g]; ok {
						return cg
					} else {
						return nil
					}
				}) {
					authorized = false
				}
			}
			if !authorized {
				err := common.ErrObjectAccessDenied
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
				return err
			}

			newRules = append(newRules, cr)
		}
	}

	var newPolicys []*share.CLUSRuleHead
	if !nsUser {
		// when scope=local, for admin/fedAdmin:
		// 	keep:           contains unchanged federal/ground rules head list
		// 	new:            contains new learned/userCreate head list
		// when scope=local, for namesapce user:
		// 	keep:           contains unchanged federal/ground rules & unaccessible learned/user-created rules head list
		// 	new:            contains extra added user-created rules' head list
		// when scope=fed:
		// 	keep:           contains unchanged local(ground/learned/userCreated) rules head list
		// 	new:            contains new federal rules head list
		if scope == share.ScopeLocal { // When replacing local rules, only learned & user-created rules could change
			newPolicys = append(keep, new...)
		} else if scope == share.ScopeFed { // When replacing federal rules, only fed rules could change
			newPolicys = append(new, keep...)
		}
	} else {
		// `keep` contains all existing rule heads. now mark all un-refilled spots in 'keep' as id=0
		// (there could be un-refilled holes in 'keep' because namespace user could delete some accessible learned/user-created rules so that those rules' spots in 'keep' are not refilled)
		for i := reusedLearnedSpotIndex; i < len(accessibleLearnedSpotIndices); i++ {
			keep[accessibleLearnedSpotIndices[i]].ID = 0
		}
		for i := reusedUserSpotIndex; i < len(accessibleUserSpotIndices); i++ {
			keep[accessibleUserSpotIndices[i]].ID = 0
		}
		// remove un-used rh spots in `keep` slice
		for loop := true; loop; {
			copied := false
			for idx, rh := range keep {
				if rh.ID == 0 {
					size := len(keep)
					copy(keep[idx:], keep[idx+1:])
					keep[size-1] = nil
					keep = keep[:size-1]
					copied = true
					break
				}
			}
			if !copied {
				break
			}
		}
		// now there is no hole in 'keep'
		newPolicys = append(keep, new...)
	}
	txn := cluster.Transact()
	defer txn.Close()

	// There might be new learned rules created between GET("/v1/policy/rule") & PATCH("/v1/policy/rule") that they are not included in the the patch request payload.
	// We try not to mistakenly delete these new learned rules.
	// However, it's hard to determine the exact location those new learned rules should be because rules can be created/moved/deleted in this function.
	// So we just append those new learned rules to the end of the header list
	{
		policyIDsNew := utils.NewSet()
		for _, crh := range newPolicys {
			if crh.CfgType == share.Learned {
				policyIDsNew.Add(crh.ID)
			}
		}
		policyIDsKV := utils.NewSet()
		for _, crh := range crhs {
			if crh.CfgType == share.Learned && isLearnedPolicyID(crh.ID) {
				policyIDsKV.Add(crh.ID)
			}
		}

		// get new learned rules created between GET("/v1/policy/rule") & PATCH("/v1/policy/rule")
		newLearnedRuleIDs := policyIDsKV.Difference(policyIDsNew).Difference(delRuleIDs)
		for id_ := range newLearnedRuleIDs.Iter() {
			// caller doesn't say to delete this learned rule
			var id uint32 = id_.(uint32)
			newPolicys = append(newPolicys, &share.CLUSRuleHead{
				ID:      id,
				CfgType: share.Learned,
			})
			del.Remove(id)
		}
	}

	// Write rule ID list to cluster
	clusHelper.PutPolicyRuleListTxn(txn, newPolicys)

	// Remove old rules
	deletePolicyRules(txn, del)
	// Put new rules into cluster
	writePolicyRules(txn, newRules)

	if ok, err := txn.Apply(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return err
	} else if !ok {
		e := "Atomic write to the cluster failed"
		log.Error(e)
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster, e)
		return err
	}

	return nil
}

func deletePolicyRule(scope string, w http.ResponseWriter, r *http.Request, ruleIDs []uint32, acc *access.AccessControl) (int, error) { // deleted rules, err
	log.Debug("")

	delIDs := utils.NewSet()
	for _, id := range ruleIDs {
		if (scope == share.ScopeFed && !isFedPolicyID(id)) || (scope == share.ScopeLocal && (isSecurityPolicyID(id) || isFedPolicyID(id))) {
			e := fmt.Errorf("Rule %v can't be deleted with scope %s", id, scope)
			log.Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrOpNotAllowed, e.Error())
			return 0, e
		}
		if _, err := cacher.GetPolicyRuleCache(id, acc); err == nil {
			delIDs.Add(id)
		}
	}

	if delIDs.Cardinality() == 0 {
		return 0, nil
	}

	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		e := "Failed to acquire cluster lock"
		log.WithFields(log.Fields{"error": err}).Error(e)
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, e)
		return 0, err
	}
	defer clusHelper.ReleaseLock(lock)

	// Read ID list from cluster
	crhs := clusHelper.GetPolicyRuleList()
	crhsNew := make([]*share.CLUSRuleHead, 0, len(crhs))
	dels := utils.NewSet()

	for _, crh := range crhs {
		if !delIDs.Contains(crh.ID) {
			crhsNew = append(crhsNew, crh)
		} else {
			dels.Add(crh.ID)
		}
	}

	if len(crhs) == len(crhsNew) && dels.Cardinality() == 0 {
		e := fmt.Errorf("Policy rule %v doesn't exist", ruleIDs)
		log.Error(e)
		restRespErrorMessage(w, http.StatusNotFound, api.RESTErrObjectNotFound, e.Error())
		return 0, e
	}

	txn := cluster.Transact()
	defer txn.Close()

	// Write rule ID list to cluster
	clusHelper.PutPolicyRuleListTxn(txn, crhsNew)

	// Remove rules.
	deletePolicyRules(txn, dels)
	if ok, err := txn.Apply(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return 0, err
	} else if !ok {
		e := "Atomic write to the cluster failed"
		log.Error(e)
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster, e)
		return 0, err
	}

	return dels.Cardinality(), nil
}

func handlerPolicyRuleAction(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}

	// Read request
	body, _ := io.ReadAll(r.Body)
	var rconf api.RESTPolicyRuleActionData
	err := json.Unmarshal(body, &rconf)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	var scope string
	if scope = restParseQuery(r).pairs[api.QueryScope]; scope == "" {
		scope = share.ScopeLocal
	} else if scope != share.ScopeFed && scope != share.ScopeLocal {
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	dataChanged := false
	if rconf.Move != nil {
		err, cfgType := movePolicyRule(w, r, rconf.Move, acc, login)
		if err == nil {
			if cfgType == share.FederalCfg {
				scope = share.ScopeFed
			}
			dataChanged = true
			restRespSuccess(w, r, nil, acc, login, &rconf, "Move policy rules")
		}
	} else if rconf.Insert != nil && len(rconf.Insert.Rules) > 0 {
		err = insertPolicyRule(scope, w, r, rconf.Insert, acc, login)
		if err == nil {
			dataChanged = true
			restRespSuccess(w, r, nil, acc, login, &rconf, "Insert policy rules")
		}
	} else if rconf.Rules != nil {
		if !acc.IsFedAdmin() && (scope == share.ScopeFed) {
			err := common.ErrObjectAccessDenied
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
			return
		}
		//notDelLearnedRule := false
		delRuleIDs := utils.NewSet()
		// rconf.Delete being:
		// 1. nil/[] means 4.2.2(-)
		// 2. [...] means the ids of learned rules to delete
		if rconf.Delete != nil {
			for _, id := range *rconf.Delete {
				delRuleIDs.Add(id)
			}
		}
		err = replacePolicyRule(scope, w, r, *rconf.Rules, delRuleIDs, acc)
		if err == nil {
			dataChanged = true
			restRespSuccess(w, r, nil, acc, login, &rconf, "Replace policy rules")
		}
	} else if rconf.Delete != nil && len(*rconf.Delete) > 0 {
		deleted, err := deletePolicyRule(scope, w, r, *rconf.Delete, acc)
		if err == nil {
			dataChanged = (deleted > 0)
			restRespSuccess(w, r, nil, acc, login, &rconf, "Delete policy rules")
		}
	} else {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
	}
	if dataChanged && scope == share.ScopeFed {
		updateFedRulesRevision([]string{share.FedNetworkRulesType}, acc, login)
	}
}

func handlerPolicyRuleConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id, err := strconv.Atoi(ps.ByName("id"))
	if err != nil || id <= 0 {
		e := "Invalid rule ID"
		log.WithFields(log.Fields{"id": id}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}

	// Read request
	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTPolicyRuleConfigData
	err = json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}
	if rconf.Config.ID != uint32(id) {
		e := "Rule ID mismatch in the request"
		log.WithFields(log.Fields{"id": id}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}

	if _, err := cacher.GetPolicyRuleCache(rconf.Config.ID, acc); err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		e := "Failed to acquire cluster lock"
		log.WithFields(log.Fields{"error": err}).Error(e)
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, e)
		return
	}
	defer clusHelper.ReleaseLock(lock)

	// Validate new rule
	rc := rconf.Config

	if isSecurityPolicyID(rc.ID) {
		log.WithFields(log.Fields{"id": rc.ID}).Error("Base rule can't edit")
		restRespError(w, http.StatusBadRequest, api.RESTErrOpNotAllowed)
		return
	}

	// Retrieve from the cluster
	cconf, _ := clusHelper.GetPolicyRule(rc.ID)
	if cconf == nil {
		e := "Policy rule doesn't exist"
		log.WithFields(log.Fields{"id": rc.ID}).Error(e)
		restRespErrorMessage(w, http.StatusNotFound, api.RESTErrObjectNotFound, e)
		return
	}

	// configuring fed network rules is only allowed on master cluster by fedAdmin
	var scope string
	if cconf.CfgType == share.FederalCfg {
		scope = share.ScopeFed
	} else {
		scope = share.ScopeLocal
	}

	// Not allow to configure learned rule
	if !rconf.Replicate {
		if cconf.CfgType == share.Learned {
			e := "Learned policy rule cannot be modified"
			log.WithFields(log.Fields{"id": rc.ID}).Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
			return
		}
		if e := isLocalReservedId(rc.ID); e != nil {
			log.WithFields(log.Fields{"id": rc.ID}).Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e.Error())
			return
		}
	}

	if err := validateRestPolicyRuleConfig(rc); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
		return
	}

	if rc.From != nil {
		cconf.From = *rc.From
	}
	if rc.To != nil {
		cconf.To = *rc.To
	}
	if rc.Ports != nil {
		cconf.Ports = *rc.Ports
	}
	if rc.Applications != nil {
		cconf.Applications = appNames2IDs(*rc.Applications)
	}
	if rc.Action != nil {
		cconf.Action = *rc.Action
	}
	if rc.Comment != nil {
		cconf.Comment = *rc.Comment
	}
	if rc.Disable != nil {
		cconf.Disable = *rc.Disable
	}

	accReadAll := access.NewReaderAccessControl()
	groups := clusHelper.GetAllGroups(scope, accReadAll)
	hosts := cacher.GetAllHosts(accReadAll)

	if !rconf.Replicate {
		cconf.LastModAt = time.Now().UTC()
		if err := validateClusterPolicyRule(cconf, groups, hosts); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("")
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
			return
		}

		if !acc.Authorize(cconf, func(g string) share.AccessObject {
			if cg, ok := groups[g]; ok {
				return cg
			} else {
				return nil
			}
		}) {
			restRespAccessDenied(w, login)
			return
		}

		// Normal config rule
		if err := clusHelper.PutPolicyRule(cconf); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("")
			restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
			return
		}
	} else {
		// Don't call validateClusterPolicyRule() for replicated rule to void
		// false group validation failure due to runtime conditions

		// Read ID list from cluster
		crhs := clusHelper.GetPolicyRuleList()

		ids := utils.NewSet()
		for _, crh := range crhs {
			ids.Add(crh.ID)
		}

		var ruleIdx int = -1
		for i, crh := range crhs {
			if crh.ID == rc.ID {
				ruleIdx = i
				break
			}
		}
		if ruleIdx == -1 {
			err := errors.New("Policy rule doesn't exist")
			log.WithFields(log.Fields{"id": rc.ID}).Error(err)
			restRespErrorMessage(w, http.StatusNotFound, api.RESTErrObjectNotFound, err.Error())
			return
		}

		toIdx := ruleIdx

		// Allocate an ID to the new rule
		var cfgType share.TCfgType = share.UserCreated
		if isFedPolicyID(cconf.ID) {
			cfgType = share.FederalCfg
		}
		newID := common.GetAvailablePolicyID(ids, cfgType)
		if newID == 0 {
			err := errors.New("Failed to locate available rule ID")
			log.WithFields(log.Fields{"id": rc.ID}).Error(err)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
			return
		}
		cconf.ID = newID
		cconf.CfgType = cfgType
		//		cconf.GroundRule = false
		cconf.CreatedAt = time.Now().UTC()
		cconf.LastModAt = cconf.CreatedAt

		if !acc.Authorize(cconf, func(g string) share.AccessObject {
			if cg, ok := groups[g]; ok {
				return cg
			} else {
				return nil
			}
		}) {
			restRespAccessDenied(w, login)
			return
		}

		// Insert to policy rule heads
		nrh := &share.CLUSRuleHead{
			ID:      cconf.ID,
			CfgType: share.UserCreated,
		}

		crhs = append(crhs, &share.CLUSRuleHead{})
		copy(crhs[toIdx+1:], crhs[toIdx:])
		crhs[toIdx] = nrh

		txn := cluster.Transact()
		defer txn.Close()

		// Write the new rule
		clusHelper.PutPolicyRuleTxn(txn, cconf)
		// Put policy rule heads
		clusHelper.PutPolicyRuleListTxn(txn, crhs)

		if ok, err := txn.Apply(); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("")
			restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
			return
		} else if !ok {
			e := "Atomic write to the cluster failed"
			log.Error(e)
			restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster, e)
			return
		}
	}

	if scope == share.ScopeFed {
		updateFedRulesRevision([]string{share.FedNetworkRulesType}, acc, login)
	}

	restRespSuccess(w, r, nil, acc, login, &rconf, "Configure policy rules")
}

func handlerPolicyRuleDelete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id, err := strconv.Atoi(ps.ByName("id"))
	if err != nil || id <= 0 {
		log.WithFields(log.Fields{"id": id}).Error("Invalid ID")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	scope := share.ScopeLocal
	var cfgType share.TCfgType
	if crule, err := cacher.GetPolicyRuleCache(uint32(id), acc); crule == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	} else {
		cfgType = crule.CfgType
		if cfgType == share.FederalCfg {
			scope = share.ScopeFed
		}
	}

	// No need to authorize again as it's done in the GetPolicyRuleCache()
	if deleted, err := deletePolicyRule(scope, w, r, []uint32{uint32(id)}, acc); err == nil {
		restRespSuccess(w, r, nil, acc, login, nil, "Delete policy rules")
		if deleted > 0 && scope == share.ScopeFed {
			updateFedRulesRevision([]string{share.FedNetworkRulesType}, acc, login)
		}
	}
}

func handlerPolicyRuleDeleteAll(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}

	query := restParseQuery(r)
	delScope := query.pairs[api.QueryScope]
	if delScope == "" {
		delScope = share.ScopeLocal
	}
	if delScope != share.ScopeFed && delScope != share.ScopeLocal {
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	// get all rules that I can modify. If I'm fedAdmin, all rules are returned. If I'm admin, only local rules are returned
	crules := cacher.GetAllPolicyRulesCache(acc)
	if len(crules) == 0 {
		restRespSuccess(w, r, nil, acc, login, nil, "Delete all policy rules")
		return
	}
	allowed := utils.NewSet()
	for _, cr := range crules {
		allowed.Add(cr.ID)
	}
	if allowed.Cardinality() == 0 {
		restRespSuccess(w, r, nil, acc, login, nil, "Delete all policy rules")
		return
	}

	// No need to authorize again as it's done in the GetAllPolicyRulesCache()

	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		e := "Failed to acquire cluster lock"
		log.WithFields(log.Fields{"error": err}).Error(e)
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, e)
		return
	}
	defer clusHelper.ReleaseLock(lock)

	// Read ID list from cluster
	crhs := clusHelper.GetPolicyRuleList()

	keeps := make([]*share.CLUSRuleHead, 0)
	dels := utils.NewSet()
	for _, crh := range crhs {
		if !allowed.Contains(crh.ID) {
			// I cannot modify this rule. so keep it in the list
			keeps = append(keeps, crh)
		} else {
			// I can modify this rule
			if delScope == share.ScopeFed {
				if crh.CfgType == share.FederalCfg {
					dels.Add(crh.ID)
				} else {
					keeps = append(keeps, crh)
				}
			} else if delScope == share.ScopeLocal {
				if crh.CfgType == share.Learned || crh.CfgType == share.GroundCfg {
					keeps = append(keeps, crh)
				} else {
					dels.Add(crh.ID)
				}
			}
		}
	}

	txn := cluster.Transact()
	defer txn.Close()

	// Write rule ID list to cluster
	clusHelper.PutPolicyRuleListTxn(txn, keeps)
	// Remove rules
	deletePolicyRules(txn, dels)

	if ok, err := txn.Apply(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	} else if !ok {
		e := "Atomic write to the cluster failed"
		log.Error(e)
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster, e)
		return
	}

	if delScope == share.ScopeFed {
		updateFedRulesRevision([]string{share.FedNetworkRulesType}, acc, login)
	}

	restRespSuccess(w, r, nil, acc, login, nil, "Delete all policy rules")
}

func derivedPolicy2Rest(r *share.CLUSDerivedPolicyRule) []*api.RESTDerivedPolicyRule {
	p := &api.RESTDerivedPolicyRule{
		ID:          r.ID,
		SrcIP:       utils.InterpretIP(r.SrcIP, r.SrcIPR),
		DstIP:       utils.InterpretIP(r.DstIP, r.DstIPR),
		Port:        utils.GetPortRangeLink(uint8(r.IPProto), uint16(r.Port), uint16(r.PortR)),
		Action:      common.PolicyActionString(uint8(r.Action)),
		Ingress:     r.Ingress,
		Application: "",
		Domain:      r.FQDN,
	}

	// For fqdn case, ip 0 means the domain is not resolved instead of external
	// Fix that here.
	if p.Domain != "" {
		if p.Ingress && p.SrcIP == "external" {
			p.SrcIP = p.Domain
		} else if !p.Ingress && p.DstIP == "external" {
			p.DstIP = p.Domain
		}
	}

	if r.Apps == nil {
		return []*api.RESTDerivedPolicyRule{p}
	} else {
		rules := make(map[uint32]*api.RESTDerivedPolicyRule)
		for _, app := range r.Apps {
			var appName string
			if app.App > 0 {
				var ok bool
				if appName, ok = common.AppNameMap[app.App]; !ok {
					appName = "Unknown"
				}
			} else {
				appName = "any"
			}
			if rule, ok := rules[app.RuleID]; !ok {
				rules[app.RuleID] = &api.RESTDerivedPolicyRule{
					ID:          app.RuleID,
					SrcIP:       p.SrcIP,
					DstIP:       p.DstIP,
					Port:        p.Port,
					Ingress:     p.Ingress,
					Action:      common.PolicyActionString(uint8(app.Action)),
					Application: appName,
					Domain:      p.Domain,
				}
			} else {
				rule.Application = rule.Application + "," + appName
			}
		}
		result := make([]*api.RESTDerivedPolicyRule, len(rules)+1)
		result[0] = p
		var i int = 1
		for _, rule := range rules {
			result[i] = rule
			i++
		}
		return result
	}
}

func parseDerivedPolicyRules(ruleMap map[string]*share.CLUSDerivedPolicyRuleArray,
	acc *access.AccessControl) []*api.RESTDerivedWorkloadPolicyRule {

	wlrs := make([]*api.RESTDerivedWorkloadPolicyRule, 0)
	for wlID, arr := range ruleMap {
		var wl *api.RESTWorkloadBrief
		if wl, _ = cacher.GetWorkloadBrief(wlID, "", acc); wl == nil {
			continue
		}
		wlPolicy := api.RESTDerivedWorkloadPolicyRule{
			Workload: wl,
			Rules:    make([]*api.RESTDerivedPolicyRule, 0),
		}
		for _, r := range arr.Rules {
			wlPolicy.Rules = append(wlPolicy.Rules, derivedPolicy2Rest(r)...)
		}

		wlrs = append(wlrs, &wlPolicy)
	}
	return wlrs
}

func handlerDebugPolicyRuleList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !authDebugCaller(w, acc, login) {
		return
	}

	query := restParseQuery(r)

	agentID, wlID, err := getAgentWorkloadFromFilter(query.filters, acc)
	if err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	var filter share.CLUSFilter
	filter.Workload = wlID
	if rules, err := rpc.GetDerivedPolicyRules(agentID, &filter); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrClusterRPCError, "Failed to make the RPC call")
		return
	} else {
		uzb := utils.GunzipBytes(rules.RuleByte)
		if uzb == nil {
			log.Error("Failed to unzip data")
			restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrClusterRPCError, "Failed to unzip data")
		}
		if rules.RuleMap == nil {
			rules.RuleMap = make(map[string]*share.CLUSDerivedPolicyRuleArray)
		}
		err := json.Unmarshal(uzb, &rules.RuleMap)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Cannot decode derived rules")
			restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrClusterRPCError, "Failed to decode derived rules")
		}

		resp := api.RESTDerivedPolicyRuleData{WorkloadRules: parseDerivedPolicyRules(rules.RuleMap, acc)}
		restRespSuccess(w, r, &resp, acc, login, nil, "Get derived policy rules")
	}
}

// caller has been verified for federal admin access right
func replaceFedNwRules(rulesNew []*share.CLUSPolicyRule, rhsNew []*share.CLUSRuleHead) bool {
	rulesMap := make(map[uint32]*share.CLUSPolicyRule, len(rulesNew))
	for _, rule := range rulesNew {
		if rule.CfgType == share.FederalCfg {
			rulesMap[rule.ID] = rule
		}
	}

	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to acquire cluster lock")
		return false
	}
	defer clusHelper.ReleaseLock(lock)

	txn := cluster.Transact()
	defer txn.Close()

	nonFedPolicies := 0
	rhsExisting := clusHelper.GetPolicyRuleList()
	for _, rhExisting := range rhsExisting {
		if rhExisting.CfgType == share.FederalCfg {
			if _, ok := rulesMap[rhExisting.ID]; !ok { // in existing but not in new. so delete it
				clusHelper.DeletePolicyRuleTxn(txn, rhExisting.ID)
			}
		} else {
			nonFedPolicies++
		}
	}

	for _, ruleNew := range rulesNew { // write each policy in new to kv
		if ruleNew != nil {
			ruleExisting, _ := clusHelper.GetPolicyRule(ruleNew.ID)
			if ruleExisting == nil || !reflect.DeepEqual(*ruleNew, *ruleExisting) {
				clusHelper.PutPolicyRuleTxn(txn, ruleNew)
			}
		}
	}

	rhsAll := make([]*share.CLUSRuleHead, 0, len(rhsNew)+nonFedPolicies)
	rhsAll = append(rhsAll, rhsNew...)
	for _, rhExisting := range rhsExisting {
		if rhExisting.CfgType != share.FederalCfg {
			rhsAll = append(rhsAll, rhExisting)
		}
	}

	if !reflect.DeepEqual(rhsAll, rhsExisting) {
		clusHelper.PutPolicyRuleListTxn(txn, rhsAll)
	}

	if ok, err := txn.Apply(); err != nil || !ok {
		log.WithFields(log.Fields{"ok": ok, "error": err}).Error("Atomic write to the cluster failed")
		return false
	}

	return true
}

func handlerPolicyRulesPromote(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()

	acc, login := isFedOpAllowed(api.FedRoleMaster, _fedAdminRequired, w, r)
	if acc == nil || login == nil {
		return
	}

	var promoteData api.RESTPolicyPromoteRequestData
	body, _ := io.ReadAll(r.Body)
	err := json.Unmarshal(body, &promoteData)
	if err != nil || promoteData.Request == nil || len(promoteData.Request.IDs) == 0 {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	var lock cluster.LockInterface
	if lock, err = lockClusKey(w, share.CLUSLockPolicyKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	fedIdInUse := utils.NewSet() // id of existing fed policies
	var topIdx int = 0           // the top-most idx that the new location could be
	var errMsg string
	crhs := clusHelper.GetPolicyRuleList()
	for _, crh := range crhs {
		if crh.CfgType == share.FederalCfg {
			topIdx++
			fedIdInUse.Add(crh.ID)
		}
	}
	crhsPromoted := make([]*share.CLUSRuleHead, 0, len(promoteData.Request.IDs)) // new fed policy rules that are just promoted
	fedGroupNames := cacher.GetFedGroupNames(acc)
	fedGroupsCountOld := fedGroupNames.Cardinality()
	emptyMonFilters := make([]share.CLUSFileMonitorFilter, 0)
	emptyFarFilters := make(map[string]*share.CLUSFileAccessFilterRule)

	txn := cluster.Transact()
	defer txn.Close()

LOOP_ALL_IDS:
	for _, id := range promoteData.Request.IDs {
		if id == 0 || (id > api.PolicyFedRuleIDBase && id < api.PolicyFedRuleIDMax) {
			continue
		}
		rule, _ := clusHelper.GetPolicyRule(id) // ruleCfg is *share.CLUSPolicyRule
		if rule == nil {
			errMsg = fmt.Sprintf("policy not found(for rule %d)", id)
			break
		}

		for pos, grpName := range map[string]string{"from": rule.From, "to": rule.To} {
			if (strings.HasPrefix(grpName, api.LearnedHostPrefix) || strings.HasPrefix(grpName, api.LearnedWorkloadPrefix)) && (grpName != api.WorkloadTunnelIF) {
				errMsg = fmt.Sprintf("policy with '%s'=%s cannot be promoted(for rule %d)", pos, grpName, id)
				break LOOP_ALL_IDS
			}
		}

		fedRuleID := common.GetAvailablePolicyID(fedIdInUse, share.FederalCfg)
		if fedRuleID == 0 {
			errMsg = fmt.Sprintf("No free rule id available(for rule %d)", id)
			break
		}

		now := time.Now().UTC()
		for _, pGrpName := range []*string{&rule.From, &rule.To} {
			grpName := *pGrpName
			if grpName == api.LearnedExternal || grpName == api.WorkloadTunnelIF {
				continue
			}
			fedGrpName := fmt.Sprintf("%s%s", api.FederalGroupPrefix, grpName)
			if !fedGroupNames.Contains(fedGrpName) {
				if grp, _, err := clusHelper.GetGroup(grpName, acc); err == nil {
					pp := clusHelper.GetProcessProfile(grpName)
					if pp == nil {
						cacher.CreateProcessProfile(grpName, "", "", share.FederalCfg)
						pp = clusHelper.GetProcessProfile(grpName)
					}
					if pp == nil {
						errMsg = fmt.Sprintf("failed to obtain process profile %s(for rule %d)", grpName, id)
						break LOOP_ALL_IDS
					} else {
						pp.Group = fedGrpName
						pp.Mode = ""
						pp.CfgType = share.FederalCfg
						for _, proc := range pp.Process {
							proc.CfgType = share.FederalCfg
							proc.Uuid = ruleid.NewUuid()
							proc.CreatedAt = now
							proc.UpdatedAt = now
							if proc.Action == share.PolicyActionLearn {
								proc.Action = share.PolicyActionAllow
							}
						}
						clusHelper.PutProcessProfileTxn(txn, fedGrpName, pp)
					}

					mon, _ := clusHelper.GetFileMonitorProfile(grpName)
					far, _ := clusHelper.GetFileAccessRule(grpName) // associated with "mon"
					if mon == nil || far == nil {
						cacher.CreateGroupFileMonitor(grpName, "", share.FederalCfg)
						mon, _ = clusHelper.GetFileMonitorProfile(grpName)
						far, _ = clusHelper.GetFileAccessRule(grpName)
					}
					if mon == nil || far == nil {
						errMsg = fmt.Sprintf("failed to obtain file monitor profile %s(for rule %d)", grpName, id)
						break LOOP_ALL_IDS
					} else {
						reservedLen := len(mon.Filters) + len(mon.FiltersCRD)
						pmap := make(map[string]*share.CLUSFileMonitorFilter, reservedLen)
						for i, ffp := range mon.Filters {
							pmap[ffp.Filter] = &mon.Filters[i]
						}
						for i, ffm := range mon.FiltersCRD {
							if ffm.Behavior != "delete" {
								pmap[ffm.Filter] = &mon.FiltersCRD[i]
							}
						}
						i := 0
						filters := make([]share.CLUSFileMonitorFilter, len(pmap))
						for _, filter := range pmap {
							filter.CustomerAdd = true
							filters[i] = *filter
							i += 1
						}
						mon.Group = fedGrpName
						mon.Mode = ""
						mon.CfgType = share.FederalCfg
						mon.Filters = filters
						mon.FiltersCRD = emptyMonFilters
						clusHelper.PutFileMonitorProfileTxn(txn, fedGrpName, mon)

						for key, ffm := range far.FiltersCRD {
							far.Filters[key] = ffm
						}
						for _, ffp := range far.Filters {
							ffp.CustomerAdd = true
							ffp.CreatedAt = now
							ffp.UpdatedAt = now
						}
						far.Group = fedGrpName
						far.FiltersCRD = emptyFarFilters
						clusHelper.PutFileAccessRuleTxn(txn, fedGrpName, far)
					}

					fedGroup := &share.CLUSGroup{
						Name:     fedGrpName,
						Criteria: grp.Criteria,
						Kind:     grp.Kind,
						CapIntcp: grp.CapIntcp,
						CfgType:  share.FederalCfg,
						//NotScored:      grp.NotScored,
						//PlatformRole:   grp.PlatformRole,
					}
					clusHelper.PutGroupTxn(txn, fedGroup)
					fedGroupNames.Add(fedGrpName)
				} else {
					errMsg = fmt.Sprintf("group %s not found(for rule %d)", grpName, id)
					break LOOP_ALL_IDS
				}
			}
			*pGrpName = fedGrpName
		}
		rule.ID = fedRuleID
		rule.CreatedAt = time.Now().UTC()
		rule.LastModAt = rule.CreatedAt
		rule.CfgType = share.FederalCfg
		comment := fmt.Sprintf("promoted from rule %d", id)
		if rule.Comment == "" {
			rule.Comment = comment
		} else {
			rule.Comment = fmt.Sprintf("%s (%s)", rule.Comment, comment)
		}
		clusHelper.PutPolicyRuleTxn(txn, rule)

		crh := &share.CLUSRuleHead{
			ID:      fedRuleID,
			CfgType: share.FederalCfg,
		}
		crhsPromoted = append(crhsPromoted, crh)
		fedIdInUse.Add(fedRuleID)
	}
	if errMsg == "" {
		if len(crhsPromoted) == 0 {
			errMsg = "no rule to promote"
		} else {
			crhs = append(crhs[:topIdx], append(crhsPromoted, crhs[topIdx:]...)...)
			clusHelper.PutPolicyRuleListTxn(txn, crhs)
			if applyTransact(w, txn) == nil {
				ruleTypes := []string{share.FedNetworkRulesType}
				if fedGroupsCountOld != fedGroupNames.Cardinality() {
					ruleTypes = append(ruleTypes, share.FedGroupType, share.FedProcessProfilesType, share.FedFileMonitorProfilesType)
				}
				updateFedRulesRevision(ruleTypes, acc, login)
				restRespSuccess(w, r, nil, acc, login, nil, "Promote policy")
			}
			return
		}
	}
	restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrPromoteFail, errMsg)
}

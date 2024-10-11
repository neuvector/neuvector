package ruleid

import (
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/google/uuid"
	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

// //////
type ProcessRuleIDHelper interface {
	ResetProcessUuidRuleMap() bool
	AddProcesProfile(pp *share.CLUSProcessProfile)
	DeleteProcesProfile(pp *share.CLUSProcessProfile)
	FindProcessRuleToRest(uuid_str string, acc *access.AccessControl) (*api.RESTProcessUuidEntry, error)
}

type FuncGetGroupWithoutLock func(string) *share.CLUSGroup

// local quick reference
var cfgTypeMap2Api = map[share.TCfgType]string{
	share.Learned:       api.CfgTypeLearned,
	share.UserCreated:   api.CfgTypeUserCreated,
	share.GroundCfg:     api.CfgTypeGround,
	share.FederalCfg:    api.CfgTypeFederal,
	share.SystemDefined: api.CfgSystemDefined, // reserved
}

// ///////
const calculateInterval uint32 = 10

// ///////
type uuidPRuleCache struct {
	// bInit   bool
	rwMutex sync.RWMutex

	// workitems
	pendingCacheLock     sync.Mutex
	pendingProcProfile_u utils.Set // update or add
	pendingProcProfile_d utils.Set // delete

	// caches
	pGrpUuidMap map[string]utils.Set // map[grp] = Set(uuid)
	pMap        *share.ProcRuleMap
}

// //////// global cache stores in this file //////////
var uuidProcCache *uuidPRuleCache

// var procHelper *ProcessRuleIDHelper

var funcGetGroupWithoutLock FuncGetGroupWithoutLock

// ///////// Operations: basically, it does not require lock ///////////
func (pc *uuidPRuleCache) setEmptyProcessRuleMap() {
	pc.pGrpUuidMap = make(map[string]utils.Set)
	pc.pMap = &share.ProcRuleMap{ // clear all
		RuleMap: make(map[string]*share.ProcRule),
	}
}

func (pc *uuidPRuleCache) findProcessRule(uuid string, acc *access.AccessControl) (*share.ProcRule, bool) {
	if pRule, ok := pc.pMap.RuleMap[uuid]; ok {
		authorized := true
		if funcGetGroupWithoutLock != nil {
			authorized = acc.Authorize(pRule, func(g string) share.AccessObject { return funcGetGroupWithoutLock(g) })
		}
		if authorized {
			//	log.WithFields(log.Fields{"rule": pRule}).Debug("UUID: ")
			return pRule, true
		}
	}
	return nil, false
}

// ///
func (pc *uuidPRuleCache) handleProcessProfile(pp *share.CLUSProcessProfile, bDelete bool, acc *access.AccessControl) {
	log.WithFields(log.Fields{"group": pp.Group}).Debug("UUID: ")
	pc.rwMutex.Lock()
	defer pc.rwMutex.Unlock()

	previous, ok := pc.pGrpUuidMap[pp.Group]
	if !ok {
		previous = utils.NewSet()
		pc.pGrpUuidMap[pp.Group] = utils.NewSet()
	}

	//
	current := utils.NewSet()
	if !bDelete {
		for _, ppe := range pp.Process {
			current.Add(ppe.Uuid)
		}
	}

	delete(pc.pGrpUuidMap, pp.Group)
	pc.pGrpUuidMap[pp.Group] = current // update

	// calculations
	gone := previous.Difference(current)
	added := current.Difference(previous)

	// gone
	for k := range gone.Iter() {
		if rule, ok := pc.findProcessRule(k.(string), acc); ok {
			rule.Active = 0
			if bDelete {
				rule.Rule.UpdatedAt = time.Now().UTC() // fabricate a time
			}
		} else {
			log.WithFields(log.Fields{"uuid": k.(string)}).Error("UUID: can not find")
		}
	}

	//  added
	for _, ppe := range pp.Process {
		if added.Contains(ppe.Uuid) { // update cache
			// copy the structure
			pRule := &share.ProcRule{
				Active: 1,
				Group:  pp.Group,
				Rule:   *ppe,
			}
			pc.pMap.RuleMap[ppe.Uuid] = pRule
		}
	}

	// release memory
	gone.Clear()
	added.Clear()
	previous.Clear()
	previous, gone, added = nil, nil, nil
}

func pRule2ApiEntry(pRule *share.ProcRule) *api.RESTProcessUuidEntry {
	return &api.RESTProcessUuidEntry{
		Active: pRule.Active,
		Group:  pRule.Group,
		Rule: api.RESTProcessProfileEntry{
			Name:             pRule.Rule.Name,
			Path:             pRule.Rule.Path,
			CfgType:          cfgTypeMap2Api[pRule.Rule.CfgType],
			User:             pRule.Rule.User,
			Uuid:             pRule.Rule.Uuid,
			Action:           pRule.Rule.Action,
			CreatedTimeStamp: pRule.Rule.CreatedAt.Unix(),
			UpdatedTimeStamp: pRule.Rule.UpdatedAt.Unix()},
	}
}

func fillSystemResevedProcessRule(uuid string) *api.RESTProcessUuidEntry {
	var name string
	if !strings.HasPrefix(uuid, share.CLUSReservedUuidPrefix) {
		return nil
	}

	switch uuid {
	case share.CLUSReservedUuidNotAlllowed:
		name = "<not_in_profile>" // beyond white-list
	case share.CLUSReservedUuidTunnelProc:
		name = "<tunnel_proc>" // tunnel
	case share.CLUSReservedUuidRootEscalation:
		name = "<root_escal>" // root privilege escallation
	case share.CLUSReservedUuidRiskyApp:
		name = "<RiskyApp>" // risky app
	case share.CLUSReservedUuidDockerCp:
		name = "<docker cp>" // docker cp
	default:
		return nil
	}

	return &api.RESTProcessUuidEntry{
		Active: 1,
		Group:  "system-defined",
		Rule: api.RESTProcessProfileEntry{
			Name:    name,
			Path:    "<any>",
			User:    "<any>",
			CfgType: api.CfgSystemDefined,
			Uuid:    uuid,
			Action:  share.PolicyActionCheckApp},
	}
}

// //////////////////////
func (pc *uuidPRuleCache) calculte_uuid_rules(acc *access.AccessControl) {
	pc.pendingCacheLock.Lock()
	proc_update := pc.pendingProcProfile_u.Clone()
	proc_delete := pc.pendingProcProfile_d.Clone()
	pc.pendingProcProfile_u.Clear()
	pc.pendingProcProfile_d.Clear()
	pc.pendingCacheLock.Unlock()

	//  delete process group at first
	if proc_delete.Cardinality() > 0 {
		for pp := range proc_delete.Iter() {
			pc.handleProcessProfile(pp.(*share.CLUSProcessProfile), true, acc)
		}
	}

	//  process update
	if proc_update.Cardinality() > 0 {
		for pp := range proc_update.Iter() {
			pc.handleProcessProfile(pp.(*share.CLUSProcessProfile), false, acc)
		}
	}

	////
	proc_delete.Clear()
	proc_update.Clear()
	proc_update, proc_delete = nil, nil
}

// ///////////////////////
func (pc *uuidPRuleCache) ruleIdTimerLoop() {
	acc := access.NewFedAdminAccessControl()
	calculateTicker := time.Tick(time.Second * time.Duration(calculateInterval))
	log.Info("UUID: timer starts")
	for {
		select {
		case <-calculateTicker:
			pc.calculte_uuid_rules(acc)
		}
	}
}

// ///////// External functions: needs lock////////////
func NewUuid() string {
	var cnt int
	var id string
	for cnt < 255 {
		id = uuid.New().String()
		if !strings.HasPrefix(id, share.CLUSReservedUuidPrefix) {
			return id
		}
		cnt += 1
	}
	log.WithFields(log.Fields{"id": id, "cnt": cnt}).Error("UUID: failed")
	return ""
}

func GetProcessRuleIDHelper() ProcessRuleIDHelper {
	return uuidProcCache
}

func SetGetGroupWithoutLockFunc(funcObj FuncGetGroupWithoutLock) {
	funcGetGroupWithoutLock = funcObj
}

// /// only process cacher for now
func Init() *uuidPRuleCache {
	log.Info("UUID: ")
	pc := new(uuidPRuleCache)
	pc.pendingProcProfile_u = utils.NewSet()
	pc.pendingProcProfile_d = utils.NewSet()
	pc.pGrpUuidMap = make(map[string]utils.Set)
	pc.pMap = &share.ProcRuleMap{RuleMap: make(map[string]*share.ProcRule)}
	uuidProcCache = pc
	pc.setEmptyProcessRuleMap()
	go pc.ruleIdTimerLoop()
	return pc
}

func (pc *uuidPRuleCache) ResetProcessUuidRuleMap() bool {
	log.Info("UUID: ")
	pc.rwMutex.Lock()
	defer pc.rwMutex.Unlock()

	pc.setEmptyProcessRuleMap()
	return true
}

// /// from cacher
func (pc *uuidPRuleCache) AddProcesProfile(pp *share.CLUSProcessProfile) {
	profile := *pp // local copy
	pc.pendingCacheLock.Lock()
	defer pc.pendingCacheLock.Unlock()
	pc.pendingProcProfile_u.Add(&profile)
}

// /// from cacher
func (pc *uuidPRuleCache) DeleteProcesProfile(pp *share.CLUSProcessProfile) {
	profile := *pp // local copy
	pc.pendingCacheLock.Lock()
	defer pc.pendingCacheLock.Unlock()
	pc.pendingProcProfile_d.Add(&profile)
}

// /// REST lookup function
func (pc *uuidPRuleCache) FindProcessRuleToRest(uuid_str string, acc *access.AccessControl) (*api.RESTProcessUuidEntry, error) {
	// is it a system reserved uuid
	if entry := fillSystemResevedProcessRule(uuid_str); entry != nil {
		return entry, nil
	}

	pc.rwMutex.RLock()
	defer pc.rwMutex.RUnlock()

	if pRule, ok := pc.findProcessRule(uuid_str, acc); ok {
		//	log.WithFields(log.Fields{"rule": pRule}).Debug("UUID: ")
		return pRule2ApiEntry(pRule), nil
	}
	return nil, common.ErrObjectNotFound
}

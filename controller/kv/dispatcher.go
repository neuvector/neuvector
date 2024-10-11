package kv

import (
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

// A kv dispatcher for the "push-config" profile distributions
// (1) WorkloadJoin(): add node-cache, workload(container id), update custom-groups for dispatcher
// (2) WorkloadLeave(): remove workloads, if its count reach zero in a node, remove learned/custom(no more referece) groups from the node
// (3) NodeLeave: remove node-cache, purge node from group2nodes
// (4) CustomGroupUpdate: handle custom group additions/updates/removes(criteria changes) to maintain group2nodes
// (5) CustomGroupDelete: remove entries in the group2nodes
// (6) PutProfile: dispatch "kv put" operatios, based on group2nodes
// (7) IsGroupAdded: a reference for outsiders (performance)

// Two major types of "profile" groups in the dispatcher
// (1) Service groups: learned containers/pods (from workloads); like: nodes, fed.nodes, nv.pods
// (2) Custom (user-defined) groups: associated criteria with Service groups; like: containers, fed.containers, fed.custom, custom.pods

type DispatcherHelper interface {
	WorkloadJoin(node, group, id string, customGrps utils.Set, bLeader bool)
	WorkloadLeave(node, group, id string, customGrps utils.Set, bLeader bool)
	NodeLeave(node string, bLeader bool)
	CustomGroupUpdate(group string, serviceGrps utils.Set, bLeader bool)
	CustomGroupDelete(group string, bLeader bool)
	PutProfile(group, subkey string, value []byte, txn *cluster.ClusterTransact, bPutIfNotExist bool) error
	IsGroupAdded(group string) bool
}

// a simple mapping to speed up process
// FROM object store: object/config/(type)/name
// TO profile store: node/<nodeID>/profile/(type)/name
type keyMappingHelper struct {
	obj string // object/config/(ept)/
	prf string // profiles/(ept)/
}

// counting (profile) workloads on a node
type nodeMemberCache struct {
	node    string               // nodeID
	members map[string]utils.Set // [group]: containerID
}

type FuncIsGroupMember func(name, id string) bool
type FuncGetConfigKVData func(key string) ([]byte, bool)
type kvDispatcher struct {
	mutex          sync.RWMutex
	nodes          utils.Set                   // debug purpose: keep a record of all nodes
	customs        utils.Set                   // reserved: purge custom groups
	node2groups    map[string]*nodeMemberCache // accounting purpose: [nodeID] => {group-members}
	group2nodes    map[string]utils.Set        // dispatching purpose: [group] => {nodes}
	profileKeys    []keyMappingHelper          // utility: profile keys in the object/ store
	matchedGrpFunc FuncIsGroupMember           // help purging custom groups when workloads leave.
	getKvDataFunc  FuncGetConfigKVData
}

// ////////////////////////////////
func (dpt *kvDispatcher) lockR() {
	dpt.mutex.RLock()
}

func (dpt *kvDispatcher) unlockR() {
	dpt.mutex.RUnlock()
}

func (dpt *kvDispatcher) lock() {
	dpt.mutex.Lock()
}

func (dpt *kvDispatcher) unlock() {
	dpt.mutex.Unlock()
}

/*
	func (dpt *kvDispatcher) dump() {
		log.WithFields(log.Fields{"nodes-group": len(dpt.node2groups), "nodes": dpt.nodes.Cardinality(), "groups": len(dpt.group2nodes)}).Debug("DPT:")
		for node, cache := range dpt.node2groups {
			log.WithFields(log.Fields{"node": node}).Debug("DPT:")
			for group, ids := range cache.members {
				log.WithFields(log.Fields{"group": group, "count": ids.Cardinality()}).Debug("DPT:")
			}
		}

		for group, nodes := range dpt.group2nodes {
			log.WithFields(log.Fields{"group": group, "nodes": nodes.String(), "count": nodes.Cardinality()}).Debug("DPT:")
		}
	}

// / reserved: future periodical purge procedure, returns expired custom groups

	func (dpt *kvDispatcher) purgeCustomGroupsByNode(node string) utils.Set {
		log.WithFields(log.Fields{"node": node}).Debug("DPT: reserved")
		exCustomGrps := utils.NewSet()

		// search this node
		if nodeCache, ok := dpt.node2groups[node]; ok {
			for customGrp := range dpt.customs.Iter() {
				custom := customGrp.(string)
				if nodes, ok := dpt.group2nodes[custom]; ok && nodes.Contains(node) {
					found := false
					// search groups by one of its workload(id)
					for _, ids := range nodeCache.members {
						if dpt.matchedGrpFunc(custom, ids.Any().(string)) {
							found = true
							break // leave nodeCache
						}
					}

					if !found {
						exCustomGrps.Add(custom)
						nodes.Remove(node)
					}
				}
			}
		}
		return exCustomGrps
	}
*/
func (dpt *kvDispatcher) purgeCustomGroupsByNodeGroups(node string, customGrps utils.Set) utils.Set {
	exCustomGrps := utils.NewSet()

	// search this node
	if nodeCache, ok := dpt.node2groups[node]; ok {
		for customGrp := range customGrps.Iter() {
			custom := customGrp.(string)
			// log.WithFields(log.Fields{"custom": custom}).Debug("DPT:")
			found := false
			// search groups by one of its workload(id)
			for _, ids := range nodeCache.members {
				if dpt.matchedGrpFunc(custom, ids.Any().(string)) {
					// log.WithFields(log.Fields{"group": group, "custom": custom}).Debug("DPT: found")
					found = true
					break // leave nodeCache
				}
			}

			if !found {
				exCustomGrps.Add(custom)
				if nodes, ok := dpt.group2nodes[custom]; ok {
					nodes.Remove(node)
				}
			}
		}
	}
	return exCustomGrps
}

func (dpt *kvDispatcher) refreshServiceGroup2Nodes(group, node, id string, bRemoved bool) bool {
	nodeCache, ok1 := dpt.node2groups[node]
	if !ok1 {
		// should not be here
		log.WithFields(log.Fields{"node": node, "group": group}).Debug("DPT: node not found")
		return false
	}

	nodes, ok2 := dpt.group2nodes[group]
	if !ok2 {
		// should not be here
		log.WithFields(log.Fields{"node": node, "group": group}).Debug("DPT: group not found")
		return false
	}

	var bGroupChanged bool
	if bRemoved {
		if ids, ok := nodeCache.members[group]; ok {
			ids.Remove(id)
			// log.WithFields(log.Fields{"group": group, "cnt": ids.Cardinality()}).Debug("DPT:")
			if ids.Cardinality() == 0 {
				bGroupChanged = true // removed
				delete(nodeCache.members, group)
				nodes.Remove(node)
				if nodes.Cardinality() == 0 {
					delete(dpt.group2nodes, group) // remove reference to save memory
				}
			}
		}
	} else {
		// Add:
		if ids, ok := nodeCache.members[group]; !ok {
			bGroupChanged = true // newly added
			nodeCache.members[group] = utils.NewSet(id)
		} else {
			ids.Add(id)
		}
		nodes.Add(node)
	}
	return bGroupChanged
}

func (dpt *kvDispatcher) refreshCustomGroups(name string, serviceGrps utils.Set, bRemoved bool) {
	// refresh: only care the group2nodes shortcuts
	if bRemoved {
		delete(dpt.group2nodes, name)
		dpt.customs.Remove(name) // reserved
		return
	}

	// Add:
	// log.WithFields(log.Fields{"name": name, "service_grp_cnt": serviceGrps.Cardinality()}).Debug("DPT:")
	// recalculate every node from group2nodes
	targetNodes := utils.NewSet()
	for serviceGrp := range serviceGrps.Iter() {
		serviceGroup := serviceGrp.(string)
		// log.WithFields(log.Fields{"serviceGroup": serviceGroup}).Debug("DPT:")
		if nodes, ok := dpt.group2nodes[serviceGroup]; ok {
			targetNodes = targetNodes.Union(nodes)
		} else {
			// should not be here
			log.WithFields(log.Fields{"name": name, "serviceGroup": serviceGroup}).Debug("DPT: not found")
		}
	}

	// the user defined groups are stored in the group2nodes
	dpt.group2nodes[name] = targetNodes
	dpt.customs.Add(name) // reserved
}

func (dpt *kvDispatcher) copyProfileKeys(node, group string, txn *cluster.ClusterTransact) {
	var value []byte
	var ok bool
	var err error

	for _, m := range dpt.profileKeys {
		from := fmt.Sprintf("%s%s", m.obj, group)
		to := fmt.Sprintf("%s%s/%s%s", share.CLUSNodeStore, node, m.prf, group)
		value, ok = dpt.getKvDataFunc(from)
		if !ok { // 2nd chance
			if value, err = cluster.Get(from); err != nil {
				continue
			}
		}
		txn.PutQuiet(to, utils.GzipBytes(value))
	}
}

func (dpt *kvDispatcher) removeProfileKeys(node, group string, txn *cluster.ClusterTransact) {
	// log.WithFields(log.Fields{"group": group, "node": node}).Debug("DPT: ")
	for _, m := range dpt.profileKeys {
		key := fmt.Sprintf("%s%s/%s%s", share.CLUSNodeStore, node, m.prf, group)
		// log.WithFields(log.Fields{"key": key}).Debug("DPT:")
		txn.Delete(key)
	}
}

func (dpt *kvDispatcher) buildCustomGroups(node string, customGrps utils.Set, txn *cluster.ClusterTransact) {
	// custom groups only, its reference map is group2nodes[]
	for customGroup := range customGrps.Iter() {
		custom := customGroup.(string)
		bExist := false
		// log.WithFields(log.Fields{"custom": custom}).Debug("DPT:")
		if nodes, ok := dpt.group2nodes[custom]; ok {
			bExist = nodes.Contains(node)
		} else {
			// custom group does not exist here, build it
			dpt.group2nodes[custom] = utils.NewSet()
		}

		if !bExist {
			dpt.group2nodes[custom].Add(node)
			dpt.copyProfileKeys(node, custom, txn)
		}
	}
}

// from cacher
func (dpt *kvDispatcher) WorkloadJoin(node, group, id string, customGrps utils.Set, bLeader bool) {
	// log.WithFields(log.Fields{"node": node, "group": group, "id": id, "customs": customGrps.String()}).Debug("DPT:")
	dpt.lock()
	defer dpt.unlock()

	// check node
	var bNewNode, bNewGroup bool
	if _, ok := dpt.node2groups[node]; !ok {
		bNewNode = true // a new node
		dpt.nodes.Add(node)
		nodeCache := &nodeMemberCache{
			node:    node,
			members: make(map[string]utils.Set),
		}
		nodeCache.members[group] = utils.NewSet()
		dpt.node2groups[node] = nodeCache
	}

	// check group
	if _, ok := dpt.group2nodes[group]; !ok {
		bNewGroup = true
		dpt.group2nodes[group] = utils.NewSet()
	}

	bBuildLocalGroup := dpt.refreshServiceGroup2Nodes(group, node, id, false)
	// dpt.dump()

	txn := cluster.Transact()
	dpt.buildCustomGroups(node, customGrps, txn)
	if bLeader {
		if bBuildLocalGroup || bNewGroup || bNewNode { // add a group on the node
			// log.WithFields(log.Fields{"group": group, "node": node}).Debug("DPT: local group")
			dpt.copyProfileKeys(node, group, txn)
		}

		if ok, err := txn.Apply(); err != nil || !ok {
			log.WithFields(log.Fields{"ok": ok, "error": err, "group": group, "node": node}).Error("write failed")
		}
	}
	txn.Close()
}

// from cacher
// Two options:
//
//	(1) (current) purge the custom groups immediately(it needs the validatation of all other groups/workloads).
//	(2) a 30-minutes timer to purge the unaffected custom groups
func (dpt *kvDispatcher) WorkloadLeave(node, group, id string, customGrps utils.Set, bLeader bool) {
	// log.WithFields(log.Fields{"node": node, "group": group, "id": id, "customs": customGrps.String()}).Debug("DPT:")

	dpt.lock()
	defer dpt.unlock()
	removeCustomGrp := utils.NewSet()
	bRemoveGroup := dpt.refreshServiceGroup2Nodes(group, node, id, true)

	// efficient enough?
	if bRemoveGroup {
		removeCustomGrp = dpt.purgeCustomGroupsByNodeGroups(node, customGrps)
		// log.WithFields(log.Fields{"groups": removeCustomGrp.String()}).Debug("DPT: rm")
	}
	// dpt.dump()

	if bLeader {
		if bRemoveGroup {
			txn := cluster.Transact()
			dpt.removeProfileKeys(node, group, txn)
			for custom := range removeCustomGrp.Iter() {
				dpt.removeProfileKeys(node, custom.(string), txn)
			}

			if _, err := txn.Apply(); err != nil {
				log.WithFields(log.Fields{"error": err, "group": group}).Error("delete failed")
			}
			txn.Close()
		}
	}
}

// from event trigger
func (dpt *kvDispatcher) NodeLeave(node string, bLeader bool) {
	log.WithFields(log.Fields{"node": node}).Debug("DPT:")
	dpt.lock()
	defer dpt.unlock()

	dpt.nodes.Remove(node)
	delete(dpt.node2groups, node)
	for _, nodes := range dpt.group2nodes {
		nodes.Remove(node)
	}
	// dpt.dump()

	if bLeader {
		// delete the kv tree under the node
		_ = cluster.DeleteTree(share.CLUSNodeProfileStoreKey(node))
	}
}

// from cacher
func (dpt *kvDispatcher) CustomGroupUpdate(group string, serviceGrps utils.Set, bLeader bool) {
	// log.WithFields(log.Fields{"group": group}).Debug("DPT:")
	dpt.lock()
	defer dpt.unlock()

	olds := utils.NewSet()
	if nodes, ok := dpt.group2nodes[group]; ok {
		olds = nodes.Clone()
	}

	// recalculate target nodes
	dpt.refreshCustomGroups(group, serviceGrps, false)
	// dpt.dump()

	if bLeader {
		curs := dpt.group2nodes[group]
		deletes := olds.Difference(curs)
		creates := curs.Difference(olds)

		txn := cluster.Transact()
		for n := range creates.Iter() {
			// log.WithFields(log.Fields{"group": group, "node": n.(string)}).Debug("DPT: add")
			dpt.copyProfileKeys(n.(string), group, txn)
		}

		for n := range deletes.Iter() {
			// log.WithFields(log.Fields{"group": group, "node": n.(string)}).Debug("DPT: rm")
			dpt.removeProfileKeys(n.(string), group, txn)
		}

		if _, err := txn.Apply(); err != nil {
			log.WithFields(log.Fields{"error": err, "group": group}).Error("delete failed")
		}
		txn.Close()
	}
}

// from event trigger
func (dpt *kvDispatcher) CustomGroupDelete(group string, bLeader bool) {
	//log.WithFields(log.Fields{"group": group}).Debug("DPT:")
	dpt.lock()
	defer dpt.unlock()

	removes := utils.NewSet()
	if nodes, ok := dpt.group2nodes[group]; ok {
		removes = nodes.Clone()
		dpt.refreshCustomGroups(group, nil, true)
	}
	// dpt.dump()

	if bLeader {
		// delete it in all assigned nodes
		txn := cluster.Transact()
		for n := range removes.Iter() {
			dpt.removeProfileKeys(n.(string), group, txn)
		}

		if _, err := txn.Apply(); err != nil {
			log.WithFields(log.Fields{"error": err, "group": group}).Error("delete failed")
		}
		txn.Close()
	}
}

// sample: nodes/ubuntu:2YZB:5T5K:....../profiles/process/containers
// subkey includes the profile/ + <type> /+ <group name>
func (dpt *kvDispatcher) PutProfile(group, subkey string, value []byte, txn *cluster.ClusterTransact, bPutIfNotExist bool) error {
	var err error
	// if nodes, put them into profile/
	if utils.IsGroupNodes(group) {
		key := fmt.Sprintf("%s%s", share.CLUSNodeCommonStoreKey, subkey)
		// log.WithFields(log.Fields{"key": key}).Debug("DPT: common")
		if txn != nil {
			txn.PutQuiet(key, value)
		} else {
			if bPutIfNotExist {
				err = cluster.PutIfNotExist(key, value, true)
			} else {
				err = cluster.PutQuiet(key, value)
			}
		}
		return err
	}

	var bExternalTxnReq = (txn != nil)
	if !bExternalTxnReq {
		// make it locally
		txn = cluster.Transact()
		defer txn.Close()
	}

	dpt.lockR()
	defer dpt.unlockR()
	if nodes, ok := dpt.group2nodes[group]; ok {
		for node := range nodes.Iter() {
			key := share.CLUSNodeProfileKey(node.(string), subkey)
			// log.WithFields(log.Fields{"key": key}).Debug("DPT:")
			if bPutIfNotExist && cluster.Exist(key) {
				// txn.PutRev(0): not suitable because txn rollbacks if there is any existing key.
				continue
			}
			txn.PutQuiet(key, value)
		}

		// local request
		if !bExternalTxnReq && txn != nil {
			_, err = txn.Apply()
		}

		if err != nil {
			log.WithFields(log.Fields{"group": group, "key": subkey, "error": err, "bPutIfNotExist": bPutIfNotExist}).Error("DPT:")
		}
	}
	return err
}

// for leader check only
func (dpt *kvDispatcher) IsGroupAdded(group string) bool {
	// log.WithFields(log.Fields{"group": group}).Debug("DPT:")
	dpt.lockR()
	defer dpt.unlockR()
	_, ok := dpt.group2nodes[group]
	return ok
}

// /////////////////////////////////////////////
var dispatcher *kvDispatcher

// /////////////////////////////////////////////
func initDispatcher(matcher FuncIsGroupMember, getter FuncGetConfigKVData) {
	dispatcher = &kvDispatcher{
		nodes:          utils.NewSet(), // reference
		customs:        utils.NewSet(),
		node2groups:    make(map[string]*nodeMemberCache),
		group2nodes:    make(map[string]utils.Set),
		matchedGrpFunc: matcher,
		getKvDataFunc:  getter,
	}

	// like "object/config/group"
	dispatcher.profileKeys = []keyMappingHelper{
		{obj: share.CLUSConfigGroupStore, prf: share.ProfileGroupStore}, // at first
		{obj: share.CLUSConfigProcessProfileStore, prf: share.ProfileProcessStore},
		{obj: share.CLUSConfigFileAccessRuleStore, prf: share.ProfileFileAccessStore},
		{obj: share.CLUSConfigFileMonitorStore, prf: share.ProfileFileMonitorStore},
		{obj: share.CLUSConfigScriptStore, prf: share.ProfileFileScriptStore},
	}
}

func GetDispatchHelper() DispatcherHelper {
	return dispatcher
}

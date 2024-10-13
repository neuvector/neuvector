package kv

import (
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

func writePolicyToKvClusterTxn(txn *cluster.ClusterTransact, dels []uint32, keeps []*share.CLUSRuleHead) int {
	// Write updated rules to the cluster
	if len(dels) > 0 {
		_ = clusHelper.PutPolicyRuleListTxn(txn, keeps)
		for _, id := range dels {
			_ = clusHelper.DeletePolicyRuleTxn(txn, id)
		}
	}
	return len(dels)
}

func deletePolicyByGroupsTxn(txn *cluster.ClusterTransact, names []string) int { // return # of deleted policies
	crhs := clusHelper.GetPolicyRuleList()
	dels := make([]uint32, 0, 32)
	keeps := make([]*share.CLUSRuleHead, 0, len(crhs))
	for _, crh := range crhs {
		var found bool
		var getFromKvCalled bool
		var r *share.CLUSPolicyRule

		rhCfgType := common.PolicyRuleIdToCfgType(crh.ID)
		for _, name := range names {
			isFedGroup := strings.HasPrefix(name, api.FederalGroupPrefix)
			if (isFedGroup && rhCfgType == share.FederalCfg) || (!isFedGroup && rhCfgType != share.FederalCfg) {
				if r == nil {
					r, _ = clusHelper.GetPolicyRule(crh.ID)
					getFromKvCalled = true
				}
				if r != nil && (r.From == name || r.To == name) {
					// found the policy to be deleted
					found = true
					break
				}
			}
		}
		if found {
			dels = append(dels, crh.ID)
		} else if !getFromKvCalled || r != nil {
			keeps = append(keeps, crh)
		}
	}

	// Write updated rules to the cluster
	return writePolicyToKvClusterTxn(txn, dels, keeps)
}

func DeletePolicyByGroups(names []string) int { // return # of deleted policies
	txn := cluster.Transact()
	defer txn.Close()

	delCount := deletePolicyByGroupsTxn(txn, names)
	if delCount > 0 {
		if ok, err := txn.Apply(); err != nil || !ok {
			log.WithFields(log.Fields{"error": err, "ok": ok}).Error("Atomic write failed")
			return 0
		}
	}

	return delCount
}

func DeletePolicyByGroup(name string) int { // return # of deleted policies
	return DeletePolicyByGroups([]string{name})
}

func DeletePolicyByGroupTxn(txn *cluster.ClusterTransact, name string) error {
	deletePolicyByGroupsTxn(txn, []string{name})

	return nil
}

func DeletePolicyByCfgTypeTxn(txn *cluster.ClusterTransact, cfgType share.TCfgType) {
	delsNum, keepsNum := 0, 0
	crhs := clusHelper.GetPolicyRuleList()
	for _, crh := range crhs {
		if cfgType == common.PolicyRuleIdToCfgType(crh.ID) {
			delsNum++
		} else {
			keepsNum++
		}
	}
	dels := make([]uint32, 0, delsNum)
	keeps := make([]*share.CLUSRuleHead, 0, keepsNum)
	for _, crh := range crhs {
		if cfgType == common.PolicyRuleIdToCfgType(crh.ID) {
			dels = append(dels, crh.ID)
		} else {
			keeps = append(keeps, crh)
		}
	}

	// Write updated rules to the cluster
	writePolicyToKvClusterTxn(txn, dels, keeps)
}

func deleteResponseRuleByGroupTxn(txn *cluster.ClusterTransact, name string, cfgType *share.TCfgType) int {
	isFedGroup := strings.HasPrefix(name, api.FederalGroupPrefix)
	if cfgType != nil && *cfgType == share.FederalCfg && name == api.LearnedExternal {
		isFedGroup = true
	}
	delCount := 0
	policyNames := []string{share.DefaultPolicyName, share.FedPolicyName}
	for _, policyName := range policyNames {
		if (isFedGroup && policyName != share.FedPolicyName) || (!isFedGroup && policyName == share.FedPolicyName) {
			continue
		}
		dels := utils.NewSet()
		keeps := make([]*share.CLUSRuleHead, 0)
		crhs := clusHelper.GetResponseRuleList(policyName)
		for _, crh := range crhs {
			rhCfgType := share.UserCreated
			if crh.ID > api.StartingFedAdmRespRuleID {
				rhCfgType = share.FederalCfg
			}
			if (isFedGroup && rhCfgType == share.FederalCfg) || (!isFedGroup && rhCfgType != share.FederalCfg) {
				if r, _ := clusHelper.GetResponseRule(policyName, crh.ID); r != nil {
					if r.Group == name {
						// To be deleted
						dels.Add(crh.ID)
					} else {
						keeps = append(keeps, crh)
					}
				}
			} else {
				keeps = append(keeps, crh)
			}
		}

		// Write updated rules to the cluster by transaction
		if dels.Cardinality() > 0 {
			_ = clusHelper.PutResponseRuleListTxn(policyName, txn, keeps)
			for id := range dels.Iter() {
				_ = clusHelper.DeleteResponseRuleTxn(policyName, txn, id.(uint32))
			}
			delCount += dels.Cardinality()
		}
	}
	return delCount
}

func deleteResponseRuleByGroupsTxn(txn *cluster.ClusterTransact, names []string) int {
	delCount := 0
	policyNames := []string{share.DefaultPolicyName, share.FedPolicyName}
	for _, policyName := range policyNames {
		dels := utils.NewSet()
		keeps := make([]*share.CLUSRuleHead, 0)
		crhs := clusHelper.GetResponseRuleList(policyName)
		for _, crh := range crhs {
			var found bool
			var getFromKvCalled bool
			var r *share.CLUSResponseRule

			rhCfgType := share.UserCreated
			if crh.ID > api.StartingFedAdmRespRuleID {
				rhCfgType = share.FederalCfg
			}
			for _, name := range names {
				isFedGroup := strings.HasPrefix(name, api.FederalGroupPrefix)
				if (isFedGroup && policyName != share.FedPolicyName) || (!isFedGroup && policyName == share.FedPolicyName) {
					continue
				}
				if (isFedGroup && rhCfgType == share.FederalCfg) || (!isFedGroup && rhCfgType != share.FederalCfg) {
					if r == nil {
						r, _ = clusHelper.GetResponseRule(policyName, crh.ID)
						getFromKvCalled = true
					}
					if r != nil && r.Group == name {
						// found the responsible rule to be deleted
						found = true
						break
					}
				}
			}
			if found {
				dels.Add(crh.ID)
			} else if !getFromKvCalled || r != nil {
				keeps = append(keeps, crh)
			}
		}
		// Write updated rules to the cluster by transaction
		if dels.Cardinality() > 0 {
			_ = clusHelper.PutResponseRuleListTxn(policyName, txn, keeps)
			for id := range dels.Iter() {
				_ = clusHelper.DeleteResponseRuleTxn(policyName, txn, id.(uint32))
			}
			delCount += dels.Cardinality()
		}
	}
	return delCount
}

func DeleteResponseRuleByGroup(name string) int {
	return DeleteResponseRuleByGroups([]string{name})
}

func DeleteResponseRuleByGroups(names []string) int {
	txn := cluster.Transact()
	defer txn.Close()

	delCount := deleteResponseRuleByGroupsTxn(txn, names)
	if delCount > 0 {
		if ok, err := txn.Apply(); err != nil || !ok {
			log.WithFields(log.Fields{"error": err, "ok": ok}).Error("Atomic write failed")
			return 0
		}
	}

	return delCount
}

func DeleteResponseRuleByGroupTxn(txn *cluster.ClusterTransact, name string, cfgType share.TCfgType) error {
	deleteResponseRuleByGroupTxn(txn, name, &cfgType)

	return nil
}

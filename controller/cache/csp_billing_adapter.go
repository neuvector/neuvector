package cache

import (
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/utils"
)

type tClusterUsage struct {
	nodes int
}

var clusterUsage tClusterUsage // local cluster usage

// 1. when called on master cluster, return (total reachable clusters' nodes count in this fed, nv usage data in this fed)
// 2. when called on joint/standalone cluster, return (nodes count in this cluster, nv usage data in this cluster)
func (m CacheMethod) GetNvUsage(fedRole string) api.RESTNvUsage {
	_, cspType := common.GetMappedCspType(nil, &cctx.CspType)
	localUsage := &api.RESTClusterCspUsage{
		CspType: cspType,
		Nodes:   clusterUsage.nodes,
	}
	roleMapping := map[string]string{
		api.FedRoleMaster: "primary",
		api.FedRoleJoint:  "downstream",
		api.FedRoleNone:   "standalone",
	}
	nvUsage := api.RESTNvUsage{
		LocalClusterRole:  roleMapping[fedRole],
		LocalClusterUsage: *localUsage,
	}

	if fedRole == api.FedRoleMaster {
		// _fedClusterConnected(200), _fedClusterJoined(201), _fedClusterOutOfSync(202), _fedClusterSynced(203)
		connectedStates := utils.NewSet(200, 201, 202, 203)
		totalNodes := 0
		unreachable := 0
		cspUsages := make(map[string]int)
		fedCacheMutexRLock()
		memberUsages := make([]*api.RESTClusterCspUsage, 0, len(fedJoinedClusterStatusCache)+1)
		for _, cached := range fedJoinedClusterStatusCache {
			if connectedStates.Contains(cached.Status) {
				_, memberCspType := common.GetMappedCspType(nil, &cached.CspType)
				cspUsages[memberCspType] += cached.Nodes
				memberUsages = append(memberUsages, &api.RESTClusterCspUsage{
					CspType: memberCspType,
					Nodes:   cached.Nodes,
				})
				totalNodes += cached.Nodes
			} else {
				unreachable += 1
			}
		}
		fedCacheMutexRUnlock()
		memberUsages = append(memberUsages, localUsage)
		cspUsages[cspType] += localUsage.Nodes
		totalNodes += localUsage.Nodes
		nvUsage.FedUsage = &api.RESTFedCspUsage{
			TotalNodes:   totalNodes,
			Unreachable:  unreachable,
			CspUsages:    cspUsages,
			MemberUsages: memberUsages,
		}
	}

	return nvUsage
}

func ConfigCspUsages(addOnly, forceConfig bool, fedRole, masterClusterID string) error {
	if localDev.Host.Platform == share.PlatformDocker {
		acc := access.NewAdminAccessControl()
		// The pricing generally should be based on total node count in the cluster, not enforcer count, even though those two are usually the same.
		// However, for NV deployment on native docker (as downstream cluster in multi-cluster env), downstream nv reports its enforcer count as node count to master cluster.
		clusterUsage.nodes = cacher.GetAgentCount(acc, "")
	} else {
		if objs, err := global.ORCH.ListResource(resource.RscTypeNode, ""); err == nil {
			clusterUsage.nodes = len(objs)
		} else {
			clusterUsage.nodes = 1
		}
	}

	if cctx.CspType == share.CSP_NONE {
		return nil
	}

	var totalNodes int

	if fedRole == api.FedRoleMaster {
		nvUsage := cacher.GetNvUsage(fedRole)
		totalNodes = nvUsage.FedUsage.TotalNodes
	} else {
		totalNodes = clusterUsage.nodes
		if fedRole == api.FedRoleJoint && masterClusterID != "" {
			data := fedJoinedClusterStatusCache[masterClusterID]
			pauseTime := data.LastConnectedTime.Add(time.Minute * time.Duration(cctx.CspPauseInterval))
			if forceConfig || (!data.LastConnectedTime.IsZero() && time.Now().Before(pauseTime)) {
				// it's still < 4 hours since master cluster was last reachable from this joint cluster
				// tell local csp-adapter not to report usage
				totalNodes = 0
			}
		}
	}

	var err error
	var obj interface{}
	rscName := resource.RscCspUsageName
	nvSemanticVersion := cctx.NvSemanticVersion
	if strings.HasPrefix(nvSemanticVersion, "v") {
		nvSemanticVersion = nvSemanticVersion[1:]
	}
	// nvSemanticVersion is in the format {major}.{minor}.{patch}
	// baseProduct is in the format cpe:/o:suse:neuvector:{major}.{minor}.{patch}
	baseProduct := fmt.Sprintf("cpe:/o:suse:neuvector:%s", nvSemanticVersion)
	t := time.Now().Format("2006-01-02T15:04:05.000000-07:00")
	if obj, err = global.ORCH.GetResource(resource.RscTypeCrdNvCspUsage, "", rscName); err == nil {
		if crCspUsage, ok := obj.(*resource.NvCspUsage); ok {
			crCspUsage.ManagedNodeCount = totalNodes
			crCspUsage.ReportingTime = t
			crCspUsage.BaseProduct = baseProduct
			err = global.ORCH.UpdateResource(resource.RscTypeCrdNvCspUsage, crCspUsage)
		} else {
			err = fmt.Errorf("unsupported type")
		}
	} else if strings.Contains(err.Error(), " 404 ") {
		if addOnly {
			kind := resource.NvCspUsageKind
			apiVersion := "susecloud.net/v1"
			crCspUsage := &resource.NvCspUsage{
				TypeMeta: metav1.TypeMeta{
					Kind:       kind,
					APIVersion: apiVersion,
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: rscName,
				},
				ManagedNodeCount: totalNodes,
				ReportingTime:    t,
				BaseProduct:      baseProduct,
			}
			err = global.ORCH.AddResource(resource.RscTypeCrdNvCspUsage, crCspUsage)
		}
	}
	if err != nil {
		log.WithFields(log.Fields{"rscName": rscName, "addOnly": addOnly, "err": err}).Error()
		return err
	}

	return nil
}

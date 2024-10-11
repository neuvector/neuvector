package cache

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/neuvector/k8s"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/controller/scan"
	"github.com/neuvector/neuvector/db"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/container"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/utils"
)

func getHostPlatform(platform, flavor string) string {
	if flavor == "" {
		return platform
	} else {
		return fmt.Sprintf("%v-%v", platform, flavor)
	}
}

func host2REST(cache *hostCache, k8sCache *k8sHostCache) *api.RESTHost {
	host := cache.host
	h := &api.RESTHost{
		Name:           host.Name,
		ID:             host.ID,
		Runtime:        host.Runtime,
		RuntimeVer:     host.RuntimeVer,
		RuntimeAPIVer:  host.RuntimeAPIVer,
		OS:             host.OS,
		Kernel:         host.Kernel,
		CPUs:           host.CPUs,
		Memory:         host.Memory,
		CGroupVersion:  host.CgroupVersion,
		Ifaces:         make(map[string][]*api.RESTIPAddr),
		State:          cache.state,
		Containers:     cache.runningCntrs.Cardinality(),
		Pods:           cache.runningPods.Cardinality(),
		Platform:       getHostPlatform(host.Platform, host.Flavor),
		CapDockerBench: host.CapDockerBench,
		CapKubeBench:   host.CapKubeBench,
		ScanSummary:    cache.scanBrief,
		StorageDriver:  host.StorageDriver,
	}
	if k8sCache != nil && k8sCache.id == host.ID {
		h.Labels = k8sCache.labels
		h.Annotations = k8sCache.annotations
	}

	h.PolicyMode, h.ProfileMode = getHostPolicyMode(cache)

	if cache.scanBrief == nil {
		h.ScanSummary = &api.RESTScanBrief{}
	}
	for name, addrs := range host.Ifaces {
		h.Ifaces[name] = make([]*api.RESTIPAddr, len(addrs))
		for i, addr := range addrs {
			ones, _ := addr.IPNet.Mask.Size()
			h.Ifaces[name][i] = &api.RESTIPAddr{
				IP:       addr.IPNet.IP.String(),
				IPPrefix: ones,
				Gateway:  addr.Gateway,
			}
		}
	}

	return h
}

func agent2REST(cache *agentCache) *api.RESTAgent {
	agent := cache.agent
	config := cache.config

	c := &api.RESTAgent{
		Name:        agent.Name,
		DisplayName: cache.displayName,
		ID:          agent.ID,
		HostName:    agent.HostName,
		HostID:      agent.HostID,
		Ver:         agent.Ver,
		Labels:      agent.Labels,
		Domain:      agent.Domain,
		PidMode:     agent.PidMode,
		NetworkMode: agent.NetworkMode,
		CreatedAt:   api.RESTTimeString(agent.CreatedAt),
		StartedAt:   api.RESTTimeString(agent.StartedAt),
		JoinedAt:    api.RESTTimeString(agent.JoinedAt),
		MemoryLimit: agent.MemoryLimit,
		CPUs:        agent.CPUs,
		ClusterIP:   agent.ClusterIP,
		DisconnAt:   api.RESTTimeString(cache.disconnAt),
		State:       cache.state,
		NvProtect:   !config.DisableNvProtectMode,
	}

	if c.Name == c.ID {
		// This happens when container doesn't have a name, such as with containerd
		c.Name = c.DisplayName
	}

	return c
}

func ctrl2REST(cache *ctrlCache) *api.RESTController {
	ctrl := cache.ctrl

	c := &api.RESTController{
		ID:                ctrl.ID,
		Name:              ctrl.Name,
		DisplayName:       cache.displayName,
		HostName:          ctrl.HostName,
		HostID:            ctrl.HostID,
		Ver:               ctrl.Ver,
		Labels:            ctrl.Labels,
		Domain:            ctrl.Domain,
		CreatedAt:         api.RESTTimeString(ctrl.CreatedAt),
		StartedAt:         api.RESTTimeString(ctrl.StartedAt),
		JoinedAt:          api.RESTTimeString(ctrl.JoinedAt),
		MemoryLimit:       ctrl.MemoryLimit,
		CPUs:              ctrl.CPUs,
		ClusterIP:         ctrl.ClusterIP,
		Leader:            ctrl.Leader,
		State:             cache.state,
		DisconnAt:         api.RESTTimeString(cache.disconnAt),
		OrchConnStatus:    ctrl.OrchConnStatus,
		OrchConnLastError: ctrl.OrchConnLastError,
		ReadPrimeConfig:   ctrl.ReadPrimeConfig,
	}

	if c.Name == c.ID {
		// This happens when container doesn't have a name, such as with containerd
		c.Name = c.DisplayName
	}

	return c
}

func translateWorkloadApps(wl *share.CLUSWorkload) []string {
	var app_set utils.Set = utils.NewSet()

	for _, app := range wl.Apps {
		noApp := false
		noSVR := false

		if name, ok := common.AppNameMap[app.Server]; ok {
			app_set.Add(name)
		} else {
			noSVR = true
		}
		if name, ok := common.AppNameMap[app.Application]; ok {
			app_set.Add(name)
		} else {
			noApp = true
		}
		if name, ok := common.AppNameMap[app.Proto]; ok {
			app_set.Add(name)
		} else if noApp && noSVR {
			switch app.IPProto {
			case syscall.IPPROTO_TCP:
				app_set.Add(fmt.Sprintf("TCP/%d", app.Port))
			case syscall.IPPROTO_UDP:
				app_set.Add(fmt.Sprintf("UDP/%d", app.Port))
			case syscall.IPPROTO_ICMP:
				app_set.Add("ICMP")
			default:
				app_set.Add(fmt.Sprintf("%d/%d", app.IPProto, app.Port))
			}
		}
	}

	i := 0
	apps := make([]string, app_set.Cardinality())
	for app := range app_set.Iter() {
		apps[i] = app.(string)
		i++
	}

	return apps
}

// Calling with both graph and cache read-lock held
func workload2EndpointREST(cache *workloadCache, withChildren bool) *api.RESTConversationEndpoint {
	r := &api.RESTConversationEndpoint{
		Kind:              api.EndpointKindContainer,
		RESTWorkloadBrief: *workload2BriefREST(cache),
	}

	if a := wlGraph.Attr(r.ID, attrLink, dummyEP); a != nil {
		attr := a.(*nodeAttr)
		if attr.alias != "" {
			r.DisplayName = attr.alias
		}
	}

	if withChildren {
		for child := range cache.children.Iter() {
			if childCache, ok := wlCacheMap[child.(string)]; ok {
				r.Children = append(r.Children, workload2BriefREST(childCache))
			}
		}
	}

	return r
}

// For internal use, only needed fields are assigned
func workload2Risk(cache *workloadCache, includeBench bool) *common.WorkloadRisk {
	wl := cache.workload
	r := &common.WorkloadRisk{
		ID:           wl.ID,
		Name:         cache.podName,
		PlatformRole: cache.platformRole,
		ImageID:      wl.ImageID,
		Domain:       wl.Domain,
	}
	if cache.scanBrief != nil {
		r.BaseOS = cache.scanBrief.BaseOS
	}
	r.PolicyMode, _ = getWorkloadPerGroupPolicyMode(cache)

	if includeBench {
		bench, err := db.GetBenchData(wl.ID)
		if err == nil {
			r.CustomBenchValue = bench.CustomBenchValue
			r.DockerBenchValue = bench.DockerBenchValue
			r.SecretBenchValue = bench.SecretBenchValue
			r.SetidBenchValue = bench.SetidBenchValue
		}
	}

	return r
}

func workload2BriefREST(cache *workloadCache) *api.RESTWorkloadBrief {
	wl := cache.workload

	r := &api.RESTWorkloadBrief{
		ID:                 wl.ID,
		Name:               wl.Name,
		DisplayName:        cache.displayName,
		PodName:            cache.podName,
		HostName:           wl.HostName,
		HostID:             wl.HostID,
		Image:              wl.Image,
		ImageID:            wl.ImageID,
		ImgCreateAt:        api.RESTTimeString(wl.ImgCreateAt),
		ImgRegScand:        scan.IsRegistryImageScanned(wl.ImageID),
		PlatformRole:       cache.platformRole,
		Domain:             wl.Domain,
		Author:             wl.Author,
		State:              deriveWorkloadState(cache),
		Service:            cache.serviceName,
		ServiceGroup:       cache.learnedGroupName,
		ShareNSWith:        wl.ShareNetNS,
		CapQuar:            wl.CapIntcp && cache.state != api.StateUnmanaged,                                      // Allow quarantine when workload is not running
		CapSniff:           wl.CapSniff && !cacher.disablePCAP && wl.Running && cache.state != api.StateUnmanaged, // Only allow sniff when workload is running
		HasDatapath:        wl.HasDatapath,
		CapChgMode:         true,
		ScanSummary:        cache.scanBrief,
		Children:           make([]*api.RESTWorkloadBrief, 0),
		ServiceMesh:        wl.ProxyMesh,
		ServiceMeshSidecar: wl.Sidecar,
		Privileged:         wl.Privileged,
		RunAsRoot:          wl.RunAsRoot,
	}

	r.PolicyMode, r.ProfileMode = getWorkloadPerGroupPolicyMode(cache)
	r.BaselineProfile = getWorkloadBaselineProfile(cache)

	if cache.scanBrief == nil {
		r.ScanSummary = &api.RESTScanBrief{}
	}
	if r.Name == r.ID {
		// This happens when container doesn't have a name, such as with containerd
		r.Name = cache.podName
	}
	if r.State == api.WorkloadStateQuarantine {
		r.QuarReason = cache.config.QuarReason
	}
	return r
}

// cacheMutexRLock is already called by caller
func workload2DetailREST(cache *workloadCache) *api.RESTWorkloadDetail {
	wl := &api.RESTWorkloadDetail{
		RESTWorkload: *workload2REST(cache),
		Groups:       make([]string, cache.groups.Cardinality()),
	}

	i := 0
	for name := range cache.groups.Iter() {
		wl.Groups[i] = name.(string)
		i++
	}

	wl.AppPorts = getAppPorts(cache.workload)
	return wl
}

// cacheMutexRLock is already called by caller
func workload2REST(cache *workloadCache) *api.RESTWorkload {
	wl := cache.workload

	r := &api.RESTWorkload{
		RESTWorkloadBrief: *workload2BriefREST(cache),
		AgentID:           wl.AgentID,
		AgentName:         getAgentNameNoLock(wl.AgentID),
		NetworkMode:       wl.NetworkMode,
		CreatedAt:         api.RESTTimeString(wl.CreatedAt),
		StartedAt:         api.RESTTimeString(wl.StartedAt),
		FinishedAt:        api.RESTTimeString(wl.FinishedAt),
		Running:           wl.Running,
		ExitCode:          wl.ExitCode,
		SecuredAt:         api.RESTTimeString(wl.SecuredAt),
		Ifaces:            make(map[string][]*api.RESTIPAddr),
		Ports:             make([]*api.RESTWorkloadPorts, len(wl.Ports)),
		Labels:            wl.Labels,
		MemoryLimit:       wl.MemoryLimit,
		CPUs:              wl.CPUs,
		Children:          make([]*api.RESTWorkload, 0),
		ServiceAccount:    cache.serviceAccount,
	}

	if wl.Running {
		for name, addrs := range wl.Ifaces {
			r.Ifaces[name] = make([]*api.RESTIPAddr, len(addrs))
			for i, addr := range addrs {
				ones, _ := addr.IPNet.Mask.Size()
				r.Ifaces[name][i] = &api.RESTIPAddr{
					IP:       addr.IPNet.IP.String(),
					IPPrefix: ones,
					Gateway:  addr.Gateway,
				}
			}
		}

		r.Applications = translateWorkloadApps(wl)
	} else {
		r.Applications = make([]string, 0)
	}

	i := 0
	for _, port := range wl.Ports {
		r.Ports[i] = &api.RESTWorkloadPorts{
			RESTProtoPort: api.RESTProtoPort{
				IPProto: port.IPProto,
				Port:    port.Port,
			},
			HostIP:   port.HostIP.String(),
			HostPort: port.HostPort,
		}
		i++
	}

	return r
}

func getDeviceDisplayName(dev *share.CLUSDevice) string {
	if task, ok := dev.Labels[container.DockerSwarmTaskName]; ok {
		if tid, ok := dev.Labels[container.DockerSwarmTaskID]; !ok {
			return task
		} else if !strings.HasSuffix(task, fmt.Sprintf(".%s", tid)) {
			return task
		} else {
			return task[:len(task)-len(tid)-1]
		}
	} else if name, ok := dev.Labels[container.RancherKeyContainerName]; ok {
		return name
	} else if pod, ok := dev.Labels[container.KubeKeyPodName]; ok {
		return pod
	}
	return dev.Name
}

func getWorkloadDisplayName(wl *share.CLUSWorkload, parent string) (string, string) {
	if task, ok := wl.Labels[container.DockerSwarmTaskName]; ok {
		if tid, ok := wl.Labels[container.DockerSwarmTaskID]; !ok {
			return task, task
		} else if !strings.HasSuffix(task, fmt.Sprintf(".%s", tid)) {
			return task, task
		} else {
			name := task[:len(task)-len(tid)-1]
			return name, name
		}
	} else if name, ok := wl.Labels[container.RancherKeyContainerName]; ok {
		if parent == "" {
			return name, name
		}
	} else if pod, ok := wl.Labels[container.KubeKeyPodName]; ok {
		if parent == "" {
			return pod, pod
		} else if cname, ok := wl.Labels[container.KubeKeyContainerName]; ok {
			// return "io.kubernetes.container.name" value for children
			return cname, pod
		}
	}
	return wl.Name, wl.Name
}

// With cachMutex held
func addrHostAdd(id string, param interface{}) {
	host := param.(*hostCache).host

	// Update Host_ip-to-Host map
	for _, addrs := range host.Ifaces {
		for _, addr := range addrs {
			switch addr.Scope {
			case share.CLUSIPAddrScopeNAT:
				key := addr.IPNet.IP.String()
				hp, ok := ipHostMap[key]
				if !ok || hp.hostID != host.ID {
					if hp, ok := ipHostMap[key]; ok {
						hp.hostID = host.ID
						hp.ipnet = addr.IPNet
						hp.managed = true
					} else {
						ipHostMap[key] = &hostDigest{hostID: host.ID, ipnet: addr.IPNet, managed: true}
					}

					log.WithFields(log.Fields{"ip": key, "host": host.ID}).Debug("ip-host map")
				}

				if global.ORCH.ConsiderHostsAsInternal() {
					updateInternalIPNet(&addr.IPNet, addr.Scope, false)
				}
			}
		}
	}

	// Update Tunnel_ip-to-Host map
	if host.TunnelIP != nil {
		for _, ipnet := range host.TunnelIP {
			key := ipnet.IP.String()
			hostID, ok := tunnelHostMap[key]
			if !ok || hostID != host.ID {
				tunnelHostMap[key] = host.ID

				log.WithFields(log.Fields{"ip": key, "host": host.ID}).Debug("tunnel-host map")
			}
			// Because tunnel IP could be in the same subnet of containers, don't add it to host
			// subnet but workload subnet. When the node joins, try to clean both workload and
			// node IP endpoint.
			updateInternalIPNet(&ipnet, share.CLUSIPAddrScopeGlobal, false)
		}
	}
}

// With cachMutex held
func addrHostDelete(id string, param interface{}) {
	host := param.(*hostCache).host

	for _, addrs := range host.Ifaces {
		for _, addr := range addrs {
			switch addr.Scope {
			case share.CLUSIPAddrScopeNAT:
				//Only delete ip with same host-id,
				//same ip can be used by newly added
				//host with different host-id, due to
				//delayed removal of old host,  same
				//ip can be deleted unexpectedly which
				//cause host violation. (NVSHAS-5120&5011)
				key := addr.IPNet.IP.String()
				hp, ok := ipHostMap[key]
				if ok && hp.hostID == host.ID {
					delete(ipHostMap, key)
				}
			}
		}
	}

	if host.TunnelIP != nil {
		for _, ipnet := range host.TunnelIP {
			key := ipnet.IP.String()
			hostID, ok := tunnelHostMap[key]
			if ok && hostID == host.ID {
				delete(tunnelHostMap, key)
			}
		}
	}
}

func addrOrchHostAdd(ipnets []net.IPNet) {
	cacheMutexLock()
	defer cacheMutexUnlock()

	for _, ipnet := range ipnets {
		key := ipnet.IP.String()
		if hp, ok := ipHostMap[key]; ok {
			if !hp.managed {
				hp.ipnet = ipnet
			}
			hp.orched = true
		} else {
			ipHostMap[key] = &hostDigest{ipnet: ipnet, orched: true}
		}

		log.WithFields(log.Fields{"ip": key}).Debug("ip-host map")

		if global.ORCH.ConsiderHostsAsInternal() {
			updateInternalIPNet(&ipnet, share.CLUSIPAddrScopeNAT, false)
		}
	}
}

func addrOrchHostDelete(ipnets []net.IPNet) {
	cacheMutexLock()
	defer cacheMutexUnlock()

	for _, ipnet := range ipnets {
		delete(ipHostMap, ipnet.IP.String())
	}
}

// With cachMutex held
func addrDeviceAdd(id string, ifaces map[string][]share.CLUSIPAddr) {
	var addcnt int = 0
	for _, addrs := range ifaces {
		for _, addr := range addrs {
			switch addr.Scope {
			case share.CLUSIPAddrScopeGlobal:
				key := addr.IPNet.IP.String()
				if _, ok := ipDevMap[key]; !ok {
					log.WithFields(log.Fields{"ip": key, "id": id}).Info("add ip-device map")
					ipDevMap[key] = &workloadEphemeral{wl: id}
					addcnt++
				} else {
					log.WithFields(log.Fields{"ip": key, "id": id}).Info("renew ip-device map")
					ipDevMap[key] = &workloadEphemeral{wl: id}
				}
				updateInternalIPNet(&addr.IPNet, share.CLUSIPAddrScopeGlobal, true)
			}
		}
	}
	//during rolling upgrade, when enforcer (re)start, orchstration can be faster
	//than agent get updated which cause neuvector device temprary to be unmanaged
	//workload, reset unManagedWlTimer to update unmanaged workload ip to prevent
	//neuvector device being treated as unmanaged wl
	if addcnt > 0 {
		scheduleUnmanagedWlProc(true)
	}

	// cleanup ephemeral entries
	for key, dev := range ipDevMap {
		if !dev.stop.IsZero() && time.Since(dev.stop) > workloadEphemeralLife {
			delete(ipDevMap, key)
		}
	}

	log.WithFields(log.Fields{"count": len(ipDevMap)}).Info()
}

// With cachMutex held
func addrDeviceDelete(id string, ifaces map[string][]share.CLUSIPAddr) {
	for _, addrs := range ifaces {
		for _, addr := range addrs {
			switch addr.Scope {
			case share.CLUSIPAddrScopeGlobal:
				key := addr.IPNet.IP.String()
				if dev, ok := ipDevMap[key]; ok {
					log.WithFields(log.Fields{"ip": key, "id": id}).Info("delay remove ip-device map")
					dev.stop = time.Now()
				}
			}
		}
	}
}

// With cachMutex held
func addrDeviceDeleteByID(id string) bool {
	var deled bool
	for key, dev := range ipDevMap {
		if dev.wl == id {
			log.WithFields(log.Fields{"ip": key, "id": id}).Info("delay remove ip-device map")
			dev.stop = time.Now()
			deled = true
		}
	}
	return deled
}

func hostUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	log.WithFields(log.Fields{"type": cluster.ClusterNotifyName[nType], "key": key}).Debug()

	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		var newHost, ok bool
		var cache *hostCache
		var host share.CLUSHost
		_ = json.Unmarshal(value, &host)

		if localDev.Host.Platform == share.PlatformKubernetes && localDev.Host.Flavor == share.FlavorRancher && host.Flavor == "" {
			host.Flavor = share.FlavorRancher
		}
		log.WithFields(log.Fields{"host": host}).Info("Add or update host")

		cacheMutexLock()

		if cache, ok = hostCacheMap[host.ID]; !ok {
			cache = initHostCache(host.ID)
			cache.host = &host
			if localDev.Host.Platform == share.PlatformKubernetes {
				k8sCache, ok := k8sHostInfoMap[host.Name]
				if !ok {
					k8sCache = &k8sHostCache{id: host.ID}
				}

				if k8sCache.id != host.ID {
					if k8sCache.id != "" {
						k8sCache.labels = nil
						k8sCache.annotations = nil
					}
					k8sCache.id = host.ID
				}
				if len(k8sCache.labels) == 0 && len(k8sCache.annotations) == 0 {
					if obj, err := global.ORCH.GetResource(resource.RscTypeNode, k8s.AllNamespaces, host.Name); err == nil {
						node := obj.(*resource.Node)
						k8sCache.labels, k8sCache.annotations = node.Labels, node.Annotations
					} else {
						k8sNames := make([]string, 0, 4)
						// [2021/07/29] special handling for IBM Cloud:
						//  host.Name is like "kube-c40msj4d0tb4oeriggqg-atibmcluste-default-000001f1"
						//  k8s node name in IBM Cloud is IP
						// when controller process restarts, kv watcher calls before resource warcher that we don't know the k8s node name(should be IP) in IBM Cloud
						if ipAddrs, ok := host.Ifaces["eth0"]; ok {
							for _, ipAddr := range ipAddrs {
								k8sNames = append(k8sNames, ipAddr.IPNet.IP.String())
							}
						}
						for eth, ipAddrs := range host.Ifaces {
							if eth != "eth0" {
								for _, ipAddr := range ipAddrs {
									k8sNames = append(k8sNames, ipAddr.IPNet.IP.String())
								}
							}
						}
						log.WithFields(log.Fields{"host": host.Name, "error": err, "k8sNames": k8sNames}).Debug()
						for _, k8sName := range k8sNames {
							if obj, err := global.ORCH.GetResource(resource.RscTypeNode, k8s.AllNamespaces, k8sName); err == nil {
								node := obj.(*resource.Node)
								if node.Name == k8sName {
									k8sCache.labels, k8sCache.annotations = node.Labels, node.Annotations
									if k8sCache.k8sNodeName == "" {
										k8sCache.k8sNodeName = node.Name
									}
									break
								}
							}
						}
					}
				}
				k8sHostInfoMap[host.Name] = k8sCache
			}

			hostCacheMap[host.ID] = cache

			newHost = true
		} else {
			// New agent will create a pseudo host
			if len(cache.host.Ifaces) == 0 && len(host.Ifaces) > 0 {
				newHost = true
			}
			cache.host = &host
		}

		cancelHostRemoval(cache)
		addrHostAdd(host.ID, cache)

		cacheMutexUnlock()

		if host.Platform != "" {
			hostPlatform = getHostPlatform(host.Platform, host.Flavor)
		}

		if newHost {
			evhdls.Trigger(EV_HOST_ADD, host.ID, cache)
		}

	case cluster.ClusterNotifyDelete:
		hostID := share.CLUSHostKey2ID(key)
		log.WithFields(log.Fields{"id": hostID}).Info("Delete host")

		cacheMutexLock()
		cache, ok := hostCacheMap[hostID]
		if ok {
			addrHostDelete(hostID, cache)
			delete(hostCacheMap, hostID)
			delete(k8sHostInfoMap, cache.host.Name)
			refreshInternalIPNet()
		}
		cacheMutexUnlock()

		if cache != nil {
			evhdls.Trigger(EV_HOST_DELETE, hostID, cache)
		}

		// cleanup records in database
		if err := db.DeleteAssetByID(db.AssetNode, hostID); err != nil {
			log.WithFields(log.Fields{"err": err, "id": hostID}).Error("Delete asset in db failed.")
		}
	}
}

func agentUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	log.WithFields(log.Fields{"type": cluster.ClusterNotifyName[nType], "key": key}).Debug("")

	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		var agent share.CLUSAgent
		var newAgent bool
		_ = json.Unmarshal(value, &agent)

		log.WithFields(log.Fields{"agent": agent}).Info("Add or update enforcer")

		// Update agent cache
		var ac *agentCache
		var ok bool

		cacheMutexLock()

		/* agent deletes its own key when agent exits. The following logic is unlikely needed
		// Some network plugin reuse ip address quickly, before an old agent is finally removed,
		// a new agent can start with the same IP. Here we check to remove it.
		if exist, ok := ipDevMap[agent.ClusterIP]; ok && exist.wl != agent.ID {
			if existAC, ok := agentCacheMap[exist.wl]; ok {
				if existAC.agent.StartedAt.Before(agent.StartedAt) {
					log.WithFields(log.Fields{
						"agent": existAC.agent.ID, "clusterIP": existAC.agent.ClusterIP,
					}).Info("Delete enforcer with duplicate cluster IP")
					deleteAgentFromCluster(existAC.agent.HostID, existAC.agent.ID)
				} else {
					cacheMutexUnlock()
					log.WithFields(log.Fields{
						"agent": agent.ID, "clusterIP": agent.ClusterIP,
					}).Info("Delete enforcer with duplicate cluster IP")
					deleteAgentFromCluster(agent.HostID, agent.ID)
					return
				}
			}
		}
		*/

		if ac, ok = agentCacheMap[agent.ID]; !ok {
			ac = initAgentCache(agent.ID)
			agentCacheMap[agent.ID] = ac
		} else {
			ac.state = api.StateOnline
		}

		if isDummyAgentCache(ac) {
			// It can be a dummy entry created from other means
			ac.joinAt = time.Now().UTC()
			ac.selfHostname = agent.SelfHostname
			newAgent = true
		}

		ac.agent = &agent
		ac.displayName = getDeviceDisplayName(&agent.CLUSDevice)

		// Update host cache
		cache, ok := hostCacheMap[agent.HostID]
		if !ok {
			// Create a faked host
			cache = initHostCache(agent.HostID)
			hostCacheMap[agent.HostID] = cache
			log.WithFields(log.Fields{"host": agent.HostID}).Debug("Create dummy host")
		}
		cache.agents.Add(agent.ID)
		cancelHostRemoval(cache)

		addrDeviceAdd(agent.ID, agent.Ifaces)

		//workload on host without agent is unmanaged
		//process unmanaged wl ip for special subnet
		scheduleUnmanagedWlProc(true)

		cacheMutexUnlock()

		if newAgent {
			evhdls.Trigger(EV_AGENT_ADD, agent.ID, ac)
		}
		evhdls.Trigger(EV_AGENT_ONLINE, agent.ID, ac)

	case cluster.ClusterNotifyDelete:
		id := share.CLUSDeviceKey2ID(key)

		log.WithFields(log.Fields{"agent": id}).Info("Delete enforcer")

		cacheMutexLock()
		cache := agentCacheMap[id]
		if cache != nil {
			deleteAgentFromCache(cache)
			addrDeviceDelete(id, cache.agent.Ifaces)
		}
		//workload on host without agent is unmanaged
		//process unmanaged wl ip for special subnet
		scheduleUnmanagedWlProc(true)

		cacheMutexUnlock()

		if cache != nil {
			evhdls.Trigger(EV_AGENT_DELETE, id, cache)
		}
	}
}

func controllerUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	log.WithFields(log.Fields{"type": cluster.ClusterNotifyName[nType], "key": key}).Debug("")

	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		var ctrl share.CLUSController
		var newCtrl bool
		_ = json.Unmarshal(value, &ctrl)

		log.WithFields(log.Fields{"controller": ctrl}).Info("Add or update controller")

		var cc *ctrlCache
		var ok bool

		cacheMutexLock()
		// Update controller cache
		if cc, ok = ctrlCacheMap[ctrl.ID]; !ok {
			// TODO: temp. workaround
			// There is a case that the new controller has the different ID but the same IP of the old
			// controller. Because we use the cluster IP as the key, this causes confusions.
			// Remove the old record. The better way is to use ID as the cluster key.
			for _, cc = range ctrlCacheMap {
				if cc.ctrl.ID != ctrl.ID && cc.ctrl.ClusterIP == ctrl.ClusterIP {
					log.WithFields(log.Fields{"controller": cc.ctrl}).Info("duplicated controller")
					_ = cluster.Delete(cc.clusKey)
				}
			}

			cc = initCtrlCache(ctrl.ID)
			ctrlCacheMap[ctrl.ID] = cc
		} else {
			cc.state = api.StateOnline
		}

		if isDummyCtrlCache(cc) {
			cc.joinAt = time.Now()
			newCtrl = true
		}

		cc.ctrl = &ctrl
		cc.clusKey = key
		cc.displayName = getDeviceDisplayName(&ctrl.CLUSDevice)

		addrDeviceAdd(ctrl.ID, ctrl.Ifaces)
		cacheMutexUnlock()

		if newCtrl {
			evhdls.Trigger(EV_CONTROLLER_ADD, ctrl.ID, cc)
		}
	case cluster.ClusterNotifyDelete:
		id := share.CLUSDeviceKey2ID(key)

		log.WithFields(log.Fields{"controller": id}).Info("Delete controller")

		cacheMutexLock()
		cache := ctrlCacheMap[id]
		if cache != nil {
			deleteControllerFromCache(cache)
			addrDeviceDelete(id, cache.ctrl.Ifaces)
		}
		cacheMutexUnlock()

		if cache != nil {
			evhdls.Trigger(EV_CONTROLLER_DELETE, id, cache)
		}
	}
}

// Called with cacheMutex() locked
func timeoutEphemeralWorkload() bool {
	refreshUWL := false
	// Note that when a worklad comes back from stop to start, or a new workload starts
	// reusing the IP address, the ephemeral entry is not deleted. We here just check if
	// the mapped entry is alive, and ignore if it is alive.
	for i, ewl := range wlEphemeral {
		if time.Since(ewl.stop) < workloadEphemeralLife {
			// array is sorted
			wlEphemeral = wlEphemeral[i:]
			return refreshUWL
		}

		if ewl.host == "" {
			if wlp, ok := ipWLMap[ewl.key]; ok && !wlp.alive {
				log.WithFields(log.Fields{
					"ip": ewl.key, "workload": container.ShortContainerId(ewl.wl),
				}).Debug("remove ip-workload map")
				delete(ipWLMap, ewl.key)
				refreshUWL = true
			}
		} else if cache, ok := hostCacheMap[ewl.host]; ok {
			if ewl.isip {
				if wlp, ok := cache.ipWLMap[ewl.key]; ok && !wlp.alive {
					log.WithFields(log.Fields{
						"ip": ewl.key, "workload": container.ShortContainerId(ewl.wl),
					}).Debug("remove host-scope ip-workload map")
					delete(cache.ipWLMap, ewl.key)
				}
			} else {
				if wlp, ok := cache.portWLMap[ewl.key]; ok && !wlp.alive {
					log.WithFields(log.Fields{
						"proto": ewl.key, "workload": container.ShortContainerId(ewl.wl),
					}).Debug("remove host-scope port-workload map")
					delete(cache.portWLMap, ewl.key)
				}
			}
		}
	}

	wlEphemeral = nil
	return refreshUWL
}

func addrWorkloadStop(id string, param interface{}) {
	wl := param.(*workloadCache).workload

	if wl.ShareNetNS != "" {
		return
	}

	log.WithFields(log.Fields{"id": id, "name": wl.Name}).Debug()

	now := time.Now()

	// Because a pod is the minimum deployment entity, we mark the entry as not-alive if any
	// container in the pod stops.
	cacheMutexLock()
	defer cacheMutexUnlock()

	// Remove workload_ip-to-workload map
	for _, addrs := range wl.Ifaces {
		for _, addr := range addrs {
			switch addr.Scope {
			case share.CLUSIPAddrScopeGlobal:
				// Keep the mapping for a while to identify remaining connection report
				key := addr.IPNet.IP.String()
				if wlp, ok := ipWLMap[key]; ok && wlp.alive && wlp.wlID == wl.ID {
					log.WithFields(log.Fields{
						"ip": key, "workload": container.ShortContainerId(wl.ID),
					}).Debug("delay remove ip-workload map")

					wlp.alive = false
					wlEphemeral = append(wlEphemeral, &workloadEphemeral{
						stop: now, key: key, wl: id,
					})
					// delete(ipWLMap, key)
				}
			}
		}
	}

	if cache, ok := hostCacheMap[wl.HostID]; ok {
		// Remove host's port-to-workload map
		for key, wlp := range cache.portWLMap {
			if wlp.wlID == wl.ID && wlp.alive {
				log.WithFields(log.Fields{
					"proto": key, "workload": container.ShortContainerId(wl.ID),
				}).Debug("delay remove host-scope port-workload map")

				// Keep the mapping for a while to identify remaining connection report
				wlp.alive = false
				wlEphemeral = append(wlEphemeral, &workloadEphemeral{
					stop: now, key: key, wl: id, host: wl.HostID,
				})
				// delete(cache.portWLMap, key)
			}
		}

		// Update workload host-scope ip-to-workload map
		for _, addrs := range wl.Ifaces {
			for _, addr := range addrs {
				switch addr.Scope {
				case share.CLUSIPAddrScopeLocalhost:
					// Keep the mapping for a while to identify remaining connection report
					key := addr.IPNet.IP.String()
					if wlp, ok := cache.ipWLMap[key]; ok && wlp.alive && wlp.wlID == wl.ID {
						log.WithFields(log.Fields{
							"ip": key, "workload": container.ShortContainerId(wl.ID),
						}).Debug("delay remove host-scope ip-workload map")

						wlp.alive = false
						wlEphemeral = append(wlEphemeral, &workloadEphemeral{
							stop: now, key: key, wl: id, host: wl.HostID, isip: true,
						})
						// delete(cache.ipWLMap, key)
					}

					// Local subnet Set entry is not removed, (we need rebuild the Set to do so).
					// A container host should not have a lot of local subnets
				}
			}
		}
	}
}

func addrWorkloadAdd(id string, param interface{}) {
	wl := param.(*workloadCache).workload

	// The container can share the network namespace with another container. This is normally
	// caused by POD deployment, and POD is considered as the minimum entity to deploy conatnienrs,
	// which means, there is no such case that some containers in a POD are removed but other
	// containers keeps running. They should come and go together.
	// --- so we map IP/port to POD's (parent) ID here.
	if wl.ShareNetNS != "" {
		return
	}

	log.WithFields(log.Fields{"id": id, "name": wl.Name}).Debug()

	cacheMutexLock()
	defer cacheMutexUnlock()

	// Update workload_ip-to-workload map
	host_mode := (wl.NetworkMode == "host")
	hostip_reused := false
	for _, addrs := range wl.Ifaces {
		for _, addr := range addrs {
			switch addr.Scope {
			case share.CLUSIPAddrScopeGlobal:
				key := addr.IPNet.IP.String()
				// No need to remove ephemeral entry
				if wlp, ok := ipWLMap[key]; ok {
					wlp.wlID = id
					wlp.ipnet = addr.IPNet
					wlp.alive = true
					wlp.managed = true
					//workload's hostname from agent is more accurate
					if wlp.node != wl.HostName {
						wlp.node = wl.HostName
					}
				} else {
					ipWLMap[key] = &workloadDigest{wlID: id, ipnet: addr.IPNet, alive: true, managed: true, node: wl.HostName}
				}

				//NVSHAS-8155, previous host ip reused by POD, remove it from iphost cache
				if !host_mode { //NVSHAS-8249, only for non-hostmode wl
					if _, ok1 := ipHostMap[key]; ok1 {
						delete(ipHostMap, key)
						hostip_reused = true
						log.WithFields(log.Fields{
							"ip": key, "workload": container.ShortContainerId(wl.ID),
						}).Debug("Remove host ip reused by workload")
					}
				}
				log.WithFields(log.Fields{
					"ip": key, "workload": container.ShortContainerId(wl.ID),
				}).Debug("ip-workload map")

				updateInternalIPNet(&addr.IPNet, addr.Scope, true)
			}
		}
	}

	if hostip_reused {
		refreshInternalIPNet()
	}

	if cache, ok := hostCacheMap[wl.HostID]; ok {
		// Update host's port-to-workload map
		for _, port := range wl.Ports {
			key := mappedPortKey(port.IPProto, port.HostPort)
			// No need to remove ephemeral entry
			cache.portWLMap[key] = &workloadDigest{wlID: id, port: port.Port, alive: true}

			log.WithFields(log.Fields{
				"host": cache.host.Name, "proto": key, "workload": container.ShortContainerId(wl.ID),
			}).Debug("host-scope port-workload map")
		}

		// Update workload host-scope ip-to-workload map
		for _, addrs := range wl.Ifaces {
			for _, addr := range addrs {
				switch addr.Scope {
				case share.CLUSIPAddrScopeLocalhost:
					key := addr.IPNet.IP.String()
					// No need to remove ephemeral entry
					if wlp, ok := cache.ipWLMap[key]; ok {
						wlp.wlID = id
						wlp.ipnet = addr.IPNet
						wlp.alive = true
						wlp.managed = true
					} else {
						cache.ipWLMap[key] = &workloadDigest{wlID: id, ipnet: addr.IPNet, alive: true, managed: true}
					}

					log.WithFields(log.Fields{
						"host": cache.host.Name, "ip": key, "workload": container.ShortContainerId(wl.ID),
					}).Debug("host-scope ip-workload map")

					// Host scope subnet doesn't need to be broadcasted.
					// updateInternalIPNet(&addr.IPNet, addr.Scope)

					subnet := utils.IPNet2Subnet(&addr.IPNet).String()
					cache.wlSubnets.Add(subnet)
				}
			}
		}
	}
}

func addrOrchWorkloadStop(ipnet *net.IPNet) {
	key := ipnet.IP.String()

	now := time.Now()

	cacheMutexLock()
	defer cacheMutexUnlock()

	if wlp, ok := ipWLMap[key]; ok && wlp.alive {
		log.WithFields(log.Fields{"ip": key}).Debug("delay remove ip-workload map")

		wlp.alive = false
		wlEphemeral = append(wlEphemeral, &workloadEphemeral{
			stop: now, key: key, wl: wlp.wlID,
		})
	}
}

// Add IP-2-workload map for workloads reported by orchestration
func addrOrchWorkloadAdd(ipnet *net.IPNet, nodename string) {
	key := ipnet.IP.String()

	cacheMutexLock()
	defer cacheMutexUnlock()

	// No need to remove ephemeral entry
	if wlp, ok := ipWLMap[key]; ok {
		if !wlp.managed {
			wlp.ipnet = *ipnet
		}
		wlp.alive = true
		wlp.orched = true
		if wlp.node == "" {
			wlp.node = nodename
		}
	} else {
		ipWLMap[key] = &workloadDigest{ipnet: *ipnet, alive: true, orched: true, node: nodename}
	}

	log.WithFields(log.Fields{"ip": key}).Debug("ip-workload map")

	updateInternalIPNet(ipnet, share.CLUSIPAddrScopeGlobal, true)
}

func setServiceAccount(node, wlID, wlName string, wlCache *workloadCache) {
	if localDev.Host.Platform != share.PlatformKubernetes {
		return
	}
	if wlCache.serviceAccount == "" {
		var podSAMap map[string]string
		if podSAMap = nodePodSAMap[node]; podSAMap == nil {
			// if k8s node is named as IP, its node entry in nodePodSAMap has key as IP.
			// because param(node) could be hostname, we try IP again when we cannot find the node entry using param(node)
			if hostCache, ok := k8sHostInfoMap[node]; ok && hostCache.k8sNodeName != "" {
				podSAMap = nodePodSAMap[hostCache.k8sNodeName]
			}
		}
		if podSAMap != nil {
			if sa, ok := podSAMap[wlID]; ok {
				wlCache.serviceAccount = sa
				delete(podSAMap, wlID)
			}
		}
	}
}

func appendProbeCmds(cmds []string) (bool, string, string, string) {
	if len(cmds) > 0 {
		exe := filepath.Base(cmds[0])
		path := filepath.Clean(cmds[0])
		if exe == path {
			// it does not have a complete path
			path = "*"
		}
		cmd := strings.TrimSuffix(strings.Join(cmds, ","), ",")
		return true, exe, path, cmd
	}
	return false, "", "", ""
}

func appendProbeSubCmds(cmds []string) []*k8sProbeCmd {
	var subcmds []*k8sProbeCmd
	if len(cmds) > 0 {
		line := strings.Join(cmds, " ")
		items := strings.Split(line, " exec ")
		for i, item := range items {
			if i == 0 {
				continue
			}
			if index := strings.Index(item, ";"); index > 0 {
				if ok, app, path, cmdline := appendProbeCmds(strings.Split(item[0:index], " ")); ok {
					p := &k8sProbeCmd{app: app, path: path, cmds: []string{cmdline}}
					subcmds = append(subcmds, p)
				}
			}
		}
	}
	return subcmds
}

func mergeProbeCommands(cmds [][]string) []k8sProbeCmd {
	pp := make(map[string]*k8sProbeCmd)
	for _, cmd := range cmds {
		if ok, app, path, cmdline := appendProbeCmds(cmd); ok {
			if p, ok := pp[app]; ok {
				p.path = "*"
				p.cmds = append(p.cmds, cmdline)
			} else {
				pp[app] = &k8sProbeCmd{app: app, path: path, cmds: []string{cmdline}}
			}

			if app == "sh" || app == "bash" || app == "ash" {
				if pcmds := appendProbeSubCmds(cmd); pcmds != nil {
					for _, pcmd := range pcmds {
						if p, ok := pp[pcmd.app]; ok {
							p.path = "*"
							p.cmds = append(p.cmds, pcmd.cmds...)
						} else {
							pp[pcmd.app] = pcmd
						}
					}
				}
			}
		}
	}

	var probes []k8sProbeCmd
	for _, p := range pp {
		probes = append(probes, *p)
	}
	return probes
}

func addK8sPodEvent(pod resource.Pod, probeCmds [][]string) {
	probes := mergeProbeCommands(probeCmds)
	groupName := fmt.Sprintf("nv.%s.%s", pod.Name, pod.Domain)
	if svc := global.ORCH.GetServiceFromPodLabels(pod.Domain, pod.Name, pod.Node, pod.Labels); svc != nil {
		groupName = api.LearnedGroupPrefix + utils.NormalizeForURL(utils.MakeServiceName(svc.Domain, svc.Name))
	}

	//log.WithFields(log.Fields{"Name": pod.Name, "groupName": groupName, "probes": probes}).Debug()
	var name_alt string
	if pos := strings.LastIndex(pod.Name, "-"); pos != -1 {
		name_alt = fmt.Sprintf("nv.%s.%s", pod.Name[:pos], pod.Domain)
	}

	p := &k8sPodEvent{
		pod:      pod,
		group:    groupName,                 // group name
		groupAlt: name_alt,                  // a likely group name
		probes:   probes,                    // probes
		cleanAt:  time.Now().Unix() + 60*30, // expired after 30 minutes
	}

	cacheMutexLock()
	defer cacheMutexUnlock()
	var bFound bool
	for group := range groupCacheMap {
		if group == p.group || group == p.groupAlt {
			log.WithFields(log.Fields{"group": group}).Debug()
			bFound = true
			addK8sProbeApps(group, p.probes)
			// delete(cacher.k8sPodEvents, p.group)
			break
		}
	}

	if !bFound {
		cacher.k8sPodEvents[p.group] = p
	}
}

// The cacheMutex is locked by callers
func updateK8sPodEvent(group, podname, domain, id string) bool {
	var bFound, bPrivileged bool
	now := time.Now().Unix()
	for name, p := range cacher.k8sPodEvents {
		if group == p.group || group == p.groupAlt {
			addK8sProbeApps(group, p.probes)
			for _, c := range p.pod.Containers {
				if c.Id == id {
					bFound = true
					bPrivileged = c.Privileged
					break
				}
			}
		}
		if now > p.cleanAt {
			log.WithFields(log.Fields{"name": name}).Debug("Clean-up")
			delete(cacher.k8sPodEvents, name)
		}

		if bFound {
			break
		}
	}

	if !bFound {
		if obj, err := global.ORCH.GetResource(resource.RscTypePod, domain, podname); err != nil {
			log.WithFields(log.Fields{"error": err, "group": group, "pod": podname, "domain": domain}).Error("get ressource")
			return bPrivileged
		} else {
			var probeCmds [][]string
			pod := obj.(*resource.Pod)
			for _, c := range pod.Containers {
				if len(c.LivenessCmds) > 0 {
					probeCmds = append(probeCmds, c.LivenessCmds)
				}
				if len(c.ReadinessCmds) > 0 {
					probeCmds = append(probeCmds, c.ReadinessCmds)
				}
				if c.Id == id {
					bPrivileged = c.Privileged
				}
			}

			if len(probeCmds) > 0 {
				probes := mergeProbeCommands(probeCmds)
				if len(probes) > 0 {
					// log.WithFields(log.Fields{"probes": probes, "group": group, "pod": podname, "domain": domain}).Debug()
					addK8sProbeApps(group, probes)
				}
			}
		}
	}
	return bPrivileged
}

func workloadUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	log.WithFields(log.Fields{"type": cluster.ClusterNotifyName[nType], "key": key}).Debug("")

	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		var wl share.CLUSWorkload
		_ = json.Unmarshal(value, &wl)

		// Check if it's NeuVector containers first
		if wl.PlatformRole == container.PlatformContainerNeuVector {
			// STOP event is always sent. In case we miss it, we should handle the key deletion
			if wl.Running {
				log.WithFields(log.Fields{"NVcontainer": wl.Name}).Info("Add")
				wlCache := &workloadCache{workload: &wl}
				if pod, ok := wl.Labels[container.KubeKeyPodName]; ok {
					wlCache.podName = pod
				}
				cacheMutexLock()
				addrDeviceAdd(wl.ID, wl.Ifaces)
				nvwlCacheMap[wl.ID] = wlCache
				cacheMutexUnlock()

				// Remove workload:x.x.x.x from the graph
				connectWorkloadAdd(wl.ID, wlCache)
			} else {
				log.WithFields(log.Fields{"NVcontainer": wl.Name}).Info("Delete")
				cacheMutexLock()
				addrDeviceDelete(wl.ID, wl.Ifaces)
				delete(nvwlCacheMap, wl.ID)
				cacheMutexUnlock()
			}
			return
		}

		// Update workload cache
		var wlCache *workloadCache
		var ok bool
		var newWorkload, started, stopped, quarantined bool
		var workloadAgentChange bool

		cacheMutexLock()
		if wlCache, ok = wlCacheMap[wl.ID]; ok && !isDummyWorkloadCache(wlCache) {
			oldRunning := wlCache.workload.Running
			oldQuar := wlCache.workload.Quarantine
			oldSvc := wlCache.workload.Service

			if !reflect.DeepEqual(wlCache.workload.Ifaces, wl.Ifaces) ||
				!reflect.DeepEqual(wlCache.workload.Ports, wl.Ports) {
				log.WithFields(log.Fields{
					"workload": container.ShortContainerId(wl.ID),
				}).Debug("intf/ports changed")
				defer scheduleIPPolicyCalculation(true)
			}

			if wlCache.workload.AgentID != wl.AgentID {
				workloadAgentChange = true
			}

			setServiceAccount(wl.HostName, wl.ID, wl.Name, wlCache)
			wl.Privileged = wlCache.workload.Privileged // pre-existing
			wlCache.workload = &wl
			wlCache.state = ""

			//in upgrade's case this can happend
			if wl.PlatformRole != "" && wlCache.platformRole == "" {
				wlCache.platformRole = api.PlatformContainerCore
			} else if wl.PlatformRole == "" && wlCache.platformRole != "" {
				wlCache.platformRole = ""
			}

			if wl.Running {
				if !oldRunning {
					wlCache.serviceName = utils.NormalizeForURL(wl.Service)
					wlCache.learnedGroupName = makeLearnedGroupName(wlCache.serviceName)

					started = true
				} else if oldSvc != wl.Service {
					// If service name is changed, it must be that the enforcer has been replaced,
					// we need create the new learned group.
					wlCache.serviceName = utils.NormalizeForURL(wl.Service)
					wlCache.learnedGroupName = makeLearnedGroupName(wlCache.serviceName)
					oldSvcName := utils.NormalizeForURL(oldSvc)
					wlCache.svcChanged = makeLearnedGroupName(oldSvcName)

					started = true
				}
			} else {
				if oldRunning {
					stopped = true
				}
			}
			if wl.Quarantine && !oldQuar {
				quarantined = true
			}
		} else {
			// We get here either the workload is not in the cache or there is a dummy record,
			// for example, added by handling uniconf or by the child
			if wlCache == nil {
				// New workload
				wlCache = initWorkloadCache()
				wlCacheMap[wl.ID] = wlCache
			}

			setServiceAccount(wl.HostName, wl.ID, wl.Name, wlCache)

			wlCache.workload = &wl

			newWorkload = true
			if wl.Running {
				wlCache.serviceName = utils.NormalizeForURL(wl.Service)
				wlCache.learnedGroupName = makeLearnedGroupName(wlCache.serviceName)

				started = true
			}
			if wl.Quarantine {
				quarantined = true
			}

			// Update parent's children list. Create a dummy parent if not exist
			if wl.ShareNetNS != "" {
				if parent, ok := wlCacheMap[wl.ShareNetNS]; !ok {
					wlParent := initWorkloadCache()
					wlParent.serviceAccount = wlCache.serviceAccount
					wlCacheMap[wl.ShareNetNS] = wlParent
					wlCacheMap[wl.ShareNetNS].children.Add(wl.ID)
				} else {
					parent.serviceAccount = wlCache.serviceAccount
					parent.children.Add(wl.ID)
				}
			}
		}

		// Here is why workload must carry HostID, instead of looking up by agent.
		// When controller starts up, there is no guarantee which KV is read first. If
		// workload's agent has not been loaded, the workload has no chance to be added
		// into host cache if the host is looked up by agent.

		// Update host cache
		if _, ok := hostCacheMap[wl.HostID]; !ok {
			// Create a faked host
			hostCacheMap[wl.HostID] = initHostCache(wl.HostID)
			log.WithFields(log.Fields{"host": wl.HostID}).Debug("Create dummy host")
		}

		// Update group cache
		if isLeader() {
			if gc, ok := groupCacheMap[wlCache.learnedGroupName]; ok && !isDummyGroupCache(gc) {
				if gc.group.CapIntcp != wl.CapIntcp || gc.group.PlatformRole != wl.PlatformRole {
					// This happens when agent env. var. changes workload role
					log.WithFields(log.Fields{"group": wlCache.learnedGroupName}).Debug("Fix group fields")
					gc.group.CapIntcp = wl.CapIntcp
					gc.group.PlatformRole = wl.PlatformRole
					_ = clusHelper.PutGroup(gc.group, false)
				}
			}
		}
		cacheMutexUnlock()

		// Trigger ADD before anything
		if newWorkload {
			evhdls.Trigger(EV_WORKLOAD_ADD, wl.ID, wlCache)
		}

		// Because IP can change in workload update event, these have to be called every time.
		if wl.Running {
			addrWorkloadAdd(wl.ID, wlCache)
		}
		//NVSHAS-7433, it is possible newly added short-lived workload is not running
		//so we need to delete Workload:IP and its related policy
		if wl.Running || newWorkload {
			connectWorkloadAdd(wl.ID, wlCache)
		}
		// workload cache change are synchronized in ObjectUpdateHandler(), so
		// reading wlCache doesn't have to be protected by cacheMutex
		if started {
			evhdls.Trigger(EV_WORKLOAD_START, wl.ID, wlCache)
		}
		if stopped {
			evhdls.Trigger(EV_WORKLOAD_STOP, wl.ID, wlCache)
		}
		if quarantined {
			evhdls.Trigger(EV_WORKLOAD_QUARANTINE, wl.ID, wlCache)
		}
		if workloadAgentChange {
			evhdls.Trigger(EV_WORKLOAD_AGENT_CHANGE, wl.ID, wlCache)
		}

	case cluster.ClusterNotifyDelete:
		id := share.CLUSWorkloadKey2ID(key)

		// Check if it's NeuVector containers first
		cacheMutexLock()
		if addrDeviceDeleteByID(id) {
			cacheMutexUnlock()
			return
		}
		cacheMutexUnlock()

		// Update workload cache
		var wlCache *workloadCache
		var ok bool

		cacheMutexLock()

		if wlCache, ok = wlCacheMap[id]; ok {
			delete(wlCacheMap, id)

			// Update parent's children list.
			if wlCache.workload.ShareNetNS != "" {
				if parent, ok := wlCacheMap[wlCache.workload.ShareNetNS]; ok {
					parent.children.Remove(id)
				}
			}
		}

		cacheMutexUnlock()

		if wlCache != nil {
			evhdls.Trigger(EV_WORKLOAD_DELETE, id, wlCache)
		}

		// cleanup records in database
		if err := db.DeleteAssetByID(db.AssetWorkload, id); err != nil {
			log.WithFields(log.Fields{"err": err, "id": id}).Error("Delete asset in db failed.")
		}
	}
}

func networkEPUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	log.WithFields(log.Fields{"type": cluster.ClusterNotifyName[nType], "key": key}).Debug("")

	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		var nep share.CLUSNetworkEP
		_ = json.Unmarshal(value, &nep)
		addToNetworkEPGroup(&nep)
	case cluster.ClusterNotifyDelete:
		id := share.CLUSNetworkEPKey2ID(key)
		removeFromNetworkEPGroup(id)
	}
}

func attrWorkloadAdd(id string, param interface{}) {
	wlc := param.(*workloadCache)
	wl := wlc.workload

	wlc.displayName, wlc.podName = getWorkloadDisplayName(wl, wl.ShareNetNS)

	if wl.PlatformRole != "" {
		wlc.platformRole = api.PlatformContainerCore
	}
}

func ObjectUpdateHandler(nType cluster.ClusterNotifyType, key string, value []byte, modifyIdx uint64) {
	object := share.CLUSObjectKey2Object(key)
	switch object {
	case "host":
		hostUpdate(nType, key, value)
	case "agent":
		agentUpdate(nType, key, value)
	case "controller":
		controllerUpdate(nType, key, value)
	case "workload":
		workloadUpdate(nType, key, value)
	case "networkep":
		networkEPUpdate(nType, key, value)
	case "threatlog":
		threatLogUpdate(nType, key, value, modifyIdx)
	case "eventlog":
		eventLogUpdate(nType, key, value, modifyIdx)
	case "incidentlog":
		incidentLogUpdate(nType, key, value, modifyIdx)
	case "auditlog":
		auditLogUpdate(nType, key, value, modifyIdx)
	case "connect": // obsolete. Use grpc instead
		connectUpdate(nType, key, value, modifyIdx)
	case "config":
		configUpdate(nType, key, value, modifyIdx)
	case "uniconf":
		uniconfUpdate(nType, key, value)
	case "cert":
		certObjectUpdate(nType, key, value)
	case "throttled", "telemetry":
	default:
		log.WithFields(log.Fields{"key": key}).Error("Not supported")
	}
}

func configUpdate(nType cluster.ClusterNotifyType, key string, value []byte, modifyIdx uint64) {
	value, _, _ = kv.UpgradeAndConvert(key, value)

	config := share.CLUSConfigKey2Config(key)

	if backupKvStores != nil {
		if backupKvStoreEPs.Contains(config) {
			backupKvStores.UpdateBackupKvStore(key, value, nType == cluster.ClusterNotifyDelete)
		}
	}

	switch config {
	case share.CFGEndpointSystem:
		systemConfigUpdate(nType, key, value)
	case share.CFGEndpointGroup:
		groupConfigUpdate(nType, key, value)
	case share.CFGEndpointPolicy:
		policyConfigUpdate(nType, key, value)
	case share.CFGEndpointScan:
		scanConfigUpdate(nType, key, value)
	case share.CFGEndpointLicense:
		licenseConfigUpdate(nType, key, value)
	case share.CFGEndpointResponseRule:
		responseRuleConfigUpdate(nType, key, value)
	case share.CFGEndpointProcessProfile:
		profileConfigUpdate(nType, key, value)
	case share.CFGEndpointRegistry:
		scan.RegistryConfigHandler(nType, key, value)
	case share.CFGEndpointAdmissionControl:
		admissionConfigUpdate(nType, key, value)
	case share.CFGEndpointCrd:
		crdConfigUpdate(nType, key, value)
	case share.CFGEndpointFileMonitor:
		fsmonProfileConfigUpdate(nType, key, value)
	case share.CFGEndpointFileAccessRule:
		fileAccessRuleConfigUpdate(nType, key, value)
	case share.CFGEndpointFederation:
		fedConfigUpdate(nType, key, value)
	case share.CFGEndpointDlpRule:
		dlpRuleConfigUpdate(nType, key, value)
	case share.CFGEndpointDlpGroup:
		dlpGroupConfigUpdate(nType, key, value)
	case share.CFGEndpointWafRule:
		wafRuleConfigUpdate(nType, key, value)
	case share.CFGEndpointWafGroup:
		wafGroupConfigUpdate(nType, key, value)
	case share.CFGEndpointCompliance:
		complianceConfigUpdate(nType, key, value)
	case share.CFGEndpointVulnerability:
		vulnerabilityConfigUpdate(nType, key, value)
	case share.CFGEndpointDomain:
		domainConfigUpdate(nType, key, value)
	case share.CFGEndpointUserRole:
		userRoleConfigUpdate(nType, key, value)
	case share.CFGEndpointPwdProfile:
		pwdProfileConfigUpdate(nType, key, value)
	case share.CFGEndpointQuerySession:
		querySessionRequest(nType, key, value)
	}

	// Only the lead run backup, because the typical use case for backup is to save config
	// on persistent storage. If all controllers backup, they overwrite the same file.
	if isLeader() {
		var subKey string
		if config == share.CFGEndpointFederation {
			subKey = share.CLUSKeyNthToken(key, 3)
			if subKey != share.CLUSFedClustersStatusSubKey {
				cfgHelper.NotifyConfigChange(config)
			}
		} else {
			cfgHelper.NotifyConfigChange(config)
		}
	}
}

func registerEventHandlers() {
	evhdls = make(map[int][]eventHandlerFunc)

	evhdls.Register(EV_WORKLOAD_ADD, []eventHandlerFunc{
		attrWorkloadAdd,
	})
	evhdls.Register(EV_WORKLOAD_DELETE, []eventHandlerFunc{
		hostWorkloadDelete,
		addrWorkloadStop,
		uniconfWorkloadDelete,
		connectWorkloadDelete,
		groupWorkloadLeave,
	})
	evhdls.Register(EV_WORKLOAD_START, []eventHandlerFunc{
		hostWorkloadStart,
		groupWorkloadJoin,
		scanWorkloadAdd,
	})
	evhdls.Register(EV_WORKLOAD_STOP, []eventHandlerFunc{
		hostWorkloadStop,
		addrWorkloadStop,
		connectWorkloadDelete,
		groupWorkloadLeave,
		scanWorkloadDelete,
	})
	/*
		evhdls.Register(EV_WORKLOAD_QUARANTINE, []eventHandlerFunc{
			// Comment out, keep the existing links.
			// connectWorkloadDeleteLink,
		})
	*/
	evhdls.Register(EV_HOST_ADD, []eventHandlerFunc{
		connectHostAdd,
	})
	evhdls.Register(EV_HOST_DELETE, []eventHandlerFunc{
		connectHostDelete,
		scanHostDelete,
		benchHostDelete,
		nodeLeaveDispatcher,
	})
	evhdls.Register(EV_CONTROLLER_ADD, []eventHandlerFunc{
		connectControllerAdd,
	})
	evhdls.Register(EV_CONTROLLER_DELETE, []eventHandlerFunc{
		uniconfControllerDelete,
	})
	evhdls.Register(EV_AGENT_ADD, []eventHandlerFunc{
		connectAgentAdd,
		scanAgentAdd,
		benchAgentOnline,
	})
	evhdls.Register(EV_AGENT_DELETE, []eventHandlerFunc{
		uniconfAgentDelete,
		scanAgentDelete,
	})
	evhdls.Register(EV_AGENT_ONLINE, []eventHandlerFunc{
		rpcAgentOnline,
	})
	evhdls.Register(EV_AGENT_OFFLINE, []eventHandlerFunc{
		rpcAgentOffline,
	})
	evhdls.Register(EV_GROUP_ADD, []eventHandlerFunc{
		connectGroupAdd,
		automodeGroupAdd,
	})
	evhdls.Register(EV_GROUP_DELETE, []eventHandlerFunc{
		connectGroupDelete,
		customGroupDelete,
		automodeGroupDelete,
	})
	evhdls.Register(EV_WORKLOAD_AGENT_CHANGE, []eventHandlerFunc{
		scanWorkloadAgentChange,
	})
}

// With cacheMutex hold
func deleteAgentFromCache(ac *agentCache) {
	hostID := ac.agent.HostID
	delete(agentCacheMap, ac.agent.ID)

	// Update host cache. If this is the last agent, remove the host.
	if hostID == "" {
		return
	}

	if cache, ok := hostCacheMap[hostID]; ok {
		cache.agents.Remove(ac.agent.ID)
		if cache.agents.Cardinality() == 0 {
			scheduleHostRemoval(cache)
		}
	}

	/* Not to remove workload, the caller should explicitly remove workload key if needed,
	   so we have one place to decide if workload should be removed or not.
	*/
}

func deleteControllerFromCache(cc *ctrlCache) {
	delete(ctrlCacheMap, cc.ctrl.ID)

}

func logAgentEvent(ev share.TLogEvent, agent *share.CLUSAgent, msg string) {
	if !isLeader() {
		return
	}
	clog := share.CLUSEventLog{
		Event:     ev,
		HostID:    agent.HostID,
		HostName:  agent.HostName,
		AgentID:   agent.ID,
		AgentName: agent.Name,
		Msg:       msg,
	}

	clog.ReportedAt = time.Now().UTC()

	_ = cctx.EvQueue.Append(&clog)
}

func logControllerEvent(ev share.TLogEvent, ctrl *share.CLUSController, msg string) {
	if !isLeader() {
		return
	}
	clog := share.CLUSEventLog{
		Event:          ev,
		HostID:         ctrl.HostID,
		HostName:       ctrl.HostName,
		ControllerID:   ctrl.ID,
		ControllerName: ctrl.Name,
		Msg:            msg,
	}
	clog.ReportedAt = time.Now().UTC()

	_ = cctx.EvQueue.Append(&clog)
}

func markWorkloadState(workloads utils.Set, state string) {
	for m := range workloads.Iter() {
		if cache, ok := wlCacheMap[m.(string)]; ok {
			cache.state = state
		}
	}
}

func getEffectiveSubnets() map[string]share.CLUSSubnet {
	retMap := make(map[string]share.CLUSSubnet)
	for key, subnet := range cachedInternalSubnets {
		retMap[key] = subnet
	}
	for _, subnet := range systemConfigCache.InternalSubnets {
		if _, ipnet, err := net.ParseCIDR(subnet); err == nil {
			snet := share.CLUSSubnet{Subnet: *ipnet, Scope: share.CLUSIPAddrScopeGlobal}
			utils.MergeSubnet(retMap, snet)
		}
	}
	return retMap
}

func getEffectiveSpecialSubnets() map[string]share.CLUSSpecSubnet {
	retMap := make(map[string]share.CLUSSpecSubnet)
	for key, subnet := range cachedSpecialSubnets {
		retMap[key] = subnet
	}
	return retMap
}

// This is called with cacheMutex
func putSpecialIPNetToCluseter(checkDiff bool) {
	newEffectiveSpecial := getEffectiveSpecialSubnets()
	if checkDiff && reflect.DeepEqual(newEffectiveSpecial, effectiveSpecialSubnets) {
		return
	}

	effectiveSpecialSubnets = newEffectiveSpecial

	if !isLeader() {
		return
	}
	var i int
	subnets := make([]share.CLUSSpecSubnet, len(effectiveSpecialSubnets))
	for _, subnet := range effectiveSpecialSubnets {
		subnets[i] = subnet
		i++
	}

	if i == 0 {
		return
	}

	key := share.CLUSInternalIPNetsKey(share.SpecialIPNetDefaultName)
	value, _ := json.Marshal(subnets)
	zb := utils.GzipBytes(value)
	if err := cluster.PutBinary(key, zb); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in putting to cluster")
	}
}

// for rolling upgrade case, especially with mixed version controller,
// old still use 16bit loose factor for mask while new use 8bit loose
// factor, here we push internal subnet to enforcer after lead change
func PutInternalIPNetToCluseterUpgrade() {
	log.Debug("")
	cacheMutexLock()
	putInternalIPNetToCluseter(false)
	putSpecialIPNetToCluseter(false)
	cacheMutexUnlock()
}

// This is called with cacheMutex
func putInternalIPNetToCluseter(checkDiff bool) {
	newEffective := getEffectiveSubnets()
	if checkDiff && reflect.DeepEqual(newEffective, effectiveInternalSubnets) {
		return
	}

	effectiveInternalSubnets = newEffective

	if !isLeader() {
		return
	}
	var i int
	subnets := make([]share.CLUSSubnet, len(effectiveInternalSubnets))
	for _, subnet := range effectiveInternalSubnets {
		subnets[i] = subnet
		i++
	}

	if i == 0 {
		return
	}

	key := share.CLUSInternalIPNetsKey(share.InternalIPNetDefaultName)
	value, _ := json.Marshal(subnets)
	zb := utils.GzipBytes(value)
	if err := cluster.PutBinary(key, zb); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in putting to cluster")
	}
}

// Return if entry is added to the map
func addInternalIPNet(subnets map[string]share.CLUSSubnet, ipnet *net.IPNet, scope string, loose bool) bool {
	var subnet *net.IPNet
	if loose {
		subnet = utils.IPNet2SubnetLoose(ipnet, scope)
	} else {
		subnet = utils.IPNet2Subnet(ipnet)
	}
	if _, ok := subnets[subnet.String()]; !ok {
		snet := share.CLUSSubnet{Subnet: *subnet, Scope: scope}
		return utils.MergeSubnet(subnets, snet)
	}
	return false
}

func addSpecialInternalIPNet(subnets map[string]share.CLUSSpecSubnet, ipnet *net.IPNet, scope, iptype string, loose bool) bool {
	var subnet *net.IPNet
	if loose {
		subnet = utils.IPNet2SubnetLoose(ipnet, scope)
	} else {
		subnet = utils.IPNet2Subnet(ipnet)
	}
	if _, ok := subnets[subnet.String()]; !ok {
		snet := share.CLUSSubnet{Subnet: *subnet, Scope: scope}
		return utils.MergeSpecialSubnet(subnets, snet, iptype)
	}
	return false
}

// This is called with cacheMutex
func updateInternalIPNet(ipnet *net.IPNet, scope string, loose bool) {
	if addInternalIPNet(cachedInternalSubnets, ipnet, scope, loose) {
		putInternalIPNetToCluseter(true)
	}
	specChg := false
	isdevip := false

	if _, ok := tunnelHostMap[ipnet.IP.String()]; ok {
		tun_ipnet := &net.IPNet{IP: ipnet.IP, Mask: net.CIDRMask(32, 32)}
		log.WithFields(log.Fields{"ip": tun_ipnet.IP.String(), "mask": tun_ipnet.Mask.String()}).Debug("tunnel subnet")
		if addSpecialInternalIPNet(cachedSpecialSubnets, tun_ipnet, scope, share.SpecInternalTunnelIP, loose) {
			specChg = true
		}
	}
	if _, ok := addr2SvcMap[ipnet.IP.String()]; ok {
		svc_ipnet := &net.IPNet{IP: ipnet.IP, Mask: net.CIDRMask(32, 32)}
		log.WithFields(log.Fields{"ip": svc_ipnet.IP.String(), "mask": svc_ipnet.Mask.String()}).Debug("svcip subnet")
		if addSpecialInternalIPNet(cachedSpecialSubnets, svc_ipnet, scope, share.SpecInternalSvcIP, loose) {
			specChg = true
		}
		for _, extip := range addr2ExtIpMap[ipnet.IP.String()] {
			ext_ipnet := &net.IPNet{IP: extip, Mask: net.CIDRMask(32, 32)}
			log.WithFields(log.Fields{"extip": ext_ipnet.IP.String(), "mask": ext_ipnet.Mask.String()}).Debug("extip subnet")
			if addSpecialInternalIPNet(cachedSpecialSubnets, ext_ipnet, share.CLUSIPAddrScopeGlobal, share.SpecInternalExtIP, false) {
				specChg = true
			}
		}
	}
	if _, ok := ipHostMap[ipnet.IP.String()]; ok {
		host_ipnet := &net.IPNet{IP: ipnet.IP, Mask: net.CIDRMask(32, 32)}
		log.WithFields(log.Fields{"ip": host_ipnet.IP.String(), "mask": host_ipnet.Mask.String()}).Debug("host-ip subnet")
		if addSpecialInternalIPNet(cachedSpecialSubnets, host_ipnet, scope, share.SpecInternalHostIP, loose) {
			specChg = true
		}
	}

	if _, ok := ipDevMap[ipnet.IP.String()]; ok {
		isdevip = true
		dev_ipnet := &net.IPNet{IP: ipnet.IP, Mask: net.CIDRMask(32, 32)}
		log.WithFields(log.Fields{"ip": dev_ipnet.IP.String(), "mask": dev_ipnet.Mask.String()}).Debug("dev-ip subnet")
		if addSpecialInternalIPNet(cachedSpecialSubnets, dev_ipnet, scope, share.SpecInternalDevIP, false) {
			specChg = true
		}
	}

	// Workload overlay/global address
	if !isdevip {
		if wlp, ok := ipWLMap[ipnet.IP.String()]; ok {
			if wlmanaged := isNodeManaged(wlp.node); !wlmanaged {
				uwl_ipnet := &net.IPNet{IP: wlp.ipnet.IP, Mask: net.CIDRMask(32, 32)}
				log.WithFields(log.Fields{"ip": uwl_ipnet.IP.String(), "mask": uwl_ipnet.Mask.String()}).Debug("unmanaged ip-workload map")
				if addSpecialInternalIPNet(cachedSpecialSubnets, uwl_ipnet, scope, share.SpecInternalUwlIP, false) {
					specChg = true
				}
			}
		}
	}

	if specChg {
		putSpecialIPNetToCluseter(true)
	}
}

// This is called with cacheMutex
/*
func delInternalIPNet(ipnet *net.IPNet) {
	subnet := utils.IPNet2Subnet(ipnet)
	key := subnet.String()
	if _, ok := cachedInternalSubnets[key]; ok {
		delete(cachedInternalSubnets, key)
		putInternalIPNetToCluseter()
	}
}
*/

// This is called with cacheMutex
func isNodeManaged(nodename string) bool {
	if nodename == "" {
		return true
	}
	for _, ac := range agentCacheMap {
		if ac.agent.HostName == nodename {
			return true
		}
	}
	return false
}

// This is called with cacheMutex
func refreshInternalIPNet() {
	newSubnets := make(map[string]share.CLUSSubnet)
	newSpecialSubnets := make(map[string]share.CLUSSpecSubnet)

	// Host address
	for _, hp := range ipHostMap {
		addInternalIPNet(newSubnets, &hp.ipnet, share.CLUSIPAddrScopeNAT, false)
		host_ipnet := &net.IPNet{IP: hp.ipnet.IP, Mask: net.CIDRMask(32, 32)}
		log.WithFields(log.Fields{"ip": host_ipnet.IP.String(), "mask": host_ipnet.Mask.String()}).Debug("host-ip subnet")
		addSpecialInternalIPNet(newSpecialSubnets, host_ipnet, share.CLUSIPAddrScopeNAT, share.SpecInternalHostIP, false)
	}

	for _, hc := range hostCacheMap {
		for _, ipnet := range hc.host.TunnelIP {
			addInternalIPNet(newSubnets, &ipnet, share.CLUSIPAddrScopeNAT, false)
			tun_ipnet := &net.IPNet{IP: ipnet.IP, Mask: net.CIDRMask(32, 32)}
			log.WithFields(log.Fields{"ip": tun_ipnet.IP.String(), "mask": tun_ipnet.Mask.String()}).Debug("tunnel subnet")
			addSpecialInternalIPNet(newSpecialSubnets, tun_ipnet, share.CLUSIPAddrScopeNAT, share.SpecInternalTunnelIP, false)
		}
	}

	// Workload overlay/global address
	for _, wlp := range ipWLMap {
		addInternalIPNet(newSubnets, &wlp.ipnet, share.CLUSIPAddrScopeGlobal, true)
		if _, ok := ipDevMap[wlp.ipnet.IP.String()]; ok {
			//device ip is not unmanaged
			continue
		}
		if wlmanaged := isNodeManaged(wlp.node); wlmanaged {
			continue
		}
		uwl_ipnet := &net.IPNet{IP: wlp.ipnet.IP, Mask: net.CIDRMask(32, 32)}
		log.WithFields(log.Fields{"ip": uwl_ipnet.IP.String(), "mask": uwl_ipnet.Mask.String()}).Debug("unmanaged ip-workload map")
		addSpecialInternalIPNet(newSpecialSubnets, uwl_ipnet, share.CLUSIPAddrScopeGlobal, share.SpecInternalUwlIP, false)
	}

	// Service address
	for _, cache := range addr2SvcMap {
		if cache.ipsvcInternal {
			for ip := range cache.svcAddrs.Iter() {
				ipnet := &net.IPNet{IP: net.ParseIP(ip.(string)), Mask: net.CIDRMask(32, 32)}
				addInternalIPNet(newSubnets, ipnet, share.CLUSIPAddrScopeGlobal /*policyApplyIngress*/, true)
				log.WithFields(log.Fields{"ip": ipnet.IP.String(), "mask": ipnet.Mask.String()}).Debug("svcip subnet")
				addSpecialInternalIPNet(newSpecialSubnets, ipnet, share.CLUSIPAddrScopeGlobal, share.SpecInternalSvcIP /*policyApplyIngress*/, true)
				for _, extip := range addr2ExtIpMap[ip.(string)] {
					ext_ipnet := &net.IPNet{IP: extip, Mask: net.CIDRMask(32, 32)}
					log.WithFields(log.Fields{"extip": ext_ipnet.IP.String(), "mask": ext_ipnet.Mask.String()}).Debug("extip subnet")
					addSpecialInternalIPNet(newSpecialSubnets, ext_ipnet, share.CLUSIPAddrScopeGlobal, share.SpecInternalExtIP, false)
				}
			}
		}
	}

	// device ip added to special internal subnet
	for key, dev := range ipDevMap {
		if !dev.stop.IsZero() && time.Since(dev.stop) > workloadEphemeralLife {
			continue
		}
		ipstr := fmt.Sprintf("%s/32", key)
		if devip, _, err := net.ParseCIDR(ipstr); err == nil {
			dev_ipnet := &net.IPNet{IP: devip, Mask: net.CIDRMask(32, 32)}
			log.WithFields(log.Fields{"ip": dev_ipnet.IP.String(), "mask": dev_ipnet.Mask.String()}).Debug("dev-ip subnet")
			addSpecialInternalIPNet(newSpecialSubnets, dev_ipnet, share.CLUSIPAddrScopeGlobal, share.SpecInternalDevIP, false)
		}
	}

	if len(newSpecialSubnets) != len(cachedSpecialSubnets) {
		cachedSpecialSubnets = newSpecialSubnets
		putSpecialIPNetToCluseter(true)
	} else {
		for key := range newSpecialSubnets {
			if _, ok := cachedSpecialSubnets[key]; !ok {
				cachedSpecialSubnets = newSpecialSubnets
				putSpecialIPNetToCluseter(true)
				break
			}
		}
	}

	if len(newSubnets) != len(cachedInternalSubnets) {
		cachedInternalSubnets = newSubnets
		putInternalIPNetToCluseter(true)
		return
	}

	for key := range newSubnets {
		if _, ok := cachedInternalSubnets[key]; !ok {
			cachedInternalSubnets = newSubnets
			putInternalIPNetToCluseter(true)
			return
		}
	}
}

func getPortsForApplication(wl *share.CLUSWorkload, application uint32) string {
	var ports string = ""
	for port, app := range wl.Apps {
		if app.Application == application || app.Proto == application {
			if ports == "" {
				ports = port
			} else {
				ports = fmt.Sprintf("%s,%s", ports, port)
			}
		}
	}
	return ports
}

func addAppPort(app string, port uint16, appMap map[string]string) {
	if p, ok := appMap[app]; ok {
		appMap[app] = fmt.Sprintf("%s,%d", p, port)
	} else {
		appMap[app] = fmt.Sprintf("%d", port)
	}
}

func getAppPorts(wl *share.CLUSWorkload) map[string]string {
	appMap := make(map[string]string)
	for _, app := range wl.Apps {
		if name, ok := common.AppNameMap[app.Application]; ok {
			addAppPort(name, app.Port, appMap)
		} else if name, ok := common.AppNameMap[app.Server]; ok {
			addAppPort(name, app.Port, appMap)
		} else if name, ok := common.AppNameMap[app.Proto]; ok {
			addAppPort(name, app.Port, appMap)
		} else {
			switch app.IPProto {
			case syscall.IPPROTO_TCP:
				addAppPort("TCP", app.Port, appMap)
			case syscall.IPPROTO_UDP:
				addAppPort("UDP", app.Port, appMap)
			case syscall.IPPROTO_ICMP:
				addAppPort("ICMP", 0, appMap)
			default:
				addAppPort(fmt.Sprintf("%d", app.IPProto), app.Port, appMap)
			}
		}
	}

	return appMap
}

func scheduleUnmanagedWlProc(fast bool) {
	log.WithFields(log.Fields{"fast": fast}).Debug("")
	if fast {
		unManagedWlTimer.Reset(unManagedWlProcDelayFast)
	} else {
		unManagedWlTimer.Reset(unManagedWlProcDelaySlow)
	}
}

// // KV store map
type kvConfigStore struct {
	mutex  sync.RWMutex
	stores map[string][]byte // [confug key] = values
}

var backupKvStores *kvConfigStore = &kvConfigStore{stores: make(map[string][]byte)}
var backupKvStoreEPs utils.Set = utils.NewSet(share.CFGEndpointFileMonitor, share.CFGEndpointFileAccessRule, share.CFGEndpointGroup, share.CFGEndpointProcessProfile, share.CFGEndpointScript)

func (kvs *kvConfigStore) UpdateBackupKvStore(key string, value []byte, bDeleted bool) {
	// log.WithFields(log.Fields{"key": key, "bDeleted": bDeleted}).Debug("Backup:")
	kvs.mutex.Lock()
	defer kvs.mutex.Unlock()
	if bDeleted {
		delete(kvs.stores, key)
	} else {
		kvs.stores[key] = value
	}
}

func (kvs *kvConfigStore) GetBackupKvStore(key string) ([]byte, bool) {
	// log.WithFields(log.Fields{"ept": ept, "key": key}).Debug("Backup:")
	kvs.mutex.RLock()
	defer kvs.mutex.RUnlock()
	if value, ok := kvs.stores[key]; ok {
		return value, ok
	}
	return nil, false
}

func querySessionRequest(nType cluster.ClusterNotifyType, key string, value []byte) {
	log.WithFields(log.Fields{"type": cluster.ClusterNotifyName[nType], "key": key}).Debug("")

	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		var qsr api.QuerySessionRequest
		_ = json.Unmarshal(value, &qsr)

		log.WithFields(log.Fields{"type": cluster.ClusterNotifyName[nType], "key": key, "qsr": qsr}).Debug("[multi-cluster] consul kv watcher added event. Will call rest.CreateQuerySession()")

		err := cctx.CreateQuerySessionFunc(&qsr)
		if err != nil {
			log.WithFields(log.Fields{"type": cluster.ClusterNotifyName[nType], "key": key, "qsr": qsr, "err": err}).Debug("[multi-cluster] consul kv watcher added event. call rest.CreateQuerySession() error")
		}
	case cluster.ClusterNotifyDelete:
		queryToken := share.CLUSKeyLastToken(key)

		err := cctx.DeleteQuerySessionFunc(queryToken)
		if err != nil {
			log.WithFields(log.Fields{"queryToken": queryToken}).Debug("[multi-cluster] consul kv watcher deleted event, call cctx.DeleteQuerySessionFunc() error")
		} else {
			log.WithFields(log.Fields{"queryToken": queryToken}).Debug("[multi-cluster] consul kv watcher deleted event")
		}
	}
}

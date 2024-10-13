package rest

import (
	"net/http"
	"sort"

	"github.com/julienschmidt/httprouter"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/rpc"
	"github.com/neuvector/neuvector/share"
	log "github.com/sirupsen/logrus"
)

func getHostBenchStatus(id string) (string, string) {
	_, dockerStatus := getCISStatusFromCluster(share.BenchDockerHost, id)
	_, kubeStatus := getCISStatusFromCluster(share.BenchKubeWorker, id)
	return dockerStatus, kubeStatus
}

func handlerHostList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	query := restParseQuery(r)

	var hosts []*api.RESTHost
	var resp api.RESTHostsData
	resp.Hosts = make([]*api.RESTHost, 0)

	if cacher.GetHostCount(acc) <= query.start {
		restRespSuccess(w, r, &resp, acc, login, nil, "Get node list")
		return
	}

	cached := cacher.GetAllHosts(acc)

	// Sort
	if len(cached) > 1 && len(query.sorts) > 0 {
		// Convert struct slice to interface slice
		var data []interface{} = make([]interface{}, len(cached))
		for i, d := range cached {
			data[i] = d
		}

		// Sort
		restNewSorter(data, query.sorts).Sort()

		// Copy the result
		hosts = make([]*api.RESTHost, len(cached))
		for i, d := range data {
			hosts[i] = d.(*api.RESTHost)
		}
	} else {
		hosts = cached
		sort.Slice(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })
	}

	// Filter
	if len(hosts) <= query.start {
		restRespSuccess(w, r, &resp, acc, login, nil, "Get node list")
		return
	}

	if len(query.filters) > 0 {
		var dummy api.RESTHost
		rf := restNewFilter(&dummy, query.filters)

		for _, host := range hosts[query.start:] {
			if !rf.Filter(host) {
				continue
			}

			resp.Hosts = append(resp.Hosts, host)

			if query.limit > 0 && len(resp.Hosts) >= query.limit {
				break
			}
		}
	} else if query.limit == 0 {
		resp.Hosts = hosts[query.start:]
	} else {
		var end int
		if query.start+query.limit > len(hosts) {
			end = len(hosts)
		} else {
			end = query.start + query.limit
		}
		resp.Hosts = hosts[query.start:end]
	}
	for _, host := range resp.Hosts {
		host.DockerBenchStatus, host.KubeBenchStatus = getHostBenchStatus(host.ID)
	}

	log.WithFields(log.Fields{"entries": len(resp.Hosts)}).Debug("Response")

	restRespSuccess(w, r, &resp, acc, login, nil, "Get node list")
}

func handlerHostShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id := ps.ByName("id")

	var resp api.RESTHostData

	// Retrieve the host
	host, err := cacher.GetHost(id, acc)
	if host == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	host.DockerBenchStatus, host.KubeBenchStatus = getHostBenchStatus(host.ID)

	resp.Host = host

	restRespSuccess(w, r, &resp, acc, login, nil, "Get node detail")
}

func handlerHostProcessProfile(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id := ps.ByName("id")

	agents, err := cacher.GetAgentsbyHost(id, acc)
	if agents == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}
	if len(agents) == 0 {
		log.WithFields(log.Fields{"host": id}).Error("No enforcer running on the node")
		restRespErrorMessage(w, http.StatusNotFound, api.RESTErrObjectNotFound, "Enforcer not found")
		return
	}

	agentID := agents[0] // take the first entry
	rules, err := rpc.GetDerivedWorkloadProcessRule(agentID, api.AllHostGroup)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to make RPC call")
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrClusterRPCError, err.Error())
		return
	}

	resp := api.RESTProcessProfile{ // Other fields are not refer-able
		ProcessList: make([]*api.RESTProcessProfileEntry, len(rules)),
	}

	for i, pp := range rules {
		resp.ProcessList[i] = &api.RESTProcessProfileEntry{
			Name:             pp.Name,
			Path:             pp.Path,
			Action:           pp.Action,
			Group:            pp.GroupName,
			CfgType:          pp.CfgType,
			CreatedTimeStamp: int64(pp.CreatedAt),
			UpdatedTimeStamp: int64(pp.UpdateAt),
		}
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get host process profile")
}

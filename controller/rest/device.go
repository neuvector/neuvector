package rest

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/rpc"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
)

// const clusterWaitPeriod int = 5

func handlerControllerList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	query := restParseQuery(r)

	var ctrls []*api.RESTController
	var resp api.RESTControllersData
	resp.Controllers = make([]*api.RESTController, 0)

	if cacher.GetControllerCount(acc) <= query.start {
		restRespSuccess(w, r, &resp, acc, login, nil, "Get controller list")
		return
	}

	cached := cacher.GetAllControllers(acc)

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
		ctrls = make([]*api.RESTController, len(cached))
		for i, d := range data {
			ctrls[i] = d.(*api.RESTController)
		}
	} else {
		ctrls = cached
		sort.Slice(ctrls, func(i, j int) bool { return ctrls[i].Name < ctrls[j].Name })
	}

	// Filter
	if len(ctrls) <= query.start {
		restRespSuccess(w, r, &resp, acc, login, nil, "Get controller list")
		return
	}

	if len(query.filters) > 0 {
		var dummy api.RESTController
		rf := restNewFilter(&dummy, query.filters)

		for _, ctrl := range ctrls[query.start:] {
			if !rf.Filter(ctrl) {
				continue
			}

			resp.Controllers = append(resp.Controllers, ctrl)

			if query.limit > 0 && len(resp.Controllers) >= query.limit {
				break
			}
		}
	} else if query.limit == 0 {
		resp.Controllers = ctrls[query.start:]
	} else {
		var end int
		if query.start+query.limit > len(ctrls) {
			end = len(ctrls)
		} else {
			end = query.start + query.limit
		}
		resp.Controllers = ctrls[query.start:end]
	}

	log.WithFields(log.Fields{"entries": len(resp.Controllers)}).Debug("Response")

	restRespSuccess(w, r, &resp, acc, login, nil, "Get controller list")
}

func handlerControllerShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id := ps.ByName("id")

	var resp api.RESTControllerData

	// Retrieve controller
	ctrl := cacher.GetController(id, acc)
	if ctrl == nil {
		restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
		return
	}

	resp.Controller = ctrl

	restRespSuccess(w, r, &resp, acc, login, nil, "Get controller detail")
}

func handlerAgentList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	query := restParseQuery(r)

	var agents []*api.RESTAgent
	var resp api.RESTAgentsData
	resp.Agents = make([]*api.RESTAgent, 0)

	if cacher.GetAgentCount(acc, "") <= query.start {
		restRespSuccess(w, r, &resp, acc, login, nil, "Get enforcer list")
		return
	}

	cached := cacher.GetAllAgents(acc)

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
		agents = make([]*api.RESTAgent, len(cached))
		for i, d := range data {
			agents[i] = d.(*api.RESTAgent)
		}
	} else {
		agents = cached
		sort.Slice(agents, func(i, j int) bool { return agents[i].Name < agents[j].Name })
	}

	// Filter
	if len(agents) <= query.start {
		restRespSuccess(w, r, &resp, acc, login, nil, "Get enforcer list")
		return
	}

	if len(query.filters) > 0 {
		var dummy api.RESTAgent
		rf := restNewFilter(&dummy, query.filters)

		for _, agent := range agents[query.start:] {
			if !rf.Filter(agent) {
				continue
			}

			resp.Agents = append(resp.Agents, agent)

			if query.limit > 0 && len(resp.Agents) >= query.limit {
				break
			}
		}
	} else if query.limit == 0 {
		resp.Agents = agents[query.start:]
	} else {
		var end int
		if query.start+query.limit > len(agents) {
			end = len(agents)
		} else {
			end = query.start + query.limit
		}
		resp.Agents = agents[query.start:end]
	}

	log.WithFields(log.Fields{"entries": len(resp.Agents)}).Debug("Response")

	restRespSuccess(w, r, &resp, acc, login, nil, "Get enforcer list")
}

func handlerAgentShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id := ps.ByName("id")

	var resp api.RESTAgentData

	// Retrieve agent
	agent := cacher.GetAgent(id, acc)
	if agent == nil {
		log.WithFields(log.Fields{"id": id}).Error("Enforcer not found")
		restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
		return
	}

	resp.Agent = agent

	restRespSuccess(w, r, &resp, acc, login, nil, "Get enforcer detail")
}

func handlerAgentStats(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	agentID := ps.ByName("id")

	agent := cacher.GetAgent(agentID, acc)
	if agent == nil {
		log.WithFields(log.Fields{"id": agentID}).Error("Enforcer not found")
		restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
		return
	}

	stats, err := rpc.GetStats(agentID, &share.CLUSFilter{})
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrClusterRPCError, "Fail to make the RPC call")
		return
	}

	var resp api.RESTAgentStatsData
	resp.ID = agentID
	resp.ReadAt = api.RESTTimeString(time.Now())
	resp.Stats = stats2REST(stats)

	restRespSuccess(w, r, &resp, acc, login, nil, "Get enforcer statistics")
}

func ctrlCounter2REST(counter *share.CLUSControllerCounter) *api.RESTControllerCounter {
	return &api.RESTControllerCounter{
		GraphNodes: counter.GraphNodes,
		GoRoutines: counter.GoRoutines,
		ScanTasks:  counter.ScanTasks,
		LsofOutput: strings.Split(string(counter.Lsof[:]), "\n"),
		PSOutput:   strings.Split(string(counter.PS[:]), "\n"),
	}
}

func handlerControllerCounter(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	ctrlID := ps.ByName("id")

	ep, err := cacher.GetControllerRPCEndpoint(ctrlID, acc)
	if ep == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	counter, err := rpc.GetControllerCounter(ep.ClusterIP, ep.RPCServerPort)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrClusterRPCError, "Fail to make the RPC call")
		return
	}

	resp := api.RESTControllerCounterData{Counter: ctrlCounter2REST(counter)}
	restRespSuccess(w, r, &resp, acc, login, nil, "Get controller counter")
}

func agentCounter2REST(counter *share.CLUSDatapathCounter) *api.RESTAgentCounter {
	return &api.RESTAgentCounter{
		RXPackets:           counter.RXPackets,
		RXDropPackets:       counter.RXDropPackets,
		TXPackets:           counter.TXPackets,
		TXDropPackets:       counter.TXDropPackets,
		ErrorPackets:        counter.ErrorPackets,
		NoWorkloadPackets:   counter.NoWorkloadPackets,
		IPv4Packets:         counter.IPv4Packets,
		IPv6Packets:         counter.IPv6Packets,
		TCPPackets:          counter.TCPPackets,
		TCPNoSessionPackets: counter.TCPNoSessionPackets,
		UDPPackets:          counter.UDPPackets,
		ICMPPackets:         counter.ICMPPackets,
		OtherPackets:        counter.OtherPackets,
		Assemblys:           counter.Assemblys,
		FreedAssemblys:      counter.FreedAssemblys,
		Fragments:           counter.Fragments,
		FreedFragments:      counter.FreedFragments,
		TimeoutFragments:    counter.TimeoutFragments,
		TotalSessions:       counter.TotalSessions,
		TCPSessions:         counter.TCPSessions,
		UDPSessions:         counter.UDPSessions,
		ICMPSessions:        counter.ICMPSessions,
		IPSessions:          counter.IPSessions,
		ParserSessions:      counter.ParserSessions,
		ParserPackets:       counter.ParserPackets,
		DropMeters:          counter.DropMeters,
		ProxyMeters:         counter.ProxyMeters,
		CurMeters:           counter.CurMeters,
		CurLogCaches:        counter.CurLogCaches,
		LimitDropConns:      counter.LimitDropConns,
		LimitPassConns:      counter.LimitPassConns,
		PolicyType1Rules:    counter.PolicyType1Rules,
		PolicyType2Rules:    counter.PolicyType2Rules,
		PolicyDomains:       counter.PolicyDomains,
		PolicyDomainIPs:     counter.PolicyDomainIPs,
		GoRoutines:          counter.GoRoutines,
		LsofOutput:          strings.Split(string(counter.Lsof[:]), "\n"),
		PSOutput:            strings.Split(string(counter.PS[:]), "\n"),
	}
}

func handlerAgentCounter(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	agentID := ps.ByName("id")

	agent := cacher.GetAgent(agentID, acc)
	if agent == nil {
		log.WithFields(log.Fields{"id": agentID}).Error("Enforcer not found")
		restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
		return
	}

	counter, err := rpc.GetDatapathCounter(agentID)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrClusterRPCError, "Fail to make the RPC call")
		return
	}

	resp := api.RESTAgentCounterData{Counter: agentCounter2REST(counter)}
	restRespSuccess(w, r, &resp, acc, login, nil, "Get enforcer counter")
}

func handlerControllerConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id := ps.ByName("id")

	ctrler := cacher.GetController(id, acc)
	if ctrler == nil {
		log.WithFields(log.Fields{"id": id}).Error("Controller not found")
		restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
		return
	}

	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTControllerConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	var cconf share.CLUSControllerConfig
	key := share.CLUSUniconfControllerKey(id, id)

	retry := 0
	for retry < retryClusterMax {
		// Retrieve from the cluster
		value, rev, _ := cluster.GetRev(key)
		if value != nil {
			json.Unmarshal(value, &cconf)
		}

		if rconf.Config.Debug != nil {
			cconf.Debug = *rconf.Config.Debug
		}

		if rconf.Config.LogLevel != nil {
			cconf.LogLevel = *rconf.Config.LogLevel
			if cconf.LogLevel == share.LogLevel_Error ||
				cconf.LogLevel == share.LogLevel_Warn ||
				cconf.LogLevel == share.LogLevel_Info {
				cconf.Debug = nil
			} else if cconf.LogLevel == share.LogLevel_Debug {
				if cconf.Debug == nil {
					cconf.Debug = make([]string, 0)
					cconf.Debug = append(cconf.Debug, "cpath")
				}
			}
		} else {
			if rconf.Config.Debug != nil {
				cconf.LogLevel = share.LogLevel_Debug
			} else {
				cconf.LogLevel = ""
			}
		}

		if !acc.Authorize(&cconf, nil) {
			restRespAccessDenied(w, login)
			return
		}

		value, _ = json.Marshal(&cconf)
		if err = cluster.PutRev(key, value, rev); err != nil {
			log.WithFields(log.Fields{"error": err, "rev": rev}).Error("")
			retry++
		} else {
			break
		}
	}

	if retry >= retryClusterMax {
		// cacher.AuthLog(cacher.LOGEV_USER_CONFIG_FAILED,
		// 	auth.Password.Username, auth.Password.Domain)
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}

	restRespSuccess(w, r, nil, acc, login, &rconf, "Configure controller")
}

func handlerControllerGetConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id := ps.ByName("id")

	conf, err := cacher.GetControllerConfig(id, acc)
	if conf == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	var resp api.RESTControllerConfigData
	resp.Config = conf
	restRespSuccess(w, r, &resp, acc, login, nil, "Get controller configurations")
}

func handlerAgentConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id := ps.ByName("id")

	agent := cacher.GetAgent(id, acc)
	if agent == nil {
		log.WithFields(log.Fields{"id": id}).Error("Enforcer not found")
		restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
		return
	}

	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTAgentConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	var cconf share.CLUSAgentConfig
	key := share.CLUSUniconfAgentKey(agent.HostID, id)

	retry := 0
	for retry < retryClusterMax {
		// Retrieve from the cluster
		value, rev, _ := cluster.GetRev(key)
		if value != nil {
			json.Unmarshal(value, &cconf)
		}

		if rconf.Config.Debug != nil {
			cconf.Debug = *rconf.Config.Debug
		}

		if rconf.Config.DisableNvProtect != nil {
			cconf.DisableNvProtectMode = *rconf.Config.DisableNvProtect
		}

		if rconf.Config.DisableKvCCtl != nil {
			cconf.DisableKvCongestCtl = *rconf.Config.DisableKvCCtl
		}

		if rconf.Config.LogLevel != nil {
			cconf.LogLevel = *rconf.Config.LogLevel
			if cconf.LogLevel == share.LogLevel_Error ||
				cconf.LogLevel == share.LogLevel_Warn ||
				cconf.LogLevel == share.LogLevel_Info {
				cconf.Debug = nil
			} else if cconf.LogLevel == share.LogLevel_Debug {
				if cconf.Debug == nil {
					cconf.Debug = make([]string, 0)
					cconf.Debug = append(cconf.Debug, "cpath")
				}
			}
		} else {
			if rconf.Config.Debug != nil {
				cconf.LogLevel = share.LogLevel_Debug
			} else {
				cconf.LogLevel = ""
			}
		}

		if !acc.Authorize(&cconf, nil) {
			restRespAccessDenied(w, login)
			return
		}

		value, _ = json.Marshal(&cconf)
		if err = cluster.PutRev(key, value, rev); err != nil {
			log.WithFields(log.Fields{"error": err, "rev": rev}).Error("")
			retry++
		} else {
			break
		}
	}

	if retry >= retryClusterMax {
		// cacher.AuthLog(cacher.LOGEV_USER_CONFIG_FAILED,
		// 	auth.Password.Username, auth.Password.Domain)
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}

	restRespSuccess(w, r, nil, acc, login, &rconf, "Configure enforcer")
}

func handlerAgentGetConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id := ps.ByName("id")

	conf, err := cacher.GetAgentConfig(id, acc)
	if conf == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	var resp api.RESTAgentConfigData
	resp.Config = conf

	restRespSuccess(w, r, &resp, acc, login, nil, "Get enforcer configurations")
}

/*
func handlerAgentGetLogs(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !authDebugCaller(w, acc, login) {
		return
	}

	id := ps.ByName("id")
	query := restParseQuery(r)

	start := 0
	if query.limit == 0 {
		query.limit = logsSizeLimit
	}
	if query.backward {
		start = -1
	}

	if cacher.GetAgent(id, acc) == nil {
		log.WithFields(log.Fields{"id": id}).Error("Enforcer not found")
		restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
		return
	}

	data, err := rpc.GetContainerLogs(id, id, start, query.limit)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to make RPC call")
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrClusterRPCError, err.Error())
		return
	}

	restRespSuccess(w, r, data, acc, login, nil, "Get enforcer logs")
}

func handlerControllerGetLogs(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !authDebugCaller(w, acc, login) {
		return
	}

	id := ps.ByName("id")
	query := restParseQuery(r)

	start := 0
	if query.limit == 0 {
		query.limit = logsSizeLimit
	}
	if query.backward {
		start = -1
	}

	if cacher.GetController(id, acc) == nil {
		log.WithFields(log.Fields{"id": id}).Error("Controller not found")
		restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
		return
	}

	// OpenShift by default using journald log driver so we can't read the file, but still avoid using docker API for now.
	// data, err := global.RT.GetContainerLogs(localDev.Host.Flavor == share.FlavorOpenShift, id, start, query.limit)
	data, err := global.RT.GetContainerLogs(false, id, start, query.limit)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Get controller log fail")
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrClusterRPCError, "Get controller log fail")
		return
	}

	restRespSuccess(w, r, data, acc, login, nil, "Get controller logs")
}
*/

func handlerControllerStats(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	ctrlID := ps.ByName("id")

	ep, err := cacher.GetControllerRPCEndpoint(ctrlID, acc)
	if ep == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	stats, err := rpc.GetControllerStat(ep.ClusterIP, ep.RPCServerPort)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrClusterRPCError, "Fail to make the RPC call")
		return
	}

	var resp api.RESTWorkloadStatsData
	resp.ID = ctrlID
	resp.ReadAt = api.RESTTimeString(time.Now())
	resp.Stats = stats2REST(stats)

	restRespSuccess(w, r, &resp, acc, login, nil, "Get controller system statistics")
}

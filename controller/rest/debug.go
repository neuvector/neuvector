package rest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/rpc"
	"github.com/neuvector/neuvector/share"
)

func authDebugCaller(w http.ResponseWriter, acc *access.AccessControl, login *loginSession) bool {
	if !acc.CanWriteCluster() { // only admin/fedAdmin can debug
		restRespAccessDenied(w, login)
		return false
	}
	return true
}

func getDebugIP2Workload(hostID string, query *restQuery) ([]*api.RESTDebugIP2Workload, error) {
	cached := cacher.GetIP2WorkloadMap(hostID)
	if hostID != "" && cached == nil {
		err := errors.New("Host not found")
		log.WithFields(log.Fields{"host": hostID}).Error(err)
		return nil, err
	}

	var wls []*api.RESTDebugIP2Workload
	ip2Workloads := make([]*api.RESTDebugIP2Workload, 0)

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
		wls = make([]*api.RESTDebugIP2Workload, len(cached))
		for i, d := range data {
			wls[i] = d.(*api.RESTDebugIP2Workload)
		}
	} else {
		wls = cached
	}

	// Filter
	if len(wls) <= query.start {
		return ip2Workloads, nil
	}

	if query.limit == 0 {
		ip2Workloads = wls[query.start:]
	} else {
		var end int
		if query.start+query.limit > len(wls) {
			end = len(wls)
		} else {
			end = query.start + query.limit
		}
		ip2Workloads = wls[query.start:end]
	}

	return ip2Workloads, nil
}

func parseProfilingArgs(args *api.RESTProfiling) *share.CLUSProfilingRequest {
	r := share.CLUSProfilingRequest{Methods: make([]share.ProfilingMethod, 0)}

	for _, m := range args.Methods {
		switch m {
		case api.ProfilingCPU:
			r.Methods = append(r.Methods, share.ProfilingMethod_CPU)
		case api.ProfilingMemory:
			r.Methods = append(r.Methods, share.ProfilingMethod_Memory)
		}
	}
	if len(r.Methods) == 0 {
		r.Methods = append(r.Methods, share.ProfilingMethod_Memory)
	}

	if args.Duration < 1 {
		r.Duration = 1
	} else if args.Duration > api.ProfilingDurationMax {
		r.Duration = api.ProfilingDurationMax
	} else {
		r.Duration = args.Duration
	}

	return &r
}

func handlerControllerProfiling(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !authDebugCaller(w, acc, login) {
		return
	}

	id := ps.ByName("id")

	body, _ := ioutil.ReadAll(r.Body)

	var rconf api.RESTProfilingData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Profiling == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	req := parseProfilingArgs(rconf.Profiling)
	req.Cmd = share.ProfilingCmd_StartProfiling

	eps := cacher.GetAllControllerRPCEndpoints(acc)
	for _, ep := range eps {
		if ep.ID == id {
			err = rpc.ProfileController(ep.ClusterIP, ep.RPCServerPort, req)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Fail to make RPC call")
				restRespError(w, http.StatusInternalServerError, api.RESTErrClusterRPCError)
			} else {
				restRespSuccess(w, r, nil, acc, login, &rconf, "Controller profiling command")
			}
			return
		}
	}

	log.WithFields(log.Fields{"id": id}).Error("Controller not found")
	restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
}

func handlerAgentProfiling(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !authDebugCaller(w, acc, login) {
		return
	}

	id := ps.ByName("id")

	agent := cacher.GetAgent(id, acc)
	if agent == nil {
		log.WithFields(log.Fields{"id": id}).Error("Enforcer not found")
		restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
		return
	}

	body, _ := ioutil.ReadAll(r.Body)

	var rconf api.RESTProfilingData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Profiling == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	req := parseProfilingArgs(rconf.Profiling)
	req.Cmd = share.ProfilingCmd_StartProfiling

	err = rpc.ProfileEnforcer(id, req)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to make RPC call")
		restRespError(w, http.StatusInternalServerError, api.RESTErrClusterRPCError)
		return
	}

	restRespSuccess(w, r, nil, acc, login, &rconf, "Enforcer profiling command")
}

func handlerDebugIP2Workload(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !authDebugCaller(w, acc, login) {
		return
	}

	query := restParseQuery(r)
	if len(query.sorts) == 0 {
		query.sorts = append(query.sorts, restFieldSort{tag: "ip", asc: true})
	}

	var hostID string
	for _, f := range query.filters {
		if f.tag == api.FilterByHost && f.op == api.OPeq {
			hostID = f.value
		}
	}

	if ip2Workloads, err := getDebugIP2Workload(hostID, query); err != nil {
		restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
	} else {
		resp := api.RESTDebugIP2WorkloadData{IP2Workloads: ip2Workloads}
		restRespSuccess(w, r, &resp, acc, login, nil, "Debug command")
	}
}

func handlerDebugWorkloadIntcp(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
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

	if wlID == "" {
		err := fmt.Errorf("Workload filter must be provided")
		log.Error(err)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrNotEnoughFilter, err.Error())
		return
	}

	cwi, err := rpc.GetContainerIntercept(agentID, wlID)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to make RPC call")
		restRespError(w, http.StatusInternalServerError, api.RESTErrClusterRPCError)
		return
	}

	rwi := api.RESTWorkloadInterceptData{
		Intercept: &api.RESTWorkloadIntercept{
			ID: cwi.ID, Inline: cwi.Inline, Quarantine: cwi.Quarantine,
		},
	}
	rwi.Intercept.Ports = make([]*api.RESTWorkloadInterceptPort, len(cwi.Ports))
	for i, p := range cwi.Ports {
		rwi.Intercept.Ports[i] = &api.RESTWorkloadInterceptPort{
			Port:          p.Port,
			Peer:          p.Peer,
			MAC:           net.HardwareAddr(p.MAC).String(),
			UCMAC:         net.HardwareAddr(p.UCMAC).String(),
			BCMAC:         net.HardwareAddr(p.BCMAC).String(),
			InPort:        p.InPort,
			ExPort:        p.ExPort,
			InPortRules:   p.InPortRules,
			ExPortRules:   p.ExPortRules,
			EnforcerRules: p.EnforcerRules,
		}
	}

	restRespSuccess(w, r, &rwi, acc, login, nil, "Get container intercept debug")
}

func handlerDebugGetInternalSubnet(w http.ResponseWriter, r *http.Request,
	ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !authDebugCaller(w, acc, login) {
		return
	}

	resp := api.RESTInternalSubnetsData{
		InternalSubnets: cacher.GetInternalSubnets(),
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Debug command")
}

func handlerDebugControllerSyncRequest(w http.ResponseWriter, r *http.Request,
	ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !authDebugCaller(w, acc, login) {
		return
	}

	ctrlID := ps.ByName("id")

	eps := cacher.GetAllControllerRPCEndpoints(acc)
	for _, ep := range eps {
		if ep.ID == ctrlID {
			if ep.Leader {
				log.WithFields(log.Fields{"ctrl": ctrlID}).Error("controller itself is lead")
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest,
					"This controller is lead - no need to sync")
				return
			}

			go func() {
				if err := rpc.TriggerSync(ep.ClusterIP, ep.RPCServerPort); err != nil {
					log.WithFields(log.Fields{"error": err}).Error("sync request error")
				} else {
					log.Debug("sync request succeed")
				}
			}()

			break
		}
	}

	restRespSuccess(w, r, nil, acc, login, nil, "Sync request")
}

func handlerDebugControllerSyncInfo(w http.ResponseWriter, r *http.Request,
	ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !authDebugCaller(w, acc, login) {
		return
	}

	var leadStatus *share.CLUSPolicySyncStatus
	list := make([]*api.RESTDebugSyncInfo, 0)

	eps := cacher.GetAllControllerRPCEndpoints(acc)
	for _, ep := range eps {
		if s, err := rpc.CheckPolicySyncStatus(ep.ClusterIP, ep.RPCServerPort); err != nil {
			log.WithFields(log.Fields{"target": ep.ClusterIP, "error": err}).Error()
		} else {
			if s.Leader {
				leadStatus = s
			}
			list = append(list, &api.RESTDebugSyncInfo{
				ClusterIP:      ep.ClusterIP,
				Leader:         s.Leader,
				LearnedRuleMax: s.LearnedRuleMax,
				GraphNodeCount: s.GraphNodeCount,
			})
		}
	}

	if leadStatus != nil {
		for _, s := range list {
			if s.LearnedRuleMax != leadStatus.LearnedRuleMax || s.GraphNodeCount != leadStatus.GraphNodeCount {
				s.SyncErrorFound = true
			}
		}
	}

	resp := api.RESTDebugSyncInfoData{Sync: list}
	restRespSuccess(w, r, &resp, acc, login, nil, "Check sync status")
}

func handlerProbeSummary(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !authDebugCaller(w, acc, login) {
		return
	}

	id := ps.ByName("id")

	agent := cacher.GetAgent(id, acc)
	if agent == nil {
		log.WithFields(log.Fields{"id": id}).Error("Enforcer not found")
		restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
		return
	}

	probe, err := rpc.ProbeSummary(id)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to make RPC call")
		restRespError(w, http.StatusInternalServerError, api.RESTErrClusterRPCError)
		return
	}
	summary := &api.RESTProbeSummary{
		ContainerMap:    probe.ContainerMap,
		PidContainerMap: probe.PidContainerMap,
		PidProcMap:      probe.PidProcMap,
		NewProcesses:    probe.NewProcesses,
		NewSuspicProc:   probe.NewSuspicProc,
		ContainerStops:  probe.ContainerStops,
		PidSet:          probe.PidSet,
		SessionTable:    probe.SessionTable,
	}
	resp := api.RESTProbeSummaryData{Summary: summary}
	restRespSuccess(w, r, &resp, acc, login, nil, "Debug command")
}

func handlerProbeProcessMap(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !authDebugCaller(w, acc, login) {
		return
	}

	query := restParseQuery(r)
	if len(query.sorts) == 0 {
		query.sorts = append(query.sorts, restFieldSort{tag: "Pid,omitempty", asc: true})
	}
	id := ps.ByName("id")

	agent := cacher.GetAgent(id, acc)
	if agent == nil {
		log.WithFields(log.Fields{"id": id}).Error("Enforcer not found")
		restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
		return
	}

	procs, err := rpc.ProbeProcessMap(id)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to make RPC call")
		restRespError(w, http.StatusInternalServerError, api.RESTErrClusterRPCError)
		return
	}
	var data []interface{} = make([]interface{}, len(procs))
	for i, d := range procs {
		data[i] = d
	}
	data = filterAndSort(data, query)

	var probe api.RESTProbeProcessesData
	probe.Processes = make([]*api.RESTProbeProcess, len(procs))
	for i, d := range data {
		proc := d.(*share.CLUSProbeProcess)
		p := &api.RESTProbeProcess{
			Pid:       proc.Pid,
			Ppid:      proc.Ppid,
			Name:      proc.Name,
			Ruid:      proc.Ruid,
			Euid:      proc.Euid,
			ScanTimes: proc.ScanTimes,
			StartTime: proc.StartTime,
			Reported:  proc.Reported,
			Container: proc.Container,
		}
		probe.Processes[i] = p
	}

	restRespSuccess(w, r, &probe, acc, login, nil, "Debug command")
}

func handlerProbeContainerMap(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !authDebugCaller(w, acc, login) {
		return
	}

	id := ps.ByName("id")

	agent := cacher.GetAgent(id, acc)
	if agent == nil {
		log.WithFields(log.Fields{"id": id}).Error("Enforcer not found")
		restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
		return
	}

	cons, err := rpc.ProbeContainerMap(id)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to make RPC call")
		restRespError(w, http.StatusInternalServerError, api.RESTErrClusterRPCError)
		return
	}
	var probe api.RESTProbeContainersData
	probe.Containers = make([]*api.RESTProbeContainer, len(cons))
	for i, con := range cons {
		c := &api.RESTProbeContainer{
			Id:       con.Id,
			Pid:      con.Pid,
			Children: con.Children,
			PortsMap: con.PortsMap,
		}
		probe.Containers[i] = c
	}

	restRespSuccess(w, r, &probe, acc, login, nil, "Debug command")
}

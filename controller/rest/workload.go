package rest

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/rpc"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

const logsSizeLimit = 500 * 1000

func stats2REST(stats *share.CLUSStats) *api.RESTStats {
	r := &api.RESTStats{
		Interval: stats.Interval,
		Total: api.RESTMetry{
			SessionIn:     stats.Total.SessionIn,
			SessionOut:    stats.Total.SessionOut,
			SessionCurIn:  stats.Total.SessionCurIn,
			SessionCurOut: stats.Total.SessionCurOut,
			PacketIn:      stats.Total.PacketIn,
			PacketOut:     stats.Total.PacketOut,
			ByteIn:        stats.Total.ByteIn,
			ByteOut:       stats.Total.ByteOut,
		},
		Span1: api.RESTMetry{
			CPU:        stats.Span1.CPU,
			Memory:     stats.Span1.Memory,
			SessionIn:  stats.Span1.SessionIn,
			SessionOut: stats.Span1.SessionOut,
			PacketIn:   stats.Span1.PacketIn,
			PacketOut:  stats.Span1.PacketOut,
			ByteIn:     stats.Span1.ByteIn,
			ByteOut:    stats.Span1.ByteOut,
		},
		Span12: api.RESTMetry{
			CPU:        stats.Span12.CPU,
			Memory:     stats.Span12.Memory,
			SessionIn:  stats.Span12.SessionIn,
			SessionOut: stats.Span12.SessionOut,
			PacketIn:   stats.Span12.PacketIn,
			PacketOut:  stats.Span12.PacketOut,
			ByteIn:     stats.Span12.ByteIn,
			ByteOut:    stats.Span12.ByteOut,
		},
		Span60: api.RESTMetry{
			CPU:        stats.Span60.CPU,
			Memory:     stats.Span60.Memory,
			SessionIn:  stats.Span60.SessionIn,
			SessionOut: stats.Span60.SessionOut,
			PacketIn:   stats.Span60.PacketIn,
			PacketOut:  stats.Span60.PacketOut,
			ByteIn:     stats.Span60.ByteIn,
			ByteOut:    stats.Span60.ByteOut,
		},
	}

	return r
}

func handlerWorkloadBrief(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	query := restParseQuery(r)

	var view string
	if value, ok := query.pairs[api.QueryKeyView]; ok && value == api.QueryValueViewPod {
		view = api.QueryValueViewPod
	}

	var wls []*api.RESTWorkloadBrief
	var resp api.RESTWorkloadsBriefData
	resp.Workloads = make([]*api.RESTWorkloadBrief, 0)

	count, _, _ := cacher.GetWorkloadCount(acc)
	if query.start > 0 && count <= query.start {
		restRespSuccess(w, r, &resp, acc, login, nil, "Get container brief")
		return
	}

	cached := cacher.GetAllWorkloadsBrief(view, acc)

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
		wls = make([]*api.RESTWorkloadBrief, len(cached))
		for i, d := range data {
			wls[i] = d.(*api.RESTWorkloadBrief)
		}
	} else {
		wls = cached
		sort.Slice(wls, func(i, j int) bool { return wls[i].Name < wls[j].Name })
	}

	// Filter
	if len(wls) <= query.start {
		restRespSuccess(w, r, &resp, acc, login, nil, "Get container brief")
		return
	}

	if len(query.filters) > 0 {
		var dummy api.RESTWorkload
		rf := restNewFilter(&dummy, query.filters)

		for _, wl := range wls[query.start:] {
			if !rf.Filter(wl) {
				continue
			}

			resp.Workloads = append(resp.Workloads, wl)

			if query.limit > 0 && len(resp.Workloads) >= query.limit {
				break
			}
		}
	} else if query.limit == 0 {
		resp.Workloads = wls[query.start:]
	} else {
		var end int
		if query.start+query.limit > len(wls) {
			end = len(wls)
		} else {
			end = query.start + query.limit
		}
		resp.Workloads = wls[query.start:end]
	}

	log.WithFields(log.Fields{"entries": len(resp.Workloads)}).Debug("Response")

	restRespSuccess(w, r, &resp, acc, login, nil, "Get container brief")
}

func workloadV1ToV2(wlV1 *api.RESTWorkload) *api.RESTWorkloadV2 {
	if wlV1 == nil {
		return nil
	}

	wlV2 := &api.RESTWorkloadV2{
		WlBrief: api.RESTWorkloadBriefV2{
			ID:           wlV1.ID,
			Name:         wlV1.Name,
			DisplayName:  wlV1.DisplayName,
			HostName:     wlV1.HostName,
			HostID:       wlV1.HostID,
			Image:        wlV1.Image,
			ImageID:      wlV1.ImageID,
			ImgCreateAt:  wlV1.ImgCreateAt,
			ImgRegScand:  wlV1.ImgRegScand,
			Domain:       wlV1.Domain,
			State:        wlV1.State,
			Service:      wlV1.Service,
			Author:       wlV1.Author,
			ServiceGroup: wlV1.ServiceGroup,
		},
		WlSecurity: api.RESTWorkloadSecurityV2{
			CapSniff:           wlV1.CapSniff,
			CapQuar:            wlV1.CapQuar,
			CapChgMode:         wlV1.CapChgMode,
			ServiceMesh:        wlV1.ServiceMesh,
			ServiceMeshSidecar: wlV1.ServiceMeshSidecar,
			PolicyMode:         wlV1.PolicyMode,
			ProfileMode:        wlV1.ProfileMode,
			BaselineProfile:    wlV1.BaselineProfile,
			QuarReason:         wlV1.QuarReason,
			ScanSummary:        wlV1.ScanSummary,
		},
		WlRtAttributes: api.RESTWorkloadRtAttribesV2{
			PodName:        wlV1.PodName,
			ShareNSWith:    wlV1.ShareNSWith,
			Privileged:     wlV1.Privileged,
			RunAsRoot:      wlV1.RunAsRoot,
			Labels:         wlV1.Labels,
			MemoryLimit:    wlV1.MemoryLimit,
			CPUs:           wlV1.CPUs,
			ServiceAccount: wlV1.ServiceAccount,
			NetworkMode:    wlV1.NetworkMode,
			Ifaces:         wlV1.Ifaces,
			Ports:          wlV1.Ports,
			Applications:   wlV1.Applications,
		},
		AgentID:      wlV1.AgentID,
		AgentName:    wlV1.AgentName,
		PlatformRole: wlV1.PlatformRole,
		CreatedAt:    wlV1.CreatedAt,
		StartedAt:    wlV1.StartedAt,
		FinishedAt:   wlV1.FinishedAt,
		Running:      wlV1.Running,
		SecuredAt:    wlV1.SecuredAt,
		ExitCode:     wlV1.ExitCode,
	}

	wlChildrenV2 := make([]*api.RESTWorkloadV2, 0, len(wlV1.Children))
	for _, cV1 := range wlV1.Children {
		if cV2 := workloadV1ToV2(cV1); cV2 != nil {
			wlChildrenV2 = append(wlChildrenV2, cV2)
		}
	}
	wlV2.Children = wlChildrenV2

	return wlV2
}

func handlerWorkloadListBase(apiVer string, w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	query := restParseQuery(r)
	if query.brief {
		handlerWorkloadBrief(w, r, ps)
		return
	}

	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	var accessOp access.AccessOP
	if r.Method == http.MethodPost {
		accessOp = access.AccessOPRead
	} else {
		accessOp = ""
	}

	acc, login := getAccessControl(w, r, accessOp)
	if acc == nil {
		return
	}

	var view string
	if value, ok := query.pairs[api.QueryKeyView]; ok && value == api.QueryValueViewPod {
		view = api.QueryValueViewPod
	}

	var wls []*api.RESTWorkload
	var respV1 api.RESTWorkloadsData
	var respV2 api.RESTWorkloadsDataV2
	var resp interface{} = &respV2
	if apiVer == "v2" {
		respV2.Workloads = make([]*api.RESTWorkloadV2, 0)
	} else {
		respV1.Workloads = make([]*api.RESTWorkload, 0)
		resp = &respV1
	}

	count, _, _ := cacher.GetWorkloadCount(acc)
	if query.start > 0 && count <= query.start {
		restRespSuccess(w, r, resp, acc, login, nil, "Get container list")
		return
	}

	// get POST body
	idlist := utils.NewSet()
	if r.Method == http.MethodPost {
		var idListData api.RESTAssetIDList
		body, _ := io.ReadAll(r.Body)
		err := json.Unmarshal(body, &idListData)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Request error")
			restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
			return
		}
		idlist = utils.NewSetFromStringSlice(idListData.IDs)
	}

	cached := cacher.GetAllWorkloads(view, acc, idlist)

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
		wls = make([]*api.RESTWorkload, len(cached))
		for i, d := range data {
			wls[i] = d.(*api.RESTWorkload)
		}
	} else {
		wls = cached
		sort.Slice(wls, func(i, j int) bool { return wls[i].Name < wls[j].Name })
	}

	// Filter
	if len(wls) <= query.start {
		restRespSuccess(w, r, resp, acc, login, nil, "Get container list")
		return
	}

	if len(query.filters) > 0 {
		var dummy api.RESTWorkload
		rf := restNewFilter(&dummy, query.filters)

		for _, wl := range wls[query.start:] {
			if !rf.Filter(wl) {
				continue
			}

			respV1.Workloads = append(respV1.Workloads, wl)

			if query.limit > 0 && len(respV1.Workloads) >= query.limit {
				break
			}
		}
	} else if query.limit == 0 {
		respV1.Workloads = wls[query.start:]
	} else {
		var end int
		if query.start+query.limit > len(wls) {
			end = len(wls)
		} else {
			end = query.start + query.limit
		}
		respV1.Workloads = wls[query.start:end]
	}

	log.WithFields(log.Fields{"entries": len(respV1.Workloads)}).Debug("Response")

	if apiVer == "v2" {
		respV2.Workloads = make([]*api.RESTWorkloadV2, 0, len(respV1.Workloads))
		for _, wlV1 := range respV1.Workloads {
			if wlV2 := workloadV1ToV2(wlV1); wlV2 != nil {
				respV2.Workloads = append(respV2.Workloads, wlV2)
			}
		}
	}
	restRespSuccess(w, r, resp, acc, login, nil, "Get container list")
}

func handlerWorkloadList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	handlerWorkloadListBase("v1", w, r, ps)
}

func handlerWorkloadListV2(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	handlerWorkloadListBase("v2", w, r, ps)
}

func workloadDetailsV1ToV2(wlV1 *api.RESTWorkloadDetail) *api.RESTWorkloadDetailV2 {
	if wlV1 == nil {
		return nil
	}

	wlV2 := &api.RESTWorkloadDetailV2{
		RESTWorkloadV2: api.RESTWorkloadV2{
			WlBrief: api.RESTWorkloadBriefV2{
				ID:           wlV1.ID,
				Name:         wlV1.Name,
				DisplayName:  wlV1.DisplayName,
				HostName:     wlV1.HostName,
				HostID:       wlV1.HostID,
				Image:        wlV1.Image,
				ImageID:      wlV1.ImageID,
				Domain:       wlV1.Domain,
				State:        wlV1.State,
				Service:      wlV1.Service,
				Author:       wlV1.Author,
				ServiceGroup: wlV1.ServiceGroup,
			},
			WlSecurity: api.RESTWorkloadSecurityV2{
				CapSniff:           wlV1.CapSniff,
				CapQuar:            wlV1.CapQuar,
				CapChgMode:         wlV1.CapChgMode,
				ServiceMesh:        wlV1.ServiceMesh,
				ServiceMeshSidecar: wlV1.ServiceMeshSidecar,
				PolicyMode:         wlV1.PolicyMode,
				ProfileMode:        wlV1.ProfileMode,
				BaselineProfile:    wlV1.BaselineProfile,
				QuarReason:         wlV1.QuarReason,
				ScanSummary:        wlV1.ScanSummary,
			},
			WlRtAttributes: api.RESTWorkloadRtAttribesV2{
				PodName:        wlV1.PodName,
				ShareNSWith:    wlV1.ShareNSWith,
				Privileged:     wlV1.Privileged,
				RunAsRoot:      wlV1.RunAsRoot,
				Labels:         wlV1.Labels,
				MemoryLimit:    wlV1.MemoryLimit,
				CPUs:           wlV1.CPUs,
				ServiceAccount: wlV1.ServiceAccount,
				NetworkMode:    wlV1.NetworkMode,
				Ifaces:         wlV1.Ifaces,
				Ports:          wlV1.Ports,
				Applications:   wlV1.Applications,
			},
			AgentID:      wlV1.AgentID,
			AgentName:    wlV1.AgentName,
			PlatformRole: wlV1.PlatformRole,
			CreatedAt:    wlV1.CreatedAt,
			StartedAt:    wlV1.StartedAt,
			FinishedAt:   wlV1.FinishedAt,
			Running:      wlV1.Running,
			SecuredAt:    wlV1.SecuredAt,
			ExitCode:     wlV1.ExitCode,
		},
		Misc: api.RESTWorkloadDetailMiscV2{
			Groups:   wlV1.Groups,
			AppPorts: wlV1.AppPorts,
		},
	}

	wlChildrenV2 := make([]*api.RESTWorkloadDetailV2, 0, len(wlV1.Children))
	for _, cV1 := range wlV1.Children {
		if cV2 := workloadDetailsV1ToV2(cV1); cV2 != nil {
			wlChildrenV2 = append(wlChildrenV2, cV2)
		}
	}
	wlV2.Misc.Children = wlChildrenV2

	return wlV2
}

func handlerWorkloadShowBase(apiVer string, w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id := ps.ByName("id")

	query := restParseQuery(r)

	var view string
	if value, ok := query.pairs[api.QueryKeyView]; ok && value == api.QueryValueViewPod {
		view = api.QueryValueViewPod
	}

	// Retrieve the workload
	wl, err := cacher.GetWorkloadDetail(id, view, acc)
	if wl == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	var respV1 api.RESTWorkloadDetailData
	var respV2 api.RESTWorkloadDetailDataV2
	var resp interface{} = &respV2
	if apiVer == "v2" {
		respV2.Workload = workloadDetailsV1ToV2(wl)
	} else {
		respV1.Workload = wl
		resp = &respV1
	}
	restRespSuccess(w, r, resp, acc, login, nil, "Get container detail")
}

func handlerWorkloadShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	handlerWorkloadShowBase("v1", w, r, ps)
}

func handlerWorkloadShowV2(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	handlerWorkloadShowBase("v2", w, r, ps)
}

func handlerWorkloadConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id := ps.ByName("id")

	wl, err := cacher.GetWorkload(id, "", acc)
	if wl == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTWorkloadConfigCfgData
	err = json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	if rconf.Config.Quarantine != nil && *rconf.Config.Quarantine {
		if wl.ShareNSWith != "" {
			err := errors.New("Only the pod container can be quarantined")
			log.WithFields(log.Fields{"id": id}).Error(err.Error())
			restRespNotFoundLogAccessDenied(w, login, err)
			return
		}
		if wl.CapQuar == false {
			err := "Unable to quarantine the container"
			log.WithFields(log.Fields{"id": id}).Error(err)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err)
			return
		}
	}

	var cconf share.CLUSWorkloadConfig
	key := share.CLUSUniconfWorkloadKey(wl.HostID, id)

	retry := 0
	for retry < retryClusterMax {
		// Retrieve from the cluster
		value, rev, _ := cluster.GetRev(key)
		if value != nil {
			json.Unmarshal(value, &cconf)
		} else {
			cconf.Wire = share.WireDefault
		}

		if rconf.Config.Wire != nil {
			cconf.Wire = *rconf.Config.Wire
		}

		if rconf.Config.Quarantine != nil {
			cconf.Quarantine = *rconf.Config.Quarantine
			if cconf.Quarantine {
				cconf.QuarReason = share.QuarantineReasonUser
			} else {
				cconf.QuarReason = ""
			}
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
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}

	restRespSuccess(w, r, nil, acc, login, &rconf, "Configure container")
}

func handlerWorkloadGetConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id := ps.ByName("id")

	conf, err := cacher.GetWorkloadConfig(id, acc)
	if conf == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	var resp api.RESTWorkloadConfigData
	resp.Config = conf

	restRespSuccess(w, r, &resp, acc, login, nil, "Get container configuration")
}

func handlerWorkloadStats(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id := ps.ByName("id")

	agentID, err := cacher.GetAgentbyWorkload(id, acc)
	if agentID == "" {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	stats, err := rpc.GetStats(agentID, &share.CLUSFilter{Workload: id})
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrClusterRPCError, "Fail to make the RPC call")
		return
	}

	var resp api.RESTWorkloadStatsData
	resp.ID = id
	resp.ReadAt = api.RESTTimeString(time.Now())
	resp.Stats = stats2REST(stats)

	restRespSuccess(w, r, &resp, acc, login, nil, "Get container statistics")
}

func proc2REST(proc *share.CLUSProcess) *api.RESTProcessInfo {
	return &api.RESTProcessInfo{
		Name:             proc.Name,
		Pid:              proc.Pid,
		Parent:           proc.PPid,
		Group:            proc.PGid,
		Session:          proc.PSid,
		Cmdline:          utils.JoinCommand(proc.Cmds),
		Root:             proc.Root,
		User:             proc.User,
		Status:           proc.Status,
		StartAtTimeStamp: proc.StartAt,
		Action:           proc.Action,
	}
}

func handlerWorkloadProcess(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id := ps.ByName("id")

	agentID, err := cacher.GetAgentbyWorkload(id, acc)
	if agentID == "" {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	procs, err := rpc.GetProcess(agentID, id)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to make RPC call")
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrClusterRPCError, err.Error())
		return
	}

	sort.Slice(procs, func(i, j int) bool { return procs[i].StartAt < procs[j].StartAt })
	resp := api.RESTProcessList{Processes: make([]*api.RESTProcessInfo, len(procs))}
	for i, proc := range procs {
		resp.Processes[i] = proc2REST(proc)
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get container process")
}

func handlerWorkloadProcessHistory(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id := ps.ByName("id")

	agentID, err := cacher.GetAgentbyWorkload(id, acc)
	if agentID == "" {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	procs, err := rpc.GetProcessHistory(agentID, id)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to make RPC call")
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrClusterRPCError, err.Error())
		return
	}

	sort.Slice(procs, func(i, j int) bool { return procs[i].StartAt < procs[j].StartAt })
	resp := api.RESTProcessList{Processes: make([]*api.RESTProcessInfo, len(procs))}
	for i, proc := range procs {
		resp.Processes[i] = proc2REST(proc)
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get container process history")
}

func handlerWorkloadRequest(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id := ps.ByName("id")

	wl, err := cacher.GetWorkload(id, "", acc)
	if wl == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	if wl.State == api.WorkloadStateUnmanaged {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrAgentError,
			"The container is in unmanaged state now.")
		return
	}

	body, _ := io.ReadAll(r.Body)

	var req api.RESTWorkloadRequestData
	err = json.Unmarshal(body, &req)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	switch req.Request.Command {
	default:
		log.WithFields(log.Fields{"command": req.Request.Command}).Error("Unsupported command")
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Unsupported command")
		return
	}

	restRespSuccess(w, r, nil, acc, login, &req, "Container request")
}

func handlerWorkloadProcessProfile(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id := ps.ByName("id")

	agentID, err := cacher.GetAgentbyWorkload(id, acc)
	if agentID == "" {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	rules, err := rpc.GetDerivedWorkloadProcessRule(agentID, id)
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

	restRespSuccess(w, r, &resp, acc, login, nil, "Get container process profile")
}

func handlerWorkloadFileMonitorProfile(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id := ps.ByName("id")

	agentID, err := cacher.GetAgentbyWorkload(id, acc)
	if agentID == "" {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	rules, err := rpc.GetDerivedWorkloadFileRule(agentID, id)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to make RPC call")
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrClusterRPCError, err.Error())
		return
	}

	resp := api.RESTFileMonitorProfile{ // Other fields are not refer-able
		Filters: make([]*api.RESTFileMonitorFilter, len(rules)),
	}

	for i, ff := range rules {
		resp.Filters[i] = &api.RESTFileMonitorFilter{
			Filter:    ff.Filter,
			Recursive: ff.Recursive,
			Behavior:  ff.Behavior,
			Apps:      ff.Apps,
			Group:     ff.GroupName,
			CfgType:   ff.CfgType,
		}
	}
	restRespSuccess(w, r, &resp, acc, login, nil, "Get container file monitor profile")
}

/*
func handlerWorkloadLogs(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
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

	agentID, err := cacher.GetAgentbyWorkload(id, acc)
	if agentID == "" {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	data, err := rpc.GetContainerLogs(agentID, id, start, query.limit)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to make RPC call")
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrClusterRPCError, err.Error())
		return
	}

	restRespSuccess(w, r, data, acc, login, nil, "Get container log")
}
*/

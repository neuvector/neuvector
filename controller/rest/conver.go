package rest

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/rpc"
	"github.com/neuvector/neuvector/share"
)

type mcastGraphRPC = func(string, uint16, *share.CLUSGraphOps) error

func handlerConverEndpointList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
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

	var resp api.RESTConversationEndpointData
	resp.Endpoints = make([]*api.RESTConversationEndpoint, 0)

	// used for graph now, no sorting or filtering
	eps := cacher.GetAllConverEndpoints(view, acc)

	// Ignore sorting. Filter
	if len(eps) <= query.start {
		restRespSuccess(w, r, &resp, acc, login, nil, "Get endpoint list")
		return
	}

	if len(query.filters) > 0 {
		var dummy api.RESTConversationEndpoint
		rf := restNewFilter(&dummy, query.filters)

		for _, ep := range eps[query.start:] {
			if !rf.Filter(ep) {
				continue
			}

			resp.Endpoints = append(resp.Endpoints, ep)

			if query.limit > 0 && len(resp.Endpoints) >= query.limit {
				break
			}
		}
	} else if query.limit == 0 {
		resp.Endpoints = eps[query.start:]
	} else {
		var end int
		if query.start+query.limit > len(eps) {
			end = len(eps)
		} else {
			end = query.start + query.limit
		}
		resp.Endpoints = eps[query.start:end]
	}

	log.WithFields(log.Fields{"entries": len(resp.Endpoints)}).Debug("Response")

	restRespSuccess(w, r, &resp, acc, login, nil, "Get conversation endpoint list")
}

func handlerConverEndpointDelete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	//	This endpoint delete function is hidden for now.
	//	Because deleting one non-workload endpoint will delete converstaion
	//	from all other namespace to it as well, we will only allow superuser
	//  to do this operation
	if !acc.CanWriteCluster() {
		restRespAccessDenied(w, login)
		return
	}

	id := ps.ByName("id")
	if !strings.HasPrefix(id, api.LearnedHostPrefix) &&
		!strings.HasPrefix(id, api.LearnedWorkloadPrefix) {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest,
			"Only host and unmanaged container can be deleted!")
		return
	}

	ops := &share.CLUSGraphOps{Endpoint: id}
	mcastAllController(rpc.DeleteEndpoint, ops)
	restRespSuccess(w, r, nil, acc, login, nil, "Delete conversation endpoint")
}

func handlerConverEndpointConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id := ps.ByName("id")

	// For now, alias is added to graph's endpoint. Without traffic, container's endpoint is not
	// in the graph, so it cannot be renamed. Plus, there seems no reason to give a container an alias.
	if !strings.HasPrefix(id, api.LearnedHostPrefix) &&
		!strings.HasPrefix(id, api.LearnedWorkloadPrefix) {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest,
			"Only host and unmanaged container can be modified!")
		return
	}

	ep, err := cacher.GetConverEndpoint(id, acc)
	if ep == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	// Read body
	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTConversationEndpointConfigData
	err = json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	rc := rconf.Config

	if rc.DisplayName != nil {
		ops := &share.CLUSGraphOps{Endpoint: id, Alias: *rc.DisplayName}
		mcastAllController(rpc.SetEndpointAlias, ops)
	}

	restRespSuccess(w, r, nil, acc, login, &rconf, "Configure conversation endpoint")
}

func handlerConverList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	query := restParseQuery(r)

	var groupFilter, domainFilter string
	for _, f := range query.filters {
		if f.tag == api.FilterByGroup && f.op == api.OPeq {
			if exist, err := cacher.DoesGroupExist(f.value, acc); !exist {
				restRespNotFoundLogAccessDenied(w, login, err)
				return
			}

			groupFilter = f.value
		} else if f.tag == api.FilterByDomain && f.op == api.OPeq {
			domainFilter = f.value
		}
	}

	convers, endpoints := cacher.GetAllApplicationConvers(groupFilter, domainFilter, acc)

	if query.verbose {
		// This is not a normal path, will be removed after 2.2
		var resp api.RESTConversationsVerboseData
		resp.Endpoints = endpoints

		epMap := make(map[string]*api.RESTConversationEndpoint, 0)
		for _, ep := range endpoints {
			epMap[ep.ID] = ep
		}
		resp.Convers = make([]*api.RESTConversation, len(convers))
		for i, conver := range convers {
			from, ok := epMap[conver.From]
			from_brief := api.RESTWorkloadBrief{ID: conver.From}
			to, ok1 := epMap[conver.To]
			to_brief := api.RESTWorkloadBrief{ID: conver.To}
			if !ok && (ok1 && !to.ServiceMesh) {
				continue
			}
			if !ok1 && (ok && !from.ServiceMesh) {
				continue
			}
			if !ok {
				from_brief.DisplayName = "sidecar-proxy"
				from = &api.RESTConversationEndpoint{
					Kind:              api.EndpointKindContainer,
					RESTWorkloadBrief: from_brief}
			}
			if !ok1 {
				to_brief.DisplayName = "sidecar-proxy"
				to = &api.RESTConversationEndpoint{
					Kind:              api.EndpointKindContainer,
					RESTWorkloadBrief: to_brief}
			}
			resp.Convers[i] = &api.RESTConversation{
				From: from, To: to,
				RESTConversationReport: conver.RESTConversationReport,
			}
		}

		log.WithFields(log.Fields{
			"conversations": len(resp.Convers), "endpoints": len(resp.Endpoints),
		}).Debug("Response")

		restRespSuccess(w, r, &resp, acc, login, nil, "Get conversation list")
	} else {
		var resp api.RESTConversationsData
		resp.Convers = convers
		resp.Endpoints = endpoints

		log.WithFields(log.Fields{
			"conversations": len(resp.Convers), "endpoints": len(resp.Endpoints),
		}).Debug("Response")

		restRespSuccess(w, r, &resp, acc, login, nil, "Get conversation list")
	}
}

func handlerConverShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}

	from := ps.ByName("from")
	to := ps.ByName("to")

	body, _ := io.ReadAll(r.Body)

	var data api.RESTConversationQueryData
	err := json.Unmarshal(body, &data)

	var conver *api.RESTConversationDetail
	if err != nil || data.Query == nil {
		conver, err = cacher.GetApplicationConver(from, to, nil, nil, acc)
	} else {
		conver, err = cacher.GetApplicationConver(from, to, data.Query.From, data.Query.To, acc)
	}

	if conver == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	var resp api.RESTConversationsDetailData
	resp.Conver = conver

	log.WithFields(log.Fields{"entries": len(resp.Conver.Entries)}).Debug("Response")

	restRespSuccess(w, r, &resp, acc, login, nil, "Get conversation detail")
}

func handlerConverDeleteAll(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	// Only support super user for now.
	if !acc.CanWriteCluster() {
		restRespAccessDenied(w, login)
		return
	}

	ops := &share.CLUSGraphOps{}
	mcastAllController(rpc.DeleteConversation, ops)
	restRespSuccess(w, r, nil, acc, login, nil, "Delete all conversations")
}

func handlerConverDelete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	from := ps.ByName("from")
	to := ps.ByName("to")

	cached, err := cacher.GetApplicationConver(from, to, nil, nil, acc)
	if cached == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	ops := &share.CLUSGraphOps{From: from, To: to}
	mcastAllController(rpc.DeleteConversation, ops)
	restRespSuccess(w, r, nil, acc, login, nil, "Delete conversation")
}

func mcastAllController(f mcastGraphRPC, ops *share.CLUSGraphOps) {
	eps := cacher.GetAllControllerRPCEndpoints(access.NewReaderAccessControl())
	for _, ep := range eps {
		go func(ClusterIP string, RPCServerPort uint16) {
			if err := f(ClusterIP, RPCServerPort, ops); err != nil {
				log.WithFields(log.Fields{"error": err}).Error()
			}
		}(ep.ClusterIP, ep.RPCServerPort)
	}
}

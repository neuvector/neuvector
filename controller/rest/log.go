package rest

import (
	"net/http"
	"sync"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
)

func filterAndSort(data []interface{}, query *restQuery) []interface{} {
	results := make([]interface{}, 0)
	// Sort first, so don't need to filter all the data
	if len(data) > 1 {
		query.sorts = append(query.sorts, restFieldSort{tag: "reported_timestamp", asc: false})

		restNewSorter(data, query.sorts).Sort()
	}
	// filter
	if len(query.filters) > 0 && len(data) > 0 {
		for i, f := range query.filters {
			if f.tag == "since" {
				query.filters[i].tag = "reported_timestamp"
				query.filters[i].op = "gte"
			}
		}
		rf := restNewFilter(data[0], query.filters)
		for _, v := range data {
			if !rf.Filter(v) {
				continue
			}
			results = append(results, v)
			if query.limit > 0 && len(results) >= query.start+query.limit {
				break
			}
		}
	} else {
		results = data
	}
	if len(results) <= query.start {
		return make([]interface{}, 0)
	}

	if query.limit == 0 || (query.start+query.limit) > len(results) {
		return results[query.start:]
	} else {
		end := query.start + query.limit
		return results[query.start:end]
	}

}

// only CLUSEvWorkloadStart/CLUSEvWorkloadStop/CLUSEvWorkloadRemove/CLUSEvWorkloadSecured events are treated as activity
func handlerActivityList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	query := restParseQuery(r)

	if cacher.GetActivityCount(acc) <= query.start {
		resp := api.RESTEventsData{Events: make([]*api.Event, 0)}
		restRespSuccess(w, r, &resp, acc, login, nil, "Get activity list")
		return
	}

	acts := cacher.GetActivities(acc)

	var data []interface{} = make([]interface{}, len(acts))
	for i, d := range acts {
		data[i] = d
	}
	data = filterAndSort(data, query)

	resp := api.RESTEventsData{Events: make([]*api.Event, len(data))}
	for i, d := range data {
		resp.Events[i] = d.(*api.Event)
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get activity list")
}

func handlerEventList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	query := restParseQuery(r)

	if cacher.GetEventCount(login.fullname, acc) <= query.start {
		resp := api.RESTEventsData{Events: make([]*api.Event, 0)}
		restRespSuccess(w, r, &resp, acc, login, nil, "Get event list")
		return
	}

	events := cacher.GetEvents(login.fullname, acc)

	var data []interface{} = make([]interface{}, len(events))
	for i, d := range events {
		data[i] = d
	}
	data = filterAndSort(data, query)

	resp := api.RESTEventsData{Events: make([]*api.Event, len(data))}
	for i, d := range data {
		resp.Events[i] = d.(*api.Event)
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get event list")
}

func handlerSecurityList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	query := restParseQuery(r)

	var threats []*api.Threat
	var violations []*api.Violation
	var incidents []*api.Incident

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		threats = getThreatList(query, acc)
	}()
	go func() {
		defer wg.Done()
		violations = getViolationList(query, acc)
	}()
	go func() {
		defer wg.Done()
		incidents = getIncidentList(query, acc)
	}()

	wg.Wait()

	resp := api.RESTSecurityData{
		Threats: threats, Violations: violations, Incidents: incidents,
	}
	restRespSuccess(w, r, &resp, acc, login, nil, "Get security event list")
}

func getThreatList(query *restQuery, acc *access.AccessControl) []*api.Threat {
	if cacher.GetThreatCount(acc) <= query.start {
		return make([]*api.Threat, 0)
	}

	threats := cacher.GetThreats(acc)

	var data []interface{} = make([]interface{}, len(threats))
	for i, d := range threats {
		// Not to send packet for threat list
		t := *d
		t.Packet = ""
		data[i] = &t
	}
	data = filterAndSort(data, query)

	rets := make([]*api.Threat, len(data))
	for i, d := range data {
		rets[i] = d.(*api.Threat)
	}

	return rets
}

func handlerThreatList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	query := restParseQuery(r)

	resp := api.RESTThreatsData{Threats: getThreatList(query, acc)}
	restRespSuccess(w, r, &resp, acc, login, nil, "Get threat list")
}

func handlerThreatShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id := ps.ByName("id")

	threat, err := cacher.GetThreat(id, acc)
	if threat == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	resp := api.RESTThreatData{Threat: threat}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get threat detail")
}

func getViolationList(query *restQuery, acc *access.AccessControl) []*api.Violation {
	if cacher.GetViolationCount(acc) <= query.start {
		return make([]*api.Violation, 0)
	}

	violations := cacher.GetViolations(acc)

	var data []interface{} = make([]interface{}, len(violations))
	for i, d := range violations {
		data[i] = d
	}
	data = filterAndSort(data, query)

	rets := make([]*api.Violation, len(data))
	for i, d := range data {
		rets[i] = d.(*api.Violation)
	}

	return rets
}

func handlerViolationList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	query := restParseQuery(r)

	resp := api.RESTPolicyViolationsData{Violations: getViolationList(query, acc)}
	restRespSuccess(w, r, &resp, acc, login, nil, "Get violation list")
}

func getIncidentList(query *restQuery, acc *access.AccessControl) []*api.Incident {
	if cacher.GetIncidentCount(acc) <= query.start {
		return make([]*api.Incident, 0)
	}

	incidents := cacher.GetIncidents(acc)

	var data []interface{} = make([]interface{}, len(incidents))
	for i, d := range incidents {
		data[i] = d
	}
	data = filterAndSort(data, query)

	rets := make([]*api.Incident, len(data))
	for i, d := range data {
		rets[i] = d.(*api.Incident)
	}

	return rets
}

func handlerIncidentList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	query := restParseQuery(r)

	resp := api.RESTIncidentsData{Incidents: getIncidentList(query, acc)}
	restRespSuccess(w, r, &resp, acc, login, nil, "Get incident list")
}

func handlerViolationWorkloads(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	query := restParseQuery(r)
	violations := cacher.GetViolations(acc)
	resp := api.RESTPolicyViolationsWLData{ViolationWorkloads: make([]*api.RESTViolationWorkload, 0)}

	if len(violations) == 0 {
		restRespSuccess(w, r, &resp, acc, login, nil, "Get violation list by container")
		return
	}

	var client bool = false
	if len(query.sorts) != 1 {
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	} else {
		if query.sorts[0].tag == "client" {
			client = true
		} else if query.sorts[0].tag != "server" {
			restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
			return
		}
	}

	violationMap := make(map[string]*api.RESTViolationWorkload)
	for _, v := range violations {
		var wlID, wlName, wlDomain string
		if client {
			wlID = v.ClientWL
			wlName = v.ClientName
			wlDomain = v.ClientDomain
		} else {
			wlID = v.ServerWL
			wlName = v.ServerName
			wlDomain = v.ServerDomain
		}
		workload, _ := cacher.GetWorkloadBrief(wlID, "", acc)
		if workload == nil { // possible cases: access denied or the workload info is not found
			workload = &api.RESTWorkloadBrief{
				ID: wlID, Name: wlName, DisplayName: wlName, Domain: wlDomain, State: api.StateOffline,
			}
		}

		if stat, ok := violationMap[wlID]; !ok {
			violationMap[wlID] = &api.RESTViolationWorkload{
				Workload: workload,
				Count:    1,
			}
		} else {
			stat.Count++
		}
	}

	// Convert struct slice to interface slice
	var data []interface{} = make([]interface{}, len(violationMap))
	var i uint = 0
	for _, d := range violationMap {
		data[i] = d
		i++
	}
	var asc bool = query.sorts[0].asc

	sortField := []restFieldSort{{tag: "count", asc: asc}}
	restNewSorter(data, sortField).Sort()

	// Copy the result
	result := make([]*api.RESTViolationWorkload, len(data))
	for i, d := range data {
		result[i] = d.(*api.RESTViolationWorkload)
	}

	if len(result) <= query.start {
		restRespSuccess(w, r, &resp, acc, login, nil, "Get violation list by container")
		return
	}
	if query.limit == 0 {
		resp.ViolationWorkloads = result[query.start:]
	} else {
		var end int
		if query.start+query.limit > len(result) {
			end = len(result)
		} else {
			end = query.start + query.limit
		}
		resp.ViolationWorkloads = result[query.start:end]
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get violation list by container")
}

func handlerAuditList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	query := restParseQuery(r)

	if cacher.GetAuditCount(acc) <= query.start {
		resp := api.RESTAuditsData{Audits: make([]*api.Audit, 0)}
		restRespSuccess(w, r, &resp, acc, login, nil, "Get audit list")
		return
	}

	audits := cacher.GetAudits(acc)

	var data []interface{} = make([]interface{}, len(audits))
	for i, d := range audits {
		data[i] = d
	}
	data = filterAndSort(data, query)

	resp := api.RESTAuditsData{Audits: make([]*api.Audit, len(data))}
	for i, d := range data {
		resp.Audits[i] = d.(*api.Audit)
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get audit list")
}

package rest

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/rpc"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
)

func bench2REST(bench share.BenchType, item *share.CLUSBenchItem, cpf *complianceProfileFilter) *api.RESTBenchItem {
	var r *api.RESTBenchItem

	_, metaMap := scanUtils.GetComplianceMeta()

	if c, ok := metaMap[item.TestNum]; ok {
		r = &api.RESTBenchItem{
			RESTBenchCheck: c.RESTBenchCheck,
			Level:          item.Level,
			Message:        make([]string, 0),
			Group:          item.Group,
		}
	} else {
		// Could be custom check
		r = &api.RESTBenchItem{
			RESTBenchCheck: api.RESTBenchCheck{
				TestNum:     item.TestNum,
				Scored:      item.Scored,
				Profile:     item.Profile,
				Description: strings.TrimRight(item.Header, "\r\n"),
				Remediation: item.Remediation,
			},
			Level:   item.Level,
			Message: make([]string, 0),
			Group:   item.Group,
		}

		switch bench {
		case share.BenchDockerHost, share.BenchDockerContainer, share.BenchContainer:
			r.Catalog = api.BenchCatalogDocker
		case share.BenchKubeMaster, share.BenchKubeWorker:
			r.Catalog = api.BenchCatalogKube
		}
	}

	switch bench {
	case share.BenchCustomHost:
		r.Profile = "Level 1"
		r.Catalog = api.BenchCatalogCustom
		r.Type = api.BenchTypeHost
	case share.BenchCustomContainer:
		r.Profile = "Level 1"
		r.Catalog = api.BenchCatalogCustom
		r.Type = api.BenchTypeContainer
	case share.BenchContainerSecret:
		if len(item.Message) >= 3 { // type, evidence, location
			r.Evidence = item.Message[1]
			r.Location = item.Message[2]
			msg := scanUtils.GetSecretBenchMessage(item.Message[0], item.Message[2], item.Message[1])
			item.Message = []string{msg}
		}
	case share.BenchContainerSetID:
		if len(item.Message) >= 3 { // type, evidence, location
			r.Evidence = item.Message[1]
			r.Location = item.Message[2]
			msg := scanUtils.GetSetIDBenchMessage(item.Message[0], item.Message[2], item.Message[1])
			item.Message = []string{msg}
		}
	}

	for _, m := range item.Message {
		r.Message = append(r.Message, m)
	}
	if len(r.Message) > 0 {
		r.Description = fmt.Sprintf("%s - %s", r.Description, r.Message[0])
	}

	// add tags
	if tags, ok := cpf.filter[r.TestNum]; ok {
		r.Tags = tags
	} else {
		r.Tags = make([]string, 0)
	}

	return r
}

func sortBenchItems(items []*api.RESTBenchItem) []*api.RESTBenchItem {
	sort.Slice(items, func(s, t int) bool {
		if items[s].Catalog != api.BenchCatalogCustom && items[t].Catalog != api.BenchCatalogCustom {
			return items[s].TestNum < items[t].TestNum
		}
		if items[s].Catalog == api.BenchCatalogCustom && items[t].Catalog == api.BenchCatalogCustom {
			return items[s].TestNum < items[t].TestNum
		}
		// custom check on the top
		return items[s].Catalog == api.BenchCatalogCustom
	})
	return items
}

func handlerDockerBenchRun(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
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
	}

	err = rpc.RunDockerBench(agents[0])
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to make RPC call")
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrClusterRPCError, err.Error())
		return
	}

	restRespSuccess(w, r, nil, acc, login, nil, "Run Docker benchmark")
}

func handlerDockerBench(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}

	id := ps.ByName("id")

	host, err := cacher.GetHost(id, acc)
	if host == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	cpf := &complianceProfileFilter{filter: make(map[string][]string), object: host}
	if cp, filter, err := cacher.GetComplianceProfile(share.DefaultComplianceProfileName, access.NewReaderAccessControl()); err != nil {
		log.WithFields(log.Fields{"profile": share.DefaultComplianceProfileName}).Error("Compliance profile not found")
	} else {
		cpf = &complianceProfileFilter{disableSystem: cp.DisableSystem, filter: filter, object: host}
	}

	rpt, errCode, msg := getCISReportFromCluster(share.BenchDockerHost, id, cpf, acc)
	// check the kubernetes status
	if errCode != 0 {
		if msg != "" {
			restRespErrorMessage(w, http.StatusInternalServerError, errCode, msg)
		} else {
			restRespError(w, http.StatusInternalServerError, errCode)
		}
		return
	}

	if rpt == nil {
		resp := api.RESTBenchReport{Items: make([]*api.RESTBenchItem, 0)}
		restRespSuccess(w, r, &resp, acc, login, nil, msg)
		return
	} else {
		restRespSuccess(w, r, &rpt, acc, login, nil, msg)
	}
}

func handlerKubeBenchRun(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
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
	}

	err = rpc.RunKubernetesBench(agents[0])
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Fail to make RPC call")
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrClusterRPCError, err.Error())
		return
	}

	restRespSuccess(w, r, nil, acc, login, nil, "Run Kubernetes benchmark")
}

func handlerKubeBench(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}

	id := ps.ByName("id")

	host, err := cacher.GetHost(id, acc)
	if host == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	cpf := &complianceProfileFilter{filter: make(map[string][]string), object: host}
	if cp, filter, err := cacher.GetComplianceProfile(share.DefaultComplianceProfileName, access.NewReaderAccessControl()); err != nil {
		log.WithFields(log.Fields{"profile": share.DefaultComplianceProfileName}).Error("Compliance profile not found")
	} else {
		cpf = &complianceProfileFilter{disableSystem: cp.DisableSystem, filter: filter, object: host}
	}

	rpt, errCode, msg := getKubeCISReportFromCluster(id, cpf, acc)
	// check the kubernetes status
	if errCode != 0 {
		if msg != "" {
			restRespErrorMessage(w, http.StatusInternalServerError, errCode, msg)
		} else {
			restRespError(w, http.StatusInternalServerError, errCode)
		}
		return
	}

	if rpt == nil {
		resp := api.RESTBenchReport{Items: make([]*api.RESTBenchItem, 0)}
		restRespSuccess(w, r, &resp, acc, login, nil, msg)
		return
	} else {
		restRespSuccess(w, r, &rpt, acc, login, nil, msg)
	}
}

func handlerCustomCheckConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	group := ps.ByName("group")

	if !cacher.AuthorizeCustomCheck(group, acc) {
		restRespAccessDenied(w, login)
		return
	}

	body, _ := ioutil.ReadAll(r.Body)

	var rconf api.RESTCustomCheckConfigData
	err := json.Unmarshal(body, &rconf)
	config := rconf.Config
	if err != nil || config == nil ||
		(config.Add == nil && config.Del == nil && config.Update == nil) {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Acquire lock error")
		return
	}
	defer clusHelper.ReleaseLock(lock)

	// Authz is based on groups
	cgroup, err := cacher.GetGroupBrief(group, false, acc)
	if err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	} else if cgroup.CfgType == api.CfgTypeGround {
		restRespError(w, http.StatusBadRequest, api.RESTErrOpNotAllowed)
		return
	} else if cgroup.Kind != share.GroupKindContainer && cgroup.Kind != share.GroupKindNode {
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	oldConfig, rev := clusHelper.GetCustomCheckConfig(group)
	if oldConfig == nil {
		oldConfig = &share.CLUSCustomCheckGroup{}
	}

	// delete
	if config.Del != nil {
		for _, script := range config.Del.Scripts {
			found := false
			for i, scr := range oldConfig.Scripts {
				if script.Name == scr.Name {
					oldConfig.Scripts = append(oldConfig.Scripts[:i], oldConfig.Scripts[i+1:]...)
					found = true
					break
				}
			}
			if !found {
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Script not found")
				return
			}
		}
	}
	// add
	if config.Add != nil {
		for _, script := range config.Add.Scripts {
			for _, scr := range oldConfig.Scripts {
				if script.Name == scr.Name {
					log.WithFields(log.Fields{"name": script.Name}).Error("Duplicate script name")
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Duplicate script name")
					return
				}
			}
			if !isObjectNameValid(script.Name) {
				log.WithFields(log.Fields{"name": script.Name}).Error("Invalid characters in the script name")
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Invalid characters in the script name")
				return
			}
			scp := &share.CLUSCustomCheck{
				Name:   script.Name,
				Script: script.Script,
			}
			oldConfig.Scripts = append(oldConfig.Scripts, scp)
		}
	}
	// update
	if config.Update != nil {
		for _, script := range config.Update.Scripts {
			found := false
			for i, scr := range oldConfig.Scripts {
				if script.Name == scr.Name {
					oldConfig.Scripts[i].Script = script.Script
					found = true
					break
				}
			}
			if !found {
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Script not found")
				return
			}
		}
	}
	// Write access rule
	if err := clusHelper.PutCustomCheckConfig(group, oldConfig, rev); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Write cluster fail")
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}

	restRespSuccess(w, r, nil, acc, login, body, "Configure bench script config")
}

func handlerCustomCheckShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	// Authz is based on groups

	group := ps.ByName("group")

	if !cacher.AuthorizeCustomCheck(group, acc) {
		restRespAccessDenied(w, login)
		return
	}

	oldConfig, _ := clusHelper.GetCustomCheckConfig(group)
	if oldConfig == nil {
		restRespNotFoundLogAccessDenied(w, login, fmt.Errorf("script config not found"))
		return
	}

	config := api.RESTCustomChecks{Group: group}
	for _, script := range oldConfig.Scripts {
		scp := &api.RESTCustomCheck{
			Name:   script.Name,
			Script: script.Script,
		}
		config.Scripts = append(config.Scripts, scp)
	}
	resp := api.RESTCustomCheckData{Config: &config}
	restRespSuccess(w, r, &resp, acc, login, nil, "Get bench script config")
}

func handlerCustomCheckList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	scripts := clusHelper.GetAllCustomCheckConfig()

	configs := make([]*api.RESTCustomChecks, 0)
	for group, script := range scripts {
		if !cacher.AuthorizeCustomCheck(group, acc) {
			continue
		}
		config := api.RESTCustomChecks{Group: group}
		for _, scr := range script.Scripts {
			scp := &api.RESTCustomCheck{
				Name:   scr.Name,
				Script: scr.Script,
			}
			config.Scripts = append(config.Scripts, scp)
		}
		configs = append(configs, &config)
	}
	sort.Slice(configs, func(i, j int) bool { return configs[i].Group < configs[j].Group })
	resp := api.RESTCustomCheckListData{Configs: configs}
	restRespSuccess(w, r, &resp, acc, login, nil, "Get bench script config list")
}

func handlerContainerCompliance(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}

	id := ps.ByName("id")

	wl, err := cacher.GetWorkloadRisk(id, acc)
	if wl == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	cpf := &complianceProfileFilter{filter: make(map[string][]string), object: wl}
	if cp, filter, err := cacher.GetComplianceProfile(share.DefaultComplianceProfileName, access.NewReaderAccessControl()); err != nil {
		log.WithFields(log.Fields{"profile": share.DefaultComplianceProfileName}).Error("Compliance profile not found")
	} else {
		cpf = &complianceProfileFilter{disableSystem: cp.DisableSystem, filter: filter, object: wl}
	}

	var ts int64
	var runAt string
	var dockerVer string
	items := make([]*api.RESTBenchItem, 0)

	// custom check
	if rpt, _, _ := getCISReportFromCluster(share.BenchCustomContainer, id, cpf, acc); rpt != nil {
		items = append(items, rpt.Items...)
		if rpt.RunAtTimeStamp > ts {
			ts = rpt.RunAtTimeStamp
			runAt = rpt.RunAt
		}
	}

	// docker bench
	if rpt, _, _ := getCISReportFromCluster(share.BenchContainer, id, cpf, acc); rpt != nil {
		dockerVer = rpt.Version
		items = append(items, rpt.Items...)
		if rpt.RunAtTimeStamp > ts {
			ts = rpt.RunAtTimeStamp
			runAt = rpt.RunAt
		}
	}

	// secrets bench
	if rpt, _, _ := getCISReportFromCluster(share.BenchContainerSecret, id, cpf, acc); rpt != nil {
		items = append(items, rpt.Items...)
		if rpt.RunAtTimeStamp > ts {
			ts = rpt.RunAtTimeStamp
			runAt = rpt.RunAt
		}
	}

	// setuid, setgid bench
	if rpt, _, _ := getCISReportFromCluster(share.BenchContainerSetID, id, cpf, acc); rpt != nil {
		items = append(items, rpt.Items...)
		if rpt.RunAtTimeStamp > ts {
			ts = rpt.RunAtTimeStamp
			runAt = rpt.RunAt
		}
	}

	var data api.RESTComplianceData
	if len(wl.Children) > 0 {
		// ignore pod compliance checks
		data = api.RESTComplianceData{
			RunAtTimeStamp: ts, RunAt: runAt, DockerVersion: dockerVer, Items: []*api.RESTBenchItem{},
		}
	} else {
		items = sortBenchItems(items)
		data = api.RESTComplianceData{
			RunAtTimeStamp: ts, RunAt: runAt, DockerVersion: dockerVer, Items: items,
		}
	}
	restRespSuccess(w, r, &data, acc, login, nil, "Get container compliance report")
}

func handlerHostCompliance(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}

	id := ps.ByName("id")

	host, err := cacher.GetHost(id, acc)
	if host == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	cpf := &complianceProfileFilter{filter: make(map[string][]string), object: host}
	if cp, filter, err := cacher.GetComplianceProfile(share.DefaultComplianceProfileName, access.NewReaderAccessControl()); err != nil {
		log.WithFields(log.Fields{"profile": share.DefaultComplianceProfileName}).Error("Compliance profile not found")
	} else {
		cpf = &complianceProfileFilter{disableSystem: cp.DisableSystem, filter: filter, object: host}
	}

	var ts int64
	var runAt string
	var dockerVer, kubeVer string
	items := make([]*api.RESTBenchItem, 0)

	if rpt, _, _ := getCISReportFromCluster(share.BenchCustomHost, id, cpf, acc); rpt != nil {
		items = append(items, rpt.Items...)
		if rpt.RunAtTimeStamp > ts {
			ts = rpt.RunAtTimeStamp
			runAt = rpt.RunAt
		}
	}
	if rpt, _, _ := getCISReportFromCluster(share.BenchDockerHost, id, cpf, acc); rpt != nil {
		dockerVer = rpt.Version
		items = append(items, rpt.Items...)
		if rpt.RunAtTimeStamp > ts {
			ts = rpt.RunAtTimeStamp
			runAt = rpt.RunAt
		}
	}
	if rpt, _, _ := getKubeCISReportFromCluster(id, cpf, acc); rpt != nil {
		kubeVer = rpt.Version
		items = append(items, rpt.Items...)
		if rpt.RunAtTimeStamp > ts {
			ts = rpt.RunAtTimeStamp
			runAt = rpt.RunAt
		}
	}

	items = sortBenchItems(items)
	data := api.RESTComplianceData{
		RunAtTimeStamp: ts, RunAt: runAt, KubeVersion: kubeVer, DockerVersion: dockerVer, Items: items,
	}
	restRespSuccess(w, r, &data, acc, login, nil, "Get host compliance report")
}

func _getCISReportFromCluster(bench share.BenchType, id string, readData bool, cpf *complianceProfileFilter) (*api.RESTBenchReport, int, string) {
	key := share.CLUSBenchReportKey(id, bench)

	var r share.CLUSBenchReport
	if value, err := cluster.Get(key); err != nil || len(value) == 0 {
		// not all bench type exist, for example custom check, so use INFO level debug
		log.WithFields(log.Fields{"error": err, "key": key}).Info("Benchmark report not found")
		return nil, api.RESTErrFailReadCluster, "Failed to read benchmark report"
	} else {
		uzb := utils.GunzipBytes(value)
		if uzb == nil {
			log.Error("Failed to unzip benchmark report")
			return nil, api.RESTErrCISBenchError, "Failed to unzip benchmark report"
		}
		if err = json.Unmarshal(uzb, &r); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to unmarshal report")
			return nil, api.RESTErrClusterWrongData, "Failed to unmarshal report"
		}
	}

	if r.Status == share.BenchStatusScheduled || r.Status == share.BenchStatusRunning {
		log.Info("Benchmark is running")
		return nil, api.RESTErrObjectInuse, "Benchmark is running"
	} else if r.Status > share.BenchStatusFinished {
		errMsg := utils.BenchStatusToStr(r.Status)
		log.WithFields(log.Fields{"key": key, "error": errMsg}).Error("Benchmark error")
		return nil, api.RESTErrCISBenchError, errMsg
	}

	if !readData {
		return nil, 0, utils.BenchStatusToStr(share.BenchStatusFinished)
	}

	rpt := api.RESTBenchReport{
		RunAtTimeStamp: r.RunAt.Unix(),
		RunAt:          api.RESTTimeString(r.RunAt),
		Version:        r.Version,
		Items:          make([]*api.RESTBenchItem, 0),
	}

	// Add check tags
	for _, item := range r.Items {
		if ritem := bench2REST(bench, item, cpf); ritem != nil {
			rpt.Items = append(rpt.Items, ritem)
		}
	}

	return &rpt, 0, utils.BenchStatusToStr(share.BenchStatusFinished)
}

func getCISStatusFromCluster(bench share.BenchType, id string) (int, string) {
	_, code, errMsg := _getCISReportFromCluster(bench, id, false, nil)
	return code, errMsg
}

func getCISReportFromCluster(bench share.BenchType, id string, cpf *complianceProfileFilter, acc *access.AccessControl) (*api.RESTBenchReport, int, string) {
	rpt, code, errMsg := _getCISReportFromCluster(bench, id, true, cpf)
	if code == 0 {
		rpt.Items = filterComplianceChecks(rpt.Items, cpf)
	}
	return rpt, code, errMsg
}

func getKubeCISReportFromCluster(id string, cpf *complianceProfileFilter, acc *access.AccessControl) (*api.RESTBenchReport, int, string) {
	rpt1, code, errMsg := getCISReportFromCluster(share.BenchKubeMaster, id, cpf, acc)
	if code != 0 {
		// Ignore the error in the master node as some nodes are not master. (BenchStatusNotSupport)
	}
	rpt2, code, errMsg := getCISReportFromCluster(share.BenchKubeWorker, id, cpf, acc)
	if code != 0 {
		return nil, code, errMsg
	}

	if rpt1 == nil || len(rpt1.Items) == 0 {
		return rpt2, 0, ""
	} else {
		for _, item := range rpt2.Items {
			rpt1.Items = append(rpt1.Items, item)
		}

		return rpt1, 0, ""
	}
}

func decodeCISReport(bench share.BenchType, value []byte, cpf *complianceProfileFilter) *api.RESTBenchReport {
	var r share.CLUSBenchReport

	if len(value) == 0 {
		return nil
	} else {
		uzb := utils.GunzipBytes(value)
		if uzb == nil {
			log.Error("Failed to unzip benchmark report")
			return nil
		}
		if err := json.Unmarshal(uzb, &r); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to unmarshal report")
			return nil
		}
	}

	if r.Status != share.BenchStatusIdle && r.Status != share.BenchStatusFinished {
		return nil
	}

	rpt := api.RESTBenchReport{
		RunAtTimeStamp: r.RunAt.Unix(),
		RunAt:          api.RESTTimeString(r.RunAt),
		Version:        r.Version,
		Items:          make([]*api.RESTBenchItem, 0),
	}

	// Add check tags
	for _, item := range r.Items {
		if ritem := bench2REST(bench, item, cpf); ritem != nil {
			rpt.Items = append(rpt.Items, ritem)
		}
	}

	rpt.Items = filterComplianceChecks(rpt.Items, cpf)

	return &rpt

}

type compAsset struct {
	Name        string
	Catalog     string
	Type        string
	Level       string
	Scored      bool
	Profile     string
	Description string
	Message     []string
	Remediation string
	Group       string
	Tags        []string
	wls         []api.RESTIDName
	nodes       []api.RESTIDName
	images      []api.RESTIDName
	platforms   []api.RESTIDName
}

func addCompAsset(all map[string]*compAsset, comp *api.RESTBenchItem) *compAsset {
	ca, ok := all[comp.TestNum]
	if !ok {
		ca = &compAsset{
			Name:        comp.TestNum,
			Catalog:     comp.Catalog,
			Type:        comp.Type,
			Level:       comp.Level,
			Scored:      comp.Scored,
			Profile:     comp.Profile,
			Description: comp.Description,
			Message:     comp.Message,
			Remediation: comp.Remediation,
			Group:       comp.Group,
			Tags:        comp.Tags,
			wls:         make([]api.RESTIDName, 0),
			nodes:       make([]api.RESTIDName, 0),
			images:      make([]api.RESTIDName, 0),
			platforms:   make([]api.RESTIDName, 0),
		}
		all[comp.TestNum] = ca
	} else {
		// Replace "custom check failed" message
		if strings.HasPrefix(ca.Description, share.CustomScriptFailedPrefix) {
			ca.Description = comp.Description
		}
	}
	return ca
}

func handlerAssetCompliance(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		resp := &api.RESTComplianceAssetData{Compliances: make([]*api.RESTComplianceAsset, 0)}
		restRespSuccess(w, r, resp, acc, login, nil, "Get compliance asset report")
		return
	}

	cpf := &complianceProfileFilter{filter: make(map[string][]string)}
	if cp, filter, err := cacher.GetComplianceProfile(share.DefaultComplianceProfileName, access.NewReaderAccessControl()); err != nil {
		log.WithFields(log.Fields{"profile": share.DefaultComplianceProfileName}).Error("Compliance profile not found")
	} else {
		cpf = &complianceProfileFilter{disableSystem: cp.DisableSystem, filter: filter}
	}

	img2mode := make(map[string]string)
	all := make(map[string]*compAsset)
	kubeVers := utils.NewSet()
	dockerVers := utils.NewSet()

	pods := cacher.GetAllWorkloadsRisk(acc)
	for _, pod := range pods {
		// Skip pod in kubernetes; if no child, show the parent (native docker)
		if len(pod.Children) == 0 {
			pod.Children = append(pod.Children, pod)
		}

		for _, wl := range pod.Children {
			setImagePolicyMode(img2mode, wl.ImageID, wl.PolicyMode)

			cpf.object = wl
			if rpt, _, _ := getCISReportFromCluster(share.BenchCustomContainer, wl.ID, cpf, acc); rpt != nil {
				for _, item := range rpt.Items {
					if item.Level != "PASS" && item.Level != "NOTE" {
						va := addCompAsset(all, item)
						va.wls = append(va.wls, api.RESTIDName{
							ID:          wl.ID,
							DisplayName: wl.Name,
							PolicyMode:  wl.PolicyMode,
							Domains:     []string{wl.Domain},
						})
					}
				}
			}

			if rpt, _, _ := getCISReportFromCluster(share.BenchContainer, wl.ID, cpf, acc); rpt != nil {
				for _, item := range rpt.Items {
					if item.Level != "PASS" && item.Level != "NOTE" {
						va := addCompAsset(all, item)
						va.wls = append(va.wls, api.RESTIDName{
							ID:          wl.ID,
							DisplayName: wl.Name,
							PolicyMode:  wl.PolicyMode,
							Domains:     []string{wl.Domain},
						})
					}
				}
			}

			if rpt, _, _ := getCISReportFromCluster(share.BenchContainerSecret, wl.ID, cpf, acc); rpt != nil {
				for _, item := range rpt.Items {
					if item.Level != "PASS" && item.Level != "NOTE" {
						va := addCompAsset(all, item)
						va.wls = append(va.wls, api.RESTIDName{
							ID:          wl.ID,
							DisplayName: wl.Name,
							PolicyMode:  wl.PolicyMode,
							Domains:     []string{wl.Domain},
						})
					}
				}
			}

			if rpt, _, _ := getCISReportFromCluster(share.BenchContainerSetID, wl.ID, cpf, acc); rpt != nil {
				for _, item := range rpt.Items {
					if item.Level != "PASS" && item.Level != "NOTE" {
						va := addCompAsset(all, item)
						va.wls = append(va.wls, api.RESTIDName{
							ID:          wl.ID,
							DisplayName: wl.Name,
							PolicyMode:  wl.PolicyMode,
							Domains:     []string{wl.Domain},
						})
					}
				}
			}
		}
	}

	if acc.HasGlobalPermissions(share.PERMS_COMPLIANCE, 0) {
		nodes := cacher.GetAllHosts(acc)
		for _, n := range nodes {
			cpf.object = n
			if rpt, _, _ := getCISReportFromCluster(share.BenchCustomHost, n.ID, cpf, acc); rpt != nil {
				for _, item := range rpt.Items {
					if item.Level != "PASS" && item.Level != "NOTE" {
						ca := addCompAsset(all, item)
						ca.nodes = append(ca.nodes, api.RESTIDName{
							ID:          n.ID,
							DisplayName: n.Name,
							PolicyMode:  n.PolicyMode,
							Domains:     nil,
						})
					}
				}
			}
			if rpt, _, _ := getCISReportFromCluster(share.BenchDockerHost, n.ID, cpf, acc); rpt != nil {
				dockerVers.Add(rpt.Version)
				for _, item := range rpt.Items {
					if item.Level != "PASS" && item.Level != "NOTE" {
						ca := addCompAsset(all, item)
						ca.nodes = append(ca.nodes, api.RESTIDName{
							ID:          n.ID,
							DisplayName: n.Name,
							PolicyMode:  n.PolicyMode,
							Domains:     nil,
						})
					}
				}
			}
			if rpt, _, _ := getKubeCISReportFromCluster(n.ID, cpf, acc); rpt != nil {
				kubeVers.Add(rpt.Version)
				for _, item := range rpt.Items {
					if item.Level != "PASS" && item.Level != "NOTE" {
						ca := addCompAsset(all, item)
						ca.nodes = append(ca.nodes, api.RESTIDName{
							ID:          n.ID,
							DisplayName: n.Name,
							PolicyMode:  n.PolicyMode,
							Domains:     nil,
						})
					}
				}
			}
		}
	}

	registries := scanner.GetAllRegistrySummary(acc)
	for _, reg := range registries {
		images := scanner.GetRegistryImageSummary(reg.Name, nil, acc)
		for _, image := range images {
			rpt, _ := scanner.GetRegistryImageReport(reg.Name, image.ImageID, nil, "", acc)
			if rpt != nil {
				cpf.object = image
				checks := scanUtils.ImageBench2REST(rpt.Cmds, rpt.Secrets, rpt.SetIDs, cpf.filter)
				checks = filterComplianceChecks(checks, cpf)
				for _, item := range checks {
					if item.Level != "PASS" && item.Level != "NOTE" {
						ca := addCompAsset(all, item)

						// If one of workload/node is in discover mode, then the image is in discover mode; and so on.
						// Policy mode is empty if the image is not used.
						pm, _ := img2mode[image.ImageID]
						ca.images = append(ca.images, api.RESTIDName{
							ID:          image.ImageID,
							DisplayName: fmt.Sprintf("%s:%s", image.Repository, image.Tag),
							PolicyMode:  pm,
							Domains:     nil,
						})
					}
				}
			}
		}
	}

	var i int
	var exists utils.Set
	list := make([]*api.RESTComplianceAsset, len(all))
	for _, comp := range all {
		va := &api.RESTComplianceAsset{
			Name:        comp.Name,
			Catalog:     comp.Catalog,
			Type:        comp.Type,
			Level:       comp.Level,
			Scored:      comp.Scored,
			Profile:     comp.Profile,
			Description: comp.Description,
			Message:     comp.Message,
			Remediation: comp.Remediation,
			Group:       comp.Group,
			Tags:        comp.Tags,
			Workloads:   make([]api.RESTIDName, 0),
			Nodes:       make([]api.RESTIDName, 0),
			Images:      make([]api.RESTIDName, 0),
			Platforms:   make([]api.RESTIDName, 0),
		}

		// Not to sort these lists to save some CPU cycles
		exists = utils.NewSet()
		for _, v := range comp.wls {
			if !exists.Contains(v.ID) {
				va.Workloads = append(va.Workloads, v)
				exists.Add(v.ID)
			}
		}

		exists = utils.NewSet()
		for _, v := range comp.nodes {
			if !exists.Contains(v.ID) {
				va.Nodes = append(va.Nodes, v)
				exists.Add(v.ID)
			}
		}

		exists = utils.NewSet()
		for _, v := range comp.images {
			if !exists.Contains(v.ID) {
				va.Images = append(va.Images, v)
				exists.Add(v.ID)
			}
		}

		exists = utils.NewSet()
		for _, v := range comp.platforms {
			if !exists.Contains(v.ID) {
				va.Platforms = append(va.Platforms, v)
				exists.Add(v.ID)
			}
		}

		list[i] = va
		i++
	}

	sort.Slice(list, func(s, t int) bool {
		if list[s].Catalog != api.BenchCatalogCustom && list[t].Catalog != api.BenchCatalogCustom {
			return list[s].Name < list[t].Name
		}
		if list[s].Catalog == api.BenchCatalogCustom && list[t].Catalog == api.BenchCatalogCustom {
			return list[s].Name < list[t].Name
		}
		// custom check on the top
		return list[s].Catalog == api.BenchCatalogCustom
	})

	resp := &api.RESTComplianceAssetData{
		Compliances:   list,
		KubeVersion:   getNewestVersion(kubeVers),
		DockerVersion: getNewestVersion(dockerVers),
	}

	log.WithFields(log.Fields{"entries": len(resp.Compliances)}).Debug("Response")
	restRespSuccess(w, r, resp, acc, login, nil, "Get compliance asset report")
}

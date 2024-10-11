package rest

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/rpc"
	"github.com/neuvector/neuvector/db"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
)

func handlerScannerList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	var resp api.RESTScannerData
	resp.Scanners = cacher.GetAllScanners(acc)
	sort.Slice(resp.Scanners, func(i, j int) bool { return resp.Scanners[i].ID < resp.Scanners[j].ID })

	log.WithFields(log.Fields{"entries": len(resp.Scanners)}).Debug("Response")
	restRespSuccess(w, r, &resp, acc, login, nil, "Get scanner list")
}

func handlerScanConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	if !licenseAllowScan() {
		restRespError(w, http.StatusBadRequest, api.RESTErrLicenseFail)
		return
	}

	body, _ := io.ReadAll(r.Body)

	var sconf api.RESTScanConfigData
	err := json.Unmarshal(body, &sconf)
	if err != nil || sconf.Config == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	cconf := &share.CLUSScanConfig{AutoScan: sconf.Config.AutoScan}

	if !acc.Authorize(cconf, nil) {
		restRespAccessDenied(w, login)
		return
	}

	value, _ := json.Marshal(cconf)
	if err := cluster.Put(share.CLUSConfigScanKey, value); err != nil {
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
	} else {
		restRespSuccess(w, r, nil, acc, login, nil, "Configure scan settings")
	}
}

func handlerScanConfigGet(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	cfg, err := cacher.GetScanConfig(acc)
	if cfg == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	resp := &api.RESTScanConfigData{Config: cfg}
	restRespSuccess(w, r, resp, acc, login, nil, "Get scan setting")
}

func handlerScanWorkloadReq(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id := ps.ByName("id")

	if !licenseAllowScan() {
		restRespError(w, http.StatusBadRequest, api.RESTErrLicenseFail)
		return
	}

	if err := cacher.ScanWorkload(id, acc); err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	restRespSuccess(w, r, nil, acc, login, nil, "Scan container")
}

func handlerScanHostReq(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
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

	if !licenseAllowScan() {
		restRespError(w, http.StatusBadRequest, api.RESTErrLicenseFail)
		return
	}

	if err := cacher.ScanHost(id, acc); err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	restRespSuccess(w, r, nil, acc, login, nil, "Scan node")
}

func handlerScanPlatformReq(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}

	if !licenseAllowScan() {
		restRespError(w, http.StatusBadRequest, api.RESTErrLicenseFail)
		return
	}

	if err := cacher.ScanPlatform(acc); err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	restRespSuccess(w, r, nil, acc, login, nil, "Scan platform")
}

func handlerScanStatus(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	status, err := cacher.GetScanStatus(acc)
	if status == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	resp := &api.RESTScanStatusData{Status: status}
	restRespSuccess(w, r, resp, acc, login, nil, "Get scan status")
}

func handlerScanWorkloadReport(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id := ps.ByName("id")

	query := restParseQuery(r)

	var showTag string
	if value, ok := query.pairs[api.QueryKeyShow]; ok && value == api.QueryValueShowAccepted {
		showTag = api.QueryValueShowAccepted
	}

	err := cacher.CanAccessWorkload(id, acc)
	if err == common.ErrObjectAccessDenied {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	var resp *api.RESTScanReportData

	vuls, modules, _ := cacher.GetVulnerabilityReport(id, showTag)
	if vuls == nil {
		// Return an empty list if workload has not been scanned
		resp = &api.RESTScanReportData{Report: &api.RESTScanReport{
			Vuls: make([]*api.RESTVulnerability, 0), Modules: modules,
		}}
	} else {
		resp = &api.RESTScanReportData{Report: &api.RESTScanReport{Vuls: vuls, Modules: modules}}
	}

	restRespSuccess(w, r, resp, acc, login, nil, "Get container scan report")
}

func handlerScanImageReport(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	id := ps.ByName("id")

	query := restParseQuery(r)

	var showTag string
	if value, ok := query.pairs[api.QueryKeyShow]; ok && value == api.QueryValueShowAccepted {
		showTag = api.QueryValueShowAccepted
	}

	cached := cacher.GetAllWorkloadsBrief("", acc)

	var brief *api.RESTWorkloadBrief
	for _, wl := range cached {
		if wl.ImageID == id && wl.ScanSummary != nil && wl.ScanSummary.Status == api.ScanStatusFinished {
			brief = wl
			break
		}
	}

	if brief == nil {
		restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
	} else {
		vuls, _, err := cacher.GetVulnerabilityReport(brief.ID, showTag)
		if vuls == nil {
			restRespNotFoundLogAccessDenied(w, login, err)
			return
		}

		resp := &api.RESTScanReportData{Report: &api.RESTScanReport{Vuls: vuls}}
		restRespSuccess(w, r, resp, acc, login, nil, "Get image scan report")
	}
}

func handlerScanImageSummary(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	query := restParseQuery(r)
	if len(query.sorts) == 0 {
		query.sorts = append(query.sorts, restFieldSort{tag: "image", asc: true})
	}

	cached := cacher.GetAllWorkloadsBrief("", acc)

	// remove duplicate results for the same image
	var imageMap map[string]*api.RESTScanImageSummary = make(map[string]*api.RESTScanImageSummary)
	for _, wl := range cached {
		if wl.ScanSummary == nil || wl.ScanSummary.Status != api.ScanStatusFinished {
			continue
		}

		if !acc.Authorize(&share.CLUSWorkloadScanDummy{Domain: wl.Domain}, nil) {
			continue
		}

		w := wl.ScanSummary

		old, ok := imageMap[wl.ImageID]
		if !ok || old.HighVuls < w.HighVuls || (old.HighVuls == w.HighVuls && old.MedVuls < w.MedVuls) {
			img := api.RESTScanImageSummary{
				Image:         wl.Image,
				ImageID:       wl.ImageID,
				RESTScanBrief: *w,
			}
			imageMap[wl.ImageID] = &img
		}
	}

	// Sort
	var result []*api.RESTScanImageSummary
	if len(imageMap) > 1 && len(query.sorts) > 0 {
		// Convert struct slice to interface slice
		var data []interface{} = make([]interface{}, len(imageMap))
		var i int = 0
		for _, d := range imageMap {
			data[i] = d
			i++
		}

		var hasSeverity bool = false
		var asc bool = false
		for i, s := range query.sorts {
			if s.tag == "severity" {
				query.sorts[i].tag = "high"
				hasSeverity = true
				asc = s.asc
				break
			}
		}
		// add medium and name as additional sorting criteria
		if hasSeverity {
			query.sorts = append(query.sorts, restFieldSort{tag: "medium", asc: asc})
			query.sorts = append(query.sorts, restFieldSort{tag: "image", asc: true})
			log.WithFields(log.Fields{"sorts": query.sorts}).Debug("")
		}
		// Sort
		restNewSorter(data, query.sorts).Sort()

		// Copy the result
		result = make([]*api.RESTScanImageSummary, len(data))
		for i, d := range data {
			result[i] = d.(*api.RESTScanImageSummary)
		}
	} else {
		var i int = 0
		result = make([]*api.RESTScanImageSummary, len(imageMap))
		for _, d := range imageMap {
			result[i] = d
			i++
		}
	}

	// Filter
	if len(result) <= query.start {
		result = make([]*api.RESTScanImageSummary, 0)
		goto exit
	}

	if len(query.filters) > 0 {
		var dummy api.RESTScanImageSummary
		rf := restNewFilter(&dummy, query.filters)
		result2 := make([]*api.RESTScanImageSummary, 0)
		for _, status := range result[query.start:] {
			if !rf.Filter(status) {
				continue
			}

			result2 = append(result2, status)

			if query.limit > 0 && len(result2) >= query.limit {
				break
			}
		}
		result = result2
	} else if query.limit == 0 {
		result = result[query.start:]
	} else {
		var end int
		if query.start+query.limit > len(result) {
			end = len(result)
		} else {
			end = query.start + query.limit
		}
		result = result[query.start:end]
	}

exit:
	log.WithFields(log.Fields{"entries": len(result)}).Debug("Response")

	reply := &api.RESTScanImageSummaryData{Summary: result}
	restRespSuccess(w, r, reply, acc, login, nil, "Get image scan summary")
}

func handlerScanHostReport(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
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

	query := restParseQuery(r)

	var showTag string
	if value, ok := query.pairs[api.QueryKeyShow]; ok && value == api.QueryValueShowAccepted {
		showTag = api.QueryValueShowAccepted
	}

	err := cacher.CanAccessHost(id, acc)
	if err == common.ErrObjectAccessDenied {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	var resp *api.RESTScanReportData

	vuls, _, _ := cacher.GetVulnerabilityReport(id, showTag)
	if vuls == nil {
		// Return an empty list if node has not been scanned
		resp = &api.RESTScanReportData{Report: &api.RESTScanReport{
			Vuls: make([]*api.RESTVulnerability, 0),
		}}
	} else {
		resp = &api.RESTScanReportData{Report: &api.RESTScanReport{Vuls: vuls}}
	}

	restRespSuccess(w, r, resp, acc, login, nil, "Get host scan report")
}

func handlerScanPlatformReport(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasGlobalPermissions(share.PERMS_RUNTIME_SCAN, 0) {
		restRespAccessDenied(w, login)
		return
	}

	query := restParseQuery(r)

	var showTag string
	if value, ok := query.pairs[api.QueryKeyShow]; ok && value == api.QueryValueShowAccepted {
		showTag = api.QueryValueShowAccepted
	}

	vuls, _, err := cacher.GetVulnerabilityReport(common.ScanPlatformID, showTag)
	if vuls == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	resp := &api.RESTScanReportData{Report: &api.RESTScanReport{Vuls: vuls}}
	restRespSuccess(w, r, resp, acc, login, nil, "Get host scan report")
}

func handlerScanPlatformSummary(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}

	summary, err := cacher.GetScanPlatformSummary(acc)
	if summary == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	reply := &api.RESTScanPlatformSummaryData{Summary: []*api.RESTScanPlatformSummary{summary}}
	restRespSuccess(w, r, reply, acc, login, nil, "Get platform scan summary")
}

type vulAsset struct {
	asset                         *api.RESTVulnerabilityAsset
	packages                      map[string]utils.Set
	wls, nodes, images, platforms utils.Set
}

func addVulAsset(all map[string]*vulAsset, vul *api.RESTVulnerability) *vulAsset {
	va, ok := all[vul.Name]
	if !ok {
		va = &vulAsset{
			asset: &api.RESTVulnerabilityAsset{
				Name:        vul.Name,
				Severity:    vul.Severity,
				Description: vul.Description,
				Link:        vul.Link,
				Score:       vul.Score,
				Vectors:     vul.Vectors,
				ScoreV3:     vul.ScoreV3,
				VectorsV3:   vul.VectorsV3,
				PublishedTS: vul.PublishedTS,
				LastModTS:   vul.LastModTS,
			},
			packages:  make(map[string]utils.Set),
			wls:       utils.NewSet(),
			nodes:     utils.NewSet(),
			images:    utils.NewSet(),
			platforms: utils.NewSet(),
		}
		all[vul.Name] = va
	}
	_, ok = va.packages[vul.PackageName]
	if !ok {
		va.packages[vul.PackageName] = utils.NewSet()
	}
	va.packages[vul.PackageName].Add(api.RESTVulnPackageVersion{
		PackageVersion: vul.PackageVersion,
		FixedVersion:   vul.FixedVersion,
	})
	return va
}

// If one of workload/node is in discover mode, then the image is in discover mode; and so on.
func setImagePolicyMode(i2m map[string]string, image, mode string) {
	if m, ok := i2m[image]; !ok {
		i2m[image] = mode
	} else if mode == share.PolicyModeLearn {
		i2m[image] = mode
	} else if mode == share.PolicyModeEvaluate && m == share.PolicyModeEnforce {
		i2m[image] = mode
	}
}

func nodeRisk2IDName(n *common.WorkloadRisk) api.RESTIDName {
	return api.RESTIDName{
		ID:          n.ID,
		DisplayName: n.Name,
		PolicyMode:  n.PolicyMode,
	}
}

func workloadRisk2IDName(wl *common.WorkloadRisk) api.RESTIDName {
	return api.RESTIDName{
		ID:          wl.ID,
		DisplayName: wl.Name,
		PolicyMode:  wl.PolicyMode,
		Domains:     []string{wl.Domain},
	}
}

func getAllVulnerabilities(acc *access.AccessControl) (map[string]*vulAsset, *api.RESTVulnerabilityAssetData) {
	sdb := scanUtils.GetScannerDB()
	vpf := cacher.GetVulnerabilityProfileInterface(share.DefaultVulnerabilityProfileName)

	resp := api.RESTVulnerabilityAssetData{
		Workloads: make(map[string][]api.RESTIDName),
		Nodes:     make(map[string][]api.RESTIDName),
		Images:    make(map[string][]api.RESTIDName),
		Platforms: make(map[string][]api.RESTIDName),
	}
	all := make(map[string]*vulAsset)
	img2mode := make(map[string]string)

	pods := cacher.GetAllWorkloadsRisk(acc)
	for _, pod := range pods {
		// Skip pod in kubernetes; if no child, show the parent (native docker)
		if len(pod.Children) == 0 {
			pod.Children = append(pod.Children, pod)
		}

		for _, wl := range pod.Children {
			setImagePolicyMode(img2mode, wl.ImageID, wl.PolicyMode)

			reportVuls, _ := db.GetVulnerability(wl.ID)
			localVulTraits := scanUtils.ExtractVulnerability(reportVuls)

			vuls := scanUtils.FillVulTraits(sdb.CVEDB, wl.BaseOS, localVulTraits, "", false)
			if vuls != nil {
				for _, vul := range vuls {
					va := addVulAsset(all, vul)
					va.wls.Add(wl.ID)
				}
				resp.Workloads[wl.ID] = []api.RESTIDName{workloadRisk2IDName(wl)}
			}
		}
	}

	if acc.HasGlobalPermissions(share.PERMS_RUNTIME_SCAN, 0) {
		nodes := cacher.GetAllHostsRisk(acc)
		for _, n := range nodes {

			reportVuls, _ := db.GetVulnerability(n.ID)
			localVulTraits := scanUtils.ExtractVulnerability(reportVuls)

			vuls := scanUtils.FillVulTraits(sdb.CVEDB, n.BaseOS, localVulTraits, "", false)
			if vuls != nil {
				for _, vul := range vuls {
					va := addVulAsset(all, vul)
					va.nodes.Add(n.ID)
				}
				resp.Nodes[n.ID] = []api.RESTIDName{nodeRisk2IDName(n)}
			}
		}
	}

	if acc.HasGlobalPermissions(share.PERMS_RUNTIME_SCAN, 0) {
		platform, _, _ := cacher.GetPlatform()
		vuls, _, _ := cacher.GetVulnerabilityReport(common.ScanPlatformID, "")
		if vuls != nil {
			for _, vul := range vuls {
				va := addVulAsset(all, vul)
				va.platforms.Add(platform)
			}

			// TODO: for now, set platform policy to "discover" to indicate it's not protected
			resp.Platforms[platform] = []api.RESTIDName{
				{
					ID:          platform,
					DisplayName: platform,
					PolicyMode:  share.PolicyModeLearn,
				},
			}
		}
	}

	registries := scanner.GetAllRegistrySummary(share.ScopeAll, acc)
	for _, reg := range registries {
		if vmap, nmap, err := scanner.GetRegistryVulnerabilities(reg.Name, vpf, "", acc); err == nil {
			for id, vuls := range vmap {
				if idns, ok := nmap[id]; ok {
					for _, vul := range vuls {
						va := addVulAsset(all, vul)
						va.images.Add(id)
					}

					// If one of workload/node is in discover mode, then the image is in discover mode; and so on.
					// Policy mode is empty if the image is not used.
					pm := img2mode[id]
					for i := 0; i < len(idns); i++ {
						idns[i].PolicyMode = pm
					}
					if exist, ok := resp.Images[id]; ok {
						resp.Images[id] = append(exist, idns...)
					} else {
						resp.Images[id] = idns
					}
				}
			}
		}
	}

	return all, &resp
}

func handlerAssetVulnerability(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}

	all, resp := getAllVulnerabilities(acc)

	list := make([]*api.RESTVulnerabilityAsset, 0, len(all))
	for _, vul := range all {
		if vul.asset.ScoreV3 == 0 && vul.asset.Score == 0 {
			continue
		}

		vul.asset.Packages = make(map[string][]api.RESTVulnPackageVersion)
		vul.asset.Workloads = vul.wls.ToStringSlice() // Not to sort these lists to save some CPU cycles
		vul.asset.Nodes = vul.nodes.ToStringSlice()
		vul.asset.Images = vul.images.ToStringSlice()
		vul.asset.Platforms = vul.platforms.ToStringSlice()

		for pkg, vers := range vul.packages {
			vul.asset.Packages[pkg] = make([]api.RESTVulnPackageVersion, vers.Cardinality())
			j := 0
			for v := range vers.Iter() {
				vul.asset.Packages[pkg][j] = v.(api.RESTVulnPackageVersion)
				j++
			}
		}

		list = append(list, vul.asset)
	}

	sort.Slice(list, func(s, t int) bool {
		if list[s].Severity == "high" && list[t].Severity == "medium" {
			return true
		} else if list[s].Severity == "medium" && list[t].Severity == "high" {
			return false
		} else {
			return list[s].Name > list[t].Name
		}
	})

	resp.Vuls = list

	// remove id from RESTIDName to reduce data size.
	for _, wls := range resp.Workloads {
		for i := range wls {
			wls[i].ID = ""
		}
	}
	for _, nodes := range resp.Nodes {
		for i := range nodes {
			nodes[i].ID = ""
		}
	}
	for _, images := range resp.Images {
		for i := range images {
			images[i].ID = ""
		}
	}

	log.WithFields(log.Fields{"entries": len(resp.Vuls)}).Debug("Response")
	restRespSuccess(w, r, resp, acc, login, nil, "Get vulnerabiility asset report")
}

func getAllAllowedResourceId(acc *access.AccessControl) map[string]utils.Set {
	allowed := map[string]utils.Set{
		db.AssetWorkload: utils.NewSet(),
		db.AssetNode:     utils.NewSet(),
		db.AssetImage:    utils.NewSet(),
		db.AssetPlatform: utils.NewSet(),
	}

	vpf := cacher.GetVulnerabilityProfileInterface(share.DefaultVulnerabilityProfileName)

	podIDs := cacher.GetAllWorkloadsID(acc)
	for _, podID := range podIDs {
		allowed[db.AssetWorkload].Add(podID)
	}

	if acc.HasGlobalPermissions(share.PERMS_RUNTIME_SCAN, 0) {
		nodes := cacher.GetAllHostsID(acc)
		for _, n := range nodes {
			allowed[db.AssetNode].Add(n)
		}
	}

	if acc.HasGlobalPermissions(share.PERMS_RUNTIME_SCAN, 0) {
		platformID := cacher.GetPlatformID(acc)
		if platformID != "" {
			allowed[db.AssetPlatform].Add(platformID) // platform
		}
	}

	registries := scanner.GetAllRegistrySummary(share.ScopeAll, acc)
	for _, reg := range registries {
		registryImagesIDs, err := scanner.GetRegistryImagesIDs(reg.Name, vpf, "", acc)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Debug("GetRegistryImagesIDs failed")
		} else {
			for _, id := range registryImagesIDs {
				allowed[db.AssetImage].Add(id)
			}
		}
	}

	return allowed
}

func handlerVulAssetCreate(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	if r.Method == http.MethodPost {
		createVulAssetSessionV2(w, r)
		return
	}
}

func handlerVulAssetGet(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	if r.Method == http.MethodGet {
		getVulAssetSession(w, r)
		return
	}
}

func handlerAssetVul(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	if r.Method == http.MethodPost {
		getAssetViewSession(w, r)
		return
	}
}

func handlerScanCacheStat(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	if !licenseAllowScan() {
		restRespError(w, http.StatusBadRequest, api.RESTErrLicenseFail)
		return
	}

	id := ps.ByName("id")
	if res, err := rpc.ScanCacheGetStat(id); err != nil {
		restRespError(w, http.StatusBadRequest, api.RESTErrObjectNotFound)
	} else {
		resp := &api.RESTScanCacheStat{
			RecordCnt:  res.RecordCnt,
			RecordSize: res.RecordSize,
			MissCnt:    res.MissCnt,
			HitCnt:     res.HitCnt,
		}
		restRespSuccess(w, r, resp, acc, login, nil, "Get scan cache stat")
	}
}

func handlerScanCacheData(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	if !licenseAllowScan() {
		restRespError(w, http.StatusBadRequest, api.RESTErrLicenseFail)
		return
	}

	id := ps.ByName("id")
	if res, err := rpc.ScanCacheGetData(id); err != nil {
		restRespError(w, http.StatusBadRequest, api.RESTErrObjectNotFound)
	} else {
		var data scanUtils.CacherData
		uzb := utils.GunzipBytes(res.DataZb)
		json.Unmarshal([]byte(uzb), &data)
		resp := &api.RESTScanCacheData{
			MissCnt:    data.MissCnt,
			HitCnt:     data.HitCnt,
			RecordSize: data.CurRecordSize,
		}

		for _, rec := range data.CacheRecords {
			r := api.RESTScanCacheRecord{
				Layer:   rec.Layer,
				Size:    rec.Size,
				RefCnt:  rec.RefCnt,
				RefLast: rec.RefLast,
			}
			resp.CacheRecords = append(resp.CacheRecords, r)
		}
		restRespSuccess(w, r, resp, acc, login, nil, "Get scan cache data")
	}
}

func handlerAssetViewCreate(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	createAssetSession(w, r)
}

func handlerAssetViewGet(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	getAssetSession(w, r)
}

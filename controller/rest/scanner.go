package rest

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"sort"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
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

	if licenseAllowScan() != true {
		restRespError(w, http.StatusBadRequest, api.RESTErrLicenseFail)
		return
	}

	body, _ := ioutil.ReadAll(r.Body)

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

	if licenseAllowScan() != true {
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

	if licenseAllowScan() != true {
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

	if licenseAllowScan() != true {
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

	vuls, _ := cacher.GetVulnerabilityReport(id, showTag)
	if vuls == nil {
		// Return an empty list if workload has not been scanned
		resp = &api.RESTScanReportData{Report: &api.RESTScanReport{
			Vuls: make([]*api.RESTVulnerability, 0),
		}}
	} else {
		resp = &api.RESTScanReportData{Report: &api.RESTScanReport{Vuls: vuls}}
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
		vuls, err := cacher.GetVulnerabilityReport(brief.ID, showTag)
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

	vuls, err := cacher.GetVulnerabilityReport(id, showTag)
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

	vuls, err := cacher.GetVulnerabilityReport(common.ScanPlatformID, showTag)
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
	Name        string
	Severity    string
	Description string
	Link        string
	Score       float32
	Vectors     string
	ScoreV3     float32
	VectorsV3   string
	PublishedTS int64
	LastModTS   int64
	Packages    map[string]utils.Set
	wls         []api.RESTIDName
	nodes       []api.RESTIDName
	images      []api.RESTIDName
	platforms   []api.RESTIDName
}

func addVulAsset(all map[string]*vulAsset, vul *api.RESTVulnerability) *vulAsset {
	va, ok := all[vul.Name]
	if !ok {
		va = &vulAsset{
			Name:        vul.Name,
			Severity:    vul.Severity,
			Description: vul.Description,
			Packages:    make(map[string]utils.Set),
			Link:        vul.Link,
			Score:       vul.Score,
			Vectors:     vul.Vectors,
			ScoreV3:     vul.ScoreV3,
			VectorsV3:   vul.VectorsV3,
			PublishedTS: vul.PublishedTS,
			LastModTS:   vul.LastModTS,
			wls:         make([]api.RESTIDName, 0),
			nodes:       make([]api.RESTIDName, 0),
			images:      make([]api.RESTIDName, 0),
			platforms:   make([]api.RESTIDName, 0),
		}
		all[vul.Name] = va
	}
	_, ok = va.Packages[vul.PackageName]
	if !ok {
		va.Packages[vul.PackageName] = utils.NewSet()
	}
	va.Packages[vul.PackageName].Add(api.RESTVulnPackageVersion{
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

func getAllVulnerabilities(acc *access.AccessControl) map[string]*vulAsset {
	sdb := scanUtils.GetScannerDB()
	vpf := cacher.GetVulnerabilityProfileInterface(share.DefaultVulnerabilityProfileName)

	img2mode := make(map[string]string)
	all := make(map[string]*vulAsset)

	pods := cacher.GetAllWorkloadsRisk(acc)
	for _, pod := range pods {
		// Skip pod in kubernetes; if no child, show the parent (native docker)
		if len(pod.Children) == 0 {
			pod.Children = append(pod.Children, pod)
		}

		for _, wl := range pod.Children {
			setImagePolicyMode(img2mode, wl.ImageID, wl.PolicyMode)

			vuls := scanUtils.FillVulDetails(sdb.CVEDB, wl.VulTraits, "")
			if vuls != nil {
				for _, vul := range vuls {
					va := addVulAsset(all, vul)
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

	if acc.HasGlobalPermissions(share.PERMS_RUNTIME_SCAN, 0) {
		nodes := cacher.GetAllHostsRisk(acc)
		for _, n := range nodes {
			vuls := scanUtils.FillVulDetails(sdb.CVEDB, n.VulTraits, "")
			if vuls != nil {
				for _, vul := range vuls {
					va := addVulAsset(all, vul)
					va.nodes = append(va.nodes, api.RESTIDName{
						ID:          n.ID,
						DisplayName: n.Name,
						PolicyMode:  n.PolicyMode,
					})
				}
			}
		}
	}

	if acc.HasGlobalPermissions(share.PERMS_RUNTIME_SCAN, 0) {
		platform, _, _ := cacher.GetPlatform()
		vuls, _ := cacher.GetVulnerabilityReport(common.ScanPlatformID, "")
		if vuls != nil {
			for _, vul := range vuls {
				va := addVulAsset(all, vul)

				// TODO: for now, set platform policy to "discover" to indicate it's not protected
				va.platforms = append(va.platforms, api.RESTIDName{
					ID:          platform,
					DisplayName: platform,
					PolicyMode:  share.PolicyModeLearn,
					Domains:     nil,
				})
			}
		}
	}

	registries := scanner.GetAllRegistrySummary(acc)
	for _, reg := range registries {
		if vmap, nmap, err := scanner.GetRegistryVulnerabilities(reg.Name, vpf, "", acc); err == nil {
			for id, vuls := range vmap {
				if idns, ok := nmap[id]; ok {
					for _, vul := range vuls {
						va := addVulAsset(all, vul)

						// If one of workload/node is in discover mode, then the image is in discover mode; and so on.
						// Policy mode is empty if the image is not used.
						pm, _ := img2mode[id]
						for i := 0; i < len(idns); i++ {
							idns[i].PolicyMode = pm
						}

						va.images = append(va.images, idns...)
					}
				}
			}
		}
	}

	return all
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

	all := getAllVulnerabilities(acc)

	var exists utils.Set
	list := make([]*api.RESTVulnerabilityAsset, 0, len(all))
	for _, vul := range all {
		if vul.ScoreV3 == 0 && vul.Score == 0 {
			continue
		}

		va := &api.RESTVulnerabilityAsset{
			Name:        vul.Name,
			Severity:    vul.Severity,
			Description: vul.Description,
			Packages:    make(map[string][]api.RESTVulnPackageVersion),
			Link:        vul.Link,
			Score:       vul.Score,
			Vectors:     vul.Vectors,
			ScoreV3:     vul.ScoreV3,
			VectorsV3:   vul.VectorsV3,
			PublishedTS: vul.PublishedTS,
			LastModTS:   vul.LastModTS,
			Workloads:   make([]api.RESTIDName, 0),
			Nodes:       make([]api.RESTIDName, 0),
			Images:      make([]api.RESTIDName, 0),
			Platforms:   make([]api.RESTIDName, 0),
		}

		for pkg, vers := range vul.Packages {
			va.Packages[pkg] = make([]api.RESTVulnPackageVersion, vers.Cardinality())
			j := 0
			for v := range vers.Iter() {
				va.Packages[pkg][j] = v.(api.RESTVulnPackageVersion)
				j++
			}
		}

		// Not to sort these lists to save some CPU cycles
		exists = utils.NewSet()
		for _, v := range vul.wls {
			if !exists.Contains(v.ID) {
				va.Workloads = append(va.Workloads, v)
				exists.Add(v.ID)
			}
		}

		exists = utils.NewSet()
		for _, v := range vul.nodes {
			if !exists.Contains(v.ID) {
				va.Nodes = append(va.Nodes, v)
				exists.Add(v.ID)
			}
		}

		exists = utils.NewSet()
		for _, v := range vul.images {
			if !exists.Contains(v.ID) {
				va.Images = append(va.Images, v)
				exists.Add(v.ID)
			}
		}

		exists = utils.NewSet()
		for _, v := range vul.platforms {
			if !exists.Contains(v.ID) {
				va.Platforms = append(va.Platforms, v)
				exists.Add(v.ID)
			}
		}

		list = append(list, va)
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

	resp := &api.RESTVulnerabilityAssetData{Vuls: list}

	log.WithFields(log.Fields{"entries": len(resp.Vuls)}).Debug("Response")
	restRespSuccess(w, r, resp, acc, login, nil, "Get vulnerabiility asset report")
}

package rest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"

	"github.com/julienschmidt/httprouter"
	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func handlerComplianceList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}
	// Remove Metas replace with new [] get it dynamically
	metas, _ := scanUtils.GetComplianceMeta(scanUtils.V1)

	resp := api.RESTListData{List: &api.RESTList{Compliance: metas}}
	restRespSuccess(w, r, &resp, acc, login, nil, "Get compliance meta list")
}

type complianceProfileFilter struct {
	disableSystem bool
	filter        map[string][]string // item testNum => tags
	object        interface{}
}

func filterComplianceChecks(items []*api.RESTBenchItem, cpf *complianceProfileFilter) []*api.RESTBenchItem {
	var domain string
	if cpf.object == nil {
		domain = api.DomainNodes
	} else if wl, ok := cpf.object.(*common.WorkloadRisk); ok {
		if cpf.disableSystem && wl.PlatformRole == api.PlatformContainerCore {
			return []*api.RESTBenchItem{}
		}

		domain = wl.Domain
		if domain == "" {
			domain = api.DomainContainers
		}
	} else if wl, ok := cpf.object.(*api.RESTWorkloadBrief); ok {
		if cpf.disableSystem && wl.PlatformRole == api.PlatformContainerCore {
			return []*api.RESTBenchItem{}
		}

		domain = wl.Domain
		if domain == "" {
			domain = api.DomainContainers
		}
	} else if _, ok := cpf.object.(*api.RESTHost); ok {
		domain = api.DomainNodes
	} else if sum, ok := cpf.object.(*api.RESTRegistryImageSummary); ok {
		domain = sum.Domain
		if domain == "" {
			domain = api.DomainImages
		}
	} else if idns, ok := cpf.object.([]api.RESTIDName); ok {
		if len(idns) > 0 && len(idns[0].Domains) > 0 {
			domain = idns[0].Domains[0]
		}
	} else {
		domain = api.DomainNodes
	}

	tags, _ := cacher.GetDomainEffectiveTags(domain, access.NewReaderAccessControl())
	if len(tags) > 0 {
		// namespace tagged
		domainTags := utils.NewSetFromSliceKind(tags)

		list := make([]*api.RESTBenchItem, 0, len(items))
		for _, item := range items {
			itemTags, ok := cpf.filter[item.TestNum]
			if !ok {
				list = append(list, item)
			} else {
				// if the item and the domain has common tags, add the item
				for _, t := range itemTags {
					if domainTags.Contains(t) {
						list = append(list, item)
						break
					}
				}
			}
		}

		return list
	} else {
		return items
	}
}

func handlerGetAvaiableComplianceFilter(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	availableFilters := []string{}
	profiles := cacher.GetAllComplianceProfiles(acc)
	_, metaMap := scanUtils.GetComplianceMeta(scanUtils.V1)
	complianceFilterMap := scanUtils.GetComplianceFilterMap()

	for _, profile := range profiles {
		for _, entry := range profile.Entries {
			// Remove the exisiting one before user profile update.
			for _, compliance := range metaMap[entry.TestNum].Tags {
				complianceFilterMap[compliance]--
			}

			// Add user new selections to ensure we have count the filter correct
			for _, compliance := range entry.Tags {
				complianceFilterMap[compliance]++
			}
		}
	}

	for compliance, complianceCount := range complianceFilterMap {
		if complianceCount > 0 {
			availableFilters = append(availableFilters, compliance)
		}
	}

	resp := api.RESTAvaiableComplianceFilter{AvailableFilter: availableFilters}
	restRespSuccess(w, r, &resp, acc, login, nil, "Get avaiable compliance filter")
}

func handlerComplianceProfileList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	var resp api.RESTComplianceProfilesData
	resp.Profiles = cacher.GetAllComplianceProfiles(acc)

	// Sort by name, keep 'default' at the top
	sort.Slice(resp.Profiles, func(i, j int) bool {
		if resp.Profiles[i].Name == share.DefaultComplianceProfileName {
			return true
		}
		return resp.Profiles[i].Name < resp.Profiles[j].Name
	})

	log.WithFields(log.Fields{"entries": len(resp.Profiles)}).Debug("Response")
	restRespSuccess(w, r, &resp, acc, login, nil, "Get compliance profile list")
}

func handlerComplianceProfileShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	name := ps.ByName("name")

	cp, _, err := cacher.GetComplianceProfile(name, acc)
	if cp == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	resp := api.RESTComplianceProfileData{Profile: cp}
	restRespSuccess(w, r, &resp, acc, login, nil, "Get compliance profile detail")
}

func configComplianceProfileEntry(ccp *share.CLUSComplianceProfile, re *api.RESTComplianceProfileEntry) error {
	_, metaMap := scanUtils.GetComplianceMeta(scanUtils.V1)
	if _, ok := metaMap[re.TestNum]; !ok {
		return errors.New("Unknonwn compliance ID")
	}

	// Make sure empty tags is allowed
	tagSet := utils.NewSet()
	for _, t := range re.Tags {
		switch t {
		case api.ComplianceTemplatePCI, api.ComplianceTemplateGDPR, api.ComplianceTemplateHIPAA, api.ComplianceTemplateNIST, api.ComplianceTemplatePCIv4, api.ComplianceTemplateDISA:
			tagSet.Add(t)
		default:
			return errors.New("Invalid compliance profile template values")
		}
	}
	tags := tagSet.ToStringSlice()
	sort.Strings(tags)
	ccp.Entries[re.TestNum] = share.CLUSComplianceProfileEntry{TestNum: re.TestNum, Tags: tags}
	return nil
}

func configComplianceProfile(ccp *share.CLUSComplianceProfile, cfgType share.TCfgType, rcp *api.RESTComplianceProfileConfig) error {
	if rcp.DisableSystem != nil {
		ccp.DisableSystem = *rcp.DisableSystem
	}

	if rcp.Entries != nil {
		for _, e := range *rcp.Entries {
			if err := configComplianceProfileEntry(ccp, e); err != nil {
				return err
			}
		}
	}
	ccp.CfgType = cfgType

	return nil
}

func handlerComplianceProfileConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	name := ps.ByName("name")
	if name != share.DefaultComplianceProfileName {
		log.Error("Only the default compliance profile is allowed")
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Only the default compliance profile is allowed")
		return
	}

	if cp, _, err := cacher.GetComplianceProfile(name, acc); cp == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	} else if cp.CfgType == api.CfgTypeGround {
		restRespError(w, http.StatusBadRequest, api.RESTErrOpNotAllowed)
		return
	}

	// Read request
	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTComplianceProfileConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	rcp := rconf.Config

	if rcp.Name != name {
		e := "Profile name mismatch"
		log.WithFields(log.Fields{"profile": rcp.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}

	retry := 0
	for retry < retryClusterMax {
		ccp, rev, err := clusHelper.GetComplianceProfile(name, acc)
		if ccp == nil {
			restRespNotFoundLogAccessDenied(w, login, err)
			return
		}

		// clean up current entries
		ccp.Entries = make(map[string]share.CLUSComplianceProfileEntry)
		if err := configComplianceProfile(ccp, share.UserCreated, rcp); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to configure compliance profile")
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
			return
		}

		if !acc.Authorize(ccp, nil) {
			restRespAccessDenied(w, login)
			return
		}

		if err := clusHelper.PutComplianceProfile(ccp, &rev); err != nil {
			log.WithFields(log.Fields{"error": err, "rev": rev}).Error()
			retry++
		} else {
			break
		}
	}

	if retry >= retryClusterMax {
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}

	restRespSuccess(w, r, nil, acc, login, &rconf, fmt.Sprintf("Configure compliance profile '%v'", rcp.Name))
}

func handlerComplianceProfileEntryConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	name := ps.ByName("name")
	testNum := ps.ByName("check")
	if name != share.DefaultComplianceProfileName {
		log.Error("Only the default compliance profile is allowed")
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Only the default compliance profile is allowed")
		return
	}

	if cp, _, err := cacher.GetComplianceProfile(name, acc); cp == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	} else if cp.CfgType == api.CfgTypeGround {
		restRespError(w, http.StatusBadRequest, api.RESTErrOpNotAllowed)
		return
	}

	// Read request
	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTComplianceProfileEntryConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	if testNum != rconf.Config.TestNum {
		e := "Test number mismatch"
		log.WithFields(log.Fields{"testNum": rconf.Config.TestNum}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}

	re := rconf.Config

	retry := 0
	for retry < retryClusterMax {
		ccp, rev, err := clusHelper.GetComplianceProfile(name, acc)
		if ccp == nil {
			restRespNotFoundLogAccessDenied(w, login, err)
			return
		}

		if err := configComplianceProfileEntry(ccp, re); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to configure compliance profile")
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
			return
		}

		if !acc.Authorize(ccp, nil) {
			restRespAccessDenied(w, login)
			return
		}

		if err := clusHelper.PutComplianceProfile(ccp, &rev); err != nil {
			log.WithFields(log.Fields{"error": err, "rev": rev}).Error()
			retry++
		} else {
			break
		}
	}

	if retry >= retryClusterMax {
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}

	restRespSuccess(w, r, nil, acc, login, &rconf, fmt.Sprintf("Configure compliance profile entry '%v'", re.TestNum))
}

func handlerComplianceProfileEntryDelete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	name := ps.ByName("name")
	testNum := ps.ByName("check")
	if name != share.DefaultComplianceProfileName {
		log.Error("Only the default compliance profile is allowed")
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Only the default compliance profile is allowed")
		return
	}

	if cp, _, err := cacher.GetComplianceProfile(name, acc); cp == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	} else if cp.CfgType == api.CfgTypeGround {
		restRespError(w, http.StatusBadRequest, api.RESTErrOpNotAllowed)
		return
	}

	retry := 0
	for retry < retryClusterMax {
		ccp, rev, err := clusHelper.GetComplianceProfile(name, acc)
		if ccp == nil {
			restRespNotFoundLogAccessDenied(w, login, err)
			return
		}

		delete(ccp.Entries, testNum)

		if !acc.Authorize(ccp, nil) {
			restRespAccessDenied(w, login)
			return
		}

		if err := clusHelper.PutComplianceProfile(ccp, &rev); err != nil {
			log.WithFields(log.Fields{"error": err, "rev": rev}).Error()
			retry++
		} else {
			break
		}
	}

	if retry >= retryClusterMax {
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}

	restRespSuccess(w, r, nil, acc, login, nil, fmt.Sprintf("Delete compliance profile entry '%v'", testNum))
}

func handlerCompProfileExport(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, access.AccessOPRead)
	if acc == nil {
		return
	}

	if !acc.Authorize(&share.CLUSComplianceProfile{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	var rconf api.RESTCompProfilesExport
	body, _ := io.ReadAll(r.Body)
	err := json.Unmarshal(body, &rconf)
	if err == nil {
		for _, name := range rconf.Names {
			if name != share.DefaultComplianceProfileName {
				err = errors.New("Non-default profile name is not supported yet")
				break
			}
		}
	}
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
		return
	}
	if len(rconf.Names) == 0 {
		rconf.Names = []string{share.DefaultComplianceProfileName}
	}

	apiVersion := fmt.Sprintf("%s/%s", common.OEMClusterSecurityRuleGroup, resource.NvCompProfileSecurityRuleVersion)
	kind := resource.NvCompProfileSecurityRuleKind
	resp := resource.NvCompProfileSecurityRuleList{
		TypeMeta: metav1.TypeMeta{
			APIVersion: apiVersion,
			Kind:       resource.NvListKind,
		},
	}

	// export compliance profile (currently only default profile is supported)
	var lock cluster.LockInterface
	if lock, err = lockClusKey(w, share.CLUSLockCompKey); err != nil {
		return
	}
	defer clusHelper.ReleaseLock(lock)

	vpNames := utils.NewSet()
	for _, name := range rconf.Names {
		if vpNames.Contains(name) {
			continue
		}
		profile, _, _ := clusHelper.GetComplianceProfile(name, acc)
		if profile == nil {
			e := "compliance profile doesn't exist"
			log.WithFields(log.Fields{"name": name}).Error(e)
			restRespErrorMessage(w, http.StatusNotFound, api.RESTErrObjectNotFound, e)
			return
		}

		entries := make([]*api.RESTComplianceProfileEntry, 0, len(profile.Entries))
		for _, entry := range profile.Entries {
			entry := &api.RESTComplianceProfileEntry{
				TestNum: entry.TestNum,
				Tags:    entry.Tags,
			}
			entries = append(entries, entry)
		}
		sort.Slice(entries, func(s, t int) bool {
			return entries[s].TestNum < entries[t].TestNum
		})

		resptmp := resource.NvCompProfileSecurityRule{
			TypeMeta: metav1.TypeMeta{
				APIVersion: apiVersion,
				Kind:       kind,
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: name,
			},
			Spec: resource.NvSecurityCompProfileSpec{
				Templates: &resource.NvSecurityCompTemplates{
					DisableSystem: profile.DisableSystem,
					Entries:       entries,
				},
			},
		}
		resp.Items = append(resp.Items, resptmp)
		vpNames.Add(name)
	}

	doExport("cfgComplianceProfileExport.yaml", "compliance profile", rconf.RemoteExportOptions, resp, w, r, acc, login)
}

func handlerCompProfileImport(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if cp, _, err := cacher.GetComplianceProfile(share.DefaultComplianceProfileName, acc); err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	} else if cp.CfgType == api.CfgTypeGround {
		restRespError(w, http.StatusBadRequest, api.RESTErrOpNotAllowed)
		return
	}

	tid := r.Header.Get("X-Transaction-ID")
	_importHandler(w, r, tid, share.IMPORT_TYPE_COMP_PROFILE, share.PREFIX_IMPORT_COMP_PROFILE, acc, login)
}

func importCompProfile(scope string, loginDomainRoles access.DomainRole, importTask share.CLUSImportTask, postImportOp kv.PostImportFunc) error {
	log.Debug()
	defer os.Remove(importTask.TempFilename)

	json_data, _ := os.ReadFile(importTask.TempFilename)
	var secRuleList resource.NvCompProfileSecurityRuleList
	var secRule resource.NvCompProfileSecurityRule
	var secRules []resource.NvCompProfileSecurityRule = []resource.NvCompProfileSecurityRule{}
	var invalidCrdKind bool
	var err error
	if err = json.Unmarshal(json_data, &secRuleList); err != nil || len(secRuleList.Items) == 0 {
		if err = json.Unmarshal(json_data, &secRule); err == nil {
			secRules = append(secRules, secRule)
		}
	} else {
		secRules = secRuleList.Items
	}
	for _, r := range secRules {
		if r.APIVersion != "neuvector.com/v1" || r.Kind != resource.NvCompProfileSecurityRuleKind {
			invalidCrdKind = true
			break
		}
	}
	if invalidCrdKind || len(secRules) == 0 {
		msg := "Invalid security rule(s)"
		log.WithFields(log.Fields{"error": err}).Error(msg)
		postImportOp(fmt.Errorf(msg), importTask, loginDomainRoles, "", share.IMPORT_TYPE_COMP_PROFILE)
		return nil
	}

	var inc float32
	var progress float32 // progress percentage

	inc = 90.0 / float32(2+2*len(secRules))
	cmpProfilesCfg := make([]*resource.NvSecurityParse, 0, len(secRules))
	progress = 6

	importTask.Percentage = int(progress)
	importTask.Status = share.IMPORT_RUNNING
	clusHelper.PutImportTask(&importTask)

	var crdHandler nvCrdHandler
	crdHandler.Init(share.CLUSLockCompKey)
	if crdHandler.AcquireLock(clusterLockWait) {
		defer crdHandler.ReleaseLock()

		// [1]: parse all security rules in the yaml file
		for _, secRule := range secRules {
			if cpCfgRet, errCount, errMsg, _ := crdHandler.parseCurCrdCompProfileContent(&secRule, share.ReviewTypeImportCompProfile, share.ReviewTypeDisplayCompProfile); errCount > 0 {
				err = fmt.Errorf(errMsg)
				break
			} else {
				cmpProfilesCfg = append(cmpProfilesCfg, cpCfgRet)
				progress += inc
				importTask.Percentage = int(progress)
				clusHelper.PutImportTask(&importTask)
			}
		}

		progress += inc
		importTask.Percentage = int(progress)
		clusHelper.PutImportTask(&importTask)

		if err == nil {
			// [2]: import compliance profile defined in the yaml file
			for _, parsedCfg := range cmpProfilesCfg {
				// [3] import compliance profile defined in the yaml file
				if err = crdHandler.crdHandleCompProfile(parsedCfg.CompProfileCfg, nil, share.ReviewTypeImportCompProfile); err != nil {
					break
				}
				progress += inc
				importTask.Percentage = int(progress)
				clusHelper.PutImportTask(&importTask)
			}
		}
		importTask.Percentage = 90
		clusHelper.PutImportTask(&importTask)
	}

	postImportOp(err, importTask, loginDomainRoles, "", share.IMPORT_TYPE_COMP_PROFILE)

	return nil
}

package rest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/share"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
)

func handlerComplianceList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() {
		restRespAccessDenied(w, login)
		return
	}

	metas, _ := scanUtils.GetComplianceMeta()
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

func handlerComplianceProfileList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
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
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
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
	_, metaMap := scanUtils.GetComplianceMeta()
	if _, ok := metaMap[re.TestNum]; !ok {
		return errors.New("Unknonwn compliance ID")
	}

	// Make sure empty tags is allowed
	tagSet := utils.NewSet()
	for _, t := range re.Tags {
		switch t {
		case api.ComplianceTemplatePCI, api.ComplianceTemplateGDPR, api.ComplianceTemplateHIPAA, api.ComplianceTemplateNIST:
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

func configComplianceProfile(ccp *share.CLUSComplianceProfile, rcp *api.RESTComplianceProfileConfig) error {
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

	return nil
}

func handlerComplianceProfileConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
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

	// Read request
	body, _ := ioutil.ReadAll(r.Body)

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
		if err := configComplianceProfile(ccp, rcp); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to configure compliance profile")
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
			return
		}

		if !acc.Authorize(ccp, nil) {
			restRespAccessDenied(w, login)
			return
		}

		if err := clusHelper.PutComplianceProfile(ccp, rev); err != nil {
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

	restRespSuccess(w, r, nil, acc, login, &rconf, fmt.Sprintf("Configure compliance profile '%v'", rcp.Name))
}

func handlerComplianceProfileEntryConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
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

	// Read request
	body, _ := ioutil.ReadAll(r.Body)

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

		if err := clusHelper.PutComplianceProfile(ccp, rev); err != nil {
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

	restRespSuccess(w, r, nil, acc, login, &rconf, fmt.Sprintf("Configure compliance profile entry '%v'", re.TestNum))
}

func handlerComplianceProfileEntryDelete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
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

		if err := clusHelper.PutComplianceProfile(ccp, rev); err != nil {
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

	restRespSuccess(w, r, nil, acc, login, nil, fmt.Sprintf("Delete compliance profile entry '%v'", testNum))
}

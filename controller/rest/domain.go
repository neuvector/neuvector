package rest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share/utils"
)

func handlerDomainList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	query := restParseQuery(r)

	var resp api.RESTDomainsData
	var domains []*api.RESTDomain

	domains, resp.TagPerDomain = cacher.GetAllDomains(acc)
	sort.Slice(domains, func(i, j int) bool { return domains[i].Name < domains[j].Name })

	if query.start > 0 && len(domains) <= query.start {
		resp.Domains = make([]*api.RESTDomain, 0)
		restRespSuccess(w, r, &resp, acc, login, nil, "Get domain list")
		return
	}

	if query.limit == 0 {
		resp.Domains = domains[query.start:]
	} else {
		var end int
		if query.start+query.limit > len(domains) {
			end = len(domains)
		} else {
			end = query.start + query.limit
		}
		resp.Domains = domains[query.start:end]
	}

	log.WithFields(log.Fields{"entries": len(resp.Domains)}).Debug("Response")

	restRespSuccess(w, r, &resp, acc, login, nil, "Get namespace list")
}

func checkDomainTags(input []string) ([]string, error) {
	// Make sure empty tags is allowed
	tagSet := utils.NewSet()
	for _, t := range input {
		switch t {
		case api.ComplianceTemplatePCI, api.ComplianceTemplateGDPR, api.ComplianceTemplateHIPAA, api.ComplianceTemplateNIST:
			tagSet.Add(t)
		default:
			return nil, errors.New("Invalid tags")
		}
	}
	tags := tagSet.ToStringSlice()
	sort.Strings(tags)
	return tags, nil
}

func handlerDomainConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	// Read body
	body, _ := ioutil.ReadAll(r.Body)

	var rconf api.RESTDomainConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	rc := rconf.Config

	retry := 0
	for retry < retryClusterMax {
		name := api.DomainContainers

		cd, rev, err := clusHelper.GetDomain(name, acc)
		if cd == nil {
			log.WithFields(log.Fields{"error": err}).Error()
			restRespNotFoundLogAccessDenied(w, login, err)
			return
		}

		if rc.TagPerDomain != nil {
			cd.Disable = *rc.TagPerDomain
		}

		if !acc.Authorize(cd, nil) {
			restRespAccessDenied(w, login)
			return
		}

		if err := clusHelper.PutDomain(cd, &rev); err != nil {
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

	restRespSuccess(w, r, nil, acc, login, &rconf, "Configure domain setting")
}

func handlerDomainEntryConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	name := ps.ByName("name")
	name, _ = url.PathUnescape(name)

	// Read body
	body, _ := ioutil.ReadAll(r.Body)

	var rconf api.RESTDomainEntryConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	rd := rconf.Config

	if rd.Name != name {
		e := "Namespace name mismatch"
		log.WithFields(log.Fields{"domain": rd.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}

	retry := 0
	for retry < retryClusterMax {
		cd, rev, err := clusHelper.GetDomain(name, acc)
		if cd == nil {
			restRespNotFoundLogAccessDenied(w, login, err)
			return
		}

		if rd.Tags != nil {
			if tags, err := checkDomainTags(*rd.Tags); err != nil {
				log.WithFields(log.Fields{"error": err}).Error()
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
			} else {
				cd.Tags = tags
			}
		}

		if !acc.Authorize(cd, nil) {
			restRespAccessDenied(w, login)
			return
		}

		if err := clusHelper.PutDomain(cd, &rev); err != nil {
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

	restRespSuccess(w, r, nil, acc, login, &rconf, fmt.Sprintf("Configure domain profile '%v'", rd.Name))
}

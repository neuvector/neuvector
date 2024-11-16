package rest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/controller/rpc"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

func criteria2REST(inEntries []share.CLUSCriteriaEntry) []api.RESTCriteriaEntry {
	var outEntries []api.RESTCriteriaEntry
	for _, inC := range inEntries {
		outC := api.RESTCriteriaEntry{
			Key:   inC.Key,
			Value: inC.Value,
			Op:    inC.Op,
		}
		outEntries = append(outEntries, outC)
	}
	sort.Slice(outEntries, func(i, j int) bool {
		if outEntries[i].Key != outEntries[j].Key {
			return outEntries[i].Key < outEntries[j].Key
		} else {
			return outEntries[i].Value < outEntries[j].Value
		}
	})
	return outEntries
}

func handlerGroupBrief(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	query := restParseQuery(r)

	scope := query.pairs[api.QueryScope] // empty string means fed & local groups

	var resp api.RESTGroupsBriefData
	resp.Groups = make([]*api.RESTGroupBrief, 0)

	if cacher.GetGroupCount(scope, acc) <= query.start {
		restRespSuccess(w, r, &resp, acc, login, nil, "Get group list")
		return
	}

	allCached := cacher.GetAllGroupsBrief(scope, query.withCap, acc)
	allSize := 0
	for _, cached := range allCached {
		allSize += len(cached)
	}

	// Filter
	if allSize <= query.start {
		restRespSuccess(w, r, &resp, acc, login, nil, "Get group list")
		return
	}
	groups := make([]*api.RESTGroupBrief, allSize)
	idx := 0

	// Sort
	for _, cached := range allCached {
		if len(cached) > 1 && len(query.sorts) > 0 {
			// Convert struct slice to interface slice
			var data []interface{} = make([]interface{}, len(cached))
			for i, d := range cached {
				data[i] = d
			}

			// Sort
			restNewSorter(data, query.sorts).Sort()

			// Copy the result
			for _, d := range data {
				groups[idx] = d.(*api.RESTGroupBrief)
				idx++
			}
		} else {
			sort.Slice(cached, func(i, j int) bool { return cached[i].Name < cached[j].Name })
			for _, g := range cached {
				groups[idx] = g
				idx++
			}
		}
	}

	// Filter
	if len(query.filters) > 0 {
		var dummy api.RESTGroup
		rf := restNewFilter(&dummy, query.filters)

		for _, g := range groups[query.start:] {
			if !rf.Filter(g) {
				continue
			}

			resp.Groups = append(resp.Groups, g)

			if query.limit > 0 && len(resp.Groups) >= query.limit {
				break
			}
		}
	} else if query.limit == 0 {
		resp.Groups = groups[query.start:]
	} else {
		var end int
		if query.start+query.limit > len(groups) {
			end = len(groups)
		} else {
			end = query.start + query.limit
		}
		resp.Groups = groups[query.start:end]
	}

	log.WithFields(log.Fields{"entries": len(resp.Groups)}).Debug("Response")

	restRespSuccess(w, r, &resp, acc, login, nil, "Get group brief list")
}

func handlerGroupList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	query := restParseQuery(r)
	if query.brief {
		handlerGroupBrief(w, r, ps)
		return
	}

	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	var view string
	if value, ok := query.pairs[api.QueryKeyView]; ok && value == api.QueryValueViewPod {
		view = api.QueryValueViewPod
	}
	scope := query.pairs[api.QueryScope] // empty string means fed & local groups

	var resp api.RESTGroupsData
	resp.Groups = make([]*api.RESTGroup, 0)

	if cacher.GetGroupCount(scope, acc) <= query.start {
		restRespSuccess(w, r, &resp, acc, login, nil, "Get group list")
		return
	}

	allCached := cacher.GetAllGroups(scope, view, query.withCap, acc)
	allSize := 0
	for _, cached := range allCached {
		allSize += len(cached)
	}

	// Filter
	if allSize <= query.start {
		restRespSuccess(w, r, &resp, acc, login, nil, "Get group list")
		return
	}
	groups := make([]*api.RESTGroup, allSize)
	idx := 0

	// Sort
	for _, cached := range allCached {
		if len(cached) > 1 && len(query.sorts) > 0 {
			// Convert struct slice to interface slice
			var data []interface{} = make([]interface{}, len(cached))
			for i, d := range cached {
				data[i] = d
			}

			// Sort
			restNewSorter(data, query.sorts).Sort()

			// Copy the result
			for _, d := range data {
				groups[idx] = d.(*api.RESTGroup)
				idx++
			}
		} else {
			sort.Slice(cached, func(i, j int) bool { return cached[i].Name < cached[j].Name })
			for _, g := range cached {
				groups[idx] = g
				idx++
			}
		}
	}

	// Filter
	if len(query.filters) > 0 {
		var dummy api.RESTGroup
		rf := restNewFilter(&dummy, query.filters)

		for _, g := range groups[query.start:] {
			if !rf.Filter(g) {
				continue
			}

			resp.Groups = append(resp.Groups, g)

			if query.limit > 0 && len(resp.Groups) >= query.limit {
				break
			}
		}
	} else if query.limit == 0 {
		resp.Groups = groups[query.start:]
	} else {
		var end int
		if query.start+query.limit > len(groups) {
			end = len(groups)
		} else {
			end = query.start + query.limit
		}
		resp.Groups = groups[query.start:end]
	}

	log.WithFields(log.Fields{"entries": len(resp.Groups)}).Debug("Response")

	restRespSuccess(w, r, &resp, acc, login, nil, "Get group list")
}

func handlerGroupShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	name := ps.ByName("name")

	query := restParseQuery(r)

	var view string
	if value, ok := query.pairs[api.QueryKeyView]; ok && value == api.QueryValueViewPod {
		view = api.QueryValueViewPod
	}

	var resp api.RESTGroupData

	// Retrieve the group
	group, err := cacher.GetGroupDetail(name, view, query.withCap, acc)
	if group == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	resp.Group = group

	restRespSuccess(w, r, &resp, acc, login, nil, "Get group detail")
}

// Accept 1.2.3.4 or 1.2.3.4/24 or 1.2.3.4-1.2.3.20. One range at a time.
func validateAddressRange(ipRange string) error {
	ip, ipr := utils.ParseIPRange(ipRange)
	if ip == nil || ipr == nil || bytes.Compare(ip, ipr) > 0 {
		e := "Invalid IP range"
		return fmt.Errorf("%s", e)
	}
	return nil
}

var regIPLoose *regexp.Regexp = regexp.MustCompile("^[0-9.]+$")
var regIPRangeLoose *regexp.Regexp = regexp.MustCompile("^[0-9-./]+$")
var regDomain *regexp.Regexp = regexp.MustCompile(`^([0-9a-zA-Z])+([0-9a-zA-Z-_])*(\.[0-9a-zA-Z]+([0-9a-zA-Z-_])*)*$`)
var regVhDomain *regexp.Regexp = regexp.MustCompile(`^vh:([0-9a-zA-Z])+([0-9a-zA-Z-_])*(\.[0-9a-zA-Z]+([0-9a-zA-Z-_])*)*$`)
var regSubDomain *regexp.Regexp = regexp.MustCompile(`^(\*)(\.[0-9a-zA-Z]+([0-9a-zA-Z-_])*){2,}$`)
var regVhSubDomain *regexp.Regexp = regexp.MustCompile(`^vh:(\*)(\.[0-9a-zA-Z]+([0-9a-zA-Z-_])*){2,}$`)

func validateDomainName(name string) bool {
	if regIPRangeLoose.MatchString(name) {
		return false
	}
	return (((len(name) < api.PolicyDomainNameMaxLen) && (regDomain.MatchString(name) || regSubDomain.MatchString(name))) ||
		((len(name) < api.PolicyDomainNameMaxLen+len(api.AddrGrpValVhPrefix)) && (regVhDomain.MatchString(name) || regVhSubDomain.MatchString(name))))
}

// check for non-fed groups only
func isReservedGroupName(name string) bool {
	return strings.HasPrefix(name, api.LearnedGroupPrefix) ||
		strings.HasPrefix(name, api.LearnedHostPrefix) ||
		strings.HasPrefix(name, api.LearnedWorkloadPrefix) ||
		strings.HasPrefix(name, api.FederalGroupPrefix) ||
		name == api.LearnedExternal || name == api.AllHostGroup || name == api.AllContainerGroup
}

func validateServiceConfig(rg *api.RESTServiceConfig) (int, string) {
	name := utils.NormalizeForURL(utils.MakeServiceName(rg.Domain, rg.Name))
	if !isObjectNameValid(name) {
		e := "Invalid characters in name"
		log.WithFields(log.Fields{"name": name}).Error(e)
		return api.RESTErrInvalidName, e
	}

	for attribute, mode := range map[string]*string{"policy": rg.PolicyMode, "profile": rg.ProfileMode} {
		if mode != nil && !share.IsValidPolicyMode(*mode) {
			e := fmt.Sprintf("Invalid %s mode %s", attribute, *mode)
			log.Error(e)
			return api.RESTErrInvalidRequest, e
		}
	}

	return 0, ""
}

func validateLearnGroupConfig(rg *api.RESTGroupConfig) (int, string) {
	var serviceFind = false
	var domainFind = false
	var serviceName string

	if !isObjectNameValid(rg.Name) {
		e := "Invalid characters in name"
		log.WithFields(log.Fields{"name": rg.Name}).Error(e)
		return api.RESTErrInvalidName, e
	}

	isNvIpGroup := strings.HasPrefix(rg.Name, api.LearnedSvcGroupPrefix)
	if rg.Criteria == nil || (len(*rg.Criteria) > 2 && !isNvIpGroup) {
		e := "Learned Group must have criteria service with/without domain"
		log.WithFields(log.Fields{"name": rg.Name}).Error(e)
		return api.RESTErrInvalidRequest, e
	}

	/*
		// a DNS-1123 label must consist of lower case alphanumeric characters or '-', and must start and end with an alphanumeric character
		// So Learned Group from k8s controlled serive have  3 part sepearted by .  1. nv  2. service name 3. domain
		// Learned Group from standalone container have 2 part, sepearated by 1. nv 2. image name (image name my have path like  rancher/cen-os, normalization will happen for name)
		tokens := strings.Split(rg.Name, ".")
		switch len(tokens) {
		case 2:
			serviceName = tokens[1]
		case 3:
			serviceName = fmt.Sprintf("%s.%s", tokens[1], tokens[2])
		default:
			e := "Learned Group name should have format as nv.serviename.domain or nv.servicename "
			log.WithFields(log.Fields{"name": rg.Name}).Error(e)
			return api.RESTErrInvalidRequest, e
		}
	*/
	// [2021-06-17] learned group like "nv.u.b.i.8" is possible
	tokens := strings.Split(rg.Name, ".")
	serviceName = rg.Name[len(api.LearnedGroupPrefix):]

	for _, ct := range *rg.Criteria {
		var e string
		if ct.Key == "" {
			e := "Criteria key cannot be empty"
			log.WithFields(log.Fields{"key": ct.Key}).Error(e)
			return api.RESTErrInvalidRequest, e
		}

		if ct.Op != share.CriteriaOpEqual {
			e = "Learned group can only have operation exact match"
		} else {
			if ct.Key == share.CriteriaKeyService {
				if isNvIpGroup {
					e = "Learned ip service group does not allow service criteria"
				} else {
					if serviceFind {
						e = "Learned group only allows one service criteria"
					} else {
						serviceFind = true
						if serviceName != utils.NormalizeForURL(ct.Value) {
							e = fmt.Sprintf("Learned group service does not match between name and criteria(key: %s, value: %s). For value, replace [/?%%& ] to :, without NonPrintable.",
								ct.Key, ct.Value)
						}
					}
				}
			} else if ct.Key == share.CriteriaKeyDomain {
				if domainFind {
					e = "Learned group only allows one domain criteria"
				} else {
					domainFind = true
					if len(tokens) < 3 || tokens[len(tokens)-1] != ct.Value { // we can only assume the last token in rg.Name is the domain
						e = fmt.Sprintf("Learned group domain does not match between name and criteria(key: %s, value: %s)", ct.Key, ct.Value)
					}
				}
			} else {
				if isNvIpGroup {
					// only domain criterion(if exists) will be kept. All other criteria will be dropped for crd nv.ip.xxx groups
				} else {
					e = "Learned group can only have key as service and domain"
				}
			}
		}
		if e != "" {
			log.WithFields(log.Fields{"key": ct.Key, "value": ct.Value, "Name": rg.Name}).Error(e)
			return api.RESTErrInvalidRequest, e
		}
	}
	return 0, ""
}

func validateGroupConfig(rg *api.RESTGroupConfig, create bool) (int, string) {
	if !isObjectNameValid(rg.Name) {
		e := "Invalid characters in name"
		log.WithFields(log.Fields{"name": rg.Name}).Error(e)
		return api.RESTErrInvalidName, e
	}
	if rg.GrpSessCur != nil && *rg.GrpSessCur > api.GrpMetricMax {
		e := "Metric group active session number exceed max limit"
		log.WithFields(log.Fields{"GrpSessCur": *rg.GrpSessCur, "Max": api.GrpMetricMax}).Error(e)
		return api.RESTErrInvalidRequest, e
	}
	if rg.GrpSessRate != nil && *rg.GrpSessRate > api.GrpMetricMax {
		e := "Metric group session rate exceed max limit"
		log.WithFields(log.Fields{"GrpSessRate": *rg.GrpSessRate, "Max": api.GrpMetricMax}).Error(e)
		return api.RESTErrInvalidRequest, e
	}
	if rg.GrpBandWidth != nil && *rg.GrpBandWidth > api.GrpMetricMax {
		e := "Metric group bandwidth exceed max limit"
		log.WithFields(log.Fields{"GrpBandWidth": *rg.GrpBandWidth, "Max": api.GrpMetricMax}).Error(e)
		return api.RESTErrInvalidRequest, e
	}
	switch rg.CfgType {
	case api.CfgTypeFederal:
		if !strings.HasPrefix(rg.Name, api.FederalGroupPrefix) || rg.Name == api.FederalGroupPrefix {
			e := "Federal group name must start with 'fed.' but cannot be just 'fed.'"
			log.WithFields(log.Fields{"name": rg.Name}).Error(e)
			return api.RESTErrInvalidName, e
		}
	default:
		if create {
			if isReservedGroupName(rg.Name) {
				e := "Cannot use reserved name"
				log.WithFields(log.Fields{"name": rg.Name}).Error(e)
				return api.RESTErrInvalidName, e
			}
		} else {
			if isReservedGroupName(rg.Name) && rg.Criteria != nil {
				e := "Cannot modify criteria of the reserved group"
				log.WithFields(log.Fields{"name": rg.Name, "c": *rg.Criteria}).Error(e)
				return api.RESTErrInvalidRequest, e
			}
		}
	}
	return 0, ""
}

func validateGroupConfigCriteria(rg *api.RESTGroupConfig, acc *access.AccessControl) (int, string, bool) {
	var hasAddrCT, hasObjCT bool
	for _, ct := range *rg.Criteria {
		if ct.Key == "" {
			e := "Criteria key cannot be empty"
			log.WithFields(log.Fields{"key": ct.Key, "value": ct.Value}).Error(e)
			return api.RESTErrInvalidRequest, e, hasAddrCT
		}

		if ct.Op != share.CriteriaOpEqual && ct.Op != share.CriteriaOpNotEqual && ct.Value == "" {
			e := fmt.Sprintf("Empty criteria value is only allowed for exact match (key: %s)", ct.Key)
			log.WithFields(log.Fields{"key": ct.Key, "value": ct.Value}).Error(e)
			return api.RESTErrInvalidRequest, e, hasAddrCT
		}

		if !isNamePathValid(ct.Key) {
			e := fmt.Sprintf("Invalid characters in criteria key %s", ct.Key)
			log.WithFields(log.Fields{"key": ct.Key}).Error(e)
			return api.RESTErrInvalidRequest, e, hasAddrCT
		}
		if ct.Op != share.CriteriaOpEqual && ct.Op != share.CriteriaOpContains &&
			ct.Op != share.CriteriaOpPrefix && ct.Op != share.CriteriaOpRegex &&
			ct.Op != share.CriteriaOpNotEqual && ct.Op != share.CriteriaOpNotRegex {
			e := fmt.Sprintf("Invalid operation in criteria (key: %s, op: %s)", ct.Key, ct.Op)
			log.WithFields(log.Fields{"key": ct.Key}).Error(e)
			return api.RESTErrInvalidRequest, e, hasAddrCT
		}

		kovStr := fmt.Sprintf("(key: %s, op: %s, value: %s)", ct.Key, ct.Op, ct.Value)
		if ct.Op == share.CriteriaOpRegex || ct.Op == share.CriteriaOpNotRegex {
			if _, err := regexp.Compile(ct.Value); err != nil {
				e := fmt.Sprintf("Invalid regex value in criteria %s", kovStr)
				log.WithFields(log.Fields{"error": err}).Error(e)
				return api.RESTErrInvalidRequest, e, hasAddrCT
			}
		}
		if ct.Op == share.CriteriaOpEqual || ct.Op == share.CriteriaOpNotEqual {
			if strings.ContainsAny(ct.Value, "?*") {
				// Check simplified regex
				if strings.ContainsAny(ct.Value, "^$") {
					e := fmt.Sprintf("Invalid simple regex value in criteria %s", kovStr)
					log.WithFields(log.Fields{"value": ct.Value}).Error(e)
					return api.RESTErrInvalidRequest, e, hasAddrCT
				}
			}
		}

		if ct.Key == share.CriteriaKeyNamespace || ct.Key == share.CriteriaKeyDomain {
			var grp *share.CLUSGroup
			cfgType := cfgTypeMapping[rg.CfgType]
			if ct.Op != share.CriteriaOpEqual {
				grp = &share.CLUSGroup{CfgType: cfgType}
			} else {
				grp = &share.CLUSGroup{CfgType: cfgType, CreaterDomains: []string{ct.Value}}
			}
			if !acc.Authorize(grp, nil) {
				e := fmt.Sprintf("No permission on the specified namespace/domain criteria %s", kovStr)
				log.WithFields(log.Fields{"value": ct.Value}).Error(e)
				return api.RESTErrInvalidRequest, e, hasAddrCT
			}
		}

		if ct.Key == share.CriteriaKeyAddress {
			if ct.Op != share.CriteriaOpEqual {
				e := fmt.Sprintf("Only exact match is supported for address criteria %s", kovStr)
				log.Error(e)
				return api.RESTErrInvalidRequest, e, hasAddrCT
			}

			if hasObjCT {
				e := fmt.Sprintf("Cannot mix address and other criteria in a group %s", kovStr)
				log.Error(e)
				return api.RESTErrInvalidRequest, e, hasAddrCT
			}
			if err := validateAddressRange(ct.Value); err != nil {
				if !validateDomainName(ct.Value) {
					e := fmt.Sprintf("Invalid address criteria %s", kovStr)
					log.WithFields(log.Fields{"address": ct.Value}).Error(e)
					return api.RESTErrInvalidRequest, e, hasAddrCT
				}
			}
			hasAddrCT = true
		} else {
			if hasAddrCT {
				e := fmt.Sprintf("Cannot mix address and other criteria in a group %s", kovStr)
				log.Error(e)
				return api.RESTErrInvalidRequest, e, hasAddrCT
			}
			hasObjCT = true
		}
	}
	return 0, "", hasAddrCT
}

func handlerGroupCreate(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	// Read body
	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTGroupConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	rg := rconf.Config
	cg := share.CLUSGroup{
		Name:           rg.Name,
		CreaterDomains: acc.GetAdminDomains(share.PERMS_RUNTIME_POLICIES),
		Kind:           share.GroupKindContainer,
	}
	cg.CfgType = cfgTypeMapping[rg.CfgType]
	if !acc.Authorize(&cg, nil) {
		restRespAccessDenied(w, login)
		return
	}

	if err, msg := validateGroupConfig(rg, true); err > 0 {
		restRespErrorMessage(w, http.StatusBadRequest, err, msg)
		return
	}
	if rg.Criteria == nil || len(*rg.Criteria) == 0 {
		e := "Group must have criteria"
		log.WithFields(log.Fields{"name": rg.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	} else if err, msg, _ := validateGroupConfigCriteria(rg, acc); err > 0 {
		restRespErrorMessage(w, http.StatusBadRequest, err, msg)
		return
	}

	// Do not lock, reply on cluster.PutIfNotExist() for consistency
	if exist, err := cacher.DoesGroupExist(rg.Name, acc); exist {
		e := "Group already exists"
		log.WithFields(log.Fields{"name": rg.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrDuplicateName, e)
		return
	} else if err != common.ErrObjectNotFound {
		if err == common.ErrObjectAccessDenied {
			restRespAccessDenied(w, login)
		} else {
			restRespErrorMessage(w, http.StatusInternalServerError, 0, err.Error())
		}
		return
	}

	for _, ct := range *rg.Criteria {
		cg.Criteria = append(cg.Criteria, share.CLUSCriteriaEntry{
			Key:   ct.Key,
			Value: ct.Value,
			Op:    ct.Op,
		})
		if ct.Key == share.CriteriaKeyAddress {
			cg.Kind = share.GroupKindAddress
		}
	}
	if rg.Comment != nil {
		cg.Comment = *rg.Comment
	}
	if rg.MonMetric != nil {
		cg.MonMetric = *rg.MonMetric
	}
	if rg.GrpSessCur != nil {
		cg.GrpSessCur = *rg.GrpSessCur
	}
	if rg.GrpSessRate != nil {
		cg.GrpSessRate = *rg.GrpSessRate
	}
	if rg.GrpBandWidth != nil {
		cg.GrpBandWidth = *rg.GrpBandWidth
	}

	// Write group definition into key-value store. Make sure group doesn't exist.
	if err := clusHelper.PutGroup(&cg, true); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}
	if cg.CfgType == share.FederalCfg {
		updateFedRulesRevision([]string{share.FedGroupType}, acc, login)
	}

	restRespSuccess(w, r, nil, acc, login, &rconf, "Create group")
}

func handlerGroupConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	name := ps.ByName("name")

	query := restParseQuery(r)

	var view string
	if value, ok := query.pairs[api.QueryKeyView]; ok && value == api.QueryValueViewPod {
		view = api.QueryValueViewPod
	}

	// Read request
	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTGroupConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	rg := rconf.Config

	if rg.Name != name {
		e := "Name mismatch"
		log.WithFields(log.Fields{"group": rg.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}
	if cached, err := cacher.GetGroup(rg.Name, view, query.withCap, acc); cached == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	} else if cached.CfgType == api.CfgTypeGround {
		e := "Group created by SecurityRule cannot be edited"
		log.WithFields(log.Fields{"name": name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	} else {
		for _, idx := range cached.PolicyRules {
			if isSecurityPolicyID(idx) {
				e := "Group referenced  by SecurityRule can only modified through CRD"
				log.WithFields(log.Fields{"name": name, "securityRule_id": idx}).Error(e)
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
				return
			}
		}
	}

	if err, msg := validateGroupConfig(rg, false); err > 0 {
		restRespErrorMessage(w, http.StatusBadRequest, err, msg)
		return
	}
	if rg.Criteria != nil {
		if len(*rg.Criteria) == 0 {
			e := "Group must have criteria"
			log.WithFields(log.Fields{"name": rg.Name}).Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
			return
		} else if err, msg, _ := validateGroupConfigCriteria(rg, acc); err > 0 {
			restRespErrorMessage(w, http.StatusBadRequest, err, msg)
			return
		}
	}

	// Group scope is set when the group is created and cannot be changed.

	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, err.Error())
		return
	}
	defer clusHelper.ReleaseLock(lock)

	// Read from cluster
	cg, _, _ := clusHelper.GetGroup(name, acc)
	if cg == nil {
		e := "Group doesn't exist"
		log.WithFields(log.Fields{"name": name}).Error(e)
		restRespErrorMessage(w, http.StatusNotFound, api.RESTErrObjectNotFound, e)
		return
	}

	// Apply changes
	if rg.Criteria != nil && len(*rg.Criteria) > 0 {
		cg.Criteria = nil
		bHasCriteriaAddress := false
		for _, ct := range *rg.Criteria {
			cg.Criteria = append(cg.Criteria, share.CLUSCriteriaEntry{
				Key:   ct.Key,
				Value: ct.Value,
				Op:    ct.Op,
			})
			if ct.Key == share.CriteriaKeyAddress {
				bHasCriteriaAddress = true
			}
		}

		if bHasCriteriaAddress {
			cg.Kind = share.GroupKindAddress
		} else {
			cg.Kind = share.GroupKindContainer
		}
	}

	if rg.Comment != nil {
		cg.Comment = *rg.Comment
	}
	if rg.MonMetric != nil {
		cg.MonMetric = *rg.MonMetric
	}
	if rg.GrpSessCur != nil {
		cg.GrpSessCur = *rg.GrpSessCur
	}
	if rg.GrpSessRate != nil {
		cg.GrpSessRate = *rg.GrpSessRate
	}
	if rg.GrpBandWidth != nil {
		cg.GrpBandWidth = *rg.GrpBandWidth
	}

	if !acc.Authorize(cg, nil) {
		restRespAccessDenied(w, login)
		return
	}

	// Write group definition into key-value store
	if err := clusHelper.PutGroup(cg, false); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}
	if cg.CfgType == share.FederalCfg {
		updateFedRulesRevision([]string{share.FedGroupType}, acc, login)
	}

	restRespSuccess(w, r, nil, acc, login, &rconf, "Configure group")
}

// Must read from cluster instead of cache.
// func isGroupInUse(name string) bool {
// 	crhs := clusHelper.GetPolicyRuleList()
// 	for _, crh := range crhs {
// 		if r, _ := clusHelper.GetPolicyRule(crh.ID); r != nil {
// 			if r.From == name || r.To == name {
// 				return true
// 			}
// 		}
// 	}
// 	return false
// }

func handlerGroupDelete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	name := ps.ByName("name")

	query := restParseQuery(r)

	var view string
	if value, ok := query.pairs[api.QueryKeyView]; ok && value == api.QueryValueViewPod {
		view = api.QueryValueViewPod
	}

	if cached, err := cacher.GetGroup(name, view, query.withCap, acc); cached == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	} else {
		/*
			Reserved group and CRD group cannot be deleted;
			If a group is referred by a CRD rule, it cannot be deleted;
			Service IP group cannot be deleted;
			Learned group with member cannot be deleted
			User-created group can be deleted;
			Federate group is similar to user-created, follow the caller's role
		*/

		if cached.Reserved {
			e := "Reserved group cannot be deleted"
			log.WithFields(log.Fields{"name": name}).Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
			return
		}

		if cached.Kind == share.GroupKindIPService {
			e := "Service IP group cannot be deleted"
			log.WithFields(log.Fields{"name": name}).Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
			return
		}

		// If learned group is deleted, containers in the group are not able to learn rules.
		// Checking member count in multi-controller case is tricky. For simplicity, disallow
		// removing learned groups.
		// Enable group delete if there is no members - 04/05/2018
		if cached.CfgType == api.CfgTypeLearned && len(cached.Members) > 0 {
			e := "Learned group with members cannot be deleted"
			log.WithFields(log.Fields{"name": name}).Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
			return
		}

		if cached.CfgType == api.CfgTypeGround {
			e := "Group created by SecurityRule cannot be deleted"
			log.WithFields(log.Fields{"name": name}).Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
			return
		}

		for _, idx := range cached.PolicyRules {
			if isSecurityPolicyID(idx) {
				e := "Group referenced by SecurityRule cannot be deleted"
				log.WithFields(log.Fields{"name": name, "securityRule_id": idx}).Error(e)
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
				return
			}
		}
	}

	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, err.Error())
		return
	}
	defer clusHelper.ReleaseLock(lock)

	cg, _, _ := clusHelper.GetGroup(name, acc)
	if cg == nil {
		log.WithFields(log.Fields{"name": name}).Error("Group doesn't exist")
		//NVSHAS-7386, Empty group deletion return errs "Object not found"
		//normally group should exist in consul when it is listed in cache
		//but in some corner cases, group is listed but not found in kv
		//and user want delete group to relearn, so we will delete group
		//from cache, but limit practice to learned group(nv.x.x)
		if utils.IsGroupLearned(name) && !strings.HasPrefix(name, api.LearnedSvcGroupPrefix) && !utils.IsGroupNodes(name) {
			err1 := cacher.DeleteGroupCache(name, acc)
			if err1 != nil {
				restRespAccessDenied(w, login)
			} else {
				kv.DeletePolicyByGroup(name)
				kv.DeleteResponseRuleByGroup(name)
				restRespSuccess(w, r, nil, acc, login, nil, "Delete group")
			}
			return
		} else {
			restRespError(w, http.StatusNotFound, api.RESTErrObjectNotFound)
			return
		}
	}

	/*
		if isGroupInUse(name) {
			log.WithFields(log.Fields{"name": name}).Error("Group in use")
			restRespError(w, http.StatusConflict, api.RESTErrObjectInuse)
			return
		}
	*/

	if !acc.Authorize(cg, nil) {
		restRespAccessDenied(w, login)
		return
	}

	var delRuleTypes []string
	if cg.CfgType == share.FederalCfg {
		delRuleTypes = make([]string, 0, 4)
	}
	if dels := kv.DeletePolicyByGroup(name); dels > 0 && cg.CfgType == share.FederalCfg {
		delRuleTypes = append(delRuleTypes, share.FedNetworkRulesType)
	}
	if dels := kv.DeleteResponseRuleByGroup(name); dels > 0 && cg.CfgType == share.FederalCfg {
		delRuleTypes = append(delRuleTypes, share.FedResponseRulesType)
	}

	if err := clusHelper.DeleteGroup(name); err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}
	if cg.CfgType == share.FederalCfg {
		delRuleTypes = append(delRuleTypes, share.FedGroupType)
		updateFedRulesRevision(delRuleTypes, acc, login)
	}

	restRespSuccess(w, r, nil, acc, login, nil, "Delete group")
}

// This allows user to create a service and its process/file/network profile before
// starting the containers in protect mode.
func handlerServiceCreate(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTServiceConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	rg := rconf.Config
	if err, msg := validateServiceConfig(rg); err > 0 {
		restRespErrorMessage(w, http.StatusBadRequest, err, msg)
		return
	}

	// Leave the duplication check in cacher

	if err := cacher.CreateService(rg, acc); err != nil {
		if err == common.ErrObjectAccessDenied {
			restRespNotFoundLogAccessDenied(w, login, err)
		} else if err == common.ErrObjectExists {
			e := "Service already exists"
			log.WithFields(log.Fields{"name": rg.Name, "domain": rg.Domain}).Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrDuplicateName, e)
		} else {
			log.WithFields(log.Fields{"error": err}).Error()
			restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		}
		return
	}

	restRespSuccess(w, r, nil, acc, login, &rconf, "Create service")
}

func configPolicyMode(grp *share.CLUSGroup) error {
	if pp := clusHelper.GetProcessProfile(grp.Name); pp != nil {
		if pp.Mode != grp.ProfileMode || pp.Baseline != grp.BaselineProfile {
			pp.Mode = grp.ProfileMode
			pp.Baseline = grp.BaselineProfile
			if err := clusHelper.PutProcessProfile(grp.Name, pp); err != nil {
				log.WithFields(log.Fields{"error": err}).Error()
				return err
			}
		}
	}
	if pp, rev := clusHelper.GetFileMonitorProfile(grp.Name); pp != nil {
		if pp.Mode != grp.ProfileMode {
			pp.Mode = grp.ProfileMode
			if err := clusHelper.PutFileMonitorProfile(grp.Name, pp, rev); err != nil {
				log.WithFields(log.Fields{"error": err}).Error()
				return err
			}
		}
	}
	return nil
}

func isManagedByCRD(grpName string, acc *access.AccessControl) bool {
	if cached, _ := cacher.GetGroup(grpName, "", false, acc); cached != nil {
		if cached.CfgType == api.CfgTypeGround {
			return true
		} else {
			for _, idx := range cached.PolicyRules {
				if isSecurityPolicyID(idx) {
					return true
				}
			}
		}
	}

	return false
}

func handlerServiceBatchConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() { // special case: if caller doesn't have enough permission, return 403
		restRespAccessDenied(w, login)
		return
	}

	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTServiceBatchConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil || len(rconf.Config.Services) == 0 {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	rc := rconf.Config

	for attribute, mode := range map[string]*string{"policy": rc.PolicyMode, "profile": rc.ProfileMode} {
		if mode != nil && !share.IsValidPolicyMode(*mode) {
			e := fmt.Sprintf("Invalid %s mode %s", attribute, *mode)
			log.Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
			return
		}
	}

	if rc.BaselineProfile != nil {
		blValue := strings.ToLower(*rc.BaselineProfile)
		switch blValue {
		case share.ProfileBasic:
			*rc.BaselineProfile = share.ProfileBasic
		case share.ProfileDefault_UNUSED, share.ProfileShield_UNUSED, share.ProfileZeroDrift:
			*rc.BaselineProfile = share.ProfileZeroDrift
		default:
			log.WithFields(log.Fields{"baseline": *rc.BaselineProfile}).Error("Invalid profile baseline")
			restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
			return
		}
	}

	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, err.Error())
		return
	}
	defer clusHelper.ReleaseLock(lock)

	var qualified bool = false    // Used to respond BadRequest if no group can be configured.
	var managedByCRD bool = false // Used to respond BadRequest if one group is managed by CRD.
	for _, svc := range rc.Services {
		name := api.LearnedGroupPrefix + svc
		if svc == api.AllHostGroup {
			name = svc
		}

		grp, _, _ := clusHelper.GetGroup(name, acc)
		if grp == nil {
			log.WithFields(log.Fields{"name": name}).Error("Service doesn't exist or access denied")
			continue
		}

		if isManagedByCRD(name, acc) {
			managedByCRD = true
			continue
		}

		qualified = true

		var changed bool = false
		var profileChanged bool = false
		var baselineChanged bool
		if rc.PolicyMode != nil {
			if cacher.IsGroupPolicyModeChangeable(name) {
				if grp.PolicyMode != *rc.PolicyMode {
					grp.PolicyMode = *rc.PolicyMode
					changed = true
				}
			}
		}

		if rc.ProfileMode != nil {
			if cacher.IsGroupPolicyModeChangeable(name) {
				if grp.ProfileMode != *rc.ProfileMode {
					grp.ProfileMode = *rc.ProfileMode
					changed = true
					profileChanged = true
				}
			}
		}

		if rc.BaselineProfile != nil {
			if grp.BaselineProfile != *rc.BaselineProfile {
				changed = true
				baselineChanged = true
				if utils.IsGroupNodes(name) {
					grp.BaselineProfile = share.ProfileBasic //	always
				} else {
					grp.BaselineProfile = *rc.BaselineProfile
				}
			}
		}

		if rc.NotScored != nil {
			grp.NotScored = *rc.NotScored
			changed = true
		}

		if changed {
			if profileChanged || baselineChanged {
				err := configPolicyMode(grp)
				if err != nil {
					restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
					return
				}
			}
			if err := clusHelper.PutGroup(grp, false); err != nil {
				log.WithFields(log.Fields{"error": err}).Error()
				restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
				return
			}
		}
	}

	if !qualified {
		var status int = http.StatusNotFound
		var code int = api.RESTErrObjectNotFound
		if managedByCRD {
			status = http.StatusBadRequest
			code = api.RESTErrOpNotAllowed
		}
		restRespError(w, status, code)
	} else {
		restRespSuccess(w, r, nil, acc, login, &rconf, "Configure services in batch")
	}
}

func setServicePolicyModeAll(policy_mode, profile_mode string, acc *access.AccessControl) error {
	log.WithFields(log.Fields{"policy_mode": policy_mode, "profile_mode": profile_mode}).Debug()

	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		return err
	}
	defer clusHelper.ReleaseLock(lock)

	grps := clusHelper.GetAllGroups(share.ScopeLocal, acc)
	for name, grp := range grps {
		if isManagedByCRD(name, acc) {
			continue
		}
		if policy_mode == "" && profile_mode == "" {
			continue
		}
		if (grp.PolicyMode == policy_mode && grp.ProfileMode == profile_mode) || !cacher.IsGroupPolicyModeChangeable(grp.Name) {
			continue
		}

		if policy_mode != "" {
			grp.PolicyMode = policy_mode
		}
		if profile_mode != "" {
			grp.ProfileMode = profile_mode
			err = configPolicyMode(grp)
			if err != nil {
				return err
			}
		}
		if err := clusHelper.PutGroup(grp, false); err != nil {
			log.WithFields(log.Fields{"error": err}).Error()
			return err
		}
	}
	return nil
}

func setServiceProcessBaslineAll(option string, acc *access.AccessControl) error {
	log.WithFields(log.Fields{"option": option}).Debug()

	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		return err
	}
	defer clusHelper.ReleaseLock(lock)

	var changed bool
	grps := clusHelper.GetAllGroups(share.ScopeLocal, acc)
	for name, grp := range grps {
		if isManagedByCRD(name, acc) {
			continue
		}
		if !utils.HasGroupProfiles(grp.Name) {
			continue
		}

		changed = false
		if grp.BaselineProfile != option {
			changed = true
			if utils.IsGroupNodes(name) {
				grp.BaselineProfile = share.ProfileBasic //	always
			} else {
				grp.BaselineProfile = option
			}
		}
		if changed {
			if pp := clusHelper.GetProcessProfile(grp.Name); pp != nil {
				pp.Baseline = grp.BaselineProfile
				if err := clusHelper.PutProcessProfile(grp.Name, pp); err != nil {
					log.WithFields(log.Fields{"error": err}).Error()
					return err
				}
			}

			if err := clusHelper.PutGroup(grp, false); err != nil {
				log.WithFields(log.Fields{"error": err}).Error()
				return err
			}
		}
	}
	return nil
}

func handlerServiceList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
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

	var services []*api.RESTService
	var resp api.RESTServicesData
	resp.Services = make([]*api.RESTService, 0)

	if cacher.GetAllServiceCount(acc) <= query.start {
		restRespSuccess(w, r, &resp, acc, login, nil, "Get service list")
		return
	}

	cached := cacher.GetAllServices(view, query.withCap, acc)

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
		services = make([]*api.RESTService, len(cached))
		for i, d := range data {
			services[i] = d.(*api.RESTService)
		}
	} else {
		services = cached
		sort.Slice(services, func(i, j int) bool { return services[i].Name < services[j].Name })
	}

	// Filter
	if len(services) <= query.start {
		restRespSuccess(w, r, &resp, acc, login, nil, "Get service list")
		return
	}

	if len(query.filters) > 0 {
		var dummy api.RESTGroup
		rf := restNewFilter(&dummy, query.filters)

		for _, sv := range services[query.start:] {
			if !rf.Filter(sv) {
				continue
			}

			resp.Services = append(resp.Services, sv)

			if query.limit > 0 && len(resp.Services) >= query.limit {
				break
			}
		}
	} else if query.limit == 0 {
		resp.Services = services[query.start:]
	} else {
		var end int
		if query.start+query.limit > len(services) {
			end = len(services)
		} else {
			end = query.start + query.limit
		}
		resp.Services = services[query.start:end]
	}

	log.WithFields(log.Fields{"entries": len(resp.Services)}).Debug("Response")

	restRespSuccess(w, r, &resp, acc, login, nil, "Get service list")
}

func handlerServiceShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	name := ps.ByName("name")

	query := restParseQuery(r)

	var view string
	if value, ok := query.pairs[api.QueryKeyView]; ok && value == api.QueryValueViewPod {
		view = api.QueryValueViewPod
	}

	var resp api.RESTServiceData

	// Retrieve the service
	service, err := cacher.GetService(name, view, query.withCap, acc)
	if service == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	resp.Service = service

	restRespSuccess(w, r, &resp, acc, login, nil, "Get service detail")
}

// caller has been verified for federal admin access right
func replaceFedGroups(groups []*share.CLUSGroup, acc *access.AccessControl) bool {
	gpsMap := make(map[string]*share.CLUSGroup, len(groups))
	for _, group := range groups {
		if group.CfgType == share.FederalCfg {
			gpsMap[group.Name] = group
		}
	}

	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to acquire cluster lock")
		return false
	}
	defer clusHelper.ReleaseLock(lock)

	txn := cluster.Transact()
	defer txn.Close()
	var hasError bool

	existing := clusHelper.GetAllGroups(share.ScopeFed, acc)
	for name, g := range existing {
		if g != nil && g.Reserved {
			continue
		}
		if _, ok := gpsMap[name]; !ok { // in existing but not in latest. so delete it
			deleteOps := []struct {
				action string
				fn     func() error
			}{
				{"DeletePolicyByGroupTxn", func() error { return kv.DeletePolicyByGroupTxn(txn, name) }},
				{"DeleteResponseRuleByGroupTxn", func() error { return kv.DeleteResponseRuleByGroupTxn(txn, name, share.FederalCfg) }},
				{"DeleteProcessProfileTxn", func() error { return clusHelper.DeleteProcessProfileTxn(txn, name) }},
				{"DeleteFileMonitorTxn", func() error { return clusHelper.DeleteFileMonitorTxn(txn, name) }},
			}

			for _, op := range deleteOps {
				err := op.fn()
				if err != nil {
					log.WithFields(log.Fields{"error": err}).Error(op.action)
					hasError = true
					break
				}
			}

			clusHelper.DeleteGroupTxn(txn, name)
			clusHelper.DeleteFileAccessRuleTxn(txn, name)
		}
	}

	for _, gp := range gpsMap {
		if gp != nil {
			_, found := existing[gp.Name]
			if !found || (found && !reflect.DeepEqual(*gp, *existing[gp.Name])) {
				if err := clusHelper.PutGroupTxn(txn, gp); err != nil {
					hasError = true
					break
				}
				if !found { // for new fed groups, create process/file profiles here instead of in groupConfigUpdate()
					cacher.CreateProcessProfileTxn(txn, gp.Name, gp.PolicyMode, "", gp.CfgType)
					cacher.CreateGroupFileMonitorTxn(txn, gp.Name, gp.PolicyMode, gp.CfgType)
				}
			}
		}
	}

	if hasError {
		return false
	}

	if ok, err := txn.Apply(); err != nil || !ok {
		log.WithFields(log.Fields{"ok": ok, "error": err}).Error("Atomic write to the cluster failed")
		return false
	}

	return true
}

func deleteFedGroupPolicy() { // delete all fed groups(caller must be fedAdmin), network rules & response rules that reference fed groups
	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to acquire cluster lock")
		return
	}
	defer clusHelper.ReleaseLock(lock)

	txn := cluster.Transact()
	defer txn.Close()

	var hasError bool

	kv.DeletePolicyByCfgTypeTxn(txn, share.FederalCfg)

	gpsMap := clusHelper.GetAllGroups(share.ScopeFed, access.NewFedAdminAccessControl())
	for name := range gpsMap {
		if err := kv.DeleteResponseRuleByGroupTxn(txn, name, share.FederalCfg); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("DeleteResponseRuleByGroupTxn")
			hasError = true
			break
		}
		if name == api.LearnedExternal {
			continue
		}
		clusHelper.DeleteGroupTxn(txn, name)
	}

	if hasError {
		return
	}

	if ok, err := txn.Apply(); err != nil || !ok {
		log.WithFields(log.Fields{"ok": ok, "error": err}).Error("Atomic write to the cluster failed")
	}
}

func handlerServiceBatchConfigNetwork(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() { // special case: if caller doesn't have enough permission, return 403
		restRespAccessDenied(w, login)
		return
	}

	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTServiceBatchConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil || len(rconf.Config.Services) == 0 {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	rc := rconf.Config

	if rc.PolicyMode != nil {
		if !share.IsValidPolicyMode(*rc.PolicyMode) {
			e := fmt.Sprintf("Invalid policy mode %s", *rc.PolicyMode)
			log.Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
			return
		}
	}

	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, err.Error())
		return
	}
	defer clusHelper.ReleaseLock(lock)

	var qualified bool = false    // Used to respond BadRequest if no group can be configured.
	var managedByCRD bool = false // Used to respond BadRequest if one group is managed by CRD.
	for _, svc := range rc.Services {
		name := api.LearnedGroupPrefix + svc
		if svc == api.AllHostGroup {
			name = svc
		}

		grp, _, _ := clusHelper.GetGroup(name, acc)
		if grp == nil {
			log.WithFields(log.Fields{"name": name}).Error("Service doesn't exist or access denied")
			continue
		}

		if isManagedByCRD(name, acc) {
			managedByCRD = true
			continue
		}

		qualified = true

		var changed bool = false
		if rc.PolicyMode != nil {
			if grp.PolicyMode != *rc.PolicyMode && cacher.IsGroupPolicyModeChangeable(name) {
				grp.PolicyMode = *rc.PolicyMode
				changed = true
			}
		}
		if rc.NotScored != nil {
			grp.NotScored = *rc.NotScored
			changed = true
		}

		if changed {
			if err := clusHelper.PutGroup(grp, false); err != nil {
				log.WithFields(log.Fields{"error": err}).Error()
				restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
				return
			}
		}
	}

	if !qualified {
		var status int = http.StatusNotFound
		var code int = api.RESTErrObjectNotFound
		if managedByCRD {
			status = http.StatusBadRequest
			code = api.RESTErrOpNotAllowed
		}
		restRespError(w, status, code)
	} else {
		restRespSuccess(w, r, nil, acc, login, &rconf, "Configure services in batch")
	}
}

func handlerServiceBatchConfigProfile(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasRequiredPermissions() { // special case: if caller doesn't have enough permission, return 403
		restRespAccessDenied(w, login)
		return
	}

	body, _ := io.ReadAll(r.Body)

	var rconf api.RESTServiceBatchConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil || len(rconf.Config.Services) == 0 {
		log.WithFields(log.Fields{"error": err}).Error("Request error")
		restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
		return
	}

	rc := rconf.Config

	if rc.ProfileMode != nil {
		if !share.IsValidPolicyMode(*rc.ProfileMode) {
			e := fmt.Sprintf("Invalid profile mode %s", *rc.ProfileMode)
			log.Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
			return
		}
	}

	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, err.Error())
		return
	}
	defer clusHelper.ReleaseLock(lock)

	var qualified bool = false    // Used to respond BadRequest if no group can be configured.
	var managedByCRD bool = false // Used to respond BadRequest if one group is managed by CRD.
	for _, svc := range rc.Services {
		name := api.LearnedGroupPrefix + svc
		if svc == api.AllHostGroup {
			name = svc
		}

		grp, _, _ := clusHelper.GetGroup(name, acc)
		if grp == nil {
			log.WithFields(log.Fields{"name": name}).Error("Service doesn't exist or access denied")
			continue
		}

		if isManagedByCRD(name, acc) {
			managedByCRD = true
			continue
		}

		qualified = true

		var changed bool = false
		var profileChanged bool = false
		var baselineChanged bool
		if rc.ProfileMode != nil {
			if grp.ProfileMode != *rc.ProfileMode && cacher.IsGroupPolicyModeChangeable(name) {
				grp.ProfileMode = *rc.ProfileMode
				changed = true
				profileChanged = true
			}
		}
		if rc.BaselineProfile != nil {
			if grp.BaselineProfile != *rc.BaselineProfile {
				changed = true
				baselineChanged = true
				if utils.IsGroupNodes(name) {
					grp.BaselineProfile = share.ProfileBasic //	always
				} else {
					grp.BaselineProfile = *rc.BaselineProfile
				}
			}
		}
		if rc.NotScored != nil {
			grp.NotScored = *rc.NotScored
			changed = true
		}

		if changed {
			if profileChanged || baselineChanged {
				err := configPolicyMode(grp)
				if err != nil {
					restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
					return
				}
			}

			if err := clusHelper.PutGroup(grp, false); err != nil {
				log.WithFields(log.Fields{"error": err}).Error()
				restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
				return
			}
		}
	}

	if !qualified {
		var status int = http.StatusNotFound
		var code int = api.RESTErrObjectNotFound
		if managedByCRD {
			status = http.StatusBadRequest
			code = api.RESTErrOpNotAllowed
		}
		restRespError(w, status, code)
	} else {
		restRespSuccess(w, r, nil, acc, login, &rconf, "Configure services in batch")
	}
}

func handlerGroupCfgImport(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	tid := r.Header.Get("X-Transaction-ID")
	if (tid == "" && !acc.HasGlobalPermissions(share.PERMS_RUNTIME_POLICIES, share.PERMS_RUNTIME_POLICIES)) ||
		(tid != "" && !acc.HasGlobalPermissions(share.PERMS_RUNTIME_POLICIES, 0)) {
		restRespAccessDenied(w, login)
		return
	}

	_importHandler(w, r, tid, share.IMPORT_TYPE_GROUP_POLICY, share.PREFIX_IMPORT_GROUP_POLICY, acc, login)
}

func handlerGetGroupCfgImport(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.HasGlobalPermissions(share.PERMS_RUNTIME_POLICIES, 0) {
		restRespAccessDenied(w, login)
		return
	}

	importRunning := false
	importNoResponse := false
	importTask, _ := clusHelper.GetImportTask()
	if importTask.TID != "" && (importTask.Status == share.IMPORT_PREPARE || importTask.Status == share.IMPORT_RUNNING) {
		importRunning = true
		if !importTask.LastUpdateTime.IsZero() && time.Now().UTC().Sub(importTask.LastUpdateTime).Seconds() > share.IMPORT_QUERY_INTERVAL {
			importNoResponse = true
		}
	}

	resp := api.RESTImportTaskData{
		Data: &api.RESTImportTask{
			TID:            importTask.TID,
			CtrlerID:       importTask.CtrlerID,
			Percentage:     importTask.Percentage,
			LastUpdateTime: importTask.LastUpdateTime,
			TriggeredBy:    importTask.CallerFullname,
			Status:         importTask.Status,
		},
	}

	if importRunning {
		if !importNoResponse {
			// import is running
			resp.Data.Status = importTask.Status
		} else {
			// the running import has no response for a while
			resp.Data.Status = share.IMPORT_NO_RESPONSE
		}
	} else {
		resp.Data.Status = share.IMPORT_DONE
	}
	restRespSuccess(w, r, &resp, acc, login, nil, "Get import status")
}

// if there are multiple yaml documents(separated by "---" line) in the yaml file, only the first document is parsed for import
func importGroupPolicy(scope string, loginDomainRoles access.DomainRole, importTask share.CLUSImportTask, postImportOp kv.PostImportFunc) error {
	log.Debug()
	defer os.Remove(importTask.TempFilename)

	json_data, _ := os.ReadFile(importTask.TempFilename)
	var secRuleList resource.NvSecurityRuleList
	var secRule resource.NvSecurityRule
	var secRules []resource.NvSecurityRule
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
		if r.APIVersion != "neuvector.com/v1" || (r.Kind != resource.NvSecurityRuleKind && r.Kind != resource.NvClusterSecurityRuleKind) {
			invalidCrdKind = true
			break
		}
	}
	if invalidCrdKind || len(secRules) == 0 {
		msg := "Invalid security rule(s)"
		log.WithFields(log.Fields{"error": err}).Error(msg)
		postImportOp(fmt.Errorf("%s", msg), importTask, loginDomainRoles, "", share.IMPORT_TYPE_GROUP_POLICY)
		return nil
	}

	var inc float32
	var progress float32 // progress percentage

	inc = 90.0 / float32(2+2*len(secRules))
	parsedGrpCfg := make([]*resource.NvSecurityParse, 0, len(secRules))
	progress = 6

	importTask.Percentage = int(progress)
	importTask.Status = share.IMPORT_RUNNING
	_ = clusHelper.PutImportTask(&importTask) // Ignore error because progress update is non-critical

	var crdHandler nvCrdHandler
	crdHandler.Init(share.CLUSLockPolicyKey)
	if crdHandler.AcquireLock(clusterLockWait) {
		defer crdHandler.ReleaseLock()

		// The following code does the same job as crdGFwRuleProcessRecord(grpCfgRet, resource.NvSecurityRuleKind, namebase)
		// It processes the group and network rule list parsed from the import payload yaml
		// For importing group, unlike CRD, we don't remember anything that was imported before. Here is how we handle it:
		// 1. If the specified group has the same name as any reserved group, return error.
		// 2. If the specified group doesn't exist, create it using the specified group name
		// 3. If the specified group exists, replace the existing group
		// 4. Delete all existing policies that refer to the target group and import all policies.
		// ---------------------------------------------------
		// [1]: parse all security rules in the yaml file
		for _, secRule := range secRules {
			if grpCfgRet, errCount, errMsg, _ := crdHandler.parseCurCrdGfwContent(&secRule, nil, share.ReviewTypeImportGroup, share.ReviewTypeDisplayGroup); errCount > 0 {
				err = fmt.Errorf("%s", errMsg)
				break
			} else {
				log.WithFields(log.Fields{"target": grpCfgRet.TargetName, "len": len(grpCfgRet.GroupCfgs)}).Debug()
				parsedGrpCfg = append(parsedGrpCfg, grpCfgRet)
			}
		}

		progress += inc
		importTask.Percentage = int(progress)
		_ = clusHelper.PutImportTask(&importTask) // Ignore error because progress update is non-critical

		if err == nil {
			var updatedGroups utils.Set
			var hasDlpWafSetting bool
			targetGroupDlpWAF := make(map[string]bool, len(parsedGrpCfg))
			targetGroups := make([]string, 0, len(parsedGrpCfg))
			// [2]: import all non-reserved groups referenced in the yaml file
			for _, grpCfgRet := range parsedGrpCfg {
				// do same job as crdHandleGroupsAdd(crdCfgRet.GroupCfgs) but only import target group
				if updatedGroups, hasDlpWafSetting, err = importGroup(scope, grpCfgRet.TargetName, grpCfgRet.GroupCfgs); err == nil {
					targetGroupDlpWAF[grpCfgRet.TargetName] = hasDlpWafSetting
					if updatedGroups.Contains(grpCfgRet.TargetName) {
						targetGroups = append(targetGroups, grpCfgRet.TargetName)
					} else if grpCfgRet.TargetName == api.LearnedExternal || grpCfgRet.TargetName == api.AllHostGroup || grpCfgRet.TargetName == api.AllContainerGroup {
						targetGroups = append(targetGroups, grpCfgRet.TargetName)
					}
				} else {
					break
				}

				progress += inc
				importTask.Percentage = int(progress)
				_ = clusHelper.PutImportTask(&importTask) // Ignore error because progress update is non-critical
			}

			if err == nil {
				// [3]: delete all network policy rules of all the target groups (not all referenced groups)
				kv.DeletePolicyByGroups(targetGroups)
				progress += inc
				importTask.Percentage = int(progress)
				_ = clusHelper.PutImportTask(&importTask) // Ignore error because progress update is non-critical

				// [4]: import network policy rules/process profile/file access rules/group policy mode
				for i, grpCfgRet := range parsedGrpCfg {
					var crdRecord share.CLUSCrdSecurityRule // leverage CLUSCrdSecurityRule but we don't save it in kv
					var policyMode string
					var profileMode string
					var baseline string
					if grpCfgRet.PolicyModeCfg != nil && grpCfgRet.PolicyModeCfg.PolicyMode != nil {
						policyMode = *grpCfgRet.PolicyModeCfg.PolicyMode
						crdRecord.PolicyMode = policyMode
					}
					if grpCfgRet.ProcessProfileCfg != nil {
						// nodes, containers, service or user-defined groups
						profileMode = grpCfgRet.ProcessProfileCfg.Mode
						crdRecord = share.CLUSCrdSecurityRule{
							ProfileName:    grpCfgRet.TargetName,
							ProfileMode:    profileMode,
							ProcessProfile: &share.CLUSCrdProcessProfile{Baseline: grpCfgRet.ProcessProfileCfg.Baseline},
							ProcessRules:   crdHandler.crdGetProcessRules(grpCfgRet.ProcessProfileCfg),
							FileRules:      crdHandler.crdGetFileRules(grpCfgRet.FileProfileCfg),
						}
					}

					//  do same job as crdHandleNetworkRules(crdCfgRet.RuleCfgs, crdRecord)
					importGroupNetworkRules(grpCfgRet.RuleCfgs)

					if crdRecord.ProfileName != "" && utils.HasGroupProfiles(crdRecord.ProfileName) {
						secRuleName := fmt.Sprintf("group-import-%d", i)
						profileMode, baseline = crdHandler.crdRebuildGroupProfiles(crdRecord.ProfileName,
							map[string]*share.CLUSCrdSecurityRule{secRuleName: &crdRecord}, share.ReviewTypeImportGroup)
					}
					//policyMode = h.crdGetProfileSecurityLevel(profileName, "policyMode", recordList)
					crdHandler.crdHandlePolicyMode(grpCfgRet.TargetName, policyMode, profileMode, baseline)

					if hasDlpWafSetting, ok := targetGroupDlpWAF[grpCfgRet.TargetName]; ok && hasDlpWafSetting {
						if grpCfgRet.DlpGroupCfg == nil {
							grpCfgRet.DlpGroupCfg = &api.RESTCrdDlpGroupConfig{RepSensors: make([]api.RESTCrdDlpGroupSetting, 0)}
						}
						if grpCfgRet.WafGroupCfg == nil {
							grpCfgRet.WafGroupCfg = &api.RESTCrdWafGroupConfig{RepSensors: make([]api.RESTCrdWafGroupSetting, 0)}
						}

						txn := cluster.Transact()
						// [4]: import dlp group data
						crdHandler.crdHandleDlpGroup(txn, grpCfgRet.TargetName, grpCfgRet.DlpGroupCfg, share.UserCreated)
						// [5]: import waf group data
						crdHandler.crdHandleWafGroup(txn, grpCfgRet.TargetName, grpCfgRet.WafGroupCfg, share.UserCreated)
						if ok, err := txn.Apply(); err != nil || !ok {
							log.WithFields(log.Fields{"ok": ok, "error": err}).Error("Atomic write to the cluster failed")
						}
						txn.Close()
					}

					progress += inc
					importTask.Percentage = int(progress)
					_ = clusHelper.PutImportTask(&importTask) // Ignore error because progress update is non-critical
				}

				progress += inc
				importTask.Percentage = int(progress)
				_ = clusHelper.PutImportTask(&importTask) // Ignore error because progress update is non-critical
			}
		}
	}

	postImportOp(err, importTask, loginDomainRoles, "", share.IMPORT_TYPE_GROUP_POLICY)

	return nil
}

// Create/update all the imported groups except for the reserved group, external/nodes/containers/Workload:ingress
func importGroup(scope, targetGroup string, groups []api.RESTCrdGroupConfig) (utils.Set, bool, error) {
	var targetGroupDlpWAF bool
	updatedGroups := utils.NewSet()
	acc := access.NewAdminAccessControl()
	txn := cluster.Transact()
	defer txn.Close()

	reservedPrefix := []string{api.LearnedHostPrefix, api.LearnedWorkloadPrefix} // see isExportSkipGroupName()
	for _, group := range groups {
		if group.Name == api.LearnedExternal || group.Name == api.AllHostGroup || group.Name == api.AllContainerGroup {
			continue
		}
		groupCriteria := []api.RESTCriteriaEntry{}
		isNvIpGroup := strings.HasPrefix(group.Name, api.LearnedSvcGroupPrefix)
		// keep processing imported nv.ip.xxx group that has empty criteria when the group is not learned yet on docker swarm
		if (group.Criteria == nil || len(*group.Criteria) == 0) && !isNvIpGroup {
			continue
		} else if group.Criteria != nil {
			groupCriteria = *group.Criteria
		}

		reserved := false
		for _, prefix := range reservedPrefix {
			if strings.HasPrefix(group.Name, prefix) {
				log.WithFields(log.Fields{"group_name": group.Name, "prefix": prefix}).Debug("use reserved prefix")
				reserved = true
				break
			}
		}

		if reserved {
			continue
		}

		create := true
		cg, _, _ := clusHelper.GetGroup(group.Name, acc)
		if cg != nil {
			// group update case
			if scope == share.ScopeLocal && cg.CfgType == share.GroundCfg {
				// existing crd group cannot be modified by rest api & we cannot override its crd policies
				continue
			} else if isNvIpGroup && cg.CfgType == share.Learned {
				// if a learned nv.ip.xxx group exists, do not update it but we still need to import all its policies later
				updatedGroups.Add(cg.Name)
				continue
			}
			create = false
		} else {
			// new group add
			cg = &share.CLUSGroup{
				Name:           group.Name,
				CreaterDomains: acc.GetAdminDomains(share.PERMS_RUNTIME_POLICIES),
			}
			if utils.DoesGroupHavePolicyMode(group.Name) {
				cg.PolicyMode, cg.ProfileMode = cacher.GetNewServicePolicyMode()
				fmt.Println("New learned svc ", group.Name, "set service as ", cg.PolicyMode)
			}
			cg.CfgType = share.UserCreated
			if utils.IsGroupLearned(group.Name) {
				cg.CfgType = share.Learned
			}
		}
		cg.Criteria = make([]share.CLUSCriteriaEntry, 0, len(groupCriteria))
		cg.Comment = group.Comment
		if isNvIpGroup {
			cg.Kind = share.GroupKindIPService
		} else {
			cg.Kind = share.GroupKindContainer
		}
		for _, ct := range groupCriteria {
			if isNvIpGroup && ct.Key != share.CriteriaKeyDomain {
				// when creating a new nv.ip.xxx group, only keep "domain" key in its criteria. hopefully it should be learned later
				continue
			}
			cg.Criteria = append(cg.Criteria, share.CLUSCriteriaEntry{
				Key:   ct.Key,
				Value: ct.Value,
				Op:    ct.Op,
			})
			if ct.Key == share.CriteriaKeyAddress {
				cg.Kind = share.GroupKindAddress
			}
			if create && ct.Key == share.CriteriaKeyDomain && strings.HasPrefix(group.Name, api.LearnedGroupPrefix) {
				cg.Domain = ct.Value
			}
		}
		if cg.Name == targetGroup && cg.Kind == share.GroupKindContainer {
			targetGroupDlpWAF = true
		}
		if cg.Kind == share.GroupKindContainer && !cg.Reserved {
			if group.MonMetric != nil {
				cg.MonMetric = *group.MonMetric
			}
			if group.GrpSessCur != nil {
				cg.GrpSessCur = *group.GrpSessCur
			}
			if group.GrpSessRate != nil {
				cg.GrpSessRate = *group.GrpSessRate
			}
			if group.GrpBandWidth != nil {
				cg.GrpBandWidth = *group.GrpBandWidth
			}

		}

		if err := clusHelper.PutGroupTxn(txn, cg); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("PutGroupTxn")
		}

		updatedGroups.Add(cg.Name)
	}
	ok, err := txn.Apply()
	if err != nil || !ok {
		log.WithFields(log.Fields{"error": err, "ok": ok}).Error("Atomic write failed")
		if !ok {
			err = fmt.Errorf("Atomic write to the cluster failed")
		}
		updatedGroups.Clear()
	}

	return updatedGroups, targetGroupDlpWAF, err
}

func importGroupNetworkRules(rulesCfg []api.RESTPolicyRuleConfig) {
	if len(rulesCfg) == 0 {
		return
	}

	// we do not have CfgType for network rules in the exported yaml file.
	// so all imported network rules are treated as "user created"
	var cr *share.CLUSPolicyRule
	crhs := clusHelper.GetPolicyRuleList()
	idsUserCreated := utils.NewSet() // ids used by existing user-created rules
	startIdx := 0                    // the idx of first non-fed/non-crd rule in crhs
	startFound := false
	for i, crh := range crhs {
		if crh.CfgType == share.Learned || crh.CfgType == share.UserCreated {
			if crh.CfgType == share.UserCreated {
				idsUserCreated.Add(crh.ID)
			}
			if !startFound {
				startIdx = i
				startFound = true
			}
		}
	}
	if !startFound {
		startIdx = len(crhs)
	}

	newRules := make([]*share.CLUSRuleHead, 0, len(rulesCfg))

	txn := cluster.Transact()
	defer txn.Close()

	var hasError bool
	for _, ruleConf := range rulesCfg {
		ruleConf.ID = common.GetAvailablePolicyID(idsUserCreated, share.UserCreated)
		idsUserCreated.Add(ruleConf.ID)

		cr = &share.CLUSPolicyRule{
			ID:        ruleConf.ID,
			CreatedAt: time.Now().UTC(),
			Disable:   false,
			CfgType:   share.UserCreated,
		}
		newRules = append(newRules, &share.CLUSRuleHead{
			ID:      ruleConf.ID,
			CfgType: share.UserCreated,
			//Priority: ruleConf.Priority,
		})

		if ruleConf.From != nil {
			cr.From = *ruleConf.From
		}
		if ruleConf.To != nil {
			cr.To = *ruleConf.To
		}
		if ruleConf.Ports != nil {
			cr.Ports = *ruleConf.Ports
		}
		if ruleConf.Applications != nil {
			cr.Applications = appNames2IDs(*ruleConf.Applications)
		}
		if ruleConf.Action != nil {
			cr.Action = *ruleConf.Action
		}
		cr.Comment = "imported policy"
		cr.LastModAt = time.Now().UTC()
		//cr.Priority = ruleConf.Priority
		if err := clusHelper.PutPolicyRuleTxn(txn, cr); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("PutPolicyRuleTxn")
			hasError = true
			break
		}
	}
	crhs = append(crhs[:startIdx], append(newRules, crhs[startIdx:]...)...)
	if err := clusHelper.PutPolicyRuleListTxn(txn, crhs); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("PutPolicyRuleListTxn")
		hasError = true
	}

	if hasError {
		log.Error("Atomic write failed")
		return
	}

	if ok, err := txn.Apply(); err != nil || !ok {
		log.WithFields(log.Fields{"error": err, "ok": ok}).Error("Atomic write failed")
	}
}

func updateGroupStats(final *api.RESTStats, data *share.CLUSStats) {
	final.Interval = data.Interval
	final.Total.SessionIn += data.Total.SessionIn
	final.Total.SessionOut += data.Total.SessionOut
	final.Total.SessionCurIn += data.Total.SessionCurIn
	final.Total.SessionCurOut += data.Total.SessionCurOut
	final.Total.PacketIn += data.Total.PacketIn
	final.Total.PacketOut += data.Total.PacketOut
	final.Total.ByteIn += data.Total.ByteIn
	final.Total.ByteOut += data.Total.ByteOut

	final.Span1.CPU += data.Span1.CPU
	final.Span1.Memory += data.Span1.Memory
	final.Span1.SessionIn += data.Span1.SessionIn
	final.Span1.SessionOut += data.Span1.SessionOut
	final.Span1.PacketIn += data.Span1.PacketIn
	final.Span1.PacketOut += data.Span1.PacketOut
	final.Span1.ByteIn += data.Span1.ByteIn
	final.Span1.ByteOut += data.Span1.ByteOut

	final.Span12.CPU += data.Span12.CPU
	final.Span12.Memory += data.Span12.Memory
	final.Span12.SessionIn += data.Span12.SessionIn
	final.Span12.SessionOut += data.Span12.SessionOut
	final.Span12.PacketIn += data.Span12.PacketIn
	final.Span12.PacketOut += data.Span12.PacketOut
	final.Span12.ByteIn += data.Span12.ByteIn
	final.Span12.ByteOut += data.Span12.ByteOut

	final.Span60.CPU += data.Span60.CPU
	final.Span60.Memory += data.Span60.Memory
	final.Span60.SessionIn += data.Span60.SessionIn
	final.Span60.SessionOut += data.Span60.SessionOut
	final.Span60.PacketIn += data.Span60.PacketIn
	final.Span60.PacketOut += data.Span60.PacketOut
	final.Span60.ByteIn += data.Span60.ByteIn
	final.Span60.ByteOut += data.Span60.ByteOut
}

func handlerGroupStats(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	groupname := ps.ByName("name")
	if groupname == "" {
		log.Debug("Empty group name")
		return
	}

	if exist, err := cacher.DoesGroupExist(groupname, acc); !exist {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	resp := api.RESTGroupStatsData{
		Name:   groupname,
		ReadAt: api.RESTTimeString(time.Now()),
		Stats: &api.RESTStats{
			Interval: 0,
			Total:    api.RESTMetry{},
			Span1:    api.RESTMetry{},
			Span12:   api.RESTMetry{},
			Span60:   api.RESTMetry{},
		},
	}

	host_wl_map := make(map[string]utils.Set)
	gr, _ := cacher.GetGroup(groupname, "", false, acc)
	if gr != nil && len(gr.Members) > 0 {
		for _, wl := range gr.Members {
			if wl.HasDatapath {
				if host_wl_map[wl.HostID] == nil {
					host_wl_map[wl.HostID] = utils.NewSet()
				}
				host_wl_map[wl.HostID].Add(wl.ID)
			}
		}
	} else {
		restRespSuccess(w, r, &resp, acc, login, nil, "Get group network session counter")
		return
	}

	agent_wl_map := make(map[string]utils.Set)
	for _, wls := range host_wl_map {
		agtid := ""
		if wls != nil {
			for wl := range wls.Iter() {
				wlid := wl.(string)
				if agtid == "" {
					agentID, err := cacher.GetAgentbyWorkload(wlid, acc)
					if err != nil || agentID == "" {
						//try other workloads in group
						continue
					}
					agtid = agentID
				}
				if agtid != "" {
					if agent_wl_map[agtid] == nil {
						agent_wl_map[agtid] = utils.NewSet()
					}
					agent_wl_map[agtid].Add(wlid)
				}
			}
		}
	}
	//log.WithFields(log.Fields{"agent_wl_map": agent_wl_map}).Debug("")

	for agid, wlids := range agent_wl_map {
		var wla share.CLUSWlIDArray
		wla.WlID = make([]string, 0)
		if wlids != nil {
			for wl := range wlids.Iter() {
				wlid := wl.(string)
				wla.WlID = append(wla.WlID, wlid)
			}
		}
		stats, err := rpc.GetGroupStats(agid, &wla)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Fail to make RPC call")
			restRespError(w, http.StatusInternalServerError, api.RESTErrClusterRPCError)
			return
		}
		updateGroupStats(resp.Stats, stats)
	}
	resp.ReadAt = api.RESTTimeString(time.Now())

	restRespSuccess(w, r, &resp, acc, login, nil, "Get group network session counter")
}

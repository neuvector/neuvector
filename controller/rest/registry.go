package rest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/controller/scan"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
)

const (
	repoRepoLimitDefault    = 200
	repoTagLimitDefault     = 20
	gcrDefaultURL           = "https://gcr.io"
	ibmcloudDefaultTokenUrl = "https://iam.cloud.ibm.com/identity/token"
)

type tFedRegistryConfig struct {
	Registry      string
	Name          string
	Type          string
	AuthWithToken bool
	RescanImage   bool
	ScanLayers    bool
	DisableFiles  bool
	RepoLimit     int
	TagLimit      int
	Schedule      string
	PollPeriod    int
	JfrogMode     string
	JfrogAQL      bool
	CfgType       share.TCfgType
}

var orgRegexp = regexp.MustCompile(`^[a-zA-Z0-9.\-_]*$`)

var registryTypeList []string = []string{
	share.RegistryTypeAWSECR,
	share.RegistryTypeAzureACR,
	share.RegistryTypeDocker,
	share.RegistryTypeGCR,
	share.RegistryTypeJFrog,
	share.RegistryTypeOpenShift,
	share.RegistryTypeRedhat,
	share.RegistryTypeSonatypeNexus,
	share.RegistryTypeGitlab,
	share.RegistryTypeIBMCloud,
}
var registryTypeSet utils.Set = utils.NewSetFromSliceKind(registryTypeList)

func handlerRegistryTypeList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSRegistryTypeDummy{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	resp := api.RESTListData{List: &api.RESTList{RegistryType: registryTypeList}}
	restRespSuccess(w, r, &resp, acc, login, nil, "Get registry type list")
}

func parseWildcardRegex(s string) (string, error) {
	if s = strings.TrimSpace(s); s == "" {
		return "", errors.New("Invalid filter format")
	}
	// If * appears at the end, but not .* or ]* or )*, expand it to ".*", not to add ^$ yet.
	var out string
	if s == "*" {
		out = ".*"
	} else {
		for i := 0; i < len(s); i++ {
			if s[i] == '*' && (i == 0 || (s[i-1] != '.' && s[i-1] != ']' && s[i-1] != ')')) {
				out = fmt.Sprintf("%s.*", out)
			} else {
				out = fmt.Sprintf("%s%c", out, s[i])
			}
		}
	}
	if _, err := regexp.Compile(out); err != nil {
		return "", err
	}
	return out, nil
}

func parseFilter(filters []string, regType string) ([]*share.CLUSRegistryFilter, error) {
	if len(filters) == 0 {
		return make([]*share.CLUSRegistryFilter, 0), nil
	}

	repoFilters := make([]*share.CLUSRegistryFilter, len(filters))

	for n, filter := range filters {
		var org, repo, tag string
		var err error

		i := strings.Index(filter, "/")
		if i > 0 {
			org = filter[:i]
			filter = filter[i+1:]
		}
		repo = strings.TrimSpace(filter)

		i = strings.Index(filter, ":")
		if i > 0 {
			repo = strings.TrimSpace(filter[:i])
			tag = strings.TrimSpace(filter[i+1:])
		}

		// org
		if (org != "" && !orgRegexp.MatchString(org)) || (org == "" && filter != "*" && regType == share.RegistryTypeOpenShift) {
			log.WithFields(log.Fields{"org": org, "type": regType}).Error("Failed to parse organization in the filter")
			return nil, errors.New("Invalid filter format")
		}

		// repo
		if repo, err = parseWildcardRegex(repo); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to parse repository in the filter")
			return nil, errors.New("Regular express error in repository")
		}

		// tag
		if tag == "" {
			tag = ".*"
		} else if tag, err = parseWildcardRegex(tag); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to parse tag in the filter")
			return nil, errors.New("Regular express error in tag")
		}

		repoFilters[n] = &share.CLUSRegistryFilter{Org: org, Repo: repo, Tag: tag}
		log.WithFields(log.Fields{"parsed": repoFilters[n]}).Debug("")
	}

	return repoFilters, nil
}

func registryConfigV2ToV1(v2data api.RESTRegistryConfigDataV2) api.RESTRegistryConfigData {
	v1data := api.RESTRegistryConfigData{
		Config: &api.RESTRegistryConfig{},
	}

	if v2data.Config != nil {
		v1data.Config.Name = v2data.Config.Name
		v1data.Config.Type = v2data.Config.Type
		v1data.Config.Registry = v2data.Config.Registry
		v1data.Config.Domains = v2data.Config.Domains
		v1data.Config.Filters = v2data.Config.Filters
		v1data.Config.CfgType = v2data.Config.CfgType

		if v2data.Config.Auth != nil {
			v1data.Config.Username = v2data.Config.Auth.Username
			v1data.Config.Password = v2data.Config.Auth.Password
			v1data.Config.AuthToken = v2data.Config.Auth.AuthToken
			v1data.Config.AuthWithToken = v2data.Config.Auth.AuthWithToken
			v1data.Config.AwsKey = v2data.Config.Auth.AwsKey
			v1data.Config.GcrKey = v2data.Config.Auth.GcrKey
		}
		if v2data.Config.Scan != nil {
			v1data.Config.RescanImage = v2data.Config.Scan.RescanImage
			v1data.Config.ScanLayers = v2data.Config.Scan.ScanLayers
			v1data.Config.RepoLimit = v2data.Config.Scan.RepoLimit
			v1data.Config.TagLimit = v2data.Config.Scan.TagLimit
			v1data.Config.Schedule = v2data.Config.Scan.Schedule
			v1data.Config.IgnoreProxy = v2data.Config.Scan.IgnoreProxy
		}
		if v2data.Config.Integrations != nil {
			v1data.Config.JfrogMode = v2data.Config.Integrations.JfrogMode
			v1data.Config.JfrogAQL = v2data.Config.Integrations.JfrogAQL
			v1data.Config.GitlabApiUrl = v2data.Config.Integrations.GitlabApiUrl
			v1data.Config.GitlabPrivateToken = v2data.Config.Integrations.GitlabPrivateToken
			v1data.Config.IBMCloudTokenURL = v2data.Config.Integrations.IBMCloudTokenURL
			v1data.Config.IBMCloudAccount = v2data.Config.Integrations.IBMCloudAccount
		}
	}

	return v1data
}

func handlerRegistryCreate(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()
	var err error

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

	var data api.RESTRegistryConfigData
	body, _ := io.ReadAll(r.Body)

	if getRequestApiVersion(r) == ApiVersion2 {
		var v2data api.RESTRegistryConfigDataV2
		err := json.Unmarshal(body, &v2data)
		if err != nil || v2data.Config == nil {
			restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
			return
		}
		data = registryConfigV2ToV1(v2data)
	} else {
		err = json.Unmarshal(body, &data)
		if err != nil || data.Config == nil {
			restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
			return
		}
	}

	rconf := data.Config

	if !isObjectNameValid(rconf.Name) {
		e := "Invalid characters in name"
		log.WithFields(log.Fields{"name": rconf.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidName, e)
		return
	}

	var e string
	if rconf.CfgType == api.CfgTypeFederal {
		if !strings.HasPrefix(rconf.Name, api.FederalGroupPrefix) || rconf.Name == api.FederalGroupPrefix {
			e = "Federal registry name must start with 'fed.' but cannot be just 'fed.'"
		}
	} else if strings.HasPrefix(rconf.Name, api.FederalGroupPrefix) {
		e = "Local registry name must not start with 'fed.'"
	}
	if e != "" {
		log.WithFields(log.Fields{"name": rconf.Name}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}

	if cc, _, _ := clusHelper.GetRegistry(rconf.Name, acc); cc != nil {
		log.WithFields(log.Fields{"Name": cc.Name}).Error("Duplicate registry name")
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrDuplicateName, "Duplicate registry name found")
		return
	}

	config := share.CLUSRegistryConfig{
		Name:           rconf.Name,
		CreaterDomains: acc.GetAdminDomains(share.PERM_REG_SCAN),
		CfgType:        share.UserCreated,
	}
	if rconf.CfgType == api.CfgTypeFederal {
		config.CfgType = share.FederalCfg
	}

	if registryTypeSet.Contains(rconf.Type) {
		config.Type = rconf.Type
	} else {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Unsupported registry Type")
		return
	}

	if rconf.Schedule == nil {
		config.Schedule = api.ScanSchManual
	} else if rconf.Schedule.Schedule == "" {
		config.Schedule = api.ScanSchManual
	} else {
		switch rconf.Type {
		case share.RegistryTypeOpenShift:
			switch rconf.Schedule.Schedule {
			case api.ScanSchManual, api.ScanSchAuto:
				config.Schedule = rconf.Schedule.Schedule
			default:
				log.WithFields(log.Fields{"schedule": rconf.Schedule.Schedule}).Error("Invalid schedule")
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Invalid schedule")
				return
			}
		default:
			switch rconf.Schedule.Schedule {
			case api.ScanSchManual:
				config.Schedule = rconf.Schedule.Schedule
			case api.ScanSchPeriodical:
				if rconf.Schedule.Interval < api.ScanIntervalMin ||
					rconf.Schedule.Interval > api.ScanIntervalMax {
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Schedule interval is out of range")
					return
				}
				config.Schedule = rconf.Schedule.Schedule
				config.PollPeriod = rconf.Schedule.Interval
			default:
				log.WithFields(log.Fields{"schedule": rconf.Schedule.Schedule}).Error("Invalid schedule")
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Invalid schedule")
				return
			}
		}
	}

	// aws ecr
	if rconf.Type == share.RegistryTypeAWSECR {
		if rconf.AwsKey == nil {
			log.Error("Missing AWS key")
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Missing AWS keys")
			return
		}

		config.AwsKey = &share.CLUSAWSAccountKey{}
		if rconf.AwsKey.ID != nil {
			config.AwsKey.ID = *rconf.AwsKey.ID
		}
		if rconf.AwsKey.AccessKeyID != nil {
			config.AwsKey.AccessKeyID = *rconf.AwsKey.AccessKeyID
		}
		if rconf.AwsKey.SecretAccessKey != nil {
			config.AwsKey.SecretAccessKey = *rconf.AwsKey.SecretAccessKey
		}
		if rconf.AwsKey.Region != nil {
			config.AwsKey.Region = *rconf.AwsKey.Region
		}

		var proxy string
		if !config.IgnoreProxy {
			proxy = scan.GetProxy(config.Registry)
		}
		auth, err := scan.GetAwsEcrAuthToken(config.AwsKey, proxy)
		if err != nil {
			e := "Failed to get authorization token by AWS keys"
			log.WithFields(log.Fields{"err": err}).Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
			return
		}

		config.Registry = auth.ProxyEndpoint
		config.Username = auth.Username
		config.Password = auth.Password
		log.WithFields(log.Fields{"URL": config.Registry}).Debug("AWS registry")
	} else if rconf.Type == share.RegistryTypeGCR {
		if rconf.GcrKey == nil {
			log.Error("No GCR json key provided")
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "No GCR json key provided")
			return
		}

		config.GcrKey = &share.CLUSGCRKey{}
		if rconf.GcrKey.JsonKey != nil {
			config.GcrKey.JsonKey = *rconf.GcrKey.JsonKey
		}

		if rconf.Registry == nil {
			config.Registry = gcrDefaultURL
		} else {
			config.Registry, err = scanUtils.ParseRegistryURI(*rconf.Registry)
			if err != nil {
				log.WithFields(log.Fields{"err": err}).Error("Invalid registry URL")
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Invalid registry URL")
				return
			}
		}
	} else {
		if rconf.Registry == nil {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Missing registry URL")
			return
		}

		config.Registry, err = scanUtils.ParseRegistryURI(*rconf.Registry)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Error("Invalid registry URL")
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Invalid registry URL")
			return
		}

		if rconf.Username != nil {
			config.Username = *rconf.Username
		}
		if rconf.Password != nil {
			config.Password = *rconf.Password
		}
		if rconf.AuthToken != nil {
			config.AuthToken = *rconf.AuthToken
		}
		if rconf.AuthWithToken != nil {
			config.AuthWithToken = *rconf.AuthWithToken

			if config.AuthWithToken && config.AuthToken == "" {
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Missing authentication token")
				return
			}
		}
	}

	// Jfrog config
	if rconf.Type == share.RegistryTypeJFrog {
		if rconf.JfrogMode == nil ||
			(*rconf.JfrogMode != share.JFrogModeRepositoryPath &&
				*rconf.JfrogMode != share.JFrogModeSubdomain &&
				*rconf.JfrogMode != share.JFrogModePort) {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Invalid Jfrog mode")
			return
		}
		config.JfrogMode = *rconf.JfrogMode
		// aql default disable
		if rconf.JfrogAQL != nil {
			config.JfrogAQL = *rconf.JfrogAQL
		}
	}

	// gitlab
	if rconf.Type == share.RegistryTypeGitlab {
		if !strings.HasPrefix(config.Registry, "https") {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Gitlab container registry should start with https")
			return
		}
		if rconf.GitlabApiUrl == nil {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Missing gitlab external url")
			return
		}
		ur, err := scanUtils.ParseRegistryURI(*rconf.GitlabApiUrl)
		if err != nil {
			log.WithFields(log.Fields{"err": err}).Error("Invalid Gitlab external_url")
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Invalid Gitlab external_url")
			return
		}
		config.GitlabApiUrl = ur
		if rconf.GitlabPrivateToken != nil {
			config.GitlabPrivateToken = *rconf.GitlabPrivateToken
		}
	}

	if rconf.Type == share.RegistryTypeIBMCloud {
		if rconf.IBMCloudAccount == nil {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "IBM Cloud account is missing")
			return
		} else {
			config.IBMCloudAccount = *rconf.IBMCloudAccount
		}
		if rconf.IBMCloudTokenURL != nil {
			config.IBMCloudTokenURL = *rconf.IBMCloudTokenURL
		} else {
			config.IBMCloudTokenURL = ibmcloudDefaultTokenUrl
		}
	}

	if rconf.Domains != nil {
		config.Domains = *rconf.Domains
	}

	if rconf.RescanImage != nil {
		config.RescanImage = *rconf.RescanImage
	} else {
		// Default enable
		config.RescanImage = true
	}

	// scan image layers, default disable
	if rconf.ScanLayers != nil {
		config.ScanLayers = *rconf.ScanLayers
	}

	if rconf.RepoLimit != nil {
		config.RepoLimit = *rconf.RepoLimit
	} else {
		config.RepoLimit = repoRepoLimitDefault
	}

	if rconf.TagLimit != nil {
		config.TagLimit = *rconf.TagLimit
	} else {
		config.TagLimit = repoTagLimitDefault
	}

	if rconf.Filters != nil {
		filters := *rconf.Filters
		sort.Slice(filters, func(i, j int) bool { return filters[i] < filters[j] })
		rfilters, err := parseFilter(filters, config.Type)
		if err != nil {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
			return
		} else if rconf.Type == share.RegistryTypeOpenShift {
			// for openshift registry, user must have reg_scan:w permission on every namespace specified in filter
			for _, rfilter := range rfilters {
				// namespace in each filter must be accessible(reg_scan:w) by this user
				if !acc.Authorize(rfilter, nil) {
					msg := fmt.Sprintf("You don't not have permission on namespace '%s'", rfilter.Org)
					restRespErrorMessage(w, http.StatusForbidden, api.RESTErrObjectAccessDenied, msg)
					return
				}
			}
		}

		config.Filters = filters
		config.ParsedFilters = rfilters
	} else {
		config.Filters = make([]string, 0)
		config.ParsedFilters = make([]*share.CLUSRegistryFilter, 0)
	}

	if rconf.IgnoreProxy != nil {
		config.IgnoreProxy = *rconf.IgnoreProxy
	}

	// For every domain that a registry is in, the user must have PERM_REG_SCAN(modify) permission in the domain
	// (use a copy object without parsed filters so that the registr's domains/creatorDomains are used for access control checking)
	configTemp := config
	configTemp.ParsedFilters = nil
	if !acc.AuthorizeOwn(&configTemp, nil) {
		restRespAccessDenied(w, login)
		return
	}

	if err := clusHelper.PutRegistryIfNotExist(&config); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}

	if config.CfgType == share.FederalCfg {
		if fedRole := cacher.GetFedMembershipRoleNoAuth(); fedRole == api.FedRoleMaster {
			clusHelper.UpdateFedScanDataRevisions(resource.Update, "", config.Name, "")
		}
	}

	restRespSuccess(w, r, nil, acc, login, &rconf, "Create registry")
}

func handlerRegistryConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
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

	var data api.RESTRegistryConfigData
	body, _ := io.ReadAll(r.Body)

	if getRequestApiVersion(r) == ApiVersion2 {
		var v2data api.RESTRegistryConfigDataV2
		err := json.Unmarshal(body, &v2data)
		if err != nil || v2data.Config == nil {
			restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
			return
		}
		data = registryConfigV2ToV1(v2data)
	} else {
		err := json.Unmarshal(body, &data)
		if err != nil || data.Config == nil {
			restRespError(w, http.StatusBadRequest, api.RESTErrInvalidRequest)
			return
		}
	}

	name := ps.ByName("name")
	rconf := data.Config

	if rconf.Name != name {
		log.WithFields(log.Fields{"registry": rconf.Name}).Error("Name mismatch")
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Name mismatch")
		return
	}

	retry := 0
	var cfgType share.TCfgType
	for retry < retryClusterMax {
		config, rev, err := clusHelper.GetRegistry(name, acc)
		if config == nil {
			restRespNotFoundLogAccessDenied(w, login, err)
			return
		}

		if rconf.Type != "" && rconf.Type != config.Type {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Registry type can't be changed")
			return
		}
		cfgType = config.CfgType

		if rconf.Schedule == nil {
		} else if rconf.Schedule.Schedule == "" {
			config.Schedule = api.ScanSchManual
		} else {
			switch config.Type {
			case share.RegistryTypeOpenShift:
				switch rconf.Schedule.Schedule {
				case api.ScanSchManual, api.ScanSchAuto:
					config.Schedule = rconf.Schedule.Schedule
				default:
					log.WithFields(log.Fields{"schedule": rconf.Schedule.Schedule}).Error("Invalid schedule")
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Invalid schedule")
					return
				}
			default:
				switch rconf.Schedule.Schedule {
				case api.ScanSchManual:
					config.Schedule = rconf.Schedule.Schedule
				case api.ScanSchPeriodical:
					if rconf.Schedule.Interval < api.ScanIntervalMin ||
						rconf.Schedule.Interval > api.ScanIntervalMax {
						restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Schedule interval is out of range")
						return
					}
					config.Schedule = rconf.Schedule.Schedule
					config.PollPeriod = rconf.Schedule.Interval
				default:
					log.WithFields(log.Fields{"schedule": rconf.Schedule.Schedule}).Error("Invalid schedule")
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Invalid schedule")
					return
				}
			}
		}

		// aws ecr
		if config.Type == share.RegistryTypeAWSECR {
			if rconf.AwsKey != nil {
				if config.AwsKey == nil {
					config.AwsKey = &share.CLUSAWSAccountKey{}
				}
				if rconf.AwsKey.ID != nil {
					config.AwsKey.ID = *rconf.AwsKey.ID
				}
				if rconf.AwsKey.AccessKeyID != nil {
					config.AwsKey.AccessKeyID = *rconf.AwsKey.AccessKeyID
				}
				if rconf.AwsKey.SecretAccessKey != nil {
					config.AwsKey.SecretAccessKey = *rconf.AwsKey.SecretAccessKey
				}
				if rconf.AwsKey.Region != nil {
					config.AwsKey.Region = *rconf.AwsKey.Region
				}

				var proxy string
				if !config.IgnoreProxy {
					proxy = scan.GetProxy(config.Registry)
				}
				auth, err := scan.GetAwsEcrAuthToken(config.AwsKey, proxy)
				if err != nil {
					e := "Failed to get authorization token by AWS keys"
					log.WithFields(log.Fields{"err": err}).Error(e)
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
					return
				}

				config.Registry = auth.ProxyEndpoint
				config.Username = auth.Username
				config.Password = auth.Password
				log.WithFields(log.Fields{"URL": config.Registry}).Debug("AWS registry")
			}
		} else if config.Type == share.RegistryTypeGCR {
			if rconf.GcrKey != nil {
				if config.GcrKey == nil {
					config.GcrKey = &share.CLUSGCRKey{}
				}
				if rconf.GcrKey.JsonKey != nil {
					config.GcrKey.JsonKey = *rconf.GcrKey.JsonKey
				}
			}

			if rconf.Registry != nil {
				var err error
				config.Registry, err = scanUtils.ParseRegistryURI(*rconf.Registry)
				if err != nil {
					log.WithFields(log.Fields{"err": err}).Error("Invalid registry URL")
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Invalid registry URL")
					return
				}
			}
		} else {
			var err error
			if rconf.Registry != nil {
				config.Registry, err = scanUtils.ParseRegistryURI(*rconf.Registry)
				if err != nil {
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Invalid registry URL")
					return
				}
			}

			if rconf.Username != nil {
				config.Username = *rconf.Username
			}
			if rconf.Password != nil {
				config.Password = *rconf.Password
			}
			if rconf.AuthToken != nil {
				config.AuthToken = *rconf.AuthToken
			}
			if rconf.AuthWithToken != nil {
				config.AuthWithToken = *rconf.AuthWithToken

				if config.AuthWithToken && config.AuthToken == "" {
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Missing authentication token")
					return
				}
			}
		}

		// Jfrog config
		if config.Type == share.RegistryTypeJFrog {
			if rconf.JfrogMode != nil &&
				(*rconf.JfrogMode != share.JFrogModeRepositoryPath &&
					*rconf.JfrogMode != share.JFrogModeSubdomain &&
					*rconf.JfrogMode != share.JFrogModePort) {
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Invalid Jfrog mode")
				return
			}
			if rconf.JfrogMode != nil {
				config.JfrogMode = *rconf.JfrogMode
			}
			if rconf.JfrogAQL != nil {
				config.JfrogAQL = *rconf.JfrogAQL
			}
		}

		// gitlab
		if config.Type == share.RegistryTypeGitlab {
			if !strings.HasPrefix(config.Registry, "https") {
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Gitlab container registry should start with https")
				return
			}
			if rconf.GitlabApiUrl != nil {
				ur, err := scanUtils.ParseRegistryURI(*rconf.GitlabApiUrl)
				if err != nil {
					log.WithFields(log.Fields{"err": err}).Error("Invalid Gitlab external_url")
					restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "Invalid Gitlab external_url")
					return
				}
				config.GitlabApiUrl = ur
			}
			if rconf.GitlabPrivateToken != nil {
				config.GitlabPrivateToken = *rconf.GitlabPrivateToken
			}
		}

		if config.Type == share.RegistryTypeIBMCloud {
			if rconf.IBMCloudAccount != nil {
				config.IBMCloudAccount = *rconf.IBMCloudAccount
			}
			if rconf.IBMCloudTokenURL != nil {
				config.IBMCloudTokenURL = *rconf.IBMCloudTokenURL
			}
		}

		if rconf.Domains != nil {
			config.Domains = *rconf.Domains
		}

		if rconf.RescanImage != nil {
			config.RescanImage = *rconf.RescanImage
		}

		if rconf.ScanLayers != nil {
			config.ScanLayers = *rconf.ScanLayers
		}

		if rconf.RepoLimit != nil {
			config.RepoLimit = *rconf.RepoLimit
		}

		if rconf.TagLimit != nil {
			config.TagLimit = *rconf.TagLimit
		}

		if rconf.Filters != nil {
			filters := *rconf.Filters
			sort.Slice(filters, func(i, j int) bool { return filters[i] < filters[j] })
			rfilters, err := parseFilter(filters, config.Type)
			if err != nil {
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
				return
			} else if config.Type == share.RegistryTypeOpenShift {
				// for openshift registry, every namespace specified in filter must be in registry's creatorDomain
				if config.CreaterDomains != nil {
					creatorDomains := utils.NewSetFromSliceKind(config.CreaterDomains)
					for _, rfilter := range rfilters {
						var msg string
						if !creatorDomains.Contains(rfilter.Org) {
							// namespace in each filter must be in registry's creatorDomains
							msg = fmt.Sprintf("The creator of this registry doesn't not have permission on namespace '%s'", rfilter.Org)
						} else if !acc.Authorize(rfilter, nil) {
							// namespace in each filter must be accessible(reg_scan:w) by this user
							msg = fmt.Sprintf("You don't not have permission on namespace '%s'", rfilter.Org)
						}
						if msg != "" {
							restRespErrorMessage(w, http.StatusForbidden, api.RESTErrObjectAccessDenied, msg)
							return
						}
					}
				}
			}

			config.Filters = filters
			config.ParsedFilters = rfilters
		}

		if rconf.IgnoreProxy != nil {
			config.IgnoreProxy = *rconf.IgnoreProxy
		}

		// For every domain that a registry is in, the user must have PERM_REG_SCAN(modify) permission in the domain
		// (use a copy object without parsed filters so that the registr's domains/creatorDomains are used for access control checking)
		configTemp := *config
		configTemp.ParsedFilters = nil
		if !acc.AuthorizeOwn(&configTemp, nil) {
			restRespAccessDenied(w, login)
			return
		}

		if err := clusHelper.PutRegistry(config, rev); err != nil {
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

	if cfgType == share.FederalCfg {
		if fedRole := cacher.GetFedMembershipRoleNoAuth(); fedRole == api.FedRoleMaster {
			clusHelper.UpdateFedScanDataRevisions(resource.Update, "", name, "")
		}
	}

	restRespSuccess(w, r, nil, acc, login, &rconf, "Configure registry")
}

func handlerRegistryImageSummary(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	name := ps.ByName("name")

	if state, err := scanner.GetRegistryState(name, acc); state == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	query := restParseQuery(r)

	var resp api.RESTRegistryImageSummaryData
	resp.Images = make([]*api.RESTRegistryImageSummary, 0)

	vpf := cacher.GetVulnerabilityProfileInterface(share.DefaultVulnerabilityProfileName)

	images := scanner.GetRegistryImageSummary(name, vpf, acc)

	// Sort
	sort.Slice(images, func(i, j int) bool {
		if images[i].Domain < images[j].Domain {
			return true
		} else if images[i].Domain > images[j].Domain {
			return false
		} else if images[i].Repository < images[j].Repository {
			return true
		} else if images[i].Repository > images[j].Repository {
			return false
		} else if images[i].Tag < images[j].Tag {
			return true
		} else {
			return false
		}
	})

	// Filter
	if len(images) <= query.start {
		restRespSuccess(w, r, &resp, acc, login, nil, "Get registry debug image list")
		return
	}

	if len(query.filters) > 0 {
		var dummy api.RESTRegistryImageSummary
		rf := restNewFilter(&dummy, query.filters)

		for _, image := range images[query.start:] {
			if !rf.Filter(image) {
				continue
			}

			resp.Images = append(resp.Images, image)

			if query.limit > 0 && len(resp.Images) >= query.limit {
				break
			}
		}
	} else if query.limit == 0 {
		resp.Images = images[query.start:]
	} else {
		var end int
		if query.start+query.limit > len(images) {
			end = len(images)
		} else {
			end = query.start + query.limit
		}
		resp.Images = images[query.start:end]
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get registry image summary")
}

func handlerRegistryShow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	name := ps.ByName("name")

	// To see a registry, the caller only needs reg_scan:r permission on one of the registry's domains
	summary, err := scanner.GetRegistrySummary(name, acc)
	if summary == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	resp := api.RESTRegistrySummaryData{Summary: summary}
	restRespSuccess(w, r, &resp, acc, login, nil, "Get registry summary")
}

func handlerRegistryList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else {
		query := restParseQuery(r)
		scope := query.pairs[api.QueryScope] // empty string means fed & local groups

		list := scanner.GetAllRegistrySummary(scope, acc)
		sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
		log.WithFields(log.Fields{"entries": len(list)}).Debug("Response")

		resp := api.RESTRegistrySummaryListData{Summarys: list}
		restRespSuccess(w, r, &resp, acc, login, nil, "Get registry summary list")
	}
}

func handlerRegistryImageReport(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	name := ps.ByName("name")
	id := ps.ByName("id")

	query := restParseQuery(r)

	var showTag string
	if value, ok := query.pairs[api.QueryKeyShow]; ok && value == api.QueryValueShowAccepted {
		showTag = api.QueryValueShowAccepted
	}

	vpf := cacher.GetVulnerabilityProfileInterface(share.DefaultVulnerabilityProfileName)

	// build image compliance list and filter the list
	cpf := &complianceProfileFilter{filter: make(map[string][]string)}
	if cp, filter, err := cacher.GetComplianceProfile(share.DefaultComplianceProfileName, access.NewReaderAccessControl()); err != nil {
		log.WithFields(log.Fields{"profile": share.DefaultComplianceProfileName}).Error("Compliance profile not found")
	} else {
		cpf = &complianceProfileFilter{
			disableSystem: cp.DisableSystem, filter: filter, object: &api.RESTRegistryImageSummary{ImageID: id},
		}
	}

	rept, err := scanner.GetRegistryImageReport(name, id, vpf, showTag, cpf.filter, acc)
	if rept == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	rept.Checks = filterComplianceChecks(rept.Checks, cpf)

	resp := api.RESTScanReportData{Report: rept}
	restRespSuccess(w, r, &resp, acc, login, nil, "Get registry image scan report")
}

func handlerRegistryLayersReport(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	name := ps.ByName("name")
	id := ps.ByName("id")

	query := restParseQuery(r)

	var showTag string
	if value, ok := query.pairs[api.QueryKeyShow]; ok && value == api.QueryValueShowAccepted {
		showTag = api.QueryValueShowAccepted
	}

	vpf := cacher.GetVulnerabilityProfileInterface(share.DefaultVulnerabilityProfileName)

	rept, err := scanner.GetRegistryLayersReport(name, id, vpf, showTag, acc)
	if rept == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	resp := api.RESTScanLayersReportData{Report: rept}
	restRespSuccess(w, r, &resp, acc, login, nil, "Get registry image scan report")
}

func handlerRegistryStart(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
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

	name := ps.ByName("name")

	// To start scanning on a registry, the caller only needs reg_scan:w permission on one of the registry's domains
	state, err := scanner.GetRegistryState(name, acc)
	if state == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	// Backend can safely allow registry to be deleted while scanning, so this check doesn't
	// have to handle the racing case, no need to lock.
	if state.Status == api.RegistryStatusScanning {
		restRespSuccess(w, r, nil, acc, login, nil, "Start registry scan")
		return
	}

	// Allow manual start even if auto-scan is enabled, as long as it's not scanning

	if err := scanner.StartRegistry(name); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}

	restRespSuccess(w, r, nil, acc, login, nil, "Start registry scan")
}

func handlerRegistryStop(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
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

	name := ps.ByName("name")

	// To stop scanning on a registry, the caller only needs reg_scan:w permission on one of the registry's domains
	state, err := scanner.GetRegistryState(name, acc)
	if state == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	// Backend can safely allow starting registry scan twice, so this check doesn't
	// have to handle the racing case, no need to lock.
	if state.Status != api.RegistryStatusScanning {
		restRespSuccess(w, r, nil, acc, login, nil, "Stop registry scan")
		return
	}

	// Allow manual stop even if auto-scan is enabled, scan can be restarted manually or with new images added

	if err := scanner.StopRegistry(name); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}

	restRespSuccess(w, r, nil, acc, login, nil, "Stop registry scan")
}

func handlerRegistryDelete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
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

	name := ps.ByName("name")

	state, err := scanner.GetRegistryState(name, acc)
	if state == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	// Backend can safely allow registry to be deleted while scanning, so this check doesn't
	// have to handle the racing case, no need to lock.
	if state.Status == api.RegistryStatusScanning {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest,
			"Cannot delete the registry while scan is running")
		return
	}

	var cfgType share.TCfgType
	// Need furthur authorize for namespace users
	// For every domain that a registry is in, the user must have PERM_REG_SCAN(modify) permission in the domain
	// (use a copy object without parsed filters so that the registr's domains/creatorDomains are used for access control checking)
	if cc, _, err := clusHelper.GetRegistry(name, acc); cc == nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	} else {
		cfgType = cc.CfgType
		ccTemp := *cc
		ccTemp.ParsedFilters = nil
		if !acc.AuthorizeOwn(&ccTemp, nil) {
			restRespAccessDenied(w, login)
			return
		}
	}

	if err := clusHelper.DeleteRegistry(nil, name); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		restRespError(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster)
		return
	}

	if cfgType == share.FederalCfg {
		if fedRole := cacher.GetFedMembershipRoleNoAuth(); fedRole == api.FedRoleMaster {
			clusHelper.UpdateFedScanDataRevisions(resource.Delete, "", name, "")
		}
	}

	restRespSuccess(w, r, nil, acc, login, nil, "Registry delete")
}

// func diffStringSlices(a, b []string) []string {
// 	mb := make(map[string]struct{}, len(b))
// 	for _, x := range b {
// 		mb[x] = struct{}{}
// 	}
// 	var diff []string
// 	for _, x := range a {
// 		if _, found := mb[x]; !found {
// 			diff = append(diff, x)
// 		}
// 	}
// 	return diff
// }

// called by managed clusters
func replaceFedRegistryConfig(newRegs []*share.CLUSRegistryConfig) bool {
	old := clusHelper.GetAllRegistry(share.ScopeFed)
	oldRegs := make(map[string]*share.CLUSRegistryConfig, len(old))
	for _, o := range old {
		oldRegs[o.Name] = o
	}

	txn := cluster.Transact()
	defer txn.Close()

	for _, n := range newRegs {
		foundSameReg := false
		if o, ok := oldRegs[n.Name]; ok {
			// found same-name fed registry in existing kv keys
			if ((o.AwsKey == nil && n.AwsKey == nil) || (o.AwsKey != nil && n.AwsKey != nil && *o.AwsKey == *n.AwsKey)) && len(o.Filters) == len(n.Filters) {
				oldFilters := utils.NewSetFromSliceKind(o.Filters)
				newFilters := utils.NewSetFromSliceKind(n.Filters)
				if diff := oldFilters.SymmetricDifference(newFilters); diff.Cardinality() == 0 {
					oTemp := tFedRegistryConfig{
						Registry:      o.Registry,
						Name:          o.Name,
						Type:          o.Type,
						AuthWithToken: o.AuthWithToken,
						RescanImage:   o.RescanImage,
						ScanLayers:    o.ScanLayers,
						DisableFiles:  o.DisableFiles,
						RepoLimit:     o.RepoLimit,
						TagLimit:      o.TagLimit,
						Schedule:      o.Schedule,
						PollPeriod:    o.PollPeriod,
						JfrogMode:     o.JfrogMode,
						JfrogAQL:      o.JfrogAQL,
						CfgType:       o.CfgType,
					}
					nTemp := tFedRegistryConfig{
						Registry:      n.Registry,
						Name:          n.Name,
						Type:          n.Type,
						AuthWithToken: n.AuthWithToken,
						RescanImage:   n.RescanImage,
						ScanLayers:    n.ScanLayers,
						DisableFiles:  n.DisableFiles,
						RepoLimit:     n.RepoLimit,
						TagLimit:      n.TagLimit,
						Schedule:      n.Schedule,
						PollPeriod:    n.PollPeriod,
						JfrogMode:     n.JfrogMode,
						JfrogAQL:      n.JfrogAQL,
						CfgType:       n.CfgType,
					}
					if oTemp == nTemp {
						foundSameReg = true
					}
				}
			}
			delete(oldRegs, n.Name)
		}
		if !foundSameReg {
			value, _ := json.Marshal(*n)
			txn.Put(share.CLUSRegistryConfigKey(n.Name), value)
		}
	}
	for name := range oldRegs {
		txn.Delete(share.CLUSRegistryConfigKey(name))
	}

	return applyTransact(nil, txn) == nil
}

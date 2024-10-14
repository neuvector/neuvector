package rest

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	//"math/rand"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

type ibmsaToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToekn string `json:"refrsh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Expiration   int64  `json:"expiration"`
	Scope        string `json:"scope"`
}

type ibmsaContext struct {
	Region          string `json:"region"`
	ResourceCrn     string `json:"resource_crn"`
	ResourceID      string `json:"resource_id"`
	ResourceName    string `json:"resource_name"`
	ResourceType    string `json:"resource_type"`
	ServiceCrn      string `json:"service_crn"`
	ServiceName     string `json:"service_name"`
	EnvironmentName string `json:"environment_name"`
	ComponentName   string `json:"component_name"`
	ToolchainID     string `json:"toolchain_id"`
}

type ibmsaRemediationStep struct {
	Title string `json:"title"`
	Url   string `json:"url,omitempty"`
}

type ibmsaSocketAddress struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
}

type ibmsaNetworkConnection struct {
	Direction string             `json:"direction"`
	Protocol  string             `json:"protocol"`
	Client    ibmsaSocketAddress `json:"client"`
	Server    ibmsaSocketAddress `json:"server"`
}

type ibmsaDataTransferred struct {
	ClientBytes   int32 `json:"client_bytes"`
	ServerBytes   int32 `json:"server_bytes"`
	ClientPackets int32 `json:"client_packets"`
	ServerPackets int32 `json:"server_packets"`
}

type ibmsaFinding struct {
	Severity          string                  `json:"severity"`
	Certainty         string                  `json:"certainty"`
	NextSteps         []ibmsaRemediationStep  `json:"next_steps"`
	NetworkConnection *ibmsaNetworkConnection `json:"network_connection"`
	DataTransferred   *ibmsaDataTransferred   `json:"data_transferred"`
}

type ibmsaKpi struct {
	Value int `json:"value"`
	Total int `json:"total"`
}

type ibmsaOccurrences struct {
	NoteName    string        `json:"note_name"`
	Kind        string        `json:"kind"`
	ID          string        `json:"id"`
	Context     ibmsaContext  `json:"context"`
	Name        string        `json:"name"`
	ResourceUrl string        `json:"resource_url"`
	Remediation string        `json:"remediation"`
	CreateTime  string        `json:"create_time"`
	UpdateTime  string        `json:"update_time"`
	ProviderID  string        `json:"provider_id"`
	Finding     *ibmsaFinding `json:"finding"`
	Kpi         *ibmsaKpi     `json:"kpi,omitempty"`
}

type ibmsaReporter struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Url   string `json:"url,omitempty"`
}

type ibmsaApiNoteRelatedUrl struct {
	Label string `json:"label"`
	Url   string `json:"url"`
}

type ibmsaFindingType struct {
	Severity  string                 `json:"severity"`
	NextSteps []ibmsaRemediationStep `json:"next_steps,omitempty"`
}

type ibmsaKpiType struct {
	AggregationType string `json:"aggregation_type"`
}

type ibmsaCardValueType struct {
	Kind             string   `json:"kind"`
	FindingNoteNames []string `json:"finding_note_names"`
}

type ibmsaCardValueType2 struct {
	Kind             string   `json:"kind"`
	Text             string   `json:"text"`
	FindingNoteNames []string `json:"finding_note_names"`
}

type ibmsaCardElement struct {
	Kind             string                `json:"kind"`
	Text             string                `json:"text"`
	DefaultTimeRange string                `json:"default_time_range"`
	ValueType        *ibmsaCardValueType   `json:"value_type,omitempty"`
	ValueTypes       []ibmsaCardValueType2 `json:"value_types,omitempty"`
}

type ibmsaCard struct {
	Section               string             `json:"section"`
	Title                 string             `json:"title"`
	Subtitle              string             `json:"subtitle,omitempty"`
	Elements              []ibmsaCardElement `json:"elements"`
	Order                 *int32             `json:"order,omitempty"`
	FindingNoteNames      []string           `json:"finding_note_names"`
	RequiresConfiguration bool               `json:"requires_configuration,omitempty"`
	BadgeText             string             `json:"badge_text,omitempty"`
	BadgeImage            string             `json:"badge_image,omitempty"`
}

type ibmsaSection struct {
	Title string `json:"title"`
	Image string `json:"image"`
}

type ibmsaNote struct {
	ShortDescription string                   `json:"short_description"`
	LongDescription  string                   `json:"long_description"`
	Kind             string                   `json:"kind"`
	ID               string                   `json:"id"`
	ReportedBy       ibmsaReporter            `json:"reported_by"`
	Name             string                   `json:"name,omitempty"`
	RelatedUrl       []ibmsaApiNoteRelatedUrl `json:"related_url,omitempty"`
	ExpirationTime   string                   `json:"expiration_time,omitempty"`
	CreateTime       string                   `json:"create_time,omitempty"`
	UpdateTime       string                   `json:"update_time,omitempty"`
	ProviderID       string                   `json:"provider_id"`
	Shared           bool                     `json:"shared,omitempty"`
	Finding          *ibmsaFindingType        `json:"finding,omitempty"`
	Kpi              *ibmsaKpiType            `json:"kpi,omitempty"`
	Card             *ibmsaCard               `json:"card,omitempty"`
	Section          *ibmsaSection            `json:"section,omitempty"`
}

// type ibmsaNotes struct {
// 	Notes         []ibmsaNote `json:"notes"`
// 	NextPageToken string      `json:"next_page_token"`
// }

type ibmsaMetadata struct {
	Notes        []ibmsaNote `json:"notes"`
	ChangedSince *string     `json:"changedSince,omitempty"`
}

const (
	_ibmFindingCard = "threat-card"

	_ibmFindingThreat = "threat"

	_findingCacheSize = 64

	_invalidDashboardURL = "Invalid URL. Configure this field from NeuVector Console of the target cluster."

	_testingFindingURL = "-*///unittest////*-"
)

var ibmTokenHttpClient *http.Client
var ibmsaHttpClient *http.Client
var ibmIamToken ibmsaToken
var ibmIamTokenMutex sync.RWMutex // for accessing ibmIamToken

var ibmsaCfg share.CLUSIBMSAConfig
var postToIBMSA uint32 // set to 1 only on leader after setting up IBM SA integration

var ibmsaChan chan api.IBMSAFinding
var ibmsaStopChan chan bool
var accIBMSAPoster *access.AccessControl

var ipPortoName = map[uint8]string{
	0: "HOPOPT", 1: "ICMP", 2: "IGMP", 3: "GGP", 4: "IP-in-IP", 5: "ST", 6: "TCP", 7: "CBT", 8: "EGP", 9: "IGP",
	10: "BBN-RCC-MON", 11: "NVP-II", 12: "PUP", 13: "ARGUS", 14: "EMCON", 15: "XNET", 16: "CHAOS", 17: "UDP", 18: "MUX", 19: "DCN-MEAS",
	20: "HMP", 21: "PRM", 22: "XNS-IDP", 23: "TRUNK-1", 24: "TRUNK-2", 25: "LEAF-1", 26: "LEAF-2", 27: "RDP", 28: "IRTP", 29: "ISO-TP4",
	30: "NETBLT", 31: "MFE-NSP", 32: "MERIT-INP", 33: "DCCP", 34: "3PC", 35: "IDPR", 36: "XTP", 37: "DDP", 38: "IDPR-CMTP", 39: "TP++",
	40: "IL", 41: "IPv6", 42: "SDRP", 43: "IPv6-Route", 44: "IPv6-Frag", 45: "IDRP", 46: "RSVP", 47: "GREs", 48: "DSR", 49: "BNA",
	50: "ESP", 51: "AH", 52: "I-NLSP", 53: "SwIPe", 54: "NARP", 55: "MOBILE", 56: "TLSP", 57: "SKIP", 58: "IPv6-ICMP", 59: "IPv6-NoNxt",
	60: "IPv6-Opts", 61: "Any host internal protocol", 62: "CFTP", 63: "Any local network", 64: "SAT-EXPAK", 65: "KRYPTOLAN", 66: "RVD", 67: "IPPC", 68: "Any distributed file system", 69: "SAT-MON",
	70: "VISA", 71: "IPCU", 72: "CPNX", 73: "CPHB", 74: "WSN", 75: "PVP", 76: "BR-SAT-MON", 77: "SUN-ND", 78: "WB-MON", 79: "WB-EXPAK",
	80: "ISO-IP", 81: "VMTP", 82: "SECURE-VMTP", 83: "VINES", 84: "TTP/IPTM", 85: "NSFNET-IGP", 86: "DGP", 87: "TCF", 88: "EIGRP", 89: "OSPF",
	90: "Sprite-RPC", 91: "LARP", 92: "MTP", 93: "AX.25", 94: "OS", 95: "MICP", 96: "SCC-SP", 97: "ETHERIP", 98: "ENCAP", 99: "Any private encryption scheme",
	100: "GMTP", 101: "IFMP", 102: "PNNI", 103: "PIM", 104: "ARIS", 105: "SCPS", 106: "QNX", 107: "A/N", 108: "IPComp", 109: "SNP",
	110: "Compaq-Peer", 111: "IPX-in-IP", 112: "VRRP", 113: "PGM", 114: "Any 0-hop protocol", 115: "L2TP", 116: "DDX", 117: "IATP", 118: "STP", 119: "SRP",
	120: "UTI", 121: "SMP", 122: "SM", 123: "PTP", 124: "IS-IS", 125: "FIRE", 126: "CRTP", 127: "CRUDP", 128: "SSCOPMCE", 129: "IPLT",
	130: "SPS", 131: "PIPE", 132: "SCTP", 133: "FC", 134: "RSVP-E2E-IGNORE", 135: "Mobility Header", 136: "UDPLite", 137: "MPLS-in-IP", 138: "manet", 139: "HIP",
	140: "Shim6", 141: "WESP", 142: "ROHC", 143: "Ethernet", 255: "Reserved",
}

func isValidDashboardUrl(str string) bool {
	if str == _testingFindingURL { // for unittest
		return true
	}
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func handlerGetIBMSASetupURL(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	var acc *access.AccessControl
	var login *loginSession

	acc, login = getAccessControl(w, r, access.AccessOPWrite) // only admin/fedAdmin can get setup URL for IBM SA integration
	if acc == nil {
		return
	} else {
		if cfg, err := cacher.GetIBMSAConfigNV(acc); err != nil || !cfg.EpEnabled || cfg.EpStart == 1 {
			// postToIBM being 1 means the setup is already done. Do not generate setup URL unless IBM SA integration is enabled and postToIBM = 0
			restRespError(w, http.StatusForbidden, api.RESTErrObjectAccessDenied)
			return
		} else if !isValidDashboardUrl(cfg.EpDashboardURL) {
			restRespError(w, http.StatusBadRequest, api.RESTErrIBMSABadDashboardURL)
			return
		}
	}

	installID, _ := clusHelper.GetInstallationID()
	id := strings.ReplaceAll(jwtGenFedTicket(installID, time.Duration(jwtIbmSaTokenLife)), "/", "-")
	resp := api.RESTIBMSASetupUrl{URL: fmt.Sprintf("/v1/partner/ibm_sa/%s/setup", url.QueryEscape(id))}

	restRespSuccess(w, r, &resp, acc, login, nil, "Get IBM SA setup endpoint")
}

func handlerGetIBMSAConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	var acc *access.AccessControl
	var login *loginSession

	acc, login = getAccessControl(w, r, access.AccessOPWrite) // only admin/fedAdmin can get configuration of IBM SA integration
	if acc == nil {
		return
	}

	resp, err := cacher.GetIBMSAConfig(acc)
	if err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	restRespSuccess(w, r, resp, acc, login, nil, "")
}

func verifyIBMSAEpSetupID(w http.ResponseWriter, ps httprouter.Params, checkTime bool) error {
	id := strings.ReplaceAll(ps.ByName("id"), "-", "/")
	installID, _ := clusHelper.GetInstallationID()
	err := validateEncryptedData(id, installID, checkTime)
	if err != nil {
		restRespErrorMessage(w, http.StatusForbidden, api.RESTErrObjectAccessDenied, err.Error())
	}
	return err
}

func handlerGetIBMSAEpSetupToken(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	if err := verifyIBMSAEpSetupID(w, ps, true); err != nil {
		return
	}

	acc := access.NewReaderAccessControl() // it's because IBM SA does not carry NV's auth token when it calls this API
	if cfg, err := cacher.GetIBMSAConfigNV(acc); err != nil || !cfg.EpEnabled || cfg.EpStart == 1 {
		// cfg.EpStart being 1 means the setup is already done. Do not allow setup unless IBM SA integration is enabled and cfg.EpStart = 0
		restRespError(w, http.StatusForbidden, api.RESTErrObjectAccessDenied)
		return
	} else if !isValidDashboardUrl(cfg.EpDashboardURL) {
		restRespError(w, http.StatusBadRequest, api.RESTErrIBMSABadDashboardURL)
		return
	}

	user, _, _ := clusHelper.GetUserRev(common.ReservedUserNameIBMSA, acc)
	if user == nil {
		secret, _ := utils.GetGuid()
		u := share.CLUSUser{
			Fullname:     common.ReservedUserNameIBMSA,
			Username:     common.ReservedUserNameIBMSA,
			PasswordHash: utils.HashPassword(secret),
			Domain:       "",
			Role:         api.UserRoleIBMSA,
			Timeout:      common.DefIdleTimeoutInternal,
			RoleDomains:  make(map[string][]string),
			Locale:       common.OEMDefaultUserLocale,
			PwdResetTime: time.Now().UTC(),
		}
		value, _ := json.Marshal(u)
		key := share.CLUSUserKey(common.ReservedUserNameIBMSA)
		cluster.PutIfNotExist(key, value, false)
		user, _, _ = clusHelper.GetUserRev(common.ReservedUserNameIBMSA, acc)
	}
	if user != nil {
		remote := r.RemoteAddr
		if i := strings.Index(remote, ":"); i > 0 {
			remote = remote[:i]
		}
		if s, rc := loginUser(user, nil, nil, remote, _interactiveSessionID, "", api.FedRoleNone, nil); rc == userOK {
			resp := api.RESTIBMSASetupToken{
				AccessToken: s.token,
			}
			restRespSuccess(w, r, &resp, acc, nil, nil, "")
			return
		}
	}
	restRespError(w, http.StatusInternalServerError, api.RESTErrInvalidRequest)
}

func handlerGetIBMSAEpInfo(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	// metadata API could be called anytime by IBM SA. So we do not check if the setupID is expired or not here
	if err := verifyIBMSAEpSetupID(w, ps, false); err != nil {
		return
	}

	info := ps.ByName("info")
	if info != "dashboard" && info != "metadata" {
		restRespError(w, http.StatusForbidden, api.RESTErrObjectAccessDenied)
		return
	}

	var epDashboardURL string
	var providerID string
	acc := access.NewReaderAccessControl() // it's because IBM SA does not carry NV's auth token when it calls these 2 GET APIs
	if cfgNV, _ := cacher.GetIBMSAConfigNV(acc); cfgNV.EpEnabled && cfgNV.EpDashboardURL != "" {
		epDashboardURL = cfgNV.EpDashboardURL
		if cfgNV.EpStart == 1 {
			if cfg, _ := cacher.GetIBMSAConfig(acc); cfg != nil {
				providerID = cfg.ProviderID
			}
		} else {
			if cfg, _ := clusHelper.GetSystemConfigRev(acc); cfg != nil && cfg.IBMSAConfigNV.EpEnabled && cfg.IBMSAConfigNV.EpStart == 1 {
				providerID = cfg.IBMSAConfig.ProviderID
			}
		}
	}
	if providerID == "" || epDashboardURL == "" {
		restRespError(w, http.StatusForbidden, api.RESTErrObjectAccessDenied)
		return
	}

	switch info {
	case "dashboard":
		resp := api.RESTIBMSASetupUrl{URL: epDashboardURL}
		restRespSuccess(w, r, &resp, nil, nil, nil, "")
	case "metadata":
		threadNoteName := fmt.Sprintf("providers/%s/notes/%s", providerID, _ibmFindingThreat) // ends with {findings-type}
		resp := ibmsaMetadata{
			Notes: []ibmsaNote{
				{
					Kind:             "CARD",
					ProviderID:       providerID,
					ID:               _ibmFindingCard, // this note id is card id
					ShortDescription: "NeuVector Security Events",
					LongDescription:  "NeuVector Container Security - Security Events",
					ReportedBy: ibmsaReporter{
						ID:    "NeuVector",
						Title: "Neuvector Security Tool",
					},
					Card: &ibmsaCard{
						Section:          "Partner Integrations",
						Title:            "NeuVector Security Report",
						Subtitle:         "Security Events",
						FindingNoteNames: []string{threadNoteName},
						BadgeText:        "No security event detected in the last 5 days",
						//BadgeImage:            "{base64 content of the image associated to the card's badge}",
						Elements: []ibmsaCardElement{
							{
								Kind:             "NUMERIC",
								Text:             "Security events count reported",
								DefaultTimeRange: "4d",
								ValueType: &ibmsaCardValueType{
									Kind:             "FINDING_COUNT",
									FindingNoteNames: []string{threadNoteName},
								},
							},
							{
								Kind:             "TIME_SERIES",
								Text:             "Security events count reported",
								DefaultTimeRange: "4d",
								ValueTypes: []ibmsaCardValueType2{
									{
										Kind:             "FINDING_COUNT",
										Text:             "Security events",
										FindingNoteNames: []string{threadNoteName},
									},
								},
							},
						},
					},
				},
				{
					Kind:             "FINDING",
					ShortDescription: "NeuVector security threat finding",
					LongDescription:  "NeuVector Container Security",
					ProviderID:       providerID,
					ID:               _ibmFindingThreat, // this note id is {findings-type}
					ReportedBy: ibmsaReporter{
						ID:    "NeuVector ",
						Title: "Neuvector Security Tool",
					},
					Finding: &ibmsaFindingType{
						Severity: "MEDIUM",
						NextSteps: []ibmsaRemediationStep{
							{
								Title: "Evaluate if server is vulnerable",
							},
						},
					},
				},
			},
		}
		restRespSuccess(w, r, &resp, nil, nil, nil, "")
	}
}

func handlerPostIBMSAEpSetup(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Info("")
	defer r.Body.Close()

	if err := verifyIBMSAEpSetupID(w, ps, true); err != nil {
		return
	}

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}

	var cfg share.CLUSIBMSAConfig
	if !acc.Authorize(&cfg, nil) {
		restRespAccessDenied(w, login)
		return
	}

	var testData ibmsaOccurrences
	var err error

	action := ps.ByName("action")
	body, _ := io.ReadAll(r.Body)
	switch action {
	case "configuration":
		err = json.Unmarshal(body, &cfg)
	case "test":
		err = json.Unmarshal(body, &testData)
	default:
		err = errors.New("unsupported action")
	}
	if err != nil {
		log.WithFields(log.Fields{"action": action, "error": err}).Error("")
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
		return
	}

	if cfg, err := cacher.GetIBMSAConfigNV(acc); err != nil || !cfg.EpEnabled || cfg.EpStart == 1 {
		// cfg.EpStart being 1 means the setup is already done. Do not allow re-configuration unless IBM SA integration is enabled and cfg.EpStart = 0
		restRespError(w, http.StatusForbidden, api.RESTErrObjectAccessDenied)
		return
	}

	retry := 0
	for retry < retryClusterMax {
		// Retrieve from the cluster
		cconf, rev := clusHelper.GetSystemConfigRev(acc)
		switch action {
		case "configuration":
			// IBM SA Endpoint
			cconf.IBMSAConfig = cfg
		case "test":
			if cconf.IBMSAConfig.FindingsURL == _testingFindingURL {
				// for unittest only
				cconf.IBMSAOnboardData = share.CLUSIBMSAOnboardData{
					NoteName:   testData.NoteName,
					ID:         testData.ID,
					ProviderID: testData.ProviderID,
				}
				cconf.IBMSAConfigNV.EpStart = 1
				cconf.IBMSAConfigNV.EpConnectedAt = time.Now().UTC()
			} else {
				url := fmt.Sprintf("%s/%s/providers/security-advisor/occurrences", cconf.IBMSAConfig.FindingsURL, cconf.IBMSAConfig.AccountID)
				if err := ibmsaCreateOccurence(url, body, &cconf.IBMSAConfig); err == nil {
					cconf.IBMSAOnboardData = share.CLUSIBMSAOnboardData{
						NoteName:   testData.NoteName,
						ID:         testData.ID,
						ProviderID: testData.ProviderID,
					}
					cconf.IBMSAConfigNV.EpStart = 1
					cconf.IBMSAConfigNV.EpConnectedAt = time.Now().UTC()
				} else {
					log.WithFields(log.Fields{"url": url, "body": string(body), "err": err}).Error("IBM Security Advisor test failed")
					restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrIBMSATestFailed, err.Error())
					return
				}
			}
		}
		// Write to cluster
		if err := clusHelper.PutSystemConfigRev(cconf, rev); err != nil {
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
	restRespSuccess(w, r, nil, nil, nil, nil, "Configure IBM SA Endpoint")
}

func unmarshalResp(r *http.Response, body []byte, v interface{}) error {
	err := json.Unmarshal(body, &v)
	if err == nil {
		return nil
	}
	ct := r.Header.Get("Content-Type")
	mediaType, _, parseErr := mime.ParseMediaType(ct)
	if parseErr == nil && mediaType == "application/json" {
		return fmt.Errorf("got Content-Type = application/json, but could not unmarshal as JSON: %v", err)
	}
	return fmt.Errorf("expected Content-Type = application/json, got %q: %v", ct, err)
}

func ibmsaGetToken(cfg *share.CLUSIBMSAConfig) (string, error) {
	var token ibmsaToken

	ibmIamTokenMutex.RLock()
	token = ibmIamToken
	ibmIamTokenMutex.RUnlock()

	if token.Expiration > 0 && (time.Now().Unix() <= (token.Expiration - 30)) { // there are still 30 seconds before the token expires
		return token.AccessToken, nil
	}

	data := url.Values{}
	data.Add("grant_type", "urn:ibm:params:oauth:grant-type:apikey")
	data.Add("apikey", cfg.APIKey)

	req, err := http.NewRequest("POST", cfg.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		log.WithFields(log.Fields{"url": cfg.TokenURL, "error": err}).Error("new request")
		return "", err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

	if ibmTokenHttpClient == nil {
		ibmTokenHttpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			Timeout: clusterAuthTimeout,
		}
	}
	resp, err := ibmTokenHttpClient.Do(req)
	if err != nil {
		log.WithFields(log.Fields{"url": cfg.TokenURL, "error": err}).Error("Failed to retrieve IAM token")
		return "", err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.WithFields(log.Fields{"url": cfg.TokenURL, "error": err}).Error("Failed to read IAM token")
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		log.WithFields(log.Fields{"url": cfg.TokenURL, "status": resp.StatusCode}).Error("Failed to retrieve IAM token")
		return "", errors.New("Failed to retrieve IAM token")
	}

	if err := unmarshalResp(resp, body, &token); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to unmarshal IAM token")
		return "", err
	}
	ibmIamTokenMutex.Lock()
	ibmIamToken = token
	ibmIamTokenMutex.Unlock()

	return token.AccessToken, nil
}

func ibmsaCreateOccurence(url string, value []byte, cfg *share.CLUSIBMSAConfig) error {
	token, err := ibmsaGetToken(cfg)
	if err != nil {
		return err
	}

	data := string(value)
	req, err := http.NewRequest("POST", url, strings.NewReader(data))
	if err != nil {
		log.WithFields(log.Fields{"url": url, "error": err}).Error("new request")
		return err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Add("Content-Length", strconv.Itoa(len(data)))

	if ibmsaHttpClient == nil {
		ibmsaHttpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			Timeout: clusterAuthTimeout,
		}
	}

	resp, err := ibmsaHttpClient.Do(req)
	if err != nil {
		log.WithFields(log.Fields{"url": url, "error": err}).Error("Failed to create occurence")
		return err
	}

	defer resp.Body.Close()

	_, err = io.ReadAll(resp.Body)
	if err != nil {
		log.WithFields(log.Fields{"url": url, "error": err}).Error("Failed to read body")
		return err
	}

	if resp.StatusCode != http.StatusOK {
		log.WithFields(log.Fields{"url": url, "status": resp.StatusCode}).Error("Failed to create occurence")
		return errors.New("Failed to create occurence")
	} /* else {
		var occur ibmsaOccurrences
		if err := unmarshalResp(resp, body, &occur); err != nil {
			return err
		}
	}*/

	return nil
}

func ibmsaPostThreatFinding(f *api.IBMSAFinding) error {
	createTime := api.RESTTimeString(f.At)
	if createTime == "" {
		createTime = api.RESTTimeString(time.Now())
	}
	occur := ibmsaOccurrences{
		NoteName: fmt.Sprintf("%s/providers/%s/notes/%s", ibmsaCfg.AccountID, ibmsaCfg.ProviderID, _ibmFindingThreat), // the ending note id tells which {findings-type} it is
		Kind:     "FINDING",
		ID:       f.ID,
		Context: ibmsaContext{
			ResourceID:    f.ID,
			ResourceName:  f.EventType,
			ResourceType:  "Security Event",
			ComponentName: f.Name,
		},
		Name:        f.Name,
		ResourceUrl: "", //->
		Remediation: "", //->
		CreateTime:  createTime,
		UpdateTime:  createTime,
		ProviderID:  ibmsaCfg.ProviderID,
		Finding: &ibmsaFinding{
			Certainty: "HIGH",
			NextSteps: []ibmsaRemediationStep{
				{
					Title: fmt.Sprintf("%s - Correlate security events in the NeuVector console to evaluate the scope of the attack", cacher.GetSystemConfigClusterName(accIBMSAPoster)),
					Url:   "https://docs.neuvector.com",
				},
			},
			NetworkConnection: &ibmsaNetworkConnection{
				Direction: f.Direction,
				Protocol:  f.ProtoName,
				Client: ibmsaSocketAddress{
					Address: f.ClientIP,
					Port:    f.ClientPort,
				},
				Server: ibmsaSocketAddress{
					Address: f.ServerIP,
					Port:    f.ServerPort,
				},
			},
			DataTransferred: &ibmsaDataTransferred{
				ClientBytes:   f.ClientBytes,
				ServerBytes:   f.ServerBytes,
				ClientPackets: f.ClientPkts,
				ServerPackets: f.ServerPkts,
			},
		},
	}

	switch f.Level {
	case api.LogLevelEMERG, api.LogLevelALERT, api.LogLevelCRIT, api.LogLevelERR:
		occur.Finding.Severity = "HIGH"
	case api.LogLevelWARNING, api.LogLevelNOTICE:
		occur.Finding.Severity = "MEDIUM"
	default:
		occur.Finding.Severity = "LOW"
	}

	value, _ := json.Marshal(&occur)
	url := fmt.Sprintf("%s/%s/providers/%s/occurrences", ibmsaCfg.FindingsURL, ibmsaCfg.AccountID, ibmsaCfg.ProviderID)
	return ibmsaCreateOccurence(url, value, &ibmsaCfg)
}

func ibmsaGetNvNote(accessToken, noteID string, cfg *share.CLUSIBMSAConfig) error {
	url := fmt.Sprintf("%s/%s/providers/%s/notes/%s", cfg.FindingsURL, cfg.AccountID, cfg.ProviderID, noteID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.WithFields(log.Fields{"url": url, "error": err}).Error("new request")
		return err
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	if ibmsaHttpClient == nil {
		ibmsaHttpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			Timeout: clusterAuthTimeout,
		}
	}
	resp, err := ibmsaHttpClient.Do(req)
	if err != nil {
		log.WithFields(log.Fields{"url": url, "error": err}).Error("Failed to get NV note")
		return err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.WithFields(log.Fields{"url": url, "error": err}).Error("Failed to read NV note")
		return err
	}

	if resp.StatusCode != http.StatusOK {
		log.WithFields(log.Fields{"url": url, "status": resp.StatusCode}).Error("Failed to retrieve NV note")
		return errors.New("Failed to retrieve NV note")
	}

	var note ibmsaNote
	if err = unmarshalResp(resp, body, &note); err != nil {
		log.WithFields(log.Fields{"url": url, "body": string(body[:]), "error": err}).Error("Failed to unmarshal NV note")
	}

	return err
}

func ibmsaPoster() {
	_clusHelper := clusHelper
	if _clusHelper == nil {
		_clusHelper = kv.GetClusterHelper()
	}
	if _clusHelper != nil {
		acc := access.NewReaderAccessControl()
		cfg, _ := _clusHelper.GetSystemConfigRev(acc)
		noteIDs := []string{_ibmFindingCard, _ibmFindingThreat}
		for _, noteID := range noteIDs {
			if token, err := ibmsaGetToken(&cfg.IBMSAConfig); err == nil {
				ibmsaGetNvNote(token, noteID, &cfg.IBMSAConfig)
			}
		}
	} else {
		log.Error("nil _clusHelper")
	}

	log.Info("Start posting to IBM SA")
	if accIBMSAPoster == nil {
		accIBMSAPoster = access.NewReaderAccessControl()
	}

	/* fake data, for testing only
	f := api.IBMSAFinding{
		ClientIP:   "192.168.1.10",
		ServerIP:   "192.168.1.20",
		ServerPort: 8080,
	}
	for i := 0; i < 10; i++ {
		f.ID, _ = utils.GetGuid()
		f.At = time.Now()
		f.Protocol = 6
		f.ClientPort = 20000 + uint16(rand.Intn(6000))
		f.ClientPkts = rand.Int31()
		f.ServerPkts = rand.Int31()
		f.ClientBytes = rand.Int31()
		f.ServerBytes = rand.Int31()
		ibmsaChan <- f
	}*/

	osSignalChan := make(chan os.Signal, 1)
	signal.Notify(osSignalChan, syscall.SIGINT, syscall.SIGTERM)

Loop:
	for {
		select {
		case f := <-ibmsaChan:
			if f.Protocol == 253 || f.Protocol == 254 {
				f.ProtoName = "Experimentatal and testing"
			} else if f.Protocol >= 144 && f.Protocol <= 252 {
				f.ProtoName = "Unassigned"
			} else if f.ProtoName != "N/A" {
				f.ProtoName = ipPortoName[f.Protocol]
			}
			ibmsaPostThreatFinding(&f)
		case <-ibmsaStopChan:
			log.Info("Stopped posting to IBM SA")
			break Loop
		case <-osSignalChan:
			log.Info("Got OS shutdown signal, shutting down IBM SA poster gracefully...")
			break Loop
		}
	}
}

func handlerDeleteIBMSAEpSetup(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	if err := verifyIBMSAEpSetupID(w, ps, false); err != nil {
		return
	}

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	}
	var ibmSA share.CLUSIBMSAConfig
	if !acc.Authorize(&ibmSA, nil) {
		restRespAccessDenied(w, login)
		return
	}

	// IBM SA carries an NV's auth token that is ibmsa role
	if ibmsaConfig, _ := cacher.GetIBMSAConfigNV(access.NewReaderAccessControl()); !ibmsaConfig.EpEnabled {
		restRespError(w, http.StatusForbidden, api.RESTErrObjectAccessDenied)
		return
	}

	accountID := ps.ByName("accountID")
	providerID := ps.ByName("providerID")

	retry := 0
	adminAcc := access.NewAdminAccessControl() // it's IBM SA carries an NV's auth token which is ibmsa role that cannot write system config object
	for retry < retryClusterMax {
		// Retrieve from the cluster
		cconf, rev := clusHelper.GetSystemConfigRev(adminAcc)
		if (cconf.IBMSAConfig.AccountID != "" && cconf.IBMSAConfig.AccountID != accountID) || (cconf.IBMSAConfig.ProviderID != "" && cconf.IBMSAConfig.ProviderID != providerID) {
			log.WithFields(log.Fields{"accountID": accountID, "providerID": providerID}).Error("")
			restRespError(w, http.StatusForbidden, api.RESTErrObjectAccessDenied)
			return
		}
		cconf.IBMSAConfig = share.CLUSIBMSAConfig{}
		cconf.IBMSAOnboardData = share.CLUSIBMSAOnboardData{}
		cconf.IBMSAConfigNV.EpStart = 0
		// Write to cluster
		if err := clusHelper.PutSystemConfigRev(cconf, rev); err != nil {
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
	restRespSuccess(w, r, nil, nil, nil, nil, "Reset IBM SA Endpoint")
}

/*
func handlerTestOccurrences(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	var occur ibmsaOccurrences
	var err error

	//accountID := ps.ByName("accountID")
	//providerID := ps.ByName("providerID")
	body, _ := io.ReadAll(r.Body)
	err = json.Unmarshal(body, &occur)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("")
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, err.Error())
		return
	}

	restRespSuccess(w, r, nil, nil, nil, nil, "")
}

func handlerTestIBMIAM(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug("")
	defer r.Body.Close()

	token := ibmsaToken{
		AccessToken:  "1234567",
		RefreshToekn: "abcde",
		TokenType:    "test",
		ExpiresIn:    300,
		Expiration:   time.Now().Unix() + 300,
		Scope:        "local",
	}

	restRespSuccess(w, r, &token, nil, nil, nil, "")
}
*/

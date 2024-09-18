package rest

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"errors"

	"github.com/dgrijalva/jwt-go"
	"sigs.k8s.io/yaml"

	"github.com/hashicorp/go-version"
	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	//	admissionv1beta1 "k8s.io/api/admission/v1beta1"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/cache"
	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/remote_repository"
	"github.com/neuvector/neuvector/controller/scan"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/auth"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/utils"
)

const retryClusterMax int = 3
const clusterLockWait = time.Duration(time.Second * 20)

const DEFAULT_JWTCERT_VALIDITY_DAYS = 90
const DEFAULT_TLSCERT_VALIDITY_DAYS = 365
const DEFAULT_CERTMANAGER_EXPIRY_CHECK_PERIOD = time.Minute * 30
const DEFAULT_CERTMANAGER_RENEW_THRESHOLD = time.Hour * 24 * 30

type ApiVersion int

const (
	ApiVersion1 ApiVersion = iota
	ApiVersion2
)

const gzipThreshold = 1200 // On most Ethernet NICs MTU is 1500 bytes. Let's give ip/tcp/http header 300 bytes

var evqueue cluster.ObjectQueueInterface
var auditQueue cluster.ObjectQueueInterface
var messenger cluster.MessengerInterface
var clusHelper kv.ClusterHelper
var cfgHelper kv.ConfigHelper
var cacher cache.CacheInterface
var scanner scan.ScanInterface
var localDev *common.LocalDevice
var remoteAuther auth.RemoteAuthInterface
var k8sPlatform bool

var fedRestServerMutex sync.Mutex
var fedRestServerState uint64
var crdEventProcTicker *time.Ticker

var dockerRegistries utils.Set
var defaultRegistries utils.Set
var searchRegistries utils.Set

const (
	_fedRestServerStopped_ = iota
	_fedRestServerRunning_
)

const _maxTransacKeys = 64

var _restPort uint
var _fedPort uint
var _fedServerChan chan bool

var _licSigKeyEnv int

var _teleNeuvectorURL string
var _teleFreq uint

const defaultSSLCertFile = "/etc/neuvector/certs/ssl-cert.pem"
const defaultSSLKeyFile = "/etc/neuvector/certs/ssl-cert.key"

const defFedSSLCertFile = "/etc/neuvector/certs/fed-ssl-cert.pem"
const defFedSSLKeyFile = "/etc/neuvector/certs/fed-ssl-cert.key"

const restErrMessageDefault string = "Unknown error"

const crdEventProcPeriod = time.Duration(time.Second * 10)

var restErrNeedAgentWorkloadFilter = errors.New("Enforcer or workload filter must be provided")
var restErrNeedAgentFilter = errors.New("Enforcer filter must be provided")
var restErrWorkloadNotFound error = errors.New("Container is not found")
var restErrAgentNotFound error = errors.New("Enforcer is not found")
var restErrAgentDisconnected error = errors.New("Enforcer is disconnected")

var checkCrdSchemaFunc func(lead, init, crossCheck bool, cspType share.TCspType) []string

var CertManager *kv.CertManager
var tlsMutex sync.RWMutex
var tlsCertificate *tls.Certificate

var restErrMessage = []string{
	api.RESTErrNotFound:              "URL not found",
	api.RESTErrMethodNotAllowed:      "Method not allowed",
	api.RESTErrUnauthorized:          "Authentication failed",
	api.RESTErrOpNotAllowed:          "Operation not allowed",
	api.RESTErrTooManyLoginUser:      "Too many login users",
	api.RESTErrInvalidRequest:        "Request in wrong format",
	api.RESTErrObjectNotFound:        "Object not found",
	api.RESTErrFailWriteCluster:      "Write to cluster failed",
	api.RESTErrFailReadCluster:       "Read from cluster failed",
	api.RESTErrClusterWrongData:      "Data read from cluster in wrong format",
	api.RESTErrClusterTimeout:        "Request to cluster timeout",
	api.RESTErrNotEnoughFilter:       "More search criteria required",
	api.RESTErrDuplicateName:         "Duplicate name",
	api.RESTErrWeakPassword:          "Password is weak",
	api.RESTErrInvalidName:           "Name in wrong format",
	api.RESTErrObjectInuse:           "Object in use",
	api.RESTErrFailExport:            "Failed to export",
	api.RESTErrFailImport:            "Failed to import",
	api.RESTErrFailLockCluster:       "Acquire cluster lock failed",
	api.RESTErrLicenseFail:           "Request not supported by license",
	api.RESTErrAgentError:            "Enforcer error",
	api.RESTErrWorkloadNotRunning:    "Container not running",
	api.RESTErrCISBenchError:         "CIS benchmark error",
	api.RESTErrClusterRPCError:       "Cluster RPC error",
	api.RESTErrObjectAccessDenied:    "Object access denied",
	api.RESTErrFailRepoScan:          "Fail to scan repository",
	api.RESTErrFailRegistryScan:      "Fail to scan registry",
	api.RESTErrFailKubernetesApi:     "Kubernetes API error",
	api.RESTErrAdmCtrlUnSupported:    "Admission control is not supported on non-Kubernetes environment",
	api.RESTErrK8sNvRBAC:             "Kubernetes RBAC settings required for NeuVector is not configured correctly",
	api.RESTErrWebhookSvcForAdmCtrl:  "The neuvector-svc-admission-webhook service required for NeuVector Admission Control is not configured correctly",
	api.RESTErrNoUpdatePermission:    "NeuVector controller doesn't have UPDATE permission for service resource",
	api.RESTErrK8sApiSrvToWebhook:    "Failed to receive a request from Kube-apiserver. Please try different client mode",
	api.RESTErrNvPermission:          "NeuVector controller is forbidden to get service details. Please check the clusterrole/clusterrolebinding required for NeuVector default service account",
	api.RESTErrWebhookIsDisabled:     "Configuring NeuVector Admission Control global settings is not allowed when admission control is disabled",
	api.RESTErrRemoteUnauthorized:    "Authentication to the remote cluster failed",
	api.RESTErrRemoterRequestFail:    "Request to the remote cluster failed",
	api.RESTErrFedOperationFailed:    "Federation operation failed",
	api.RESTErrFedJointUnreachable:   "Managed cluster is unreachable from primary cluster",
	api.RESTErrFedDuplicateName:      "Another cluster with the same name already exists in the federation",
	api.RESTErrMasterUpgradeRequired: "Version of primary cluster is too old",
	api.RESTErrJointUpgradeRequired:  "Version of managed cluster is too old",
	api.RESTErrIBMSATestFailed:       "Failed to call IBM Security Advisor Findings endpoint",
	api.RESTErrIBMSABadDashboardURL:  "Invalid dashboard URL",
	api.RESTErrReadOnlyRules:         "Read-only rule(s) cannot be updated by current login user",
	api.RESTErrUserLoginBlocked:      "Temporarily blocked because of too many login failures",
	api.RESTErrPasswordExpired:       "Password expired",
	api.RESTErrPromoteFail:           "Failed to promote rules",
	api.RESTErrPlatformAuthDisabled:  "Platform authentication is disabled",
	api.RESTErrRancherUnauthorized:   "Rancher authentication failed",
	api.RESTErrRemoteExportFail:      "Failed to export to remote repository",
	api.RESTErrInvalidQueryToken:     "Invalid or expired query token",
}

func restRespForward(w http.ResponseWriter, r *http.Request, statusCode int, headers map[string]string, data []byte, remoteExport, remoteRegScanTest bool) {
	hNames := []string{"Content-Encoding", "Cache-Control", "Content-Type"}
	if remoteExport {
		hNames = append(hNames, "Content-Disposition")
	}
	if remoteRegScanTest {
		hNames = append(hNames, "X-Transaction-ID")
	}
	for _, hName := range hNames {
		if v, _ := headers[hName]; v != "" {
			w.Header().Set(hName, v)
		}
	}
	w.WriteHeader(statusCode)
	if data != nil {
		w.Write(data)
	}
}

func restRespPartial(w http.ResponseWriter, r *http.Request, resp interface{}) {
	var data []byte
	if resp != nil {
		var e common.EmptyMarshaller
		data, _ = e.Marshal(resp)

		if hdrs, ok := r.Header["Accept-Encoding"]; ok {
		loop:
			for _, hdr := range hdrs {
				// Accept-Encoding: gzip, deflate
				for _, enc := range strings.Split(hdr, ",") {
					if enc == "gzip" {
						w.Header().Set("Content-Encoding", "gzip")
						data = utils.GzipBytes(data)
						break loop
					}
				}
			}
		}
	}
	w.Header().Set("Content-Type", jsonContentType)
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusPartialContent)
	if data != nil {
		w.Write(data)
	}
}

func restRespSuccess(w http.ResponseWriter, r *http.Request, resp interface{},
	acc *access.AccessControl, login *loginSession, req interface{}, msg string) {

	var ct string = jsonContentType
	var data []byte
	if resp != nil {
		if restIsSupportReq(r) {
			var m common.MaskMarshaller
			data, _ = m.Marshal(resp)
		} else {
			accept := r.Header.Get("Accept")
			if accept == "application/gob" {
				var buf bytes.Buffer
				enc := gob.NewEncoder(&buf)
				enc.Encode(resp)
				data = buf.Bytes()
				ct = accept
			} else {
				var e common.EmptyMarshaller
				data, _ = e.Marshal(resp)
			}
		}

		if len(data) > gzipThreshold {
			if hdrs, ok := r.Header["Accept-Encoding"]; ok {
			loop:
				for _, hdr := range hdrs {
					// Accept-Encoding: gzip, deflate
					for _, enc := range strings.Split(hdr, ",") {
						if enc == "gzip" {
							w.Header().Set("Content-Encoding", "gzip")
							data = utils.GzipBytes(data)
							break loop
						}
					}
				}
			}
		}
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	if data != nil {
		w.Write(data)
	}

	if msg != "" {
		switch r.Method {
		case http.MethodGet:
			// no log
		case http.MethodPost, http.MethodPatch, http.MethodDelete:
			var masked []byte
			if req != nil {
				var m common.MaskMarshaller
				masked, _ = m.Marshal(req)
			}
			restEventLog(r, masked, login, restLogFields{restLogFieldMsg: msg})
		}
	}
}

func restRespErrorMessage(w http.ResponseWriter, status int, code int, msg string) {
	if w == nil {
		return
	}
	w.Header().Set("Content-Type", jsonContentType)
	w.WriteHeader(status)

	var e string
	if code >= len(restErrMessage) || restErrMessage[code] == "" {
		e = restErrMessageDefault
	} else {
		e = restErrMessage[code]
	}
	if msg == "" {
		msg = e
	}
	resp := api.RESTError{Code: code, Error: e, Message: msg}
	value, _ := json.Marshal(resp)
	w.Write(value)
}

func restRespErrorMessageEx(w http.ResponseWriter, status int, code int, msg string, i interface{}) {
	if w == nil {
		return
	}
	w.Header().Set("Content-Type", jsonContentType)
	w.WriteHeader(status)

	var e string
	if code >= len(restErrMessage) || restErrMessage[code] == "" {
		e = restErrMessageDefault
	} else {
		e = restErrMessage[code]
	}
	if msg == "" {
		msg = e
	}
	resp := api.RESTError{Code: code, Error: e, Message: msg}
	switch v := i.(type) {
	case api.RESTPwdProfileBasic:
		// v has type api.RESTPwdProfileBasic
		if v.MinLen > 0 {
			resp.PwdProfileBasic = &v
		}
	case api.RESTImportTaskData:
		// v has type api.RESTImportTaskData
		resp.ImportTaskData = &v
	}
	value, _ := json.Marshal(resp)
	w.Write(value)
}

func restRespError(w http.ResponseWriter, status int, code int) {
	restRespErrorMessage(w, status, code, "")
}

func restRespErrorReadOnlyRules(w http.ResponseWriter, status int, code int, msg string, readOnlyRuleIDs []uint32) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	var e string
	if code >= len(restErrMessage) || restErrMessage[code] == "" {
		e = restErrMessageDefault
	} else {
		e = restErrMessage[code]
	}
	if msg == "" {
		msg = e
	}
	resp := api.RESTErrorReadOnlyRules{
		RESTError: api.RESTError{
			Code:    code,
			Error:   e,
			Message: msg,
		},
		ReadOnlyRuleIDs: readOnlyRuleIDs,
	}
	value, _ := json.Marshal(resp)
	w.Write(value)
}

func restRespAccessDenied(w http.ResponseWriter, login *loginSession) {
	if w == nil {
		return
	}
	restRespError(w, http.StatusForbidden, api.RESTErrObjectAccessDenied)
	log.WithFields(log.Fields{"roles": login.domainRoles, "permits": login.extraDomainPermits, "nvPage": login.nvPage}).Error("Object access denied")
	if strings.HasPrefix(login.mainSessionID, _rancherSessionPrefix) || login.server == share.FlavorRancher {
		// do not write AccessDenied events for Rancher SSO sessions
	} else if login.nvPage != api.RESTNvPageDashboard && login.nvPage != api.RESTNvPageNavigationBar {
		authLog(share.CLUSEvAuthAccessDenied, login.fullname, login.remote, login.id, login.domainRoles, "")
	}
}

func restRespNotFoundLogAccessDenied(w http.ResponseWriter, login *loginSession, err error) {
	if w == nil {
		return
	}
	if err == common.ErrObjectAccessDenied {
		restRespAccessDenied(w, login)
	} else if err == common.ErrObjectNotFound {
		restRespErrorMessage(w, http.StatusNotFound, api.RESTErrObjectNotFound, "Object not found")
		log.WithFields(log.Fields{"roles": login.domainRoles}).Error(err.Error())
		authLog(share.CLUSEvAuthAccessDenied, login.fullname, login.remote, login.id, login.domainRoles, "")
	} else if err == restErrNeedAgentWorkloadFilter || err == restErrNeedAgentFilter {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrNotEnoughFilter, err.Error())
	} else {
		restRespErrorMessage(w, http.StatusNotFound, api.RESTErrObjectNotFound, err.Error())
	}
}

func handlerNotFound(w http.ResponseWriter, r *http.Request) {
	restRespError(w, http.StatusNotFound, api.RESTErrNotFound)
	r.Body.Close()
}

func handlerMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	restRespError(w, http.StatusMethodNotAllowed, api.RESTErrMethodNotAllowed)
	r.Body.Close()
}

// ---

const MaxFilelds int = 8

type restFieldFilter struct {
	tag        string
	field      string
	op         string
	value      string
	valueInt   int64
	valueFloat float64
	valueBool  bool
}

type restFieldSort struct {
	tag   string
	field string
	asc   bool
}

type restQuery struct {
	start    int
	limit    int
	backward bool
	brief    bool
	raw      bool
	verbose  bool
	withCap  bool
	filters  []restFieldFilter
	sorts    []restFieldSort
	pairs    map[string]string
}

func restIsSupportReq(r *http.Request) bool {
	query := r.URL.Query()
	if values, ok := query[api.SupportFlag]; ok {
		if sup, err := strconv.ParseBool(values[0]); err == nil {
			return sup
		}
	}
	return false
}

func restParseQuery(r *http.Request) *restQuery {
	var rq restQuery
	rq.pairs = make(map[string]string)

	query := r.URL.Query()

	for key, values := range query {
		value := values[0]

		if key == api.PageStart {
			if start, err := strconv.Atoi(value); err == nil {
				if start >= 0 {
					rq.start = start
				} else {
					rq.start = -start
					rq.backward = true
				}
			}
		} else if key == api.PageLimit {
			if limit, err := strconv.Atoi(value); err == nil {
				if limit >= 0 {
					rq.limit = limit
				}
			}
		} else if key == api.RawFlag {
			if raw, err := strconv.ParseBool(value); err == nil {
				rq.raw = raw
			}
		} else if key == api.WithCapFlag {
			if withCap, err := strconv.ParseBool(value); err == nil {
				rq.withCap = withCap
			}
		} else if key == api.BriefFlag {
			if brief, err := strconv.ParseBool(value); err == nil {
				rq.brief = brief
			}
		} else if key == api.VerboseFlag {
			if verbose, err := strconv.ParseBool(value); err == nil {
				rq.verbose = verbose
			}
		} else if strings.HasPrefix(key, api.FilterPrefix) && len(key) > 2 {
			if len(rq.filters) >= MaxFilelds {
				continue
			}

			tag := key[2:]
			v := strings.Split(value, ",")
			if len(v) == 1 && len(v[0]) > 0 {
				rq.filters = append(rq.filters,
					restFieldFilter{
						tag:   tag,
						op:    api.OPeq,
						value: v[0],
					})
			} else if len(v) > 1 && len(v[1]) > 0 {
				var op string

				switch v[0] {
				case api.OPeq, api.OPneq, api.OPin,
					api.OPgt, api.OPgte, api.OPlt, api.OPlte, api.OPprefix:
					op = v[0]
				default:
					op = api.OPeq
				}

				rq.filters = append(rq.filters,
					restFieldFilter{
						tag:   tag,
						op:    op,
						value: v[1],
					})
			}
		} else if strings.HasPrefix(key, api.SortPrefix) {
			if len(rq.sorts) >= MaxFilelds {
				continue
			}

			tag := key[2:]
			switch value {
			case api.SortDesc:
				rq.sorts = append(rq.sorts, restFieldSort{tag: tag, asc: false})
			case api.SortAsc:
				rq.sorts = append(rq.sorts, restFieldSort{tag: tag, asc: true})
			}
		} else {
			rq.pairs[key] = value
		}
	}

	log.WithFields(log.Fields{"req": rq}).Debug("")
	return &rq
}

// -- Filter

type restFilter struct {
	filters []*restFieldFilter
	tags    map[string]string
}

func filterString(value string, filter *restFieldFilter) bool {
	switch filter.op {
	case api.OPeq:
		return value == filter.value
	case api.OPneq:
		return value != filter.value
	case api.OPin:
		ss := strings.Split(filter.value, "|")
		for _, s := range ss {
			if strings.Contains(value, s) {
				return true
			}
		}
		return false
	case api.OPgt:
		return value > filter.value
	case api.OPgte:
		return value >= filter.value
	case api.OPlt:
		return value < filter.value
	case api.OPlte:
		return value <= filter.value
	case api.OPprefix:
		return strings.HasPrefix(value, filter.value)
	}

	return false
}

func filterInt(value int64, filter *restFieldFilter) bool {
	switch filter.op {
	case api.OPeq:
		return value == filter.valueInt
	case api.OPneq:
		return value != filter.valueInt
	case api.OPgt:
		return value > filter.valueInt
	case api.OPgte:
		return value >= filter.valueInt
	case api.OPlt:
		return value < filter.valueInt
	case api.OPlte:
		return value <= filter.valueInt
	}

	return false
}

func filterFloat(value float64, filter *restFieldFilter) bool {
	switch filter.op {
	case api.OPeq:
		return value == filter.valueFloat
	case api.OPneq:
		return value != filter.valueFloat
	case api.OPgt:
		return value > filter.valueFloat
	case api.OPgte:
		return value >= filter.valueFloat
	case api.OPlt:
		return value < filter.valueFloat
	case api.OPlte:
		return value <= filter.valueFloat
	}

	return false
}

func filterBool(value bool, filter *restFieldFilter) bool {
	switch filter.op {
	case api.OPeq:
		return value == filter.valueBool
	case api.OPneq:
		return value != filter.valueBool
	case api.OPgt:
		return value && !filter.valueBool
	case api.OPgte:
		return value || !filter.valueBool
	case api.OPlt:
		return !value && filter.valueBool
	case api.OPlte:
		return !value || filter.valueBool
	}

	return false
}

func filter(d interface{}, filter *restFieldFilter) bool {
	v := reflect.ValueOf(d).Elem()
	f := v.FieldByName(filter.field)

	switch f.Kind() {
	case reflect.String:
		return filterString(f.String(), filter)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return filterInt(f.Int(), filter)
	case reflect.Float32, reflect.Float64:
		return filterFloat(f.Float(), filter)
	case reflect.Bool:
		return filterBool(f.Bool(), filter)
	}

	return false
}

func restNewFilter(data interface{}, filters []restFieldFilter) *restFilter {
	rf := restFilter{
		filters: make([]*restFieldFilter, 0),
		tags:    make(map[string]string),
	}

	// Build tag to field name map.
	// Embedded fields first so non-embedded fields can overwrite fields with the same names.
	t := reflect.TypeOf(data).Elem()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous {
			ft := f.Type
			if ft.Kind() == reflect.Struct {
				for i := 0; i < ft.NumField(); i++ {
					f = ft.Field(i)
					if tag := f.Tag.Get("json"); tag != "" {
						if comma := strings.Index(tag, ","); comma > 0 { // comma cannot be the first char
							tag = tag[:comma]
						}
						rf.tags[tag] = f.Name
					}
				}
				/* Embedded pointer to struct is not supported, see TestFilterEmbedded()
				} else if ft.Kind() == reflect.Ptr {
					ft = ft.Elem()
					if ft.Kind() == reflect.Struct {
						for i := 0; i < ft.NumField(); i++ {
							f = ft.Field(i)
							tag := f.Tag.Get("json")
							if tag != "" {
								rf.tags[tag] = f.Name
							}
						}
					}
				*/
			}
		}
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.Anonymous {
			if tag := f.Tag.Get("json"); tag != "" {
				if comma := strings.Index(tag, ","); comma > 0 { // comma cannot be the first char
					tag = tag[:comma]
				}
				rf.tags[tag] = f.Name
			}
		}
	}

	for i, _ := range filters {
		rf.FilteredBy(data, &filters[i])
	}

	return &rf
}

func (rf *restFilter) FilteredBy(data interface{}, ff *restFieldFilter) *restFilter {
	v := reflect.ValueOf(data).Elem()

	// Get field name from tag
	if ff.field, _ = rf.tags[ff.tag]; ff.field == "" {
		log.WithFields(log.Fields{"tag": ff.tag}).Debug("Field with tag not exist")
		return rf
	}

	// Check if field exists
	f := v.FieldByName(ff.field)
	if !f.IsValid() {
		log.WithFields(log.Fields{"field": ff.field}).Debug("Field not exist")
		return rf
	}

	// Check if type is supported
	switch f.Kind() {
	case reflect.String:
		rf.filters = append(rf.filters, ff)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if valueInt, err := strconv.ParseInt(ff.value, 10, 64); err == nil {
			ff.valueInt = valueInt
			rf.filters = append(rf.filters, ff)
		}
	case reflect.Float32, reflect.Float64:
		if valueFloat, err := strconv.ParseFloat(ff.value, 64); err == nil {
			ff.valueFloat = valueFloat
			rf.filters = append(rf.filters, ff)
		}
	case reflect.Bool:
		if valueBool, err := strconv.ParseBool(ff.value); err == nil {
			ff.valueBool = valueBool
			rf.filters = append(rf.filters, ff)
		}
	default:
		log.WithFields(log.Fields{
			"field": ff.field, "kind": f.Kind(),
		}).Error("Field type not supported")
	}

	return rf
}

func (rf *restFilter) Filter(data interface{}) bool {
	for _, ff := range rf.filters {
		if !filter(data, ff) {
			return false
		}
	}

	return true
}

// -- Sort

type restSorter struct {
	data []interface{}
	sort []*restFieldSort
	tags map[string]string
}

func compareInt(i, j int64) int {
	if i < j {
		return -1
	} else if i > j {
		return 1
	} else {
		return 0
	}
}

func compareFloat(i, j float64) int {
	if i < j {
		return -1
	} else if i > j {
		return 1
	} else {
		return 0
	}
}

func compareBool(i, j bool) int {
	if !i && j {
		return -1
	} else if i && !j {
		return 1
	} else {
		return 0
	}
}

func compare(di, dj interface{}, field string) int {
	vi := reflect.ValueOf(di).Elem()
	fi := vi.FieldByName(field)
	vj := reflect.ValueOf(dj).Elem()
	fj := vj.FieldByName(field)

	switch fi.Kind() {
	case reflect.String:
		return strings.Compare(fi.String(), fj.String())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return compareInt(fi.Int(), fj.Int())
	case reflect.Float32, reflect.Float64:
		return compareFloat(fi.Float(), fj.Float())
	case reflect.Bool:
		return compareBool(fi.Bool(), fj.Bool())
	}

	return 0
}

func restNewSorter(data []interface{}, sorts []restFieldSort) *restSorter {
	if len(data) == 0 {
		return nil
	}

	rs := restSorter{
		data: data,
		sort: make([]*restFieldSort, 0),
		tags: make(map[string]string),
	}

	// Build tag to field name map
	// Embedded fields first so non-embedded fields can overwrite fields with the same names.
	d := rs.data[0]
	t := reflect.TypeOf(d).Elem()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous {
			ft := f.Type
			if ft.Kind() == reflect.Struct {
				for i := 0; i < ft.NumField(); i++ {
					f = ft.Field(i)
					if tag := f.Tag.Get("json"); tag != "" {
						if comma := strings.Index(tag, ","); comma > 0 { // comma cannot be the first char
							tag = tag[:comma]
						}
						rs.tags[tag] = f.Name
					}
				}
			}
		}
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.Anonymous {
			if tag := f.Tag.Get("json"); tag != "" {
				if comma := strings.Index(tag, ","); comma > 0 { // comma cannot be the first char
					tag = tag[:comma]
				}
				rs.tags[tag] = f.Name
			}
		}
	}

	for i, _ := range sorts {
		rs.SortedBy(&sorts[i])
	}
	return &rs
}

func (rs *restSorter) SortedBy(s *restFieldSort) *restSorter {
	d := rs.data[0]
	v := reflect.ValueOf(d).Elem()

	// Get field name from tag
	if s.field, _ = rs.tags[s.tag]; s.field == "" {
		log.WithFields(log.Fields{"tag": s.tag}).Error("Field with tag not exist")
		return rs
	}

	// Check if field exists
	f := v.FieldByName(s.field)
	if !f.IsValid() {
		log.WithFields(log.Fields{"field": s.field}).Error("Field not exist")
		return rs
	}

	// Check if type is supported
	switch f.Kind() {
	case reflect.String:
		rs.sort = append(rs.sort, s)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		rs.sort = append(rs.sort, s)
	case reflect.Float32, reflect.Float64:
		rs.sort = append(rs.sort, s)
	case reflect.Bool:
		rs.sort = append(rs.sort, s)
	default:
		log.WithFields(log.Fields{
			"field": s.field, "kind": f.Kind(),
		}).Error("Field type not supported")
	}
	return rs
}

func (rs *restSorter) Sort() {
	if len(rs.data) <= 1 || len(rs.sort) == 0 {
		return
	}
	sort.Sort(rs)
}

// Len is part of sort.Interface.
func (rs *restSorter) Len() int {
	return len(rs.data)
}

// Swap is part of sort.Interface.
func (rs *restSorter) Swap(i, j int) {
	rs.data[i], rs.data[j] = rs.data[j], rs.data[i]
}

func (rs *restSorter) Less(i, j int) bool {
	di, dj := rs.data[i], rs.data[j]

	var k, r int
	var s *restFieldSort

	// Try all but the last comparison.
	for k = 0; k < len(rs.sort)-1; k++ {
		s = rs.sort[k]
		r = compare(di, dj, s.field)
		if r > 0 {
			return !s.asc
		} else if r < 0 {
			return s.asc
		}
	}

	// All previous comparison are equal, return the last one.
	s = rs.sort[k]
	r = compare(di, dj, s.field)
	if r > 0 {
		return !s.asc
	} else {
		return s.asc
	}
}

// --
const restEventLogBodyMax int = 1024

const (
	restLogFieldMsg = "msg"
)

type restLogFields map[string]string

func restEventLog(r *http.Request, body []byte, login *loginSession, fields restLogFields) {
	clog := share.CLUSEventLog{
		Event:          share.CLUSEvRESTRead,
		HostID:         localDev.Host.ID,
		HostName:       localDev.Host.Name,
		ControllerID:   localDev.Ctrler.ID,
		ControllerName: localDev.Ctrler.Name,
		ReportedAt:     time.Now().UTC(),
	}
	if r.Method != http.MethodGet {
		clog.Event = share.CLUSEvRESTWrite
	}

	if login != nil {
		if login.mainSessionID == _interactiveSessionID || strings.HasPrefix(login.mainSessionID, _rancherSessionPrefix) {
			clog.User = login.fullname
			clog.UserRoles = login.domainRoles
			clog.UserPermits = login.extraDomainPermits
		} else {
			userRole := api.UserRoleFedAdmin
			if r, ok := login.domainRoles[access.AccessDomainGlobal]; ok && r == api.UserRoleReader {
				userRole = api.UserRoleFedReader
			}
			clog.User = fmt.Sprintf("%s (primary cluster)", login.mainSessionUser)
			clog.UserRoles = map[string]string{access.AccessDomainGlobal: userRole}
		}
		clog.UserAddr = login.remote
		clog.UserSession = login.id
	}

	clog.RESTMethod = r.Method
	clog.RESTRequest = r.URL.String()
	if body != nil {
		size := len(body)
		if size > restEventLogBodyMax {
			size = restEventLogBodyMax
		}
		clog.RESTBody = string(body[:size])
	}

	if fields != nil {
		for key, value := range fields {
			switch key {
			case restLogFieldMsg:
				clog.Msg = value
			}
		}
	}

	evqueue.Append(&clog)
}

// --

func getNewestVersion(vers utils.Set) string {
	var newest string
	for ver := range vers.Iter() {
		if v, err := version.NewVersion(ver.(string)); err == nil {
			if newest == "" || v.Compare(version.Must(version.NewVersion(newest))) > 0 {
				newest = ver.(string)
			}
		}
	}
	return newest
}

func isIDStringValid(name string) bool {
	valid, _ := regexp.MatchString("^[.a-zA-Z0-9_-]*$", name)
	return valid
}

func isObjectNameValid(name string) bool {
	// Object name must starts with letters or digits
	valid, _ := regexp.MatchString("^[a-zA-Z0-9]+[.:a-zA-Z0-9_-]*$", name)
	return valid
}

func isObjectNameWithSpaceValid(name string) bool {
	// Object name must starts with letters or digits
	valid, _ := regexp.MatchString("(^[a-zA-Z0-9]$)|(^[a-zA-Z0-9]+[ .:a-zA-Z0-9_-]*[.:a-zA-Z0-9_-]+$)", name)
	return valid
}

func isUserNameValid(name string) bool {
	if !isObjectNameWithSpaceValid(name) {
		return false
	}
	// user name cannot start with "ldap1:"/"saml1:"/"oidc1:"/"rancher:"/"openshift:"
	for _, prefix := range []string{"ldap1:", "saml1:", "oidc1:", "rancher:", "openshift:"} {
		if strings.HasPrefix(name, prefix) {
			return false
		}
	}

	return true
}

func isNamePathValid(name string) bool {
	// Accept name or path, such as "https://mydomain.com/groups" or "/groups"
	valid, _ := regexp.MatchString("^[/a-zA-Z0-9]+[/.:a-zA-Z0-9_-]*$", name)
	return valid
}

func isDomainNameValid(name string) bool {
	// k8s namesapce naming rule: a DNS-1123 label must consist of lower case alphanumeric characters or '-', and must start and end with an alphanumeric character (e.g. 'my-name',  or '123-abc')
	// plus, we support * at the end of namespace configuration for regex matching
	valid, _ := regexp.MatchString(`^[a-z0-9]+[-a-z0-9\*]*[\*a-z0-9]$`, name)
	return valid
}

func getAgentFromFilter(filters []restFieldFilter, acc *access.AccessControl) (string, error) {
	var agentID string

	for _, f := range filters {
		if f.tag == api.FilterByAgent && f.op == api.OPeq {
			agentID = f.value
		}
	}

	if agentID != "" {
		// Agent ID is specified, authz on agent is required
		if agent := cacher.GetAgent(agentID, acc); agent == nil {
			err := restErrAgentNotFound
			log.WithFields(log.Fields{"agent": agentID}).Error(err)
			return agentID, err
		} else if agent.State == api.StateOffline {
			err := restErrAgentDisconnected
			log.WithFields(log.Fields{"agent": agentID}).Error(err)
			return agentID, err
		}
		return agentID, nil
	}

	err := restErrNeedAgentFilter
	log.Error(err)
	return "", err
}

func getAgentWorkloadFromFilter(filters []restFieldFilter, acc *access.AccessControl) (string, string, error) {
	var agentID, wlID string

	for _, f := range filters {
		if f.tag == api.FilterByAgent && f.op == api.OPeq {
			agentID = f.value
		} else if f.tag == api.FilterByWorkload && f.op == api.OPeq {
			wlID = f.value
		}
	}

	if wlID != "" {
		// If workload is specified, try to get agent ID first by workload.
		// Only authz on the workload, no authz on agent here.
		devID, err := cacher.GetAgentbyWorkload(wlID, acc)
		if devID == "" {
			if err != common.ErrObjectAccessDenied {
				err = restErrWorkloadNotFound
			}
			log.WithFields(log.Fields{"workload": wlID}).Error(err)
			return agentID, wlID, err
		}
		if agentID != "" && agentID != devID {
			err = restErrWorkloadNotFound
			log.WithFields(log.Fields{"agent": agentID, "id": wlID}).Error(err)
			return agentID, wlID, err
		}

		agentID = devID

		// Get agent with read-all, as we have to communicate with the agent.
		if agent := cacher.GetAgent(agentID, access.NewReaderAccessControl()); agent == nil {
			err = restErrAgentNotFound
			log.WithFields(log.Fields{"agent": agentID}).Error(err)
			return agentID, wlID, err
		} else if agent.State == api.StateOffline {
			err = restErrAgentDisconnected
			log.WithFields(log.Fields{"agent": agentID}).Error(err)
			return agentID, wlID, err
		}
	} else if agentID != "" {
		// If agent ID is specified, authz on agent is required
		if agent := cacher.GetAgent(agentID, acc); agent == nil {
			err := restErrAgentNotFound
			log.WithFields(log.Fields{"agent": agentID}).Error(err)
			return agentID, wlID, err
		} else if agent.State == api.StateOffline {
			err := restErrAgentDisconnected
			log.WithFields(log.Fields{"agent": agentID}).Error(err)
			return agentID, wlID, err
		}
	} else {
		err := restErrNeedAgentWorkloadFilter
		log.Error(err)
		return agentID, wlID, err
	}

	return agentID, wlID, nil
}

func initDefaultRegistries() {
	// all on lower-case
	dockerRegistries = utils.NewSet("https://docker.io/", "https://index.docker.io/", "https://registry.hub.docker.com/", "https://registry-1.docker.io/")

	// if a flag was provided for search registries, use those,
	// otherwise use the default docker registries
	if len(searchRegistries.ToSlice()) > 0 {
		defaultRegistries = searchRegistries
	} else {
		defaultRegistries = utils.NewSet("https://docker.io/", "https://index.docker.io/", "https://registry.hub.docker.com/", "https://registry-1.docker.io/")
	}

	regNames := global.RT.GetDefaultRegistries()
	for _, reg := range regNames {
		k := fmt.Sprintf("https://%s/", reg)
		if !defaultRegistries.Contains(k) {
			defaultRegistries.Add(k)
		}
	}
	log.WithFields(log.Fields{"default registries": defaultRegistries.ToStringSlice()}).Info()
}

const (
	ruleTypeRespRule = "responseRule"
	ruleTypeAdmCtrl  = "admCtrl"
	ruleTypeVulProf  = "vulProf"
)

func getAvailableRuleID(ruleType string, ids utils.Set, cfgType share.TCfgType) uint32 {
	var id, max uint32
	var idMax, idMin uint32
	if cfgType == share.FederalCfg {
		idMax = api.MaxFedAdmRespRuleID
		idMin = api.StartingFedAdmRespRuleID + 1
	} else if cfgType == share.GroundCfg {
		idMax = api.AdmCtrlCrdRuleIDMax
		idMin = api.AdmCtrlCrdRuleIDBase
	} else {
		idMax = api.StartingFedAdmRespRuleID
		if ruleType == ruleTypeAdmCtrl {
			idMin = uint32(api.StartingLocalAdmCtrlRuleID)
		} else if ruleType == ruleTypeVulProf {
			idMin = uint32(api.StartingLocalVulProfRuleID)
		} else {
			idMin = 1
		}
	}
	max = idMin - 1
	// Find the largest
	for mid := range ids.Iter() {
		id = mid.(uint32)
		if id < idMax && id > max {
			max = id
		}
	}
	if max < idMax-1 {
		return max + 1
	}

	// Find the smallest
	for id = idMin; id < idMax; id++ {
		if !ids.Contains(id) {
			return id
		}
	}

	return 0
}

// --
type writer struct {
	req    *http.Request
	writer http.ResponseWriter
}

func (w writer) Header() http.Header {
	return w.writer.Header()
}

func (w writer) Write(a []byte) (int, error) {
	return w.writer.Write(a)
}

func (w writer) WriteHeader(statusCode int) {
	url := w.req.URL.String()
	if statusCode == http.StatusOK {
		suffixes := []string{"/fed/ping_internal", "/fed/poll_internal", "/fed/scan_data_internal"}
		for _, suffix := range suffixes {
			if strings.HasSuffix(url, suffix) {
				w.writer.WriteHeader(statusCode)
				return
			}
		}
	}

	log.WithFields(log.Fields{"Method": w.req.Method, "URL": url}).Debug(statusCode)
	w.writer.WriteHeader(statusCode)
}

type restLogger struct {
	handler http.Handler
}

func (l restLogger) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Already logged in each handler function
	// log.WithFields(log.Fields{"Method": r.Method, "URL": r.URL.String()}).Debug()
	l.handler.ServeHTTP(writer{r, w}, r)
}

type Context struct {
	LocalDev           *common.LocalDevice
	EvQueue            cluster.ObjectQueueInterface
	AuditQueue         cluster.ObjectQueueInterface
	Messenger          cluster.MessengerInterface
	Cacher             cache.CacheInterface
	Scanner            scan.ScanInterface
	SearchRegistries   string
	FedPort            uint
	RESTPort           uint
	PwdValidUnit       uint
	TeleNeuvectorURL   string
	TeleFreq           uint
	NvAppFullVersion   string
	NvSemanticVersion  string
	CspType            share.TCspType
	CspPauseInterval   uint   // in minutes
	CustomCheckControl string // disable / strict / loose
	CheckCrdSchemaFunc func(lead, init, crossCheck bool, cspType share.TCspType) []string
}

var cctx *Context

func getExpiryDate(certPEM []byte) (time.Time, error) {
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

func initCertificates() error {
	expiryCheckPeriod := DEFAULT_CERTMANAGER_EXPIRY_CHECK_PERIOD
	renewThreshold := DEFAULT_CERTMANAGER_RENEW_THRESHOLD

	jwtCertValidityPeriodDay := DEFAULT_JWTCERT_VALIDITY_DAYS
	tlsCertValidityPeriodDay := DEFAULT_TLSCERT_VALIDITY_DAYS

	if envvar := os.Getenv("CERT_EXPIRY_CHECK_PERIOD"); envvar != "" {
		if v, err := time.ParseDuration(envvar); err == nil {
			expiryCheckPeriod = v
		} else {
			log.WithError(err).Warn("failed to load ExpiryCheckPeriod")
		}
	}
	if envvar := os.Getenv("CERT_RENEW_THRESHOLD"); envvar != "" {
		if v, err := time.ParseDuration(envvar); err == nil {
			renewThreshold = v
		} else {
			log.WithError(err).Warn("failed to load RenewThreshold")
		}
	}
	if envvar := os.Getenv("JWTCERT_VALIDITY_PERIOD_DAY"); envvar != "" {
		if v, err := strconv.Atoi(envvar); err == nil {
			jwtCertValidityPeriodDay = v
		} else {
			log.WithError(err).Warn("failed to load JWTCertValidityPeriodDay")
		}
	}

	if envvar := os.Getenv("TLSCERT_VALIDITY_PERIOD_DAY"); envvar != "" {
		if v, err := strconv.Atoi(envvar); err == nil {
			tlsCertValidityPeriodDay = v
		} else {
			log.WithError(err).Warn("failed to load TLSCertValidityPeriodDay")
		}
	}

	log.WithFields(log.Fields{
		"period":              expiryCheckPeriod,
		"threshold":           renewThreshold,
		"validity_length_day": jwtCertValidityPeriodDay,
	}).Info("cert manager is configured.")

	CertManager = kv.NewCertManager(kv.CertManagerConfig{
		RenewThreshold:    renewThreshold,
		ExpiryCheckPeriod: expiryCheckPeriod,
	})
	CertManager.Register(share.CLUSJWTKey, &kv.CertManagerCallback{
		NewCert: func(*share.CLUSX509Cert) (*share.CLUSX509Cert, error) {
			cert, key, err := kv.GenTlsKeyCert(share.CLUSJWTKey, "", "", kv.ValidityPeriod{Day: jwtCertValidityPeriodDay}, x509.ExtKeyUsageAny)
			if err != nil {
				return nil, fmt.Errorf("failed to generate tls key/cert: %w", err)
			}
			return &share.CLUSX509Cert{
				CN:   share.CLUSJWTKey,
				Key:  string(key),
				Cert: string(cert),
			}, nil
		},
		NotifyNewCert: func(oldcert *share.CLUSX509Cert, newcert *share.CLUSX509Cert) {
			jwtKeyMutex.Lock()
			defer jwtKeyMutex.Unlock()

			var rsaPublicKey *rsa.PublicKey
			var rsaOldPublicKey *rsa.PublicKey
			var rsaPrivateKey *rsa.PrivateKey
			var err error
			if rsaPublicKey, err = jwt.ParseRSAPublicKeyFromPEM([]byte(newcert.Cert)); err != nil {
				log.WithError(err).Error("failed to parse jwt cert.")
				return
			}

			if newcert.OldCert != nil {
				if rsaOldPublicKey, err = jwt.ParseRSAPublicKeyFromPEM([]byte(newcert.OldCert.Cert)); err != nil {
					log.WithError(err).Warn("failed to parse old jwt cert.")
					// Ignore the error
				}
			}

			if rsaPrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM([]byte(newcert.Key)); err != nil {
				log.WithError(err).Error("failed to parse jwt key.")
				return
			}

			// Here we replace pointers directly, so it's safe to continue using the original pointers in GetJWTSigningKey().
			jwtCertState.jwtPublicKey = rsaPublicKey
			jwtCertState.jwtPrivateKey = rsaPrivateKey
			jwtCertState.jwtOldPublicKey = rsaOldPublicKey

			if t, err := getExpiryDate([]byte(newcert.Cert)); err != nil {
				log.WithError(err).Error("failed to get jwt cert's expiry time.")
			} else {
				jwtCertState.jwtPublicKeyNotAfter = &t
			}

			if newcert.OldCert != nil {
				if t, err := getExpiryDate([]byte(newcert.Cert)); err != nil {
					log.WithError(err).Error("failed to get jwt cert's expiry time.")
				} else {
					jwtCertState.jwtOldPublicKeyNotAfter = &t
				}
			}

			log.WithFields(log.Fields{
				"cn":            "neuvector-jwt-signing",
				"newExpiryDate": jwtCertState.jwtPublicKeyNotAfter,
				"oldExpiryDate": jwtCertState.jwtOldPublicKeyNotAfter,
			}).Info("new certificate is loaded")
		},
	})

	tlsCertNotfound := false
	if _, err := os.Stat(defaultSSLCertFile); errors.Is(err, os.ErrNotExist) {
		tlsCertNotfound = true
	}

	if _, err := os.Stat(defaultSSLKeyFile); errors.Is(err, os.ErrNotExist) {
		tlsCertNotfound = true
	}

	if tlsCertNotfound {
		CertManager.Register(share.CLUSTLSCert, &kv.CertManagerCallback{
			NewCert: func(*share.CLUSX509Cert) (*share.CLUSX509Cert, error) {
				cert, key, err := kv.GenTlsKeyCert(share.CLUSTLSCert, "", "", kv.ValidityPeriod{Day: tlsCertValidityPeriodDay}, x509.ExtKeyUsageServerAuth)
				if err != nil {
					return nil, fmt.Errorf("failed to generate tls key/cert: %w", err)
				}
				return &share.CLUSX509Cert{
					CN:   share.CLUSTLSCert,
					Key:  string(key),
					Cert: string(cert),
				}, nil
			},
			NotifyNewCert: func(oldcert *share.CLUSX509Cert, newcert *share.CLUSX509Cert) {
				tlsMutex.Lock()
				defer tlsMutex.Unlock()

				var oldExpiryDate *time.Time
				var newExpiryDate *time.Time
				var err error

				tlsCert, err := tls.X509KeyPair([]byte(newcert.Cert), []byte(newcert.Key))
				if err != nil {
					log.WithError(err).Error("failed to parse key.")
					return
				}

				if expiryDate, err := getExpiryDate([]byte(newcert.Cert)); err != nil {
					log.WithError(err).Error("failed to get cert's expiry time.")
				} else {
					newExpiryDate = &expiryDate
				}

				if newcert.OldCert != nil {
					if expiryDate, err := getExpiryDate([]byte(newcert.Cert)); err != nil {
						log.WithError(err).Error("failed to get cert's expiry time.")
					} else {
						oldExpiryDate = &expiryDate
					}
				}

				tlsCertificate = &tlsCert

				log.WithFields(log.Fields{
					"cn":            share.CLUSTLSCert,
					"newExpiryDate": newExpiryDate,
					"oldExpiryDate": oldExpiryDate,
				}).Info("new certificate is loaded")
			},
		})
	}
	// Create and setup certificate.
	CertManager.CheckAndRenewCerts()
	go CertManager.Run(context.TODO())
	return nil
}

// PreInitContext() must be called before orch connector starts in main()
func PreInitContext(ctx *Context) {
	cctx = ctx
	localDev = ctx.LocalDev
	cacher = ctx.Cacher
	scanner = ctx.Scanner
	evqueue = ctx.EvQueue
	auditQueue = ctx.AuditQueue
	messenger = ctx.Messenger

	remoteAuther = auth.NewRemoteAuther(nil)
	clusHelper = kv.GetClusterHelper()
	cfgHelper = kv.GetConfigHelper()
}

// InitContext() must be called before StartRESTServer(), StartFedRestServer or AdmissionRestServer()
func InitContext(ctx *Context) {

	_restPort = ctx.RESTPort
	_fedPort = ctx.FedPort
	_fedServerChan = make(chan bool, 1)
	crdEventProcTicker = time.NewTicker(crdEventProcPeriod)
	checkCrdSchemaFunc = ctx.CheckCrdSchemaFunc

	if ctx.PwdValidUnit < _pwdValidPerDayUnit && ctx.PwdValidUnit > 0 {
		_pwdValidUnit = time.Duration(ctx.PwdValidUnit)
	}

	_teleNeuvectorURL = ctx.TeleNeuvectorURL
	_teleFreq = ctx.TeleFreq
	if _teleFreq == 0 {
		_teleFreq = 60
	}

	if err := initCertificates(); err != nil {
		log.WithError(err).Error("failed to initialize keys/certificates.")
	}

	searchRegistries = utils.NewSet()

	for _, reg := range strings.Split(ctx.SearchRegistries, ",") {
		if parsedReg, err := url.Parse(reg); err != nil {
			log.WithError(err).WithFields(log.Fields{"registry": reg}).Warn("unable to parse registry")
			continue
		} else if parsedReg.Host != "" {
			reg = parsedReg.Host
		}

		k := fmt.Sprintf("https://%s/", strings.Trim(reg, " "))
		if !searchRegistries.Contains(k) {
			searchRegistries.Add(k)
		}
	}

	initHttpClients()
}

func StartRESTServer(isNewCluster bool, isLead bool) {
	initDefaultRegistries()
	licenseInit()
	newRepoScanMgr()
	newRegTestMgr()

	if localDev.Host.Platform == share.PlatformKubernetes {
		k8sPlatform = true
	}

	r := httprouter.New()
	r.NotFound = http.HandlerFunc(handlerNotFound)
	r.MethodNotAllowed = http.HandlerFunc(handlerMethodNotAllowed)

	r.POST("/v1/auth", handlerAuthLogin)
	r.POST("/v1/fed_auth", handlerFedAuthLogin) // Skip API document
	r.POST("/v1/auth/:server", handlerAuthLoginServer)
	r.PATCH("/v1/auth", handlerAuthRefresh)
	r.DELETE("/v1/auth", handlerAuthLogout)
	r.DELETE("/v1/fed_auth", handlerFedAuthLogout) // Skip API document. Called by master cluster
	r.GET("/v1/eula", handlerEULAShow)
	r.POST("/v1/eula", handlerEULAConfig)
	r.GET("/v1/user", handlerUserList)
	r.GET("/v1/user/:fullname", handlerUserShow)
	r.GET("/v1/selfuser", handlerSelfUserShow) // Skip API document
	r.POST("/v1/user", handlerUserCreate)
	r.PATCH("/v1/user/:fullname", handlerUserConfig)
	r.PATCH("/v1/user/:fullname/role/:role", handlerUserRoleDomainsConfig) // For CLI to modify one role
	r.POST("/v1/user/:fullname/password", handlerUserPwdConfig)
	r.DELETE("/v1/user/:fullname", handlerUserDelete)
	r.GET("/v1/password_profile", handlerPwdProfileList)
	r.GET("/v1/password_profile/:name", handlerPwdProfileShow)
	//r.POST("/v1/password_profile", handlerPwdProfileCreate)
	r.PATCH("/v1/password_profile/:name", handlerPwdProfileConfig)
	//r.DELETE("/v1/password_profile/:name", handlerPwdProfileDelete)
	r.GET("/v1/token_auth_server", handlerTokenAuthServerList) // Skip API document
	r.GET("/v1/token_auth_server/:server", handlerTokenAuthServerRequest)
	r.POST("/v1/token_auth_server/:server", handlerTokenAuthServerRequest)
	r.GET("/v1/token_auth_server/:server/slo", handlerGenerateSLORequest)
	r.GET("/v1/server", handlerServerList)
	r.GET("/v1/server/:name", handlerServerShow)
	r.GET("/v1/server/:name/user", handlerServerUserList)
	r.POST("/v1/server", handlerServerCreate)
	r.PATCH("/v1/server/:name", handlerServerConfig)
	r.PATCH("/v1/server/:name/role/:role", handlerServerRoleGroupsConfig)         // (4.2-) For CLI to modify one role. For backward compatible only after 4.3
	r.PATCH("/v1/server/:name/group/:group", handlerServerGroupRoleDomainsConfig) // (4.3+) For CLI to modify/add a group's mapped roles
	r.PATCH("/v1/server/:name/groups", handlerServerGroupsOrderConfig)            // (4.3+) For CLI to modify mapped groups order
	r.DELETE("/v1/server/:name", handlerServerDelete)
	r.GET("/v1/file/config", handlerConfigExport)
	r.POST("/v1/file/config", handlerConfigImport)
	r.GET("/v1/file/group", handlerGroupCfgExport)
	r.POST("/v1/file/group", handlerGroupCfgExport)                           // as client, GO's http.NewRequest(http.MethodGet) doesn't use body. This API is for multi-cluster purpose.
	r.GET("/v1/file/group/config", handlerGetGroupCfgImport)                  // get current running import task
	r.POST("/v1/file/group/config", handlerGroupCfgImport)                    // for providing similar function as crd import but do not rely on crd webhook. supported 'scope' query parameter values: "local"(default).
	r.POST("/v1/file/admission", handlerAdmCtrlExport)                        // supported 'scope' query parameter values: "local"(default).
	r.POST("/v1/file/admission/config", handlerAdmCtrlImport)                 // for providing similar function as crd import but do not rely on crd webhook. besides, it's for replacement
	r.POST("/v1/file/dlp", handlerDlpExport)                                  // supported 'scope' query parameter values: "local"(default).
	r.POST("/v1/file/dlp/config", handlerDlpImport)                           // for providing similar function as crd import but do not rely on crd webhook. besides, it's for replacement
	r.POST("/v1/file/waf", handlerWafExport)                                  // supported 'scope' query parameter values: "local"(default).
	r.POST("/v1/file/waf/config", handlerWafImport)                           // for providing similar function as crd import but do not rely on crd webhook. besides, it's for replacement
	r.POST("/v1/file/compliance/profile", handlerCompProfileExport)           //
	r.POST("/v1/file/compliance/profile/config", handlerCompProfileImport)    // for providing similar function as crd import but do not rely on crd webhook. besides, it's for replacement
	r.POST("/v1/file/vulnerability/profile", handlerVulnProfileExport)        //
	r.POST("/v1/file/vulnerability/profile/config", handlerVulnProfileImport) // for providing similar function as crd import but do not rely on crd webhook. besides, it's for replacement
	r.POST("/v1/internal/alert", handlerAcceptAlert)                          // skip API document
	r.GET("/v1/internal/system", handlerInternalSystem)                       // skip API document
	r.GET("/v1/system/usage", handlerSystemUsage)                             // skip API document
	r.GET("/v1/system/summary", handlerSystemSummary)
	r.GET("/v1/system/config", handlerSystemGetConfig)   // supported 'scope' query parameter values: ""(all, default)/"fed"/"local". no payload
	r.GET("/v2/system/config", handlerSystemGetConfigV2) // supported 'scope' query parameter values: ""(all, default)/"fed"/"local". no payload. starting from 5.0, rest client should call this api.
	r.GET("/v1/system/alerts", handlerSystemGetAlerts)
	r.PATCH("/v1/system/config", handlerSystemConfig)
	r.PATCH("/v2/system/config", handlerSystemConfigV2)
	r.POST("/v1/system/config/webhook", handlerSystemWebhookCreate)
	r.PATCH("/v1/system/config/webhook/:name", handlerSystemWebhookConfig)  // supported 'scope' query parameter values: "fed"/"local"(default).
	r.DELETE("/v1/system/config/webhook/:name", handlerSystemWebhookDelete) // supported 'scope' query parameter values: "fed"/"local"(default).
	r.POST("/v1/system/request", handlerSystemRequest)
	r.GET("/v1/system/license", handlerLicenseShow)
	r.POST("/v1/system/license/update", handlerLicenseUpdate)
	r.DELETE("/v1/system/license", handlerLicenseDelete)
	r.GET("/v1/domain", handlerDomainList)
	r.PATCH("/v1/domain", handlerDomainConfig)
	r.PATCH("/v1/domain/:name", handlerDomainEntryConfig)
	r.GET("/v1/host", handlerHostList)
	r.GET("/v1/host/:id", handlerHostShow)
	r.GET("/v1/host/:id/compliance", handlerHostCompliance)
	r.GET("/v1/host/:id/process_profile", handlerHostProcessProfile) // debug, possibly used by UI
	r.GET("/v1/controller", handlerControllerList)
	r.GET("/v1/controller/:id", handlerControllerShow)
	r.GET("/v1/controller/:id/stats", handlerControllerStats)
	r.GET("/v1/controller/:id/config", handlerControllerGetConfig)
	r.GET("/v1/controller/:id/counter", handlerControllerCounter)      // debug
	r.POST("/v1/controller/:id/profiling", handlerControllerProfiling) // debug
	// r.GET("/v1/controller/:id/logs", handlerControllerGetLogs) // debug
	r.PATCH("/v1/controller/:id", handlerControllerConfig)
	r.GET("/v1/enforcer", handlerAgentList)
	r.GET("/v1/enforcer/:id", handlerAgentShow)
	r.GET("/v1/enforcer/:id/stats", handlerAgentStats)
	r.GET("/v1/enforcer/:id/counter", handlerAgentCounter)      // debug
	r.POST("/v1/enforcer/:id/profiling", handlerAgentProfiling) // debug
	r.GET("/v1/enforcer/:id/config", handlerAgentGetConfig)
	r.PATCH("/v1/enforcer/:id", handlerAgentConfig)
	r.GET("/v1/enforcer/:id/probe_summary", handlerProbeSummary)         // debug
	r.GET("/v1/enforcer/:id/probe_processes", handlerProbeProcessMap)    // debug
	r.GET("/v1/enforcer/:id/probe_containers", handlerProbeContainerMap) // debug
	// r.GET("/v1/enforcer/:id/logs", handlerAgentGetLogs)               // debug
	r.GET("/v1/workload", handlerWorkloadList)
	r.GET("/v2/workload", handlerWorkloadListV2)  // starting from 5.0, rest client should call this api.
	r.POST("/v2/workload", handlerWorkloadListV2) // starting from 5.0, rest client should call this api.
	r.GET("/v1/workload/:id", handlerWorkloadShow)
	r.GET("/v2/workload/:id", handlerWorkloadShowV2) // starting from 5.0, rest client should call this api.
	r.GET("/v1/workload/:id/stats", handlerWorkloadStats)
	r.GET("/v1/workload/:id/config", handlerWorkloadGetConfig)
	r.GET("/v1/workload/:id/process", handlerWorkloadProcess)
	r.GET("/v1/workload/:id/process_history", handlerWorkloadProcessHistory)
	r.GET("/v1/workload/:id/process_profile", handlerWorkloadProcessProfile)  // Skip API document, debug, possibly used by UI
	r.GET("/v1/workload/:id/file_profile", handlerWorkloadFileMonitorProfile) // Skip API document, debug, possibly used by UI
	// r.GET("/v1/workload/:id/logs", handlerWorkloadLogs) // debug
	r.PATCH("/v1/workload/:id", handlerWorkloadConfig)
	r.POST("/v1/workload/request/:id", handlerWorkloadRequest)
	r.GET("/v1/workload/:id/compliance", handlerContainerCompliance)
	r.GET("/v1/conversation_endpoint", handlerConverEndpointList)          // Skip API document
	r.PATCH("/v1/conversation_endpoint/:id", handlerConverEndpointConfig)  // Skip API document
	r.DELETE("/v1/conversation_endpoint/:id", handlerConverEndpointDelete) // Skip API document
	r.GET("/v1/conversation", handlerConverList)                           // Skip API document
	r.GET("/v1/conversation/:from/:to", handlerConverShow)                 // Skip API document
	r.DELETE("/v1/conversation", handlerConverDeleteAll)                   // Skip API document
	r.DELETE("/v1/conversation/:from/:to", handlerConverDelete)            // Skip API document
	r.GET("/v1/group", handlerGroupList)                                   // supported 'scope' query parameter values: ""(all, default)/"fed"/"local". no payload
	r.GET("/v1/group/:name", handlerGroupShow)                             // no payload
	r.POST("/v1/group", handlerGroupCreate)                                //
	r.PATCH("/v1/group/:name", handlerGroupConfig)                         //
	r.DELETE("/v1/group/:name", handlerGroupDelete)                        // no payload
	r.GET("/v1/group/:name/stats", handlerGroupStats)
	r.GET("/v1/process_profile", handlerProcessProfileList)           // supported 'scope' query parameter values: ""(all, default)/"fed"/"local". no payload
	r.GET("/v1/process_profile/:name", handlerProcessProfileShow)     //
	r.PATCH("/v1/process_profile/:name", handlerProcessProfileConfig) //
	r.GET("/v1/process_rules/:uuid", handlerProcRuleShow)             //
	r.GET("/v1/file_monitor", handlerFileMonitorList)                 // supported 'scope' query parameter values: ""(all, default)/"fed"/"local". no payload
	r.GET("/v1/file_monitor/:name", handlerFileMonitorShow)
	r.PATCH("/v1/file_monitor/:name", handlerFileMonitorConfig)
	r.GET("/v1/file_monitor_file", handlerFileMonitorFile) // debug
	r.GET("/v1/dlp/sensor", handlerDlpSensorList)
	r.GET("/v1/dlp/sensor/:name", handlerDlpSensorShow)
	r.POST("/v1/dlp/sensor", handlerDlpSensorCreate)
	r.PATCH("/v1/dlp/sensor/:name", handlerDlpSensorConfig)
	r.DELETE("/v1/dlp/sensor/:name", handlerDlpSensorDelete)
	r.GET("/v1/dlp/group", handlerDlpGroupList)
	r.GET("/v1/dlp/group/:name", handlerDlpGroupShow)
	r.PATCH("/v1/dlp/group/:name", handlerDlpGroupConfig)
	r.GET("/v1/dlp/rule", handlerDlpRuleList)
	r.GET("/v1/dlp/rule/:name", handlerDlpRuleShow)
	//r.POST("/v1/dlp/rule", handlerDlpRuleCreate)							  // before uncomment this line, check if access control needs to be adjusted in handlerDlpRuleCreate for required permissions
	//r.PATCH("/v1/dlp/rule/:name", handlerDlpRuleConfig)					  // before uncomment this line, check if access control needs to be adjusted in handlerDlpRuleConfig for required permissions
	//r.DELETE("/v1/dlp/rule/:name", handlerDlpRuleDelete)					  // before uncomment this line, check if access control needs to be adjusted in handlerDlpRuleDelete for required permissions
	r.GET("/v1/waf/sensor", handlerWafSensorList) // supported 'scope' query parameter values: "local"(default).
	r.GET("/v1/waf/sensor/:name", handlerWafSensorShow)
	r.POST("/v1/waf/sensor", handlerWafSensorCreate)
	r.PATCH("/v1/waf/sensor/:name", handlerWafSensorConfig)
	r.DELETE("/v1/waf/sensor/:name", handlerWafSensorDelete)
	r.GET("/v1/waf/group", handlerWafGroupList) // supported 'scope' query parameter values: "local"(default).
	r.GET("/v1/waf/group/:name", handlerWafGroupShow)
	r.PATCH("/v1/waf/group/:name", handlerWafGroupConfig)
	r.GET("/v1/waf/rule", handlerWafRuleList)
	r.GET("/v1/waf/rule/:name", handlerWafRuleShow)
	r.GET("/v1/policy/rule", handlerPolicyRuleList)                           // supported 'scope' query parameter values: ""(all, default)/"fed"/"local". no payload
	r.GET("/v1/policy/rule/:id", handlerPolicyRuleShow)                       // no payload
	r.PATCH("/v1/policy/rule", handlerPolicyRuleAction)                       // supported 'scope' query parameter values: "fed"/"local"(default).
	r.PATCH("/v1/policy/rule/:id", handlerPolicyRuleConfig)                   //
	r.DELETE("/v1/policy/rule/:id", handlerPolicyRuleDelete)                  // no payload
	r.DELETE("/v1/policy/rule", handlerPolicyRuleDeleteAll)                   // supported 'scope' query parameter values: "fed"/"local"(default). no payload
	r.POST("/v1/policy/rules/promote", handlerPolicyRulesPromote)             // promote local/crd network policy rules to fed
	r.GET("/v1/response/rule", handlerResponseRuleList)                       // supported 'scope' query parameter values: ""(all, default)/"fed"/"local". no payload
	r.GET("/v1/response/rule/:id", handlerResponseRuleShow)                   // no payload
	r.GET("/v1/response/workload_rules/:id", handlerResponseRuleShowWorkload) //
	r.PATCH("/v1/response/rule", handlerResponseRuleAction)                   // all inserted rules in the payload must have the same CfgType.
	r.PATCH("/v1/response/rule/:id", handlerResponseRuleConfig)               //
	r.DELETE("/v1/response/rule/:id", handlerResponseRuleDelete)              // no payload
	r.DELETE("/v1/response/rule", handlerResponseRuleDeleteAll)               // supported 'scope' query parameter values: "fed"/"local"(default). no payload
	r.GET("/v1/response/options", handlerResponseRuleOptions)                 // Skip API document, use internally. supported 'scope' query parameter values: "fed"/"local"(default).
	r.GET("/v1/admission/state", handlerGetAdmissionState)
	r.PATCH("/v1/admission/state", handlerPatchAdmissionState)
	r.GET("/v1/admission/options", handlerGetAdmissionOptions)
	r.GET("/v1/admission/stats", handlerAdmissionStatistics)
	r.GET("/v1/admission/rules", handlerGetAdmissionRules)             // supported 'scope' query parameter values: ""(all, default)/"fed"/"local". no payload
	r.GET("/v1/admission/rule/:id", handlerGetAdmissionRule)           // no payload
	r.POST("/v1/admission/rule", handlerAddAdmissionRule)              //
	r.PATCH("/v1/admission/rule", handlerPatchAdmissionRule)           // rule id is in payload
	r.DELETE("/v1/admission/rule/:id", handlerDeleteAdmissionRule)     // no payload
	r.DELETE("/v1/admission/rules", handlerDeleteAdmissionRules)       // supported 'scope' query parameter values: "fed"/"local"(default). no payload
	r.POST("/v1/admission/rule/promote", handlerPromoteAdmissionRules) // promote local/crd admission control rules to fed

	r.POST("/v1/assess/admission/rule", handlerAssessAdmCtrlRules) // for assessing admission control rules' criteria

	r.POST("/v1/service", handlerServiceCreate)
	r.PATCH("/v1/service/config", handlerServiceBatchConfig)
	r.GET("/v1/service", handlerServiceList)
	r.GET("/v1/service/:name", handlerServiceShow)
	r.PATCH("/v1/service/config/profile", handlerServiceBatchConfigProfile)
	r.PATCH("/v1/service/config/network", handlerServiceBatchConfigNetwork)

	r.GET("/v1/fed/member", handlerGetFedMember)                             // Skip API document
	r.PATCH("/v1/fed/config", handlerConfigLocalCluster)                     // Skip API document
	r.POST("/v1/fed/promote", handlerPromoteToMaster)                        // Skip API document
	r.POST("/v1/fed/demote", handlerDemoteFromMaster)                        // Skip API document
	r.GET("/v1/fed/join_token", handlerGetFedJoinToken)                      // Skip API document
	r.POST("/v1/fed/join", handlerJoinFed)                                   // Skip API document, called by manager of joint cluster
	r.POST("/v1/fed/leave", handlerLeaveFed)                                 // Skip API document, called by manager of joint cluster
	r.DELETE("/v1/fed/cluster/:id", handlerRemoveJointCluster)               // Skip API document, called by manager of master cluster
	r.POST("/v1/fed/deploy", handlerDeployFedRules)                          // Skip API document, called by manager of master cluster
	r.POST("/v1/fed/ping_internal", handlerPingJointInternal)                // Skip API document, called from master cluster to joint cluster
	r.POST("/v1/fed/joint_test_internal", handlerTestJointInternal)          // Skip API document, called from master cluster to joint cluster
	r.POST("/v1/fed/remove_internal", handlerJointKickedInternal)            // Skip API document, called from master cluster to joint cluster
	r.POST("/v1/fed/command_internal", handlerFedCommandInternal)            // Skip API document, called from master cluster to joint cluster
	r.GET("/v1/fed/view/:id", handlerGetJointClusterView)                    // Skip API document, called by manager of master cluster
	r.GET("/v1/fed/cluster/:id/*request", handlerFedClusterForwardGet)       // Skip API document, called by manager of master cluster
	r.POST("/v1/fed/cluster/:id/*request", handlerFedClusterForwardPost)     // Skip API document, called by manager of master cluster
	r.PATCH("/v1/fed/cluster/:id/*request", handlerFedClusterForwardPatch)   // Skip API document, called by manager of master cluster
	r.DELETE("/v1/fed/cluster/:id/*request", handlerFedClusterForwardDelete) // Skip API document, called by manager of master cluster
	//r.GET("/v1/fed/tokens", handlerDumpAuthData)                           // TEST only. Must be comment out in release build
	//-----------------------------------------------------------------------

	r.GET("/v1/log/activity", handlerActivityList)
	r.GET("/v1/log/event", handlerEventList)
	r.GET("/v1/log/security", handlerSecurityList) // return incidents, threats and violations
	r.GET("/v1/log/incident", handlerIncidentList)
	r.GET("/v1/log/threat", handlerThreatList)
	r.GET("/v1/log/threat/:id", handlerThreatShow)
	r.GET("/v1/log/violation", handlerViolationList)
	r.GET("/v1/log/violation/workload", handlerViolationWorkloads)
	r.GET("/v1/log/audit", handlerAuditList)
	r.GET("/v1/scan/scanner", handlerScannerList)
	r.PATCH("/v1/scan/config", handlerScanConfig)
	r.GET("/v1/scan/config", handlerScanConfigGet)
	r.GET("/v1/scan/status", handlerScanStatus)
	r.GET("/v1/scan/cache_stat/:id", handlerScanCacheStat)
	r.GET("/v1/scan/cache_data/:id", handlerScanCacheData)
	r.POST("/v1/scan/workload/:id", handlerScanWorkloadReq)
	r.GET("/v1/scan/workload/:id", handlerScanWorkloadReport)
	r.GET("/v1/scan/image", handlerScanImageSummary)    // Returns all workload's scan result summary by images
	r.GET("/v1/scan/image/:id", handlerScanImageReport) // Returns workload scan result by workload's image ID
	r.POST("/v1/scan/host/:id", handlerScanHostReq)
	r.GET("/v1/scan/host/:id", handlerScanHostReport)
	r.POST("/v1/scan/platform/platform", handlerScanPlatformReq)
	r.GET("/v1/scan/platform", handlerScanPlatformSummary)
	r.GET("/v1/scan/platform/platform", handlerScanPlatformReport)
	r.POST("/v1/scan/result/repository", handlerScanRepositorySubmit) // Used by CI-integration, for scanner submit scan result. Skip API
	r.POST("/v1/scan/repository", handlerScanRepositoryReq)           // Used by CI-integration, for scanning container image
	r.POST("/v1/scan/registry", handlerRegistryCreate)
	r.POST("/v2/scan/registry", handlerRegistryCreate)
	r.PATCH("/v1/scan/registry/:name", handlerRegistryConfig)
	r.PATCH("/v2/scan/registry/:name", handlerRegistryConfig)
	r.POST("/v1/scan/registry/:name/test", handlerRegistryTest)         // debug
	r.POST("/v2/scan/registry/:name/test", handlerRegistryTest)         // debug
	r.DELETE("/v1/scan/registry/:name/test", handlerRegistryTestCancel) // debug
	r.GET("/v1/scan/registry", handlerRegistryList)                     // supported 'scope' query parameter values: ""(all, default)/"fed"/"local". no payload
	r.GET("/v1/scan/registry/:name", handlerRegistryShow)
	r.GET("/v1/scan/registry/:name/images", handlerRegistryImageSummary)
	r.DELETE("/v1/scan/registry/:name", handlerRegistryDelete)
	r.POST("/v1/scan/registry/:name/scan", handlerRegistryStart)
	r.DELETE("/v1/scan/registry/:name/scan", handlerRegistryStop)
	r.GET("/v1/scan/registry/:name/image/:id", handlerRegistryImageReport)
	r.GET("/v1/scan/registry/:name/layers/:id", handlerRegistryLayersReport)
	r.GET("/v1/scan/asset", handlerAssetVulnerability)      // skip API document
	r.POST("/v1/vulasset", handlerVulAssetCreate)           // skip API document
	r.GET("/v1/vulasset", handlerVulAssetGet)               // skip API document
	r.POST("/v1/assetvul", handlerAssetVul)                 // skip API document
	r.POST("/v1/scan/asset/images", handlerAssetViewCreate) // skip API document
	r.GET("/v1/scan/asset/images", handlerAssetViewGet)     // skip API document

	// Sigstore Configuration
	r.GET("/v1/scan/sigstore/root_of_trust", handlerSigstoreRootOfTrustGetAll)
	r.POST("/v1/scan/sigstore/root_of_trust", handlerSigstoreRootOfTrustPost)
	r.GET("/v1/scan/sigstore/root_of_trust/:root_name", handlerSigstoreRootOfTrustGetByName)
	r.PATCH("/v1/scan/sigstore/root_of_trust/:root_name", handlerSigstoreRootOfTrustPatchByName)
	r.DELETE("/v1/scan/sigstore/root_of_trust/:root_name", handlerSigstoreRootOfTrustDeleteByName)
	r.GET("/v1/scan/sigstore/root_of_trust/:root_name/verifier", handlerSigstoreVerifierGetAll)
	r.POST("/v1/scan/sigstore/root_of_trust/:root_name/verifier", handlerSigstoreVerifierPost)
	r.GET("/v1/scan/sigstore/root_of_trust/:root_name/verifier/:verifier_name", handlerSigstoreVerifierGetByName)
	r.PATCH("/v1/scan/sigstore/root_of_trust/:root_name/verifier/:verifier_name", handlerSigstoreVerifierPatchByName)
	r.DELETE("/v1/scan/sigstore/root_of_trust/:root_name/verifier/:verifier_name", handlerSigstoreVerifierDeleteByName)

	// compliance
	r.GET("/v1/compliance/asset", handlerAssetCompliance) // Skip API document
	r.GET("/v1/bench/host/:id/docker", handlerDockerBench)
	r.POST("/v1/bench/host/:id/docker", handlerDockerBenchRun)
	r.GET("/v1/bench/host/:id/kubernetes", handlerKubeBench)
	r.POST("/v1/bench/host/:id/kubernetes", handlerKubeBenchRun)
	r.GET("/v1/custom_check/:group", handlerCustomCheckShow)
	r.GET("/v1/custom_check", handlerCustomCheckList)
	r.PATCH("/v1/custom_check/:group", handlerCustomCheckConfig)
	r.GET("/v1/compliance/available_filter", handlerGetAvaiableComplianceFilter) // Skip API document, use internally
	r.GET("/v1/compliance/profile", handlerComplianceProfileList)                // Only default is accepted, so not POST/DELETE
	r.GET("/v1/compliance/profile/:name", handlerComplianceProfileShow)
	r.PATCH("/v1/compliance/profile/:name", handlerComplianceProfileConfig)
	r.PATCH("/v1/compliance/profile/:name/entry/:check", handlerComplianceProfileEntryConfig)
	r.DELETE("/v1/compliance/profile/:name/entry/:check", handlerComplianceProfileEntryDelete)

	// vulnerability management
	r.GET("/v1/vulnerability/profile", handlerVulnerabilityProfileList) // Only default is accepted, so not POST/DELETE
	r.GET("/v1/vulnerability/profile/:name", handlerVulnerabilityProfileShow)
	r.PATCH("/v1/vulnerability/profile/:name", handlerVulnerabilityProfileConfig)
	r.POST("/v1/vulnerability/profile/:name/entry", handlerVulnerabilityProfileEntryCreate)
	r.PATCH("/v1/vulnerability/profile/:name/entry/:id", handlerVulnerabilityProfileEntryConfig)
	r.DELETE("/v1/vulnerability/profile/:name/entry/:id", handlerVulnerabilityProfileEntryDelete)

	r.GET("/v1/sniffer", handlerSnifferList)
	r.GET("/v1/sniffer/:id", handlerSnifferShow)
	r.POST("/v1/sniffer", handlerSnifferStart)
	r.PATCH("/v1/sniffer/stop/:id", handlerSnifferStop)
	r.DELETE("/v1/sniffer/:id", handlerSnifferDelete)
	r.GET("/v1/sniffer/:id/pcap", handlerSnifferGetFile)
	r.GET("/v1/list/application", handlerApplicationList)    // Skip API document, use internally
	r.GET("/v1/list/registry_type", handlerRegistryTypeList) // Skip API document, use internally
	r.GET("/v1/list/compliance", handlerComplianceList)      // Skip API document, use internally
	r.GET("/v1/session", handlerSessionList)                 // Skip API document, debug, but used in UI
	r.GET("/v1/session/summary", handlerSessionSummary)      // Skip API document, debug
	r.DELETE("/v1/session", handlerSessionDelete)            // Skip API document

	r.GET("/v1/meter", handlerMeterList)                                       // debug
	r.POST("/v1/debug/server/test", handlerServerTest)                         // debug
	r.GET("/v1/debug/ip2workload", handlerDebugIP2Workload)                    // debug
	r.GET("/v1/debug/internal_subnets", handlerDebugGetInternalSubnet)         // debug
	r.GET("/v1/debug/policy/rule", handlerDebugPolicyRuleList)                 // debug
	r.GET("/v1/debug/dlp/wlrule", handlerDebugDlpWlRuleList)                   // debug
	r.GET("/v1/debug/dlp/rule", handlerDebugDlpRuleList)                       // debug
	r.GET("/v1/debug/dlp/mac", handlerDebugDlpRuleMac)                         // debug
	r.GET("/v1/debug/system/stats", handlerDebugSystemStats)                   // debug
	r.POST("/v1/debug/controller/sync/:id", handlerDebugControllerSyncRequest) // debug
	r.GET("/v1/debug/controller/sync", handlerDebugControllerSyncInfo)         // debug
	r.GET("/v1/debug/workload/intercept", handlerDebugWorkloadIntcp)           // debug
	r.GET("/v1/debug/registry/image/:name", handlerDebugRegistryImage)         // debug
	r.GET("/v1/debug/admission_stats", handlerAdmissionStatistics)             // debug
	r.POST("/v1/debug/admission/test", handlerGetAdmissionTest)                // debug

	// IBM SA integration
	r.GET("/v1/partner/ibm_sa_ep", handlerGetIBMSASetupURL)                 // Skip API document, called by NV Manager to get setup URI  like "/v1/partner/ibm_sa/{id}/setup" that is used for IBM SA integration
	r.GET("/v1/partner/ibm_sa_config", handlerGetIBMSAConfig)               // Skip API document
	r.GET("/v1/partner/ibm_sa/:id/setup", handlerGetIBMSAEpSetupToken)      // Skip API document, called by IBM SA to get token used by POST("/v1/partner/ibm_sa/:id/setup/:action")
	r.GET("/v1/partner/ibm_sa/:id/setup/:info", handlerGetIBMSAEpInfo)      // Skip API document, called by IBM SA
	r.POST("/v1/partner/ibm_sa/:id/setup/:action", handlerPostIBMSAEpSetup) // Skip API document, called by IBM SA
	//r.DELETE("/v1/partner/ibm_sa/:id/setup/:accountID/:providerID", handlerDeleteIBMSAEpSetup) // it's for IBM SA IBM SA to test the integration. Need to comment out in release build
	//r.POST("/findings/v1/:accountID/providers/:providerID/occurrences", handlerTestOccurrences) // for simulating IBM SA. Need to comment out in release build
	//r.POST("/identity/token", handlerTestIBMIAM)                                                // for simulating IBM IAM. Need to comment out in release build

	// custom role
	r.GET("/v1/user_role_permission/options", handlerGetRolePermissionOptions) // Skip API document
	r.GET("/v1/user_role", handlerRoleList)
	r.GET("/v1/user_role/:name", handlerRoleShow)
	r.POST("/v1/user_role", handlerRoleCreate)
	r.PATCH("/v1/user_role/:name", handlerRoleConfig)
	r.DELETE("/v1/user_role/:name", handlerRoleDelete)

	// api key
	r.GET("/v1/api_key", handlerApikeyList)
	r.GET("/v1/api_key/:name", handlerApikeyShow)
	r.POST("/v1/api_key", handlerApikeyCreate)
	r.DELETE("/v1/api_key/:name", handlerApikeyDelete)
	r.GET("/v1/selfapikey", handlerSelfApikeyShow) // Skip API document

	// remote export repository
	r.POST("/v1/system/config/remote_repository", handlerRemoteRepositoryPost)
	r.PATCH("/v1/system/config/remote_repository/:nickname", handlerRemoteRepositoryPatch)
	r.DELETE("/v1/system/config/remote_repository/:nickname", handlerRemoteRepositoryDelete)

	// csp billing adapter integration
	r.POST("/v1/csp/file/support", handlerCspSupportExport) // Skip API document. For downloading the tar ball that can be submitted to support portal

	access.CompileUriPermitsMapping()

	log.WithFields(log.Fields{"port": _restPort}).Info("Start REST server")

	if isNewCluster && isLead {
		go loadFedInitCfg()
	}

	addr := fmt.Sprintf(":%d", _restPort)
	config := &tls.Config{
		MinVersion:               tls.VersionTLS11,
		PreferServerCipherSuites: true,
		CipherSuites:             utils.GetSupportedTLSCipherSuites(),
	}

	// tlsCertificate is only generated when default location has no files
	// so we can check if tlsCertificate is nil to see if we should adopt dynamically generated certificate.
	certFileName := defaultSSLCertFile
	keyFileName := defaultSSLKeyFile
	if tlsCertificate != nil {
		// When provide certificate from memory, certFileName and keyFileName have to be empty strings.
		certFileName = ""
		keyFileName = ""
		config.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			tlsMutex.RLock()
			defer tlsMutex.RUnlock()
			return tlsCertificate, nil
		}
	}

	server := &http.Server{
		Addr:      addr,
		Handler:   restLogger{r},
		TLSConfig: config,
		// ReadTimeout:  time.Duration(5) * time.Second,
		// WriteTimeout: time.Duration(35) * time.Second,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0), // disable http/2
		ErrorLog:     newHttpServerErrorWriter(),
	}
	for {
		if err := server.ListenAndServeTLS(certFileName, keyFileName); err != nil {
			if err == http.ErrServerClosed {
				if cfgmapRetryTimer != nil {
					cfgmapRetryTimer.Stop()
				}
			}
			log.WithFields(log.Fields{"error": err}).Error("Fail to start SSL rest")
			time.Sleep(time.Second * 5)
		} else {
			break
		}
	}
}

func startFedRestServer(fedPingInterval uint32) {
	if m := clusHelper.GetFedMembership(); m == nil || m.FedRole != api.FedRoleMaster {
		return
	} else {
		_masterClusterIP = m.MasterCluster.RestInfo.Server
	}

	fedRestServerMutex.Lock()
	atomic.LoadUint64(&fedRestServerState)
	if fedRestServerState == _fedRestServerRunning_ {
		fedRestServerMutex.Unlock()
		return
	}

	addr := fmt.Sprintf(":%d", _fedPort)
	r := httprouter.New()
	r.NotFound = http.HandlerFunc(handlerNotFound)
	r.MethodNotAllowed = http.HandlerFunc(handlerMethodNotAllowed)

	r.POST("/v1/fed/join_internal", handlerJoinFedInternal)              // Skip API document, called from joining cluster to master cluster
	r.POST("/v1/fed/poll_internal", handlerPollFedRulesInternal)         // Skip API document, called from joint cluster to master cluster
	r.POST("/v1/fed/scan_data_internal", handlerPollFedScanDataInternal) // Skip API document, called from joint cluster to master cluster
	r.POST("/v1/fed/leave_internal", handlerLeaveFedInternal)            // Skip API document, called from joint cluster to master cluster
	r.POST("/v1/fed/csp_support_internal", handlerCspSupportInternal)    // Skip API document, called from joint cluster to master cluster for collecting support config
	r.GET("/v1/fed/healthcheck", handlerFedHealthCheck)                  // for fed master REST server health-check. no token required

	config := &tls.Config{MinVersion: tls.VersionTLS11}
	server := &http.Server{
		Addr:      addr,
		Handler:   restLogger{r},
		TLSConfig: config,
		// ReadTimeout:  time.Duration(5) * time.Second,
		// WriteTimeout: time.Duration(35) * time.Second,
		ErrorLog: newHttpServerErrorWriter(),
	}

	atomic.StoreUint64(&fedRestServerState, _fedRestServerRunning_)

	log.WithFields(log.Fields{"port": _fedPort}).Info("Start fed REST server")
	go func() {
		// The certificate used by fed rest server will be in the order below:
		// 1. fed-ssl-cert.key
		// 2. ssl-cert.key
		// 3. tlsCertificate, which is generated in memory and stored in consul.
		keyFileName := defFedSSLKeyFile
		certFileName := defFedSSLCertFile
		_, err1 := os.Stat(keyFileName)
		_, err2 := os.Stat(certFileName)
		if os.IsNotExist(err1) || os.IsNotExist(err2) {
			certFileName = defaultSSLCertFile
			keyFileName = defaultSSLKeyFile

			// tlsCertificate is only generated when default location has no files
			// so we can check if tlsCertificate is nil to see if we should adopt dynamically generated certificate.
			if tlsCertificate != nil {
				// When provide certificate from memory, certFileName and keyFileName have to be empty strings.
				certFileName = ""
				keyFileName = ""
				config.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					tlsMutex.RLock()
					defer tlsMutex.RUnlock()
					return tlsCertificate, nil
				}
			}
		}
		for i := 0; i < 5; i++ {
			if err := server.ListenAndServeTLS(certFileName, keyFileName); err != nil {
				if err == http.ErrServerClosed {
					log.Info("REST Server closed")
					break
				}
				log.WithFields(log.Fields{"error": err}).Error("Fail to start fed SSL rest")
				time.Sleep(time.Second * 5)
			}
		}
		atomic.StoreUint64(&fedRestServerState, _fedRestServerStopped_)
	}()

	fedRestServerMutex.Unlock()

	if fedPingInterval > 0 {
		atomic.StoreUint32(&_fedPingInterval, fedPingInterval)
	}
	if leader := atomic.LoadUint32(&_isLeader); leader == 1 {
		_fedPingTimer.Reset(time.Minute * time.Duration(atomic.LoadUint32(&_fedPingInterval)))
	} else {
		_fedPingTimer.Stop()
	}
	// listening OS shutdown singal
	osSignalChan := make(chan os.Signal, 1)
	signal.Notify(osSignalChan, syscall.SIGINT, syscall.SIGTERM)

Loop:
	for {
		select {
		case <-_fedServerChan:
			log.Info("Got master cluster demoted signal, shutting down fed REST server gracefully...")
			kickFedLoginSessions()
			server.Shutdown(context.Background())
			break Loop
		case <-osSignalChan:
			log.Info("Got OS shutdown signal, shutting down fed REST server gracefully...")
			server.Shutdown(context.Background())
			break Loop
		case <-_fedPingTimer.C:
			if leader := atomic.LoadUint32(&_isLeader); leader == 1 {
				go pingJointClusters()
				_fedPingTimer.Reset(time.Minute * time.Duration(atomic.LoadUint32(&_fedPingInterval)))
			} else {
				_fedPingTimer.Stop()
			}
		}
	}
}

func stopFedRestServer() {
	_fedPingTimer.Stop()
	fedRestServerMutex.Lock()
	defer fedRestServerMutex.Unlock()
	atomic.LoadUint64(&fedRestServerState)
	if fedRestServerState == _fedRestServerRunning_ {
		log.Info("Signal to shutdown fed REST server...")
		_fedServerChan <- true
	}
}

func StartStopFedPingPoll(cmd, interval uint32, param1 interface{}) error {
	var err error
	leader := atomic.LoadUint32(&_isLeader)
	switch cmd {
	case share.StartPollFedMaster:
		if interval > 0 {
			atomic.StoreUint32(&_fedPollInterval, interval)
		}
		if leader == 1 {
			pollFedRules(true, 3)
			_fedPollingTimer.Reset(time.Minute * time.Duration(atomic.LoadUint32(&_fedPollInterval)))
		}
	case share.InstantPollFedMaster:
		if leader == 1 {
			if interval > 0 {
				// for share.ImmediatePollFedMaster cmd, param `interval` is actually for _fedFullPolling
				atomic.StoreUint32(&_fedFullPolling, 1)
			}
			_fedPollingTimer.Reset(0)
		}
	case share.InstantPingFedJoints:
		if leader == 1 {
			_fedPingTimer.Reset(0)
		}
	case share.JointLoadOwnKeys, share.MasterLoadJointKeys:
		if param1 != nil {
			var callerFedRole string
			if cmd == share.JointLoadOwnKeys {
				callerFedRole = api.FedRoleJoint
			} else if cmd == share.MasterLoadJointKeys {
				callerFedRole = api.FedRoleMaster
			}
			if cluster, ok := param1.(*share.CLUSFedJointClusterInfo); ok && cluster != nil {
				if err = setJointKeysInCache(callerFedRole, cluster); err != nil {
					log.WithFields(log.Fields{"id": cluster.ID, "err": err}).Error("invalid joint keys")
				}
			} else {
				err = fmt.Errorf("wrong type")
			}
		}
	case share.PurgeJointKeys:
		resetFedJointKeys()
	case share.MasterUnloadJointKeys:
		if param1 != nil {
			if clusterID, ok := param1.(*string); ok && clusterID != nil {
				_setFedJointPrivateKey(*clusterID, nil)
				_httpClientMutex.Lock()
				delete(_proxyOptionHistory, *clusterID)
				_httpClientMutex.Unlock()
			} else {
				err = fmt.Errorf("wrong type")
			}
		}
	case share.StartPostToIBMSA:
		if _ibmSAConfig, ok := param1.(*share.CLUSIBMSAConfig); ok && _ibmSAConfig != nil {
			log.Info("Start ibmsa poster")
			if ibmsaChan == nil {
				ibmsaChan = make(chan api.IBMSAFinding, _findingCacheSize)
			}
			if ibmsaStopChan == nil {
				ibmsaStopChan = make(chan bool)
			}
			if atomic.CompareAndSwapUint32(&postToIBMSA, 0, 1) {
				ibmsaCfg = *_ibmSAConfig
				go ibmsaPoster()
			}
		} else {
			err = fmt.Errorf("wrong type")
		}
	case share.StopPostToIBMSA:
		if atomic.CompareAndSwapUint32(&postToIBMSA, 1, 0) {
			log.Info("Stop ibmsa poster")
			if ibmsaStopChan != nil {
				ibmsaStopChan <- true
			}
		}
		ibmsaCfg = share.CLUSIBMSAConfig{}
	case share.PostToIBMSA:
		if post := atomic.LoadUint32(&postToIBMSA); post == 1 {
			if f, ok := param1.(*api.IBMSAFinding); ok && f != nil {
				if len(ibmsaChan) < _findingCacheSize {
					ibmsaChan <- *f
				} else {
					log.WithFields(log.Fields{"len": len(ibmsaChan)}).Info("ibmsa chanel full")
				}
			} else {
				err = fmt.Errorf("wrong type")
			}
		}
	case share.RestartWebhookServer:
		if param1 != nil {
			if svcName, ok := param1.(*string); ok && svcName != nil {
				go restartWebhookServer(*svcName)
			} else {
				err = fmt.Errorf("wrong type")
			}
		}
	case share.StartFedRestServer:
		_fedPollingTimer.Stop()
		startFedRestServer(interval)
	case share.StopFedRestServer:
		_fedPollingTimer.Stop()
		stopFedRestServer()
	case share.ReportTelemetryData:
		if param1 != nil && _teleNeuvectorURL != "" {
			if teleData, ok := param1.(*common.TelemetryData); ok && teleData != nil {
				go reportTelemetryData(*teleData)
			} else {
				err = fmt.Errorf("wrong type")
			}
		}
	case share.ProcessCrdQueue:
		if crdReqMgr != nil {
			crdReqMgr.crdReqProcTimer.Reset(0)
		}
	}

	return err
}

func doExport(filename, exportType string, remoteExportOptions *api.RESTRemoteExportOptions, resp interface{}, w http.ResponseWriter, r *http.Request, acc *access.AccessControl, login *loginSession) {
	var data []byte
	json_data, _ := json.MarshalIndent(resp, "", "  ")
	data, _ = yaml.JSONToYAML(json_data)

	if remoteExportOptions != nil {
		remoteExport := remote_repository.Export{
			DefaultFilePath: filename,
			Options:         remoteExportOptions,
			Content:         data,
			Cacher:          cacher,
			AccessControl:   acc,
		}
		err := remoteExport.Do()
		if err != nil {
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrRemoteExportFail, err.Error())
			log.WithFields(log.Fields{"error": err}).Error("could not do remote export")
			return
		}
		msg := fmt.Sprintf("Export %s to remote repository", exportType)
		restRespSuccess(w, r, nil, acc, login, nil, msg)
	} else {
		// tell the browser the returned content should be downloaded
		w.Header().Set("Content-Disposition", "Attachment; filename="+filename)
		w.Header().Set("Content-Encoding", "gzip")
		data = utils.GzipBytes(data)
		w.WriteHeader(http.StatusOK)
		w.Write(data)
	}
}

// api version is always the first path element
// Ex: /v1/scan/registry
//
//	^^
func getRequestApiVersion(r *http.Request) ApiVersion {
	if r.URL == nil || len(r.URL.Path) == 0 {
		return ApiVersion1
	}
	trimmedPath := strings.Trim(r.URL.Path, "/")
	splitPath := strings.Split(trimmedPath, "/")
	if splitPath[0] == "v2" {
		return ApiVersion2
	}
	return ApiVersion1
}

func IsCertNearExpired(certPath string, expireThresholdDay int) (bool, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return false, fmt.Errorf("failed to read certificate file %s: %v", certPath, err)
	}

	// Decode the PEM block
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return false, errors.New("failed to decode certificate")
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Check the expiration date
	expireThreshold := time.Duration(expireThresholdDay) * 24 * time.Hour
	if time.Now().After(cert.NotAfter.Add(-expireThreshold)) {
		log.WithFields(log.Fields{
			"expiry":             cert.NotAfter,
			"expireThresholdDay": expireThresholdDay,
		}).Debug("nearly expired certificate is detected")
		return true, nil
	}

	return false, nil
}

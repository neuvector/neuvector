package rest

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg"
	"github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg/admission"
	"github.com/neuvector/neuvector/controller/opa"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

func handlerAssessAdmCtrlRules(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if licenseAllowEnforce() == false {
		restRespError(w, http.StatusBadRequest, api.RESTErrLicenseFail)
		return
	} else if _, err := cacher.GetAdmissionState(acc); err != nil {
		restRespNotFoundLogAccessDenied(w, login, err)
		return
	}

	var defaultAction int = nvsysadmission.AdmCtrlActionAllow
	var mode string = share.AdmCtrlModeProtect
	if k8sPlatform {
		var ctrlState *share.CLUSAdmCtrlState
		state, _ := clusHelper.GetAdmissionStateRev(resource.NvAdmSvcName)
		if state != nil && state.CtrlStates != nil {
			ctrlState = state.CtrlStates[admission.NvAdmValidateType]
		}
		if ctrlState == nil {
			err := "no admission state in cluster!"
			log.Error(err)
			restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrInvalidRequest, err)
			return
		}
		_, mode, defaultAction, _, _ = cacher.IsAdmControlEnabled(&ctrlState.Uri)
	}

	var resp api.RESTAdmCtrlRulesTestResults
	var i int
	var msg string
	var whsvr WebhookServer
	var stamps api.AdmCtlTimeStamps

	body, _ := ioutil.ReadAll(r.Body)
	yamlParts := strings.Split(string(body), "\n---\n")

	// check if it's Windows format
	if len(yamlParts) == 1 && strings.Contains(string(body), "\r\n") {
		yamlParts = strings.Split(string(body), "\r\n---\r\n")
	}

	resp.PropsUnavailable = []string{share.CriteriaKeyUser, share.CriteriaKeyK8sGroups}
	resp.Results = make([]*api.RESTAdmCtrlRulesTestResult, 0, len(yamlParts))

	// first pass: put RBAC resources into OPA
	// note the format and length of this guid is important, rego code rely on this signature
	sessionGuid := fmt.Sprintf("%s_config_assessment_", utils.RandomString(5))
	opaKeys := []string{}
	for _, yamlPart := range yamlParts {
		var sb strings.Builder
		scanner := bufio.NewScanner(strings.NewReader(yamlPart))
		for scanner.Scan() {
			line := scanner.Text()
			lineTemp := strings.Trim(line, " ")
			if len(lineTemp) == 0 || lineTemp[0] == byte('#') {
				continue
			} else {
				sb.WriteString(line)
				sb.WriteString("\n")
			}
		}
		yamlPart = sb.String()
		if len(yamlPart) == 0 {
			continue
		}

		json_data, err := yaml.YAMLToJSON([]byte(yamlPart))
		if err != nil {
			msg = fmt.Sprintf("Invalid yaml: %s", err.Error())
			log.WithFields(log.Fields{"i": i}).Error(msg)
		} else {
			var tempObj admissionRequestObject
			if err := json.Unmarshal(json_data, &tempObj); err != nil {
				msg = fmt.Sprintf("Invalid yaml: %s", err.Error())
				log.WithFields(log.Fields{"i": i}).Error(msg)
			} else {
				switch tempObj.Kind {
				case K8sKindRole:
					docKey := fmt.Sprintf("/v1/data/neuvector/k8s/roles/%s%s.%s", sessionGuid, tempObj.ObjectMeta.Namespace, tempObj.ObjectMeta.Name)
					opaKeys = append(opaKeys, docKey)
					opa.AddDocument(docKey, string(json_data))
				case K8sKindClusterRole:
					docKey := fmt.Sprintf("/v1/data/neuvector/k8s/clusterroles/%s%s", sessionGuid, tempObj.ObjectMeta.Name)
					opaKeys = append(opaKeys, docKey)
					opa.AddDocument(docKey, string(json_data))
				case K8sKindRoleBinding:
					docKey := fmt.Sprintf("/v1/data/neuvector/k8s/rolebindings/%s%s.%s", sessionGuid, tempObj.ObjectMeta.Namespace, tempObj.ObjectMeta.Name)
					opaKeys = append(opaKeys, docKey)
					opa.AddDocument(docKey, string(json_data))
				case K8sKindClusterRoleBinding:
					docKey := fmt.Sprintf("/v1/data/neuvector/k8s/clusterrolebindings/%s%s", sessionGuid, tempObj.ObjectMeta.Name)
					opaKeys = append(opaKeys, docKey)
					opa.AddDocument(docKey, string(json_data))
				}
			}
		}
	}

	for _, yamlPart := range yamlParts {
		var sb strings.Builder
		scanner := bufio.NewScanner(strings.NewReader(yamlPart))
		for scanner.Scan() {
			line := scanner.Text()
			lineTemp := strings.Trim(line, " ")
			if len(lineTemp) == 0 || lineTemp[0] == byte('#') {
				continue
			} else {
				sb.WriteString(line)
				sb.WriteString("\n")
			}
		}
		yamlPart = sb.String()
		if len(yamlPart) == 0 {
			continue
		}

		var tempObj admissionRequestObject
		i++
		assessed := false
		oneResp := api.RESTAdmCtrlRulesTestResult{
			Index:   i,
			Allowed: true,
		}
		json_data, err := yaml.YAMLToJSON([]byte(yamlPart))
		if err != nil {
			msg = fmt.Sprintf("Invalid yaml: %s", err.Error())
			log.WithFields(log.Fields{"i": i}).Error(msg)
		} else {
			if err := json.Unmarshal(json_data, &tempObj); err != nil {
				msg = fmt.Sprintf("Invalid yaml: %s", err.Error())
				log.WithFields(log.Fields{"i": i}).Error(msg)
			} else {
				oneResp.Kind = tempObj.Kind
				oneResp.Name = tempObj.ObjectMeta.Name
				switch tempObj.Kind {
				case k8sKindCronJob, k8sKindDaemonSet, k8sKindDeployment, k8sKindDeploymentConfig, k8sKindJob,
					K8sKindReplicationController, k8sKindReplicaSet, K8sKindStatefulSet, k8sKindPod:
					ar := admissionv1beta1.AdmissionReview{
						Request: &admissionv1beta1.AdmissionRequest{
							Operation: admissionv1beta1.Create,
							Kind:      metav1.GroupVersionKind{Kind: tempObj.Kind},
							Namespace: tempObj.ObjectMeta.Namespace,
							Object:    runtime.RawExtension{Raw: json_data},
						},
					}
					stamps.Start = time.Now()
					if response, reqIgnored := whsvr.validate(&ar, mode, defaultAction, &stamps, true); response == nil {
						msg = "Could not get response"
					} else if reqIgnored {
						msg = "Request is ignored"
					} else {
						oneResp.Allowed = response.Allowed
						msg = response.Result.Message
						assessed = true
					}
				default:
					msg = "skip"
					log.WithFields(log.Fields{"i": i, "kind": tempObj.Kind, "name": tempObj.ObjectMeta.Name}).Debug(msg)
				}
			}
		}
		if oneResp.Allowed || !assessed {
			oneResp.Message = msg
			resp.Results = append(resp.Results, &oneResp)
		} else {
			for _, ss := range strings.Split(msg, "\n") {
				oneRuleResp := api.RESTAdmCtrlRulesTestResult{
					Index:   i,
					Kind:    tempObj.Kind,
					Name:    tempObj.ObjectMeta.Name,
					Message: ss,
				}
				resp.Results = append(resp.Results, &oneRuleResp)
			}
		}
	}

	// cleanup, delete opa keys in opaKeys
	for _, docKey := range opaKeys {
		opa.DeleteDocument(docKey)
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Test admission control rules")
}

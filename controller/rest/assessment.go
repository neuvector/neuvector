package rest

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/ghodss/yaml"
	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg"
	"github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg/admission"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
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
		_, _, defaultAction, _, _ = cacher.IsAdmControlEnabled(&ctrlState.Uri)
	}

	var resp api.RESTAdmCtrlRulesTestResults
	var i int
	var msg string
	var whsvr WebhookServer
	var stamps api.AdmCtlTimeStamps

	body, _ := ioutil.ReadAll(r.Body)
	yamlParts := strings.Split(string(body), "\n---\n")
	resp.PropsUnavailable = []string{share.CriteriaKeyUser, share.CriteriaKeyK8sGroups}
	resp.Results = make([]*api.RESTAdmCtrlRulesTestResult, 0, len(yamlParts))
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

		i++
		oneResp := api.RESTAdmCtrlRulesTestResult{
			Index:   i,
			Allowed: true,
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
					if response, reqIgnored := whsvr.validate(&ar, share.AdmCtrlModeProtect, defaultAction, &stamps, true); response == nil {
						msg = "Could not get response"
					} else if reqIgnored {
						msg = "Request is ignored"
					} else {
						oneResp.Allowed = response.Allowed
						msg = response.Result.Message
					}
				default:
					msg = "skip"
					log.WithFields(log.Fields{"i": i, "kind": tempObj.Kind, "name": tempObj.ObjectMeta.Name}).Debug(msg)
				}
			}
		}
		oneResp.Message = msg
		resp.Results = append(resp.Results, &oneResp)
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Test admission control rules")
}

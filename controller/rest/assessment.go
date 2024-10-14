package rest

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
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
	admission "github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg"
	nvsysadmission "github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg/admission"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
)

func handlerAssessAdmCtrlRules(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !licenseAllowEnforce() {
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

	body, _ := io.ReadAll(r.Body)
	body = _preprocessImportBody(body)
	yamlParts := strings.Split(string(body), "\n---\n")

	// check if it's Windows format
	if len(yamlParts) == 1 && strings.Contains(string(body), "\r\n") {
		yamlParts = strings.Split(string(body), "\r\n---\r\n")
	}

	resp.PropsUnavailable = []string{share.CriteriaKeyUser, share.CriteriaKeyK8sGroups}
	resp.GlobalMode = mode
	resp.Results = make([]*api.RESTAdmCtrlRulesTestResult, 0, len(yamlParts))

	for _, yamlPart := range yamlParts {
		var sb strings.Builder
		scanner := bufio.NewScanner(strings.NewReader(yamlPart))
		for scanner.Scan() {
			line := scanner.Text()
			lineTemp := strings.TrimSpace(line)
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
		oneResult := api.RESTAdmCtrlRulesTestResult{
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
				oneResult.Kind = tempObj.Kind
				oneResult.Name = tempObj.ObjectMeta.Name
				switch tempObj.Kind {
				case k8sKindCronJob, k8sKindDaemonSet, k8sKindDeployment, k8sKindDeploymentConfig, k8sKindJob,
					K8sKindReplicationController, k8sKindReplicaSet, K8sKindStatefulSet, k8sKindPod, k8sKindPersistentVolumeClaim:
					ar := admissionv1beta1.AdmissionReview{
						Request: &admissionv1beta1.AdmissionRequest{
							Operation: admissionv1beta1.Create,
							Kind:      metav1.GroupVersionKind{Kind: tempObj.Kind},
							Namespace: tempObj.ObjectMeta.Namespace,
							Object:    runtime.RawExtension{Raw: json_data},
						},
					}
					stamps.Start = time.Now()
					if response, assessResults, reqIgnored := whsvr.validate(&ar, mode, defaultAction, &stamps, true); response == nil {
						msg = "Could not get response"
					} else if reqIgnored {
						msg = "Request is ignored"
					} else {
						oneResult.Allowed = response.Allowed
						msg = response.Result.Message
						matchedRules := make([]*api.RESTAdmCtrlTestRuleInfo, 0, len(assessResults))
						for _, assessResult := range assessResults {
							matchedRule := &api.RESTAdmCtrlTestRuleInfo{
								ContainerImage: assessResult.ContainerImage,
								ID:             assessResult.RuleID,
								Disabled:       assessResult.Disabled,
								Mode:           assessResult.RuleMode,
								RuleDetails:    assessResult.RuleDetails,
							}
							if assessResult.IsDenyRuleType {
								matchedRule.Type = api.ValidatingDenyRuleType
							} else {
								matchedRule.Type = api.ValidatingAllowRuleType
							}
							matchedRule.RuleCfgType = cfgTypeMap2Api[assessResult.RuleCfgType]
							matchedRules = append(matchedRules, matchedRule)
						}
						oneResult.MatchedRules = matchedRules
					}
				default:
					msg = "This resource kind is not assessed by Admission Control"
					log.WithFields(log.Fields{"i": i, "kind": tempObj.Kind, "name": tempObj.ObjectMeta.Name}).Debug(msg)
				}
			}
		}
		oneResult.Message = msg
		resp.Results = append(resp.Results, &oneResult)
	}

	restRespSuccess(w, r, &resp, acc, login, nil, "Test admission control rules")
}

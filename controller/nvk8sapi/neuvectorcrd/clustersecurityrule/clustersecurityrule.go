package nvclustersecurityrule

/*
// see controller/nvk8sapi/neuvectorcrd/crd.go
import (
	log "github.com/sirupsen/logrus"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/controller/rest"
	"github.com/neuvector/neuvector/share"
	"strings"
	"time"
)

const clusterLockWait = time.Duration(time.Second * 10)

func ResumeNvSecurityHandler(leader bool, op, admClientMode string, ctrlState *share.CLUSAdmCtrlState) (bool, error) {
	if leader {
		rest.CrossCheckCrd(resource.NvClusterSecurityRuleKind, false)
	}
	k8sResInfo := admission.ValidatingWebhookConfigInfo{
		Name: resource.NvCrdValidatingName,
		WebhooksInfo: []*admission.WebhookInfo{
			&admission.WebhookInfo{
				Name: resource.NvCrdValidatingWebhookName,
				ClientConfig: admission.ClientConfig{
					ClientMode:  admClientMode,
					ServiceName: resource.NvCrdSvcName,
					Path:        ctrlState.Uri,
				},
				FailurePolicy:  resource.Ignore,
				TimeoutSeconds: resource.DefTimeoutSeconds,
			},
		},
	}
	skip, err := admission.ConfigK8sAdmissionControl(k8sResInfo, ctrlState)
	return skip, err

}

func ConfigNvSecurityHandler(op, admClientMode string, ctrlState *share.CLUSAdmCtrlState) (bool, error) {
	clusHelper := kv.GetClusterHelper()
	lock, err := clusHelper.AcquireLock(share.CLUSLockPolicyKey, clusterLockWait)
	if err != nil {
		return true, err
	}
	defer clusHelper.ReleaseLock(lock)

	gwrecordlist := clusHelper.GetCrdSecurityRuleRecordList(resource.NvSecurityRuleKind)
	for name, gw := range gwrecordlist {
		tokens := strings.Split(name, "-")
		if tokens[0] != resource.RscTypeCrdClusterSecurityRule {
			continue
		}
		rest.CrdDeleteRules(gw.Rules)
		rest.CrdHandleGroupRecordDel(gw, gw.Groups, false)
		rest.CrdDeleteRecordEx(name, gw.ProfileName)
		rest.CrdDeleteAdmCtrlRules(gw.AdmCtrlRules)
	}

	if op == admission.K8sResOpDelete {
		err := admission.UnregK8sAdmissionControl(admission.NvAdmValidateType, resource.NvCrdValidatingName)
		if err == nil {
			log.WithFields(log.Fields{"name": resource.NvCrdValidatingName, "op": op, "enable": ctrlState.Enable}).
				Info("Configured fwrule control in k8s")
			return false, nil
		}
		return true, err
	} else {
		k8sResInfo := admission.ValidatingWebhookConfigInfo{
			Name: resource.NvCrdValidatingName,
			WebhooksInfo: []*admission.WebhookInfo{
				&admission.WebhookInfo{
					Name: resource.NvCrdValidatingWebhookName,
					ClientConfig: admission.ClientConfig{
						ClientMode:  admClientMode,
						ServiceName: resource.NvCrdSvcName,
						Path:        ctrlState.Uri,
					},
					FailurePolicy:  resource.Ignore,
					TimeoutSeconds: resource.DefTimeoutSeconds,
				},
			},
		}
		skip, err := admission.ConfigK8sAdmissionControl(k8sResInfo, ctrlState)
		return skip, err
	}
}
*/

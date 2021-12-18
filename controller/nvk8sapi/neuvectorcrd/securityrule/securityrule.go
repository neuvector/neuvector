package nvsecurityrule

// see controller/nvk8sapi/neuvectorcrd/crd.go
/*
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

func ResumeNvSecurityHandler(leader bool, op, admClientMode, k8sKind string, ctrlState *share.CLUSAdmCtrlState) (bool, error) {
	if leader {
		rest.CrossCheckCrd(k8sKind, false)
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

func ConfigNvSecurityHandler(op, admClientMode, rscType string, ctrlState *share.CLUSAdmCtrlState) (bool, error) {
	var keyLock string
	if rscType == resource.NvAdmCtrlRuleKind || rscType == resource.NvAdmCtrlConfigKind {
		keyLock = share.CLUSLockAdmCtrlKey
	} else {
		keyLock = share.CLUSLockPolicyKey
	}
	clusHelper := kv.GetClusterHelper()
	lock, err := clusHelper.AcquireLock(keyLock, clusterLockWait)
	if err != nil {
		return true, err
	}
	defer clusHelper.ReleaseLock(lock)

	gwrecordlist := clusHelper.GetCrdSecurityRuleRecordList(resource.NvSecurityRuleKind)
	for name, gw := range gwrecordlist {
		tokens := strings.Split(name, "-")
		if tokens[0] != rscType {
			continue
		}
		if rscType == resource.NvAdmCtrlRuleKind {
			rest.CrdDeleteAdmCtrlRules(gw.AdmCtrlRules)
			rest.CrdDeleteRecord(name)
		} else if rscType == resource.NvSecurityRuleKind || rscType == resource.NvClusterSecurityRuleKind {
			rest.CrdDeleteRules(gw.Rules)
			rest.CrdHandleGroupRecordDel(gw, gw.Groups, false)
			rest.CrdDeleteRecordEx(name, gw.ProfileName)
		}
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

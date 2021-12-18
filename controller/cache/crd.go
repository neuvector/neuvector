package cache

import (
	"encoding/json"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/global"
)

var crdStateCache share.CLUSAdmissionState

func crdInit() {
	if localDev.Host.Platform == share.PlatformKubernetes {
		var svcAvailable bool
		if _, err := global.ORCH.GetResource(resource.RscTypeService, resource.NvAdmSvcNamespace, resource.NvCrdSvcName); err == nil {
			svcAvailable = true
		}
		setAdmCtrlStateInCluster(admission.NvAdmValidateType, resource.NvCrdSvcName, true, &svcAvailable)
		initStateCache(resource.NvCrdSvcName, &crdStateCache)
	}
}

func crdConfigUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	log.Debug("")

	cfgType := share.CLUSPolicyKey2AdmCfgSubkey(key)

	switch nType {
	case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
		switch cfgType {
		case share.CLUSAdmissionCfgState:
			var state share.CLUSAdmissionState
			json.Unmarshal(value, &state)
			sameUri := true
			for admType, ctrlState := range state.CtrlStates {
				switch admType {
				case admission.NvAdmValidateType:
					if cacheCtrlState, _ := crdStateCache.CtrlStates[admType]; cacheCtrlState != nil {
						if cacheCtrlState.Uri != ctrlState.Uri {
							sameUri = false
							cacheCtrlState.Uri = ctrlState.Uri
							var param interface{} = &resource.NvCrdSvcName
							cctx.StartStopFedPingPollFunc(share.RestartWebhookServer, 0, param)
						}
					}
				}
			}
			crdStateCache.AdmClientMode = state.AdmClientMode
			if isLeader() && !sameUri {
				if ctrlState := state.CtrlStates[admission.NvAdmValidateType]; ctrlState != nil {
					if !ctrlState.Enable {
						setAdmCtrlStateInCluster(admission.NvAdmValidateType, resource.NvCrdSvcName, true, nil)
					}
					ctrlState.Enable = true
					k8sResInfo := admission.ValidatingWebhookConfigInfo{
						Name: resource.NvCrdValidatingName,
						WebhooksInfo: []*admission.WebhookInfo{
							&admission.WebhookInfo{
								Name: resource.NvCrdValidatingWebhookName,
								ClientConfig: admission.ClientConfig{
									ClientMode:  state.AdmClientMode,
									ServiceName: resource.NvCrdSvcName,
									Path:        ctrlState.Uri,
								},
								FailurePolicy:  resource.Ignore,
								TimeoutSeconds: resource.DefTimeoutSeconds,
							},
						},
					}
					admission.ConfigK8sAdmissionControl(k8sResInfo, ctrlState)
				}
			}
		}
	}
}

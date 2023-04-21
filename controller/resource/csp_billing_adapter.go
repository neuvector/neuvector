package resource

import (
	"encoding/json"
	"fmt"
	"time"

	corev1 "github.com/neuvector/k8s/apis/core/v1"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share/global"
)

type tCspConfig struct {
	Timestamp          string   `json:"timestamp"`
	BillingApiAccessOk bool     `json:"billing_api_access_ok"`
	Expire             string   `json:"expire"`
	Errors             []string `json:"errors"`
	LastBilled         string   `json:"last_billed"`
	XXX_unrecognized   []byte   `json:"-"`
}

func GetCspConfig() api.RESTFedCspSupportResp {
	var err error
	var tExpire time.Time
	var resp api.RESTFedCspSupportResp

	var obj interface{}
	now := time.Now()
	if obj, err = global.ORCH.GetResource(RscTypeConfigMap, NvAdmSvcNamespace, "csp-config"); err == nil {
		if cm, ok := obj.(*corev1.ConfigMap); cm == nil || !ok {
			err = fmt.Errorf("Error: Unknown type")
		} else {
			err = fmt.Errorf("No billing data")
			if cm.Data != nil {
				if value, ok := cm.Data["data"]; ok {
					resp.CspConfigData = value
					var cspConfig tCspConfig
					if err = json.Unmarshal([]byte(value), &cspConfig); err == nil {
						resp.ExpireTime = cspConfig.Expire
						resp.CspErrors = cspConfig.Errors
						resp.CspConfigFrom = "local cluster"
						if tExpire, err = time.Parse(time.RFC3339, resp.ExpireTime); err == nil {
							if cspConfig.BillingApiAccessOk && tExpire.After(now) {
								resp.Compliant = true
							}
						}
					}
				}
			}
		}
	}
	if err != nil {
		resp.NvError = err.Error()
		log.WithFields(log.Fields{"compliant": resp.Compliant, "nvError": resp.NvError, "cspErrors": resp.CspErrors}).Error()
	}

	return resp
}

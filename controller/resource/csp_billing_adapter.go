package resource

import (
	"encoding/json"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share/global"
)

type tCustomerCspData struct {
	AccountID        string `json:"account_id"`
	Arch             string `json:"arch"`
	CloudProvider    string `json:"cloud_provider"`
	XXX_unrecognized []byte `json:"-"`
}

type tCspConfig struct {
	Timestamp          string            `json:"timestamp"`
	BillingApiAccessOk bool              `json:"billing_api_access_ok"`
	Expire             string            `json:"expire"`
	Errors             []string          `json:"errors"`
	LastBilled         string            `json:"last_billed"`
	Usage              map[string]int    `json:"usage"`
	CustomerCspData    tCustomerCspData  `json:"customer_csp_data"`
	BaseProduct        string            `json:"base_product"`
	Versions           map[string]string `json:"versions"`
	XXX_unrecognized   []byte            `json:"-"`
}

func GetCspConfig() api.RESTFedCspSupportResp {
	var err error
	var dataExpiredErr error
	var tExpire time.Time
	var resp api.RESTFedCspSupportResp

	var obj interface{}
	now := time.Now()
	if obj, err = global.ORCH.GetResource(RscTypeConfigMap, NvAdmSvcNamespace, "csp-config"); err == nil {
		if cm, ok := obj.(*corev1.ConfigMap); cm == nil || !ok {
			log.WithFields(log.Fields{"err": "Error: Unknown type"}).Error()
		} else {
			// err = fmt.Errorf("No billing data")
			if cm.Data != nil {
				if value, ok := cm.Data["data"]; ok {
					resp.CspConfigData = value
					var cspConfig tCspConfig
					if err = json.Unmarshal([]byte(value), &cspConfig); err == nil {
						if json_data, e := json.Marshal(cspConfig.Versions); e == nil {
							resp.AdapterVersions = string(json_data)
						}
						resp.CspErrors = cspConfig.Errors
						resp.CspConfigFrom = "local cluster"
						if tExpire, err = time.Parse("2006-01-02T15:04:05.000000-07:00", cspConfig.Expire); err == nil {
							if tExpire.Before(now) {
								resp.ExpireTime = tExpire.Unix()
							}
							if cspConfig.BillingApiAccessOk && tExpire.After(now) {
								resp.Compliant = true
							} else {
								dataExpiredErr = fmt.Errorf("Billing data expired on %s", cspConfig.Expire)
							}
						}
					} else {
						log.WithFields(log.Fields{"err": err}).Error()
					}
				}
			}
		}
	}

	if obj, err = global.ORCH.GetResource(RscTypeConfigMap, NvAdmSvcNamespace, "metering-archive"); err == nil {
		if cm, ok := obj.(*corev1.ConfigMap); cm == nil || !ok {
			err = fmt.Errorf("Error: Unknown type")
		} else if cm.Data != nil {
			resp.MeteringArchiveData = cm.Data["archive"]
		}
	}

	if err != nil || len(resp.CspErrors) > 0 {
		if err != nil {
			resp.NvError = err.Error()
		}
		log.WithFields(log.Fields{"compliant": resp.Compliant, "nvError": resp.NvError, "expire": dataExpiredErr, "cspErrors": resp.CspErrors}).Error()
	}

	return resp
}

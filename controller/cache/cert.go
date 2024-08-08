package cache

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	admission "github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
)

func certObjectUpdate(nType cluster.ClusterNotifyType, key string, value []byte) {
	log.Debug("")

	cn := share.CLUSKeyNthToken(key, 2)

	type keyCertFileInfo struct {
		svcName    string
		keyPath    string
		certPath   string
		k8sEnvOnly bool
	}

	cnAdm := fmt.Sprintf("%s.%s.svc", resource.NvAdmSvcName, resource.NvAdmSvcNamespace)
	cnCrd := fmt.Sprintf("%s.%s.svc", resource.NvCrdSvcName, resource.NvAdmSvcNamespace)
	admKeyPath, admCertPath := resource.GetTlsKeyCertPath(resource.NvAdmSvcName, resource.NvAdmSvcNamespace)
	crdKeyPath, crdCertPath := resource.GetTlsKeyCertPath(resource.NvCrdSvcName, resource.NvAdmSvcNamespace)
	pathInfoMap := map[string]*keyCertFileInfo{
		share.CLUSRootCAKey: &keyCertFileInfo{share.CLUSRootCAKey, kv.AdmCAKeyPath, kv.AdmCACertPath, false},
		cnAdm:               &keyCertFileInfo{resource.NvAdmSvcName, admKeyPath, admCertPath, true},
		cnCrd:               &keyCertFileInfo{resource.NvCrdSvcName, crdKeyPath, crdCertPath, true},
	}

	certmanagerCerts := map[string]bool{
		share.CLUSJWTKey:  true,
		share.CLUSTLSCert: true,
	}

	if pathInfo, ok := pathInfoMap[cn]; !ok {
		if _, ok := certmanagerCerts[cn]; ok {
			if cctx.NotifyCertChange != nil {
				cctx.NotifyCertChange(cn)
			}
		} else {
			log.WithFields(log.Fields{"cn": cn}).Debug("unsupported")
		}
	} else if pathInfo.k8sEnvOnly && localDev.Host.Platform != share.PlatformKubernetes {
		// do nothing if it's webhook cert key change on non-k8s env
	} else {
		switch nType {
		case cluster.ClusterNotifyAdd, cluster.ClusterNotifyModify:
			var cert share.CLUSX509Cert
			var dec common.DecryptUnmarshaller
			dec.Unmarshal(value, &cert)

			if len(cert.Key) > 0 && len(cert.Cert) > 0 {
				if err := os.WriteFile(pathInfo.keyPath, []byte(cert.Key), 0600); err == nil {
					certData := []byte(cert.Cert)
					b := md5.Sum(certData)
					log.WithFields(log.Fields{"svcName": pathInfo.svcName, "cert": hex.EncodeToString(b[:])}).Info("md5")
					if err = os.WriteFile(pathInfo.certPath, certData, 0600); err == nil {
						if localDev.Host.Platform == share.PlatformKubernetes && pathInfo.svcName != share.CLUSRootCAKey {
							// return value of ResetCABundle() tells us whether remembered cert is different from new cert
							if admission.ResetCABundle(pathInfo.svcName, certData) {
								// remembered cert is updated with new cert. in rest.restartWebhookServer() it will re-register the webhook resource to k8s
								var param interface{} = &pathInfo.svcName
								cctx.StartStopFedPingPollFunc(share.RestartWebhookServer, 0, param)
							}
						}
					}
				}
			}
		}
	}
}

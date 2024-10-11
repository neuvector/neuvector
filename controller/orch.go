package main

import (
	"encoding/json"
	"sync"

	"github.com/neuvector/k8s"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/controller/rest"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/global"
	log "github.com/sirupsen/logrus"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextv1b1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
)

type orchConnInterface interface {
	LeadChangeNotify(leader bool)
	Start(ocRegImage bool, cspType share.TCspType)
	Stop()
	Close()
}

type orchConn struct {
	objChan  chan *resource.Event
	scanChan chan *resource.Event
	leader   bool
}

var OrchConnStatus string
var OrchConnLastError string

var connStatusLock sync.RWMutex

func GetOrchConnStatus() (string, string) {
	connStatusLock.RLock()
	defer connStatusLock.RUnlock()

	return OrchConnStatus, OrchConnLastError
}

func (c *orchConn) cbWatcherState(state string, err error) {
	var lastError string
	if err != nil {
		lastError = err.Error()
	}

	connStatusLock.Lock()
	defer connStatusLock.Unlock()
	if state != OrchConnStatus || lastError != OrchConnLastError {
		log.WithFields(log.Fields{
			"status":    state,
			"lastError": lastError,
		}).Info("updating conn status")

		OrchConnStatus = state
		OrchConnLastError = lastError
		value, err := json.Marshal(share.CLUSController{
			CLUSDevice:        Ctrler.CLUSDevice,
			Leader:            Ctrler.Leader,
			OrchConnStatus:    OrchConnStatus,
			OrchConnLastError: OrchConnLastError,
			ReadPrimeConfig:   Ctrler.ReadPrimeConfig,
		})

		if err != nil {
			log.WithError(err).Error("failed to marshal cluster structure in cbWatcherState()")
			return
		}

		key := share.CLUSControllerKey(Host.ID, Ctrler.ID)
		if err := cluster.Put(key, value); err != nil {
			log.WithFields(log.Fields{"error": err}).Error()
		}
	}
}

func (c *orchConn) cbResourceWatcher(rt string, event string, res interface{}, old interface{}) {

	switch rt {
	case resource.RscTypeRBAC:
		k8sResLog.WithFields(log.Fields{"event": event, "type": rt, "object": res}).Debug("Event received")
		var rbac *resource.RBAC
		if old != nil {
			rbac = old.(*resource.RBAC)
		} else {
			rbac = res.(*resource.RBAC)
		}
		rest.KickLoginSessionsForRoleChange(rbac.Name, rbac.Domain)
	case resource.RscTypeImage:
		k8sResLog.WithFields(log.Fields{"event": event, "type": rt, "object": res}).Debug("Event received")
		if event == resource.WatchEventDelete {
			// Force new resource to nil to indicate the deletion
			ev := resource.Event{ResourceType: rt, Event: event, ResourceOld: old, ResourceNew: nil}
			c.scanChan <- &ev
		} else {
			ev := resource.Event{ResourceType: rt, Event: event, ResourceOld: old, ResourceNew: res}
			c.scanChan <- &ev
		}
	case resource.RscTypeCrd:

		if event == resource.WatchEventDelete {
			k8sResLog.WithFields(log.Fields{"event": event, "type": rt, "object": res, "old object": old}).Debug("Event received")
			nvCrdInfo := map[string]*resource.NvCrdInfo{
				resource.NvSecurityRuleName: {
					LockKey:   share.CLUSLockPolicyKey,
					KvCrdKind: resource.NvSecurityRuleKind,
				},
				resource.NvClusterSecurityRuleName: {
					LockKey:   share.CLUSLockPolicyKey,
					KvCrdKind: resource.NvSecurityRuleKind,
				},
				resource.NvAdmCtrlSecurityRuleName: {
					LockKey:   share.CLUSLockAdmCtrlKey,
					KvCrdKind: resource.NvAdmCtrlSecurityRuleKind,
				},
				resource.NvDlpSecurityRuleName: {
					LockKey:   share.CLUSLockPolicyKey,
					KvCrdKind: resource.NvDlpSecurityRuleKind,
				},
				resource.NvWafSecurityRuleName: {
					LockKey:   share.CLUSLockPolicyKey,
					KvCrdKind: resource.NvWafSecurityRuleKind,
				},
				resource.NvVulnProfileSecurityRuleName: {
					LockKey:   share.CLUSLockVulnKey,
					KvCrdKind: resource.NvVulnProfileSecurityRuleKind,
				},
				resource.NvCompProfileSecurityRuleName: {
					LockKey:   share.CLUSLockCompKey,
					KvCrdKind: resource.NvCompProfileSecurityRuleKind,
				},
			}
			var name string
			var kind string
			if event == resource.WatchEventDelete {
				if crd, ok := res.(*apiextv1b1.CustomResourceDefinition); ok {
					name = crd.Name
					kind = crd.Spec.Names.Kind
				} else if crd, ok := res.(*apiextv1.CustomResourceDefinition); ok {
					name = crd.Name
					kind = crd.Spec.Names.Kind
				}
				if crdInfo, ok := nvCrdInfo[name]; ok {
					k8sResLog.WithFields(log.Fields{"crd event": event, "type": rt, "name": name}).Debug("Event done")
					rest.CrdDelAll(kind, crdInfo.KvCrdKind, crdInfo.LockKey)
				}
			}
		}
	default:
		k8sResLog.WithFields(log.Fields{"event": event, "type": rt, "object": res}).Debug("Event received")
		if event == resource.WatchEventDelete {
			// Force new resource to nil to indicate the deletion
			ev := resource.Event{ResourceType: rt, Event: event, ResourceOld: old, ResourceNew: nil}
			c.objChan <- &ev
		} else {
			ev := resource.Event{ResourceType: rt, Event: event, ResourceOld: old, ResourceNew: res}
			c.objChan <- &ev
		}
	}

	k8sResLog.WithFields(log.Fields{"event": event, "type": rt}).Debug("Event done")
}

func (c *orchConn) Start(ocImageRegistered bool, cspType share.TCspType) {
	var r string

	// Make sure register resource first, otherwise it may trigger a race condition in k8s client library
	// between Watch()
	if !ocImageRegistered {
		r = resource.RscTypeImage
		if err := global.ORCH.RegisterResource(r); err == nil {
			// Use ImageStream as an indication of OpenShift
			Host.Flavor = share.FlavorOpenShift
			ocImageRegistered = true
		}
	}

	r = resource.RscTypeNode
	if err := global.ORCH.StartWatchResource(r, k8s.AllNamespaces, c.cbResourceWatcher, c.cbWatcherState); err != nil {
		if err != resource.ErrMethodNotSupported {
			c.cbWatcherState(resource.ConnStateDisconnected, err)
		}
	}

	r = resource.RscTypeNamespace
	if err := global.ORCH.StartWatchResource(r, k8s.AllNamespaces, c.cbResourceWatcher, c.cbWatcherState); err != nil {
		if err != resource.ErrMethodNotSupported {
			c.cbWatcherState(resource.ConnStateDisconnected, err)
		}
	}

	rscTypes := []string{resource.RscTypeCrd, resource.RscTypeService, resource.RscTypePod, resource.RscTypeRBAC,
		resource.RscTypeValidatingWebhookConfiguration, resource.RscTypePersistentVolumeClaim}
	for _, r := range rscTypes {
		global.ORCH.StartWatchResource(r, k8s.AllNamespaces, c.cbResourceWatcher, nil)
	}
	global.ORCH.StartWatchResource(resource.RscTypeDeployment, Ctrler.Domain, c.cbResourceWatcher, nil)

	rscTypes = []string{
		resource.RscTypeCrdSecurityRule,
		resource.RscTypeCrdClusterSecurityRule,
		resource.RscTypeCrdAdmCtrlSecurityRule,
		resource.RscTypeCrdDlpSecurityRule,
		resource.RscTypeCrdWafSecurityRule,
		resource.RscTypeCrdVulnProfile,
		resource.RscTypeCrdCompProfile,
	}
	for _, r := range rscTypes {
		global.ORCH.RegisterResource(r)
	}

	if cspType != share.CSP_NONE {
		global.ORCH.RegisterResource(resource.RscTypeCrdNvCspUsage)
	}

	if ocImageRegistered {
		r = resource.RscTypeImage
		global.ORCH.StartWatchResource(r, k8s.AllNamespaces, c.cbResourceWatcher, c.cbWatcherState)
	}
}

func (c *orchConn) LeadChangeNotify(isLeader bool) {
	c.leader = isLeader
}

func (c *orchConn) Stop() {
	global.ORCH.StopWatchAllResources()
	c.cbWatcherState(resource.ConnStateNone, nil)
}

func (c *orchConn) Close() {
	global.ORCH.StopWatchAllResources()
}

func newOrchConnector(orchObjChan, orchScanChan chan *resource.Event, leader bool) orchConnInterface {
	return &orchConn{
		objChan:  orchObjChan,
		scanChan: orchScanChan,
		leader:   leader,
	}
}

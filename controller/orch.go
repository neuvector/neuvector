package main

import (
	"encoding/json"

	apiextv1 "github.com/neuvector/k8s/apis/apiextensions/v1"
	apiextv1b1 "github.com/neuvector/k8s/apis/apiextensions/v1beta1"
	log "github.com/sirupsen/logrus"
	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/controller/rest"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/global"
)

type orchConnInterface interface {
	LeadChangeNotify(leader bool)
	Start()
	Stop()
	Close()
}

type orchConn struct {
	objChan  chan *resource.Event
	scanChan chan *resource.Event
	leader   bool
}

func (c *orchConn) cbWatcherState(state string, err error) {
	var lastError string
	if err != nil {
		lastError = err.Error()
	}

	// FIXME: both lead change and here modify Ctrler and write to the cluster, should we lock?
	if state != Ctrler.OrchConnStatus || lastError != Ctrler.OrchConnLastError {
		Ctrler.OrchConnStatus = state
		Ctrler.OrchConnLastError = lastError
		value, _ := json.Marshal(Ctrler)
		key := share.CLUSControllerKey(Host.ID, Ctrler.ID)
		if err := cluster.Put(key, value); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("")
		}
	}
}

func (c *orchConn) cbResourceWatcher(rt string, event string, res interface{}, old interface{}) {

	switch rt {
	case resource.RscTypeRBAC:
		log.WithFields(log.Fields{"event": event, "type": rt, "object": res}).Debug("Event received")
		var rbac *resource.RBAC
		if old != nil {
			rbac = old.(*resource.RBAC)
		} else {
			rbac = res.(*resource.RBAC)
		}
		rest.KickLoginSessionsForRoleChange(rbac.Name, rbac.Domain)
	case resource.RscTypeImage:
		log.WithFields(log.Fields{"event": event, "type": rt, "object": res}).Debug("Event received")
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
			log.WithFields(log.Fields{"xsun event": event, "xsun type": rt, "xsun object": res, "xsun old object": old}).Debug("Event received")
			nvCrdInfo := map[string]*resource.NvCrdInfo{
				resource.NvSecurityRuleName: &resource.NvCrdInfo{
					LockKey:   share.CLUSLockPolicyKey,
					KvCrdKind: resource.NvSecurityRuleKind,
				},
				resource.NvClusterSecurityRuleName: &resource.NvCrdInfo{
					LockKey:   share.CLUSLockPolicyKey,
					KvCrdKind: resource.NvSecurityRuleKind,
				},
				resource.NvAdmCtrlSecurityRuleName: &resource.NvCrdInfo{
					LockKey:   share.CLUSLockAdmCtrlKey,
					KvCrdKind: resource.NvAdmCtrlSecurityRuleKind,
				},
				resource.NvWafSecurityRuleName: &resource.NvCrdInfo{
					LockKey:   share.CLUSLockPolicyKey,
					KvCrdKind: resource.NvWafSecurityRuleKind,
				},
			}
			if crd, ok := res.(*apiextv1b1.CustomResourceDefinition); ok {
				if crdInfo, ok := nvCrdInfo[*crd.Metadata.Name]; ok {
					if event == resource.WatchEventDelete {
						log.WithFields(log.Fields{"crd event": event, "type": rt, "name": crd.Metadata.Name}).Debug("Event done")
						rest.CrdDelAll(*crd.Spec.Names.Kind, crdInfo.KvCrdKind, crdInfo.LockKey, nil)
					}
				}
			} else if crd, ok := res.(*apiextv1.CustomResourceDefinition); ok {
				if crdInfo, ok := nvCrdInfo[*crd.Metadata.Name]; ok {
					if event == resource.WatchEventDelete {
						log.WithFields(log.Fields{"crd event": event, "type": rt, "name": crd.Metadata.Name}).Debug("Event done")
						rest.CrdDelAll(*crd.Spec.Names.Kind, crdInfo.KvCrdKind, crdInfo.LockKey, nil)
					}
				}
			}
		}
	default:
		log.WithFields(log.Fields{"event": event, "type": rt, "object": res}).Debug("Event received")
		if event == resource.WatchEventDelete {
			// Force new resource to nil to indicate the deletion
			ev := resource.Event{ResourceType: rt, Event: event, ResourceOld: old, ResourceNew: nil}
			c.objChan <- &ev
		} else {
			ev := resource.Event{ResourceType: rt, Event: event, ResourceOld: old, ResourceNew: res}
			c.objChan <- &ev
		}
	}

	log.WithFields(log.Fields{"event": event, "type": rt}).Debug("Event done")
}

func (c *orchConn) Start() {
	var r string
	var regImage bool

	// Make sure register resource first, otherwise it may trigger a race condition in k8s client library
	// between Watch()
	r = resource.RscTypeImage
	if err := global.ORCH.RegisterResource(r); err == nil {
		// Use ImageStream as an indication of OpenShift
		Host.Flavor = share.FlavorOpenShift
		regImage = true
	} else {
		log.WithFields(log.Fields{"watch": r, "error": err}).Error("Fail to register image watch")
	}

	r = resource.RscTypeNode
	if err := global.ORCH.StartWatchResource(r, c.cbResourceWatcher, c.cbWatcherState); err != nil {
		log.WithFields(log.Fields{"watch": r, "error": err}).Error("")

		if err != resource.ErrMethodNotSupported {
			c.cbWatcherState(resource.ConnStateDisconnected, err)
		}
	}

	r = resource.RscTypeNamespace
	if err := global.ORCH.StartWatchResource(r, c.cbResourceWatcher, c.cbWatcherState); err != nil {
		log.WithFields(log.Fields{"watch": r, "error": err}).Error("")

		if err != resource.ErrMethodNotSupported {
			c.cbWatcherState(resource.ConnStateDisconnected, err)
		}
	}

	rscTypes := make([]string, 0, 5)
	rscTypes = append(rscTypes, resource.RscTypeCrd, resource.RscTypeService, resource.RscTypePod, resource.RscTypeRBAC)
	if Host.Platform == share.PlatformKubernetes {
		rscTypes = append(rscTypes, resource.RscTypeValidatingWebhookConfiguration)
	}
	for _, r := range rscTypes {
		if err := global.ORCH.StartWatchResource(r, c.cbResourceWatcher, nil); err != nil {
			log.WithFields(log.Fields{"watch": r, "error": err}).Error()
		}
	}

	rscTypes = []string{
		resource.RscTypeCrdSecurityRule,
		resource.RscTypeCrdClusterSecurityRule,
		resource.RscTypeCrdAdmCtrlSecurityRule,
		resource.RscTypeCrdWafSecurityRule,
	}
	for _, r := range rscTypes {
		if err := global.ORCH.RegisterResource(r); err != nil {
			log.WithFields(log.Fields{"watch": r, "error": err}).Error("Fail to register")
		}
	}

    if regImage {
		r = resource.RscTypeImage
		if err := global.ORCH.StartWatchResource(r, c.cbResourceWatcher, c.cbWatcherState); err != nil {
			log.WithFields(log.Fields{"watch": r, "error": err}).Error("")
		}
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

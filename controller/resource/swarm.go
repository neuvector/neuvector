package resource

import (
	"errors"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share/container"
	"github.com/neuvector/neuvector/share/global"
	orchAPI "github.com/neuvector/neuvector/share/orchestration"
)

type swarmWatcher struct {
	cb orchAPI.WatchCallback
}

type swarm struct {
	*noop

	lock     sync.RWMutex
	watchers map[string]*swarmWatcher
}

func newSwarmDriver(platform, flavor, network string) *swarm {
	d := &swarm{
		noop:     newNoopDriver(platform, flavor, network),
		watchers: make(map[string]*swarmWatcher),
	}
	return d
}

func (d *swarm) xlateService(svc *container.Service) (*Service, error) {
	if len(svc.VIPs) > 0 {
		r := &Service{
			UID:         svc.ID,
			Name:        svc.Name,
			Labels:      svc.Labels,
			IPs:         svc.VIPs,
			ExternalIPs: make([]net.IP, 0),
		}
		return r, nil
	} else {
		return nil, errors.New("No virtual IP")
	}
}

func (d *swarm) cpEventCallback(rtev container.Event, id string, pid int) {
	log.WithFields(log.Fields{"event": rtev, "id": id}).Debug()
	switch rtev {
	case container.EventServiceCreate, container.EventServiceUpdate:
		if svc, err := global.RT.GetService(id); err != nil {
			log.WithFields(log.Fields{"id": id, "error": err}).Error("Failed to inspect service")
		} else if res, err := d.xlateService(svc); err == nil {
			if ev, old := d.updateResourceCache(RscTypeService, id, res); ev != "" {
				d.lock.Lock()
				w, ok := d.watchers[RscTypeService]
				d.lock.Unlock()
				if ok {
					w.cb(RscTypeService, ev, res, old)
				}
			}
		}
	case container.EventServiceDelete:
		if ev, old := d.deleteResourceCache(RscTypeService, id); ev != "" {
			d.lock.Lock()
			w, ok := d.watchers[RscTypeService]
			d.lock.Unlock()
			if ok {
				w.cb(RscTypeService, ev, nil, old)
			}
		}
	}
}

func (d *swarm) StartWatchResource(rt, ns string, wcb orchAPI.WatchCallback, scb orchAPI.StateCallback) error {
	log.WithFields(log.Fields{"resource": rt}).Debug()

	if rt != RscTypeService {
		return ErrResourceNotSupported
	}

	d.lock.Lock()
	d.watchers[rt] = &swarmWatcher{cb: wcb}
	d.lock.Unlock()

	if svcs, err := global.RT.ListServices(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to list services")
	} else {
		for _, svc := range svcs {
			if res, err := d.xlateService(svc); err == nil {
				if ev, old := d.updateResourceCache(RscTypeService, svc.ID, res); ev != "" {
					wcb(RscTypeService, ev, res, old)
				}
			}
		}
	}
	go func() {
		if err := global.RT.MonitorEvent(d.cpEventCallback, true); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("monitor event")
		}
	}()
	return nil
}

func (d *swarm) StopWatchResource(rt string) error {
	if rt != RscTypeService {
		return ErrResourceNotSupported
	}

	global.RT.StopMonitorEvent()
	return nil
}

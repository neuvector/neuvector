package cache

import (
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share/utils"
)

const (
	EV_WORKLOAD_ADD = iota
	EV_WORKLOAD_START
	EV_WORKLOAD_STOP
	EV_WORKLOAD_DELETE
	EV_WORKLOAD_QUARANTINE
	EV_HOST_ADD
	EV_HOST_DELETE
	EV_AGENT_ADD
	EV_AGENT_ONLINE
	EV_AGENT_OFFLINE
	EV_AGENT_DELETE
	EV_CONTROLLER_ADD
	EV_CONTROLLER_DELETE
	EV_GROUP_ADD
	EV_GROUP_DELETE
	EV_LICENSE_UPDATE
	EV_WORKLOAD_AGENT_CHANGE
)

type eventHandlerFunc func(id string, param interface{})
type eventHandlers map[int][]eventHandlerFunc

func (evhs eventHandlers) Register(ev int, handlers []eventHandlerFunc) {
	evhs[ev] = handlers
}

func (evhs eventHandlers) Trigger(ev int, id string, param interface{}) {
	if handlers, ok := evhs[ev]; ok {
		for _, handler := range handlers {
			log.WithFields(log.Fields{
				"handler": utils.GetFunctionName(handler), "id": id,
			}).Debug("")

			handler(id, param)
		}
	}
}

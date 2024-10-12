package probe

import (
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share/container"
	"github.com/neuvector/neuvector/share/utils"
)

var intfMonitorPollTimeoutLong = syscall.Timeval{Sec: 5, Usec: 0}
var intfMonitorPollTimeoutShort = syscall.Timeval{Sec: 0, Usec: 500000}

type intfMonitorInterface interface {
	WaitAddrChange(*syscall.Timeval) (bool, error)
	WaitHostAddrChange(*syscall.Timeval) (bool, error) // obsolete
	Close()
}

func (p *Probe) intfMonitorLoop(id string, m intfMonitorInterface, timeout time.Duration, stopCh chan struct{}) {
	toNotify := false
	pollTimeout := intfMonitorPollTimeoutLong
	expire := time.After(timeout)

	for {
		select {
		case <-stopCh:
			log.WithFields(log.Fields{"id": container.ShortContainerId(id)}).Debug("Stopped")
			m.Close()
			return
		case <-expire:
			log.WithFields(log.Fields{"id": container.ShortContainerId(id)}).Debug("Timeout")
			m.Close()
			p.intfMonMux.Lock()
			delete(p.intfMonMap, id)
			p.intfMonMux.Unlock()
			return
		default:
			// Aggregate addr/route change notification.
			changed, err := m.WaitAddrChange(&pollTimeout)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Debug("Receive error")
			} else if changed {
				toNotify = true
				pollTimeout = intfMonitorPollTimeoutShort
			} else if toNotify {
				log.WithFields(log.Fields{"id": container.ShortContainerId(id)}).Debug("Notify addr or route changed")
				toNotify = false
				msg := ProbeMessage{Type: PROBE_CONTAINER_NEW_IP, ContainerIDs: utils.NewSet(id)}
				p.notifyTaskChan <- &msg
				pollTimeout = intfMonitorPollTimeoutLong
			} else {
				pollTimeout = intfMonitorPollTimeoutLong
			}
		}
	}
}

func (p *Probe) StartMonitorInterface(id string, pid int, timeout time.Duration) {
	log.WithFields(log.Fields{"id": container.ShortContainerId(id)}).Debug("")

	m := p.openIntfMonitor(pid)
	if m == nil {
		log.WithFields(log.Fields{"id": container.ShortContainerId(id)}).Debug("start fail")
		return
	}

	stopCh := make(chan struct{})
	p.intfMonMux.Lock()
	p.intfMonMap[id] = stopCh
	p.intfMonMux.Unlock()

	go p.intfMonitorLoop(id, m, timeout, stopCh)
}

func (p *Probe) StopMonitorInterface(id string) {
	log.WithFields(log.Fields{"id": container.ShortContainerId(id)}).Debug("")

	p.intfMonMux.Lock()
	ch, ok := p.intfMonMap[id]
	if ok {
		delete(p.intfMonMap, id)
	}
	p.intfMonMux.Unlock()
	if ok {
		close(ch)
	}
}

// obsolete
func (p *Probe) intfHostMonitorLoop(hid string, m intfMonitorInterface, stopCh chan struct{}) {
	toNotify := false
	pollTimeout := intfMonitorPollTimeoutLong

	for {
		select {
		case <-stopCh:
			log.WithFields(log.Fields{"hostid": hid}).Debug("Monitor host i/f Stopped")
			m.Close()
			return
		default:
			// Aggregate addr/route change notification.
			changed, err := m.WaitHostAddrChange(&pollTimeout)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Debug("Receive error")
			} else if changed {
				toNotify = true
				pollTimeout = intfMonitorPollTimeoutShort
			} else if toNotify {
				log.WithFields(log.Fields{"hostid": hid}).Debug("Notify host addr changes")
				toNotify = false
				msg := ProbeMessage{Type: PROBE_HOST_NEW_IP}
				p.notifyTaskChan <- &msg
				pollTimeout = intfMonitorPollTimeoutLong
			} else {
				pollTimeout = intfMonitorPollTimeoutLong
			}
		}
	}
}

// obsolete
func (p *Probe) StartMonitorHostInterface(hid string, pid int) {
	log.WithFields(log.Fields{"hostid": hid}).Debug("")

	m := p.openIntfMonitor(pid)
	if m == nil {
		log.WithFields(log.Fields{"hostid": hid}).Debug("start monitor host i/f fail")
		return
	}

	stopCh := make(chan struct{})
	p.intfMonMux.Lock()
	p.intfMonMap[hid] = stopCh
	p.intfMonMux.Unlock()

	go p.intfHostMonitorLoop(hid, m, stopCh)
}

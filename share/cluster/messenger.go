package cluster

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

const CLUSUnicastStore string = "unicast/"
const CLUSUniackStore string = "uniack/"

type CLUSUnicast struct {
	Expect string `json:"expect"`
	Data   []byte `json:"data"`
}

type MessengerInterface interface {
	Unicast(target string, subject string, data []byte,
		cb UnicastCallback, timeout int, args ...interface{}) error
	UnicastStore(target string) string
	UnicastKey2Subject(key string) string
	UniackStore() string
	UniackUpdateHandler(nType ClusterNotifyType, key string, value []byte, unused uint64)
}

type unicastReceiver struct {
	ch chan []byte
}

type msgrMethod struct {
	msgIndex             uint32
	hostID               string
	devID                string
	unicastReceiverMap   map[string]*unicastReceiver
	unicastReceiverMutex sync.Mutex
}

type UnicastCallback func(string, []byte, ...interface{})

var msgr *msgrMethod

func NewMessenger(hostID string, devID string) MessengerInterface {
	msgr = &msgrMethod{
		msgIndex:           0,
		hostID:             hostID,
		devID:              devID,
		unicastReceiverMap: make(map[string]*unicastReceiver),
	}
	return msgr
}

func (msgr *msgrMethod) unicastRegisterReceiver(expect string, receiver *unicastReceiver) {
	msgr.unicastReceiverMutex.Lock()
	defer msgr.unicastReceiverMutex.Unlock()

	msgr.unicastReceiverMap[expect] = receiver
}

func (msgr *msgrMethod) unicastRemoveReceiver(expect string) {
	_ = Delete(expect)

	msgr.unicastReceiverMutex.Lock()
	defer msgr.unicastReceiverMutex.Unlock()

	delete(msgr.unicastReceiverMap, expect)
}

func (msgr *msgrMethod) unicastNotifyReceiver(expect string, value []byte) {
	var notfound bool

	msgr.unicastReceiverMutex.Lock()
	if r, ok := msgr.unicastReceiverMap[expect]; ok {
		if len(r.ch) == 0 {
			// The receiver channel can only receive one msg
			// Check the length of the channel to avoid being blocked accidently
			// This was hit once but not sure why
			r.ch <- value
		} else {
			log.WithFields(log.Fields{"expect": expect}).Error("The channel is not empty!")
		}
	} else {
		// This could happen if response comes back too late. Clean it up.
		notfound = true
	}
	msgr.unicastReceiverMutex.Unlock()

	if notfound {
		_ = Delete(expect)
	}
}

func (msgr *msgrMethod) UnicastStore(target string) string {
	return fmt.Sprintf("%s%s/", CLUSUnicastStore, target)
}

func (msgr *msgrMethod) UnicastKey2Subject(key string) string {
	tokens := strings.Split(key, "/")
	if len(tokens) > 3 {
		return strings.Join(tokens[3:], "/")
	} else {
		return ""
	}
}

func (msgr *msgrMethod) unicastKey(target string, subject string) string {
	return fmt.Sprintf("%s%s:%d/%s", msgr.UnicastStore(target), msgr.hostID, msgr.msgIndex, subject)
}

func (msgr *msgrMethod) UniackStore() string {
	return fmt.Sprintf("%s%s/", CLUSUniackStore, msgr.devID)
}

func (msgr *msgrMethod) uniackKey(subject string) string {
	return fmt.Sprintf("%s%s:%d/%s", msgr.UniackStore(), msgr.hostID, msgr.msgIndex, subject)
}

func (msgr *msgrMethod) UniackUpdateHandler(nType ClusterNotifyType, key string, value []byte, unused uint64) {
	if nType != ClusterNotifyDelete {
		log.WithFields(log.Fields{"key": key}).Debug("UniackUpdateHandler")

		msgr.unicastNotifyReceiver(key, value)
	}
}

// Unicast messages are of this format
// From controller: unicast/<device_uuid>/<host_docker_id>:index/<subject>
//                  uniconf/<device_uuid>/<subject>
// From agent:      uniack/<device_uuid>/<host_docker_id>:index/<subject>
//
// Expected uniack key is carried in the unicast request. The agent should use it to
// answer the request and the controller is waiting on that.
//
// The portion of "<host_docker_id>:index" is the message ID which should be globally unique.
//
// The agent should delete the unicast KV pair after handling the request; the controller
// should delete the uniack KV pair after the answer if received.

func (msgr *msgrMethod) unicast(subject, key string, data []byte, cb UnicastCallback,
	expect string, timeout int, delKey bool, args ...interface{}) error {
	var ch chan []byte

	if cb != nil {
		// When request times out, if response comes before the receiver is removed,
		// writing to the channel will hang if the channel size is 0.
		ch = make(chan []byte, 1)
		msgr.unicastRegisterReceiver(expect, &unicastReceiver{ch: ch})
	}

	msg := CLUSUnicast{Expect: expect, Data: data}
	value, _ := json.Marshal(msg)

	if err := Put(key, value); err != nil {
		if cb != nil {
			msgr.unicastRemoveReceiver(expect)
			cb(subject, nil, args...)
		}
		return err
	}

	if cb != nil {
		select {
		case body := <-ch:
			msgr.unicastRemoveReceiver(expect)
			cb(subject, body, args...)
		case <-time.After(time.Second * time.Duration(timeout)):
			msgr.unicastRemoveReceiver(expect)
			cb(subject, nil, args...)
		}
	}

	if delKey {
		_ = Delete(key)
	}

	return nil
}

func (msgr *msgrMethod) Unicast(target string, subject string, data []byte,
	cb UnicastCallback, timeout int, args ...interface{}) error {
	atomic.AddUint32(&msgr.msgIndex, 1)

	log.WithFields(log.Fields{
		"target": target, "index": msgr.msgIndex, "subject": subject,
	}).Debug("Unicast")

	key := msgr.unicastKey(target, subject)
	expect := msgr.uniackKey(subject)

	return msgr.unicast(subject, key, data, cb, expect, timeout, true, args...)
}

/*
func (msgr *msgrMethod) Uniconf(target string, subject string, data []byte) error {
	log.WithFields(log.Fields{"target": target, "subject": subject}).Debug("Uniconf")

	key := msgr.UniconfKey(target, subject)
	return Put(key, data)
}

func (msgr *msgrMethod) Getconf(target string, subject string) ([]byte, error) {
	var msg CLUSUnicast

	log.WithFields(log.Fields{"target": target, "subject": subject}).Debug("Getconf")

	key := msgr.UniconfKey(target, subject)
	value, err := Get(key)
	if err != nil {
		return nil, err
	}

	json.Unmarshal(value, &msg)

	return msg.Data, nil
}
*/

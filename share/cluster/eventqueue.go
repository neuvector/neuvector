package cluster

import (
	"encoding/json"
	"errors"
	"sync"

	"github.com/neuvector/neuvector/share/utils"
)

var ErrQueueFull = errors.New("Queue full")

type ObjectQueueInterface interface {
	Append(obj interface{}) error
	Flush() error
}

type objectQueue struct {
	lock    sync.RWMutex
	key     string
	queue   []interface{}
	maxQLen int
}

const DefaultMaxQLen = 4096

func NewObjectQueue(key string, maxQLen int) ObjectQueueInterface {
	q := &objectQueue{key: key, queue: nil, maxQLen: maxQLen}
	return q
}

func (q *objectQueue) Append(obj interface{}) error {
	q.lock.Lock()
	defer q.lock.Unlock()
	if len(q.queue) < q.maxQLen {
		q.queue = append(q.queue, obj)
		return nil
	} else {
		return ErrQueueFull
	}
}

func (q *objectQueue) Flush() error {
	q.lock.Lock()
	defer q.lock.Unlock()
	if len(q.queue) > 0 {
		value, _ := json.Marshal(q.queue)
		zb := utils.GzipBytes(value)
		if err := PutBinary(q.key, zb); err != nil {
			return err
		}

		q.queue = nil
	}

	return nil
}

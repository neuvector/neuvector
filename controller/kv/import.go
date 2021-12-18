package kv

import (
	"sync/atomic"
)

var importing uint32

func SetImporting(value uint32) {
	atomic.StoreUint32(&importing, value)
}

func IsImporting() bool {
	var ret bool
	if paused := atomic.LoadUint32(&importing); paused > 0 {
		ret = true
	}

	return ret
}

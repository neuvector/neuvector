package ringbuffer

import (
	"testing"
	//	log "github.com/sirupsen/logrus"
)

func TestRingBuffer_empty(t *testing.T) {
	r := New(8)

	history := r.DumpExt()
	// log.WithFields(log.Fields{"len": len(history)}).Info("empty")
	if len(history) != 0 {
		t.Errorf("Error length[%d]: %d\n", 0, len(history))
	}
}

func TestRingBuffer_in_range(t *testing.T) {
	r := New(8)
	for i := 0; i < 3; i++ {
		r.Write(i)
	}

	history := r.DumpExt()
	// log.WithFields(log.Fields{"len": len(history)}).Info("in range")
	if len(history) != 3 {
		t.Errorf("Error length[%d]: %d\n", 3, len(history))
	}

	for i, item := range history {
		//log.WithFields(log.Fields{"i": i, "item": item}).Info()
		if item != i {
			t.Errorf("Error[%d]: [%v,%v]\n", i, i, item)
		}
	}
}

func TestRingBuffer_wrap_around(t *testing.T) {
	r := New(8)
	for i := 0; i < 128; i++ {
		r.Write(i)
	}

	history := r.DumpExt()
	// log.WithFields(log.Fields{"len": len(history)}).Info("wrap around")
	if len(history) != 8 {
		t.Errorf("Error length[%d]: %d\n", 3, len(history))
	}

	for i, item := range history {
		// log.WithFields(log.Fields{"i": i, "item": item}).Info()
		if item != (i + 120) {
			t.Errorf("Error[%d]: [%v,%v]\n", i, i+120, item)
		}
	}
}

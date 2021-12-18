package utils

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
)

var profiling int32

func PerfProfile(req *share.CLUSProfilingRequest, prefix string) {
	log.WithFields(log.Fields{"methods": req.Methods}).Debug()

	if !atomic.CompareAndSwapInt32(&profiling, 0, 1) {
		log.Debug("Profiling is running. Exit!")
		return
	}

	defer atomic.StoreInt32(&profiling, 0)

	if _, err := os.Stat(share.ProfileFolder); os.IsNotExist(err) {
		if err = os.MkdirAll(share.ProfileFolder, 0775); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to create profile folder")
			return
		}
	}

	for _, m := range req.Methods {
		switch m {
		case share.ProfilingMethod_Memory:
			log.Debug("profiling memory")
			if f, err := os.Create(fmt.Sprintf(share.ProfileMemoryFileFmt, prefix)); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Failed to create memory profiling file")
			} else {
				pprof.WriteHeapProfile(f)
				f.Close()
			}

			if f, err := os.Create(fmt.Sprintf(share.ProfileMemoryFileFmt, prefix + "gc.")); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Failed to create memory profiling gc file")
			} else {
				runtime.GC()    // get up-to-date statistics
				pprof.WriteHeapProfile(f)
				f.Close()
			}
		case share.ProfilingMethod_CPU:
			log.Debug("profiling cpu/goroutine")
			if f, err := os.Create(fmt.Sprintf(share.ProfileCPUFileFmt, prefix)); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Failed to create cpu profiling file")
			} else {
				pprof.StartCPUProfile(f)
				time.Sleep(time.Second * time.Duration(req.Duration))
				pprof.StopCPUProfile()
				f.Close()
			}
			if f, err := os.Create(fmt.Sprintf(share.ProfileGoroutineFileFmt, prefix)); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Failed to create goroutine profiling file")
			} else {
				pprof.Lookup("goroutine").WriteTo(f, 0)
				f.Close()
			}
		}
	}

	log.Debug("Profiling is done.")
}

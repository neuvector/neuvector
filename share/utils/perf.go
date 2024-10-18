package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/codeskyblue/go-sh"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
)

var profiling int32

func PerfProfile(req *share.CLUSProfilingRequest, folder, prefix string) {
	log.WithFields(log.Fields{"methods": req.Methods}).Debug()

	if !atomic.CompareAndSwapInt32(&profiling, 0, 1) {
		log.Debug("Profiling is running. Exit!")
		return
	}

	defer atomic.StoreInt32(&profiling, 0)

	if _, err := os.Stat(folder); os.IsNotExist(err) {
		if err = os.MkdirAll(folder, 0775); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to create profile folder")
			return
		}
	}

	var filename string
	for _, m := range req.Methods {
		switch m {
		case share.ProfilingMethod_Memory:
			log.Debug("profiling memory")
			filename = filepath.Join(folder, fmt.Sprintf(share.ProfileMemoryFileFmt, prefix))
			if f, err := os.Create(filename); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Failed to create memory profiling file")
			} else {
				if err := pprof.WriteHeapProfile(f); err != nil {
					log.WithFields(log.Fields{"err": err}).Error("Failed to write memory profiling file")
				}
				f.Close()
			}
		case share.ProfilingMethod_CPU:
			log.Debug("profiling cpu/goroutine")
			filename = filepath.Join(folder, fmt.Sprintf(share.ProfileCPUFileFmt, prefix))
			if f, err := os.Create(filename); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Failed to create cpu profiling file")
			} else {
				if err := pprof.StartCPUProfile(f); err != nil {
					log.WithFields(log.Fields{"err": err}).Error("Failed to start cpu profiling")
				} else {
					time.Sleep(time.Second * time.Duration(req.Duration))
					pprof.StopCPUProfile()
				}
				f.Close()
			}

			filename = filepath.Join(folder, fmt.Sprintf(share.ProfileGoroutineFileFmt, prefix))
			if f, err := os.Create(filename); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Failed to create goroutine profiling file")
			} else {
				if err := pprof.Lookup("goroutine").WriteTo(f, 0); err != nil {
					log.WithFields(log.Fields{"err": err}).Error("Failed to write goroutine profiling file")
				}
				f.Close()
			}
		}
	}

	log.Debug("Profiling is done.")
}

// //////////////////////////////////////////////////////////
var lastSnapshot time.Time

const snapshotWindow = time.Duration(time.Minute * 5)

func PerfSnapshot(pid int, memLimit, profileLimit, usage uint64, folder, cid, prefix, label string) {
	type snapshotData struct {
		RecordedAt        time.Time
		MemoryLimit       uint64
		WorkingMemory     uint64
		MemPercentage     int
		ProfileLimit      uint64
		ProfilePercentage int
		Cid               string
		Lsof              []string
		Ps                []string
	}

	if time.Since(lastSnapshot) < snapshotWindow {
		log.Debug("skip")
		return
	}

	lastSnapshot = time.Now()
	go func() {
		workFolder := filepath.Join(folder, cid) // add cid to avoid the collision in the PV
		log.WithFields(log.Fields{"pid": pid, "memLimit": memLimit, "profileLimit": profileLimit, "workingSet": usage, "workFolder": workFolder, "prefix": prefix, "label": label, "at": lastSnapshot}).Info()
		mem_percentage := -1
		if memLimit > 0 {
			mem_percentage = (int)(usage * 100 / memLimit)
		}

		var pLimit uint64
		var profile_percentage int
		if profileLimit <= 1 { // sync with the memLimit
			pLimit = profileLimit
			profile_percentage = mem_percentage
		} else {
			pLimit = profileLimit * 1024 * 1024
			profile_percentage = (int)(usage * 100 / pLimit)
		}

		// get auxiliary data
		lsof, _ := sh.Command("lsof", "+D", "/usr/local/bin").Output()
		ps, _ := sh.Command("ps", "-o", "%cpu,pid,ppid,pgid,vsz,rss,ni,comm", "-g", strconv.Itoa(pid)).Output()
		data := snapshotData{
			RecordedAt:        lastSnapshot,
			MemoryLimit:       memLimit,
			WorkingMemory:     usage,
			MemPercentage:     mem_percentage,
			ProfileLimit:      pLimit,
			ProfilePercentage: profile_percentage,
			Cid:               cid,
			Lsof:              strings.Split(string(lsof), "\n"),
			Ps:                strings.Split(string(ps), "\n"),
		}
		file, _ := json.MarshalIndent(data, "", " ")

		// get golang profiles
		req := &share.CLUSProfilingRequest{
			Methods:  []share.ProfilingMethod{share.ProfilingMethod_CPU, share.ProfilingMethod_Memory},
			Duration: 10, // seconds
		}

		PerfProfile(req, workFolder, prefix)

		// deferred action because PerfProfile will create the tmp_folder
		path := filepath.Join(workFolder, "data.json")
		if err := os.WriteFile(path, file, 0644); err != nil {
			log.WithFields(log.Fields{"err": err, "path": path, "len": len(file)}).Error()
		}

		//  write the .tar.gzip
		targetZipFile := filepath.Join(folder, fmt.Sprintf("%ssnapshot.%s.%s.zip", prefix, cid, label))
		if err := CompressToZipFile(workFolder, targetZipFile); err == nil {
			os.RemoveAll(workFolder)
			log.WithFields(log.Fields{"package": targetZipFile}).Info()
		}
		log.Info("done")
	}()
}

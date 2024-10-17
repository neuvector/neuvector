package system

// #include  <sys/eventfd.h>
import "C"
import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

const neuvectorContainer = "/usr/local/bin/.nvcontainer"
const (
	from_cgroup = iota
	from_fscgroup
	from_hostname
)
const (
	cgroup_v1 = 1
	cgroup_v2 = 2
)

var errUnsupported = errors.New("not supported")

// from github.com\opencontainers\runc\libcontainer\cgroups\stats.go
type MemoryData struct {
	Usage    uint64 `json:"usage,omitempty"`
	MaxUsage uint64 `json:"max_usage,omitempty"`
	Failcnt  uint64 `json:"failcnt"`
	Limit    uint64 `json:"limit"`
}

type CgroupMemoryStats struct {
	// memory used reference by "kubectl top"
	WorkingSet uint64 `json:"working_set,omitempty"`
	// memory used for cache
	Cache uint64 `json:"cache,omitempty"`
	// usage of memory
	Usage MemoryData `json:"usage,omitempty"`
	// usage of memory + swap
	SwapUsage MemoryData `json:"swap_usage,omitempty"`
	// usage of kernel memory
	KernelUsage MemoryData `json:"kernel_usage,omitempty"`
	// usage of kernel TCP memory
	KernelTCPUsage MemoryData `json:"kernel_tcp_usage,omitempty"`
	// if true, memory usage is accounted for throughout a hierarchy of cgroups.
	UseHierarchy bool `json:"use_hierarchy"`

	Stats map[string]uint64 `json:"stats,omitempty"`
}

// CPU
type ThrottlingData struct {
	// Number of periods with throttling active
	Periods uint64 `json:"periods,omitempty"`
	// Number of periods when the container hit its throttling limit.
	ThrottledPeriods uint64 `json:"throttled_periods,omitempty"`
	// Aggregate time the container was throttled for in nanoseconds.
	ThrottledTime uint64 `json:"throttled_time,omitempty"`
}

type CpuUsage struct {
	// Total CPU time consumed.
	// Units: nanoseconds.
	TotalUsage uint64 `json:"total_usage,omitempty"`
	// Total CPU time consumed per core.
	// Units: nanoseconds.
	PercpuUsage []uint64 `json:"percpu_usage,omitempty"`
	// CPU time consumed per core in kernel mode
	// Units: nanoseconds.
	PercpuUsageInKernelmode []uint64 `json:"percpu_usage_in_kernelmode"`
	// CPU time consumed per core in user mode
	// Units: nanoseconds.
	PercpuUsageInUsermode []uint64 `json:"percpu_usage_in_usermode"`
	// Time spent by tasks of the cgroup in kernel mode.
	// Units: nanoseconds.
	UsageInKernelmode uint64 `json:"usage_in_kernelmode"`
	// Time spent by tasks of the cgroup in user mode.
	// Units: nanoseconds.
	UsageInUsermode uint64 `json:"usage_in_usermode"`
}

type CpuStats struct {
	CpuUsage       CpuUsage       `json:"cpu_usage,omitempty"`
	ThrottlingData ThrottlingData `json:"throttling_data,omitempty"`
}

type MemoryPressureReport struct {
	// pressure level
	Level uint64 `json:"level"`
	// memory stats
	Stats CgroupMemoryStats `json:"stats"`
}

type MemoryPressureCallback func(report *MemoryPressureReport)

func (s *SystemTools) IsRunningInContainer() bool {
	// A hidden file to indicate we are in container
	_, err := os.Stat(neuvectorContainer)
	return err == nil

	// If we look at /proc/1/cgroup, in the host, lines end by /; in container, it has name of the anchor point.
	// However, this approach is not reliable if the container is sharing pid namespace with the host !!!
}

// With containerd runtime, container ID can be any string. But when it is used
// in kubernetes, the format is same as the docker.
func isContainerID(id string) bool {
	if len(id) != 64 {
		return false
	}
	if _, err := hex.DecodeString(id); err != nil {
		return false
	}

	return true
}

// Return container ID and if cgroup file exist
func (s *SystemTools) GetContainerIDByPID(pid int) (string, bool, error, bool) {
	return s.getContainerIDByCgroup(filepath.Join(s.procDir, strconv.Itoa(pid)))
}

// Reture container ID, if it's container in container and error message
func (s *SystemTools) GetSelfContainerID() (string, bool, error) {
	id, containerInContainer, err, _ := s.getContainerIDByCgroup("/proc/self")
	return id, containerInContainer, err
}

func (s *SystemTools) getContainerIDByCgroup(path string) (string, bool, error, bool) {
	f, err := os.Open(filepath.Join(path, "cgroup"))
	if err != nil {
		return "", false, err, false
	}
	defer f.Close()

	if s.cgroupVersion == cgroup_v2 {
		id, containerInContainer, found := getContainerIDByCgroupReaderV2(f, from_cgroup)
		if !found {
			f2, err := os.Open(filepath.Join(path, "mountinfo"))
			if err != nil {
				return "", false, err, false
			}
			defer f2.Close()
			id, containerInContainer, _ = getContainerIDByCgroupReaderV2(f2, from_hostname)
		}
		return id, containerInContainer, nil, true
	}

	// v1
	id, containerInContainer, _, bFlushed := getContainerIDByCgroupReader(f)
	if id != "" {
		return id, containerInContainer, nil, bFlushed
	}

	// last resort for k8s: it will return the pod ID
	if f2, err := os.Open(filepath.Join(path, "mountinfo")); err == nil {
		defer f2.Close()
		id, containerInContainer, _ = getContainerIDByCgroupReaderV2(f2, from_hostname)
		return id, containerInContainer, nil, true
	}
	return "", false, nil, false
}

// Return container ID, container-in-container, and error
func getContainerIDByCgroupReader(file io.ReadSeeker) (string, bool, error, bool) {
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "docker") {
			tokens := strings.Split(line, "/")
			if len(tokens) == 3 {
				switch tokens[1] {
				case "docker":
					return tokens[2], false, nil, true
				case "system.slice":
					size := len(tokens[2])
					if tokens[2][:7] == "docker-" && tokens[2][size-6:] == ".scope" {
						return tokens[2][7 : size-6], false, nil, true
					}
				}
			} else if len(tokens) == 5 {
				if tokens[3] == "docker" {
					if tokens[1] == "docker" {
						return tokens[4], true, nil, true
					} else {
						return tokens[4], false, nil, true
					}
				}
			}
		}
	}

	// Pick the last token. See test cases for examples.
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", false, fmt.Errorf("Unable to rewind file"), false
	}

	scanner = bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "memory") {
			tokens := strings.Split(line, "/")
			if n := len(tokens); n >= 2 {
				token := tokens[n-1]
				if dash := strings.LastIndex(token, "-"); dash >= 0 {
					token = token[dash+1:]
				}
				if dot := strings.LastIndex(token, "."); dot >= 0 {
					token = token[:dot]
				}
				if colon := strings.LastIndex(token, ":"); colon >= 0 {
					token = token[colon+1:]
				}
				if isContainerID(token) {
					return token, false, nil, true
				}

				// 2nd chance
				// seek 2nd to the last token
				token = tokens[n-2]
				if isContainerID(token) {
					return token, true, nil, true
				}
			}
		}
	}
	return "", false, nil, true
}

// Return container ID, container-in-container ??, and error
func getContainerIDByCgroupReaderV2(file io.ReadSeeker, choice int) (string, bool, bool) {
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		switch choice {
		case from_cgroup:
			elements := strings.Split(line, ":")
			if len(elements) > 2 {
				// log.WithFields(log.Fields{"path": elements[2]}).Debug()
				tokens := strings.Split(elements[2], "/")
				for i := len(tokens) - 1; i > 0; i-- { // the last item is most possible target
					token := tokens[i]
					//token = strings.TrimPrefix(token, "docker-") // TODO: other runtimes
					//token = strings.TrimPrefix(token, "crio-")
					//token = strings.TrimPrefix(token, "cri-containerd-")
					if index := strings.LastIndex(token, "-"); index != -1 {
						token = token[index+1:]
					}
					token = strings.TrimSuffix(token, ".scope")
					if isContainerID(token) {
						return token, false, true
					}
				}
			}
		case from_fscgroup: // optional: not available from self-probe
			if strings.Contains(line, "/sys/fs/cgroup") {
				fstab := strings.Fields(line)
				if len(fstab) > 3 {
					// log.WithFields(log.Fields{"fstab": fstab[3]}).Debug()
					tokens := strings.Split(fstab[3], "/")
					for i := len(tokens) - 1; i > 0; i-- {
						token := tokens[i]
						if index := strings.LastIndex(token, "-"); index != -1 {
							token = token[index+1:]
						}
						token = strings.TrimSuffix(token, ".scope")
						if isContainerID(token) {
							return token, false, true
						}
					}
				}
			}
		case from_hostname: // alternate ID (the container ID of the POD) for nv containers (self probe)
			if strings.Contains(line, "/etc/hostname") {
				// log.WithFields(log.Fields{"field": fstab[3]}).Debug()
				fstab := strings.Fields(line)
				if len(fstab) > 3 { //
					tokens := strings.Split(fstab[3], "/")
					for i := len(tokens) - 1; i >= 0; i-- {
						token := tokens[i]
						if isContainerID(token) {
							return token, false, true
						}
					}
				}
			}
		}
	}

	return "", false, false
}

func getCgroupPathReaderV2(file io.ReadSeeker) string {
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		tokens := strings.Split(scanner.Text(), ":")
		if len(tokens) > 2 {
			// log.WithFields(log.Fields{"cpath": tokens[2]}).Debug()
			// For k8s, we're looking for kubepods
			// example: "0::/kubepods/besteffort/podad1189b4-15b6-4ee5-b509-084defdd5c70/f459165f653a853823b2807f22e5b21c4214ff1d89e71790ca28da9b38695ea1"
			// For systemd based OS, we're looking for system.slice and we're in cgroup v2
			// https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/resource_management_guide/sec-default_cgroup_hierarchies
			// system.slice/docker-53a44c2a8e2bef215199d4c37cc391e1e7caa654f9fb0ac4af29ac9610bbb3f2.scope
			// https://docs.fedoraproject.org/en-US/quick-docs/understanding-and-administering-systemd/
			if strings.HasPrefix(tokens[2], "/kubepods") || strings.HasPrefix(tokens[2], "/system.slice") {
				return filepath.Join("/sys/fs/cgroup", tokens[2])
			}
		}
	}
	return ""
}

// cgroup v2 is collected inside an unified file folder
func getCgroupPath_cgroup_v2(pid int) (string, error) {
	var path string
	if pid == 0 { // self
		path = "/proc/self/cgroup"
	} else {
		path = filepath.Join("/proc", strconv.Itoa(pid), "cgroup")
	}

	f, err := os.Open(path)
	if err != nil {
		log.WithFields(log.Fields{"path": path, "err": err}).Warning("cgroup cannot be read, stats cannot be found")
		return "", err
	}
	defer f.Close()

	cpath := getCgroupPathReaderV2(f)

	return cpath, nil

}

// verifyContainerCgroupPath - Checks if a cgroup path for a subsystem is valid
// We only support checking "memory" and "cpuacct" cgroup subsystems.
func (s *SystemTools) verifyContainerCgroupPath(path string, subsystem string) error {
	switch subsystem {
	case "memory":
		if _, err := s.GetContainerMemoryUsage(path); err != nil {
			return err
		}
	case "cpuacct":
		if _, err := s.GetContainerCPUUsage(path); err != nil {
			return err
		}
	default:
		// For everything else, just check if the directory/file exists
		if _, err := os.Stat(path); err != nil {
			return err
		}
	}

	return nil
}

func (s *SystemTools) GetContainerCgroupPath(pid int, subsystem string) (string, error) {
	switch s.cgroupVersion {
	case cgroup_v1:
		var path string
		// It is a well-known path: /proc/<pid>/root/sys/fs/cgroup/<subsystem>
		if pid == 0 {
			path = filepath.Join("/sys/fs/cgroup", subsystem)
		} else {
			path = filepath.Join(s.procDir, strconv.Itoa(pid), "root/sys/fs/cgroup", subsystem)
		}
		if err := s.verifyContainerCgroupPath(path, subsystem); err != nil {
			log.WithFields(log.Fields{
				"path": path, "cgroup": s.cgroupVersion, "subsystem": subsystem, "err": err,
			}).Warning("Unable to get cgroup path")
			return "", err
		} else {
			return path, nil
		}

	case cgroup_v2:
		// unified file structure
		path, err := getCgroupPath_cgroup_v2(pid)
		if err != nil || path == "" {
			// path wasn't parsed, so we'll default to v1 style for best effort
			if pid == 0 {
				path = filepath.Join("/sys/fs/cgroup")
			} else {
				path = filepath.Join(s.procDir, strconv.Itoa(pid), "root/sys/fs/cgroup")
			}
		}
		if err := s.verifyContainerCgroupPath(path, subsystem); err != nil {
			log.WithFields(log.Fields{
				"path": path, "cgroup": s.cgroupVersion, "subsystem": subsystem, "err": err,
			}).Warning("Unable to get cgroup path")
			return "", err
		} else {
			return path, nil
		}

	default:
		log.WithFields(log.Fields{"cgroup": s.cgroupVersion, "subsystem": subsystem}).Warning("Unable to get cgroup path")
		return "", fmt.Errorf("Unable to find subsystem in container cgroup file")
	}
}

// Copied from: github.com/opencontainers/runc/libcontainer/cgroups/fs/utils.go

// Saturates negative values at zero and returns a uint64.
// Due to kernel bugs, some of the memory cgroup stats can be negative.
func parseUint(s string, base, bitSize int) (uint64, error) {
	value, err := strconv.ParseUint(s, base, bitSize)
	if err != nil {
		intValue, intErr := strconv.ParseInt(s, base, bitSize)
		// 1. Handle negative values greater than MinInt64 (and)
		// 2. Handle negative values lesser than MinInt64
		if intErr == nil && intValue < 0 {
			return 0, nil
		} else if intErr != nil && intErr.(*strconv.NumError).Err == strconv.ErrRange && intValue < 0 {
			return 0, nil
		}

		return value, err
	}

	return value, nil
}

// Parses a cgroup param and returns as name, value
//
//	i.e. "io_service_bytes 1234" will return as io_service_bytes, 1234
func getCgroupParamKeyValue(t string) (string, uint64, error) {
	parts := strings.Fields(t)
	switch len(parts) {
	case 2:
		value, err := parseUint(parts[1], 10, 64)
		if err != nil {
			return "", 0, fmt.Errorf("Unable to convert value (%q) to uint64: %v", parts[1], err)
		}

		return parts[0], value, nil
	default:
		return "", 0, fmt.Errorf("Invalid format: %v", t)
	}
}

// Gets a single uint64 value from the specified cgroup file.
func getCgroupParamUint(cgroupPath, cgroupFile string) (uint64, error) {
	fileName := filepath.Join(cgroupPath, cgroupFile)
	contents, err := os.ReadFile(fileName)
	if err != nil {
		return 0, err
	}

	valueStr := strings.TrimSpace(string(contents))
	if valueStr == "max" || valueStr == "-1" { // cgroup v2
		return 0, nil
	}

	res, err := parseUint(valueStr, 10, 64)
	if err != nil {
		return res, fmt.Errorf("Unable to parse %q as a uint from Cgroup file %q", string(contents), fileName)
	}
	return res, nil
}

// //
func getMemoryData(path, name string) (MemoryData, error) {
	memoryData := MemoryData{}

	moduleName := "memory"
	if name != "" {
		moduleName = strings.Join([]string{"memory", name}, ".")
	}

	usage := strings.Join([]string{moduleName, "usage_in_bytes"}, ".")
	maxUsage := strings.Join([]string{moduleName, "max_usage_in_bytes"}, ".")
	failcnt := strings.Join([]string{moduleName, "failcnt"}, ".")
	limit := strings.Join([]string{moduleName, "limit_in_bytes"}, ".")

	value, err := getCgroupParamUint(path, usage)
	if err != nil {
		if moduleName != "memory" && os.IsNotExist(err) {
			return MemoryData{}, nil
		}
		return MemoryData{}, fmt.Errorf("failed to parse %s - %v", usage, err)
	}
	memoryData.Usage = value
	value, err = getCgroupParamUint(path, maxUsage)
	if err != nil {
		if moduleName != "memory" && os.IsNotExist(err) {
			return MemoryData{}, nil
		}
		return MemoryData{}, fmt.Errorf("failed to parse %s - %v", maxUsage, err)
	}
	memoryData.MaxUsage = value
	value, err = getCgroupParamUint(path, failcnt)
	if err != nil {
		if moduleName != "memory" && os.IsNotExist(err) {
			return MemoryData{}, nil
		}
		return MemoryData{}, fmt.Errorf("failed to parse %s - %v", failcnt, err)
	}
	memoryData.Failcnt = value
	value, err = getCgroupParamUint(path, limit)
	if err != nil {
		if moduleName != "memory" && os.IsNotExist(err) {
			return MemoryData{}, nil
		}
		return MemoryData{}, fmt.Errorf("failed to parse %s - %v", limit, err)
	}
	if value >= 0x7FFFFFFFFFFFF000 {
		value = 0 // as unlimited
	}
	memoryData.Limit = value

	return memoryData, nil
}

func (s *SystemTools) getMemoryStats(path string, mStats *CgroupMemoryStats, bFullSet bool) error {
	// Set stats from memory.stat.
	filePath := filepath.Join(path, "memory.stat")
	statsFile, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer statsFile.Close()

	sc := bufio.NewScanner(statsFile)
	for sc.Scan() {
		t, v, err := getCgroupParamKeyValue(sc.Text())
		// log.WithFields(log.Fields{"t": t, "v": v, "err": err}).Debug()
		if err != nil {
			return fmt.Errorf("failed to parse memory.stat (%q) - %v", sc.Text(), err)
		}
		mStats.Stats[t] = v
	}
	mStats.Cache = mStats.Stats["cache"]
	var inactiveFileKeyName string

	switch s.cgroupVersion {
	case cgroup_v1:
		if memoryUsage, err := getMemoryData(path, ""); err == nil {
			mStats.Usage = memoryUsage
		}
		if kernelUsage, err := getMemoryData(path, "kmem"); err == nil {
			mStats.KernelUsage = kernelUsage
		}
		if bFullSet {
			if swapUsage, err := getMemoryData(path, "memsw"); err == nil {
				mStats.SwapUsage = swapUsage
			}
			if kernelTCPUsage, err := getMemoryData(path, "kmem.tcp"); err == nil {
				mStats.KernelTCPUsage = kernelTCPUsage
			}
			useHierarchy := strings.Join([]string{"memory", "use_hierarchy"}, ".")
			if value, err := getCgroupParamUint(path, useHierarchy); err == nil {
				if value == 1 {
					mStats.UseHierarchy = true
				}
			}
		}
		inactiveFileKeyName = "total_inactive_file"
	case cgroup_v2:
		if usage, err := getCgroupParamUint(path, "memory.current"); err == nil {
			mStats.Usage.Usage = usage
		}
		if usageHigh, err := getCgroupParamUint(path, "memory.high"); err == nil {
			mStats.Usage.MaxUsage = usageHigh
		}
		if usageMax, err := getCgroupParamUint(path, "memory.max"); err == nil {
			mStats.Usage.Limit = usageMax
		}
		inactiveFileKeyName = "inactive_file"
	default:
		return errUnsupported
	}

	// update working set data
	// from cAdvisor: The amount of working set memory, this includes recently accessed memory,
	// dirty memory, and kernel memory. Working set is <= "usage". (Bytes)
	workingSet := mStats.Usage.Usage
	if v, ok := mStats.Stats[inactiveFileKeyName]; ok {
		if workingSet < v {
			workingSet = 0
		} else {
			workingSet -= v
		}
	}
	mStats.WorkingSet = workingSet
	return nil
}

// https://github.com/opencontainers/runc/blob/master/libcontainer/cgroups/fs2/cpu.go
func (s *SystemTools) statCpu(path string, stats *CpuStats) error {
	if path == "" {
		return fmt.Errorf("empty path not supported")
	}
	f, err := os.Open(filepath.Join(path, "cpu.stat"))
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		t, v, err := getCgroupParamKeyValue(sc.Text())
		if err != nil {
			return err
		}
		switch t {
		case "usage_usec":
			stats.CpuUsage.TotalUsage = v * 1000
		case "user_usec":
			stats.CpuUsage.UsageInUsermode = v * 1000
		case "system_usec":
			stats.CpuUsage.UsageInKernelmode = v * 1000
		case "nr_periods":
			stats.ThrottlingData.Periods = v
		case "nr_throttled":
			stats.ThrottlingData.ThrottledPeriods = v
		case "throttled_usec":
			stats.ThrottlingData.ThrottledTime = v * 1000
		}
	}
	return nil
}

func (s *SystemTools) GetContainerMemoryUsage(cgroupPath string) (uint64, error) {
	mStats := CgroupMemoryStats{Stats: make(map[string]uint64)}
	if err := s.getMemoryStats(cgroupPath, &mStats, false); err != nil {
		return 0, err
	}
	return mStats.WorkingSet, nil
}

func (s *SystemTools) GetContainerMemoryLimitUsage(cgroupPath string) (uint64, error) {
	if s.cgroupVersion == cgroup_v2 {
		return getCgroupParamUint(cgroupPath, "memory.max") // the memory usage hard limit,
	}
	mStats := CgroupMemoryStats{Stats: make(map[string]uint64)}
	if err := s.getMemoryStats(cgroupPath, &mStats, false); err != nil {
		return 0, err
	}
	return mStats.Usage.Limit, nil // zero as no-limit
}

func (s *SystemTools) GetContainerCPUUsage(cgroupPath string) (uint64, error) {
	if s.cgroupVersion == cgroup_v2 {
		var stats CpuStats
		err := s.statCpu(cgroupPath, &stats)
		return stats.CpuUsage.TotalUsage, err // ns
	}
	return getCgroupParamUint(cgroupPath, "cpuacct.usage")
}

func (s *SystemTools) getContainerMemoryWorkingSetUsage() (uint64, error) {
	mStats := CgroupMemoryStats{Stats: make(map[string]uint64)}
	if err := s.getMemoryStats(s.cgroupMemoryDir, &mStats, false); err != nil {
		return 0, err
	}
	return mStats.WorkingSet, nil
}

func (s *SystemTools) GetContainerMemoryStats() (*CgroupMemoryStats, error) {
	mStats := &CgroupMemoryStats{Stats: make(map[string]uint64)}
	if err := s.getMemoryStats(s.cgroupMemoryDir, mStats, false); err != nil {
		return nil, err
	}
	return mStats, nil
}

func (s *SystemTools) setMemoryForceEmpty() error {
	if s.cgroupVersion == cgroup_v2 {
		return errUnsupported
	}

	f, err := os.OpenFile(filepath.Join(s.cgroupMemoryDir, "memory.force_empty"), os.O_WRONLY, 0400)
	if err == nil {
		_, err = f.WriteString("0")
		f.Close()
	}
	return err
}

func (s *SystemTools) CGroupMemoryStatReset(threshold uint64) bool {
	usage, err := s.getContainerMemoryWorkingSetUsage()
	if err == nil {
		if usage > threshold {
			log.WithFields(log.Fields{"usage": usage, "threshold": threshold}).Info()
			go func() {
				if err := s.setMemoryForceEmpty(); err != nil && err != errUnsupported {
					log.WithFields(log.Fields{"err": err}).Debug()
				}
			}()
			return true
		}
	}
	return false
}

// MemOomNotifier sends pressure level notifications
//
//	"low": system is reclaiming memory for new allocations.
//	"medium": system is experiencing medium memory pressure, the system might be making swap, paging out active file caches, etc.
//	"critical": system is actively thrashing, it is about to out of memory (OOM) or even the in-kernel OOM killer is on its way to trigger.
func (s *SystemTools) registerCGroupMemoryPressureNotifier() (int, int, int, error) {
	if s.cgroupVersion == cgroup_v2 {
		return -1, -1, -1, errUnsupported
	}

	watchfd, err := syscall.Open(fmt.Sprintf("%s/memory.pressure_level", s.cgroupMemoryDir), syscall.O_RDONLY, 0)
	if err == nil {
		controlfd, err2 := syscall.Open(fmt.Sprintf("%s/cgroup.event_control", s.cgroupMemoryDir), syscall.O_WRONLY, 0)
		if err2 == nil {
			efd, err3 := C.eventfd(0, C.EFD_CLOEXEC)
			if err3 == nil {
				eventfd := int(efd)
				if eventfd < 0 {
					err = fmt.Errorf("eventfd call failed")
				} else {
					config := fmt.Sprintf("%d %d low", eventfd, watchfd)
					// log.WithFields(log.Fields{"config": config}).Debug()
					if _, err = syscall.Write(controlfd, []byte(config)); err == nil {
						return watchfd, controlfd, eventfd, nil
					}
				}
				syscall.Close(eventfd)
			} else {
				err = err3
			}
		} else {
			err = err2
		}
		syscall.Close(controlfd)
		syscall.Close(watchfd)
	}
	return -1, -1, -1, err
}

// Linux kernel: mm/vmpressure.c
//
//	VMPRESSURE_LOW = 0,
//	VMPRESSURE_MEDIUM, <== 1, 60%
//	VMPRESSURE_CRITICAL, <== 2, 95%
//
// These thresholds are used when we account memory pressure through
// scanned/reclaimed ratio. The current values were chosen empirically. In
// essence, they are percents: the higher the value, the more number
// unsuccessful reclaims there were.
func (s *SystemTools) MonitorMemoryPressureEvents(threshold uint64, callback MemoryPressureCallback) error {
	ctlfd, watchfd, eventfd, err := s.registerCGroupMemoryPressureNotifier()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		return err
	}

	eventCh := make(chan uint64)
	errorCh := make(chan error)
	go func() {
		for {
			buf := make([]byte, 8)
			if _, err = syscall.Read(eventfd, buf); err != nil {
				log.WithFields(log.Fields{"error": err}).Error()
				errorCh <- err
				return
			}
			var level uint64
			if err := binary.Read(bytes.NewBuffer(buf[:]), binary.LittleEndian, &level); err == nil {
				// log.WithFields(log.Fields{"level": level}).Debug()
				eventCh <- level
			}
		}
	}()

	const report_interval = time.Duration(time.Minute * 10)
	var now, last_level1, last_level2, last_level_above time.Time
	var report, action bool
	for {
		select {
		case err := <-errorCh:
			syscall.Close(ctlfd)
			syscall.Close(watchfd)
			syscall.Close(eventfd)
			return err
		case level := <-eventCh:
			now = time.Now()
			report = false
			action = true
			switch level {
			case 0: // should not and ignored
				action = false
			case 1:
				if time.Since(last_level1) > report_interval {
					last_level1 = now
					report = true
				}
			case 2:
				if time.Since(last_level2) > report_interval {
					last_level2 = now
					report = true
				}
			default: // > 2, very critical, could up to 26. Not sure what does it mean from varied kernel responses
				if time.Since(last_level_above) > report_interval {
					last_level_above = now
					report = true
				}
			}

			if report {
				time.Sleep(time.Second * 5) // for acurrate data
				mStats := CgroupMemoryStats{Stats: make(map[string]uint64)}
				if err := s.getMemoryStats(s.cgroupMemoryDir, &mStats, true); err == nil {
					// skip the false alarm
					if mStats.WorkingSet < threshold {
						log.WithFields(log.Fields{"workingSet": mStats.WorkingSet, "threshold": threshold, "level": level}).Debug("Change Event")
						action = false
						level = 0
					}

					rpt := &MemoryPressureReport{
						Level: level,
						Stats: mStats,
					}

					if callback != nil {
						callback(rpt)
					}

					// TODO: add other actions and avoid aggressive approach
					if action {
						s.ReCalculateMemoryMetrics(0)
					}
				}
			}
		}
	}
}

/*
fstab(5):

The first field (fs_spec): the device to be mounted
The second field (fs_file): the mount point (target) for the filesystem.
The third field (fs_vfstype): the type of the filesystem.
The fourth field (fs_mntops): the mount options associated with the filesystem.
The fifth field (fs_freq)
The sixth field (fs_passno)

Examples:
(1) single-mount:

	"overlay / overlay rw,......""

(2) multiple-mounts:

	"overlay /run/containerd/io.containerd.runtime.v2.task/k8s.io/5e14.../rootfs "
*/
func readUppperLayerPath(file io.ReadSeeker, id string) (string, string, error) {
	var rootfs, upperdir string
	var found bool
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fstab := strings.Fields(line)
		for i, field := range fstab {
			if i == 0 && !strings.Contains(strings.ToLower(field), "overlay") { // fs_spec: overlay family only
				break // skip
			}

			if i == 1 { // fs_file: "mount point"
				rootfs = field
				if strings.Contains(field, id) {
					// log.WithFields(log.Fields{"rootfs": descs[1], "id": id}).Debug("not target")
					found = true
				}
			}

			if i == 3 { // fs_mntops
				options := strings.Split(field, ",")
				for _, op := range options {
					if strings.HasPrefix(op, "upperdir=") {
						upperdir = op[len("upperdir="):]
						if rootfs == "" { // common case
							found = true
						}
						break
					}
				} // the last entry of the overlay could be a good target, too
				break // discard following fields
			}
		}

		if found { // skip scanning other entries
			break
		}
	}

	return upperdir, rootfs, nil
}

// btrfs use two idential folders to store container files
// (1) working folder, like <subvol>, which includes the newly added files
// (2) init folder, like <subvol>-init, which has the original image files
// It needs extra works to differentiate these two folder.
// notes: /etc/host, /etc/hostname and /etc/resolv.conf are added by runtime-engine.
func readBtrfsWorkingPath(file io.ReadSeeker, id string) (string, string, error) {
	var rootfs string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fstab := strings.Fields(line)
		for i, field := range fstab {
			// log.WithFields(log.Fields{"field": field, "i": i}).Debug()
			if i == 1 && field != "/" { // fs_file: "mount point"
				if !strings.Contains(field, id) {
					// log.WithFields(log.Fields{"rootfs": descs[1], "id": id}).Debug("not target")
					break
				}
				rootfs = field
				continue
			}

			if i == 2 && !strings.Contains(strings.ToLower(field), "btrfs") { // fs_vfstype: btrfs
				break // skip
			}

			if i == 3 { // fs_mntops: mount options
				options := strings.Split(field, ",")
				for _, op := range options {
					if strings.HasPrefix(op, "subvol=") {
						return strings.TrimPrefix(op[len("subvol="):], "/@"), rootfs, nil
					}
				}
				break // ignore below fields
			}
		}
	}

	return "", rootfs, fmt.Errorf("not found")
}

// http://manpages.ubuntu.com/manpages/cosmic/man5/aufs.5.html
func readAufsSI(file io.ReadSeeker, id string) (string, error) {
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fstab := strings.Fields(line)
		for i, field := range fstab {
			// log.WithFields(log.Fields{"field": field, "i": i}).Debug()
			if i == 1 && field != "/" { // fs_file: "mount point"
				if !strings.Contains(field, id) { // TODO:
					// log.WithFields(log.Fields{"rootfs": descs[1], "id": id}).Debug("not target")
					break
				}
				continue
			}

			if i == 2 && !strings.Contains(strings.ToLower(field), "aufs") { // fs_vfstype: aufs family only
				break // skip
			}

			if i == 3 { // fs_mntops: mount options
				options := strings.Split(field, ",")
				for _, op := range options {
					if strings.HasPrefix(op, "si=") {
						return op[len("si="):], nil
					}
				}
				break // ignore below fields
			}
		}
	}

	return "", fmt.Errorf("not found")
}

func (s *SystemTools) ReadMountedUppperLayerPath(rootPid int, id string) (string, string, error) {
	file, err := os.Open(fmt.Sprintf("/proc/%d/mounts", rootPid))
	if err != nil {
		return "", "", err
	}
	defer file.Close()

	path, rootfs, err := readUppperLayerPath(file, id)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "pid": rootPid}).Error()
		return "", "", err
	}
	return path, rootfs, err
}

func (s *SystemTools) ReadMountedBtrfsWorkingPath(rootPid int, id string) (string, string, error) {
	file, err := os.Open(fmt.Sprintf("/proc/%d/mounts", rootPid))
	if err != nil {
		return "", "", err
	}
	defer file.Close()

	path, rootfs, err := readBtrfsWorkingPath(file, id)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "pid": rootPid}).Error()
		return "", "", err
	}
	return path, rootfs, err
}

func readAufsContainerLayerPaths(rootPid int, id string) (string, string, error) {
	var si, cPath, iPath string

	if file, err := os.Open(fmt.Sprintf("/proc/%d/mounts", rootPid)); err != nil {
		log.WithFields(log.Fields{"error": err, "pid": rootPid}).Error("open")
		return "", "", err
	} else {
		si, err = readAufsSI(file, id)
		file.Close()
		if err != nil {
			log.WithFields(log.Fields{"error": err, "pid": rootPid}).Error("read layers")
			return "", "", err
		}
	}

	// Aufs  shows  branch  paths  through <sysfs>/fs/aufs/si_XXX/brNNN.
	siPath := fmt.Sprintf("/proc/1/root/sys/fs/aufs/si_%s", si)
	// br0: rw (after init)
	// br1: ro+rh (-init: added by runtime engine)
	// br2-N: ro+rh (image layers), only keep the base-OS image path for now
	baseIndex := 2
	if d, err := os.Open(siPath); err == nil {
		if files, err := d.Readdir(-1); err == nil {
			// find the largest index of the barnch (br)
			for _, file := range files {
				name := file.Name()
				if file.Mode().IsRegular() && !strings.HasPrefix(name, "brid") && strings.HasPrefix(name, "br") {
					if m, err := strconv.Atoi(name[2:]); err == nil {
						if baseIndex < m {
							baseIndex = m
						}
					}
				}
			}
		}
		d.Close()
	}

	if content, err := os.ReadFile(filepath.Join(siPath, "br0")); err == nil {
		cPath = string(content)
		if pos := strings.LastIndex(cPath, "="); pos != -1 {
			cPath = cPath[:pos]
		}
	}

	if content, err := os.ReadFile(filepath.Join(siPath, fmt.Sprintf("br%d", baseIndex))); err == nil {
		iPath = string(content)
		if pos := strings.LastIndex(iPath, "="); pos != -1 {
			iPath = iPath[:pos]
		}
	}
	return cPath, iPath, nil
}

func (s *SystemTools) ReadAufsContainerLayerPath(rootPid int, id string) (string, string, error) {
	cPath, iPath, err := readAufsContainerLayerPaths(rootPid, id)
	if err != nil {
		// 2nd try
		log.WithFields(log.Fields{"id": id, "pid": rootPid}).Debug("2nd try")
		return s.LookupAufsContainerLayerPath(rootPid, id)
	}

	return cPath, iPath, err
}

// Apply touch and probe technique to find the path of the container layer
type layerPaths struct {
	cpath string // container layer (rw): upperDir
	ipath string // image layer (ro)
}

type lookupRef struct {
	mutex   sync.Mutex
	path2id map[string]string      // aufs: touch method
	id2path map[string]*layerPaths // index: container id
}

var containerLayerRef lookupRef = lookupRef{
	path2id: make(map[string]string),
	id2path: make(map[string]*layerPaths),
}

const root_pid_1 = "/proc/1/root"
const docker_aufs_root_path = "/var/lib/docker/aufs/diff"

// /
func (s *SystemTools) RemoveContainerLayerPath(id string) {
	containerLayerRef.mutex.Lock()
	defer containerLayerRef.mutex.Unlock()
	if layers, ok := containerLayerRef.id2path[id]; ok {
		delete(containerLayerRef.id2path, id)
		delete(containerLayerRef.path2id, layers.cpath)
	}
}

// / Obsolated: the directory names do not correspond to the layer IDs (this has been true since Docker 1.10).
// / TODO: discover rootFs
func (s *SystemTools) LookupAufsContainerLayerPath(pid int, id string) (string, string, error) {
	var path string
	var err error

	containerLayerRef.mutex.Lock()
	defer containerLayerRef.mutex.Unlock()
	layers, ok := containerLayerRef.id2path[id]
	if ok && layers.cpath != "" {
		return layers.cpath, layers.ipath, nil
	}

	idFileName := fmt.Sprintf("nv.%s", id)
	file := fmt.Sprintf("/proc/%d/root/%s", pid, idFileName)
	if fptr, err := os.Create(file); err != nil {
		if !strings.HasSuffix(err.Error(), "permission denied") {
			log.WithFields(log.Fields{"error": err}).Error("touch")
		}
		return "", "", err
	} else {
		fptr.Close()
	}
	defer os.Remove(file)

	path, err = s.matchIdFile(docker_aufs_root_path, idFileName)
	if err != nil {
		log.WithFields(log.Fields{"id": id, "pid": pid, "error": err}).Error("match")
		return "", "", err
	}

	// log.WithFields(log.Fields{"path": path}).Debug()   // found
	containerLayerRef.path2id[path] = id
	containerLayerRef.id2path[id] = &layerPaths{cpath: path, ipath: ""}
	return path, "", nil
}

// /
func (s *SystemTools) matchIdFile(rootPath, idFileName string) (string, error) {
	d, err := os.Open(filepath.Join(root_pid_1, rootPath))
	if err != nil {
		return "", err
	}
	defer d.Close()

	files, err := d.Readdir(-1)
	if err != nil {
		return "", err
	}

	// get all the sub-directories
	for _, file := range files {
		if file.IsDir() && strings.HasSuffix(file.Name(), "-init") {
			path := filepath.Join(rootPath, strings.TrimSuffix(file.Name(), "-init"))
			if _, ok := containerLayerRef.path2id[path]; !ok { // skip found entry
				f, err := os.Open(filepath.Join(root_pid_1, path, idFileName))
				if err != nil {
					continue
				}
				f.Close()
				return path, nil
			}
		}
	}
	return "", fmt.Errorf("no match")
}

const reclaim_interval = time.Duration(time.Minute * 5) // do not push too much
var last_reclaim_time time.Time

// Limit the re-calculate function apart in 5 minutes
func (s *SystemTools) ReCalculateMemoryMetrics(threshold uint64) {
	if threshold == 0 || time.Since(last_reclaim_time) > reclaim_interval {
		if s.CGroupMemoryStatReset(threshold) {
			last_reclaim_time = time.Now()
		}
	}
}

// verify the cgroup's memory controller
// cgroup v2 is a unified file system, it does not have the memory folder
func (s *SystemTools) GetCgroupVersion() int {
	return s.cgroupVersion
}

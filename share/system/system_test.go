package system

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseSharedNetNS(t *testing.T) {
	var sys SystemTools
	pid := sys.ParseNetNamespacePath("/proc/11217/ns/net")
	if pid != 11217 {
		t.Errorf("Incorrect pid: %v\n", pid)
	}
}

func TestCgroupSelector(t *testing.T) {

	var sys SystemTools

	sys.cgroupVersion = -1
	sys.cgroupDir = "/host/cgroup"
	sys.cgroupMemoryDir = "/"
	sys.SetCgroupInfo(cgroup_v1)
	assert.Equal(t,
		"/host/cgroup/memory",
		sys.cgroupMemoryDir, "For v1, we should use the memory directory")

	sys.cgroupVersion = -1
	sys.cgroupDir = "/host/cgroup"
	sys.cgroupMemoryDir = "/"
	sys.SetCgroupInfo(cgroup_v2)
	assert.Equal(t,
		"/host/cgroup",
		sys.cgroupMemoryDir, "For v2, we should use the base directory")


	sys.cgroupVersion = -1
	sys.cgroupDir = "/host/cgroup"
	sys.cgroupMemoryDir = "/"
	sys.SetCgroupInfo(-1)
	assert.Equal(t,
		"/host/cgroup/memory",
		sys.cgroupMemoryDir, "For unsupported, we should default to v1")
}

func TestCgroupVersion(t *testing.T) {

	var sys SystemTools
	// When we upgrade golang, use TempDir
	//sys.cgroupDir = T.TempDir()
	sys.cgroupDir = "/tmp"
	tmpcontrollerpath := "/tmp/cgroup.controllers"
	// Make sure there isn't one here
	os.Remove(tmpcontrollerpath) // Best effort

	// Test v1
	version := sys.DetermineCgroupVersion()
	assert.Equal(t, cgroup_v1, version, "Should be cgroup v1")

	// Test V2
	cgroupcontroller := tmpcontrollerpath
	fp, err := os.Create(cgroupcontroller)
	if err != nil {
		t.Fatalf("Could not create tmp file for testing: %s", err.Error())
	}
	fp.Close() // We don't need

	version2 := sys.DetermineCgroupVersion()
	assert.Equal(t, cgroup_v2, version2, "Should be cgroup v1")

	os.Remove(tmpcontrollerpath) // best effort
}

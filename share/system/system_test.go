package system

import (
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

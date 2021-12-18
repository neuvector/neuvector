package system

import (
	"testing"
)

func TestParseSharedNetNS(t *testing.T) {
	var sys SystemTools
	pid := sys.ParseNetNamespacePath("/proc/11217/ns/net")
	if pid != 11217 {
		t.Errorf("Incorrect pid: %v\n", pid)
	}
}

package fsmon

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/neuvector/neuvector/share"
)

func TestGetBaseDirPrefix(t *testing.T) {
	assert.Equal(t, "/lib64", getBaseDirPrefix(share.CLUSFileMonitorFilter{Behavior: share.FileAccessBehaviorMonitor, Path: "/lib64", Regex: "ld-linux.*", Recursive: true}))
}

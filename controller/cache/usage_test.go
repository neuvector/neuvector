package cache

import (
	"testing"

	"fmt"
	"strings"
	"time"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

func TestUsageKey(t *testing.T) {
	r := share.CLUSSystemUsageReport{ReportedAt: time.Now().UTC()}
	key := signUsageReport(&r)

	ts := fmt.Sprintf("%d", r.ReportedAt.Unix())
	hash := utils.DecryptPassword(key)
	if !strings.HasPrefix(ts, ts) {
		t.Errorf("Error in signing: timestamp=%s hash=%s\n", ts, hash)
	}
}

package cache

import (
	"testing"

	"fmt"
	"strings"
	"time"

	"github.com/neuvector/neuvector/share"
)

func TestUsageKey(t *testing.T) {
	r := share.CLUSSystemUsageReport{ReportedAt: time.Now().UTC()}
	ts := fmt.Sprintf("%d", r.ReportedAt.Unix())
	if !strings.HasPrefix(ts, ts) {
		t.Errorf("Error in signing: timestamp=%s\n", ts)
	}
}

package main

import (
	"testing"

	"github.com/neuvector/neuvector/agent/dp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dp policy action values mirrored from defs.h so the test does not depend on cgo.
const (
	testActionOpen     uint8 = 0
	testActionLearn    uint8 = 1
	testActionAllow    uint8 = 2
	testActionCheckVH  uint8 = 3
	testActionCheckNBE uint8 = 4
	testActionCheckApp uint8 = 5
	testActionViolate  uint8 = 6
	testActionDeny     uint8 = 7
)

// NOTE: these tests mutate the package-global connsCache/connsCacheDropped and
// therefore must NOT be run with t.Parallel(); each resets state via
// resetConnsCache() and relies on serial execution.

// resetConnsCache clears the package-global ingestion state so each subtest starts clean.
func resetConnsCache() {
	connsCacheMutex.Lock()
	connsCache = nil
	connsCacheDropped = 0
	connsCacheMutex.Unlock()
}

func newConnData(action uint8) *dp.ConnectionData {
	return &dp.ConnectionData{Conn: &dp.Connection{PolicyAction: action}}
}

// repeatConnData returns a slice of n ConnectionData all pointing at a single
// shared Conn of the given action, so a large count costs only pointer memory.
func repeatConnData(action uint8, n int) []*dp.ConnectionData {
	cd := newConnData(action)
	conns := make([]*dp.ConnectionData, n)
	for i := range conns {
		conns[i] = cd
	}
	return conns
}

func TestConnIsHighPriority(t *testing.T) {
	cases := []struct {
		name string
		conn *dp.Connection
		want bool
	}{
		// policy-action based priority
		{name: "open", conn: &dp.Connection{PolicyAction: testActionOpen}, want: false},
		{name: "learn", conn: &dp.Connection{PolicyAction: testActionLearn}, want: true},
		{name: "allow", conn: &dp.Connection{PolicyAction: testActionAllow}, want: false},
		{name: "check_vh", conn: &dp.Connection{PolicyAction: testActionCheckVH}, want: false},
		{name: "check_nbe", conn: &dp.Connection{PolicyAction: testActionCheckNBE}, want: false},
		{name: "check_app", conn: &dp.Connection{PolicyAction: testActionCheckApp}, want: false},
		{name: "violate", conn: &dp.Connection{PolicyAction: testActionViolate}, want: true},
		{name: "deny", conn: &dp.Connection{PolicyAction: testActionDeny}, want: true},
		// DNS-tunnel candidate: dp set ClientPort on an otherwise low-priority conn
		{name: "allow with client port", conn: &dp.Connection{PolicyAction: testActionAllow, ClientPort: 5353}, want: true},
		{name: "open with client port", conn: &dp.Connection{PolicyAction: testActionOpen, ClientPort: 1}, want: true},
		// dp-detected threat on an otherwise low-priority conn
		{name: "allow with severity", conn: &dp.Connection{PolicyAction: testActionAllow, Severity: 1}, want: true},
		{name: "allow with threat id", conn: &dp.Connection{PolicyAction: testActionAllow, ThreatID: 42}, want: true},
		// plain low-priority conn with none of the above stays droppable
		{name: "allow no signals", conn: &dp.Connection{PolicyAction: testActionAllow, ClientPort: 0, Severity: 0, ThreatID: 0}, want: false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, connIsHighPriority(c.conn))
		})
	}
}

func TestCacheConnections(t *testing.T) {
	cases := []struct {
		name        string
		feed        []*dp.ConnectionData
		wantLen     int
		wantDropped uint64
	}{
		{
			name:        "under cap keeps all low priority",
			feed:        repeatConnData(testActionAllow, 100),
			wantLen:     100,
			wantDropped: 0,
		},
		{
			name:        "exactly at soft cap keeps all low priority",
			feed:        repeatConnData(testActionAllow, connsCacheMax),
			wantLen:     connsCacheMax,
			wantDropped: 0,
		},
		{
			name:        "low priority dropped once soft cap reached",
			feed:        repeatConnData(testActionAllow, connsCacheMax+50),
			wantLen:     connsCacheMax,
			wantDropped: 50,
		},
		{
			name:        "exactly at hard cap keeps all high priority",
			feed:        repeatConnData(testActionViolate, connsCacheHardMax),
			wantLen:     connsCacheHardMax,
			wantDropped: 0,
		},
		{
			name:        "high priority kept past soft cap up to hard cap",
			feed:        repeatConnData(testActionViolate, connsCacheHardMax+50),
			wantLen:     connsCacheHardMax,
			wantDropped: 50,
		},
		{
			name:        "learn is high priority",
			feed:        repeatConnData(testActionLearn, connsCacheMax+10),
			wantLen:     connsCacheMax + 10,
			wantDropped: 0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resetConnsCache()
			cacheConnections(c.feed)

			connsCacheMutex.Lock()
			gotLen := len(connsCache)
			gotDropped := connsCacheDropped
			connsCacheMutex.Unlock()

			assert.Equal(t, c.wantLen, gotLen)
			assert.Equal(t, c.wantDropped, gotDropped)
		})
	}
}

// TestCacheConnectionsHighPriorityAfterLowFills verifies that once low-priority
// connections have filled the soft cap, high-priority connections are still
// admitted (up to the hard cap) while further low-priority ones are dropped.
func TestCacheConnectionsHighPriorityAfterLowFills(t *testing.T) {
	resetConnsCache()

	cacheConnections(repeatConnData(testActionAllow, connsCacheMax))
	cacheConnections(repeatConnData(testActionViolate, 100))
	cacheConnections(repeatConnData(testActionAllow, 100))

	connsCacheMutex.Lock()
	gotLen := len(connsCache)
	gotDropped := connsCacheDropped
	connsCacheMutex.Unlock()

	assert.Equal(t, connsCacheMax+100, gotLen, "high-priority admitted past soft cap")
	assert.Equal(t, uint64(100), gotDropped, "later low-priority dropped")
}

// TestCacheConnectionsDNSTunnelCandidateKeptPastSoftCap verifies that a large
// DNS-tunnel candidate (ClientPort set by dp on an otherwise ALLOW connection)
// is treated as high-priority and admitted past the soft cap.
func TestCacheConnectionsDNSTunnelCandidateKeptPastSoftCap(t *testing.T) {
	resetConnsCache()

	cacheConnections(repeatConnData(testActionAllow, connsCacheMax))

	tunnelCandidate := &dp.ConnectionData{Conn: &dp.Connection{PolicyAction: testActionAllow, ClientPort: 5353}}
	cacheConnections([]*dp.ConnectionData{tunnelCandidate})
	cacheConnections(repeatConnData(testActionAllow, 5)) // plain low-priority, dropped

	connsCacheMutex.Lock()
	gotLen := len(connsCache)
	gotDropped := connsCacheDropped
	connsCacheMutex.Unlock()

	assert.Equal(t, connsCacheMax+1, gotLen, "DNS-tunnel candidate admitted past soft cap")
	assert.Equal(t, uint64(5), gotDropped, "plain low-priority still dropped")
}

// TestCacheConnectionsInterleavedSingleFeed verifies the per-element decision
// within a single cacheConnections call: once the soft cap is reached partway
// through the slice, subsequent high-priority elements are still admitted while
// low-priority ones in the same slice are dropped.
func TestCacheConnectionsInterleavedSingleFeed(t *testing.T) {
	resetConnsCache()

	feed := repeatConnData(testActionAllow, connsCacheMax)
	// After the soft cap, interleave two high- and two low-priority connections.
	feed = append(feed,
		newConnData(testActionDeny),
		newConnData(testActionAllow),
		newConnData(testActionViolate),
		newConnData(testActionOpen),
	)
	cacheConnections(feed)

	connsCacheMutex.Lock()
	gotLen := len(connsCache)
	gotDropped := connsCacheDropped
	connsCacheMutex.Unlock()

	assert.Equal(t, connsCacheMax+2, gotLen, "two high-priority admitted past soft cap")
	assert.Equal(t, uint64(2), gotDropped, "two low-priority dropped")
}

func TestDrainConnsCache(t *testing.T) {
	cases := []struct {
		name        string
		feed        []*dp.ConnectionData
		wantConns   int
		wantDropped uint64
	}{
		{name: "empty", feed: nil, wantConns: 0, wantDropped: 0},
		{name: "some", feed: repeatConnData(testActionAllow, 10), wantConns: 10, wantDropped: 0},
		{
			name:        "carries drop count",
			feed:        repeatConnData(testActionAllow, connsCacheMax+7),
			wantConns:   connsCacheMax,
			wantDropped: 7,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resetConnsCache()
			cacheConnections(c.feed)

			conns, dropped := drainConnsCache()
			assert.Len(t, conns, c.wantConns)
			assert.Equal(t, c.wantDropped, dropped)

			// After draining, the cache must be reset to nil so the backing
			// array is released rather than retained at peak capacity.
			connsCacheMutex.Lock()
			require.Nil(t, connsCache)
			assert.Zero(t, connsCacheDropped)
			connsCacheMutex.Unlock()
		})
	}
}

// TestDrainConnsCacheSecondDrainEmpty verifies that a drain immediately
// following another (with no intervening cacheConnections) reports nothing,
// confirming the drain fully resets both the slice and the drop counter.
func TestDrainConnsCacheSecondDrainEmpty(t *testing.T) {
	resetConnsCache()
	cacheConnections(repeatConnData(testActionAllow, connsCacheMax+7))

	_, dropped := drainConnsCache()
	require.Equal(t, uint64(7), dropped)

	conns, dropped := drainConnsCache()
	assert.Empty(t, conns)
	assert.Zero(t, dropped)
}

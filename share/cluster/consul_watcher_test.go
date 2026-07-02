package cluster

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Named package-level functions used as test fixtures.
// Pointer()-based dedup is reliable for named functions; see closure test below.
func testNodeWatcherA(_ ClusterNotifyType, _, _ string)                   {}
func testNodeWatcherB(_ ClusterNotifyType, _, _ string)                   {}
func testKeyWatcherA(_ ClusterNotifyType, _ string, _ []byte, _ uint64)   {}
func testKeyWatcherB(_ ClusterNotifyType, _ string, _ []byte, _ uint64)   {}
func testStateWatcherA(_ ClusterNotifyType, _, _ string)                  {}
func testStateWatcherB(_ ClusterNotifyType, _, _ string)                  {}
func testStoreWatcherA(_ ClusterNotifyType, _ string, _ []byte, _ uint64) {}
func testStoreWatcherB(_ ClusterNotifyType, _ string, _ []byte, _ uint64) {}

// TestAddWatcher covers all four add*Watcher functions with the same shared
// cases, expressed as "pre-populate with N copies of watcher A and M copies of
// watcher B, then try to add A or B".
func TestAddWatcher(t *testing.T) {
	cases := []struct {
		name      string
		preSame   int  // watchers identical to the one being added
		preDiff   int  // watchers different from the one being added
		addSame   bool // true → add the "same" watcher; false → add the "different" one
		wantAdded bool
		wantLen   int
	}{
		{name: "add to empty list", preSame: 0, preDiff: 0, addSame: true, wantAdded: true, wantLen: 1},
		{name: "dedup same function", preSame: 1, preDiff: 0, addSame: true, wantAdded: false, wantLen: 1},
		{name: "add different function", preSame: 1, preDiff: 0, addSame: false, wantAdded: true, wantLen: 2},
		{name: "dedup when not at end of list", preSame: 1, preDiff: 1, addSame: true, wantAdded: false, wantLen: 2},
	}

	t.Run("addNodeWatcher", func(t *testing.T) {
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				nodeWatchers = make([]NodeWatcher, 0)
				for range c.preSame {
					nodeWatchers = append(nodeWatchers, testNodeWatcherA)
				}
				for range c.preDiff {
					nodeWatchers = append(nodeWatchers, testNodeWatcherB)
				}

				var got bool
				if c.addSame {
					got = addNodeWatcher(testNodeWatcherA)
				} else {
					got = addNodeWatcher(testNodeWatcherB)
				}

				assert.Equal(t, c.wantAdded, got)
				assert.Len(t, nodeWatchers, c.wantLen)
			})
		}
	})

	t.Run("addStateWatcher", func(t *testing.T) {
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				stateWatchers = make([]StateWatcher, 0)
				for range c.preSame {
					stateWatchers = append(stateWatchers, testStateWatcherA)
				}
				for range c.preDiff {
					stateWatchers = append(stateWatchers, testStateWatcherB)
				}

				var got bool
				if c.addSame {
					got = addStateWatcher(testStateWatcherA)
				} else {
					got = addStateWatcher(testStateWatcherB)
				}

				assert.Equal(t, c.wantAdded, got)
				assert.Len(t, stateWatchers, c.wantLen)
			})
		}
	})

	t.Run("addKeyWatcher", func(t *testing.T) {
		const key = "cluster/testkey"

		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				keyWatchers = make(map[string][]KeyWatcher)
				existing := make([]KeyWatcher, 0, c.preSame+c.preDiff)
				for range c.preSame {
					existing = append(existing, testKeyWatcherA)
				}
				for range c.preDiff {
					existing = append(existing, testKeyWatcherB)
				}
				if len(existing) > 0 {
					keyWatchers[key] = existing
				}

				var got bool
				if c.addSame {
					got = addKeyWatcher(key, testKeyWatcherA)
				} else {
					got = addKeyWatcher(key, testKeyWatcherB)
				}

				assert.Equal(t, c.wantAdded, got)
				require.Contains(t, keyWatchers, key)
				assert.Len(t, keyWatchers[key], c.wantLen)
			})
		}

		t.Run("same function on different key is not deduped", func(t *testing.T) {
			const keyA, keyB = "cluster/keyA", "cluster/keyB"
			keyWatchers = map[string][]KeyWatcher{keyA: {testKeyWatcherA}}

			got := addKeyWatcher(keyB, testKeyWatcherA)

			assert.True(t, got)
			assert.Len(t, keyWatchers[keyB], 1)
			assert.Len(t, keyWatchers[keyA], 1, "existing key unaffected")
		})
	})

	t.Run("addStoreWatcher", func(t *testing.T) {
		const store = "cluster/teststore/"

		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				storeWatchers = make(map[string][]StoreWatcher)
				storeWatchersCongestCtl = make(map[string]bool)
				existing := make([]StoreWatcher, 0, c.preSame+c.preDiff)
				for range c.preSame {
					existing = append(existing, testStoreWatcherA)
				}
				for range c.preDiff {
					existing = append(existing, testStoreWatcherB)
				}
				if len(existing) > 0 {
					storeWatchers[store] = existing
				}

				var got bool
				if c.addSame {
					got = addStoreWatcher(store, testStoreWatcherA, true)
				} else {
					got = addStoreWatcher(store, testStoreWatcherB, false)
				}

				assert.Equal(t, c.wantAdded, got)
				require.Contains(t, storeWatchers, store)
				assert.Len(t, storeWatchers[store], c.wantLen)
			})
		}

		t.Run("same function on different store is not deduped", func(t *testing.T) {
			const storeA, storeB = "cluster/storeA/", "cluster/storeB/"
			storeWatchers = map[string][]StoreWatcher{storeA: {testStoreWatcherA}}
			storeWatchersCongestCtl = make(map[string]bool)

			got := addStoreWatcher(storeB, testStoreWatcherA, true)

			assert.True(t, got)
			assert.Len(t, storeWatchers[storeB], 1)
			assert.Len(t, storeWatchers[storeA], 1, "existing store unaffected")
		})

		t.Run("congestCtl is recorded on add", func(t *testing.T) {
			storeWatchers = make(map[string][]StoreWatcher)
			storeWatchersCongestCtl = make(map[string]bool)

			addStoreWatcher(store, testStoreWatcherA, true)
			assert.True(t, storeWatchersCongestCtl[store])

			// congestCtl is NOT updated on a duplicate registration
			storeWatchersCongestCtl[store] = false
			addStoreWatcher(store, testStoreWatcherA, true)
			assert.False(t, storeWatchersCongestCtl[store], "dedup should not update congestCtl")
		})
	})
}

// TestAddWatcher_ClosureLimitation documents that Pointer()-based dedup is
// unreliable for closures: two distinct closures with the same body may share a
// code pointer and be incorrectly treated as duplicates.
func TestAddWatcher_ClosureLimitation(t *testing.T) {
	nodeWatchers = make([]NodeWatcher, 0)

	counter := 0
	closureA := NodeWatcher(func(_ ClusterNotifyType, _, _ string) { counter++ })
	closureB := NodeWatcher(func(_ ClusterNotifyType, _, _ string) { counter += 2 })

	addNodeWatcher(closureA)
	addNodeWatcher(closureB)

	t.Logf("len(nodeWatchers) after adding two closure instances: %d", len(nodeWatchers))
	if len(nodeWatchers) == 1 {
		t.Log("KNOWN LIMITATION: closures with identical bodies may share a code pointer; dedup is over-aggressive")
	}
}

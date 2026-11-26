package fsmon

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/s3rj1k/go-fanotify/fanotify"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// The agent opens files that have a FAN_OPEN_PERM mark.
// For example, HandleWatchedFiles calculates the hash of a protected file.
// Each of these opens must get a response.
// If an open does not get a response, the open does not complete.
func TestHandleEventsAnswersOwnPermEvents(t *testing.T) {
	fa, err := fanotify.Initialize(faInitFlags, unix.O_RDONLY|unix.O_LARGEFILE)
	if err != nil {
		t.Skipf("fanotify unavailable (needs CAP_SYS_ADMIN): %v", err)
	}
	defer fa.File.Close()

	dir := t.TempDir()
	file := filepath.Join(dir, "protected")
	require.NoError(t, os.WriteFile(file, []byte("data"), 0o600))
	require.NoError(t, fa.Mark(faMarkAddFlags, unix.FAN_OPEN_PERM|faMarkMaskDir, unix.AT_FDCWD, dir))

	fn := &FaNotify{fa: fa, agentPid: os.Getpid(), bEnabled: true}
	// handleEvents stays in read until the process stops.
	// The channel has a buffer, so the goroutine does not use t.
	handled := make(chan error, 1)
	go func() { handled <- fn.handleEvents() }()

	opened := make(chan error, 1)
	go func() {
		f, err := os.Open(file)
		if err == nil {
			defer f.Close()
		}
		opened <- err
	}()

	select {
	case err := <-opened:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("open of a perm-marked file by the agent itself was never answered")
	}
}

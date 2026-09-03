package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/neuvector/neuvector/agent/workerlet"
	"github.com/neuvector/neuvector/share/system"
)

// walkTree runs WalkPathTask over dir and returns the relative paths it reported.
//
// WalkPathTask always resolves its root as /proc/<Pid>/root + Path, so the test
// passes its own pid: /proc/self/root is the caller's root filesystem, which
// makes an ordinary temp directory reachable without root privileges or a
// running container.
func walkTree(t *testing.T, dir string, dirs []string) []string {
	t.Helper()

	done := make(chan error, 1)
	tm := InitTaskMain(t.TempDir(), done, system.NewSystemTools())

	go tm.WalkPathTask(workerlet.WalkPathRequest{
		Pid:      os.Getpid(),
		Path:     dir,
		ExecOnly: false,
		Dirs:     dirs,
	})

	if err := <-done; err != nil {
		t.Fatalf("WalkPathTask: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(tm.workPath, workerlet.ResultJson))
	if err != nil {
		t.Fatalf("read result: %v", err)
	}

	var res workerlet.WalkPathResult
	if err := json.Unmarshal(data, &res); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	found := make([]string, 0, len(res.Files))
	for _, f := range res.Files {
		found = append(found, f.File)
	}
	return found
}

func contains(list []string, want string) bool {
	for _, got := range list {
		if got == want {
			return true
		}
	}
	return false
}

// A request that sets no Dirs asks for no directory filter, so the whole tree
// below the root must be reported. Before the fix every sub-directory was
// skipped and only files sitting directly in the root were returned.
func TestWalkPathEmptyDirsWalksWholeTree(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "usr", "bin"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "top"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr", "bin", "nested"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	found := walkTree(t, root, nil)

	if !contains(found, "/top") {
		t.Errorf("file in the root was not reported, got %v", found)
	}
	if !contains(found, "/usr/bin/nested") {
		t.Errorf("nested file was not reported, got %v", found)
	}
}

// A request that does set Dirs keeps its scope: directories outside the listed
// prefixes stay pruned.
func TestWalkPathDirsLimitsScope(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "keep"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "prune"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "keep", "wanted"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "prune", "unwanted"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	found := walkTree(t, root, []string{"/keep"})

	if !contains(found, "/keep/wanted") {
		t.Errorf("file under the requested directory was not reported, got %v", found)
	}
	if contains(found, "/prune/unwanted") {
		t.Errorf("file outside the requested directories was reported, got %v", found)
	}
}

package resource

import (
	"regexp"
	"testing"
)

func TestGenShellSafeRandomString(t *testing.T) {
	value, err := GenShellSafeRandomString(64)
	if err != nil {
		t.Fatalf("GenShellSafeRandomString returned error: %v", err)
	}
	if len(value) != 64 {
		t.Fatalf("GenShellSafeRandomString length=%d, want 64", len(value))
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9]+$`).MatchString(value) {
		t.Fatalf("GenShellSafeRandomString returned shell-unsafe characters")
	}
}

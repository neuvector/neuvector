package common

import (
	"testing"
)

func TestEncryptLocalDB(t *testing.T) {
	if !encryptLocalDB {
		t.Error("encryptLocalDB is false")
	}
}

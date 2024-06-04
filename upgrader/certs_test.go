package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestIsUpgradeInProgress(t *testing.T) {
	assert.Equal(t, false, IsUpgradeInProgress(context.Background(), &corev1.Secret{}))

	// Upgrade completes
	assert.Equal(t, false, IsUpgradeInProgress(context.Background(), &corev1.Secret{
		Data: map[string][]byte{
			NEW_SECRET_PREFIX + CACERT_FILENAME:    []byte("aaa"),
			NEW_SECRET_PREFIX + CERT_FILENAME:      []byte("aaa"),
			NEW_SECRET_PREFIX + KEY_FILENAME:       []byte("aaa"),
			ACTIVE_SECRET_PREFIX + CACERT_FILENAME: []byte("aaa"),
			ACTIVE_SECRET_PREFIX + CERT_FILENAME:   []byte("aaa"),
			ACTIVE_SECRET_PREFIX + KEY_FILENAME:    []byte("aaa"),
			DEST_SECRET_PREFIX + CACERT_FILENAME:   []byte("aaa"),
			DEST_SECRET_PREFIX + CERT_FILENAME:     []byte("aaa"),
			DEST_SECRET_PREFIX + KEY_FILENAME:      []byte("aaa"),
		},
	}))

	// During stage 1
	assert.Equal(t, true, IsUpgradeInProgress(context.Background(), &corev1.Secret{
		Data: map[string][]byte{
			NEW_SECRET_PREFIX + CACERT_FILENAME:    []byte("bbb"),
			NEW_SECRET_PREFIX + CERT_FILENAME:      []byte("bbb"),
			NEW_SECRET_PREFIX + KEY_FILENAME:       []byte("bbb"),
			ACTIVE_SECRET_PREFIX + CACERT_FILENAME: []byte("aaabbb"),
			ACTIVE_SECRET_PREFIX + CERT_FILENAME:   []byte("aaa"),
			ACTIVE_SECRET_PREFIX + KEY_FILENAME:    []byte("aaa"),
			DEST_SECRET_PREFIX + CACERT_FILENAME:   []byte("aaa"),
			DEST_SECRET_PREFIX + CERT_FILENAME:     []byte("aaa"),
			DEST_SECRET_PREFIX + KEY_FILENAME:      []byte("aaa"),
		},
	}))

	// During stage 2
	assert.Equal(t, true, IsUpgradeInProgress(context.Background(), &corev1.Secret{
		Data: map[string][]byte{
			NEW_SECRET_PREFIX + CACERT_FILENAME:    []byte("bbb"),
			NEW_SECRET_PREFIX + CERT_FILENAME:      []byte("bbb"),
			NEW_SECRET_PREFIX + KEY_FILENAME:       []byte("bbb"),
			ACTIVE_SECRET_PREFIX + CACERT_FILENAME: []byte("aaabbb"),
			ACTIVE_SECRET_PREFIX + CERT_FILENAME:   []byte("bbb"),
			ACTIVE_SECRET_PREFIX + KEY_FILENAME:    []byte("bbb"),
			DEST_SECRET_PREFIX + CACERT_FILENAME:   []byte("aaa"),
			DEST_SECRET_PREFIX + CERT_FILENAME:     []byte("aaa"),
			DEST_SECRET_PREFIX + KEY_FILENAME:      []byte("aaa"),
		},
	}))

	// During stage 3
	assert.Equal(t, true, IsUpgradeInProgress(context.Background(), &corev1.Secret{
		Data: map[string][]byte{
			NEW_SECRET_PREFIX + CACERT_FILENAME:    []byte("bbb"),
			NEW_SECRET_PREFIX + CERT_FILENAME:      []byte("bbb"),
			NEW_SECRET_PREFIX + KEY_FILENAME:       []byte("bbb"),
			ACTIVE_SECRET_PREFIX + CACERT_FILENAME: []byte("bbb"),
			ACTIVE_SECRET_PREFIX + CERT_FILENAME:   []byte("bbb"),
			ACTIVE_SECRET_PREFIX + KEY_FILENAME:    []byte("bbb"),
			DEST_SECRET_PREFIX + CACERT_FILENAME:   []byte("aaa"),
			DEST_SECRET_PREFIX + CERT_FILENAME:     []byte("aaa"),
			DEST_SECRET_PREFIX + KEY_FILENAME:      []byte("aaa"),
		},
	}))

	// Completes
	assert.Equal(t, false, IsUpgradeInProgress(context.Background(), &corev1.Secret{
		Data: map[string][]byte{
			NEW_SECRET_PREFIX + CACERT_FILENAME:    []byte("bbb"),
			NEW_SECRET_PREFIX + CERT_FILENAME:      []byte("bbb"),
			NEW_SECRET_PREFIX + KEY_FILENAME:       []byte("bbb"),
			ACTIVE_SECRET_PREFIX + CACERT_FILENAME: []byte("bbb"),
			ACTIVE_SECRET_PREFIX + CERT_FILENAME:   []byte("bbb"),
			ACTIVE_SECRET_PREFIX + KEY_FILENAME:    []byte("bbb"),
			DEST_SECRET_PREFIX + CACERT_FILENAME:   []byte("bbb"),
			DEST_SECRET_PREFIX + CERT_FILENAME:     []byte("bbb"),
			DEST_SECRET_PREFIX + KEY_FILENAME:      []byte("bbb"),
		},
	}))
}

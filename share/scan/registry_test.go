package scan

import (
	"errors"
	"reflect"
	"testing"

	"github.com/docker/distribution"
	manifestV2 "github.com/docker/distribution/manifest/schema2"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/scan/registry"
	"github.com/stretchr/testify/assert"
)

func TestClassifyManifestErr(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		expected share.ScanErrorCode
	}{
		{
			name:     "nil error returns ImageNotFound",
			err:      nil,
			expected: share.ScanErrorCode_ScanErrImageNotFound,
		},
		{
			name:     "x509 certificate error returns Certificate",
			err:      errors.New(`Get "https://registry.example.com/v2/": tls: failed to verify certificate: x509: certificate signed by unknown authority`),
			expected: share.ScanErrorCode_ScanErrCertificate,
		},
		{
			name:     "tls handshake error returns Certificate",
			err:      errors.New(`tls: no supported versions satisfy MinVersion and MaxVersion`),
			expected: share.ScanErrorCode_ScanErrCertificate,
		},
		{
			name:     "connection refused returns Network",
			err:      errors.New(`dial tcp 10.0.0.1:443: connect: connection refused`),
			expected: share.ScanErrorCode_ScanErrNetwork,
		},
		{
			name:     "no such host returns Network",
			err:      errors.New(`dial tcp: lookup registry.example.com on 8.8.8.8:53: no such host`),
			expected: share.ScanErrorCode_ScanErrNetwork,
		},
		{
			name:     "dial tcp timeout returns Network",
			err:      errors.New(`dial tcp 10.0.0.1:443: i/o timeout`),
			expected: share.ScanErrorCode_ScanErrNetwork,
		},
		{
			name:     "404 not found returns ImageNotFound",
			err:      errors.New(`manifest unknown: manifest unknown`),
			expected: share.ScanErrorCode_ScanErrImageNotFound,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.expected, classifyManifestErr(c.err))
		})
	}
}

func printLayers(t *testing.T, imageInfo *ImageInfo) {
	for i := 0; i < len(imageInfo.Layers); i++ {
		t.Errorf("  [%d]: %s\n", i, imageInfo.Layers[i])
	}
}

func TestCopyLayers1(t *testing.T) {
	var ccmi *registry.ManifestInfo

	imageInfo := &ImageInfo{ID: "test", Cmds: make([]string, 0), Sizes: make(map[string]int64)}
	manV2 := &manifestV2.Manifest{Layers: []distribution.Descriptor{
		{Digest: "1", Size: 1},
		{Digest: "2", Size: 2},
		{Digest: "3", Size: 3},
		{Digest: "4", Size: 4},
	}}

	copyV2Layers(imageInfo, manV2, ccmi) // ccmi is nil
	if len(imageInfo.Layers) != 4 {
		t.Errorf("Incorrect layer count: %d\n", len(imageInfo.Layers))
	}
	if imageInfo.Layers[0] != "4" {
		t.Errorf("Incorrect layer order: [0]=%v\n", imageInfo.Layers[0])
	}
}

func TestCopyLayers2(t *testing.T) {
	imageInfo := &ImageInfo{ID: "test", Cmds: make([]string, 0), Sizes: make(map[string]int64)}
	manV2 := &manifestV2.Manifest{Layers: []distribution.Descriptor{
		{Digest: "1", Size: 1},
		{Digest: "2", Size: 2},
		{Digest: "3", Size: 3},
		{Digest: "4", Size: 4},
	}}
	ccmi := &registry.ManifestInfo{
		Cmds:        []string{"cmd 1", "cmd 2", "cmd 3", "cmd 4", "cmd 5", "cmd 6", "cmd 7"},
		EmptyLayers: []bool{true, false, false, true, false, false, true},
	}

	copyV2Layers(imageInfo, manV2, ccmi)
	if len(imageInfo.Layers) != 7 {
		t.Errorf("Incorrect layer count: %d\n", len(imageInfo.Layers))
	}
	if !reflect.DeepEqual(imageInfo.Layers, []string{"", "4", "3", "", "2", "1", ""}) {
		t.Errorf("Incorrect layers:\n")
		printLayers(t, imageInfo)
	}
}

func TestCopyLayers3(t *testing.T) {
	// This is an error case, where manifest doesn't have enough layers
	imageInfo := &ImageInfo{ID: "test", Cmds: make([]string, 0), Sizes: make(map[string]int64)}
	manV2 := &manifestV2.Manifest{Layers: []distribution.Descriptor{
		{Digest: "1", Size: 1},
		{Digest: "2", Size: 2},
		{Digest: "3", Size: 3},
	}}
	ccmi := &registry.ManifestInfo{
		Cmds:        []string{"cmd 1", "cmd 2", "cmd 3", "cmd 4", "cmd 5", "cmd 6", "cmd 7"},
		EmptyLayers: []bool{true, false, false, true, false, false, true},
	}

	copyV2Layers(imageInfo, manV2, ccmi)
	if len(imageInfo.Layers) != 7 {
		t.Errorf("Incorrect layer count: %d\n", len(imageInfo.Layers))
	}
	if !reflect.DeepEqual(imageInfo.Layers, []string{"", "3", "2", "", "1", "", ""}) {
		t.Errorf("Incorrect layers:\n")
		printLayers(t, imageInfo)
	}
}

func TestCopyLayers4(t *testing.T) {
	// This is an error case, where container config has less non-empty layer count
	imageInfo := &ImageInfo{ID: "test", Cmds: make([]string, 0), Sizes: make(map[string]int64)}
	manV2 := &manifestV2.Manifest{Layers: []distribution.Descriptor{
		{Digest: "1", Size: 1},
		{Digest: "2", Size: 2},
		{Digest: "3", Size: 3},
		{Digest: "4", Size: 4},
	}}
	ccmi := &registry.ManifestInfo{
		Cmds:        []string{"cmd 1", "cmd 2", "cmd 3", "cmd 4", "cmd 5", "cmd 6", "cmd 7"},
		EmptyLayers: []bool{true, false, false, true, false, true, true},
	}

	copyV2Layers(imageInfo, manV2, ccmi)
	if len(imageInfo.Layers) != 7 {
		t.Errorf("Incorrect layer count: %d\n", len(imageInfo.Layers))
	}
	if !reflect.DeepEqual(imageInfo.Layers, []string{"", "4", "3", "", "2", "", ""}) {
		t.Errorf("Incorrect layers:\n")
		printLayers(t, imageInfo)
	}
}

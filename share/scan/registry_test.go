package scan

import (
	"reflect"
	"testing"

	"github.com/docker/distribution"
	manifestV2 "github.com/docker/distribution/manifest/schema2"
	"github.com/neuvector/neuvector/share/scan/registry"
)

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

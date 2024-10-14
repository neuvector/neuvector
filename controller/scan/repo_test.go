package scan

import (
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

var sr1 = share.ScanResult{
	Version:   "1.000",
	Error:     share.ScanErrorCode_ScanErrNone,
	Namespace: "alpine:2.10",
	Vuls: []*share.ScanVulnerability{
		{Name: "CVE-2020-0001", Severity: "High", PublishedDate: "1546300800"},
		{Name: "CVE-2019-0001", Severity: "Medium", PublishedDate: "1577836800"},
		{Name: "CVE-2018-0001", Severity: "High", PublishedDate: "1514764800"},
	},
	Repository: "neuvector/alpine",
	Tag:        "2.10.1",
	Digest:     "sha256:111987",
	ImageID:    "111123",
	Layers:     make([]*share.ScanLayerResult, 0),
	Envs:       make([]string, 0),
	Labels:     make(map[string]string),
	Modules:    make([]*share.ScanModule, 0),
	Secrets:    nil,
	Cmds:       []string{"first layer command", "second layer command"},
	SetIdPerms: nil,
}

var sr2 = share.ScanResult{
	Version:   "1.001",
	Error:     share.ScanErrorCode_ScanErrNone,
	Namespace: "alpine:2.10",
	Vuls: []*share.ScanVulnerability{
		{Name: "CVE-2020-0001", Severity: "High", PublishedDate: "1546300800"},
		{Name: "CVE-2019-0001", Severity: "Medium", PublishedDate: "1577836800"},
		{Name: "CVE-2020-0002", Severity: "Medium", PublishedDate: "1546300900"},
	},
	Repository: "neuvector/alpine",
	Tag:        "2.10.1",
	Digest:     "sha256:222987",
	ImageID:    "222123",
	Layers:     make([]*share.ScanLayerResult, 0),
	Envs:       make([]string, 0),
	Labels:     make(map[string]string),
	Modules:    make([]*share.ScanModule, 0),
	Secrets:    nil,
	Cmds:       []string{"first layer command", "second layer command"},
	SetIdPerms: nil,
}

var sr3 = share.ScanResult{
	Version:   "1.001",
	Error:     share.ScanErrorCode_ScanErrNone,
	Namespace: "alpine:2.10",
	Vuls: []*share.ScanVulnerability{
		{Name: "CVE-2020-0001", Severity: "High", PublishedDate: "1546300800"},
		{Name: "CVE-2019-0001", Severity: "Medium", PublishedDate: "1577836800"},
	},
	Registry:   "https://docker.io/",
	Repository: "neuvector/alpine",
	Tag:        "2.10.1",
	Digest:     "sha256:333987",
	ImageID:    "333123",
	Layers:     make([]*share.ScanLayerResult, 0),
	Envs:       make([]string, 0),
	Labels:     make(map[string]string),
	Modules:    make([]*share.ScanModule, 0),
	Secrets:    nil,
	Cmds:       []string{"first layer command", "second layer command"},
	SetIdPerms: nil,
}

func TestLocalRepoScan(t *testing.T) {
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init([]*share.CLUSPolicyRule{}, []*share.CLUSGroup{})
	clusHelper = &mockCluster

	smd = &scanMethod{mutexLog: log.New(), scanLog: log.New()}
	newRepoScanRegistry(common.RegistryRepoScanName)

	// Store scan result
	err := smd.StoreRepoScanResult(&sr1)
	if err != nil {
		t.Errorf("Failed to store result: %+v", err)
	}

	// retrieve sum from mock cluster helper
	key := share.CLUSRegistryImageStateKey(common.RegistryRepoScanName, sr1.ImageID)
	sum, ok := mockCluster.ScanSums[key]
	if !ok {
		t.Errorf("Unable to retrieve summary: key=%+v", key)
	}

	// Simulate sum update callback
	RegistryImageStateUpdate(common.RegistryRepoScanName, sr1.ImageID, sum, false, nil)

	// Check image cache
	c, ok := repoScanRegistry.cache[sr1.ImageID]
	if !ok {
		t.Errorf("Unable to local image cache: id=%+v", sr1.ImageID)
	} else if c.highVuls != 2 || c.medVuls != 1 {
		t.Errorf("Incorrect CVE count: high=%+v, medium=%+v", c.highVuls, c.medVuls)
	} else if h := c.vulInfo["High"]; len(h) != 2 {
		t.Errorf("Incorrect CVE info high count: high=%+v", len(h))
	} else if m := c.vulInfo["Medium"]; len(m) != 1 {
		t.Errorf("Incorrect CVE info medium count: medium=%+v", len(m))
	}

	// Get summary for adm. ctrl with registry
	regs := utils.NewSet("https://dockerhub.com")
	admSum := GetScannedImageSummary(regs, "neuvector/alpine", "2.10.1", nil)
	if len(admSum) != 1 {
		t.Errorf("Incorrect scanned image summary count: %+v", len(admSum))
	}
	if admSum[0].ImageID != sr1.ImageID {
		t.Errorf("Incorrect scanned image summary id: %+v", admSum[0].ImageID)
	}

	// Store another result, same name different ID
	_ = smd.StoreRepoScanResult(&sr2)
	key = share.CLUSRegistryImageStateKey(common.RegistryRepoScanName, sr1.ImageID)
	_, ok = mockCluster.ScanSums[key]
	if !ok {
		t.Errorf("Unable to retrieve old summary: key=%+v", key)
	}
	key = share.CLUSRegistryImageStateKey(common.RegistryRepoScanName, sr2.ImageID)
	sum, ok = mockCluster.ScanSums[key]
	if !ok {
		t.Errorf("Unable to retrieve new summary: key=%+v", key)
	}
	RegistryImageStateUpdate(common.RegistryRepoScanName, sr2.ImageID, sum, false, nil)

	// Get summary for adm. ctrl with registry, should return new image
	regs = utils.NewSet("https://dockerhub.com")
	admSum = GetScannedImageSummary(regs, "neuvector/alpine", "2.10.1", nil)
	if len(admSum) != 1 {
		t.Errorf("Incorrect scanned image summary count: %+v", len(admSum))
	}
	if admSum[0].ImageID != sr2.ImageID {
		t.Errorf("Incorrect scanned image summary id: %+v", admSum[0].ImageID)
	}

	// Get old image summary by digest
	regs = utils.NewSet("https://dockerhub.com")
	admSum = GetScannedImageSummary(regs, "neuvector/alpine", sr1.Digest, nil)
	if len(admSum) != 1 {
		t.Errorf("Incorrect scanned image summary count: %+v", len(admSum))
	}
	if admSum[0].ImageID != sr1.ImageID {
		t.Errorf("Incorrect scanned image summary id: %+v", admSum[0])
	}
}

func TestRemoteRepoScan(t *testing.T) {
	preTest()

	var mockCluster kv.MockCluster
	mockCluster.Init([]*share.CLUSPolicyRule{}, []*share.CLUSGroup{})
	clusHelper = &mockCluster

	smd = &scanMethod{mutexLog: log.New(), scanLog: log.New()}
	newRepoScanRegistry(common.RegistryRepoScanName)

	// store a local image
	_ = smd.StoreRepoScanResult(&sr1)
	key := share.CLUSRegistryImageStateKey(common.RegistryRepoScanName, sr1.ImageID)
	sum := mockCluster.ScanSums[key]
	RegistryImageStateUpdate(common.RegistryRepoScanName, sr1.ImageID, sum, false, nil)

	// store a remote image
	_ = smd.StoreRepoScanResult(&sr3)
	key = share.CLUSRegistryImageStateKey(common.RegistryRepoScanName, sr3.ImageID)
	sum = mockCluster.ScanSums[key]
	RegistryImageStateUpdate(common.RegistryRepoScanName, sr3.ImageID, sum, false, nil)

	// search image that registry matches
	regs := utils.NewSet("https://dockerhub.com", "https://docker.io/")
	admSum := GetScannedImageSummary(regs, "neuvector/alpine", "2.10.1", nil)
	if len(admSum) != 1 {
		t.Errorf("Incorrect scanned image summary count: %+v", len(admSum))
	}
	if admSum[0].ImageID != sr3.ImageID {
		t.Errorf("Incorrect scanned image summary id: %+v", admSum[0].ImageID)
	}

	// search image that registry doesn't match, local image should be found
	regs = utils.NewSet("https://dockerhub.com")
	admSum = GetScannedImageSummary(regs, "neuvector/alpine", "2.10.1", nil)
	if len(admSum) != 1 {
		t.Errorf("Incorrect scanned image summary count: %+v", len(admSum))
	}
	if admSum[0].ImageID != sr1.ImageID {
		t.Errorf("Incorrect scanned image summary id: %+v", admSum[0].ImageID)
	}
}

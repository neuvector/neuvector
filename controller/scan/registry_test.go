package scan

import (
	"context"
	"os"
	"testing"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/scheduler"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

// type testDriver struct {
// 	registryDriver
// }

// func (d *testDriver) Login(cfg *share.CLUSRegistryConfig) (bool, error) {
// 	return false, nil
// }

// func (d *testDriver) Logout() {
// }

func preTest() {
	log.SetOutput(os.Stdout)
	log.SetFormatter(&utils.LogFormatter{Module: "TEST"})
	log.SetLevel(log.FatalLevel)

	scanLog := log.New()
	scanLog.Out = os.Stdout
	scanLog.Formatter = &utils.LogFormatter{Module: "TEST"}
	scanLog.Level = log.FatalLevel

	smd = &scanMethod{isLeader: true, isScanner: true, scanLog: scanLog}
}

// func preTestDebug() {
// 	preTest()
// 	log.SetLevel(log.DebugLevel)
// 	smd.scanLog.Level = log.DebugLevel
// }

func postTest() {
	log.SetLevel(log.DebugLevel)
}

func newTestScanContext() *scanContext {
	ctx, cancel := context.WithCancel(context.Background())
	return &scanContext{ctx: ctx, cancel: cancel}
}

func TestImageScanFresh(t *testing.T) {
	preTest()

	var mockCluster kv.MockCluster
	clusHelper = &mockCluster

	var scher scheduler.Schd
	scher.Init()
	regScher = &scher

	var newm map[string]*imageMeta
	var count int

	r := newRegistry(&share.CLUSRegistryConfig{
		Name: "test", Type: share.RegistryTypeDocker, Schedule: api.ScanSchAuto,
	})
	r.sctx = newTestScanContext()

	r.scheduleScanImagesOnDemand(r.sctx, nil)
	count = r.taskQueue.Cardinality()
	if count != 0 {
		t.Errorf("Task count: %+v\n", count)
	}

	// Start scan with some images
	newm = map[string]*imageMeta{
		"1": {id: "1", digest: "d1", images: utils.NewSet(
			share.CLUSImage{Repo: "image1", Tag: "latest"},
			share.CLUSImage{Repo: "image1", Tag: "1.0"},
		)},
	}
	r.scheduleScanImagesOnDemand(r.sctx, newm)
	count = r.taskQueue.Cardinality()
	if count != 1 {
		t.Errorf("Task count: %+v\n", count)
	}
	if s, ok := r.summary["1"]; !ok {
		t.Errorf("Summary not found: %+v\n", count)
	} else if s.Status != api.ScanStatusScheduled {
		t.Errorf("Summary status: %+v\n", s.Status)
	} else if len(s.Images) != 2 {
		t.Errorf("Summary images: %+v\n", len(s.Images))
	}

	// Add a new tag but same image
	newm = map[string]*imageMeta{
		"1": {id: "1", digest: "d1", images: utils.NewSet(
			share.CLUSImage{Repo: "image1", Tag: "1.1"},
		)},
	}
	r.scheduleScanImagesOnDemand(r.sctx, newm)
	count = r.taskQueue.Cardinality()
	if count != 1 {
		t.Errorf("Task count: %+v\n", count)
	}
	if s, ok := r.summary["1"]; !ok {
		t.Errorf("Summary not found: %+v\n", count)
	} else if s.Status != api.ScanStatusScheduled {
		t.Errorf("Summary status: %+v\n", s.Status)
	} else if len(s.Images) != 3 {
		t.Errorf("Summary images: %+v\n", len(s.Images))
	}

	// Add a new tag and different image
	newm = map[string]*imageMeta{
		"2": {id: "2", digest: "d2", images: utils.NewSet(
			share.CLUSImage{Repo: "image1", Tag: "2.0"},
		)},
	}
	r.scheduleScanImagesOnDemand(r.sctx, newm)
	count = r.taskQueue.Cardinality()
	if count != 2 {
		t.Errorf("Task count: %+v\n", count)
	}
	if s, ok := r.summary["2"]; !ok {
		t.Errorf("Summary not found: %+v\n", count)
	} else if s.Status != api.ScanStatusScheduled {
		t.Errorf("Summary status: %+v\n", s.Status)
	} else if len(s.Images) != 1 {
		t.Errorf("Summary images: %+v\n", len(s.Images))
	}

	// Re-start scan instead of add images
	newm = map[string]*imageMeta{
		"2": {id: "2", digest: "d2", images: utils.NewSet(
			share.CLUSImage{Repo: "image1", Tag: "2.0"},
		)},
	}
	r.stopScan()
	r.scheduleScanImagesOnDemand(r.sctx, newm)
	count = r.taskQueue.Cardinality()
	if count != 1 {
		t.Errorf("Task count: %+v\n", count)
	}
	if s, ok := r.summary["2"]; !ok {
		t.Errorf("Summary not found: %+v\n", count)
	} else if s.Status != api.ScanStatusScheduled {
		t.Errorf("Summary status: %+v\n", s.Status)
	} else if len(s.Images) != 1 {
		t.Errorf("Summary images: %+v\n", len(s.Images))
	}

	postTest()
}

func TestImageScanCont(t *testing.T) {
	preTest()

	var mockCluster kv.MockCluster
	clusHelper = &mockCluster

	var scher scheduler.Schd
	scher.Init()
	regScher = &scher

	var newm map[string]*imageMeta
	var count int

	r := newRegistry(&share.CLUSRegistryConfig{
		Name: "test", Type: share.RegistryTypeDocker, Schedule: api.ScanSchAuto,
	})
	r.sctx = newTestScanContext()
	r.summary = map[string]*share.CLUSRegistryImageSummary{
		"2": {ImageID: "2", Digest: "d2",
			Status:    api.ScanStatusFinished,
			ScanFlags: share.ScanFlagCVE | share.ScanFlagFiles,
			Images: []share.CLUSImage{
				{Repo: "image2", Tag: "latest"},
				{Repo: "image2", Tag: "1.0"},
			}},
		"3": {ImageID: "3", Digest: "d3",
			Status: api.ScanStatusIdle,
			Images: []share.CLUSImage{
				{Repo: "image3", Tag: "latest"},
			}},
	}

	// Add a new tag but same image
	newm = map[string]*imageMeta{
		"1": {id: "1", digest: "d1", images: utils.NewSet(
			share.CLUSImage{Repo: "image1", Tag: "latest"},
			share.CLUSImage{Repo: "image1", Tag: "1.0"},
		)},
	}
	r.scheduleScanImagesOnDemand(r.sctx, newm)
	count = r.taskQueue.Cardinality()
	if count != 1 {
		t.Errorf("Task count: %+v\n", count)
	}
	if s, ok := r.summary["1"]; !ok {
		t.Errorf("Summary not found: %+v\n", count)
	} else if s.Status != api.ScanStatusScheduled {
		t.Errorf("Summary status: %+v\n", s.Status)
	} else if len(s.Images) != 2 {
		t.Errorf("Summary images: %+v\n", len(s.Images))
	}

	// Add a finished image
	newm = map[string]*imageMeta{
		"2": {id: "2", digest: "d2", images: utils.NewSet(
			share.CLUSImage{Repo: "image2", Tag: "2.0"},
		)},
	}
	r.scheduleScanImagesOnDemand(r.sctx, newm)
	count = r.taskQueue.Cardinality()
	if count != 1 {
		t.Errorf("Task count: %+v\n", count)
	}
	if s, ok := r.summary["2"]; !ok {
		t.Errorf("Summary not found: %+v\n", count)
	} else if s.Status != api.ScanStatusFinished {
		t.Errorf("Summary status: %+v\n", s.Status)
	} else if len(s.Images) != 3 {
		t.Errorf("Summary images: %+v\n", len(s.Images))
	}

	postTest()
}

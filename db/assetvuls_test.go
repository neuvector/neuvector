package db

import (
	"encoding/json"
	"testing"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
	"github.com/stretchr/testify/assert"
)

func TestPopulateAssetVul(t *testing.T) {
	err := CreateVulAssetDb(true)
	if err != nil {
		t.Errorf("CreateDatabase() returns %v", err)
	}

	// populate an workload asset to database
	workloadID := "0c0156a5c9e349b9fe0596db0a3846cce6de655936781386764040c6532841f3"
	dbAssetVul := generateWorkloadDbAssetVul(workloadID)
	err = PopulateAssetVul(dbAssetVul)
	if err != nil {
		t.Errorf("PopulateAssetVul returns %v", err)
	}

	// read it back
	dbAssetVulReadBack, err := GetAssetVulIDByAssetID(workloadID)
	if err != nil {
		t.Errorf("GetAssetVulIDByAssetID returns %v", err)
	}

	// verify the assetid
	if dbAssetVulReadBack.AssetID != workloadID {
		t.Errorf("Read back asset id doesn't match. Expected %v, but got %v", workloadID, dbAssetVulReadBack.AssetID)
	}

	t.Log("TestAssetVul completed successfully.")
}

func TestUpdateHostContainerCount(t *testing.T) {
	err := CreateVulAssetDb(true)
	if err != nil {
		t.Errorf("CreateDatabase() returns %v", err)
	}

	// populate an node asset to database with initial container count to 50
	hostID := "ddd156a5c9e349b9fe0596db0a3846cce6de655936781386764040c6532841f3"
	containerCount := 50
	dbAssetVul := generateHostDbAssetVul(hostID, containerCount)
	err = PopulateAssetVul(dbAssetVul)
	if err != nil {
		t.Errorf("PopulateAssetVul returns %v", err)
	}

	// update container count to 60
	newContainerCount := 60
	err = UpdateHostContainers(hostID, newContainerCount)
	if err != nil {
		t.Errorf("UpdateHostContainers returns %v", err)
	}

	// read it back
	vulMap := make(map[string]*DbVulAsset, 0)
	assets := make([]string, 0)
	assets = append(assets, hostID)
	queryFilter := &VulQueryFilter{Filters: &api.VulQueryFilterViewModel{
		ViewType: "all",
	}}
	cvePackages := make(map[string]map[string]utils.Set)
	assetViews, err := getHostAssetView(vulMap, assets, queryFilter, cvePackages)
	if err != nil {
		t.Errorf("getHostAssetView returns %v", err)
	}

	if len(assetViews) != 1 {
		t.Errorf("Not return correct number of asset view records. Expected %v, but got %v", 1, len(assetViews))
	}

	if assetViews[0].Containers != newContainerCount {
		t.Errorf("Read back container count doesn't match. Expected %v, but got %v", newContainerCount, assetViews[0].Containers)
	}

	t.Log("TestUpdateHostContainerCount completed successfully.")
}

func TestGetImageAssetSessionIncludesOSScanStatus(t *testing.T) {
	err := CreateVulAssetDb(true)
	assert.NoError(t, err)

	SetGetCVECountFunc(func(string, string) (int, int, int, error) {
		return 0, 5, 3, nil
	})

	imageID := "img-156a5c9e349b9fe0596db0a3846cce6de655936781386764040c6532841f3"
	err = PopulateAssetVul(generateImageDbAssetVul(imageID))
	assert.NoError(t, err)

	queryToken := "abc123def456"
	queryFilter := &AssetQueryFilter{
		QueryToken: queryToken,
		QueryStart: 0,
		QueryCount: -1,
		Filters: &api.AssetQueryFilterViewModel{
			Type:          AssetImage,
			OrderByColumn: "repository",
			OrderByType:   "asc",
		},
	}

	allowed := map[string]utils.Set{
		AssetImage: utils.NewSet(imageID),
	}
	_, _, err = CreateImageAssetSession(allowed, queryFilter)
	assert.NoError(t, err)

	filterBytes, err := json.Marshal(queryFilter)
	assert.NoError(t, err)

	_, err = PopulateQueryStat(&QueryStat{
		Token:        queryToken,
		CreationTime: 1,
		LoginType:    0,
		LoginName:    "test",
		Data1:        string(filterBytes),
		FileDBReady:  0,
		Type:         QueryStateType_Asset,
	})
	assert.NoError(t, err)
	defer func() {
		if err := DeleteQuerySessionByToken(queryToken); err != nil {
			t.Logf("DeleteQuerySessionByToken returns %v", err)
		}
	}()

	assets, quickFilterMatched, err := GetImageAssetSession(queryFilter)
	assert.NoError(t, err)

	assert.Equal(t, 1, quickFilterMatched)

	assert.Equal(t, 1, len(assets))

	assert.Equal(t, "OSScanStatusSupported", assets[0].OSScanStatus)
}

func generateHostDbAssetVul(assetid string, containerCount int) *DbAssetVul {
	d := &DbAssetVul{
		Type:         AssetNode,
		AssetID:      assetid,
		Name:         "ubuntu2204-A",
		CVE_critical: 2,
		CVE_high:     10,
		CVE_medium:   6,
		CVE_low:      3,
		N_os:         "Ubuntu 22.04 LTS",
		N_kernel:     "5.15.0-78-generic",
		N_cpus:       2,
		N_memory:     8323616768,
		N_containers: containerCount,
	}

	d.Policy_mode = "Discover"
	return d
}

func generateWorkloadDbAssetVul(assetid string) *DbAssetVul {
	d := &DbAssetVul{
		Type:             AssetWorkload,
		AssetID:          assetid,
		Name:             "my-dep3-7b64995fb5-ftqln",
		W_domain:         "default",
		W_service_group:  "my-dep3.default",
		W_workload_image: "alpine-5ff9c682:5ff9c682-1c02-4b06-a0fd-011531cf1fc6",
		CVE_critical:     2,
		CVE_high:         10,
		CVE_medium:       6,
		CVE_low:          3,
	}

	apps := []string{"HTTP", "TCP/9153", "UDP/53", "TCP/53"}
	b, err := json.Marshal(apps)
	if err == nil {
		d.W_applications = string(b)
	}

	d.Policy_mode = "Discover"

	d.Scanned_at = "2023-12-29T08:46:32Z"
	return d
}

func generateImageDbAssetVul(assetid string) *DbAssetVul {
	images, err := json.Marshal([]share.CLUSImage{{Repo: "library/nginx", Tag: "1.25"}})
	if err != nil {
		images = []byte("[]")
	}

	return &DbAssetVul{
		Type:              AssetImage,
		AssetID:           assetid,
		Name:              "library/nginx:1.25",
		CVE_critical:      2,
		CVE_high:          5,
		CVE_medium:        3,
		I_repository_name: "registry-1",
		I_repository_url:  "https://registry.example.com/",
		I_base_os:         "debian",
		I_os_scan_status:  "OSScanStatusSupported",
		I_created_at:      "2024-01-02T03:04:05Z",
		I_scanned_at:      "2024-01-03T03:04:05Z",
		I_digest:          "sha256:abc",
		I_images:          string(images),
	}
}

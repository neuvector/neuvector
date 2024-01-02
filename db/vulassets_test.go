package db

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share/utils"
)

func TestPopulateVulAssets(t *testing.T) {
	err := CreateVulAssetDb(true)
	if err != nil {
		t.Errorf("CreateDatabase() returns %v", err)
	}

	workloadID := "0c0156a5c9e349b9fe0596db0a3846cce6de655936781386764040c6532841f3"
	baseOS := "alpine"
	cveNames := []string{"CVE-2030-1001", "CVE-2030-2001", "CVE-2030-3001"}
	vuls := geneateDummyVul(cveNames)
	for _, vul := range vuls {
		if err := PopulateVulAsset(TypeWorkload, workloadID, vul, baseOS); err != nil {
			t.Errorf("PopulateVulAsset failed, err = %v", err)
		}
	}

	dbAssetVul := generateWorkloadDbAssetVul(workloadID)
	err = PopulateAssetVul(dbAssetVul)
	if err != nil {
		t.Errorf("PopulateAssetVul returns %v", err)
	}

	allowed := map[string]utils.Set{
		AssetWorkload: utils.NewSet(),
		AssetNode:     utils.NewSet(),
		AssetImage:    utils.NewSet(),
		AssetPlatform: utils.NewSet(),
	}
	allowed[AssetWorkload].Add(workloadID)

	queryFilter := &VulQueryFilter{Filters: &api.VulQueryFilterViewModel{
		ViewType: "all",
	}}
	filteredMap := make(map[string]bool)

	dbVulAssets, nTotalCVE, err := FilterVulAssets(allowed, queryFilter, filteredMap)
	if err != nil {
		t.Errorf("FilterVulAssets() returns %v", err)
	}

	// check cve count
	if len(cveNames) != nTotalCVE {
		t.Errorf("FilterVulAssets returned cve count %d, expected %d", nTotalCVE, len(cveNames))
	}

	// check vulassets count
	if len(dbVulAssets) != len(cveNames) {
		t.Errorf("FilterVulAssets returned vulassets count %d, expected %d", len(dbVulAssets), len(cveNames))
	}

	// check each cve name appear
	for _, vul := range dbVulAssets {
		if !containsString(cveNames, vul.Name) {
			t.Errorf("CVE name is not listed in original list, %s", vul.Name)
		}
	}

	t.Log("PopulateVulAssets completed successfully.")
}

func generateWorkloadDbAssetVul(assetid string) *DbAssetVul {
	d := &DbAssetVul{
		Type:             AssetWorkload,
		AssetID:          assetid,
		Name:             "my-dep3-7b64995fb5-ftqln",
		W_domain:         "default",
		W_service_group:  "my-dep3.default",
		W_workload_image: "alpine-5ff9c682:5ff9c682-1c02-4b06-a0fd-011531cf1fc6",
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
	allCVEs := []string{"CVE-2030-1001", "CVE-2030-2001", "CVE-2030-3001"}
	b, err = json.Marshal(allCVEs)
	if err == nil {
		d.CVE_lists = string(b)
	}

	d.Scanned_at = "2023-12-29T08:46:32Z"
	return d
}

func geneateDummyVul(cveNames []string) []*api.RESTVulnerability {
	vuls := make([]*api.RESTVulnerability, 0)
	for _, name := range cveNames {
		v := &api.RESTVulnerability{
			Name:           name,
			Score:          9.8,
			Severity:       "Critical",
			Vectors:        "Local",
			Description:    "A critical security vulnerability affecting the system.",
			FileName:       "system_vuln.txt",
			PackageName:    "system-package",
			PackageVersion: "2.0.0",
			FixedVersion:   "2.0.1",
			Link:           fmt.Sprintf("https://example.com/%s", name),
			ScoreV3:        9.5,
			VectorsV3:      "Local",
			PublishedTS:    1672531200, // UNIX timestamp for January 1, 2023
			LastModTS:      1672531200,
			CPEs:           []string{"cpe:/o:linux:linux_kernel:4.18.0"},
			CVEs:           []string{name},
			FeedRating:     "5 stars",
			InBaseImage:    false,
			Tags:           []string{"security", "local vulnerability"},
			DbKey:          "abcdef123456",
		}

		vuls = append(vuls, v)
	}
	return vuls
}

func containsString(slice []string, target string) bool {
	for _, value := range slice {
		if value == target {
			return true
		}
	}
	return false
}

package rest

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/neuvector/neuvector/db"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
)

func perf_createDummyVulAssets(q *db.VulQueryFilter) error {

	howManyAssets := q.CreateDummyAsset_Asset
	for i := 0; i < howManyAssets; i++ {
		vuls := perf_randomSelectCVEs(q.CreateDummyAsset_CVE_per_asset) // random pick from cvedb

		assetid := "xx" + utils.GetRandomID(30, "")
		dbAssetVul := perf_generateWorkloadDbAssetVul(assetid, vuls)

		db.PopulateAssetVul(dbAssetVul)
	}

	return nil
}

// func perf_randomSelectVuls(vuls []*api.RESTVulnerability, count int) []*api.RESTVulnerability {
// 	// Seed the random number generator with the current time
// 	rand.Seed(time.Now().UnixNano())

// 	// Define the maximum value (exclusive)
// 	maxValue := len(vuls)

// 	results := make([]*api.RESTVulnerability, 0)
// 	for i := 0; i < count; i++ {
// 		randomNumber := rand.Intn(maxValue)
// 		results = append(results, vuls[randomNumber])
// 	}
// 	return results
// }

// "upstream:CVE-2015-8324"
func _get_cvename(cvename string) string {
	parts := strings.Split(cvename, ":")
	if len(parts) >= 2 {
		return parts[1]
	}
	return cvename
}

func perf_generateWorkloadDbAssetVul(assetid string, vuls []string) *db.DbAssetVul {
	podName := fmt.Sprintf("workload-%s", utils.GetRandomID(6, ""))
	domain := fmt.Sprintf("domain-%s", utils.GetRandomID(3, ""))
	serviceGroup := fmt.Sprintf("service-%s", utils.GetRandomID(3, ""))
	workloadImage := fmt.Sprintf("image-%s", utils.GetRandomID(6, ""))

	cveCount := len(vuls)
	oneThird := cveCount / 3

	var highs, meds, lows []string
	for i := 0; i < oneThird; i++ {
		highs = append(highs, _get_cvename(vuls[i]))
	}

	for i := oneThird; i < oneThird*2; i++ {
		meds = append(meds, _get_cvename(vuls[i]))
	}

	for i := oneThird * 2; i < cveCount; i++ {
		lows = append(lows, _get_cvename(vuls[i]))
	}

	//
	d := &db.DbAssetVul{
		Type:             "workload",
		AssetID:          assetid,
		Name:             podName,
		W_domain:         domain,
		W_service_group:  serviceGroup,
		W_workload_image: workloadImage,
		CVE_high:         len(highs),
		CVE_medium:       len(meds),
		CVE_low:          len(lows),
		Policy_mode:      "Discover",
	}

	//
	apps := []string{"TCP/6782", "TCP/6783", "TCP/6784", "UDP/6783", "TCP/6781"}
	b, err := json.Marshal(apps)
	if err == nil {
		d.W_applications = string(b)
	}

	d.Scanned_at = "2023-12-29T08:46:32Z"

	return d
}

func perf_randomSelectCVEs(count int) []string {
	return scanUtils.Perf_getRandomCVEs(count)
}

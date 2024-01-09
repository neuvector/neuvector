package rest

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strconv"
	"time"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/db"
	"github.com/neuvector/neuvector/share/utils"
)

func perf_createDummyVulAssets(q *db.VulQueryFilter) error {
	allVuls := perf_geneateDummyVul(q.CreateDummyAsset_CVE)

	howManyAssets := q.CreateDummyAsset_Asset
	for i := 0; i < howManyAssets; i++ {
		cveCount := q.CreateDummyAsset_CVE_per_asset
		vuls := perf_randomSelectVuls(allVuls, cveCount)

		assetid := "xx" + utils.GetRandomID(30, "")
		dbAssetVul := perf_generateWorkloadDbAssetVul(assetid, vuls, cveCount)

		for _, vul := range vuls {
			db.PopulateVulAsset(db.TypeWorkload, assetid, vul, "")
		}

		db.PopulateAssetVul(dbAssetVul)
	}

	return nil
}

func perf_randomSelectVuls(vuls []*api.RESTVulnerability, count int) []*api.RESTVulnerability {
	// Seed the random number generator with the current time
	rand.Seed(time.Now().UnixNano())

	// Define the maximum value (exclusive)
	maxValue := len(vuls)

	results := make([]*api.RESTVulnerability, 0)
	for i := 0; i < count; i++ {
		randomNumber := rand.Intn(maxValue)
		results = append(results, vuls[randomNumber])
	}
	return results
}

func perf_geneateDummyVul(nCount int) []*api.RESTVulnerability {
	vuls := make([]*api.RESTVulnerability, 0)
	for i := 1; i <= nCount; i++ {
		name := fmt.Sprintf("CVE-2030-%05d", i)
		vuls = append(vuls, perf_createOneVul(name))
	}
	return vuls
}

func perf_createOneVul(name string) *api.RESTVulnerability {
	description := fmt.Sprintf("[%s] Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent: Serialization). Supported versions that are affected are Java SE: 6u161, 7u151, 8u144 and 9; Java SE Embedded: 8u144; JRockit: R28.3.15. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. Successful attacks require human interaction from a person other than the attacker. Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded, JRockit. Note: This vulnerability can be exploited through sandboxed Java Web Start applications and sandboxed Java applets. It can also be exploited by supplying data to APIs in the specified Component without using sandboxed Java Web Start applications or sandboxed Java applets, such as through a web service. CVSS 3.0 Base Score 3.1 (Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L).", name)

	vul := &api.RESTVulnerability{
		Name:           name,
		Vectors:        "AV:N/AC:H/Au:N/C:P/I:N/A:N",
		Description:    description,
		FileName:       "system_vuln.txt",
		PackageName:    "system-package",
		PackageVersion: "2.0.0",
		FixedVersion:   "2.0.1",
		VectorsV3:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
		PublishedTS:    1672531200,
		LastModTS:      1672531200,
		CPEs:           []string{"cpe:/o:linux:linux_kernel:4.18.0"},
		CVEs:           []string{name},
		InBaseImage:    false,
		Tags:           []string{"security", "local vulnerability"},
		DbKey:          "abcdef123456",
	}

	// randomize Score, ScoreV3
	// Generate a random float between 1 and 10
	// trimmedValue := trimFloat(value, 1)
	vul.Score = trimFloat(rand.Float32()*9+1, 1)
	vul.ScoreV3 = trimFloat(rand.Float32()*9+1, 1)
	vul.Link = fmt.Sprintf("https://example.com/%s", name)

	if vul.ScoreV3 <= 3.9 {
		vul.Severity = "Low"
	} else if vul.ScoreV3 > 3.9 && vul.ScoreV3 <= 6.9 {
		vul.Severity = "Medium"
	} else {
		vul.Severity = "High"
	}

	// randomize PackageName
	vul.PackageName = fmt.Sprintf("system-package-%s", utils.GetRandomID(4, ""))

	return vul
}

func perf_generateWorkloadDbAssetVul(assetid string, vuls []*api.RESTVulnerability, cveCount int) *db.DbAssetVul {
	podName := fmt.Sprintf("workload-%s", utils.GetRandomID(6, ""))
	domain := fmt.Sprintf("domain-%s", utils.GetRandomID(3, ""))
	serviceGroup := fmt.Sprintf("service-%s", utils.GetRandomID(3, ""))
	workloadImage := fmt.Sprintf("image-%s", utils.GetRandomID(6, ""))

	oneThird := cveCount / 3

	var highs, meds, lows []string
	for i := 0; i < oneThird; i++ {
		highs = append(highs, vuls[i].Name)
	}

	for i := oneThird; i < oneThird*2; i++ {
		meds = append(meds, vuls[i].Name)
	}

	for i := oneThird * 2; i < cveCount; i++ {
		lows = append(lows, vuls[i].Name)
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

	//
	allCVEs := append(append(highs, meds...), lows...)
	b, err = json.Marshal(allCVEs)
	if err == nil {
		d.CVE_lists = string(b)
	}
	d.Scanned_at = "2023-12-29T08:46:32Z"

	return d
}

func trimFloat(value float32, precision int) float32 {
	trimmedFloat, _ := strconv.ParseFloat(fmt.Sprintf(fmt.Sprintf("%%.%df", precision), value), 32)
	return float32(trimmedFloat)
}

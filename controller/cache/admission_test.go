package cache

import (
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg/admission"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"

	"strings"
	"testing"
)

func TestAdmCriteria2CLUS(t *testing.T) {
	reservedRegs["dockerhub"] = []string{"https://index.docker.io/", "https://registry.hub.docker.com/", "https://registry-1.docker.io/"}

	restCrtArr := []*api.RESTAdmRuleCriterion{
		&api.RESTAdmRuleCriterion{
			Name:  share.CriteriaKeyImageRegistry,
			Op:    share.CriteriaOpContainsAny,
			Value: "dockerhub, localhost, dockerhub, https://localhost",
		},
	}

	clusCrtArr, _ := AdmCriteria2CLUS(restCrtArr) //[]*share.CLUSAdmRuleCriterion
	if len(clusCrtArr) == len(restCrtArr) {
		got := utils.NewSetFromSliceKind(strings.Split(clusCrtArr[0].Value, ","))
		expected := utils.NewSet("https://index.docker.io/", "https://registry.hub.docker.com/", "https://registry-1.docker.io/", "https://localhost/")
		if got.Cardinality() != expected.Cardinality() || got.Intersect(expected).Cardinality() != got.Cardinality() {
			t.Errorf("Unexpected CLUSAdmRuleCriterion[1]: %+v for %+v\n", clusCrtArr, restCrtArr)
		}
	} else {
		t.Errorf("Unexpected CLUSAdmRuleCriterion[2]: %+v for %+v\n", clusCrtArr, restCrtArr)
	}

	restCrtArr = []*api.RESTAdmRuleCriterion{
		&api.RESTAdmRuleCriterion{
			Name:  share.CriteriaKeyImageRegistry,
			Op:    share.CriteriaOpContainsAny,
			Value: "https://INDEX.docker.io, index.docker.io, https://localhost, 10.1.127.3:5000/neuvector/toolbox/selvam_coreos_http, https://10.1.127.3:5000/neuvector",
		},
	}

	clusCrtArr, _ = AdmCriteria2CLUS(restCrtArr) //[]*share.CLUSAdmRuleCriterion
	if len(clusCrtArr) == len(restCrtArr) {
		got := utils.NewSetFromSliceKind(strings.Split(clusCrtArr[0].Value, ","))
		expected := utils.NewSet("https://index.docker.io/", "https://10.1.127.3:5000/", "https://localhost/")
		if got.Cardinality() != expected.Cardinality() || got.Intersect(expected).Cardinality() != got.Cardinality() {
			t.Errorf("Unexpected CLUSAdmRuleCriterion[1]: %+v for %+v\n", clusCrtArr, restCrtArr)
		}
	} else {
		t.Errorf("Unexpected CLUSAdmRuleCriterion[2]: %+v for %+v\n", clusCrtArr, restCrtArr)
	}
}

func TestNormalizeImageValue(t *testing.T) {
	preTest()

	input := map[string]string{
		"localhost":              "https://localhost/",
		"localhost:8080":         "https://localhost:8080/",
		"https://localhost:8080": "https://localhost:8080/",
		"10.1.127.3:5000/neuvector/toolbox/selvam_coreos_http":        "https://10.1.127.3:5000/neuvector/toolbox/selvam_coreos_http",
		"10.1.127.3:5000/neuvector/toolbox/selvam_coreos_http:latest": "https://10.1.127.3:5000/neuvector/toolbox/selvam_coreos_http:latest",
		"docker.io/nvlab/iperf":                                       "https://docker.io/nvlab/iperf",
		"docker.io/nvlab/iperf:RELEASE":                               "https://docker.io/nvlab/iperf:RELEASE",
		"docker.io":                                                   "https://docker.io/",
		"nvlab/iperf":                                                 "nvlab/iperf",
		"iperfserver:latest":                                          "iperfserver:latest",
		":latest":                                                     ":latest",
	}
	var output string
	for k, v := range input {
		output = normalizeImageValue(k, false)
		if output != v {
			t.Errorf("Unexpected normalized image(%+v) for: %+v, %+v\n", output, k, v)
			break
		}
	}

	input = map[string]string{
		"localhost":              "https://localhost/",
		"localhost:8080":         "https://localhost:8080/",
		"https://localhost:8080": "https://localhost:8080/",
		"10.1.127.3:5000/neuvector/toolbox/selvam_coreos_http":        "https://10.1.127.3:5000/",
		"10.1.127.3:5000/neuvector/toolbox/selvam_coreos_http:latest": "https://10.1.127.3:5000/",
		"docker.io/nvlab/iperf":                                       "https://docker.io/",
		"docker.io/nvlab/iperf:RELEASE":                               "https://docker.io/",
		"docker.io":                                                   "https://docker.io/",
		"nvlab/iperf":                                                 "",
		"iperfserver:latest":                                          "",
		":latest":                                                     "",
	}
	for k, v := range input {
		output = normalizeImageValue(k, true)
		if output != v {
			t.Errorf("Unexpected normalizeImageValue result(%+v) for: %+v, %+v\n", output, k, v)
			break
		}
	}

	postTest()
}

func TestIsStringCriterionMet(t *testing.T) {
	preTest()

	type matchResult struct {
		met      bool
		positive bool
	}

	crts := []*share.CLUSAdmRuleCriterion{
		&share.CLUSAdmRuleCriterion{
			Name:  share.CriteriaKeyImageRegistry,
			Op:    share.CriteriaOpContainsAny,
			Value: "https://index.docker.io/,https://10.1.127.3:5000/",
		},
	}
	values := []string{"https://index.docker.io/"}
	expected := []matchResult{
		matchResult{met: true, positive: true},
	}
	for idx, crt := range crts {
		crt.ValueSlice = strings.Split(crt.Value, ",")
		met, positive := isStringCriterionMet(crt, values[idx])
		if met != expected[idx].met || positive != expected[idx].positive {
			t.Errorf("Unexpected isStringCriterionMet[%d] result(%+v) for: %+v, %+v\n", idx, expected[idx], crt, values[idx])
			break
		}
	}

	postTest()
}

type testContainer struct {
	image            string
	imageRegistry    string
	ImageRepo        string
	ImageTag         string
	expectedMet      bool
	expectedPositive bool
}

type testMatchResult struct {
	expectedMet      bool
	expectedPositive bool
}

func TestMatchImageValue(t *testing.T) {
	preTest()

	crtValue := "https://10.1.127.3:5000/neuvector/toolbox/selvam_coreos_http"
	testContainers := []*testContainer{
		&testContainer{
			imageRegistry: "https://10.1.127.3:5000/",
			ImageRepo:     "neuvector/toolbox/selvam_coreos_http",
			ImageTag:      "latest",
			expectedMet:   true,
		},
		&testContainer{
			imageRegistry: "https://10.1.127.3:5000/",
			ImageRepo:     "neuvector/toolbox/selvam_coreos_http",
			ImageTag:      "RELEASE",
			expectedMet:   true,
		},
		&testContainer{
			imageRegistry: "https://10.1.127.3/",
			ImageRepo:     "neuvector/selvam_coreos_http",
			ImageTag:      "latest",
			expectedMet:   false,
		},
	}

	ctnerInfo := &nvsysadmission.AdmContainerInfo{}
	for idx, testContainer := range testContainers {
		ctnerInfo.ImageRegistry = utils.NewSet(testContainer.imageRegistry)
		ctnerInfo.ImageRepo = testContainer.ImageRepo
		ctnerInfo.ImageTag = testContainer.ImageTag
		met := matchImageValue(share.CriteriaOpContainsAny, crtValue, ctnerInfo)
		if met != testContainer.expectedMet {
			t.Errorf("Unexpected matchImageValue[%d] result(%+v) for CriteriaOpContainsAny, crtValue:%s, container:%+v\n", idx, met, crtValue, testContainer)
			break
		}
	}

	crtValue = "*/selvam_coreos_http"
	testContainers[0].expectedMet = true
	testContainers[1].expectedMet = true
	testContainers[2].expectedMet = true
	for idx, testContainer := range testContainers {
		ctnerInfo.ImageRegistry = utils.NewSet(testContainer.imageRegistry)
		ctnerInfo.ImageRepo = testContainer.ImageRepo
		ctnerInfo.ImageTag = testContainer.ImageTag
		met := matchImageValue(share.CriteriaOpContainsAny, crtValue, ctnerInfo)
		if met != testContainer.expectedMet {
			t.Errorf("Unexpected matchImageValue[%d] result(%+v) for CriteriaOpContainsAny, crtValue:%s, container:%+v\n", idx, met, crtValue, testContainer)
			break
		}
	}

	postTest()
}

func TestIsImageCriterionMet(t *testing.T) {
	preTest()

	crt := &share.CLUSAdmRuleCriterion{
		Name:  share.CriteriaKeyImage,
		Op:    share.CriteriaOpContainsAny,
		Value: "https://index.docker.io/library/ubuntu,https://10.1.127.3:5000/neuvector/toolbox/selvam_coreos_http",
	}

	testContainers := []*testContainer{
		&testContainer{
			imageRegistry:    "https://10.1.127.3:5000/",
			ImageRepo:        "neuvector/toolbox/selvam_coreos_http",
			ImageTag:         "latest",
			expectedMet:      true,
			expectedPositive: true,
		},
		&testContainer{
			imageRegistry:    "https://10.1.127.3:5000/",
			ImageRepo:        "neuvector/toolbox/selvam_coreos_http",
			ImageTag:         "RELEASE",
			expectedMet:      true,
			expectedPositive: true,
		},
		&testContainer{
			imageRegistry:    "https://10.1.127.3/",
			ImageRepo:        "neuvector/selvam_coreos_http",
			ImageTag:         "latest",
			expectedMet:      false,
			expectedPositive: true,
		},
		&testContainer{
			imageRegistry:    "https://index.docker.io/",
			ImageRepo:        "library/ubuntu",
			ImageTag:         "11.0-release",
			expectedMet:      true,
			expectedPositive: true,
		},
	}
	crt.ValueSlice = strings.Split(crt.Value, ",")
	ctnerInfo := &nvsysadmission.AdmContainerInfo{}
	for idx, testContainer := range testContainers {
		ctnerInfo.Image = testContainer.image
		ctnerInfo.ImageRegistry = utils.NewSet(testContainer.imageRegistry)
		ctnerInfo.ImageRepo = testContainer.ImageRepo
		ctnerInfo.ImageTag = testContainer.ImageTag
		met, positive := isImageCriterionMet(crt, ctnerInfo)
		if met != testContainer.expectedMet || positive != testContainer.expectedPositive {
			t.Errorf("Unexpected isImageCriterionMet[%d] result(%+v, %+v) for criterion:%+v, container:%+v\n", idx, met, positive, crt, testContainer)
			break
		}
	}

	postTest()
}

func TestIsMapCriterionMet(t *testing.T) {
	preTest()

	crts := []*share.CLUSAdmRuleCriterion{
		&share.CLUSAdmRuleCriterion{
			Name:  share.CriteriaKeyLabels,
			Op:    share.CriteriaOpContainsAny,
			Value: "label1=value1,label2=value2,label3",
		},
		&share.CLUSAdmRuleCriterion{
			Name:  share.CriteriaKeyLabels,
			Op:    share.CriteriaOpContainsAll,
			Value: "label2=value2,label3,label1",
		},
		&share.CLUSAdmRuleCriterion{
			Name:  share.CriteriaKeyLabels,
			Op:    share.CriteriaOpNotContainsAny,
			Value: "label2=value2,label3,label1=aaa",
		},
		&share.CLUSAdmRuleCriterion{
			Name:  share.CriteriaKeyLabels,
			Op:    share.CriteriaOpContainsOtherThan,
			Value: "label1,label2=value2",
		},
		&share.CLUSAdmRuleCriterion{
			Name:  share.CriteriaKeyLabels,
			Op:    share.CriteriaOpContainsOtherThan,
			Value: "label1",
		},
		&share.CLUSAdmRuleCriterion{
			Name:  share.CriteriaKeyLabels,
			Op:    share.CriteriaOpContainsOtherThan,
			Value: "label1,label2=value2,label3=value3",
		},
		&share.CLUSAdmRuleCriterion{
			Name:  share.CriteriaKeyLabels,
			Op:    share.CriteriaOpContainsAny,
			Value: "label1=value1,label1=value2",
		},
	}
	expected1 := []bool{true, false, true, true, true, true, true}
	ctnerLabels1 := map[string]string{
		"token":  "100",
		"label1": "value1",
	}
	expected2 := []bool{true, false, false, false, true, false, false}
	ctnerLabels2 := map[string]string{
		"label1": "",
		"label2": "value2",
	}
	expected3 := []bool{true, false, false, false, true, false, false}
	ctnerLabels3 := map[string]string{
		"label2": "value2",
	}
	expected4 := []bool{false, false, true, false, false, false, false}
	ctnerLabels4 := map[string]string{}

	expected5 := []bool{false, false, true, true, true, true, false}
	ctnerLabels5 := map[string]string{
		"token": "100",
	}

	for idx, crt := range crts {
		crt.ValueSlice = strings.Split(crt.Value, ",")
		met, positive := isMapCriterionMet(crt, ctnerLabels1)
		if met != expected1[idx] {
			t.Errorf("Unexpected isMapCriterionMet[1:%d] result(%+v,%+v) for crtValue:%s, container:%+v\n", idx, met, positive, crt.Value, ctnerLabels1)
			break
		}
		met, positive = isMapCriterionMet(crt, ctnerLabels2)
		if met != expected2[idx] {
			t.Errorf("Unexpected isMapCriterionMet[2:%d] result(%+v,%+v) for crtValue:%s, container:%+v\n", idx, met, positive, crt.Value, ctnerLabels2)
			break
		}
		met, positive = isMapCriterionMet(crt, ctnerLabels3)
		if met != expected3[idx] {
			t.Errorf("Unexpected isMapCriterionMet[3:%d] result(%+v,%+v) for crtValue:%s, container:%+v\n", idx, met, positive, crt.Value, ctnerLabels3)
			break
		}
		met, positive = isMapCriterionMet(crt, ctnerLabels4)
		if met != expected4[idx] {
			t.Errorf("Unexpected isMapCriterionMet[4:%d] result(%+v,%+v) for crtValue:%s, container:%+v\n", idx, met, positive, crt.Value, ctnerLabels4)
			break
		}
		met, positive = isMapCriterionMet(crt, ctnerLabels5)
		if met != expected5[idx] {
			t.Errorf("Unexpected isMapCriterionMet[5:%d] result(%+v,%+v) for crtValue:%s, container:%+v\n", idx, met, positive, crt.Value, ctnerLabels5)
			break
		}
	}

	postTest()
}

func TestIsSetCriterionMet(t *testing.T) {
	preTest()

	type ret struct {
		met      bool
		positive bool
	}

	criteria := []*share.CLUSAdmRuleCriterion{
		&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyUser, Op: share.CriteriaOpContainsAny, Value: "jane,ted"},
		&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyUser, Op: share.CriteriaOpContainsAny, Value: "andrew,ted"},
		&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyUser, Op: share.CriteriaOpNotContainsAny, Value: "jane,ted"},
		&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyUser, Op: share.CriteriaOpNotContainsAny, Value: "andrew,ted"},
		&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyCVENames, Op: share.CriteriaOpContainsAny, Value: "CVE-2014-887,CVE-2014-888"},
		&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyCVENames, Op: share.CriteriaOpContainsAny, Value: "CVE-2014-002,CVE-2016-001"},
		&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyCVENames, Op: share.CriteriaOpContainsAny, Value: "CVE-2014-885,CVE-2014-886,CVE-2014-887,CVE-2014-888,CVE-2014-889"},
		&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyCVENames, Op: share.CriteriaOpNotContainsAny, Value: "CVE-2014-887,CVE-2014-888"},
		&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyCVENames, Op: share.CriteriaOpNotContainsAny, Value: "CVE-2014-002,CVE-2016-001"},
		&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyCVENames, Op: share.CriteriaOpNotContainsAny, Value: "CVE-2014-885,CVE-2014-886,CVE-2014-887,CVE-2014-888,CVE-2014-889"},
		&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyCVENames, Op: share.CriteriaOpContainsAll, Value: "CVE-2014-887,CVE-2014-888"},
		&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyCVENames, Op: share.CriteriaOpContainsAll, Value: "CVE-2014-887,CVE-2016-001"},
		&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyCVENames, Op: share.CriteriaOpContainsAll, Value: "CVE-2014-885,CVE-2014-886,CVE-2014-887,CVE-2014-888,CVE-2014-889"},
		&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyCVENames, Op: share.CriteriaOpContainsOtherThan, Value: "CVE-2014-887,CVE-2014-888"},
		&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyCVENames, Op: share.CriteriaOpContainsOtherThan, Value: "CVE-2014-887,CVE-2016-001"},
		&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyCVENames, Op: share.CriteriaOpContainsOtherThan, Value: "CVE-2014-885,CVE-2014-886,CVE-2014-887,CVE-2014-888,CVE-2014-889"},
	}
	valueSet1 := utils.NewSet("jane")
	valueSet2 := utils.NewSet("CVE-2014-886", "CVE-2014-887", "CVE-2014-888")
	expected := []ret{
		ret{met: true, positive: true}, // for "user", CriteriaOpContainsAny
		ret{met: false, positive: true},
		ret{met: false, positive: false}, // for "user", CriteriaOpNotContainsAny
		ret{met: true, positive: false},
		ret{met: true, positive: true}, // for "cveNames", CriteriaOpContainsAny
		ret{met: false, positive: true},
		ret{met: true, positive: true},
		ret{met: false, positive: false}, // for "cveNames", CriteriaOpNotContainsAny
		ret{met: true, positive: false},
		ret{met: false, positive: false},
		ret{met: true, positive: true}, // for "cveNames", CriteriaOpContainsAll
		ret{met: false, positive: true},
		ret{met: false, positive: true},
		ret{met: true, positive: true}, // for "cveNames", CriteriaOpContainsOtherThan
		ret{met: true, positive: true},
		ret{met: false, positive: true},
	}

	var met, positive bool
	for idx, crt := range criteria {
		crt.ValueSlice = strings.Split(crt.Value, ",")
		switch crt.Name {
		case share.CriteriaKeyUser:
			met, positive = isSetCriterionMet(crt, valueSet1)
		case share.CriteriaKeyCVENames:
			met, positive = isSetCriterionMet(crt, valueSet2)
		default:
			t.Errorf("Unexpected criterion name(%s)\n", crt.Name)
		}
		if met != expected[idx].met || positive != expected[idx].positive {
			t.Errorf("Unexpected isSetCriterionMet[1:%d] result(%s, %s, %s, %+v, %+v)\n", idx, crt.Name, crt.Op, crt.Value, met, positive)
			break
		}
	}

	valueSet3 := utils.NewSet()
	expected3 := []ret{
		ret{met: false, positive: true}, // for "user", CriteriaOpContainsAny
		ret{met: false, positive: true},
		ret{met: true, positive: false}, // for "user", CriteriaOpNotContainsAny
		ret{met: true, positive: false},
		ret{met: false, positive: true}, // for "cveNames", CriteriaOpContainsAny
		ret{met: false, positive: true},
		ret{met: false, positive: true},
		ret{met: true, positive: false}, // for "cveNames", CriteriaOpNotContainsAny
		ret{met: true, positive: false},
		ret{met: true, positive: false},
		ret{met: false, positive: true}, // for "cveNames", CriteriaOpContainsAll
		ret{met: false, positive: true},
		ret{met: false, positive: true},
		ret{met: false, positive: true}, // for "cveNames", CriteriaOpContainsOtherThan
		ret{met: false, positive: true},
		ret{met: false, positive: true},
	}
	for idx, crt := range criteria {
		crt.ValueSlice = strings.Split(crt.Value, ",")
		switch crt.Name {
		case share.CriteriaKeyCVENames:
			met, positive = isSetCriterionMet(crt, valueSet3)
			if met != expected3[idx].met || positive != expected3[idx].positive {
				t.Errorf("Unexpected isSetCriterionMet[2:%d] result(%s, %s, %s, %+v, %+v)\n", idx, crt.Name, crt.Op, crt.Value, met, positive)
				break
			}
		}
	}

	postTest()
}

func TestIsHighCveWithFixCriterionMet(t *testing.T) {
	preTest()

	crt1 := &share.CLUSAdmRuleCriterion{
		Name:  share.CriteriaKeyCVEHighWithFixCount,
		Op:    share.CriteriaOpBiggerEqualThan,
		Value: "1",
	}

	crt2 := &share.CLUSAdmRuleCriterion{
		Name:        share.CriteriaKeyCVEHighWithFixCount,
		Op:          share.CriteriaOpBiggerEqualThan,
		Value:       "1",
		SubCriteria: []*share.CLUSAdmRuleCriterion{},
	}

	crt3 := &share.CLUSAdmRuleCriterion{
		Name:  share.CriteriaKeyCVEHighWithFixCount,
		Op:    share.CriteriaOpBiggerEqualThan,
		Value: "1",
		SubCriteria: []*share.CLUSAdmRuleCriterion{
			&share.CLUSAdmRuleCriterion{
				Name:  share.SubCriteriaPublishDays,
				Op:    share.CriteriaOpBiggerEqualThan,
				Value: "1",
			},
		},
	}

	crt1.ValueSlice = strings.Split(crt1.Value, ",")
	crt2.ValueSlice = strings.Split(crt2.Value, ",")
	crt3.ValueSlice = strings.Split(crt3.Value, ",")
	crts := []*share.CLUSAdmRuleCriterion{crt1, crt2, crt3}

	vulInfo1 := make(map[string]share.CLUSScannedVulInfo, 0)
	vulInfo2 := make(map[string]share.CLUSScannedVulInfo, 0)

	vulInfo1["CVE-1019-15847"] = share.CLUSScannedVulInfo{
		PublishDate: 1590281356,
	}
	vulInfo2["CVE-1019-15847"] = share.CLUSScannedVulInfo{
		PublishDate: 1590281356,
		WithFix:     true,
	}

	expected1 := []*testMatchResult{ // vul has no fix
		&testMatchResult{ // for crt1
			expectedMet:      false,
			expectedPositive: true,
		},
		&testMatchResult{ // for crt2
			expectedMet:      false,
			expectedPositive: true,
		},
		&testMatchResult{ // for crt3. in test-1 vulInfo is nil so we assume the scan summary as from pre-3.2.2 that doesn't contain HighVulInfo/MediumVulInfo & treat it as always met for SubCriteriaPublishDays criterion
			expectedMet:      true,
			expectedPositive: true,
		},
	}
	expected2 := []*testMatchResult{ // vul has no fix
		&testMatchResult{ // for crt1
			expectedMet:      false,
			expectedPositive: true,
		},
		&testMatchResult{ // for crt2
			expectedMet:      false,
			expectedPositive: true,
		},
		&testMatchResult{ // for crt3
			expectedMet:      false,
			expectedPositive: true,
		},
	}
	expected3 := []*testMatchResult{ // vul has no fix
		&testMatchResult{ // for crt1
			expectedMet:      false,
			expectedPositive: true,
		},
		&testMatchResult{ // for crt2
			expectedMet:      false,
			expectedPositive: true,
		},
		&testMatchResult{ // for crt3
			expectedMet:      false,
			expectedPositive: true,
		},
	}
	expected4 := []*testMatchResult{ // vul has fix
		&testMatchResult{ // for crt1
			expectedMet:      true,
			expectedPositive: true,
		},
		&testMatchResult{ // for crt2
			expectedMet:      true,
			expectedPositive: true,
		},
		&testMatchResult{ // for crt3
			expectedMet:      true,
			expectedPositive: true,
		},
	}

	var met, positive bool
	for idx, crt := range crts {
		// test-1: vul has no fix
		met, positive = isCveCountCriterionMet(crt, true, 0, nil)
		if met != expected1[idx].expectedMet || positive != expected1[idx].expectedPositive {
			t.Errorf("Unexpected isCveCountCriterionMet[crt%d] result(%+v, %+v) for criterion:%+v, expected-1:%+v\n", idx+1, met, positive, crt, *expected1[idx])
		}

		// test-2: vul has no fix
		met, positive = isCveCountCriterionMet(crt, true, 0, make(map[string]share.CLUSScannedVulInfo, 0))
		if met != expected2[idx].expectedMet || positive != expected2[idx].expectedPositive {
			t.Errorf("Unexpected isCveCountCriterionMet[crt%d] result(%+v, %+v) for criterion:%+v, expected-2:%+v\n", idx+1, met, positive, crt, *expected2[idx])
		}

		// test-3: vul has no fix
		met, positive = isCveCountCriterionMet(crt, true, 0, vulInfo1)
		if met != expected3[idx].expectedMet || positive != expected3[idx].expectedPositive {
			t.Errorf("Unexpected isCveCountCriterionMet[crt%d] result(%+v, %+v) for criterion:%+v, expected-3:%+v\n", idx+1, met, positive, crt, *expected3[idx])
		}

		// test-4: vul has fix
		met, positive = isCveCountCriterionMet(crt, true, 1, vulInfo2)
		if met != expected4[idx].expectedMet || positive != expected4[idx].expectedPositive {
			t.Errorf("Unexpected isCveCountCriterionMet[crt%d] result(%+v, %+v) for criterion:%+v, expected-4:%+v\n", idx+1, met, positive, crt, *expected4[idx])
		}
	}

	postTest()
}

func TestIsLabelCriterionMet1(t *testing.T) {
	preTest()

	crtss := [][]*share.CLUSAdmRuleCriterion{
		[]*share.CLUSAdmRuleCriterion{&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyLabels, Op: share.CriteriaOpContainsAny, Value: "owner=*"}},
		[]*share.CLUSAdmRuleCriterion{&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyLabels, Op: share.CriteriaOpContainsAll, Value: "owner=*"}},
		[]*share.CLUSAdmRuleCriterion{&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyLabels, Op: share.CriteriaOpNotContainsAny, Value: "owner=*"}},
		[]*share.CLUSAdmRuleCriterion{&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyLabels, Op: share.CriteriaOpContainsOtherThan, Value: "owner=*"}},
	}
	for _, crts := range crtss {
		for _, crt := range crts {
			crt.ValueSlice = strings.Split(crt.Value, ",")
		}
	}

	type typeExpected struct {
		matched       bool
		matchedSource string // because we do union(yaml label, image labels) before comparison, we don't try to say the matched data is from which one
	}
	expected := [][]*typeExpected{
		[]*typeExpected{ // for CriteriaOpContainsAny
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcResourceLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcBothLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcResourceLabels},
		},
		[]*typeExpected{ // for CriteriaOpContainsAll
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcResourceLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcBothLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcResourceLabels},
		},
		[]*typeExpected{ // for CriteriaOpNotContainsAny
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
		},
		[]*typeExpected{ // for CriteriaOpContainsOtherThan
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
		},
	}

	admResObjects := []*nvsysadmission.AdmResObject{
		&nvsysadmission.AdmResObject{
			Labels: nil,
		},
		&nvsysadmission.AdmResObject{
			Labels: map[string]string{
				"owner": "*",
			},
		},
	}
	cs := []*nvsysadmission.AdmContainerInfo{&nvsysadmission.AdmContainerInfo{}}
	scannedImages := []*nvsysadmission.ScannedImageSummary{
		&nvsysadmission.ScannedImageSummary{
			Scanned: true,
			Labels:  nil,
		},
		&nvsysadmission.ScannedImageSummary{
			Scanned: true,
			Labels: map[string]string{
				"owner": "*",
			},
		},
		&nvsysadmission.ScannedImageSummary{
			Scanned: false,
		},
	}

	var matched bool
	var matchedSource string
	for idx, crts := range crtss {
		tag := 0
		for _, admResObject := range admResObjects {
			for _, scannedImage := range scannedImages {
				matched, matchedSource = isAdmissionRuleMet(admResObject, cs[0], scannedImage, crts, false)
				if matched != expected[idx][tag].matched || matchedSource != expected[idx][tag].matchedSource {
					t.Errorf("Unexpected isAdmissionRuleMet[%d:%d] result(%+v,%+v) for (yaml:%+v, image:%+v, scanned:%+v) %s %s, expect:(%+v,%+v)\n",
						idx, tag, matched, matchedSource, admResObject.Labels, scannedImage.Labels, scannedImage.Scanned, crts[0].Op, crts[0].Value, expected[idx][tag].matched, expected[idx][tag].matchedSource)
				} /*else {
					t.Errorf("Expected   isAdmissionRuleMet[%d:%d] result(%+v,%+v) for (yaml:%+v, image:%+v, scanned:%+v) %s %s, expect:(%+v,%+v)\n",
						tag, idx, matched, matchedSource, admResObject.Labels, scannedImage.Labels, scannedImage.Scanned, crts[0].Op, crts[0].Value, expected[idx][tag].matched, expected[idx][tag].matchedSource)
				}*/
				tag++
			}
		}
	}

	postTest()
}

func TestIsLabelCriterionMet2(t *testing.T) {
	preTest()

	crtss := [][]*share.CLUSAdmRuleCriterion{
		[]*share.CLUSAdmRuleCriterion{&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyLabels, Op: share.CriteriaOpContainsAny, Value: "owner=*"}},
		[]*share.CLUSAdmRuleCriterion{&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyLabels, Op: share.CriteriaOpContainsAll, Value: "owner=*"}},
		[]*share.CLUSAdmRuleCriterion{&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyLabels, Op: share.CriteriaOpNotContainsAny, Value: "owner=*"}},
		[]*share.CLUSAdmRuleCriterion{&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyLabels, Op: share.CriteriaOpContainsOtherThan, Value: "owner=*"}},
	}
	for _, crts := range crtss {
		for _, crt := range crts {
			crt.ValueSlice = strings.Split(crt.Value, ",")
		}
	}

	type typeExpected struct {
		matched       bool
		matchedSource string // because we do union(yaml label, image labels) before comparison, we don't try to say the matched data is from which one
	}
	expected := [][]*typeExpected{
		[]*typeExpected{ // for CriteriaOpContainsAny
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcResourceLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcBothLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcResourceLabels},
		},
		[]*typeExpected{ // for CriteriaOpContainsAll
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcResourceLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcBothLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcResourceLabels},
		},
		[]*typeExpected{ // for CriteriaOpNotContainsAny
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
		},
		[]*typeExpected{ // for CriteriaOpContainsOtherThan
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcResourceLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcBothLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcResourceLabels},
		},
	}

	admResObjects := []*nvsysadmission.AdmResObject{
		&nvsysadmission.AdmResObject{
			Labels: nil,
		},
		&nvsysadmission.AdmResObject{
			Labels: map[string]string{
				"owner": "*",
				"app":   "test",
			},
		},
	}
	cs := []*nvsysadmission.AdmContainerInfo{&nvsysadmission.AdmContainerInfo{}}
	scannedImages := []*nvsysadmission.ScannedImageSummary{
		&nvsysadmission.ScannedImageSummary{
			Scanned: true,
			Labels:  nil,
		},
		&nvsysadmission.ScannedImageSummary{
			Scanned: true,
			Labels: map[string]string{
				"owner": "*",
				"app":   "test",
			},
		},
		&nvsysadmission.ScannedImageSummary{
			Scanned: false,
		},
	}

	var matched bool
	var matchedSource string
	for idx, crts := range crtss {
		tag := 0
		for _, admResObject := range admResObjects {
			for _, scannedImage := range scannedImages {
				matched, matchedSource = isAdmissionRuleMet(admResObject, cs[0], scannedImage, crts, false)
				if matched != expected[idx][tag].matched || matchedSource != expected[idx][tag].matchedSource {
					t.Errorf("Unexpected isAdmissionRuleMet[%d:%d] result(%+v,%+v) for (yaml:%+v, image:%+v, scanned:%+v) %s %s, expect:(%+v,%+v)\n",
						idx, tag, matched, matchedSource, admResObject.Labels, scannedImage.Labels, scannedImage.Scanned, crts[0].Op, crts[0].Value, expected[idx][tag].matched, expected[idx][tag].matchedSource)
				} /*else {
					t.Errorf("Expected   isAdmissionRuleMet[%d:%d] result(%+v,%+v) for (yaml:%+v, image:%+v, scanned:%+v) %s %s, expect:(%+v,%+v)\n",
						tag, idx, matched, matchedSource, admResObject.Labels, scannedImage.Labels, scannedImage.Scanned, crts[0].Op, crts[0].Value, expected[idx][tag].matched, expected[idx][tag].matchedSource)
				}*/
				tag++
			}
		}
	}

	postTest()
}

func TestIsLabelCriterionMet3(t *testing.T) {
	preTest()

	crtss := [][]*share.CLUSAdmRuleCriterion{[]*share.CLUSAdmRuleCriterion{&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyLabels, Op: share.CriteriaOpContainsAny, Value: "owner=*,app=server"}},
		[]*share.CLUSAdmRuleCriterion{&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyLabels, Op: share.CriteriaOpContainsAll, Value: "owner=*,app=server"}},
		[]*share.CLUSAdmRuleCriterion{&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyLabels, Op: share.CriteriaOpNotContainsAny, Value: "owner=*,app=server"}},
		[]*share.CLUSAdmRuleCriterion{&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyLabels, Op: share.CriteriaOpContainsOtherThan, Value: "owner=*,app=server"}},
	}
	for _, crts := range crtss {
		for _, crt := range crts {
			crt.ValueSlice = strings.Split(crt.Value, ",")
		}
	}

	type typeExpected struct {
		matched       bool
		matchedSource string // because we do union(yaml label, image labels) before comparison, we don't try to say the matched data is from which one
	}
	expected := [][]*typeExpected{
		[]*typeExpected{ // for CriteriaOpContainsAny
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcResourceLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcBothLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcResourceLabels},
		},
		[]*typeExpected{ // for CriteriaOpContainsAll
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
		},
		[]*typeExpected{ // for CriteriaOpNotContainsAny
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
		},
		[]*typeExpected{ // for CriteriaOpContainsOtherThan
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcResourceLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcBothLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcResourceLabels},
		},
	}

	admResObjects := []*nvsysadmission.AdmResObject{
		&nvsysadmission.AdmResObject{
			Labels: nil,
		},
		&nvsysadmission.AdmResObject{
			Labels: map[string]string{
				"owner": "*",
				"app":   "test",
			},
		},
	}
	cs := []*nvsysadmission.AdmContainerInfo{&nvsysadmission.AdmContainerInfo{}}
	scannedImages := []*nvsysadmission.ScannedImageSummary{
		&nvsysadmission.ScannedImageSummary{
			Scanned: true,
			Labels:  nil,
		},
		&nvsysadmission.ScannedImageSummary{
			Scanned: true,
			Labels: map[string]string{
				"owner": "*",
				"app":   "test",
			},
		},
		&nvsysadmission.ScannedImageSummary{
			Scanned: false,
		},
	}

	var matched bool
	var matchedSource string
	for idx, crts := range crtss {
		tag := 0
		for _, admResObject := range admResObjects {
			for _, scannedImage := range scannedImages {
				matched, matchedSource = isAdmissionRuleMet(admResObject, cs[0], scannedImage, crts, false)
				if matched != expected[idx][tag].matched || matchedSource != expected[idx][tag].matchedSource {
					t.Errorf("Unexpected isAdmissionRuleMet[%d:%d] result(%+v,%+v) for (yaml:%+v, image:%+v, scanned:%+v) %s %s, expect:(%+v,%+v)\n",
						idx, tag, matched, matchedSource, admResObject.Labels, scannedImage.Labels, scannedImage.Scanned, crts[0].Op, crts[0].Value, expected[idx][tag].matched, expected[idx][tag].matchedSource)
				} /*else {
					t.Errorf("Expected   isAdmissionRuleMet[%d:%d] result(%+v,%+v) for (yaml:%+v, image:%+v, scanned:%+v) %s %s, expect:(%+v,%+v)\n",
						tag, idx, matched, matchedSource, admResObject.Labels, scannedImage.Labels, scannedImage.Scanned, crts[0].Op, crts[0].Value, expected[idx][tag].matched, expected[idx][tag].matchedSource)
				}*/
				tag++
			}
		}
	}

	postTest()
}

func TestIsLabelCriterionMet4(t *testing.T) {
	preTest()

	crtss := [][]*share.CLUSAdmRuleCriterion{
		[]*share.CLUSAdmRuleCriterion{&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyLabels, Op: share.CriteriaOpContainsAny, Value: "owner"}},
		[]*share.CLUSAdmRuleCriterion{&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyLabels, Op: share.CriteriaOpContainsAll, Value: "owner"}},
		[]*share.CLUSAdmRuleCriterion{&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyLabels, Op: share.CriteriaOpNotContainsAny, Value: "owner"}},
		[]*share.CLUSAdmRuleCriterion{&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyLabels, Op: share.CriteriaOpContainsOtherThan, Value: "owner"}},
	}
	for _, crts := range crtss {
		for _, crt := range crts {
			crt.ValueSlice = strings.Split(crt.Value, ",")
		}
	}

	type typeExpected struct {
		matched       bool
		matchedSource string // because we do union(yaml label, image labels) before comparison, we don't try to say the matched data is from which one
	}
	expected := [][]*typeExpected{
		[]*typeExpected{ // for CriteriaOpContainsAny
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcResourceLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcBothLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcBothLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcBothLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcResourceLabels},
		},
		[]*typeExpected{ // for CriteriaOpContainsAll
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcResourceLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcBothLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcBothLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcBothLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcResourceLabels},
		},
		[]*typeExpected{ // for CriteriaOpNotContainsAny
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
		},
		[]*typeExpected{ // for CriteriaOpContainsOtherThan
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcBothLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcBothLabels},
			&typeExpected{matched: false, matchedSource: ""},
		},
	}

	admResObjects := []*nvsysadmission.AdmResObject{
		&nvsysadmission.AdmResObject{
			Labels: nil,
		},
		&nvsysadmission.AdmResObject{
			Labels: map[string]string{
				"owner": "joe",
			},
		},
	}
	cs := []*nvsysadmission.AdmContainerInfo{&nvsysadmission.AdmContainerInfo{}}
	scannedImages := []*nvsysadmission.ScannedImageSummary{
		&nvsysadmission.ScannedImageSummary{
			Scanned: true,
			Labels:  nil,
		},
		&nvsysadmission.ScannedImageSummary{
			Scanned: true,
			Labels: map[string]string{
				"owner": "joe",
			},
		},
		&nvsysadmission.ScannedImageSummary{
			Scanned: true,
			Labels: map[string]string{
				"owner": "joe",
				"app":   "proxy",
			},
		},
		&nvsysadmission.ScannedImageSummary{
			Scanned: true,
			Labels: map[string]string{
				"owner": "joe",
				"app":   "proxy",
				"skip":  "yes",
			},
		},
		&nvsysadmission.ScannedImageSummary{
			Scanned: false,
		},
	}

	var matched bool
	var matchedSource string
	for idx, crts := range crtss {
		tag := 0
		for _, admResObject := range admResObjects {
			for _, scannedImage := range scannedImages {
				matched, matchedSource = isAdmissionRuleMet(admResObject, cs[0], scannedImage, crts, false)
				if matched != expected[idx][tag].matched || matchedSource != expected[idx][tag].matchedSource {
					t.Errorf("Unexpected isAdmissionRuleMet[%d:%d] result(%+v,%+v) for (yaml:%+v, image:%+v, scanned:%+v) %s %s, expect:(%+v,%+v)\n",
						idx, tag, matched, matchedSource, admResObject.Labels, scannedImage.Labels, scannedImage.Scanned, crts[0].Op, crts[0].Value, expected[idx][tag].matched, expected[idx][tag].matchedSource)
				} /*else {
					t.Errorf("Expected   isAdmissionRuleMet[%d:%d] result(%+v,%+v) for (yaml:%+v, image:%+v, scanned:%+v) %s %s, expect:(%+v,%+v)\n",
						tag, idx, matched, matchedSource, admResObject.Labels, scannedImage.Labels, scannedImage.Scanned, crts[0].Op, crts[0].Value, expected[idx][tag].matched, expected[idx][tag].matchedSource)
				}*/
				tag++
			}
		}
	}

	postTest()
}

func TestIsLabelCriterionMet5(t *testing.T) {
	preTest()

	crtss := [][]*share.CLUSAdmRuleCriterion{
		[]*share.CLUSAdmRuleCriterion{&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyLabels, Op: share.CriteriaOpContainsAny, Value: "owner,app"}},
		[]*share.CLUSAdmRuleCriterion{&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyLabels, Op: share.CriteriaOpContainsAll, Value: "owner,app"}},
		[]*share.CLUSAdmRuleCriterion{&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyLabels, Op: share.CriteriaOpNotContainsAny, Value: "owner,app"}},
		[]*share.CLUSAdmRuleCriterion{&share.CLUSAdmRuleCriterion{Name: share.CriteriaKeyLabels, Op: share.CriteriaOpContainsOtherThan, Value: "owner,app"}},
	}
	for _, crts := range crtss {
		for _, crt := range crts {
			crt.ValueSlice = strings.Split(crt.Value, ",")
		}
	}

	type typeExpected struct {
		matched       bool
		matchedSource string // because we do union(yaml label, image labels) before comparison, we don't try to say the matched data is from which one
	}
	expected := [][]*typeExpected{
		[]*typeExpected{ // for CriteriaOpContainsAny
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcResourceLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcBothLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcBothLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcBothLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcResourceLabels},
		},
		[]*typeExpected{ // for CriteriaOpContainsAll
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcBothLabels},
			&typeExpected{matched: true, matchedSource: _matchedSrcBothLabels},
			&typeExpected{matched: false, matchedSource: ""},
		},
		[]*typeExpected{ // for CriteriaOpNotContainsAny
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
		},
		[]*typeExpected{ // for CriteriaOpContainsOtherThan
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcImageLabels},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: false, matchedSource: ""},
			&typeExpected{matched: true, matchedSource: _matchedSrcBothLabels},
			&typeExpected{matched: false, matchedSource: ""},
		},
	}

	admResObjects := []*nvsysadmission.AdmResObject{
		&nvsysadmission.AdmResObject{
			Labels: nil,
		},
		&nvsysadmission.AdmResObject{
			Labels: map[string]string{
				"owner": "joe",
			},
		},
	}
	cs := []*nvsysadmission.AdmContainerInfo{&nvsysadmission.AdmContainerInfo{}}
	scannedImages := []*nvsysadmission.ScannedImageSummary{
		&nvsysadmission.ScannedImageSummary{
			Scanned: true,
			Labels:  nil,
		},
		&nvsysadmission.ScannedImageSummary{
			Scanned: true,
			Labels: map[string]string{
				"owner": "joe",
			},
		},
		&nvsysadmission.ScannedImageSummary{
			Scanned: true,
			Labels: map[string]string{
				"owner": "joe",
				"app":   "proxy",
			},
		},
		&nvsysadmission.ScannedImageSummary{
			Scanned: true,
			Labels: map[string]string{
				"owner": "joe",
				"app":   "proxy",
				"skip":  "yes",
			},
		},
		&nvsysadmission.ScannedImageSummary{
			Scanned: false,
		},
	}

	var matched bool
	var matchedSource string
	for idx, crts := range crtss {
		tag := 0
		for _, admResObject := range admResObjects {
			for _, scannedImage := range scannedImages {
				matched, matchedSource = isAdmissionRuleMet(admResObject, cs[0], scannedImage, crts, false)
				if matched != expected[idx][tag].matched || matchedSource != expected[idx][tag].matchedSource {
					t.Errorf("Unexpected isAdmissionRuleMet[%d:%d] result(%+v,%+v) for (yaml:%+v, image:%+v, scanned:%+v) %s %s, expect:(%+v,%+v)\n",
						idx, tag, matched, matchedSource, admResObject.Labels, scannedImage.Labels, scannedImage.Scanned, crts[0].Op, crts[0].Value, expected[idx][tag].matched, expected[idx][tag].matchedSource)
				} /*else {
					t.Errorf("Expected   isAdmissionRuleMet[%d:%d] result(%+v,%+v) for (yaml:%+v, image:%+v, scanned:%+v) %s %s, expect:(%+v,%+v)\n",
						tag, idx, matched, matchedSource, admResObject.Labels, scannedImage.Labels, scannedImage.Scanned, crts[0].Op, crts[0].Value, expected[idx][tag].matched, expected[idx][tag].matchedSource)
				}*/
				tag++
			}
		}
	}

	postTest()
}

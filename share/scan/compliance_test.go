package scan

import (
	"io"
	"path/filepath"
	"reflect"
	"testing"

	"encoding/json"
	"log"
	"os"

	"github.com/neuvector/neuvector/controller/api"
)

var (
	mockComplianceMetaConfig = &UpdateConfigParams{
		Metas:     &[]api.RESTBenchMeta{},
		MetaMap:   make(map[string]api.RESTBenchMeta),
		MetasV2:   &[]api.RESTBenchMeta{},
		MetaMapV2: make(map[string]api.RESTBenchMeta),
	}

	mockPrimeComplianceMetaConfig = &UpdateConfigParams{
		Metas:     &[]api.RESTBenchMeta{},
		MetaMap:   make(map[string]api.RESTBenchMeta),
		MetasV2:   &[]api.RESTBenchMeta{},
		MetaMapV2: make(map[string]api.RESTBenchMeta),
		FilterMap: make(map[string]int),
	}

	mockPrimeImageBenchConfig = &UpdateConfigParams{
		Metas:   &[]api.RESTBenchMeta{},
		MetaMap: make(map[string]api.RESTBenchMeta),
	}

	mockCISItems = make(map[string]api.RESTBenchCheck)

	// V2 Return the Tags map[string]share.TagDetails
	mockComplianceMetasV2   []api.RESTBenchMeta
	mockComplianceMetaMapV2 = make(map[string]api.RESTBenchMeta)
	// Return the Tags []string
	mockComplianceMetas   []api.RESTBenchMeta
	mockComplianceMetaMap = make(map[string]api.RESTBenchMeta)
)

// For Load Prime data
var mockLoadItems = map[string]api.RESTBenchCheck{
	"I.4.1": api.RESTBenchCheck{
		TestNum:     "I.4.1",
		Type:        "image",
		Category:    "image",
		Scored:      true,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure a user for the container has been created",
	},
	"I.4.6": api.RESTBenchCheck{
		TestNum:     "I.4.6",
		Type:        "image",
		Category:    "image",
		Scored:      false,
		Profile:     "Level 1",
		Automated:   false,
		Description: "Ensure that HEALTHCHECK instructions have been added to container images",
	},
}

var expectedTags = map[string]map[string]bool{
	"I.4.1": {"Mock3": true},
	"I.4.6": {"Mock1": true, "Mock2": true, "Mock4": true},
}

var expectedFilterMapAfterfLoadConfig = map[string]int{
	"Mock3": 1, "Mock1": 1, "Mock2": 1, "Mock4": 1,
}

type TagsValidator struct {
	Tags []string `json:"Tags"`
}

func TestSetup(t *testing.T) {
	// must PrepareBackup() in the first test function to store the original cisItems
	PrepareBackup()

	for key, value := range backupCISItems {
		mockCISItems[key] = DeepCopyRESTBenchCheck(value)
		cisItems[key] = DeepCopyRESTBenchCheck(value)
	}
	PrepareBenchMeta(mockLoadItems, mockComplianceMetaConfig.MetaMapV2)
	updateComplianceMetasFromMap(mockComplianceMetaConfig.Metas, mockComplianceMetaConfig.MetaMap, mockComplianceMetaConfig.MetasV2, mockComplianceMetaConfig.MetaMapV2)
}

func TestTagConsistance(t *testing.T) {
	// Hard-coded the tag into the cisItems, we wnat to make sure this works fine.
	// Make sure run this first, this is to test the cisItems is correct or not
	path := filepath.Join(".", "testdata", "validate_tag.json")

	// Read the file content
	dataBytes, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Failed to read file: %s", err)
	}

	// Parse JSON data
	validate_tags := make(map[string]TagsValidator)
	err = json.Unmarshal(dataBytes, &validate_tags)
	if err != nil {
		t.Errorf("Error parsing JSON: %s", err)
	}

	// Output the parsed data to verify
	if len(validate_tags) != len(cisItems) {
		t.Errorf("hard-coded cisItems should not be updated.")
	}

	for id, value := range validate_tags {
		mockTagCount := make(map[string]int)
		cisItemTagCount := make(map[string]int)

		for tag, _ := range cisItems[id].TagsV2 {
			cisItemTagCount[tag]++
		}

		for _, tag := range value.Tags {
			mockTagCount[tag]++
		}

		// Compare the maps
		if len(mockTagCount) != len(cisItemTagCount) {
			t.Errorf("hard-coded cisItems should not be updated.")
		}
		for tag, count := range mockTagCount {
			if cisItemTagCount[tag] != count {
				t.Errorf("hard-coded cisItems should not be updated.")
			}
		}
	}
}

func getComplianceMetaForTest(remediationFolder string, items map[string]api.RESTBenchCheck, params *UpdateConfigParams) {
	GetK8sCISMeta(remediationFolder, items)
	PrepareBenchMeta(items, params.MetaMapV2)
	updateComplianceMetasFromMap(params.Metas, params.MetaMap, params.MetasV2, params.MetaMapV2)
}

func isSameExceptTags(meta1, meta2 api.RESTBenchMeta) bool {
	return meta1.RESTBenchCheck.TestNum == meta2.RESTBenchCheck.TestNum &&
		meta1.RESTBenchCheck.Type == meta2.RESTBenchCheck.Type &&
		meta1.RESTBenchCheck.Category == meta2.RESTBenchCheck.Category &&
		meta1.RESTBenchCheck.Scored == meta2.RESTBenchCheck.Scored &&
		meta1.RESTBenchCheck.Profile == meta2.RESTBenchCheck.Profile &&
		meta1.RESTBenchCheck.Automated == meta2.RESTBenchCheck.Automated &&
		meta1.RESTBenchCheck.Description == meta2.RESTBenchCheck.Description &&
		meta1.RESTBenchCheck.Remediation == meta2.RESTBenchCheck.Remediation
}

func isIdenticalTags(meta, mockMeta api.RESTBenchMeta, isV2 bool) bool {
	if isV2 {
		if len(meta.RESTBenchCheck.TagsV2) != len(mockMeta.RESTBenchCheck.TagsV2) {
			return false
		}

		for key, val1 := range meta.RESTBenchCheck.TagsV2 {
			val2, ok := mockMeta.RESTBenchCheck.TagsV2[key]
			if !ok || !reflect.DeepEqual(val1, val2) {
				return false
			}
		}
		return true

	} else {
		if len(meta.RESTBenchCheck.Tags) != len(mockMeta.RESTBenchCheck.Tags) {
			return false
		}
		counts := make(map[string]int)

		for _, item := range meta.RESTBenchCheck.Tags {
			counts[item]++
		}

		for _, item := range mockMeta.RESTBenchCheck.Tags {
			if counts[item] == 0 {
				return false
			}
			counts[item]--
		}

		return true
	}
}

func checkMetaConfig(t *testing.T, complianceMetaConfig, mockComplianceMetaConfig *UpdateConfigParams) {
	if len(*complianceMetaConfig.Metas) != len(*mockComplianceMetaConfig.Metas) {
		t.Errorf("Length of complianceMetaConfig.Metas and mockComplianceMetaConfig.Metas should be the same")
	}

	if len(*complianceMetaConfig.MetasV2) != len(*mockComplianceMetaConfig.MetasV2) {
		t.Errorf("Length of complianceMetaConfig.MetasV2 and mockComplianceMetaConfig.MetasV2 should be the same")
	}

	if len(complianceMetaConfig.MetaMap) != len(mockComplianceMetaConfig.MetaMap) {
		t.Errorf("Length of complianceMetaConfig.MetaMap and mockComplianceMetaConfig.MetaMap should be the same")
	}

	if len(complianceMetaConfig.MetaMapV2) != len(mockComplianceMetaConfig.MetaMapV2) {
		t.Errorf("Length of complianceMetaConfig.MetaMapV2 and mockComplianceMetaConfig.MetaMapV2 should be the same")
	}

	for i := range *complianceMetaConfig.Metas {
		if !isSameExceptTags((*complianceMetaConfig.Metas)[i], (*mockComplianceMetaConfig.Metas)[i]) {
			t.Errorf("complianceMetaConfig.Metas[%d] and mockComplianceMetaConfig.Metas[%d] should be the identical", i, i)
		}
		if !isIdenticalTags((*complianceMetaConfig.Metas)[i], (*mockComplianceMetaConfig.Metas)[i], false) {
			t.Errorf("Tags for complianceMetaConfig.Metas[%d] and mockComplianceMetaConfig.Metas[%d] should be the same, got %v and %v", i, i, (*complianceMetaConfig.Metas)[i].RESTBenchCheck.Tags, (*mockComplianceMetaConfig.MetasV2)[i].RESTBenchCheck.Tags)
		}
	}

	for i := range *complianceMetaConfig.MetasV2 {
		if !isSameExceptTags((*complianceMetaConfig.MetasV2)[i], (*mockComplianceMetaConfig.MetasV2)[i]) {
			t.Errorf("complianceMetaConfig.MetasV2[%d] and mockComplianceMetaConfig.MetasV2[%d] should be the identical", i, i)
		}
		if !isIdenticalTags((*complianceMetaConfig.MetasV2)[i], (*mockComplianceMetaConfig.MetasV2)[i], true) {
			t.Errorf("Tags for complianceMetaConfig.MetasV2[%d] and mockComplianceMetaConfig.MetasV2[%d] should be the same, got %v and %v", i, i, (*complianceMetaConfig.Metas)[i].RESTBenchCheck.Tags, (*mockComplianceMetaConfig.MetasV2)[i].RESTBenchCheck.Tags)
		}
	}

	for key, meta := range complianceMetaConfig.MetaMap {
		mockMeta, ok := mockComplianceMetaConfig.MetaMap[key]
		if !ok {
			t.Errorf("metaMapV2 should contain key %s", key)
		}

		if !isSameExceptTags(meta, mockMeta) {
			t.Errorf("complianceMetaConfig.MetaMap[%s] and mockComplianceMetaConfig.MetaMap[%s] should be identical except for Tags", key, key)
		}

		if !isIdenticalTags(meta, mockMeta, false) {
			t.Errorf("Tags for complianceMetaConfig.MetaMap[%s] and mockComplianceMetaConfig.MetaMap[%s] should be the same, got %v and %v", key, key, meta.RESTBenchCheck.Tags, mockMeta.RESTBenchCheck.Tags)
		}
	}

	for key, meta := range complianceMetaConfig.MetaMapV2 {
		mockMeta, ok := mockComplianceMetaConfig.MetaMapV2[key]
		if !ok {
			t.Errorf("metaMapV2 should contain key %s", key)
		}

		if !isSameExceptTags(meta, mockMeta) {
			t.Errorf("complianceMetaConfig.MetaMapV2[%s] and mockComplianceMetaConfig.MetaMapV2[%s] should be identical except for Tags", key, key)
		}

		if !isIdenticalTags(meta, mockMeta, false) {
			t.Errorf("Tags for complianceMetaConfig.MetaMapV2[%s] and mockComplianceMetaConfig.MetaMapV2[%s] should be the same, got %v and %v", key, key, meta.RESTBenchCheck.Tags, mockMeta.RESTBenchCheck.Tags)
		}
	}
}

func TestComplianceMetaUpdate(t *testing.T) {
	remediationFolder = filepath.Join(".", "testdata", "mock-cis")
	complianceMetaConfig = &UpdateConfigParams{
		Metas:     &complianceMetas,
		MetaMap:   complianceMetaMap,
		MetasV2:   &complianceMetasV2,
		MetaMapV2: complianceMetaMapV2,
	}
	mockComplianceMetaConfig = &UpdateConfigParams{
		Metas:     &mockComplianceMetas,
		MetaMap:   mockComplianceMetaMap,
		MetasV2:   &mockComplianceMetasV2,
		MetaMapV2: mockComplianceMetaMapV2,
	}

	getComplianceMetaForTest(remediationFolder, cisItems, complianceMetaConfig)
	getComplianceMetaForTest(remediationFolder, mockCISItems, mockComplianceMetaConfig)
	checkMetaConfig(t, mockComplianceMetaConfig, complianceMetaConfig)

	remediationFolder = filepath.Join(".", "testdata", "mock-cis-notexist")
	getComplianceMetaForTest(remediationFolder, cisItems, complianceMetaConfig)
	getComplianceMetaForTest(remediationFolder, mockCISItems, mockComplianceMetaConfig)
	checkMetaConfig(t, mockComplianceMetaConfig, complianceMetaConfig)
}

func TestGetComplianceMeta(t *testing.T) {
	metas, metaMap := GetComplianceMeta(V1)
	metasV2, metaMapV2 := GetComplianceMeta(V2)

	if len(metas) != len(metasV2) {
		t.Errorf("metas and metasV2 should have the same length")
	}

	if len(metaMap) != len(metaMapV2) {
		t.Errorf("metaMap and metaMapV2 should have the same length")
	}

	for i := range metas {
		if !isSameExceptTags(metas[i], metasV2[i]) {
			t.Errorf("metas[%d] and metasV2[%d] should be the same except for Tags", i, i)
		}

		if len(metas[i].RESTBenchCheck.Tags) != len(metasV2[i].RESTBenchCheck.TagsV2) {
			t.Errorf("Tags length for metas[%d] and metasV2[%d] should be the same", i, i)
		}

		if len(metas[i].RESTBenchCheck.TagsV2) != 0 {
			t.Errorf("TagsV2 length for metas[%d] should be 0", i)
		}

		if len(metasV2[i].RESTBenchCheck.Tags) != 0 {
			t.Errorf("Tags length for metasV2[%d] should be 0", i)
		}
	}

	for key, meta := range metaMap {
		metaV2, ok := metaMapV2[key]
		if !ok {
			t.Errorf("metaMapV2 should contain key %s", key)
		}

		if !isSameExceptTags(meta, metaV2) {
			t.Errorf("metaMap[%s] and metaMapV2[%s] should be the same except for Tags", key, key)
		}

		if len(meta.RESTBenchCheck.Tags) != len(metaV2.RESTBenchCheck.TagsV2) {
			t.Errorf("Tags length for metaMap[%s] and metaMapV2[%s] should be the same", key, key)
		}

		if len(meta.RESTBenchCheck.TagsV2) != 0 {
			t.Errorf("TagsV2 length for meta should be 0")
		}

		if len(metaV2.RESTBenchCheck.Tags) != 0 {
			t.Errorf("Tags length for metaV2 should be 0")
		}
	}
}

func TestGetImageBenchMeta(t *testing.T) {
	metas, metaMap := InitImageBenchMeta()
	for i := range metas {
		if len(metas[i].RESTBenchCheck.TagsV2) != 0 {
			t.Errorf("TagsV2 length for metas[%d] should be 0", i)
		}
	}

	for _, meta := range metaMap {
		if len(meta.RESTBenchCheck.TagsV2) != 0 {
			t.Errorf("TagsV2 length for meta should be 0")
		}
	}
}

func verifyFilterMapUpdate(t *testing.T, actualFilterMap, expectedFilterMap map[string]int) {
	// Check if the actualFilterMap is updated correctly
	if len(actualFilterMap) != len(expectedFilterMap) {
		t.Errorf("actualFilterMap is not updated correctly, expected length %d, got %d",
			len(expectedFilterMap), len(actualFilterMap))
	}

	for key, actualValue := range actualFilterMap {
		expectedValue, ok := expectedFilterMap[key]
		if !ok || !reflect.DeepEqual(actualValue, expectedValue) {
			t.Errorf("FilterMap[%v] is not updated correctly, expected %v, got %v", key, expectedValue, actualValue)
		}
	}
}

func copyFile(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	if err != nil {
		return err
	}

	return nil
}

// TestUpdateComplianceConfigs verifies that the complianceMetaConfig is correctly updated using the mock-prime-config.yaml file.
// It also ensures that the source directory is empty after the update process is completed.
// Cover the following Cases
// Case 1. if Update is not fully update the the prime config (none of the prime file exist) => ReadPrimeConfig should be false
// Case 2. if Update is not fully update the the prime config (some of the prime file exist) => ReadPrimeConfig should be false
// Case 3. if Update is not fully update the the prime config => ReadPrimeConfig should be true
func TestUpdateComplianceConfigs(t *testing.T) {
	complianceMetaMapV2 = make(map[string]api.RESTBenchMeta)
	complianceMetaMap = make(map[string]api.RESTBenchMeta)
	PrepareBenchMeta(mockLoadItems, complianceMetaMapV2)
	updateComplianceMetasFromMap(&complianceMetas, complianceMetaMap, &complianceMetasV2, complianceMetaMapV2)

	if ReadPrimeConfig {
		t.Errorf("Expected ReadPrimeConfig to be false, but get %v", ReadPrimeConfig)
	}

	dir, err := os.MkdirTemp("", "tmp-testdata")
	if err != nil {
		log.Fatal(err)
	}
	primeConfigFolder = dir
	defer os.RemoveAll(primeConfigFolder)

	// Case 1: None of the prime file exist, ReadPrimeConfig should be false
	primeCISConfig = filepath.Join(primeConfigFolder, "mock-prime-config-not-exist.yaml")
	UpdateComplianceConfigs()
	if ReadPrimeConfig {
		t.Errorf("Expected ReadPrimeConfig to be false, but get %v", ReadPrimeConfig)
	}

	// Case 2: Some of the prime file exist, ReadPrimeConfig should be false
	primeCISConfig = filepath.Join(primeConfigFolder, "mock-prime-config.yaml")

	// Copy the file
	err = copyFile(filepath.Join(".", "testdata", "mock-prime-config.yaml"), primeCISConfig)
	if err != nil {
		t.Errorf("Error copying file: %v\n", err)
	}

	UpdateComplianceConfigs()
	updatecComplianceFilterMap(complianceMetaConfig.Metas, complianceMetaConfig.FilterMap)
	// Check the prime config update the filerfmap correctly
	verifyFilterMapUpdate(t, complianceMetaConfig.FilterMap, expectedFilterMapAfterfLoadConfig)

	// Check complianceMetaConfig is updated correctly
	for _, meta := range *complianceMetaConfig.Metas {
		if meta.TagsV2 != nil {
			t.Errorf("Expected meta.TagsV2 is the should be nil in complianceMetaConfig.Metas")
		}
		if _, ok := expectedTags[meta.TestNum]; ok {
			if len(meta.Tags) != len(expectedTags[meta.TestNum]) {
				t.Errorf("Expected meta.Tags in complianceMetaConfig is the same size as expectedTag")
			}
			for _, compliance := range meta.Tags {
				if _, found := expectedTags[meta.TestNum][compliance]; !found {
					t.Errorf("Expected compliance %s not found for TestNum %s", compliance, meta.TestNum)
				}
			}
		} else {
			t.Errorf("Unexpected TestNum %s found", meta.TestNum)
		}
	}

	for _, meta := range complianceMetaConfig.MetaMap {
		if meta.TagsV2 != nil {
			t.Errorf("Expected meta.TagsV2 is the should be nil in complianceMetaConfig.MetaMap")
		}
		if _, ok := expectedTags[meta.TestNum]; ok {
			if len(meta.Tags) != len(expectedTags[meta.TestNum]) {
				t.Errorf("Expected meta.Tags in complianceMetaConfig is the same size as expectedTag")
			}
			for _, compliance := range meta.Tags {
				if _, found := expectedTags[meta.TestNum][compliance]; !found {
					t.Errorf("Expected compliance %s not found for TestNum %s", compliance, meta.TestNum)
				}
			}
		} else {
			t.Errorf("Unexpected TestNum %s found", meta.TestNum)
		}
	}

	for _, meta := range *complianceMetaConfig.MetasV2 {
		if meta.Tags != nil {
			t.Errorf("Expected meta.Tags is the should be nil in complianceMetaConfig.MetasV2")
		}
		if _, ok := expectedTags[meta.TestNum]; ok {
			for compliance, _ := range meta.TagsV2 {
				if _, found := expectedTags[meta.TestNum][compliance]; !found {
					t.Errorf("Expected compliance %s not found for TestNum %s", compliance, meta.TestNum)
				}
			}
		} else {
			t.Errorf("Unexpected TestNum %s found", meta.TestNum)
		}
	}

	for _, meta := range complianceMetaConfig.MetaMapV2 {
		if meta.Tags != nil {
			t.Errorf("Expected meta.Tags is the should be nil in complianceMetaConfig.MetaMapV2")
		}
		if _, ok := expectedTags[meta.TestNum]; ok {
			for compliance, _ := range meta.TagsV2 {
				if _, found := expectedTags[meta.TestNum][compliance]; !found {
					t.Errorf("Expected compliance %s not found for TestNum %s", compliance, meta.TestNum)
				}
			}
		} else {
			t.Errorf("Unexpected TestNum %s found", meta.TestNum)
		}
	}

	// Case 2: Some of the prime file exist, ReadPrimeConfig should be false
	if ReadPrimeConfig {
		t.Errorf("Expected ReadPrimeConfig to be false, but get %v", ReadPrimeConfig)
	}

	// Case 3: All of the prime file exist, ReadPrimeConfig should be false
	primeCISConfig = filepath.Join(primeConfigFolder, "mock-prime-config.yaml")
	primeDockerConfig = filepath.Join(primeConfigFolder, "mock-prime-config.yaml")
	primeDockerImageConfig = filepath.Join(primeConfigFolder, "mock-prime-config.yaml")
	// Copy the file
	err = copyFile(filepath.Join(".", "testdata", "mock-prime-config.yaml"), primeCISConfig)
	if err != nil {
		t.Errorf("Error copying file: %v\n", err)
	}
	UpdateComplianceConfigs()
	if !ReadPrimeConfig {
		t.Errorf("Expected ReadPrimeConfig to be true, but get %v", ReadPrimeConfig)
	}
}

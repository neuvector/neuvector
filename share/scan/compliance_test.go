package scan

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"encoding/json"
	"log"
	"os"

	"github.com/google/go-cmp/cmp"

	"github.com/neuvector/neuvector/controller/api"
)

var (
	mockComplianceMetas           []api.RESTBenchMeta
	mockLoadMetas                 []api.RESTBenchMeta
	backupMockLoadMetas           []api.RESTBenchMeta
	mockComplianceMetaMap         = make(map[string]api.RESTBenchMeta)
	backupMockLoadMetaMap         = make(map[string]api.RESTBenchMeta)
	mockLoadMetaMap               = make(map[string]api.RESTBenchMeta)
	mockCISItems                  = make(map[string]api.RESTBenchCheck)
	mockCISItemsPathFail          = make(map[string]api.RESTBenchCheck)
	isUpdateMockComplianceMetaMap = false
	isUpdateMockLoadMetaMap       = false
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

type TagsValidator struct {
	Tags []string `json:"Tags"`
}

func TestSetup(t *testing.T) {
	// must PrepareBackup() in the first test function to store the original cisItems
	PrepareBackup()

	for key, value := range backupCISItems {
		mockCISItems[key] = DeepCopyRESTBenchCheck(value)
		cisItems[key] = DeepCopyRESTBenchCheck(value)
		mockCISItemsPathFail[key] = DeepCopyRESTBenchCheck(value)
	}

	for key, value := range mockLoadItems {
		backupMeta := api.RESTBenchMeta{RESTBenchCheck: DeepCopyRESTBenchCheck(value)}
		backupMockLoadMetaMap[key] = backupMeta
		backupMockLoadMetas = append(backupMockLoadMetas, backupMeta)
	}

	PrepareBenchMeta(mockLoadItems, &mockLoadMetas, mockLoadMetaMap, &isUpdateMockLoadMetaMap)
	if isUpdateMockLoadMetaMap {
		updateMetasFromMap(&mockLoadMetas, mockLoadMetaMap, &isUpdateMockLoadMetaMap)
	}
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

		for _, tags := range cisItems[id].Tags {
			for tag, _ := range tags {
				cisItemTagCount[tag]++
			}
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

func getMetaMapForTest(remediationFolder string, items map[string]api.RESTBenchCheck, metas []api.RESTBenchMeta, metaMap map[string]api.RESTBenchMeta, updateFlag *bool) ([]api.RESTBenchMeta, map[string]api.RESTBenchMeta) {
	GetK8sCISMeta(remediationFolder, items)
	PrepareBenchMeta(items, &metas, metaMap, updateFlag)
	if *updateFlag {
		updateMetasFromMap(&metas, metaMap, updateFlag)
	}

	return metas, metaMap
}

func TestGetComplianceMeta(t *testing.T) {
	remediationFolder = filepath.Join(".", "testdata", "mock-cis")
	metas, metaMap := getMetaMapForTest(remediationFolder, cisItems, complianceMetas, complianceMetaMap, &isUpdateComplianceMetaMap)
	mockMetas, mockMetaMap := getMetaMapForTest(remediationFolder, mockCISItems, mockComplianceMetas, mockComplianceMetaMap, &isUpdateMockComplianceMetaMap)

	if diff := cmp.Diff(mockMetas, metas); diff != "" {
		t.Errorf("mockMetas metas (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff(mockMetaMap, metaMap); diff != "" {
		t.Errorf("mockMetaMap mismatch (-want +got):\n%s", diff)
	}

	// After update, we need to make sure we close the update flag
	if isUpdateComplianceMetaMap {
		t.Error("isUpdateComplianceMetaMap is not update properly")
	}

	if isUpdateMockComplianceMetaMap {
		t.Error("isUpdateMockComplianceMetaMap is not update properly")
	}

	// Test when the path is not exist
	remediationFolder = filepath.Join(".", "testdata", "mock-cis-notexist")
	metas, metaMap = getMetaMapForTest(remediationFolder, cisItems, complianceMetas, complianceMetaMap, &isUpdateComplianceMetaMap)

	PrepareBenchMeta(mockCISItems, &mockComplianceMetas, mockComplianceMetaMap, &isUpdateMockComplianceMetaMap)
	updateMetasFromMap(&mockComplianceMetas, mockComplianceMetaMap, &isUpdateMockComplianceMetaMap)

	if diff := cmp.Diff(mockComplianceMetas, metas); diff != "" {
		t.Errorf("mockMetas metas (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff(mockComplianceMetaMap, metaMap); diff != "" {
		t.Errorf("mockMetaMap mismatch (-want +got):\n%s", diff)
	}

	// After update, we need to make sure we close the update flag
	if isUpdateComplianceMetaMap {
		t.Error("isUpdateComplianceMetaMap is not update properly")
	}

	if isUpdateMockComplianceMetaMap {
		t.Error("isUpdateMockComplianceMetaMap is not update properly")
	}
}

func getMetaMapForLoadTest(metas *[]api.RESTBenchMeta, metaMap map[string]api.RESTBenchMeta, updateFlag *bool) {
	if *updateFlag {
		updateMetasFromMap(metas, metaMap, updateFlag)
	}
}

func TestLoadCreateEmpty(t *testing.T) {
	dir, err := os.MkdirTemp("", "testdata")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	primeConfig := filepath.Join(dir, "mock.yml")

	// Run Load in a goroutine and use a channel to wait for it to finish setup
	done := make(chan bool)
	go func() {
		LoadConfig(primeConfig, mockLoadMetaMap, &isUpdateMockLoadMetaMap)
		close(done)
		fmt.Println("stop the channel")
	}()

	// Give some time for fsnotify to start watching
	time.Sleep(1 * time.Second)
	// Create an empty file at primeConfig path
	file, err := os.Create(primeConfig)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	file.Close()
	<-done

	getMetaMapForLoadTest(&mockLoadMetas, mockLoadMetaMap, &isUpdateMockLoadMetaMap)
	for _, meta := range mockLoadMetas {
		if len(meta.Tags) != 0 {
			t.Error("Expected Tag in metas to be empty")
		}
	}

	for _, meta := range mockLoadMetaMap {
		if len(meta.Tags) != 0 {
			t.Error("Expected Tag in metas to be empty")
		}
	}

	// Clean up and stop Load
	os.Remove(primeConfig)

}

func TestLoadCreateExisting(t *testing.T) {
	TestSetup(t)
	dir, err := os.MkdirTemp("", "testdata")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)
	primeConfig := filepath.Join(dir, "mock.yml")

	// Run Load in a goroutine and use a channel to wait for it to finish setup
	done := make(chan bool)
	go func() {
		LoadConfig(primeConfig, mockLoadMetaMap, &isUpdateMockLoadMetaMap)
		close(done)
		fmt.Println("XXX done", mockLoadMetaMap)
	}()

	// Give some time for fsnotify to start watching
	time.Sleep(1 * time.Second)
	mock_prime_config := filepath.Join(".", "testdata", "mock-prime-config.yaml")
	content, err := os.ReadFile(mock_prime_config)
	if err != nil {
		log.Fatalf("Failed to read from file: %v", err)
	}
	// Create the file && Write Situation
	os.WriteFile(primeConfig, content, 0644)

	<-done
	getMetaMapForLoadTest(&mockLoadMetas, mockLoadMetaMap, &isUpdateMockLoadMetaMap)
	fmt.Println("XXX getMetaMapForLoadTest", mockLoadMetaMap)

	// Iterate over the slice of Meta structs
	for _, meta := range mockLoadMetas {
		// Check if the current meta ID is one we're interested in
		if _, ok := expectedTags[meta.TestNum]; ok {
			for _, tag := range meta.Tags {
				for compliance, _ := range tag {
					if _, found := expectedTags[meta.TestNum][compliance]; !found {
						t.Errorf("Expected compliance %s not found for TestNum %s", compliance, meta.TestNum)
					}
				}
			}
		} else {
			t.Errorf("Unexpected TestNum %s found", meta.TestNum)
		}
	}

	for _, meta := range mockLoadMetaMap {
		// Check if the current meta ID is one we're interested in
		if _, ok := expectedTags[meta.TestNum]; ok {
			for _, tag := range meta.Tags {
				for compliance, _ := range tag {
					if _, found := expectedTags[meta.TestNum][compliance]; !found {
						t.Errorf("Expected compliance %s not found for TestNum %s", compliance, meta.TestNum)
					}
				}
			}
		} else {
			t.Errorf("Unexpected TestNum %s found", meta.TestNum)
		}
	}
	os.Remove(primeConfig)
}

package db

import (
	"bytes"
	"net/http"
	"testing"
)

func TestCreateDatabaseAndTables(t *testing.T) {
	err := CreateVulAssetDb(true)
	if err != nil {
		t.Errorf("CreateDatabase() returns %v", err)
	}
	t.Log("CreateDatabase completed successfully.")
}

func TestQueryFilterParsing(t *testing.T) {
	url := "/v1/vulassets"
	method := "POST"

	// use an invalid value for viewType
	payload := []byte(`{"viewType": "containers__invalid"}`)

	req, err := http.NewRequest(method, url, bytes.NewBuffer(payload))
	if err != nil {
		t.Errorf("create http request failed, returned %v", err)
		return
	}

	// parse it
	queryFilter, err := GetVulnerabilityQuery(req)
	if err != nil {
		t.Errorf("GetVulnerabilityQuery returned %v", err)
	}

	// it should treat it as default
	if queryFilter.Filters.ViewType != "all" {
		t.Errorf("Invalid view type should treat as all, returned %v", queryFilter.Filters.ViewType)
	}
}

func TestAssetBasedFilterParsing(t *testing.T) {
	url := "/v1/vulassets"
	method := "POST"

	// prepare two asset based filters
	payload := []byte(`{"matchTypeContainer": "equals", "containerName": "loki", "matchTypeService": "contains", "serviceName": "svc"}`)
	req, err := http.NewRequest(method, url, bytes.NewBuffer(payload))
	if err != nil {
		t.Errorf("create http request failed, returned %v", err)
		return
	}

	// parse it
	queryFilter, err := GetVulnerabilityQuery(req)
	if err != nil {
		t.Errorf("GetVulnerabilityQuery returned %v", err)
	}

	// verify it can parse correctly
	filters := queryFilter.GetAssestBasedFilters()
	if filters[AssetRuleService] != 1 {
		t.Error("Asset based filter doesn't contains service type")
	}

	if filters[AssetRuleContainer] != 1 {
		t.Error("Asset based filter doesn't contains container type")
	}
}

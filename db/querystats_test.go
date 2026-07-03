package db

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPopulateQueryStat(t *testing.T) {
	err := CreateVulAssetDb(true)
	if err != nil {
		t.Errorf("CreateDatabase() returns %v", err)
	}

	id := "0123456789ab"
	queryID, err := GenQueryID(id)
	assert.NoError(t, err)
	qs := &QueryStat{
		QueryID:      queryID,
		CreationTime: time.Now().UTC().Unix(),
		LoginType:    1,
		LoginID:      "111",
		LoginName:    "admin",
		Data1:        "",
	}

	_, err = PopulateQueryStat(qs)
	if err != nil {
		t.Errorf("PopulateQueryStat() returns %v", err)
	}

	// read it back
	readbackQs, err := GetQueryStat(queryID, id)
	if err != nil {
		t.Errorf("GetQueryStat() returns %v", err)
	}

	if readbackQs.QueryID != queryID {
		t.Errorf("Read back query stat data doesn't match. Expected %v, but got %v", queryID, readbackQs.QueryID)
	}

	t.Log("TestQueryStat completed successfully.")
}

func TestDeleteQuerySession(t *testing.T) {
	err := CreateVulAssetDb(true)
	if err != nil {
		t.Errorf("CreateDatabase() returns %v", err)
	}

	id := "0123456789ab"
	queryID, err := GenQueryID(id)
	assert.NoError(t, err)
	qs := &QueryStat{
		QueryID:      queryID,
		CreationTime: time.Now().UTC().Unix(),
		LoginType:    1,
		LoginID:      id,
		LoginName:    "admin",
		Data1:        "",
	}

	_, err = PopulateQueryStat(qs)
	if err != nil {
		t.Errorf("PopulateQueryStat() returns %v", err)
	}

	// read it back
	readbackQs, err := GetQueryStat(queryID, id)
	if err != nil {
		t.Errorf("GetQueryStat() returns %v", err)
	}

	if readbackQs.QueryID != queryID {
		t.Errorf("Read back query stat data doesn't match. Expected %v, but got %v", queryID, readbackQs.QueryID)
	}

	// delete it
	// This function will fail because it attempts to delete both the in-memory and file-based databases,
	// but only a file-based database is in use.
	_ = DeleteQuerySessionByQueryID(queryID)

	// we should not get any records back
	readbackQs, err = GetQueryStat(queryID, id)
	if err == nil {
		t.Error("Read deleted query status, got success return code. Expected error returned.")
	}

	// the query stats should be nil as it is deleted
	if readbackQs != nil {
		t.Errorf("Read deleted query status, still got something back. Got %v", readbackQs)
	}

	t.Log("TestDeleteQuerySession completed successfully.")
}

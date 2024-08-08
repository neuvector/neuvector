package db

import (
	"testing"
	"time"
)

func TestPopulateQueryStat(t *testing.T) {
	err := CreateVulAssetDb(true)
	if err != nil {
		t.Errorf("CreateDatabase() returns %v", err)
	}

	queryToken := "query-token-111"
	qs := &QueryStat{
		Token:        queryToken,
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
	readbackQs, err := GetQueryStat(queryToken)
	if err != nil {
		t.Errorf("GetQueryStat() returns %v", err)
	}

	if readbackQs.Token != queryToken {
		t.Errorf("Read back query stat data doesn't match. Expected %v, but got %v", queryToken, readbackQs.Token)
	}

	t.Log("TestQueryStat completed successfully.")
}

func TestDeleteQuerySession(t *testing.T) {
	err := CreateVulAssetDb(true)
	if err != nil {
		t.Errorf("CreateDatabase() returns %v", err)
	}

	queryToken := "query-token-111"
	qs := &QueryStat{
		Token:        queryToken,
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
	readbackQs, err := GetQueryStat(queryToken)
	if err != nil {
		t.Errorf("GetQueryStat() returns %v", err)
	}

	if readbackQs.Token != queryToken {
		t.Errorf("Read back query stat data doesn't match. Expected %v, but got %v", queryToken, readbackQs.Token)
	}

	// delete it
	err = DeleteQuerySessionByToken(queryToken)
	if err != nil {
		t.Errorf("DeleteQuerySessionByToken() returns %v", err)
	}

	// we should not get any records back
	readbackQs, err = GetQueryStat(queryToken)
	if err == nil {
		t.Error("Read deleted query status, got success return code. Expected error returned.")
	}

	// the query stats should be nil as it is deleted
	if readbackQs != nil {
		t.Errorf("Read deleted query status, still got something back. Got %v", readbackQs)
	}

	t.Log("TestDeleteQuerySession completed successfully.")
}

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

func TestQueryStatQueryByName(t *testing.T) {
	err := CreateVulAssetDb(true)
	if err != nil {
		t.Errorf("CreateDatabase() returns %v", err)
	}

	// populate one query stat
	queryToken1 := "query-token-111"
	userName := "admin"
	qs := &QueryStat{
		Token:        queryToken1,
		CreationTime: time.Now().UTC().Unix(),
		LoginType:    1,
		LoginID:      "111",
		LoginName:    userName,
		Data1:        "",
	}

	_, err = PopulateQueryStat(qs)
	if err != nil {
		t.Errorf("PopulateQueryStat() returns %v", err)
	}

	// populate another query stat
	queryToken2 := "query-token-222"
	qs = &QueryStat{
		Token:        queryToken2,
		CreationTime: time.Now().UTC().Unix(),
		LoginType:    1,
		LoginID:      "111",
		LoginName:    userName,
		Data1:        "",
	}

	_, err = PopulateQueryStat(qs)
	if err != nil {
		t.Errorf("PopulateQueryStat() returns %v", err)
	}

	// read it back
	queryStats, err := GetQueryStatsByLoginName(userName)
	if err != nil {
		t.Errorf("GetQueryStatsByLoginName() returns %v", err)
	}

	if len(queryStats) != 2 {
		t.Errorf("Doesn't get all query status, Expected %v, but got %v", 2, len(queryStats))
	}

	for _, record := range queryStats {
		if record.LoginName != userName {
			t.Errorf("Got unexpected query token, Expected login name %v, but got %v", userName, record.LoginName)
		}
	}

	t.Log("TestQueryStatQueryByName completed successfully.")
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

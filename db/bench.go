package db

import (
	"errors"

	"github.com/doug-martin/goqu/v9"
	"github.com/doug-martin/goqu/v9/exp"
	_ "github.com/mattn/go-sqlite3"
)

type DbBench struct {
	Db_ID            int
	Type             string
	AssetID          string
	CustomBenchValue []byte
	DockerBenchValue []byte
	MasterBenchValue []byte
	WorkerBenchValue []byte
	SecretBenchValue []byte
	SetidBenchValue  []byte
}

func getBenchSchema() []string {
	schema := []string{"id INTEGER NOT NULL PRIMARY KEY", "type TEXT", "assetid TEXT UNIQUE", // type="workload", "host"
		"CustomBenchValue BLOB", "DockerBenchValue BLOB", "MasterBenchValue BLOB",
		"WorkerBenchValue BLOB", "SecretBenchValue BLOB", "SetidBenchValue BLOB",
		"notes TEXT", // for debug
	}

	return schema
}

func GetBenchData(assetID string) (*DbBench, error) {
	bench := &DbBench{}

	columns := []interface{}{"Type",
		"CustomBenchValue", "DockerBenchValue", "MasterBenchValue",
		"WorkerBenchValue", "SecretBenchValue", "SetidBenchValue"}

	dialect := goqu.Dialect("sqlite3")
	statement, args, _ := dialect.From(Table_bench).Select(columns...).Where(goqu.C("assetid").Eq(assetID)).Prepared(true).ToSQL()

	rows, err := dbHandle.Query(statement, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if rows.Next() {
		err = rows.Scan(&bench.Type, &bench.CustomBenchValue, &bench.DockerBenchValue, &bench.MasterBenchValue,
			&bench.WorkerBenchValue, &bench.SecretBenchValue, &bench.SetidBenchValue)
		if err != nil {
			return nil, err
		}
		return bench, nil
	}

	return nil, errors.New("no such asset id")
}

func PopulateBenchData(bench *DbBench) error {
	if dbHandle == nil {
		return errors.New("db is not initialized")
	}

	existingID, err := getBenchID(bench.AssetID)
	if err != nil {
		bench.Db_ID = 0 // not exist, need to create a new one
	} else {
		bench.Db_ID = existingID
	}

	// update/insert
	_, err = UpdateBenchData(bench)
	if err != nil {
		return err
	}
	return nil
}

func UpdateBenchData(bench *DbBench) (int, error) {
	db := dbHandle
	dialect := goqu.Dialect("sqlite3")

	// Insert case
	if bench.Db_ID == 0 {
		ds := dialect.Insert(Table_bench).Rows(getCompiledBenchRecord(bench))
		sql, args, _ := ds.Prepared(true).ToSQL()

		result, err := db.Exec(sql, args...)
		if err != nil {
			return 0, err
		}

		lastInsertID, err := result.LastInsertId()
		if err != nil {
			return 0, err
		}

		return int(lastInsertID), nil
	}

	// Update case
	sql, args, _ := dialect.Update(Table_bench).Where(goqu.C("id").Eq(bench.Db_ID)).Set(getCompiledBenchRecord(bench)).Prepared(true).ToSQL()
	_, err := db.Exec(sql, args...)
	if err != nil {
		return 0, err
	}

	return bench.Db_ID, nil
}

func getBenchID(assetID string) (int, error) {
	dialect := goqu.Dialect("sqlite3")
	statement, args, _ := dialect.From(Table_bench).Select("id").Where(goqu.C("assetid").Eq(assetID)).Prepared(true).ToSQL()

	rows, err := dbHandle.Query(statement, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	if rows.Next() {
		var dbid int
		err = rows.Scan(&dbid)
		if err != nil {
			return 0, err
		}
		return dbid, nil
	}

	return 0, errors.New("no such asset id")
}

func getCompiledBenchRecord(bench *DbBench) *exp.Record {
	record := &goqu.Record{
		"type":             bench.Type,
		"assetid":          bench.AssetID,
		"CustomBenchValue": bench.CustomBenchValue,
		"DockerBenchValue": bench.DockerBenchValue,
		"MasterBenchValue": bench.MasterBenchValue,
		"WorkerBenchValue": bench.WorkerBenchValue,
		"SecretBenchValue": bench.SecretBenchValue,
		"SetidBenchValue":  bench.SetidBenchValue,
	}

	return record
}

func DeleteBenchByID(assetID string) error {
	dialect := goqu.Dialect("sqlite3")
	db := dbHandle

	sql, args, _ := dialect.Delete(Table_bench).Where(goqu.C("assetid").Eq(assetID)).Prepared(true).ToSQL()
	_, err := db.Exec(sql, args...)
	if err != nil {
		return err
	}
	return nil
}

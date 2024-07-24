package db

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/doug-martin/goqu/v9"
	_ "github.com/mattn/go-sqlite3"
)

type QueryStat struct {
	Db_ID        int
	Token        string
	CreationTime int64
	LoginID      string // APIKey will be different for each request..
	LoginName    string
	LoginType    int // 0=JWTToken, 1=APIKey
	Data1        string
	Data2        string
	Data3        string
	FileDBReady  int
	Type         int // QueryStateType_Vul(0), QueryStateType_Asset(1)
}

const queryStatTablename = "querystats"

func PopulateQueryStat(queryStat *QueryStat) (int, error) {
	dialect := goqu.Dialect("sqlite3")
	ds := dialect.Insert(queryStatTablename).Rows(
		goqu.Record{
			"token":            queryStat.Token,
			"create_timestamp": queryStat.CreationTime,
			"login_type":       queryStat.LoginType,
			"login_id":         queryStat.LoginID,
			"login_name":       queryStat.LoginName,
			"data1":            queryStat.Data1,
			"data2":            queryStat.Data2,
			"data3":            queryStat.Data3,
			"filedb_ready":     queryStat.FileDBReady,
			"type":             queryStat.Type,
		},
	)
	sql, args, _ := ds.Prepared(true).ToSQL()

	// execute the statement
	var lastErr error
	for retry := 0; retry < 50; retry++ {
		result, err := dbHandle.Exec(sql, args...)
		if err != nil {
			if shouleRetry(err) {
				time.Sleep(time.Millisecond * time.Duration(retry*retry))
				lastErr = err
				continue
			}
			return 0, err
		}

		lastInsertID, err := result.LastInsertId()
		if err != nil {
			return 0, err
		}

		return int(lastInsertID), nil
	}

	if lastErr != nil && shouleRetry(lastErr) {
		return 0, lastErr
	}

	return 0, errors.New("populate query stat failed")
}

func GetQueryStat(token string) (*QueryStat, error) {
	dialect := goqu.Dialect("sqlite3")

	columns := []interface{}{"id", "token", "create_timestamp", "login_type", "login_id", "login_name", "data1", "data2", "data3", "filedb_ready", "type"}
	sql, args, _ := dialect.From(queryStatTablename).Select(columns...).Where(goqu.C("token").Eq(token)).Prepared(true).ToSQL()

	var lastErr error
	for retry := 0; retry < 50; retry++ {
		rows, err := dbHandle.Query(sql, args...)
		if err != nil {
			if shouleRetry(err) {
				time.Sleep(time.Millisecond * time.Duration(retry*retry))
				lastErr = err
				continue
			}
			return nil, err
		}
		defer rows.Close()

		stat := &QueryStat{}
		if rows.Next() {
			err = rows.Scan(&stat.Db_ID, &stat.Token, &stat.CreationTime, &stat.LoginType, &stat.LoginID,
				&stat.LoginName, &stat.Data1, &stat.Data2, &stat.Data3, &stat.FileDBReady, &stat.Type)
			if err != nil {
				return nil, err
			}
			return stat, nil
		}
		break
	}

	if lastErr != nil && shouleRetry(lastErr) {
		return nil, lastErr
	}

	return nil, errors.New("no such query token")
}

func GetExceededSessions(loginName, loginID string, loginType int) ([]string, error) {
	dialect := goqu.Dialect("sqlite3")

	records := make([]string, 0)
	columns := []interface{}{"token"}

	expLoginName := goqu.Ex{"login_name": loginName}
	// expLoginId := goqu.Ex{"login_id": loginID}

	nLimit := 10
	if loginType == 1 {
		nLimit = 2 // apikey
	}
	// sql, args, _ := dialect.From(Table_querystats).Select(columns...).Where(goqu.And(expLoginName, expLoginId)).Order(goqu.C("create_timestamp").Desc()).Limit(100).Offset(uint(nLimit)).Prepared(true).ToSQL()
	sql, args, _ := dialect.From(Table_querystats).Select(columns...).Where(goqu.And(expLoginName)).Order(goqu.C("create_timestamp").Desc()).Limit(100).Offset(uint(nLimit)).Prepared(true).ToSQL()

	rows, err := dbHandle.Query(sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var token string
		err = rows.Scan(&token)
		if err != nil {
			return nil, err
		}

		records = append(records, token)
	}

	// exceed 2 hours of create_timestamp
	t := time.Now().UTC().Unix() - 7200
	sql, args, _ = dialect.From(Table_querystats).Select(columns...).Where(goqu.Ex{"create_timestamp": goqu.Op{"lt": t}}).Prepared(true).ToSQL()

	rows, err = dbHandle.Query(sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var token string
		err = rows.Scan(&token)
		if err != nil {
			return nil, err
		}

		records = append(records, token)
	}

	return records, nil
}

func setFileDbState(queryToken string, newValue int) error {
	dialect := goqu.Dialect("sqlite3")
	sql, args, _ := dialect.Update(queryStatTablename).Where(goqu.C("token").Eq(queryToken)).Set(
		goqu.Record{
			"filedb_ready": newValue,
		},
	).Prepared(true).ToSQL()

	_, err := dbHandle.Exec(sql, args...)
	if err != nil {
		return err
	}

	return nil
}

func DeleteQuerySessionByToken(queryToken string) error {
	qs, err := GetQueryStat(queryToken)
	if err != nil {
		return err
	}

	// delete record in querystats table
	dialect := goqu.Dialect("sqlite3")
	sql, args, _ := dialect.Delete("querystats").Where(goqu.ExOr{"id": goqu.Op{"eq": qs.Db_ID}}).Prepared(true).ToSQL()
	_, err = dbHandle.Exec(sql, args...)
	if err != nil {
		return err
	}

	// delete session table in memory
	err = deleteSessionTempTableInMemDb(queryToken)
	if err != nil {
		return err
	}

	// delete the session table in file-based db, ignore the error
	deleteSessionFileDb(queryToken)

	return nil
}

func deleteSessionTempTableInMemDb(queryToken string) error {
	memdbMutex.Lock()
	defer memdbMutex.Unlock()

	db := memoryDbHandle

	// SQLite does not support parameterized substitution for table and column names, only for values.
	if len(queryToken) == 12 && isValidSessionTableName(queryToken) {
		for i := 0; i < 10; i++ {
			sql := fmt.Sprintf("DROP TABLE IF EXISTS '%s';", formatSessionTempTableName(queryToken))
			_, err := db.Exec(sql)
			if err != nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			break
		}
	}

	return nil
}

func isValidSessionTableName(name string) bool {
	match, _ := regexp.MatchString("^[a-f0-9]+$", name)
	return match
}

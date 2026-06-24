package db

import (
	"encoding/json"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
)

// ReplaceCVEDB atomically replaces the entire cvedb table in a single transaction.
// iterate is called with a writeFn; the caller must call writeFn once per consul slot.
// Slots are processed one at a time so they are never all in memory simultaneously.
func ReplaceCVEDB(version, createTime string, iterate func(writeFn func(*share.CLUSScannerDB) error) error) error {
	if dbCVEHandle == nil {
		return fmt.Errorf("cvedb: db not initialized")
	}
	tx, err := dbCVEHandle.Begin()
	if err != nil {
		return fmt.Errorf("cvedb: begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				log.WithFields(log.Fields{"err": rbErr}).Warn("cvedb: rollback failed")
			}
		}
	}()

	if _, err = tx.Exec("DELETE FROM " + Table_cvedb); err != nil {
		return fmt.Errorf("cvedb: delete: %w", err)
	}

	const insertSQL = `INSERT OR REPLACE INTO cvedb
		(name, prefix, score, score_v3, severity, description, link, vectors, vectors_v3,
		 published_date, last_modified_date, package_name, fixed_version,
		 feed_rating, in_base, db_key, cpes, cves)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	stmt, err := tx.Prepare(insertSQL)
	if err != nil {
		return fmt.Errorf("cvedb: prepare insert: %w", err)
	}
	defer stmt.Close()

	writeFn := func(slot *share.CLUSScannerDB) error {
		for name, cve := range slot.CVEDB {
			cpesJSON, err := json.Marshal(cve.CPEs)
			if err != nil {
				return fmt.Errorf("cvedb: failed to marshal cpes: %w", err)
			}
			cvesJSON, err := json.Marshal(cve.CVEs)
			if err != nil {
				return fmt.Errorf("cvedb: failed to marshal cves: %w", err)
			}
			inBase := 0
			if cve.InBase {
				inBase = 1
			}
			if _, err := stmt.Exec(
				name, prefixOf(name),
				cve.Score, cve.ScoreV3,
				cve.Severity, cve.Description, cve.Link,
				cve.Vectors, cve.VectorsV3,
				cve.PublishedDate, cve.LastModifiedDate,
				cve.PackageName, cve.FixedVersion,
				cve.FeedRating, inBase, cve.DBKey,
				string(cpesJSON), string(cvesJSON),
			); err != nil {
				return fmt.Errorf("cvedb: insert %q: %w", name, err)
			}
		}
		return nil
	}

	if err = iterate(writeFn); err != nil {
		return fmt.Errorf("cvedb: iterate slots: %w", err)
	}

	if _, err = tx.Exec(
		"INSERT OR REPLACE INTO cvedb_meta (id, db_version, db_create_time) VALUES (1, ?, ?)",
		version, createTime,
	); err != nil {
		return fmt.Errorf("cvedb: upsert meta: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("cvedb: commit: %w", err)
	}
	return nil
}

// LoadPrefixGroup fetches all CVE entries for the given baseOS prefix from SQLite.
// prefix = "ubuntu" returns all "ubuntu:*" entries (one indexed equality scan).
// prefix = "" returns all bare CVE names (no ":" in the key).
func LoadPrefixGroup(prefix string) (map[string]*share.ScanVulnerability, error) {
	if dbCVEHandle == nil {
		return nil, fmt.Errorf("cvedb: db not initialized")
	}
	rows, err := dbCVEHandle.Query(
		`SELECT name, score, score_v3, severity, description, link, vectors, vectors_v3,
		        published_date, last_modified_date, package_name, fixed_version,
		        feed_rating, in_base, db_key, cpes, cves
		 FROM cvedb WHERE prefix = ?`, prefix)
	if err != nil {
		return nil, fmt.Errorf("cvedb: query prefix %q: %w", prefix, err)
	}
	defer rows.Close()

	result := make(map[string]*share.ScanVulnerability)
	for rows.Next() {
		var (
			name, severity, desc, link, vectors, vectorsV3 string
			pubDate, lastModDate, pkgName, fixedVer        string
			feedRating, dbKey                              string
			cpesJSON, cvesJSON                             string
			inBase                                         int
			score, scoreV3                                 float32
		)
		if err := rows.Scan(
			&name, &score, &scoreV3, &severity, &desc, &link, &vectors, &vectorsV3,
			&pubDate, &lastModDate, &pkgName, &fixedVer,
			&feedRating, &inBase, &dbKey, &cpesJSON, &cvesJSON,
		); err != nil {
			return nil, fmt.Errorf("cvedb: scan row: %w", err)
		}

		cve := &share.ScanVulnerability{
			Name:             name,
			Score:            score,
			ScoreV3:          scoreV3,
			Severity:         severity,
			Description:      desc,
			Link:             link,
			Vectors:          vectors,
			VectorsV3:        vectorsV3,
			PublishedDate:    pubDate,
			LastModifiedDate: lastModDate,
			PackageName:      pkgName,
			FixedVersion:     fixedVer,
			FeedRating:       feedRating,
			InBase:           inBase != 0,
			DBKey:            dbKey,
		}
		if cpesJSON != "" && cpesJSON != "null" {
			err = json.Unmarshal([]byte(cpesJSON), &cve.CPEs)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal cpe json: %w", err)
			}
		}
		if cvesJSON != "" && cvesJSON != "null" {
			err = json.Unmarshal([]byte(cvesJSON), &cve.CVEs)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal cve json: %w", err)
			}
		}
		result[name] = cve
	}
	return result, rows.Err()
}

// GetCVECount returns the number of entries in the cvedb table.
func GetCVECount() (int, error) {
	if dbCVEHandle == nil {
		return 0, fmt.Errorf("cvedb: db not initialized")
	}
	var count int
	err := dbCVEHandle.QueryRow("SELECT COUNT(*) FROM " + Table_cvedb).Scan(&count)
	return count, err
}

// prefixOf extracts the prefix from a CVEDB key. Returns "" for bare CVE names.
func prefixOf(name string) string {
	prefix, _, _ := strings.Cut(name, ":")
	if prefix == name {
		return "" // no ":" found — bare CVE name
	}
	return prefix
}

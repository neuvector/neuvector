package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decodeBatch(t *testing.T, zb []byte) share.CLUSScannerDB {
	t.Helper()
	gr, err := gzip.NewReader(bytes.NewReader(zb))
	require.NoError(t, err)
	var db share.CLUSScannerDB
	require.NoError(t, json.NewDecoder(gr).Decode(&db))
	return db
}

func makeScannerData(version, createTime string, cves map[string]*share.ScanVulnerability) *share.ScannerRegisterData {
	return &share.ScannerRegisterData{
		CVEDBVersion:    version,
		CVEDBCreateTime: createTime,
		CVEDB:           cves,
	}
}

func simpleCVEs(n int) map[string]*share.ScanVulnerability {
	m := make(map[string]*share.ScanVulnerability, n)
	for i := range n {
		name := fmt.Sprintf("CVE-2021-%04d", i)
		m[name] = &share.ScanVulnerability{Name: name}
	}
	return m
}

func TestIncrementalDBWriter(t *testing.T) {
	const testVersion = "1.0"
	const testCreateTime = "2024-01-01"

	// Compute entry and base sizes used by threshold-dependent cases.
	// All simpleCVE entries share the same size since names are fixed-width ("CVE-2021-XXXX").
	sampleName := "CVE-2021-0000"
	entrySize, err := cveEntryJSONSize(sampleName, &share.ScanVulnerability{Name: sampleName})
	require.NoError(t, err)
	emptyBase, err := json.Marshal(share.CLUSScannerDB{
		CVEDBVersion:    testVersion,
		CVEDBCreateTime: testCreateTime,
		CVEDB:           make(map[string]*share.ScanVulnerability),
	})
	require.NoError(t, err)
	// twoPerSlot is a threshold that fits exactly 2 simpleCVE entries per slot:
	// after 2 entries currentSize == threshold (not over), but adding a 3rd pushes it over.
	twoPerSlot := len(emptyBase) + 2*entrySize

	cases := []struct {
		name         string
		entries      map[string]*share.ScanVulnerability
		slotSizeMax  int // 0 = use default cvedbSlotSizeMax
		kvSizeMax    int // 0 = use default cluster.KVValueSizeMax
		writeFuncErr error
		wantSlots    int
		wantTotal    int
		wantErr      bool
	}{
		{
			name:      "empty input produces no slots",
			entries:   map[string]*share.ScanVulnerability{},
			wantSlots: 0,
			wantTotal: 0,
		},
		{
			name:      "entries below threshold produce one slot",
			entries:   simpleCVEs(3),
			wantSlots: 1,
			wantTotal: 3,
		},
		{
			name:        "entries exactly at threshold produce one slot",
			entries:     simpleCVEs(2),
			slotSizeMax: twoPerSlot,
			wantSlots:   1,
			wantTotal:   2,
		},
		{
			name:        "entries one over threshold produce two slots",
			entries:     simpleCVEs(3),
			slotSizeMax: twoPerSlot,
			wantSlots:   2,
			wantTotal:   3,
		},
		{
			name:        "five entries with two-per-slot threshold produce three slots",
			entries:     simpleCVEs(5),
			slotSizeMax: twoPerSlot,
			wantSlots:   3,
			wantTotal:   5,
		},
		{
			name: "colon-prefixed CVE expands to two entries",
			entries: map[string]*share.ScanVulnerability{
				"ubuntu:CVE-2021-001": {Description: "heap overflow"},
			},
			wantSlots: 1,
			wantTotal: 2,
		},
		{
			name: "duplicate CVE name is counted once",
			// ubuntu:CVE-2021-001 expands to CVE-2021-001 (dup, skipped) + ubuntu:CVE-2021-001;
			// plain CVE-2021-001 is also skipped as dup → 2 unique entries total.
			entries: map[string]*share.ScanVulnerability{
				"CVE-2021-001":        {Description: "first"},
				"ubuntu:CVE-2021-001": {Description: "second"},
			},
			wantSlots: 1,
			wantTotal: 2,
		},
		{
			name:      "compressed slot exceeding KV limit returns error",
			entries:   simpleCVEs(1),
			kvSizeMax: 1,
			wantErr:   true,
		},
		{
			name:         "write function error is propagated",
			entries:      simpleCVEs(1),
			writeFuncErr: errors.New("consul unavailable"),
			wantErr:      true,
		},
		{
			name:        "metadata is preserved in every slot",
			entries:     simpleCVEs(4),
			slotSizeMax: twoPerSlot,
			// 4 entries / 2-per-slot → 2 slots; both must carry correct version and createTime.
			wantSlots: 2,
			wantTotal: 4,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.slotSizeMax > 0 {
				orig := cvedbSlotSizeMax
				cvedbSlotSizeMax = c.slotSizeMax
				defer func() { cvedbSlotSizeMax = orig }()
			}
			if c.kvSizeMax > 0 {
				orig := cluster.KVValueSizeMax
				cluster.KVValueSizeMax = c.kvSizeMax
				defer func() { cluster.KVValueSizeMax = orig }()
			}

			var batches [][]byte
			writeFunc := func(_ int, data []byte) error {
				if c.writeFuncErr != nil {
					return c.writeFuncErr
				}
				batches = append(batches, data)
				return nil
			}
			w, err := newIncrementalDBWriter(testVersion, testCreateTime, "scan/database/test/", writeFunc)
			require.NoError(t, err)

			var addErr error
			for name, cve := range c.entries {
				if addErr = w.Add(name, cve); addErr != nil {
					break
				}
			}
			if addErr == nil {
				addErr = w.Flush()
			}

			if c.wantErr {
				require.Error(t, addErr)
				return
			}
			require.NoError(t, addErr)
			assert.Equal(t, c.wantSlots, len(batches), "slot count")
			assert.Equal(t, c.wantTotal, w.Total, "Total entry count")

			total := 0
			for _, zb := range batches {
				db := decodeBatch(t, zb)
				assert.Equal(t, testVersion, db.CVEDBVersion, "CVEDBVersion in slot")
				assert.Equal(t, testCreateTime, db.CVEDBCreateTime, "CVEDBCreateTime in slot")
				total += len(db.CVEDB)
			}
			assert.Equal(t, c.wantTotal, total, "total CVEs across all slots")
		})
	}
}

func TestPrepareDBSlots(t *testing.T) {
	ss := &ScanService{}

	cases := []struct {
		name          string
		data          *share.ScannerRegisterData
		cvedb         map[string]*share.ScanVulnerability
		kvSizeMax     int
		wantSlots     int
		wantTotalCVEs int
		wantErr       bool
	}{
		{
			name:          "empty CVEDB produces dbSlotsBase empty slots",
			data:          makeScannerData("1.0", "2024-01-01", nil),
			cvedb:         map[string]*share.ScanVulnerability{},
			wantSlots:     dbSlotsBase,
			wantTotalCVEs: 0,
		},
		{
			name:  "CVEs are distributed across dbSlotsBase slots",
			data:  makeScannerData("1.0", "2024-01-01", nil),
			cvedb: simpleCVEs(10),
			// hash distribution; all 10 CVEs end up somewhere in the 256 slots
			wantSlots:     dbSlotsBase,
			wantTotalCVEs: 10,
		},
		{
			name:      "compressed slot exceeding KV size limit returns error",
			data:      makeScannerData("1.0", "", nil),
			cvedb:     simpleCVEs(1),
			kvSizeMax: 1,
			wantErr:   true,
		},
		{
			name:  "metadata is preserved in every slot",
			data:  makeScannerData("3.0", "2025-01-15", nil),
			cvedb: simpleCVEs(4),
			// version/createTime must appear in each slot's header
			wantSlots:     dbSlotsBase,
			wantTotalCVEs: 4,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.kvSizeMax > 0 {
				orig := cluster.KVValueSizeMax
				cluster.KVValueSizeMax = c.kvSizeMax
				defer func() { cluster.KVValueSizeMax = orig }()
			}

			zbs, err := ss.prepareDBSlots(c.data, c.cvedb)

			if c.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, zbs, c.wantSlots)

			total := 0
			for _, zb := range zbs {
				db := decodeBatch(t, zb)
				assert.Equal(t, c.data.CVEDBVersion, db.CVEDBVersion)
				assert.Equal(t, c.data.CVEDBCreateTime, db.CVEDBCreateTime)
				total += len(db.CVEDB)
			}
			assert.Equal(t, c.wantTotalCVEs, total)
		})
	}
}

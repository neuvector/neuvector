package scan

import (
	"fmt"
	"testing"

	"github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mapLookup is a simple CVELookup backed by a map, used only in tests.
type mapLookup map[string]*share.ScanVulnerability

func (m mapLookup) Get(name string) (*share.ScanVulnerability, bool) {
	v, ok := m[name]
	return v, ok
}

// ── FillVul ──────────────────────────────────────────────────────────────────

func TestFillVul(t *testing.T) {
	cve := &share.ScanVulnerability{
		Score: 7.5, ScoreV3: 8.1,
		Description: "heap overflow",
		Link:        "https://example.com",
		Vectors:     "AV:N/AC:L", VectorsV3: "CVSS:3.1/AV:N",
	}
	cvedb := mapLookup{"ubuntu:CVE-2021-1234": cve}

	cases := []struct {
		name        string
		cvedb       CVELookup
		dbKey       string
		wantScore   float32
		wantScoreV3 float32
		wantDesc    string
		wantLink    string
		wantVectors string
	}{
		{
			name:  "nil cvedb leaves vul unchanged",
			cvedb: nil, dbKey: "ubuntu:CVE-2021-1234",
		},
		{
			name:  "empty DBKey leaves vul unchanged",
			cvedb: cvedb, dbKey: "",
		},
		{
			name:  "missing key leaves vul unchanged",
			cvedb: cvedb, dbKey: "ubuntu:CVE-9999-9999",
		},
		{
			name:  "matching key fills all fields",
			cvedb: cvedb, dbKey: "ubuntu:CVE-2021-1234",
			wantScore: 7.5, wantScoreV3: 8.1,
			wantDesc:    "heap overflow",
			wantLink:    "https://example.com",
			wantVectors: "AV:N/AC:L",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vul := &share.ScanVulnerability{DBKey: c.dbKey}
			FillVul(c.cvedb, vul)
			assert.Equal(t, c.wantScore, vul.Score)
			assert.Equal(t, c.wantScoreV3, vul.ScoreV3)
			assert.Equal(t, c.wantDesc, vul.Description)
			assert.Equal(t, c.wantLink, vul.Link)
			assert.Equal(t, c.wantVectors, vul.Vectors)
		})
	}
}

// ── ExtractVulnerability ──────────────────────────────────────────────────────

func TestExtractVulnerability(t *testing.T) {
	const unix2021 = int64(1609459200)     // 2021-01-01T00:00:00Z
	const unix2021June = int64(1622505600) // 2021-06-01T00:00:00Z

	cvedbNewer := mapLookup{"ubuntu:CVE-2021-1234": {PublishedDate: "2021-06-01T00:00:00Z"}}
	cvedbSame := mapLookup{"ubuntu:CVE-2021-1234": {PublishedDate: "2021-01-01T00:00:00Z"}}

	type wantTrait struct {
		name     string
		severity int8
		pubTS    int64
		dbKey    string
		pkgName  string
		pkgVer   string
		fixVer   string
		fileName string
	}
	cases := []struct {
		name  string
		cvedb CVELookup
		vuls  []*share.ScanVulnerability
		want  []wantTrait
	}{
		// ── severity mapping ────────────────────────────────────────────
		{
			name: "Low severity",
			vuls: []*share.ScanVulnerability{{Name: "CVE-X", Severity: share.VulnSeverityLow}},
			want: []wantTrait{{name: "CVE-X", severity: vulnSeverityLow}},
		},
		{
			name: "Medium severity",
			vuls: []*share.ScanVulnerability{{Name: "CVE-X", Severity: share.VulnSeverityMedium}},
			want: []wantTrait{{name: "CVE-X", severity: vulnSeverityMedium}},
		},
		{
			name: "High severity",
			vuls: []*share.ScanVulnerability{{Name: "CVE-X", Severity: share.VulnSeverityHigh}},
			want: []wantTrait{{name: "CVE-X", severity: vulnSeverityHigh}},
		},
		{
			name: "Critical severity",
			vuls: []*share.ScanVulnerability{{Name: "CVE-X", Severity: share.VulnSeverityCritical}},
			want: []wantTrait{{name: "CVE-X", severity: vulnSeverityCritical}},
		},
		{
			name: "Unknown severity falls back to Low",
			vuls: []*share.ScanVulnerability{{Name: "CVE-X", Severity: "unknown"}},
			want: []wantTrait{{name: "CVE-X", severity: vulnSeverityLow}},
		},
		{
			name: "v2 score ≥9 upgrades to Critical",
			vuls: []*share.ScanVulnerability{{Name: "CVE-X", Severity: share.VulnSeverityHigh, Score: 9.0}},
			want: []wantTrait{{name: "CVE-X", severity: vulnSeverityCritical}},
		},
		{
			name: "v3 score ≥9 upgrades to Critical",
			vuls: []*share.ScanVulnerability{{Name: "CVE-X", Severity: share.VulnSeverityHigh, ScoreV3: 9.0}},
			want: []wantTrait{{name: "CVE-X", severity: vulnSeverityCritical}},
		},
		// ── published date ──────────────────────────────────────────────
		{
			name: "numeric published date",
			vuls: []*share.ScanVulnerability{{Name: "CVE-X", Severity: share.VulnSeverityLow, PublishedDate: "1609459200"}},
			want: []wantTrait{{name: "CVE-X", severity: vulnSeverityLow, pubTS: unix2021}},
		},
		{
			name: "RFC3339 published date",
			vuls: []*share.ScanVulnerability{{Name: "CVE-X", Severity: share.VulnSeverityLow, PublishedDate: "2021-01-01T00:00:00Z"}},
			want: []wantTrait{{name: "CVE-X", severity: vulnSeverityLow, pubTS: unix2021}},
		},
		{
			name:  "cvedb overrides published date when different",
			cvedb: cvedbNewer,
			vuls:  []*share.ScanVulnerability{{Name: "CVE-2021-1234", Severity: share.VulnSeverityLow, DBKey: "ubuntu:CVE-2021-1234", PublishedDate: "1609459200"}},
			want:  []wantTrait{{severity: vulnSeverityLow, pubTS: unix2021June, dbKey: "ubuntu:CVE-2021-1234"}},
		},
		{
			name:  "cvedb same date leaves pubTS unchanged",
			cvedb: cvedbSame,
			vuls:  []*share.ScanVulnerability{{Name: "CVE-2021-1234", Severity: share.VulnSeverityLow, DBKey: "ubuntu:CVE-2021-1234", PublishedDate: "1609459200"}},
			want:  []wantTrait{{severity: vulnSeverityLow, pubTS: unix2021, dbKey: "ubuntu:CVE-2021-1234"}},
		},
		{
			name:  "cvedb key not found leaves pubTS unchanged",
			cvedb: cvedbNewer,
			vuls:  []*share.ScanVulnerability{{Name: "CVE-2021-1234", Severity: share.VulnSeverityLow, DBKey: "ubuntu:CVE-9999-9999", PublishedDate: "1609459200"}},
			want:  []wantTrait{{severity: vulnSeverityLow, pubTS: unix2021, dbKey: "ubuntu:CVE-9999-9999"}},
		},
		// ── VulTrait fields ─────────────────────────────────────────────
		{
			name: "all VulTrait fields populated",
			vuls: []*share.ScanVulnerability{{
				Name:           "CVE-2021-1234",
				DBKey:          "ubuntu:CVE-2021-1234",
				Severity:       share.VulnSeverityHigh,
				PackageName:    "openssl",
				PackageVersion: "1.1.1",
				FixedVersion:   "1.1.1k",
				FileName:       "libssl.so",
				PublishedDate:  "1609459200",
			}},
			want: []wantTrait{{
				name:     "CVE-2021-1234",
				severity: vulnSeverityHigh,
				pubTS:    unix2021,
				dbKey:    "ubuntu:CVE-2021-1234",
				pkgName:  "openssl",
				pkgVer:   "1.1.1",
				fixVer:   "1.1.1k",
				fileName: "libssl.so",
			}},
		},
		// ── multiple vuls ───────────────────────────────────────────────
		{
			name: "multiple vuls produce one trait each",
			vuls: func() []*share.ScanVulnerability {
				vs := make([]*share.ScanVulnerability, 3)
				for i := range vs {
					vs[i] = &share.ScanVulnerability{
						Name:          fmt.Sprintf("CVE-2021-%04d", i),
						Severity:      share.VulnSeverityMedium,
						PublishedDate: "1609459200",
					}
				}
				return vs
			}(),
			want: func() []wantTrait {
				ws := make([]wantTrait, 3)
				for i := range ws {
					ws[i] = wantTrait{
						name:     fmt.Sprintf("CVE-2021-%04d", i),
						severity: vulnSeverityMedium,
						pubTS:    unix2021,
					}
				}
				return ws
			}(),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			traits := ExtractVulnerability(c.cvedb, c.vuls)
			require.Len(t, traits, len(c.want))
			for i, w := range c.want {
				tr := traits[i]
				if w.name != "" {
					assert.Equal(t, w.name, tr.Name, "Name[%d]", i)
				}
				assert.Equal(t, w.severity, tr.severity, "severity[%d]", i)
				if w.pubTS != 0 {
					assert.Equal(t, w.pubTS, tr.pubTS, "pubTS[%d]", i)
				}
				if w.dbKey != "" {
					assert.Equal(t, w.dbKey, tr.dbKey, "dbKey[%d]", i)
				}
				if w.pkgName != "" {
					assert.Equal(t, w.pkgName, tr.pkgName, "pkgName[%d]", i)
				}
				if w.pkgVer != "" {
					assert.Equal(t, w.pkgVer, tr.pkgVer, "pkgVer[%d]", i)
				}
				if w.fixVer != "" {
					assert.Equal(t, w.fixVer, tr.fixVer, "fixVer[%d]", i)
				}
				if w.fileName != "" {
					assert.Equal(t, w.fileName, tr.fileName, "fileName[%d]", i)
				}
			}
		})
	}
}

// ── GetCVERecord ──────────────────────────────────────────────────────────────

func TestGetCVERecord(t *testing.T) {
	cveByKey := &share.ScanVulnerability{Score: 9.0, ScoreV3: 9.5, Description: "by key"}
	cveByOS := &share.ScanVulnerability{Score: 7.0, Description: "by baseOS"}
	cveApps := &share.ScanVulnerability{Score: 5.0, Description: "by apps"}
	cveBare := &share.ScanVulnerability{Score: 3.0, Description: "by bare"}

	fullDB := mapLookup{
		"ubuntu:CVE-2021-1234": cveByKey,
		"centos:CVE-2021-1234": cveByOS,
		"apps:CVE-2021-1234":   cveApps,
		"CVE-2021-1234":        cveBare,
	}

	cases := []struct {
		name      string
		cvedb     CVELookup
		vulName   string
		dbKey     string
		baseOS    string
		wantScore float32
		wantDesc  string
	}{
		// nil cvedb
		{"nil cvedb returns empty vul", nil, "CVE-2021-1234", "", "ubuntu", 0, ""},
		// DBKey lookup
		{"found by DBKey", fullDB, "CVE-2021-1234", "ubuntu:CVE-2021-1234", "", 9.0, "by key"},
		{"DBKey not found returns empty vul", fullDB, "CVE-2021-1234", "ubuntu:CVE-9999-9999", "", 0, ""},
		{"DBKey takes priority over baseOS", fullDB, "CVE-2021-1234", "ubuntu:CVE-2021-1234", "centos", 9.0, "by key"},
		// fallback chain (no DBKey): baseOS → apps → bare
		{"found by baseOS prefix", fullDB, "CVE-2021-1234", "", "ubuntu", 9.0, "by key"},
		{"apps prefix wins over bare", mapLookup{"apps:CVE-2021-1234": cveApps, "CVE-2021-1234": cveBare},
			"CVE-2021-1234", "", "ubuntu", 5.0, "by apps"},
		{"bare name used as last resort", mapLookup{"CVE-2021-1234": cveBare},
			"CVE-2021-1234", "", "ubuntu", 3.0, "by bare"},
		{"nothing found returns empty vul", mapLookup{}, "CVE-2021-1234", "", "ubuntu", 0, ""},
		// baseOS normalization
		{"strip :version from baseOS", fullDB, "CVE-2021-1234", "", "ubuntu:20.04", 9.0, "by key"},
		{"rhel:N aliased to centos", mapLookup{"centos:CVE-2021-1234": cveByOS},
			"CVE-2021-1234", "", "rhel:8", 7.0, "by baseOS"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vul := GetCVERecord(c.cvedb, c.vulName, c.dbKey, c.baseOS)
			assert.Equal(t, c.vulName, vul.Name)
			assert.Equal(t, c.wantScore, vul.Score)
			if c.wantDesc != "" {
				assert.Equal(t, c.wantDesc, vul.Description)
			}
		})
	}
}

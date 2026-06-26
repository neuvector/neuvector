package scan

import (
	"time"

	"testing"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVulnerabilityProfile(t *testing.T) {
	p := api.RESTVulnerabilityProfile{
		Name: "default",
		Entries: []api.RESTVulnerabilityProfileEntry{
			{
				ID: 1, Name: api.VulnerabilityNameRecent, Days: 10, Images: []string{"nginx:*"},
			},
			{
				ID: 2, Name: "CVE-2021-*", Domains: []string{"dev-*", "prod-*"}, Images: []string{"alpine:3", "node-*:*"},
			},
			{
				ID: 3, Name: "CVE-2020-6789", Domains: []string{"dev-*"},
			},
			{
				ID: 4, Name: "CVE-2019-AAAA", Images: []string{"controller:4.0.1", "enforcer:*"},
			},
			{
				ID: 5, Name: "CVE-2018-*",
			},
		},
	}

	vpf := MakeVulnerabilityProfileFilter(&p)

	positives := []struct {
		v       api.RESTVulnerability
		domains []string
		image   string
	}{
		{api.RESTVulnerability{Name: "CVE-2021-YYYY", PublishedTS: time.Now().AddDate(0, 0, -5).Unix()}, nil, "nginx:3"},
		{api.RESTVulnerability{Name: "CVE-2021-1234"}, []string{"dev-1"}, "alpine:3"},
		{api.RESTVulnerability{Name: "CVE-2021-1234"}, []string{"dev-1"}, "node-10:latest"},
		{api.RESTVulnerability{Name: "CVE-2021-1234"}, []string{"prod-1"}, "alpine:3"},
		{api.RESTVulnerability{Name: "CVE-2020-6789"}, []string{"dev-1"}, ""},
		{api.RESTVulnerability{Name: "CVE-2020-6789"}, []string{"dev-1"}, "nginx:latest"},
		{api.RESTVulnerability{Name: "CVE-2019-AAAA"}, []string{""}, "enforcer:3"},
		{api.RESTVulnerability{Name: "CVE-2019-AAAA"}, nil, "enforcer:3"},
		{api.RESTVulnerability{Name: "CVE-2018-BBBB"}, []string{"stage-1"}, "enforcer:3"},
		{api.RESTVulnerability{Name: "CVE-2018-BBBB"}, nil, ""},
	}
	for _, p := range positives {
		if !vpf.filterOneVulREST(&p.v, p.domains, p.image) {
			t.Errorf("Vulnerability positive test fails: %v", p)
		}
	}

	negtives := []struct {
		v       api.RESTVulnerability
		domains []string
		image   string
	}{
		{api.RESTVulnerability{Name: "CVE-2021-YYYY", PublishedTS: time.Now().AddDate(0, 0, -11).Unix()}, nil, "nginx:3"},
		{api.RESTVulnerability{Name: "CVE-2021-YYYY", PublishedTS: time.Now().AddDate(0, 0, -5).Unix()}, nil, "alpine:3"},
		{api.RESTVulnerability{Name: "CVE-2021-1234"}, []string{""}, ""},
		{api.RESTVulnerability{Name: "CVE-2021-1234"}, []string{"dev-1"}, ""},
		{api.RESTVulnerability{Name: "CVE-2021-1234"}, []string{""}, "alpine:3"},
		{api.RESTVulnerability{Name: "CVE-2020-6789"}, []string{"prod-1"}, "alpine:3"},
		{api.RESTVulnerability{Name: "CVE-2019-XXXX"}, nil, "enforcer:3"},
		{api.RESTVulnerability{Name: "CVE-2017-BBBB"}, []string{"stage-1"}, "enforcer:3"},
	}
	for _, n := range negtives {
		if vpf.filterOneVulREST(&n.v, n.domains, n.image) {
			t.Errorf("Vulnerability negtive test fails: %v", n)
		}
	}

	tests := []struct {
		skip bool
		v    api.RESTVulnerability
		idns []api.RESTIDName
		tag  string
	}{
		{true, api.RESTVulnerability{Name: "CVE-2018-BBBB"}, []api.RESTIDName{}, ""},
		{true, api.RESTVulnerability{Name: "CVE-2018-BBBB"}, nil, ""},
		{true, api.RESTVulnerability{Name: "CVE-2018-BBBB"}, nil, "test"},
	}
	for _, s := range tests {
		r := vpf.FilterVulREST([]*api.RESTVulnerability{&s.v}, s.idns, s.tag)
		if !s.skip && len(r) == 0 {
			t.Errorf("Vulnerability negtive test fails: %v", s)
		} else if s.skip {
			if s.tag == "" && len(r) != 0 {
				t.Errorf("Vulnerability positive test fails: %v", s)
			} else if s.tag != "" && (len(r) == 0 || r[0].Tags[0] != s.tag) {
				t.Errorf("Vulnerability positive test fails: %v", s)
			}
		}
	}
}

// ── ScanVul2REST ──────────────────────────────────────────────────────────────

func TestScanVul2REST(t *testing.T) {
	base := &share.ScanVulnerability{
		Name:           "CVE-2021-1234",
		Score:          5.0,
		ScoreV3:        6.0,
		Severity:       share.VulnSeverityMedium,
		Vectors:        "AV:N",
		VectorsV3:      "CVSS:3.1/AV:N",
		Description:    "base desc",
		PackageName:    "openssl",
		FileName:       "libssl.so",
		PackageVersion: "1.1.1",
		FixedVersion:   "1.1.1k",
		Link:           "https://base.link",
		FeedRating:     "Medium",
		InBase:         true,
		CPEs:           []string{"cpe:openssl"},
		CVEs:           []string{"CVE-2021-1234"},
	}

	enriched := &share.ScanVulnerability{
		Score:            9.0,
		ScoreV3:          9.5,
		Description:      "enriched desc",
		Link:             "https://enriched.link",
		Vectors:          "AV:N/AC:L",
		VectorsV3:        "CVSS:3.1/AV:N/AC:L",
		PublishedDate:    "2021-01-01T00:00:00Z",
		LastModifiedDate: "2021-06-01T00:00:00Z",
	}

	cvedb := mapLookup{
		"ubuntu:CVE-2021-1234": enriched,
		"apps:CVE-2021-1234":   {Score: 7.0, Description: "apps desc"},
		"CVE-2021-1234":        {Score: 3.0, Description: "bare desc"},
	}

	cases := []struct {
		name       string
		cvedb      CVELookup
		baseOS     string
		vul        *share.ScanVulnerability
		wantScore  float32
		wantDesc   string
		wantInBase bool
	}{
		{
			name: "nil cvedb copies basic fields only",
			vul:  base, wantScore: 5.0, wantDesc: "base desc", wantInBase: true,
		},
		{
			name:  "all basic fields copied from vul",
			cvedb: mapLookup{}, // non-nil but empty
			vul:   base, wantScore: 5.0, wantDesc: "base desc", wantInBase: true,
		},
		{
			name:  "enriched via DBKey",
			cvedb: cvedb, baseOS: "rhel",
			vul:       &share.ScanVulnerability{Name: "CVE-2021-1234", DBKey: "ubuntu:CVE-2021-1234"},
			wantScore: 9.0, wantDesc: "enriched desc",
		},
		{
			name:  "enriched via baseOS fallback",
			cvedb: cvedb, baseOS: "ubuntu:20.04", // strips to "ubuntu"
			vul:       &share.ScanVulnerability{Name: "CVE-2021-1234"},
			wantScore: 9.0, wantDesc: "enriched desc",
		},
		{
			name:      "enriched via apps fallback",
			cvedb:     mapLookup{"apps:CVE-2021-1234": {Score: 7.0, Description: "apps desc"}},
			baseOS:    "ubuntu",
			vul:       &share.ScanVulnerability{Name: "CVE-2021-1234"},
			wantScore: 7.0, wantDesc: "apps desc",
		},
		{
			name:      "enriched via bare name fallback",
			cvedb:     mapLookup{"CVE-2021-1234": {Score: 3.0, Description: "bare desc"}},
			baseOS:    "ubuntu",
			vul:       &share.ScanVulnerability{Name: "CVE-2021-1234"},
			wantScore: 3.0, wantDesc: "bare desc",
		},
		{
			name:  "DBKey miss leaves basic fields",
			cvedb: cvedb, baseOS: "ubuntu",
			vul:       &share.ScanVulnerability{Name: "CVE-2021-1234", Score: 5.0, DBKey: "ubuntu:CVE-9999-9999"},
			wantScore: 5.0, wantDesc: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := ScanVul2REST(c.cvedb, c.baseOS, c.vul)
			require.NotNil(t, v)
			assert.Equal(t, c.vul.Name, v.Name)
			assert.Equal(t, c.wantScore, v.Score)
			assert.Equal(t, c.wantDesc, v.Description)
			assert.Equal(t, c.wantInBase, v.InBaseImage)
		})
	}

	// Verify all basic fields from vul are copied regardless of cvedb
	t.Run("all basic fields copied", func(t *testing.T) {
		v := ScanVul2REST(nil, "", base)
		assert.Equal(t, base.Name, v.Name)
		assert.Equal(t, base.Score, v.Score)
		assert.Equal(t, base.ScoreV3, v.ScoreV3)
		assert.Equal(t, base.Severity, v.Severity)
		assert.Equal(t, base.Vectors, v.Vectors)
		assert.Equal(t, base.VectorsV3, v.VectorsV3)
		assert.Equal(t, base.Description, v.Description)
		assert.Equal(t, base.PackageName, v.PackageName)
		assert.Equal(t, base.FileName, v.FileName)
		assert.Equal(t, base.PackageVersion, v.PackageVersion)
		assert.Equal(t, base.FixedVersion, v.FixedVersion)
		assert.Equal(t, base.Link, v.Link)
		assert.Equal(t, base.FeedRating, v.FeedRating)
		assert.True(t, v.InBaseImage)
		assert.Equal(t, base.CPEs, v.CPEs)
		assert.Equal(t, base.CVEs, v.CVEs)
	})

	// Enrichment overwrites score/description but preserves timestamps
	t.Run("enrichment writes PublishedTS and LastModTS", func(t *testing.T) {
		vul := &share.ScanVulnerability{Name: "CVE-2021-1234", DBKey: "ubuntu:CVE-2021-1234"}
		v := ScanVul2REST(cvedb, "", vul)
		assert.Equal(t, int64(1609459200), v.PublishedTS) // 2021-01-01
		assert.Equal(t, int64(1622505600), v.LastModTS)   // 2021-06-01
	})
}

// ── FillVulTraits ─────────────────────────────────────────────────────────────

func TestFillVulTraits(t *testing.T) {
	cvedb := mapLookup{
		"ubuntu:CVE-2021-1234": {Score: 8.0, Description: "enriched", ScoreV3: 9.0},
		"apps:CVE-2021-9999":   {Score: 5.0, Description: "apps cve"},
	}

	// helper: build a VulTrait with all relevant fields set
	makeTrait := func(name, dbKey, pkg, pkgVer, fixVer, fileName string, sev int8, filtered bool) *VulTrait {
		return &VulTrait{
			Name:     name,
			dbKey:    dbKey,
			pkgName:  pkg,
			pkgVer:   pkgVer,
			fixVer:   fixVer,
			fileName: fileName,
			severity: sev,
			filtered: filtered,
		}
	}

	cases := []struct {
		name            string
		cvedb           CVELookup
		baseOS          string
		traits          []*VulTrait
		showTag         string
		includeFiltered bool
		wantLen         int
		wantNames       []string // if non-empty, check order
		wantTags        [][]string
		wantScores      []float32
	}{
		{
			name:    "nil cvedb returns traits without enrichment",
			traits:  []*VulTrait{makeTrait("CVE-X", "", "pkg", "1.0", "1.1", "", vulnSeverityHigh, false)},
			wantLen: 1, wantScores: []float32{0},
		},
		{
			name:    "empty traits returns empty slice",
			traits:  []*VulTrait{},
			wantLen: 0,
		},
		{
			name:    "unfiltered trait always included",
			cvedb:   mapLookup{},
			traits:  []*VulTrait{makeTrait("CVE-X", "", "", "", "", "", vulnSeverityLow, false)},
			wantLen: 1,
		},
		{
			name:    "filtered trait excluded when showTag is empty",
			cvedb:   mapLookup{},
			traits:  []*VulTrait{makeTrait("CVE-X", "", "", "", "", "", vulnSeverityLow, true)},
			showTag: "", wantLen: 0,
		},
		{
			name:    "filtered trait included with tag when showTag is set",
			cvedb:   mapLookup{},
			traits:  []*VulTrait{makeTrait("CVE-X", "", "", "", "", "", vulnSeverityLow, true)},
			showTag: "accept", wantLen: 1, wantTags: [][]string{{"accept"}},
		},
		{
			// When includeFiltered=true and the trait is filtered, Tags is still set to
			// []string{showTag} by FillVulTraits — here showTag="" so Tags=[]string{""}.
			name:            "includeFiltered includes filtered trait even without tag",
			cvedb:           mapLookup{},
			traits:          []*VulTrait{makeTrait("CVE-X", "", "", "", "", "", vulnSeverityLow, true)},
			includeFiltered: true, wantLen: 1, wantTags: [][]string{{""}},
		},
		{
			name:    "mixed filtered and unfiltered, no showTag",
			cvedb:   mapLookup{},
			traits:  []*VulTrait{makeTrait("CVE-A", "", "", "", "", "", vulnSeverityLow, false), makeTrait("CVE-B", "", "", "", "", "", vulnSeverityLow, true)},
			wantLen: 1, wantNames: []string{"CVE-A"},
		},
		{
			name:    "VulTrait fields mapped to REST vul",
			cvedb:   nil,
			traits:  []*VulTrait{makeTrait("CVE-2021-1234", "ubuntu:CVE-2021-1234", "openssl", "1.1.1", "1.1.1k", "libssl.so", vulnSeverityHigh, false)},
			wantLen: 1,
		},
		{
			name:  "enriched via DBKey",
			cvedb: cvedb, baseOS: "rhel",
			traits:  []*VulTrait{makeTrait("CVE-2021-1234", "ubuntu:CVE-2021-1234", "", "", "", "", vulnSeverityMedium, false)},
			wantLen: 1, wantScores: []float32{8.0},
		},
		{
			name:  "enriched via baseOS fallback",
			cvedb: cvedb, baseOS: "ubuntu",
			traits:  []*VulTrait{makeTrait("CVE-2021-1234", "", "", "", "", "", vulnSeverityMedium, false)},
			wantLen: 1, wantScores: []float32{8.0},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vuls := FillVulTraits(c.cvedb, c.baseOS, c.traits, c.showTag, c.includeFiltered)
			require.Len(t, vuls, c.wantLen)
			for i, name := range c.wantNames {
				assert.Equal(t, name, vuls[i].Name, "Name[%d]", i)
			}
			for i, tags := range c.wantTags {
				assert.Equal(t, tags, vuls[i].Tags, "Tags[%d]", i)
			}
			for i, score := range c.wantScores {
				assert.Equal(t, score, vuls[i].Score, "Score[%d]", i)
			}
		})
	}

	// Verify VulTrait fields are correctly mapped
	t.Run("all VulTrait fields mapped", func(t *testing.T) {
		tr := makeTrait("CVE-2021-1234", "ubuntu:CVE-2021-1234", "openssl", "1.1.1", "1.1.1k", "libssl.so", vulnSeverityHigh, false)
		vuls := FillVulTraits(nil, "", []*VulTrait{tr}, "", false)
		require.Len(t, vuls, 1)
		v := vuls[0]
		assert.Equal(t, "CVE-2021-1234", v.Name)
		assert.Equal(t, "ubuntu:CVE-2021-1234", v.DbKey)
		assert.Equal(t, "openssl", v.PackageName)
		assert.Equal(t, "1.1.1", v.PackageVersion)
		assert.Equal(t, "1.1.1k", v.FixedVersion)
		assert.Equal(t, "libssl.so", v.FileName)
		assert.Equal(t, share.VulnSeverityHigh, v.Severity)
	})
}

// ── ScanRepoResult2REST ───────────────────────────────────────────────────────

func TestScanRepoResult2REST(t *testing.T) {
	cve := &share.ScanVulnerability{Name: "CVE-2021-1234", Score: 7.0, Severity: share.VulnSeverityHigh, DBKey: "ubuntu:CVE-2021-1234"}
	cvedb := mapLookup{"ubuntu:CVE-2021-1234": {Score: 9.0, Description: "enriched"}}

	cases := []struct {
		name          string
		cvedb         CVELookup
		result        *share.ScanResult
		wantVulLen    int
		wantLayerLen  int
		wantLayerVuls int  // vuls in first layer
		wantSigInfo   bool // expect non-nil verifiers (true = SignatureInfo had content)
		wantVulScore  float32
	}{
		{
			// ScanRepoResult2REST dereferences result.Secrets.Logs, so Secrets must be non-nil.
			name: "empty result produces empty report",
			result: &share.ScanResult{
				Version: "1.0", ImageID: "img1", Registry: "reg", Repository: "repo",
				Tag: "latest", Digest: "sha256:abc", Namespace: "ubuntu",
				CVEDBCreateTime: "2021-01-01",
				Secrets:         &share.ScanSecretResult{},
			},
			wantVulLen: 0, wantLayerLen: 0,
		},
		{
			name:  "vuls converted via ScanVul2REST",
			cvedb: cvedb,
			result: &share.ScanResult{
				Namespace: "ubuntu", Secrets: &share.ScanSecretResult{},
				Vuls: []*share.ScanVulnerability{cve},
			},
			wantVulLen: 1, wantVulScore: 9.0,
		},
		{
			name: "nil cvedb skips enrichment",
			result: &share.ScanResult{
				Namespace: "ubuntu", Secrets: &share.ScanSecretResult{},
				Vuls: []*share.ScanVulnerability{cve},
			},
			wantVulLen: 1, wantVulScore: 7.0,
		},
		{
			name:  "layers converted with their own vuls",
			cvedb: cvedb,
			result: &share.ScanResult{
				Namespace: "ubuntu", Secrets: &share.ScanSecretResult{},
				Layers: []*share.ScanLayerResult{
					{Digest: "sha256:layer1", Vuls: []*share.ScanVulnerability{cve}},
					{Digest: "sha256:layer2", Vuls: nil},
				},
			},
			wantLayerLen: 2, wantLayerVuls: 1,
		},
		{
			name:        "nil SignatureInfo produces empty struct",
			result:      &share.ScanResult{Namespace: "ubuntu", Secrets: &share.ScanSecretResult{}},
			wantSigInfo: false,
		},
		{
			name: "SignatureInfo verifiers and timestamp copied",
			result: &share.ScanResult{
				Namespace: "ubuntu", Secrets: &share.ScanSecretResult{},
				SignatureInfo: &share.ScanSignatureInfo{
					Verifiers:             []string{"cosign"},
					VerificationTimestamp: "2021-01-01T00:00:00Z",
				},
			},
			wantSigInfo: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			report := ScanRepoResult2REST(c.cvedb, c.result, nil)
			require.NotNil(t, report)
			assert.Len(t, report.Vuls, c.wantVulLen)
			assert.Len(t, report.Layers, c.wantLayerLen)
			if c.wantVulLen > 0 {
				assert.Equal(t, c.wantVulScore, report.Vuls[0].Score)
			}
			if c.wantLayerLen > 0 {
				assert.Len(t, report.Layers[0].Vuls, c.wantLayerVuls)
				if c.wantLayerVuls > 0 {
					assert.Equal(t, float32(9.0), report.Layers[0].Vuls[0].Score)
				}
			}
			require.NotNil(t, report.SignatureInfo)
			if c.wantSigInfo {
				assert.Equal(t, []string{"cosign"}, report.SignatureInfo.Verifiers)
				assert.Equal(t, "2021-01-01T00:00:00Z", report.SignatureInfo.VerificationTimestamp)
			}
		})
	}

	// Verify all metadata fields are copied from ScanResult
	t.Run("all metadata fields copied", func(t *testing.T) {
		result := &share.ScanResult{
			Version:         "2.0",
			CVEDBCreateTime: "2021-01-01",
			ImageID:         "img123",
			Registry:        "registry.io",
			Repository:      "myrepo",
			Tag:             "v1.0",
			Digest:          "sha256:abc",
			Size:            1024,
			Author:          "alice",
			Created:         "2021-01-01T00:00:00Z",
			Namespace:       "ubuntu",
			Secrets:         &share.ScanSecretResult{},
		}
		report := ScanRepoResult2REST(nil, result, nil)
		assert.Equal(t, "2.0", report.CVEDBVersion)
		assert.Equal(t, "2021-01-01", report.CVEDBCreateTime)
		assert.Equal(t, "img123", report.ImageID)
		assert.Equal(t, "registry.io", report.Registry)
		assert.Equal(t, "myrepo", report.Repository)
		assert.Equal(t, "v1.0", report.Tag)
		assert.Equal(t, "sha256:abc", report.Digest)
		assert.Equal(t, int64(1024), report.Size)
		assert.Equal(t, "alice", report.Author)
		assert.Equal(t, "2021-01-01T00:00:00Z", report.CreatedAt)
		assert.Equal(t, "ubuntu", report.BaseOS)
	})
}

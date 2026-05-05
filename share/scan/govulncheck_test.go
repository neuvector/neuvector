package scan

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeGovulnVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"v1.2.3", "1.2.3"},
		{"go1.19", "1.19"},
		{"1.0.0", "1.0.0"},
		{"v28.5.2+incompatible", "28.5.2+incompatible"},
		{"go1.21.5", "1.21.5"},
		{"  v1.0.0  ", "1.0.0"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeGovulnVersion(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestParseGovulncheckOpenVEXSubcomponent(t *testing.T) {
	tests := []struct {
		name           string
		id             string
		wantModuleName string
		wantVersion    string
		wantOk         bool
	}{
		{
			name:           "normal package with version",
			id:             "pkg:golang/github.com/stretchr/testify@v1.8.0",
			wantModuleName: "go:github.com/stretchr/testify",
			wantVersion:    "1.8.0",
			wantOk:         true,
		},
		{
			name:           "package with URL-encoded path",
			id:             "pkg:golang/github.com%2Fdocker%2Fdocker@v28.5.2+incompatible",
			wantModuleName: "go:github.com/docker/docker",
			wantVersion:    "28.5.2+incompatible",
			wantOk:         true,
		},
		{
			name:           "stdlib package",
			id:             "pkg:golang/stdlib@go1.21.5",
			wantModuleName: "go:stdlib",
			wantVersion:    "1.21.5",
			wantOk:         true,
		},
		{
			name:           "package with go prefix in version",
			id:             "pkg:golang/example.com/module@go1.19",
			wantModuleName: "go:example.com/module",
			wantVersion:    "1.19",
			wantOk:         true,
		},
		{
			name:           "no prefix - should fail",
			id:             "github.com/stretchr/testify@v1.8.0",
			wantModuleName: "",
			wantVersion:    "",
			wantOk:         false,
		},
		{
			name:           "no version - should fail",
			id:             "pkg:golang/github.com/stretchr/testify",
			wantModuleName: "",
			wantVersion:    "",
			wantOk:         false,
		},
		{
			name:           "empty string - should fail",
			id:             "",
			wantModuleName: "",
			wantVersion:    "",
			wantOk:         false,
		},
		{
			name:           "@ at beginning - should fail",
			id:             "pkg:golang/@v1.0.0",
			wantModuleName: "",
			wantVersion:    "",
			wantOk:         false,
		},
		{
			name:           "with spaces",
			id:             "  pkg:golang/example.com/module@v1.0.0  ",
			wantModuleName: "go:example.com/module",
			wantVersion:    "1.0.0",
			wantOk:         true,
		},
		{
			name:           "different package format - npm (should fail)",
			id:             "pkg:npm/lodash@4.17.21",
			wantModuleName: "",
			wantVersion:    "",
			wantOk:         false,
		},
		{
			name:           "complex module path",
			id:             "pkg:golang/go.opentelemetry.io/otel/exporters/otlp@v1.0.0",
			wantModuleName: "go:go.opentelemetry.io/otel/exporters/otlp",
			wantVersion:    "1.0.0",
			wantOk:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotModuleName, gotVersion, gotOk := parseGovulncheckOpenVEXSubcomponent(tt.id)
			require.Equal(t, tt.wantModuleName, gotModuleName, "module name mismatch")
			require.Equal(t, tt.wantVersion, gotVersion, "version mismatch")
			require.Equal(t, tt.wantOk, gotOk, "ok flag mismatch")
		})
	}
}

func TestParseGovulncheckConfirmedFindings(t *testing.T) {
	data := []byte(`{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "govulncheck/vex:test",
  "author": "Unknown Author",
  "timestamp": "2026-04-29T03:00:46.094309797Z",
  "version": 1,
  "tooling": "https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck",
  "statements": [
    {
      "vulnerability": {
        "@id": "https://pkg.go.dev/vuln/GO-2026-4883",
        "name": "GO-2026-4883",
        "description": "Moby issue",
        "aliases": [
          "CVE-2026-33997",
          "GHSA-pxq6-2prw-chj9"
        ]
      },
      "products": [
        {
          "@id": "Unknown Product",
          "subcomponents": [
            {
              "@id": "pkg:golang/github.com%2Fdocker%2Fdocker@v28.5.2+incompatible"
            },
            {
              "@id": "pkg:golang/github.com%2Fdocker%2Fdocker@v28.5.2+incompatible"
            }
          ]
        }
      ],
      "status": "affected"
    }
  ]
}`)

	findingsByModule, err := parseGovulncheckConfirmedFindings(data)
	if err != nil {
		t.Fatalf("parseGovulncheckConfirmedFindings() error = %v", err)
	}

	key := "go:github.com/docker/docker@28.5.2+incompatible"
	findings := findingsByModule[key]
	require.Len(t, findings, 1)
	require.Equal(t, "GO-2026-4883", findings[0].OSV)
	require.Empty(t, findings[0].FixedVersion)
	require.Equal(t, "https://pkg.go.dev/vuln/GO-2026-4883", findings[0].Link)
	require.Len(t, findings[0].Aliases, 2)
}

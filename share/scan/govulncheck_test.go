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

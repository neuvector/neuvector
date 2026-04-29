package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	vulnscan "golang.org/x/vuln/scan"
)

const govulcheckDBPath = "file:///etc/neuvector/govulndb"

type GovulnFinding struct {
	OSV          string    `json:"O,omitempty"`
	Aliases      []string  `json:"A,omitempty"`
	Details      string    `json:"D,omitempty"`
	FixedVersion string    `json:"F,omitempty"`
	Link         string    `json:"L,omitempty"`
	Published    time.Time `json:"P,omitempty"`
	Modified     time.Time `json:"M,omitempty"`
}

type govulncheckOpenVEXDocument struct {
	Statements []govulncheckOpenVEXStatement `json:"statements"`
}

type govulncheckOpenVEXStatement struct {
	Vulnerability govulncheckOpenVEXVulnerability `json:"vulnerability"`
	Products      []govulncheckOpenVEXProduct     `json:"products"`
	Status        string                          `json:"status"`
}

type govulncheckOpenVEXVulnerability struct {
	ID          string   `json:"@id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Aliases     []string `json:"aliases"`
}

type govulncheckOpenVEXProduct struct {
	Subcomponents []govulncheckOpenVEXSubcomponent `json:"subcomponents"`
}

type govulncheckOpenVEXSubcomponent struct {
	ID string `json:"@id"`
}

func runGovulncheckBinary(ctx context.Context, fullpath string) (map[string][]GovulnFinding, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	cmd := vulnscan.Command(ctx, "-db", govulcheckDBPath, "-mode", "binary", "-format", "openvex", fullpath)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if err := cmd.Wait(); err != nil {
		if stderr.Len() == 0 {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}

	return parseGovulncheckConfirmedFindings(stdout.Bytes())
}

func parseGovulncheckConfirmedFindings(data []byte) (map[string][]GovulnFinding, error) {
	var doc govulncheckOpenVEXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	findingsByModule := make(map[string][]GovulnFinding)
	dedupedfindings := make(map[string]struct{})
	for _, statement := range doc.Statements {
		if statement.Status != "affected" || statement.Vulnerability.Name == "" {
			continue
		}

		govulnFinding := GovulnFinding{
			OSV:     statement.Vulnerability.Name,
			Aliases: statement.Vulnerability.Aliases,
			Link:    statement.Vulnerability.ID,
		}
		for _, product := range statement.Products {
			for _, subcomponent := range product.Subcomponents {
				moduleName, version, ok := parseGovulncheckOpenVEXSubcomponent(subcomponent.ID)
				if !ok {
					continue
				}

				key := govulnModuleVersionKey(moduleName, version)
				dedupKey := key + "|" + govulnFinding.OSV
				if _, ok := dedupedfindings[dedupKey]; ok {
					continue
				}
				dedupedfindings[dedupKey] = struct{}{}

				findingsByModule[key] = append(findingsByModule[key], govulnFinding)
			}
		}
	}

	return findingsByModule, nil
}

func parseGovulncheckOpenVEXSubcomponent(id string) (string, string, bool) {
	const prefix = "pkg:golang/"

	id = strings.TrimSpace(id)
	if !strings.HasPrefix(id, prefix) {
		return "", "", false
	}

	trimmed := strings.TrimPrefix(id, prefix)
	at := strings.LastIndex(trimmed, "@")
	if at <= 0 {
		return "", "", false
	}

	modulePath, err := url.PathUnescape(trimmed[:at])
	if err != nil {
		return "", "", false
	}

	version := normalizeGovulnVersion(trimmed[at+1:])
	if modulePath == "stdlib" {
		return "go:stdlib", version, true
	}

	return "go:" + modulePath, version, true
}

func lookupGovulnFindings(findingsByModule map[string][]GovulnFinding, moduleName, version string) []GovulnFinding {
	for _, key := range govulnLookupKeys(moduleName, version) {
		if findings, ok := findingsByModule[key]; ok {
			return findings
		}
	}
	return nil
}

func govulnLookupKeys(moduleName, version string) []string {
	keys := make([]string, 0, 2)
	if moduleName == "" {
		return keys
	}
	if v := normalizeGovulnVersion(version); v != "" {
		keys = append(keys, govulnModuleVersionKey(moduleName, v))
	}
	keys = append(keys, moduleName)
	return keys
}

func govulnModuleVersionKey(moduleName, version string) string {
	if moduleName == "" {
		return ""
	}
	version = normalizeGovulnVersion(version)
	if version == "" {
		return moduleName
	}
	return moduleName + "@" + version
}

// normalizeGovulnVersion is to align the version format of parseGolangPackage.
func normalizeGovulnVersion(version string) string {
	version = strings.TrimSpace(version)
	version = strings.TrimPrefix(version, "go")
	version = strings.TrimPrefix(version, "v")
	return version
}

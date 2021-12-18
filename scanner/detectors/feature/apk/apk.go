package apk

import (
	"bufio"
	"bytes"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/scanner/common"
	"github.com/neuvector/neuvector/scanner/detectors"
)

const apkPackageFile = "lib/apk/db/installed"

// RpmFeaturesDetector implements FeaturesDetector and detects rpm packages
// It requires the "rpm" binary to be in the PATH
type RpmFeaturesDetector struct{}

func init() {
	detectors.RegisterFeaturesDetector("apk", &RpmFeaturesDetector{})
}

// Detect detects packages using var/lib/rpm/Packages from the input data
func (detector *RpmFeaturesDetector) Detect(namespace string, files map[string]*detectors.FeatureFile, path string) ([]detectors.FeatureVersion, error) {
	f, hasFile := files[apkPackageFile]
	if !hasFile {
		return []detectors.FeatureVersion{}, nil
	}

	packagesMap := make(map[string]detectors.FeatureVersion)

	var pkg detectors.FeatureVersion
	var err error
	scanner := bufio.NewScanner(bytes.NewReader(f.Data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) > 3 {
			if line[0] == 'P' && line[1] == ':' {
				pkg.Feature.Name = strings.TrimPrefix(line, "P:")
			} else if line[0] == 'V' && line[1] == ':' {
				pkg.Version, err = common.NewVersion(strings.TrimPrefix(line, "V:"))
				if err != nil {
					log.Warningf("could not parse package version '%c': %s. skipping", line[1], err.Error())
				}
			} else if line[0] == 'o' && line[1] == ':' {
				pkg.Feature.Name = strings.TrimPrefix(line, "o:")
			}
		}
		// Add the package to the result array if we have all the informations
		if line == "" {
			if pkg.Feature.Name != "" && pkg.Version.String() != "" {
				pkg.InBase = f.InBase
				packagesMap[pkg.Feature.Name+"#"+pkg.Version.String()] = pkg
				pkg.Feature.Name = ""
				pkg.Version = common.Version{}
			}
		}
	}

	// Convert the map to a slice
	packages := make([]detectors.FeatureVersion, 0, len(packagesMap))
	for _, pkg := range packagesMap {
		packages = append(packages, pkg)
	}

	return packages, nil
}

// GetRequiredFiles returns the list of files required for Detect, without
// leading /
func (detector *RpmFeaturesDetector) GetRequiredFiles() []string {
	return []string{"lib/apk/db/installed"}
}

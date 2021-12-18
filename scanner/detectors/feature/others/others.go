package others

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/scanner/common"
	"github.com/neuvector/neuvector/scanner/detectors"
)

var pipPackagesRegexp = regexp.MustCompile(`(.*) \((.*)\)`)

// OthersFeaturesDetector implements FeaturesDetector and detects pip packages
type OthersFeaturesDetector struct{}

func init() {
	detectors.RegisterFeaturesDetector("others", &OthersFeaturesDetector{})
}

// Detect detects packages using others_modules from the input data
func (detector *OthersFeaturesDetector) Detect(namespace string, files map[string]*detectors.FeatureFile, path string) ([]detectors.FeatureVersion, error) {
	f, hasFile := files["others_modules"]
	if !hasFile {
		return []detectors.FeatureVersion{}, nil
	}

	packagesMap := make(map[string]detectors.FeatureVersion)

	var err error
	scanner := bufio.NewScanner(bytes.NewReader(f.Data))
	for scanner.Scan() {
		var pkg detectors.FeatureVersion
		line := scanner.Text()
		r := pipPackagesRegexp.FindStringSubmatch(line)
		if len(r) == 3 {
			if r[1] == "OpenSSL" {
				// quick way to disable openssl, other_modules is from running container, not essential.
				continue
			}
			pkg.Feature.Name = strings.ToLower(r[1])
			pkg.Version, err = common.NewVersion(r[2])
			if err != nil {
				log.Warningf("could not parse package version '%s': %s. skipping", r[2], err.Error())
				continue
			}

			pkg.InBase = f.InBase
			packagesMap[pkg.Feature.Name+"#"+pkg.Version.String()] = pkg
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
func (detector *OthersFeaturesDetector) GetRequiredFiles() []string {
	return []string{"others_modules"}
}

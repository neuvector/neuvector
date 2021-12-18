// Copyright 2015 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dpkg

import (
	"bufio"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/scanner/common"
	"github.com/neuvector/neuvector/scanner/detectors"
)

var (
	dpkgSrcCaptureRegexp      = regexp.MustCompile(`Source: (?P<name>[^\s]*)( \((?P<version>.*)\))?`)
	dpkgSrcCaptureRegexpNames = dpkgSrcCaptureRegexp.SubexpNames()
)

const (
	installedStatus = "install ok installed"
	dpkgPackageFile = "var/lib/dpkg/status"
	dpkgPackageDir  = "var/lib/dpkg/status.d/"
)

// DpkgFeaturesDetector implements FeaturesDetector and detects dpkg packages
type DpkgFeaturesDetector struct{}

func init() {
	detectors.RegisterFeaturesDetector("dpkg", &DpkgFeaturesDetector{})
}

type dpkgPackage struct {
	pkgName string
	status  string
	source  string
	version string
}

func (detector *DpkgFeaturesDetector) addFeature(packagesMap map[string]detectors.FeatureVersion, pkg *dpkgPackage, inBase bool, installed bool) {
	// Add the package to the result array if we have all the informations
	if (pkg.pkgName != "" || pkg.source != "") && pkg.version != "" { //
		var name string
		if pkg.pkgName != "" && pkg.source != "" {
			name = pkg.source + "/" + pkg.pkgName
		} else if pkg.source != "" {
			name = pkg.source
		} else {
			name = pkg.pkgName
		}

		ver, _ := common.NewVersion(pkg.version)
		fv := detectors.FeatureVersion{
			Feature: detectors.Feature{
				Name: name,
			},
			Version: ver,
			InBase:  inBase,
		}

		/*
			if strings.Contains(pkg.pkgName, "liblz") || strings.Contains(pkg.pkgName, "debianutils") {
				log.WithFields(log.Fields{"feature": fv, "pkg": pkg}).Error("======")
			}
		*/

		if installed || strings.Contains(pkg.status, installedStatus) {
			packagesMap[fv.Feature.Name+"#"+pkg.version] = fv
		}
	}
}

// Detect detects packages using var/lib/dpkg/status or var/lib/dpkg/status.d/* (distroless) from the input data
func (detector *DpkgFeaturesDetector) Detect(namespace string, files map[string]*detectors.FeatureFile, path string) ([]detectors.FeatureVersion, error) {
	// Create a map to store packages and ensure their uniqueness
	packagesMap := make(map[string]detectors.FeatureVersion)

	for name, file := range files {
		if name == dpkgPackageFile {
			detector.parseFeatureFile(packagesMap, string(file.Data[:]), file.InBase, false)
		} else if strings.HasPrefix(name, dpkgPackageDir) {
			detector.parseFeatureFile(packagesMap, string(file.Data[:]), file.InBase, true)
		}
	}

	// Convert the map to a slice
	packages := make([]detectors.FeatureVersion, 0, len(packagesMap))
	for _, pkg := range packagesMap {
		packages = append(packages, pkg)
	}

	return packages, nil
}

func (detector *DpkgFeaturesDetector) parseFeatureFile(packagesMap map[string]detectors.FeatureVersion, f string, inBase bool, installed bool) error {
	var pkg dpkgPackage
	scanner := bufio.NewScanner(strings.NewReader(f))
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "Package: ") {
			// Package line
			// Defines the name of the package
			pkg.pkgName = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
		} else if strings.HasPrefix(line, "Status: ") {
			pkg.status = strings.TrimSpace(strings.TrimPrefix(line, "Status: "))
		} else if strings.HasPrefix(line, "Source: ") {
			// Source line (Optionnal)
			// Gives the name of the source package
			// May also specifies a version

			srcCapture := dpkgSrcCaptureRegexp.FindAllStringSubmatch(line, -1)[0]
			md := map[string]string{}
			for i, n := range srcCapture {
				md[dpkgSrcCaptureRegexpNames[i]] = strings.TrimSpace(n)
			}

			pkg.source = md["name"]
			if md["version"] != "" {
				ver, err := common.NewVersion(md["version"])
				if err != nil {
					log.Warningf("could not parse package version '%c': %s. skipping", line[1], err.Error())
				}
				pkg.version = ver.String()
			}
		} else if strings.HasPrefix(line, "Version: ") && pkg.version == "" {
			// Version line
			// Defines the version of the package
			// This version is less important than a version retrieved from a Source line
			// because the Debian vulnerabilities often skips the epoch from the Version field
			// which is not present in the Source version, and because +bX revisions don't matter
			sver := strings.TrimPrefix(line, "Version: ")
			ver, err := common.NewVersion(sver)
			if err != nil {
				log.Warningf("could not parse package version '%c': %s. skipping", line[1], err.Error())
			}
			pkg.version = ver.String()
		} else if line == "" {
			detector.addFeature(packagesMap, &pkg, inBase, installed)
			pkg = dpkgPackage{}
		}
	}

	detector.addFeature(packagesMap, &pkg, inBase, installed)
	return nil
}

// GetRequiredFiles returns the list of files required for Detect, without
// leading /
func (detector *DpkgFeaturesDetector) GetRequiredFiles() []string {
	return []string{"var/lib/dpkg/status"}
}

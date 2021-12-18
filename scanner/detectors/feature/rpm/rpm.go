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

package rpm

import (
	"bufio"
	"encoding/json"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/scanner/common"
	"github.com/neuvector/neuvector/scanner/detectors"
	"github.com/neuvector/neuvector/share/utils"
)

// RpmFeaturesDetector implements FeaturesDetector and detects rpm packages
// It requires the "rpm" binary to be in the PATH
type RpmFeaturesDetector struct{}

const (
	contentManifest = "root/buildinfo/content_manifests"
	dockerfile      = "root/buildinfo/Dockerfile-"
	rpmPackageFile  = "var/lib/rpm/Packages"
	// pyxisUrl        = "https://catalog.redhat.com/api/containers/v1/images/nvr"
)

var redhatRegexp = regexp.MustCompile(`com.redhat.component="([a-zA-Z0-9\-_\.]*)"`)
var archRegexp = regexp.MustCompile(`"architecture"="([a-zA-Z0-9\-_\.]*)"`)
var versionRegexp = regexp.MustCompile(`root/buildinfo/Dockerfile-([a-zA-Z0-9_]+)-([a-zA-z0-9\-_\.]*)`)

var rpmsMap RpmsMap

func init() {
	detectors.RegisterFeaturesDetector("rpm", &RpmFeaturesDetector{})
}

// Detect detects packages using var/lib/rpm/Packages from the input data
func (detector *RpmFeaturesDetector) Detect(namespace string, files map[string]*detectors.FeatureFile, path string) ([]detectors.FeatureVersion, error) {
	f, hasFile := files[rpmPackageFile]
	if !hasFile {
		return []detectors.FeatureVersion{}, nil
	}

	if len(rpmsMap.Data) == 0 {
		if mdata, _ := common.LoadRawFile(path, common.RHELCpeMapFile); mdata != nil {
			if err := json.Unmarshal(mdata, &rpmsMap); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Failed to unmarshal cpe map")
			}
		}
	}

	var cpes utils.Set
	// check the redhat CPEs
	if len(rpmsMap.Data) > 0 {
		for filename, d := range files {
			// log.WithFields(log.Fields{"filename": filename}).Info("=============")
			if strings.HasPrefix(filename, contentManifest) && strings.HasSuffix(filename, ".json") {
				// log.WithFields(log.Fields{"file": string(d[:])}).Info("=============")
				cpes = getMappingJson(getContentSets(d.Data))
			}
		}
	}

	if cpes == nil || cpes.Cardinality() == 0 {
		if strings.HasPrefix(namespace, "rhel:7.") {
			cpes = utils.NewSet(
				"cpe:/a:redhat:rhel_software_collections:1::el7",
				"cpe:/a:redhat:rhel_software_collections:2::el7",
				"cpe:/a:redhat:rhel_software_collections:3::el7",
				"cpe:/o:redhat:enterprise_linux:7::server")
		} else if strings.HasPrefix(namespace, "rhel:8.") {
			cpes = utils.NewSet(
				"cpe:/o:redhat:rhel:8.3::baseos",
				"cpe:/a:redhat:enterprise_linux:8::appstream",
				"cpe:/o:redhat:enterprise_linux:8::baseos")
		}
	}

	/*
		// require live download
		if cpes == nil || cpes.Cardinality() == 0 {
			// check the customer build CPEs
			for filename, d := range data {
				var component string
				var arch string
				var version string
				if strings.HasPrefix(filename, dockerfile) {
					r := versionRegexp.FindStringSubmatch(filename)
					if len(r) > 2 {
						version = r[2]
					}
					scanner := bufio.NewScanner(strings.NewReader(string(d)))
					for scanner.Scan() {
						lines := strings.Split(scanner.Text(), " ")
						for _, line := range lines {
							r = redhatRegexp.FindStringSubmatch(line)
							if len(r) > 1 {
								component = r[1]
							}

							r = archRegexp.FindStringSubmatch(line)
							if len(r) > 1 {
								arch = r[1]
							}
						}
					}
					if arch != "" && component != "" && version != "" {
						cpes = pyxisGetCpes(arch, component, version)
						if cpes != nil && cpes.Cardinality() > 0 {
							break
						}
					}
				}
			}
		}
	*/
	log.WithFields(log.Fields{"namespace": namespace, "cpes": cpes}).Info()

	// Create a map to store packages and ensure their uniqueness
	packagesMap := make(map[string]detectors.FeatureVersion)

	scanner := bufio.NewScanner(strings.NewReader(string(f.Data)))
	for scanner.Scan() {
		line := strings.Split(scanner.Text(), " ")
		if len(line) != 2 {
			// We may see warnings on some RPM versions:
			// "warning: Generating 12 missing index(es), please wait..."
			continue
		}

		// Ignore gpg-pubkey packages which are fake packages used to store GPG keys - they are not versionned properly.
		if line[0] == "gpg-pubkey" {
			continue
		}

		// Parse version
		version, err := common.NewVersion(strings.Replace(line[1], "(none):", "", -1))
		if err != nil {
			log.Warningf("could not parse package version '%s': %s. skipping", line[1], err.Error())
			continue
		}

		// Add package
		pkg := detectors.FeatureVersion{
			Feature: detectors.Feature{
				Name: line[0],
			},
			Version: version,
			CPEs:    cpes,
			InBase:  f.InBase,
		}
		packagesMap[pkg.Feature.Name+"#"+pkg.Version.String()] = pkg
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
	return []string{"var/lib/rpm/Packages"}
}

type Metadata struct {
	IcmVersion      int    `json:"icm_version"`
	IcmSpec         string `json:"icm_spec"`
	ImageLayerIndex int    `json:"image_layer_index"`
}

type ContainerJson struct {
	Metadata      Metadata `json:"metadata"`
	ContentSets   []string `json:"content_sets"`
	ImageContents []string `json:"image_contents"`
}

type RpmsMap struct {
	Data map[string]map[string][]string
}

func getContentSets(data []byte) []string {
	var v ContainerJson
	err := json.Unmarshal(data, &v)
	if err != nil {
		log.Errorf("could not Unmarshal the ContainerJson data: %s", err)
		return nil
	}
	return v.ContentSets
}

func getMappingJson(rpms []string) utils.Set {
	allCpes := utils.NewSet()
	for _, rpm := range rpms {
		if cpesMap, ok := rpmsMap.Data[rpm]; ok {
			if cpes, ok := cpesMap["cpes"]; ok {
				for _, cpe := range cpes {
					allCpes.Add(cpe)
				}
			}
		}
	}
	return allCpes
}

type RpmsNvrData struct {
	Data []RpmsData
}

type RpmsData struct {
	CpeIds     []string   `json:"cpe_ids"`
	ParsedData ParsedData `json:"parsed_data"`
}

type ParsedData struct {
	Labels []map[string]string `json:"labels"`
}

/*
func pyxisGetCpes(arch, component, version string) utils.Set {
	rurl := fmt.Sprintf("%s/%s-%s", pyxisUrl, component, version)
	req, err := http.NewRequest("GET", rurl, nil)
	req.Header.Add("User-Agent", "dbgen")
	client := http.Client{}
	r, err := client.Do(req)
	if err != nil {
		log.Errorf("could not download mapping json: %s", err)
		return nil
	}
	body, _ := ioutil.ReadAll(r.Body)
	var v RpmsNvrData
	err = json.Unmarshal(body, &v)
	if err != nil {
		log.Errorf("could not Unmarshal the file: %s", err)
		return nil
	}

	allCpes := utils.NewSet()
	for _, data := range v.Data {
		for _, label := range data.ParsedData.Labels {
			if name, ok := label["name"]; ok && name == "architecture" {
				if value, ok := label["value"]; ok && value == arch {
					for _, cpe := range data.CpeIds {
						allCpes.Add(cpe)
					}
				}
			}
		}
	}

	return allCpes
}
*/

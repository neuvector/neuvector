package kv

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
)

const registryDataDir = NeuvectorDir + "registry/"
const summarySuffix = ".sum"
const reportSuffix = ".gz"

func registryImageSummaryFileName(name, id string) string {
	return fmt.Sprintf("%s%s/%s%s", registryDataDir, name, id, summarySuffix)
}

func registryImageReportFileName(name, id string) string {
	return fmt.Sprintf("%s%s/%s%s", registryDataDir, name, id, reportSuffix)
}

func writeRegistryImageSummary(name, id string, dat []byte) error {
	path := fmt.Sprintf("%s%s", registryDataDir, name)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		os.MkdirAll(path, 0755)
	}
	filename := registryImageSummaryFileName(name, id)
	if err := ioutil.WriteFile(filename, dat, 0755); err != nil {
		log.WithFields(log.Fields{"error": err, "filename": filename}).Error("Unable to write file")
		return err
	}
	return nil
}

func writeRegistryImageReport(name, id string, dat []byte) error {
	path := fmt.Sprintf("%s%s", registryDataDir, name)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		os.MkdirAll(path, 0755)
	}
	filename := registryImageReportFileName(name, id)
	if err := ioutil.WriteFile(filename, dat, 0755); err != nil {
		log.WithFields(log.Fields{"error": err, "filename": filename}).Error("Unable to write file")
		return err
	}
	return nil
}

func deleteRegistryImageSummary(name, id string) error {
	filename := registryImageSummaryFileName(name, id)
	return os.Remove(filename)
}

func deleteRegistryImageReport(name, id string) error {
	filename := registryImageReportFileName(name, id)
	return os.Remove(filename)
}

func readRegistryImageSummary(name, id string) ([]byte, error) {
	filename := registryImageSummaryFileName(name, id)
	if dat, err := ioutil.ReadFile(filename); err != nil {
		return nil, err
	} else {
		return dat, nil
	}
}

func readRegistryImageReport(name, id string) ([]byte, error) {
	filename := registryImageReportFileName(name, id)
	if dat, err := ioutil.ReadFile(filename); err != nil {
		return nil, err
	} else {
		return dat, nil
	}
}

func createRegistryDir(name string) error {
	path := fmt.Sprintf("%s%s", registryDataDir, name)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, 0755)
	} else {
		return nil
	}
}

func deleteRegistryDir(name string) error {
	path := fmt.Sprintf("%s%s", registryDataDir, name)
	return os.RemoveAll(path)
}

func restoreToCluster(reg string) {
	regPath := fmt.Sprintf("%s%s", registryDataDir, reg)
	log.WithFields(log.Fields{"regPath": regPath, "name": reg}).Debug("Restore to cluster")

	// 1. Read summary first
	sums := make([]*share.CLUSRegistryImageSummary, 0)
	filepath.Walk(regPath, func(path string, info os.FileInfo, err error) error {
		if info != nil && strings.HasSuffix(path, summarySuffix) {
			value, err := ioutil.ReadFile(path)
			if err == nil {
				var sum share.CLUSRegistryImageSummary
				if err = json.Unmarshal(value, &sum); err == nil {
					if sum.Status == api.ScanStatusFinished {
						sums = append(sums, &sum)
					}
				} else {
					log.WithFields(log.Fields{"error": err, "path": path}).Error("Failed to unmarshal summary")
				}
			} else {
				log.WithFields(log.Fields{"error": err, "path": path}).Error("Failed to read summary")
			}
		}
		return nil
	})

	// 2. Sort summary new to old, and remove the old ones
	if len(sums) > api.ScanPersistImageMax {
		sort.Slice(sums, func(i, j int) bool { return sums[i].ScannedAt.After(sums[j].ScannedAt) })
		dels := sums[api.ScanPersistImageMax:]
		sums = sums[:api.ScanPersistImageMax]

		for _, sum := range dels {
			os.Remove(fmt.Sprintf("%s/%s%s", regPath, sum.ImageID, summarySuffix))
			os.Remove(fmt.Sprintf("%s/%s%s", regPath, sum.ImageID, reportSuffix))
		}
		log.WithFields(log.Fields{"count": len(dels)}).Info("Remove old images")
	}

	// 3. Read the report and write both into kv
	for _, sum := range sums {
		key := share.CLUSRegistryImageStateKey(reg, sum.ImageID)
		value, _ := json.Marshal(&sum)
		if err := cluster.Put(key, value); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to restore summary to cluster")
		}

		rptFile := fmt.Sprintf("%s/%s%s", regPath, sum.ImageID, reportSuffix)
		value, err := ioutil.ReadFile(rptFile)
		if err == nil {
			key = share.CLUSRegistryImageDataKey(reg, sum.ImageID)
			if err = cluster.PutBinary(key, value); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Failed to restore report to cluster")
			}
		} else {
			log.WithFields(log.Fields{"error": err, "path": rptFile}).Error("Failed to read report")
		}
	}
}

func restoreRegistry(ch chan<- error) {
	files, err := ioutil.ReadDir(registryDataDir)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Failed to read registry directory")
	} else {
		for _, info := range files {
			name := info.Name()
			if info.IsDir() && name != "" && name != "." {
				restoreToCluster(name)
			}
		}
	}

	ch <- err
}

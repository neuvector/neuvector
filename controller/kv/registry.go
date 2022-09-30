package kv

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
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

type regImageSummaryReport struct {
	Summary []byte `json:"summary"`
	Report  []byte `json:"report"`
}

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

func restoreToCluster(reg, fedRole string, fedScanReportRevisions map[string]map[string]string) {
	var imageRevs map[string]string
	isFedReg := false
	if strings.HasPrefix(reg, api.FederalGroupPrefix) {
		isFedReg = true
		if _, ok := fedScanReportRevisions[reg]; !ok {
			fedScanReportRevisions[reg] = make(map[string]string, 1)
		}
		imageRevs = fedScanReportRevisions[reg]
	}

	regPath := fmt.Sprintf("%s%s", registryDataDir, reg)
	log.WithFields(log.Fields{"regPath": regPath, "name": reg, "fedRole": fedRole}).Debug("Restore to cluster")

	// 1. Read summary first
	sums := make([]*share.CLUSRegistryImageSummary, 0)
	if !isFedReg || fedRole == api.FedRoleMaster || (fedRole == api.FedRoleJoint && isFedReg) {
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
	} else {
		os.RemoveAll(regPath)
	}

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
		var sErr error
		key := share.CLUSRegistryImageStateKey(reg, sum.ImageID)
		vSummary, _ := json.Marshal(&sum)
		if sErr = cluster.Put(key, vSummary); sErr != nil {
			log.WithFields(log.Fields{"error": sErr}).Error("Failed to restore summary to cluster")
		}

		rptFile := fmt.Sprintf("%s/%s%s", regPath, sum.ImageID, reportSuffix)
		vReport, vErr := ioutil.ReadFile(rptFile)
		if vErr == nil {
			key = share.CLUSRegistryImageDataKey(reg, sum.ImageID)
			if vErr = cluster.PutBinary(key, vReport); vErr != nil {
				log.WithFields(log.Fields{"error": vErr}).Error("Failed to restore report to cluster")
			}
		} else {
			log.WithFields(log.Fields{"error": vErr, "path": rptFile}).Error("Failed to read report")
		}

		if sErr == nil && vErr == nil && isFedReg && imageRevs != nil {
			scan_data := regImageSummaryReport{
				Summary: vSummary,
				Report:  vReport,
			}
			data, _ := json.Marshal(&scan_data)
			md5Sum := md5.Sum(data)
			imageRevs[sum.ImageID] = hex.EncodeToString(md5Sum[:])
		}
	}

	// 4. (for restoring scan result of the images in fed registry on master cluster only)
	if isFedReg && len(imageRevs) > 0 {
		fedScanReportRevisions[reg] = imageRevs
	}
}

func restoreRegistry(ch chan<- error, importInfo fedRulesRevInfo) {
	files, err := ioutil.ReadDir(registryDataDir)
	if err != nil {
		log.WithFields(log.Fields{"fedRole": importInfo.fedRole}).Debug("Failed to read registry directory")
	} else {
		fedScanReportRevisions := make(map[string]map[string]string) // registry name : image id : scan report md5
		for _, info := range files {
			name := info.Name()
			if info.IsDir() && name != "" && name != "." {
				restoreToCluster(name, importInfo.fedRole, fedScanReportRevisions)
			}
		}

		if len(fedScanReportRevisions) > 0 {
			lock, err := clusHelper.AcquireLock(share.CLUSLockFedScanDataKey, clusterLockWait)
			if err != nil {
				return
			}
			defer clusHelper.ReleaseLock(lock)

			retry := 0
			for retry < 3 {
				scanRevs, rev, err := clusHelper.GetFedScanRevisions()
				if err != nil {
					break
				}

				scanRevs.RegistryRevision = 0
				scanRevs.ScannedRegImagesRev = 0
				// assign random numbers to scanRevs.RegistryRevision & scanRevs.ScannedRegImagesRev on managed clusters so that the first scan data polling is always triggered
				if importInfo.fedRole == api.FedRoleJoint {
					scanRevs.RegistryRevision = rand.Uint64()
					scanRevs.ScannedRegImagesRev = rand.Uint64()
				} else if importInfo.fedRole == api.FedRoleMaster {
					scanRevs.RegistryRevision = 1
					scanRevs.ScannedRegImagesRev = 1
				}
				for regName, imageRevs := range fedScanReportRevisions {
					if existing, ok := scanRevs.ScanReportRevisions[regName]; !ok {
						scanRevs.ScanReportRevisions[regName] = imageRevs
					} else {
						for imageID, imageRev := range imageRevs {
							if imageRev != existing[imageID] {
								existing[imageID] = imageRev
							}
						}
					}
				}
				if err = clusHelper.PutFedScanRevisions(&scanRevs, &rev); err == nil {
					break
				}
				retry++
			}
			if retry >= 3 {
				log.WithFields(log.Fields{"error": err}).Error("Failed to update fed scan revisions")
			}
		}
	}

	//ch <- err
}

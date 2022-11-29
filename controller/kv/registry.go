package kv

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
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

func restoreToCluster(reg, fedRole string) {
	isFedReg := false
	if strings.HasPrefix(reg, api.FederalGroupPrefix) {
		isFedReg = true
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
		rptFile := fmt.Sprintf("%s/%s%s", regPath, sum.ImageID, reportSuffix)
		vReport, vErr := ioutil.ReadFile(rptFile)
		if vErr == nil {
			// 3-1. must restore scan/data/image/{reg}/{id} key first !
			vKey := share.CLUSRegistryImageDataKey(reg, sum.ImageID)
			if err := cluster.PutBinary(vKey, vReport); err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Failed to restore report to cluster")
			} else {
				// 3-2. then restore scan/state/image/{reg}/{id} key
				var sErr error
				sKey := share.CLUSRegistryImageStateKey(reg, sum.ImageID)
				vSummary, _ := json.Marshal(&sum)
				if sErr = cluster.Put(sKey, vSummary); sErr != nil {
					cluster.Delete(vKey)
					log.WithFields(log.Fields{"error": sErr}).Error("Failed to restore summary to cluster")
				}
			}
		} else {
			log.WithFields(log.Fields{"error": vErr, "path": rptFile}).Error("Failed to read report")
		}
	}
}

func restoreRegistry(ch chan<- error, importInfo fedRulesRevInfo) {
	scanRevs, _, _ := clusHelper.GetFedScanRevisions()
	if !scanRevs.Restoring {
		// assign random numbers to RegConfigRev, ScannedRegRevs & ScannedRepoRev on managed clusters so that the first scan data polling is always triggered
		files, err := ioutil.ReadDir(registryDataDir)
		if err != nil {
			log.WithFields(log.Fields{"fedRole": importInfo.fedRole}).Debug("Failed to read registry directory")
		} else {
			if scanRevs.ScannedRegRevs == nil {
				scanRevs.ScannedRegRevs = make(map[string]uint64)
			}
			scanRevs.Restoring = true
			clusHelper.PutFedScanRevisions(&scanRevs, nil)

			randRev := uint64(rand.Uint32())
			if randRev == 0 {
				randRev = uint64(rand.Uint32())
			}
			fedScannedRegRevs := make(map[string]uint64)
			acc := access.NewFedAdminAccessControl()
			var fedScannedRepoRev uint64 = 0
			for _, info := range files {
				name := info.Name()
				if info.IsDir() && name != "" && name != "." {
					// no matter deployRegScanData/deployRepoScanData is true or not, always restore fed registry/repo scan result(if any in backup)
					if strings.HasPrefix(name, api.FederalGroupPrefix) {
						if name != common.RegistryFedRepoScanName {
							if config, _, _ := clusHelper.GetRegistry(name, acc); config == nil {
								if importInfo.fedRole == api.FedRoleJoint {
									// when a fed registry's scan result is restored on joint cluster, its fed registry key may not exist in kv yet.
									// when this happens, we need to create a pseudo fed registry key so that the scan result can be restored successfully
									log.WithFields(log.Fields{"name": name}).Info("add pseudo fed registry key")
									clusHelper.PutRegistryIfNotExist(&share.CLUSRegistryConfig{Name: name, CfgType: share.FederalCfg})
									time.Sleep(time.Second)
								} else {
									log.WithFields(log.Fields{"name": name}).Error("fed registry not found")
								}
							}
						}
					}
					restoreToCluster(name, importInfo.fedRole)
					if strings.HasPrefix(name, api.FederalGroupPrefix) {
						if name == common.RegistryFedRepoScanName {
							// scan/state/image/fed._repo_scan/... & scan/data/image/fed._repo_scan/... are only available on managed clusters
							if importInfo.fedRole == api.FedRoleJoint {
								fedScannedRepoRev = randRev
							}
						} else {
							fedScannedRegRevs[name] = randRev
						}
					} else if name == common.RegistryRepoScanName && importInfo.fedRole == api.FedRoleMaster {
						// scan/state/image/_repo_scan/... & scan/data/image/_repo_scan/... on master cluster are for fed repo
						fedScannedRepoRev = randRev
					}
				}
			}

			success := false
			lock, err := clusHelper.AcquireLock(share.CLUSLockFedScanDataKey, clusterLockWait)
			if err == nil {
				defer clusHelper.ReleaseLock(lock)

				retry := 0
				for retry < 3 {
					scanRevs, rev, err := clusHelper.GetFedScanRevisions()
					if err != nil {
						break
					}

					// assign random numbers to RegConfigRev, ScannedRegRevs & ScannedRepoRev on managed clusters so that the first scan data polling is always triggered
					scanRevs.Restoring = false
					scanRevs.RegConfigRev = randRev
					for name, value := range scanRevs.ScannedRegRevs {
						if _, ok := fedScannedRegRevs[name]; !ok {
							fedScannedRegRevs[name] = value
						}
					}
					scanRevs.ScannedRegRevs = fedScannedRegRevs
					scanRevs.ScannedRepoRev = fedScannedRepoRev
					if err = clusHelper.PutFedScanRevisions(&scanRevs, &rev); err == nil {
						log.WithFields(log.Fields{"scanRevs": scanRevs}).Info()
						success = true
						break
					}
					retry++
				}
				if retry >= 3 {
					log.WithFields(log.Fields{"error": err}).Error("Failed to update fed scan revisions")
				}
			}
			if !success {
				if scanRevs, _, err := clusHelper.GetFedScanRevisions(); err == nil {
					scanRevs.Restoring = false
					clusHelper.PutFedScanRevisions(&scanRevs, nil)
				}
			}
		}
		log.Info("Done")

		//ch <- err
	}
}

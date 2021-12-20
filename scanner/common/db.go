package common

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

const maxExtractSize = 0 // No extract limit
const maxVersionHeader = 100 * 1024
const maxBufferSize = 1024 * 1024
const encryptLocalDB = true

type DBFile struct {
	Filename string
	Key      KeyVersion
	Files    []utils.TarFileInfo
}

type outputPackage struct {
	Package      string `json:"Package"`
	FixedVersion string `json:"Fixed_version"`
}

type outputCVEVul struct {
	share.ScanVulnerability
	Source   string          `json:"Source"`
	Packages []outputPackage `json:"Packages"`
}

func ReadCveDbMeta(path string, hasAlpine, hasAmazon bool, output bool) (map[string]*share.ScanVulnerability, error) {
	var outCVEs []*outputCVEVul

	if output {
		outCVEs = make([]*outputCVEVul, 0)
	}

	fullDb := make(map[string]*share.ScanVulnerability, 0)
	if err := readCveDbMeta(path, "ubuntu", fullDb, outCVEs); err != nil {
		return nil, err
	}
	if err := readCveDbMeta(path, "centos", fullDb, outCVEs); err != nil {
		return nil, err
	}
	if err := readCveDbMeta(path, "debian", fullDb, outCVEs); err != nil {
		return nil, err
	}
	if hasAlpine {
		if err := readCveDbMeta(path, "alpine", fullDb, outCVEs); err != nil {
			return nil, err
		}
	}
	if hasAmazon {
		if err := readCveDbMeta(path, "amazon", fullDb, outCVEs); err != nil {
			return nil, err
		}
	}
	if err := readAppDbMeta(path, fullDb, outCVEs); err != nil {
		return nil, err
	}

	if output {
		sort.Slice(outCVEs, func(s, t int) bool {
			return outCVEs[s].Name < outCVEs[t].Name
		})
		file, _ := json.MarshalIndent(outCVEs, "", "    ")
		_ = ioutil.WriteFile("cvedb.json", file, 0644)
	}

	return fullDb, nil
}

func readCveDbMeta(path, osname string, fullDb map[string]*share.ScanVulnerability, outCVEs []*outputCVEVul) error {
	filename := fmt.Sprintf("%s%s_full.tb", path, osname)
	fvul, err := os.Open(filename)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "os": osname}).Error("Can't open file")
		return err
	}
	defer fvul.Close()

	data, err := ioutil.ReadAll(fvul)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Read file error")
		return err
	}

	if encryptLocalDB {
		data, err = utils.Decrypt(utils.GetCVEDBEncryptKey(), data)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Decrypt file error")
			return err
		}
	}

	buf := make([]byte, maxBufferSize)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(buf, maxBufferSize)
	for scanner.Scan() {
		var v VulFull
		s := scanner.Text()
		err := json.Unmarshal([]byte(s), &v)
		var cveName string
		// get ubuntu upstream out from ubuntu. make it an independent branch
		if v.Namespace == "ubuntu:upstream" {
			cveName = fmt.Sprintf("upstream:%s", v.Name)
		} else {
			cveName = fmt.Sprintf("%s:%s", osname, v.Name)
		}
		if err == nil {
			if _, ok := fullDb[cveName]; !ok {
				sv := &share.ScanVulnerability{
					Score:            getCvssScore(v.Metadata),
					Vectors:          getCvssVector(v.Metadata),
					Description:      v.Description,
					Link:             v.Link,
					ScoreV3:          getCvssScoreV3(v.Metadata),
					VectorsV3:        getCvssVectorV3(v.Metadata),
					PublishedDate:    getPublishedDate(v.Metadata),
					LastModifiedDate: getLastModifiedDate(v.Metadata),
					FeedRating:       v.FeedRating,
				}
				fullDb[cveName] = sv

				if outCVEs != nil {
					out := &outputCVEVul{ScanVulnerability: *sv, Packages: make([]outputPackage, 0)}
					out.Name = v.Name
					out.Source = osname

					for _, fi := range v.FixedIn {
						out.Packages = append(out.Packages, outputPackage{Package: fi.Name, FixedVersion: fi.Version})
					}
					sort.Slice(out.Packages, func(s, t int) bool {
						return out.Packages[s].Package < out.Packages[t].Package
					})
					outCVEs = append(outCVEs, out)
				}
			}
		}
	}

	log.WithFields(log.Fields{"vuls": len(fullDb), "osname": osname, "path": path}).Debug("")
	return nil
}

func readAppDbMeta(path string, fullDb map[string]*share.ScanVulnerability, outCVEs []*outputCVEVul) error {
	var filename string
	filename = fmt.Sprintf("%s/apps.tb", path)
	fvul, err := os.Open(filename)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("open file error")
		return err
	}
	defer fvul.Close()

	data, err := ioutil.ReadAll(fvul)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Read file error")
		return err
	}

	if encryptLocalDB {
		data, err = utils.Decrypt(utils.GetCVEDBEncryptKey(), data)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Decrypt file error")
			return err
		}
	}

	buf := make([]byte, maxBufferSize)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(buf, maxBufferSize)
	for scanner.Scan() {
		var v AppModuleVul
		s := scanner.Text()
		err := json.Unmarshal([]byte(s), &v)
		if err == nil {
			cveName := fmt.Sprintf("%s:%s", "apps", v.VulName)
			if _, ok := fullDb[cveName]; !ok {
				sv := &share.ScanVulnerability{
					Score:            float32(v.Score),
					Vectors:          v.Vectors,
					ScoreV3:          float32(v.ScoreV3),
					VectorsV3:        v.VectorsV3,
					Severity:         v.Severity,
					Description:      v.Description,
					Link:             v.Link,
					PublishedDate:    v.IssuedDate.Format(time.RFC3339),
					LastModifiedDate: v.LastModDate.Format(time.RFC3339),
				}
				fullDb[cveName] = sv

				if outCVEs != nil {
					out := &outputCVEVul{ScanVulnerability: *sv, Packages: make([]outputPackage, 0)}
					out.Name = v.VulName
					out.Source = "apps"
					out.Packages = append(out.Packages, outputPackage{Package: v.ModuleName})
					for _, fv := range v.FixedVer {
						op := strings.Replace(fv.OpCode, "or", "||", -1)
						op = strings.Replace(op, "gt", ">", -1)
						op = strings.Replace(op, "lt", "<", -1)
						op = strings.Replace(op, "eq", "=", -1)
						out.Packages[0].FixedVersion = fmt.Sprintf("%s%s;%s", op, fv.Version, out.Packages[0].FixedVersion)
					}
					outCVEs = append(outCVEs, out)
				}
			}
		} else {
			log.Error("Unmarshal vulnerability err")
		}
	}
	return nil
}

func getCvssScore(meta map[string]NVDMetadata) float32 {
	if n, ok := meta["NVD"]; ok {
		return float32(n.CVSSv2.Score)
	} else {
		return 0
	}
}

func getCvssVector(meta map[string]NVDMetadata) string {
	if n, ok := meta["NVD"]; ok {
		return n.CVSSv2.Vectors
	} else {
		return ""
	}
}

func getCvssScoreV3(meta map[string]NVDMetadata) float32 {
	if n, ok := meta["NVD"]; ok {
		return float32(n.CVSSv3.Score)
	} else {
		return 0
	}
}

func getCvssVectorV3(meta map[string]NVDMetadata) string {
	if n, ok := meta["NVD"]; ok {
		return n.CVSSv3.Vectors
	} else {
		return ""
	}
}

func getPublishedDate(meta map[string]NVDMetadata) string {
	if n, ok := meta["NVD"]; ok {
		return n.PublishedDate.Format(time.RFC3339)
	} else {
		return ""
	}
}

func getLastModifiedDate(meta map[string]NVDMetadata) string {
	if n, ok := meta["NVD"]; ok {
		return n.LastModifiedDate.Format(time.RFC3339)
	} else {
		return ""
	}
}

func LoadVulnerabilityIndex(path, osname string) ([]VulShort, error) {
	var filename string
	filename = fmt.Sprintf("%s/%s_index.tb", path, osname)
	fvul, err := os.Open(filename)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Open file error")
		return nil, err
	}
	defer fvul.Close()

	data, err := ioutil.ReadAll(fvul)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Read file error")
		return nil, err
	}

	if encryptLocalDB {
		data, err = utils.Decrypt(utils.GetCVEDBEncryptKey(), data)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Decrypt file error")
			return nil, err
		}
	}

	vul := make([]VulShort, 0)

	buf := make([]byte, maxBufferSize)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(buf, maxBufferSize)
	for scanner.Scan() {
		var v VulShort
		s := scanner.Text()
		err := json.Unmarshal([]byte(s), &v)
		if err == nil {
			vul = append(vul, v)
		} else {
			log.Error("Unmarshal vulnerability err")
		}
	}
	return vul, nil
}

func LoadFullVulnerabilities(path, osname string) (map[string]VulFull, error) {
	filename := fmt.Sprintf("%s%s_full.tb", path, osname)

	fvul, err := os.Open(filename)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Can't open file")
		return nil, err
	}
	defer fvul.Close()

	data, err := ioutil.ReadAll(fvul)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Read file error")
		return nil, err
	}

	if encryptLocalDB {
		data, err = utils.Decrypt(utils.GetCVEDBEncryptKey(), data)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Decrypt file error")
			return nil, err
		}
	}

	fullDb := make(map[string]VulFull, 0)

	buf := make([]byte, maxBufferSize)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(buf, maxBufferSize)
	for scanner.Scan() {
		var v VulFull
		s := scanner.Text()
		err := json.Unmarshal([]byte(s), &v)
		cveName := fmt.Sprintf("%s:%s", v.Namespace, v.Name)
		if err == nil {
			fullDb[cveName] = v
		}
	}
	return fullDb, nil
}

func LoadAppVulsTb(path string) (map[string][]AppModuleVul, error) {
	var filename string
	filename = fmt.Sprintf("%s/apps.tb", path)
	fvul, err := os.Open(filename)
	if err != nil {
		log.WithFields(log.Fields{"filename": filename, "error": err}).Error("open file error")
		return nil, err
	}
	defer fvul.Close()

	data, err := ioutil.ReadAll(fvul)
	if err != nil {
		log.WithFields(log.Fields{"filename": filename, "error": err}).Error("Read file error")
		return nil, err
	}

	if encryptLocalDB {
		data, err = utils.Decrypt(utils.GetCVEDBEncryptKey(), data)
		if err != nil {
			log.WithFields(log.Fields{"filename": filename, "error": err}).Error("Decrypt file error")
			return nil, err
		}
	}

	vul := make(map[string][]AppModuleVul, 0)

	buf := make([]byte, maxBufferSize)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(buf, maxBufferSize)
	for scanner.Scan() {
		var v AppModuleVul
		s := scanner.Text()
		err := json.Unmarshal([]byte(s), &v)
		if err == nil {
			vf, ok := vul[v.ModuleName]
			if !ok {
				vf = make([]AppModuleVul, 0)
			}
			vf = append(vf, v)
			vul[v.ModuleName] = vf
		} else {
			log.Error("Unmarshal vulnerability err")
		}
	}

	// for org.apache.logging.log4j:log4j-core, we will also search
	// org.apache.logging.log4j.log4j-core: for backward compatibility
	// log4j-core: for jar file without pom.xml. Prefix jar: to avoid collision
	for mn, vf := range vul {
		if colon := strings.LastIndex(mn, ":"); colon > 0 {
			m := strings.ReplaceAll(mn, ":", ".")
			if _, ok := vul[m]; ok {
				vul[m] = append(vul[m], vf...)
			} else {
				vul[m] = vf
			}
			if m = mn[colon+1:]; len(m) > 0 {
				vul[fmt.Sprintf("jar:%s", m)] = vf
			}
		}
	}

	return vul, nil
}

func LoadRawFile(path, name string) ([]byte, error) {
	var filename string
	filename = fmt.Sprintf("%s/%s", path, name)
	fp, err := os.Open(filename)
	if err != nil {
		log.WithFields(log.Fields{"filename": filename, "error": err}).Error("open file error")
		return nil, err
	}
	defer fp.Close()

	data, err := ioutil.ReadAll(fp)
	if err != nil {
		log.WithFields(log.Fields{"filename": filename, "error": err}).Error("Read file error")
		return nil, err
	}

	if encryptLocalDB {
		data, err = utils.Decrypt(utils.GetCVEDBEncryptKey(), data)
		if err != nil {
			log.WithFields(log.Fields{"filename": filename, "error": err}).Error("Decrypt file error")
			return nil, err
		}
	}

	return data, nil
}

func LoadCveDb(path, desPath string) (string, string, bool, bool, error) {
	var latestVer string

	if err := os.RemoveAll(desPath); err != nil {
		log.WithFields(log.Fields{"error": err, "dir": desPath}).Error("Failed to remove directory")
	}

	if _, err := os.Stat(desPath); os.IsNotExist(err) {
		if err = os.MkdirAll(desPath, 0760); err != nil {
			log.WithFields(log.Fields{"error": err, "dir": desPath}).Error("Failed to make directory")
			return "", "", false, false, err
		}
	}

	// Read new db version
	newVer, update, err := GetDbVersion(path)
	if err == nil {
		log.WithFields(log.Fields{"version": newVer, "update": update}).Debug("New DB found")
	} else {
		log.Error(err)
	}

	// Read expanded db version
	oldVer, _, hasAlpineTb, hasAmazonTb, oldErr := CheckExpandedDb(desPath, true)
	if oldErr != nil && err != nil {
		// no new database, no expanded database
		log.WithFields(log.Fields{"error": err}).Error("No CVE database found")
		return "", "", false, false, err
	} else if oldErr != nil && err == nil {
		log.WithFields(log.Fields{"version": newVer}).Info("Expand new DB")

		// has new database, no expanded database, untar the new database
		err = unzipDb(path, desPath)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Unzip CVE database")
			return "", "", false, false, err
		}

		newVer, update, hasAlpineTb, hasAmazonTb, err = CheckExpandedDb(desPath, true)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("CVE database format error")
			return "", "", false, false, errors.New("Invalid database format")
		}
		latestVer = fmt.Sprintf("%.3f", newVer)
	} else if oldErr == nil && err == nil && newVer > oldVer {
		log.WithFields(log.Fields{"version": newVer}).Info("Expand new DB")

		// new database is newer then the expanded database, untar the new database
		tmpDir, err := ioutil.TempDir(os.TempDir(), "cvedb")
		if err != nil {
			log.Errorf("could not create temporary folder for RPM detection: %s", err)
			return "", "", false, false, err
		}

		err = unzipDb(path, tmpDir+"/")
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Unzip CVE database")
			os.RemoveAll(tmpDir)
			return "", "", false, false, err
		}

		newVer, update, hasAlpineTb, hasAmazonTb, err = CheckExpandedDb(tmpDir+"/", true)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("CVE database format error")
			os.Remove(path + share.DefaultCVEDBName)
			os.RemoveAll(tmpDir)
		} else {
			removeDb(desPath)
			err = moveDb(tmpDir+"/", desPath)
			os.RemoveAll(tmpDir)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("mv CVE database error")
				return "", "", false, false, err
			}
		}
		latestVer = fmt.Sprintf("%.3f", newVer)
	} else {
		latestVer = fmt.Sprintf("%.3f", oldVer)
	}

	return latestVer, update, hasAlpineTb, hasAmazonTb, nil
}

func GetDbVersion(path string) (float64, string, error) {
	f, err := os.Open(path + share.DefaultCVEDBName)
	if err != nil {
		return 0, "", fmt.Errorf("Read db file fail: %v", err)
	}
	defer f.Close()

	bhead := make([]byte, 4)
	nlen, err := f.Read(bhead)
	if err != nil || nlen != 4 {
		return 0, "", fmt.Errorf("Read db file error: %v", err)
	}
	var headLen int32
	err = binary.Read(bytes.NewReader(bhead), binary.BigEndian, &headLen)
	if err != nil {
		return 0, "", fmt.Errorf("Read header len error: %v", err)
	}

	if headLen > maxVersionHeader {
		return 0, "", fmt.Errorf("Version Header too big: %v", headLen)
	}

	bhead = make([]byte, headLen)
	nlen, err = f.Read(bhead)
	if err != nil || nlen != int(headLen) {
		return 0, "", fmt.Errorf("Read db file version error:%v", err)
	}

	var keyVer KeyVersion

	err = json.Unmarshal(bhead, &keyVer)
	if err != nil {
		return 0, "", fmt.Errorf("Unmarshal keys error:%v", err)
	}
	verFl, err := strconv.ParseFloat(keyVer.Version, 64)
	if err != nil {
		return 0, "", fmt.Errorf("Invalid version value:%v", err)
	}

	return verFl, keyVer.UpdateTime, nil
}

func unzipDb(path, desPath string) error {
	f, err := os.Open(path + share.DefaultCVEDBName)
	if err != nil {
		log.Info("Open zip db file fail")
		return err
	}
	defer f.Close()

	f.Seek(0, 0)

	// read keys len
	bhead := make([]byte, 4)
	nlen, err := f.Read(bhead)
	if err != nil || nlen != 4 {
		log.WithFields(log.Fields{"error": err}).Error("Read db file error")
		return err
	}
	var headLen int32
	err = binary.Read(bytes.NewReader(bhead), binary.BigEndian, &headLen)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Write header len error")
		return err
	}
	if headLen > maxVersionHeader {
		log.Info("Version Header too big:", headLen)
		return err
	}

	// Read head and write keys file
	bhead = make([]byte, headLen)
	nlen, err = f.Read(bhead)
	if err != nil || nlen != int(headLen) {
		log.WithFields(log.Fields{"error": err}).Error("Read db file error")
		return err
	}
	err = ioutil.WriteFile(desPath+"keys", bhead, 0400)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Write keys file error")
		return err
	}

	// Read the rest of DB
	cipherData, err := ioutil.ReadAll(f)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Read db file tar part error")
		return err
	}

	// Use local decrypt function
	plainData, err := decrypt(cipherData, utils.GetCVEDBEncryptKey())
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Decrypt tar file error")
		return err
	}

	tarFile := bytes.NewReader(plainData)
	if encryptLocalDB {
		err = utils.ExtractAllArchiveToFiles(desPath, tarFile, maxExtractSize, utils.GetCVEDBEncryptKey())
	} else {
		err = utils.ExtractAllArchiveToFiles(desPath, tarFile, maxExtractSize, nil)
	}
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Extract db file error")
		return err
	}

	return nil
}

func checkDbHash(filename, hash string) bool {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.WithFields(log.Fields{"file": filename, "error": err}).Info("Read file error")
		return false
	}

	if encryptLocalDB {
		data, err = utils.Decrypt(utils.GetCVEDBEncryptKey(), data)
		if err != nil {
			log.WithFields(log.Fields{"file": filename, "error": err}).Error("Decrypt file error")
			return false
		}
	}

	sha := sha256.Sum256(data)
	ss := fmt.Sprintf("%x", sha)
	if hash == ss {
		return true
	} else {
		log.WithFields(log.Fields{"file": filename}).Error("Hash not match")
		return false
	}
}

const RHELCpeMapFile = "rhel-cpe.map"

var fileList = []string{"keys",
	"ubuntu_index.tb",
	"ubuntu_full.tb",
	"debian_index.tb",
	"debian_full.tb",
	"centos_index.tb",
	"centos_full.tb",
	"alpine_index.tb",
	"alpine_full.tb",
	"amazon_index.tb",
	"amazon_full.tb",
	"apps.tb",
	RHELCpeMapFile,
}

func removeDb(path string) {
	for _, file := range fileList {
		os.Remove(path + file)
	}
}

func moveDb(path, desPath string) error {
	for _, file := range fileList {
		buf, err := utils.Exec(desPath, "mv", path+file, desPath+file)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error(fmt.Sprintf("%s\n", buf))
			return err
		}
	}
	return nil
}

func CheckExpandedDb(path string, checkHash bool) (float64, string, bool, bool, error) {
	var hasAlpineTb bool
	var hasAmazonTb bool

	data, err := ioutil.ReadFile(path + "keys")
	if err != nil {
		return 0, "", false, false, err
	}

	var key KeyVersion
	err = json.Unmarshal(data, &key)
	if err != nil {
		removeDb(path)
		return 0, "", false, false, err
	}

	var verFl float64
	verFl, err = strconv.ParseFloat(key.Version, 64)
	if err != nil {
		removeDb(path)
		return 0, "", false, false, err
	}

	valid := true
	for i := 1; i < len(fileList); i++ {
		if strings.Contains(fileList[i], "alpine") {
			if _, err := os.Stat(path + fileList[i]); err == nil {
				hasAlpineTb = true
			} else {
				hasAlpineTb = false
				continue
			}
		}
		if strings.Contains(fileList[i], "amazon") {
			if _, err := os.Stat(path + fileList[i]); err == nil {
				hasAmazonTb = true
			} else {
				hasAmazonTb = false
				continue
			}
		}

		if checkHash {
			if !checkDbHash(path+fileList[i], key.Shas[fileList[i]]) {
				log.WithFields(log.Fields{"file": fileList[i]}).Error("Database hash error")
				valid = false
			}
		}
	}

	if !valid {
		removeDb(path)
		return 0, "", false, false, errors.New("database hash error")
	}
	return verFl, key.UpdateTime, hasAlpineTb, hasAmazonTb, nil
}

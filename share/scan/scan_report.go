package scan

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

type CVEDBType map[string]*share.ScanVulnerability

// CVELookup provides key-based access to CVE metadata.
// The controller uses a SQLite-backed implementation; tests may use CVEDBMapLookup.
type CVELookup interface {
	Get(name string) (*share.ScanVulnerability, bool)
}

// CVEDBMapLookup adapts a CVEDBType map to the CVELookup interface.
type CVEDBMapLookup struct{ M CVEDBType }

func (l CVEDBMapLookup) Get(name string) (*share.ScanVulnerability, bool) {
	v, ok := l.M[name]
	return v, ok
}

// cvedbMeta holds both CVEDB fields so they can be stored and loaded as a single atomic unit,
// preventing a concurrent reader from observing a new version paired with an old createTime.
type cvedbMeta struct {
	version    string
	createTime string
}

var cvedbMetaPtr atomic.Pointer[cvedbMeta]

// SetCVEDBMeta records the current CVEDB version and create time. Called once per CVEDB
// update from ScannerUpdateHandler after the data has been written to SQLite.
func SetCVEDBMeta(version, createTime string) {
	cvedbMetaPtr.Store(&cvedbMeta{version: version, createTime: createTime})
}

// GetCVEDBMeta returns the current CVEDB version and create time.
func GetCVEDBMeta() (version, createTime string) {
	if m := cvedbMetaPtr.Load(); m != nil {
		return m.version, m.createTime
	}
	return
}

const (
	vulnSeverityLow int8 = iota
	vulnSeverityMedium
	vulnSeverityHigh
	vulnSeverityCritical
)

var serverityString2ID = map[string]int8{
	share.VulnSeverityLow:      vulnSeverityLow,
	share.VulnSeverityMedium:   vulnSeverityMedium,
	share.VulnSeverityHigh:     vulnSeverityHigh,
	share.VulnSeverityCritical: vulnSeverityCritical,
}

var severityID2String = map[int8]string{
	vulnSeverityLow:      share.VulnSeverityLow,
	vulnSeverityMedium:   share.VulnSeverityMedium,
	vulnSeverityHigh:     share.VulnSeverityHigh,
	vulnSeverityCritical: share.VulnSeverityCritical,
}

// These are the unique attributes of vul. that can be different in different workload,
// other info can get from cvedb
type VulTrait struct {
	Name     string
	fileName string
	pkgName  string
	pkgVer   string
	fixVer   string
	dbKey    string
	pubTS    int64
	severity int8
	filtered bool
}

type FixedVulInfo struct {
	PubTS int64
}

func (v VulTrait) IsFiltered() bool {
	return v.filtered
}

func (v VulTrait) GetPubTS() int64 {
	return v.pubTS
}

// Functions can be used in both controllers and scanner
func ScanVul2REST(cvedb CVELookup, baseOS string, vul *share.ScanVulnerability) *api.RESTVulnerability {
	v := &api.RESTVulnerability{
		Name:           vul.Name,
		Score:          vul.Score,
		Severity:       vul.Severity,
		Vectors:        vul.Vectors,
		Description:    vul.Description,
		PackageName:    vul.PackageName,
		FileName:       vul.FileName,
		PackageVersion: vul.PackageVersion,
		FixedVersion:   vul.FixedVersion,
		Link:           vul.Link,
		ScoreV3:        vul.ScoreV3,
		VectorsV3:      vul.VectorsV3,
		CPEs:           vul.CPEs,
		CVEs:           vul.CVEs,
		FeedRating:     vul.FeedRating,
		InBaseImage:    vul.InBase,
	}

	if cvedb == nil {
		return v
	}

	// Fill verbose vulnerability info, new scanner should return DBKey for each cve.
	// The guess work based on baseOS is only needed for upgrade from pre-5.0 cases.
	if vul.DBKey != "" {
		if vr, ok := cvedb.Get(vul.DBKey); ok {
			fillVulFields(vr, v)
		}
	} else {
		baseOS = normalizeBaseOS(baseOS)

		key := fmt.Sprintf("%s:%s", baseOS, v.Name)
		if vr, ok := cvedb.Get(key); ok {
			fillVulFields(vr, v)
		} else {
			// lookup apps
			key = fmt.Sprintf("apps:%s", v.Name)
			if vr, ok := cvedb.Get(key); ok {
				fillVulFields(vr, v)
			} else {
				// fix metadata
				if vr, ok := cvedb.Get(v.Name); ok {
					fillVulFields(vr, v)
				}
			}
		}
	}

	return v
}

func ScanModule2REST(m *share.ScanModule) *api.RESTScanModule {
	var mcve []*api.RESTModuleCve
	if len(m.Vuls) > 0 {
		mcve = make([]*api.RESTModuleCve, len(m.Vuls))
		for i, mc := range m.Vuls {
			mcve[i] = &api.RESTModuleCve{Name: mc.Name}
			switch mc.Status {
			case share.ScanVulStatus_Unpatched:
				mcve[i].Status = api.ScanVulStatusUnpatched
			case share.ScanVulStatus_FixExists:
				mcve[i].Status = api.ScanVulStatusFixExists
			case share.ScanVulStatus_WillNotFix:
				mcve[i].Status = api.ScanVulStatusWillNotFix
			case share.ScanVulStatus_Unaffected:
				mcve[i].Status = api.ScanVulStatusUnaffected
			}
		}
	}
	return &api.RESTScanModule{
		Name:    m.Name,
		File:    m.File,
		Version: m.Version,
		Source:  m.Source,
		CVEs:    mcve,
		CPEs:    m.CPEs,
	}
}

func ScanSecrets2REST(s *share.ScanSecretLog) *api.RESTScanSecret {
	return &api.RESTScanSecret{
		Type:       s.RuleDesc,
		Evidence:   s.Text,
		File:       s.File,
		Suggestion: s.Suggestion,
	}
}

func ScanSetIdPerm2REST(p *share.ScanSetIdPermLog) *api.RESTScanSetIdPerm {
	return &api.RESTScanSetIdPerm{
		Type:     p.Type,
		Evidence: p.Evidence,
		File:     p.File,
	}
}

func GetSetIDBenchMessage(stype, loc, evidence string) string {
	return fmt.Sprintf("File %s has %s mode: %s", loc, stype, evidence)
}

func GetSecretBenchMessage(stype, loc, evidence string) string {
	return fmt.Sprintf("File %s contains %s: %s", loc, stype, evidence)
}

func ImageBench2REST(cmds []string, secrets []*share.ScanSecretLog, setids []*share.ScanSetIdPermLog, complianceProfileFilter map[string][]string) []*api.RESTBenchItem {
	_, metaMap := GetImageBenchMeta()
	runAsRoot, hasADD, hasHEALTHCHECK := ParseImageCmds(cmds)

	checks := make([]*api.RESTBenchItem, 0)
	if runAsRoot {
		if c, ok := metaMap["I.4.1"]; ok {
			item := &api.RESTBenchItem{
				RESTBenchCheck: c.RESTBenchCheck,
				Level:          "WARN",
				Message:        []string{},
			}
			checks = append(checks, item)
		}
	}
	if hasADD {
		if c, ok := metaMap["I.4.9"]; ok {
			item := &api.RESTBenchItem{
				RESTBenchCheck: c.RESTBenchCheck,
				Level:          "WARN",
				Message:        []string{},
			}
			checks = append(checks, item)
		}
	}
	if !hasHEALTHCHECK {
		if c, ok := metaMap["I.4.6"]; ok {
			item := &api.RESTBenchItem{
				RESTBenchCheck: c.RESTBenchCheck,
				Level:          "WARN",
				Message:        []string{},
			}
			checks = append(checks, item)
		}
	}
	if len(secrets) > 0 {
		if c, ok := metaMap["I.4.10"]; ok {
			for _, s := range secrets {
				item := &api.RESTBenchItem{
					RESTBenchCheck: c.RESTBenchCheck,
					Level:          "WARN",
					Location:       s.File,
					Evidence:       s.Text,
					Message:        []string{GetSecretBenchMessage(s.Type, s.File, s.Text)},
				}
				item.Remediation = s.Suggestion
				item.Description = fmt.Sprintf("%s - %s", item.Description, item.Message[0])
				checks = append(checks, item)
			}
		}
	}
	if len(setids) > 0 {
		if c, ok := metaMap["I.4.8"]; ok {
			for _, s := range setids {
				item := &api.RESTBenchItem{
					RESTBenchCheck: c.RESTBenchCheck,
					Level:          "WARN",
					Location:       s.File,
					Evidence:       s.Evidence,
					Message:        []string{GetSetIDBenchMessage(s.Type, s.File, s.Evidence)},
				}
				item.Description = fmt.Sprintf("%s - %s", item.Description, item.Message[0])
				checks = append(checks, item)
			}
		}
	}

	// add tags to every checks
	for _, item := range checks {
		filteredTagsV2 := make(map[string]share.TagDetails)
		if complianceProfileFilter == nil {
			item.Tags = make([]string, 0)
		} else if tags, ok := complianceProfileFilter[item.TestNum]; !ok {
			item.Tags = make([]string, 0)
		} else {
			item.Tags = tags
			for _, tag := range tags {
				filteredTagsV2[tag] = share.TagDetails{}
			}
		}
		// init the TagV2 for compliance profile.
		item.TagsV2 = filteredTagsV2
	}

	return checks
}

// This is use when grpc structure is returned
func FillVul(cvedb CVELookup, vul *share.ScanVulnerability) {
	if cvedb == nil || vul.DBKey == "" {
		return
	}
	if vr, ok := cvedb.Get(vul.DBKey); ok {
		vul.Score = vr.Score
		vul.Vectors = vr.Vectors
		vul.ScoreV3 = vr.ScoreV3
		vul.VectorsV3 = vr.VectorsV3
		vul.Description = vr.Description
		vul.Link = vr.Link
	}
}

func ScanRepoResult2REST(cvedb CVELookup, result *share.ScanResult, tagMap map[string][]string) *api.RESTScanRepoReport {
	rvuls := make([]*api.RESTVulnerability, len(result.Vuls))
	for i, vul := range result.Vuls {
		rvuls[i] = ScanVul2REST(cvedb, result.Namespace, vul)
	}
	rmods := make([]*api.RESTScanModule, len(result.Modules))
	for i, m := range result.Modules {
		rmods[i] = ScanModule2REST(m)
	}

	rsecrets := make([]*api.RESTScanSecret, 0)
	if result.Secrets != nil {
		for _, s := range result.Secrets.Logs {
			rsecrets = append(rsecrets, ScanSecrets2REST(s))
		}
	}

	ridperms := make([]*api.RESTScanSetIdPerm, len(result.SetIdPerms))
	for i, p := range result.SetIdPerms {
		ridperms[i] = ScanSetIdPerm2REST(p)
	}

	layers := make([]*api.RESTScanLayer, len(result.Layers))
	for j, layer := range result.Layers {
		rvuls := make([]*api.RESTVulnerability, len(layer.Vuls))
		for i, vul := range layer.Vuls {
			rvuls[i] = ScanVul2REST(cvedb, result.Namespace, vul)
		}
		/*
			var rsrts []*api.RESTScanSecret
			if scanSecrets { // only display secrets when the flag is enabled
				rsrts = make([]*api.RESTScanSecret, 0)
				if layer.Secrets != nil {
					for _, s := range layer.Secrets.Logs {
						rsrts = append(rsrts, ScanSecrets2REST(s))
					}
				}
			}
		*/
		layers[j] = &api.RESTScanLayer{Digest: layer.Digest, Cmds: layer.Cmds, Vuls: rvuls, Size: layer.Size}
	}

	checks := ImageBench2REST(result.Cmds, result.Secrets.Logs, result.SetIdPerms, tagMap)

	report := &api.RESTScanRepoReport{
		CVEDBVersion:    result.Version,
		CVEDBCreateTime: result.CVEDBCreateTime,
		ImageID:         result.ImageID,
		Registry:        result.Registry,
		Repository:      result.Repository,
		Tag:             result.Tag,
		Digest:          result.Digest,
		Size:            result.Size,
		Author:          result.Author,
		CreatedAt:       result.Created,
		BaseOS:          result.Namespace,
		Layers:          layers,
		RESTScanReport: api.RESTScanReport{
			OSScanStatus: result.OSScanStatus.String(),
			Envs:         result.Envs,
			Labels:       result.Labels,
			Vuls:         rvuls,
			Modules:      rmods,
			Secrets:      rsecrets,
			SetIDs:       ridperms,
			Checks:       checks,
			Cmds:         result.Cmds,
		},
	}
	if result.SignatureInfo != nil {
		report.SignatureInfo = &api.RESTScanSignatureInfo{
			Verifiers:             result.SignatureInfo.Verifiers,
			VerificationTimestamp: result.SignatureInfo.VerificationTimestamp,
		}
	} else {
		report.SignatureInfo = &api.RESTScanSignatureInfo{}
	}

	return report
}

func fillVulFields(vr *share.ScanVulnerability, v *api.RESTVulnerability) {
	v.Score = vr.Score
	v.Vectors = vr.Vectors
	v.ScoreV3 = vr.ScoreV3
	v.VectorsV3 = vr.VectorsV3
	v.Description = vr.Description
	v.Link = vr.Link
	if t, err := time.Parse(time.RFC3339, vr.PublishedDate); err == nil {
		v.PublishedTS = t.Unix()
	}
	if t, err := time.Parse(time.RFC3339, vr.LastModifiedDate); err == nil {
		v.LastModTS = t.Unix()
	}

	if v.Severity == "" {
		if v.Score >= 9 || v.ScoreV3 >= 9 {
			v.Severity = share.VulnSeverityCritical
		} else if v.Score >= 7 || v.ScoreV3 >= 7 {
			v.Severity = share.VulnSeverityHigh
		} else if v.Score >= 4 || v.ScoreV3 >= 4 {
			v.Severity = share.VulnSeverityMedium
		} else {
			v.Severity = share.VulnSeverityLow
		}
	}

	if vr.FeedRating == "" {
		v.FeedRating = v.Severity
	} else {
		v.FeedRating = vr.FeedRating
	}
}

// cvedb lookup now uses DBKey in each vulnerability entry.
// This function is kept for upgrade from pre-5.0 cases.
func normalizeBaseOS(baseOS string) string {
	if a := strings.Index(baseOS, ":"); a > 0 {
		baseOS = baseOS[:a]
		switch baseOS {
		case "rhel", "server", "centos":
			baseOS = "centos"
		case "rhcos":
			baseOS = ""
		case "ol":
			baseOS = "oracle"
		case "amzn":
			baseOS = "amazon"
		case "sles":
			baseOS = "suse"
		}
	}
	return baseOS
}

func FillVulTraits(cvedb CVELookup, baseOS string, vts []*VulTrait, showTag string, includeFiltered bool) []*api.RESTVulnerability {
	baseOS = normalizeBaseOS(baseOS)

	vuls := make([]*api.RESTVulnerability, 0, len(vts))

	for _, vt := range vts {
		if !includeFiltered {
			if vt.filtered && showTag == "" {
				continue
			}
		}

		vul := &api.RESTVulnerability{
			Name:           vt.Name,
			PackageName:    vt.pkgName,
			FileName:       vt.fileName,
			PackageVersion: vt.pkgVer,
			FixedVersion:   vt.fixVer,
			DbKey:          vt.dbKey,
		}
		if sev, ok := severityID2String[vt.severity]; ok {
			vul.Severity = sev
		}

		// Fill verbose vulnerability info, new scanner should return DBKey for each cve.
		// The guess work based on baseOS is only needed for upgrade from pre-5.0 cases.
		if cvedb != nil {
			if vt.dbKey != "" {
				if vr, ok := cvedb.Get(vt.dbKey); ok {
					fillVulFields(vr, vul)
				}
			} else {
				key := fmt.Sprintf("%s:%s", baseOS, vul.Name)
				if vr, ok := cvedb.Get(key); ok {
					fillVulFields(vr, vul)
				} else {
					// lookup apps
					key = fmt.Sprintf("apps:%s", vul.Name)
					if vr, ok := cvedb.Get(key); ok {
						fillVulFields(vr, vul)
					} else {
						if vr, ok := cvedb.Get(vul.Name); ok {
							fillVulFields(vr, vul)
						}
					}
				}
			}
		}

		if vt.filtered {
			vul.Tags = []string{showTag}
		}

		vuls = append(vuls, vul)
	}

	return vuls
}

func ExtractVulnerability(cvedb CVELookup, vuls []*share.ScanVulnerability) []*VulTrait {
	traits := make([]*VulTrait, len(vuls))
	for i, v := range vuls {
		s, ok := serverityString2ID[v.Severity]
		if !ok {
			s = serverityString2ID[share.VulnSeverityLow]
		}

		// This can be called when controller starts, when cvedb has not populated yet
		pubTS, err := strconv.ParseInt(v.PublishedDate, 0, 64)
		if err != nil {
			if t, err := time.Parse(time.RFC3339, v.PublishedDate); err == nil {
				pubTS = t.Unix()
			} else {
				log.WithFields(log.Fields{"publish": v.PublishedDate, "name": v.Name}).Error()
			}
		} else if cvedb != nil && v.DBKey != "" {
			if vr, ok := cvedb.Get(v.DBKey); ok {
				if t, err := time.Parse(time.RFC3339, vr.PublishedDate); err == nil {
					publishedTS := t.Unix()
					if publishedTS != pubTS {
						// found a same-key entry in scannerDB but with different publishDate value than tne entry in vuls(scanResult).
						pubTS = publishedTS
					}
				}
			}
		}

		traits[i] = &VulTrait{
			Name:     v.Name,
			severity: s,
			dbKey:    v.DBKey,
			pubTS:    pubTS,
			fileName: v.FileName,
			pkgName:  v.PackageName, pkgVer: v.PackageVersion, fixVer: v.FixedVersion,
		}

		if v.Score >= 9 || v.ScoreV3 >= 9 {
			traits[i].severity = vulnSeverityCritical
		}
	}
	return traits
}

func CountVulTrait(traits []*VulTrait) (int, int, int) {
	var criticals, highs, meds int

	for _, t := range traits {
		if !t.filtered {
			switch t.severity {
			case vulnSeverityCritical:
				criticals++
			case vulnSeverityHigh:
				highs++
			case vulnSeverityMedium:
				meds++
			}
		}
	}
	return criticals, highs, meds
}

func GatherVulTrait(traits []*VulTrait) ([]string, []string, []string, []string, []FixedVulInfo, []FixedVulInfo) {
	criticals := make([]string, 0)
	highs := make([]string, 0)
	meds := make([]string, 0)
	lows := make([]string, 0)
	fixedCriticalsInfo := make([]FixedVulInfo, 0)
	fixedHighsInfo := make([]FixedVulInfo, 0)
	for _, t := range traits {
		if !t.filtered {
			switch t.severity {
			case vulnSeverityCritical:
				if t.fixVer != "" {
					fixedCriticalsInfo = append(fixedCriticalsInfo, FixedVulInfo{PubTS: t.pubTS})
				}
				criticals = append(criticals, t.Name)
			case vulnSeverityHigh:
				if t.fixVer != "" {
					fixedHighsInfo = append(fixedHighsInfo, FixedVulInfo{PubTS: t.pubTS})
				}
				highs = append(highs, t.Name)
			case vulnSeverityMedium:
				meds = append(meds, t.Name)
			case vulnSeverityLow:
				lows = append(lows, t.Name)

			}
		}
	}
	return criticals, highs, meds, lows, fixedCriticalsInfo, fixedHighsInfo
}

// ----

type VPFInterface interface {
	GetUpdatedTime() time.Time
	filterOneVulREST(vul *api.RESTVulnerability, domains []string, image string) bool
	FilterVulREST(vuls []*api.RESTVulnerability, idns []api.RESTIDName, showTag string) []*api.RESTVulnerability
	FilterVulTraits(traits []*VulTrait, idns []api.RESTIDName) utils.Set
	FilterVuls(vuls []*share.ScanVulnerability, idns []api.RESTIDName) []*share.ScanVulnerability
}

type vpfEntry struct {
	isNameRegexp   bool
	name           *regexp.Regexp
	isDomainRegexp []bool
	domains        []*regexp.Regexp
	isImageRegexp  []bool
	images         []*regexp.Regexp
}

type vpFilter struct {
	vf      *api.RESTVulnerabilityProfile
	filters []vpfEntry
	updated time.Time
}

func MakeVulnerabilityProfileFilter(vf *api.RESTVulnerabilityProfile) VPFInterface {
	if vf == nil {
		return &vpFilter{}
	}

	vpf := &vpFilter{
		vf:      vf,
		filters: make([]vpfEntry, len(vf.Entries)),
		updated: time.Now(),
	}

	for i, e := range vf.Entries {
		f := &vpf.filters[i]

		if f.isNameRegexp = strings.Contains(e.Name, "*"); f.isNameRegexp {
			// case insensitive
			f.name = regexp.MustCompile("(?i)" + strings.ReplaceAll(e.Name, "*", ".*"))
		}

		f.isDomainRegexp = make([]bool, len(e.Domains))
		f.domains = make([]*regexp.Regexp, len(e.Domains))
		for j, domain := range e.Domains {
			if f.isDomainRegexp[j] = strings.Contains(domain, "*"); f.isDomainRegexp[j] {
				f.domains[j] = regexp.MustCompile(strings.ReplaceAll(domain, "*", ".*"))
			}
		}

		f.isImageRegexp = make([]bool, len(e.Images))
		f.images = make([]*regexp.Regexp, len(e.Images))
		for j, image := range e.Images {
			if f.isImageRegexp[j] = strings.Contains(image, "*"); f.isImageRegexp[j] {
				f.images[j] = regexp.MustCompile(strings.ReplaceAll(image, "*", ".*"))
			}
		}
	}

	return vpf
}

func (vpf vpFilter) GetUpdatedTime() time.Time {
	return vpf.updated
}

func (vpf vpFilter) filterOneVulTrait(vul *VulTrait, domains []string, image string) bool {
	for i, e := range vpf.vf.Entries {
		f := vpf.filters[i]

		if e.Name == api.VulnerabilityNameRecent {
			if uint(time.Since(time.Unix(vul.pubTS, 0)).Hours()/24) >= e.Days {
				continue
			}
		} else if e.Name == api.VulnerabilityNameRecentWithoutFix {
			if vul.fixVer != "" || uint(time.Since(time.Unix(vul.pubTS, 0)).Hours()/24) >= e.Days {
				continue
			}
		} else {
			// case insensitive
			if f.isNameRegexp && !f.name.MatchString(vul.Name) {
				continue
			} else if !f.isNameRegexp && !strings.EqualFold(e.Name, vul.Name) {
				continue
			}
		}

		// if one of domains/images matches move to the next field
		if len(e.Domains) > 0 {
			if len(domains) == 0 {
				continue
			}
			for j, fdomain := range e.Domains {
				if f.isDomainRegexp[j] {
					for _, domain := range domains {
						if f.domains[j].MatchString(domain) {
							goto MATCH_IMAGE
						}
					}
				} else {
					for _, domain := range domains {
						if fdomain == domain {
							goto MATCH_IMAGE
						}
					}
				}
			}
			continue
		}

	MATCH_IMAGE:
		if len(e.Images) > 0 {
			if image == "" {
				continue
			}
			for j, fimage := range e.Images {
				if f.isImageRegexp[j] && f.images[j].MatchString(image) {
					goto MATCH
				} else if !f.isImageRegexp[j] && fimage == image {
					goto MATCH
				}
			}
			continue
		}

	MATCH:
		return true
	}

	return false
}

func (vpf vpFilter) filterOneVulREST(vul *api.RESTVulnerability, domains []string, image string) bool {
	for i, e := range vpf.vf.Entries {
		f := vpf.filters[i]

		if e.Name == api.VulnerabilityNameRecent {
			if uint(time.Since(time.Unix(vul.PublishedTS, 0)).Hours()/24) >= e.Days {
				continue
			}
		} else if e.Name == api.VulnerabilityNameRecentWithoutFix {
			if vul.FixedVersion != "" || uint(time.Since(time.Unix(vul.PublishedTS, 0)).Hours()/24) >= e.Days {
				continue
			}
		} else {
			// case insensitive
			if f.isNameRegexp && !f.name.MatchString(vul.Name) {
				continue
			} else if !f.isNameRegexp && !strings.EqualFold(e.Name, vul.Name) {
				continue
			}
		}

		// if one of domains/images matches move to the next field
		if len(e.Domains) > 0 {
			if len(domains) == 0 {
				continue
			}
			for j, fdomain := range e.Domains {
				if f.isDomainRegexp[j] {
					for _, domain := range domains {
						if f.domains[j].MatchString(domain) {
							goto MATCH_IMAGE
						}
					}
				} else {
					for _, domain := range domains {
						if fdomain == domain {
							goto MATCH_IMAGE
						}
					}
				}
			}
			continue
		}

	MATCH_IMAGE:
		if len(e.Images) > 0 {
			if image == "" {
				continue
			}
			for j, fimage := range e.Images {
				if f.isImageRegexp[j] && f.images[j].MatchString(image) {
					goto MATCH
				} else if !f.isImageRegexp[j] && fimage == image {
					goto MATCH
				}
			}
			continue
		}

	MATCH:
		return true
	}

	return false
}

func (vpf vpFilter) filterOneVul(vul *share.ScanVulnerability, domains []string, image string) bool {
	for i, e := range vpf.vf.Entries {
		f := vpf.filters[i]

		if e.Name == api.VulnerabilityNameRecent {
			pubTS, err := strconv.ParseInt(vul.PublishedDate, 0, 64)
			if err == nil {
				if uint(time.Since(time.Unix(pubTS, 0)).Hours()/24) >= e.Days {
					continue
				}
			}
		} else if e.Name == api.VulnerabilityNameRecentWithoutFix {
			pubTS, err := strconv.ParseInt(vul.PublishedDate, 0, 64)
			if err == nil {
				if vul.FixedVersion != "" || uint(time.Since(time.Unix(pubTS, 0)).Hours()/24) >= e.Days {
					continue
				}
			}
		} else {
			// case insensitive
			if f.isNameRegexp && !f.name.MatchString(vul.Name) {
				continue
			} else if !f.isNameRegexp && !strings.EqualFold(e.Name, vul.Name) {
				continue
			}
		}

		// if one of domains/images matches move to the next field
		if len(e.Domains) > 0 {
			if len(domains) == 0 {
				continue
			}
			for j, fdomain := range e.Domains {
				if f.isDomainRegexp[j] {
					for _, domain := range domains {
						if f.domains[j].MatchString(domain) {
							goto MATCH_IMAGE
						}
					}
				} else {
					for _, domain := range domains {
						if fdomain == domain {
							goto MATCH_IMAGE
						}
					}
				}
			}
			continue
		}

	MATCH_IMAGE:
		if len(e.Images) > 0 {
			if image == "" {
				continue
			}
			for j, fimage := range e.Images {
				if f.isImageRegexp[j] && f.images[j].MatchString(image) {
					goto MATCH
				} else if !f.isImageRegexp[j] && fimage == image {
					goto MATCH
				}
			}
			continue
		}

	MATCH:
		return true
	}

	return false
}

// Use Domains as namespace and DisplayName as image name
func (vpf vpFilter) FilterVulREST(vuls []*api.RESTVulnerability, idns []api.RESTIDName, showTag string) []*api.RESTVulnerability {
	if vpf.vf == nil || len(vpf.vf.Entries) == 0 {
		return vuls
	}

	list := make([]*api.RESTVulnerability, 0, len(vuls))
	for _, v := range vuls {
		skip := false
		if len(idns) == 0 {
			skip = vpf.filterOneVulREST(v, nil, "")
		} else {
			for _, s := range idns {
				if vpf.filterOneVulREST(v, s.Domains, s.DisplayName) {
					skip = true
					break
				}
			}
		}
		if !skip {
			list = append(list, v)
		} else if showTag != "" {
			v.Tags = []string{showTag}
			list = append(list, v)
		}
	}

	return list
}

// This can be used re-filter, so 'filtered' flag of all entries must set.
func (vpf vpFilter) FilterVulTraits(traits []*VulTrait, idns []api.RESTIDName) utils.Set {
	alives := utils.NewSet()

	if vpf.vf == nil || len(vpf.vf.Entries) == 0 {
		for _, t := range traits {
			t.filtered = false
			alives.Add(t.Name)
		}
		return alives
	}

	for _, t := range traits {
		var skip bool
		if len(idns) == 0 {
			skip = vpf.filterOneVulTrait(t, nil, "")
		} else {
			for _, s := range idns {
				if vpf.filterOneVulTrait(t, s.Domains, s.DisplayName) {
					skip = true
					break
				}
			}
		}
		t.filtered = skip
		if !skip {
			alives.Add(t.Name)
		}
	}

	return alives
}

// This is used when grpc struct is returned.
func (vpf vpFilter) FilterVuls(vuls []*share.ScanVulnerability, idns []api.RESTIDName) []*share.ScanVulnerability {
	if vpf.vf == nil || len(vpf.vf.Entries) == 0 {
		return vuls
	}

	list := make([]*share.ScanVulnerability, 0, len(vuls))
	for _, v := range vuls {
		skip := false
		if len(idns) == 0 {
			skip = vpf.filterOneVul(v, nil, "")
		} else {
			for _, s := range idns {
				// DisplayName is image name
				if vpf.filterOneVul(v, s.Domains, s.DisplayName) {
					skip = true
					break
				}
			}
		}
		if !skip {
			list = append(list, v)
		}
	}

	return list
}

func GetCVERecord(cvedb CVELookup, name, dbKey, baseOS string) *api.RESTVulnerability {
	vul := &api.RESTVulnerability{Name: name}
	if cvedb == nil {
		return vul
	}
	baseOS = normalizeBaseOS(baseOS)

	if dbKey != "" {
		if vr, ok := cvedb.Get(dbKey); ok {
			fillVulFields(vr, vul)
		}
	} else {
		key := fmt.Sprintf("%s:%s", baseOS, vul.Name)
		if vr, ok := cvedb.Get(key); ok {
			fillVulFields(vr, vul)
		} else {
			key = fmt.Sprintf("apps:%s", vul.Name)
			if vr, ok := cvedb.Get(key); ok {
				fillVulFields(vr, vul)
			} else {
				if vr, ok := cvedb.Get(vul.Name); ok {
					fillVulFields(vr, vul)
				}
			}
		}
	}

	return vul
}

package scan

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/common"
	nvsysadmission "github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg/admission"
	"github.com/neuvector/neuvector/db"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/httptrace"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
)

type ScanInterface interface {
	// registry
	GetRegistry(name string, acc *access.AccessControl) (*api.RESTRegistry, error)
	GetRegistryState(name string, acc *access.AccessControl) (*share.CLUSRegistryState, error)
	GetRegistrySummary(name string, acc *access.AccessControl) (*api.RESTRegistrySummary, error)
	GetAllRegistrySummary(scope string, acc *access.AccessControl) []*api.RESTRegistrySummary
	GetRegistryImageSummary(name string, vpf scanUtils.VPFInterface, acc *access.AccessControl) []*api.RESTRegistryImageSummary
	GetRegistryVulnerabilities(name string, vpf scanUtils.VPFInterface, showTag string, acc *access.AccessControl) (map[string][]*api.RESTVulnerability, map[string][]api.RESTIDName, error)
	GetRegistryBenches(name string, tagMap map[string][]string, acc *access.AccessControl) (map[string][]*api.RESTBenchItem, map[string][]api.RESTIDName, error)
	GetRegistryImageReport(name, id string, vpf scanUtils.VPFInterface, showTag string, tagMap map[string][]string, acc *access.AccessControl) (*api.RESTScanReport, error)
	GetRegistryLayersReport(name, id string, vpf scanUtils.VPFInterface, showTag string, acc *access.AccessControl) (*api.RESTScanLayersReport, error)
	GetRegistryDebugImages(source string) []*api.RESTRegistryDebugImage
	StartRegistry(name string) error
	StopRegistry(name string) error
	GetFedRegistryCache(getCfg, getNames bool) ([]*share.CLUSRegistryConfig, utils.Set)
	CheckRegistry(name string) bool
	GetRegistryImagesIDs(name string, vpf scanUtils.VPFInterface, showTag string, acc *access.AccessControl) ([]string, error)

	// GetScannedImageSummary(reqImgRegistry utils.Set, reqImgRepo, reqImgTag string, vpf scanUtils.VPFInterface) []*nvsysadmission.ScannedImageSummary
	// RegistryImageStateUpdate(name, id string, sum *share.CLUSRegistryImageSummary, vpf scanUtils.VPFInterface) (utils.Set, []string, []string)
	StoreRepoScanResult(result *share.ScanResult) error
	TestRegistry(ctx context.Context, config *share.CLUSRegistryConfig, tracer httptrace.HTTPTrace) error
}

// --

type imageSummary struct {
	summary  *share.CLUSRegistryImageSummary
	cache    *imageInfoCache
	vulNames utils.Set
	modules  []*share.ScanModule
}

func refreshScanCache(rs *Registry, id string, sum *share.CLUSRegistryImageSummary, c *imageInfoCache, vpf scanUtils.VPFInterface) {
	if vpf != nil && vpf.GetUpdatedTime().After(c.filteredTime) {
		key := share.CLUSRegistryImageDataKey(rs.config.Name, id)
		if report := clusHelper.GetScanReport(key); report != nil {
			var criticals, highs, meds []string
			localVulTraits := scanUtils.ExtractVulnerability(report.Vuls)
			alives := vpf.FilterVulTraits(localVulTraits, images2IDNames(rs, sum))
			criticals, highs, meds, _, c.criticalVulsWithFix, c.highVulsWithFix, c.vulScore, c.vulInfo, c.lowVulInfo = countVuln(report.Vuls, nil, alives)
			c.criticalVuls = len(criticals)
			c.highVuls = len(highs)
			c.medVuls = len(meds)
			c.filteredTime = time.Now()
		}
	}
}

func addScannedImage(rs *Registry, id string, sumMap map[string]*imageSummary, vpf scanUtils.VPFInterface) {
	if sum, ok := rs.summary[id]; ok && sum.Status == api.ScanStatusFinished {
		if c, ok := rs.cache[id]; ok {
			if s, ok := sumMap[id]; !ok || sum.ScannedAt.After(s.summary.ScannedAt) {
				refreshScanCache(rs, id, sum, c, vpf)
				sumMap[id] = &imageSummary{summary: sum, cache: c, vulNames: utils.NewSet()}
				fillImageVulModule(rs, id, sumMap[id], vpf)
			}
		}
	}
}

func getScannedImages(reqImgRegistry utils.Set, reqImgRepo, reqImgTag string, vpf scanUtils.VPFInterface) map[string]*imageSummary {
	sumMap := make(map[string]*imageSummary)

	var ocDomain string // for openshift only, the first portion of the repo
	if idx := strings.Index(reqImgRepo, "/"); idx != -1 {
		ocDomain = reqImgRepo[:idx]
	}

	reqImgRegistrySlice := reqImgRegistry.ToStringSlice()
	for i, r := range reqImgRegistrySlice {
		reqImgRegistrySlice[i] = strings.ToLower(r)
	}

	clusImage := share.CLUSImage{
		Repo: reqImgRepo,
		Tag:  reqImgTag,
	}
	rss := [2]*Registry{repoFedScanRegistry, repoScanRegistry}
	for _, rs := range rss {
		if rs == nil {
			continue
		}
		// 1. check repo scan images, add registry to repo to locate scanner images in registry
		for _, reqRegistry := range reqImgRegistrySlice {
			clusImage := share.CLUSImage{
				Repo: fmt.Sprintf("%s:%s", reqRegistry, reqImgRepo),
				Tag:  reqImgTag,
			}

			rs.stateLock()
			if id, exist := rs.digest2ID[reqImgTag]; exist {
				// if image tag is of sha256: format
				addScannedImage(rs, id, sumMap, vpf)
			} else if id, exist := rs.image2ID[clusImage]; exist {
				addScannedImage(rs, id, sumMap, vpf)
			}
			rs.stateUnlock()
		}

		if len(sumMap) > 0 {
			return sumMap
		}

		// 2. check repo scan images, ignore registry in request. This is to match if it is
		// the local image (without registry) that was scanned
		rs.stateLock()
		if id, exist := rs.image2ID[clusImage]; exist {
			addScannedImage(rs, id, sumMap, vpf)
		}
		rs.stateUnlock()

		if len(sumMap) > 0 {
			return sumMap
		}
	}

	// 3. scan normal registry
	regs := regMapToArray(true, true)

	for _, reqRegistry := range reqImgRegistrySlice {
		for _, rs := range regs {
			// No registry comparison for images in repoScan registry.
			if !strings.Contains(strings.ToLower(rs.config.Registry), reqRegistry) {
				// image in admission control request is in differerent registry from current registry
				continue
			}

			if rs.config.Type == share.RegistryTypeOpenShift {
				clusImage.Domain = ocDomain
			} else {
				clusImage.Domain = ""
			}
			rs.stateLock()
			if id, exist := rs.digest2ID[reqImgTag]; exist {
				// if image tag is of sha256: format
				addScannedImage(rs, id, sumMap, vpf)
			} else if id, exist := rs.image2ID[clusImage]; exist {
				addScannedImage(rs, id, sumMap, vpf)
			}
			rs.stateUnlock()
		}
	}

	return sumMap
}

// Normalize the request if the registry URL is added to the repo field
func FixRegRepoForAdmCtrl(result *share.ScanResult) {
	if result.Registry == "" && result.Repository != "" {
		var proto string
		regRepoTag := result.Repository
		for _, proto = range []string{"http://", "https://"} {
			if strings.HasPrefix(regRepoTag, proto) {
				regRepoTag = regRepoTag[len(proto):]
				break
			}
		}
		if proto == "" {
			proto = "https://"
		}
		if ss := strings.Split(regRepoTag, "/"); len(ss) > 1 {
			// see splitDockerDomain() in https://github.com/docker/distribution/blob/release/2.7/reference/normalize.go
			if !strings.ContainsAny(ss[0], ".:") && ss[0] != "localhost" {
				// there is no registry info in regRepoTag, like "library/centos"
			} else {
				// there is registry info in regRepoTag, like "docker.io/library/centos" or "10.1.127.3:5000/......" or "localhost/........"
				result.Registry = fmt.Sprintf("%s%s/", proto, ss[0])
				result.Repository = strings.Join(ss[1:], "/")
			}
		} else if len(ss) == 1 {
			// there is no registry info in regRepoTag, like "centos". Adm ctrl always prefix library, so keep the behavior same here
			// if the local image is 'centos', then it is scanned as 'centos' but store the result as 'library/centos'
			result.Repository = fmt.Sprintf("library/%s", ss[0])
		}
	}
}

func GetScannedImageSummary(reqImgRegistry utils.Set, reqImgRepo, reqImgTag string, vpf scanUtils.VPFInterface) []*nvsysadmission.ScannedImageSummary {
	log.WithFields(log.Fields{"registry": reqImgRegistry, "repo": reqImgRepo, "tag": reqImgTag}).Debug()

	sumMap := getScannedImages(reqImgRegistry, reqImgRepo, reqImgTag, vpf)
	if len(sumMap) == 0 {
		log.Debug("Scanned image not found")
		summary := &nvsysadmission.ScannedImageSummary{VulNames: utils.NewSet()}
		return []*nvsysadmission.ScannedImageSummary{summary}
	}

	list := make([]*nvsysadmission.ScannedImageSummary, 0)

	for _, s := range sumMap {
		summary := &nvsysadmission.ScannedImageSummary{
			ImageID:             s.summary.ImageID,
			BaseOS:              s.summary.BaseOS,
			Registry:            s.summary.Registry,
			RegName:             s.summary.RegName,
			Digest:              s.summary.Digest,
			Author:              s.summary.Author,
			ScannedAt:           s.summary.ScannedAt,
			Result:              int32(s.summary.Result),
			CriticalVuls:        s.cache.criticalVuls,
			HighVuls:            s.cache.highVuls,
			MedVuls:             s.cache.medVuls,
			CriticalVulsWithFix: s.cache.criticalVulsWithFix,
			HighVulsWithFix:     s.cache.highVulsWithFix,
			VulScore:            s.cache.vulScore,
			VulNames:            utils.NewSet(),
			Scanned:             true,
			Signed:              false, // scanned.Signed, // [2019.Apr] set as false until we can accurately tell it
			RunAsRoot:           s.summary.RunAsRoot,
			EnvVars:             make(map[string]string, len(s.cache.envs)),
			Labels:              make(map[string]string, len(s.cache.labels)),
			SecretsCnt:          len(s.cache.secrets),
			SetIDPermCnt:        len(s.cache.setIDPerm),
			Verifiers:           s.cache.signatureVerifiers,
		}

		summary.VulNames = s.vulNames
		summary.Modules = s.modules

		if s.cache.vulInfo != nil {
			summary.CriticalVulInfo = s.cache.vulInfo[share.VulnSeverityCritical]
			summary.HighVulInfo = s.cache.vulInfo[share.VulnSeverityHigh]
			summary.MediumVulInfo = s.cache.vulInfo[share.VulnSeverityMedium]
		}
		summary.LowVulInfo = s.cache.lowVulInfo
		for _, envVar := range s.cache.envs {
			ss := strings.SplitN(envVar, "=", 2)
			if len(ss) > 0 {
				if len(ss) == 1 {
					summary.EnvVars[ss[0]] = ""
				} else {
					summary.EnvVars[ss[0]] = ss[1]
				}
			}
		}
		for k, v := range s.cache.labels {
			summary.Labels[k] = v
		}
		list = append(list, summary)
	}

	log.WithFields(log.Fields{"images": len(list)}).Debug("Scanned image found")
	return list
}

// cache can be nil !!
func image2RESTSummary(rs *Registry, id string, sum *share.CLUSRegistryImageSummary, cache *imageInfoCache, vpf scanUtils.VPFInterface) *api.RESTRegistryImageSummary {
	s := &api.RESTRegistryImageSummary{
		ImageID: sum.ImageID,
		Digest:  sum.Digest,
		// Signed:    sum.Signed, // [2019.Apr] comment out until we can accurately tell it
		RunAsRoot: sum.RunAsRoot,
		RESTScanBrief: api.RESTScanBrief{
			Status:       sum.Status,
			BaseOS:       sum.BaseOS,
			CVEDBVersion: sum.Version,
		},
	}
	if !sum.ScannedAt.IsZero() {
		s.ScannedTimeStamp = sum.ScannedAt.Unix()
		s.ScannedAt = api.RESTTimeString(sum.ScannedAt)
		s.CreatedAt = api.RESTTimeString(sum.CreatedAt)
		s.Result = scanUtils.ScanErrorToStr(sum.Result)
		s.Size = sum.Size
		s.Author = sum.Author
		if cache != nil {
			refreshScanCache(rs, id, sum, cache, vpf)
			s.CriticalVuls = cache.criticalVuls
			s.HighVuls = cache.highVuls
			s.MedVuls = cache.medVuls
			s.Envs = cache.envs
			s.Labels = cache.labels
			s.Layers = cache.layers
		}
	}
	return s
}

func (m *scanMethod) StoreRepoScanResult(result *share.ScanResult) error {
	smd.scanLog.WithFields(log.Fields{
		"registry": result.Registry, "repo": result.Repository, "tag": result.Tag,
	}).Debug()

	// In repoScan, it's common that the image is scanned before it is pushed to the registry,
	// so no registry URL available. At the time of admission control calls, the requested images
	// always have the registry URL, it should be ignored when looking for the scan results.
	//
	// So, if when the image is scanned there is no registry specified, then the image will be
	// used no matter what the registry is in the admission control webhook call; if the scanned
	// image does have the registry, the registry value in the admission control webhook call
	// need to match.

	rs := repoScanRegistry

	var imgs []share.CLUSImage
	var img share.CLUSImage

	rs.stateLock()
	if sum, ok := rs.summary[result.ImageID]; ok {
		imgs = sum.Images
	} else {
		imgs = make([]share.CLUSImage, 0)
	}
	rs.stateUnlock()

	if result.Registry == "" {
		img = share.CLUSImage{Repo: result.Repository, Tag: result.Tag}
	} else {
		img = share.CLUSImage{Repo: fmt.Sprintf("%s:%s", result.Registry, result.Repository), Tag: result.Tag}
	}

	// Chekc if the image already exists
	for _, img1 := range imgs {
		if img == img1 {
			return nil
		}
	}

	imgs = append(imgs, img)

	sum := &share.CLUSRegistryImageSummary{
		ImageID:   result.ImageID,
		Registry:  result.Registry,
		RegName:   common.RegistryRepoScanName,
		Images:    imgs,
		Digest:    result.Digest,
		ScannedAt: time.Now().UTC(),
		BaseOS:    result.Namespace,
		Version:   result.Version,
		Result:    result.Error,
		Status:    api.ScanStatusFinished,
		Author:    result.Author,
		ScanFlags: share.ScanFlagCVE,
	}
	if c, err := time.Parse(time.RFC3339, result.Created); err == nil {
		sum.CreatedAt = c
	}
	if result.Secrets != nil {
		sum.ScanFlags |= share.ScanFlagFiles
	}
	if result.SignatureInfo != nil {
		sum.Verifiers = result.SignatureInfo.Verifiers
	}
	sum.RunAsRoot, _, _ = scanUtils.ParseImageCmds(result.Cmds)
	rs.summary[result.ImageID] = sum

	report := share.CLUSScanReport{
		ScannedAt:  sum.ScannedAt,
		ScanResult: *result,
	}

	clusHelper.PutRegistryImageSummaryAndReport(common.RegistryRepoScanName, result.ImageID, smd.fedRole, sum, &report)

	if len(rs.summary) > api.ScanPersistImageMax+scanPersistImageExtra {
		rs.cleanupOldImages()
	}

	return nil
}

func (m *scanMethod) GetRegistryState(name string, acc *access.AccessControl) (*share.CLUSRegistryState, error) {
	var rs *Registry
	var ok bool

	if name == common.RegistryRepoScanName {
		rs = repoScanRegistry
	} else if name == common.RegistryFedRepoScanName {
		rs = repoFedScanRegistry
	} else if rs, ok = regMapLookup(name); !ok {
		if !acc.Authorize(&share.CLUSRegistryConfig{Name: name}, nil) {
			return nil, common.ErrObjectAccessDenied
		}
		return nil, common.ErrObjectNotFound
	}

	if !acc.Authorize(rs.config, nil) {
		return nil, common.ErrObjectAccessDenied
	} else {
		return rs.state, nil
	}
}

func images2IDNames(rs *Registry, sum *share.CLUSRegistryImageSummary) []api.RESTIDName {
	idns := make([]api.RESTIDName, len(sum.Images))
	for i, image := range sum.Images {
		idn := api.RESTIDName{
			ID:          sum.ImageID,
			DisplayName: fmt.Sprintf("%s:%s", image.Repo, image.Tag),
		}
		if image.Domain != "" {
			idn.Domains = []string{image.Domain}
		} else if len(rs.config.Domains) != 0 {
			idn.Domains = rs.config.Domains
		} else {
			idn.Domains = rs.config.CreaterDomains
		}

		idns[i] = idn
	}

	return idns
}

func (m *scanMethod) GetRegistryVulnerabilities(name string, vpf scanUtils.VPFInterface, showTag string, acc *access.AccessControl) (map[string][]*api.RESTVulnerability, map[string][]api.RESTIDName, error) {
	var rs *Registry
	var ok bool

	if name == common.RegistryRepoScanName {
		rs = repoScanRegistry
	} else if name == common.RegistryFedRepoScanName {
		rs = repoFedScanRegistry
	} else if rs, ok = regMapLookup(name); !ok {
		return nil, nil, common.ErrObjectNotFound
	}

	rs.stateLock()
	defer rs.stateUnlock()
	if !acc.Authorize(rs.config, nil) {
		return nil, nil, common.ErrObjectAccessDenied
	}

	vmap := make(map[string][]*api.RESTVulnerability)
	nmap := make(map[string][]api.RESTIDName)

	sdb := scanUtils.GetScannerDB()
	if acc.HasGlobalPermissions(share.PERM_REG_SCAN, 0) {
		// To avoid authorize for every image - run faster.
		for id, c := range rs.cache {
			if sum, ok := rs.summary[id]; ok {
				refreshScanCache(rs, id, sum, c, vpf)

				reportVuls, _ := db.GetVulnerability(id)
				localVulTraits := scanUtils.ExtractVulnerability(reportVuls)
				vmap[id] = scanUtils.FillVulTraits(sdb.CVEDB, sum.BaseOS, localVulTraits, showTag, false)
				nmap[id] = images2IDNames(rs, sum)
			}
		}
	} else {
		for id, c := range rs.cache {
			if sum, ok := rs.summary[id]; ok {
				if acc.Authorize(sum, func(s string) share.AccessObject { return rs.config }) {
					refreshScanCache(rs, id, sum, c, vpf)

					reportVuls, _ := db.GetVulnerability(id)
					localVulTraits := scanUtils.ExtractVulnerability(reportVuls)
					vmap[id] = scanUtils.FillVulTraits(sdb.CVEDB, sum.BaseOS, localVulTraits, showTag, false)
					nmap[id] = images2IDNames(rs, sum)
				}
			}
		}
	}

	return vmap, nmap, nil
}

func (m *scanMethod) GetRegistryBenches(name string, tagMap map[string][]string, acc *access.AccessControl) (map[string][]*api.RESTBenchItem, map[string][]api.RESTIDName, error) {
	var rs *Registry
	var ok bool

	if name == common.RegistryRepoScanName {
		rs = repoScanRegistry
	} else if name == common.RegistryFedRepoScanName {
		rs = repoFedScanRegistry
	} else if rs, ok = regMapLookup(name); !ok {
		return nil, nil, common.ErrObjectNotFound
	}

	rs.stateLock()
	defer rs.stateUnlock()
	if !acc.Authorize(rs.config, nil) {
		return nil, nil, common.ErrObjectAccessDenied
	}

	cmap := make(map[string][]*api.RESTBenchItem)
	nmap := make(map[string][]api.RESTIDName)

	if acc.HasGlobalPermissions(share.PERM_REG_SCAN, 0) {
		// To avoid authorize for every image - run faster.
		for id, c := range rs.cache {
			if sum, ok := rs.summary[id]; ok {
				cmap[id] = scanUtils.ImageBench2REST(c.cmds, c.secrets, c.setIDPerm, tagMap)
				nmap[id] = images2IDNames(rs, sum)
			}
		}
	} else {
		for id, c := range rs.cache {
			if sum, ok := rs.summary[id]; ok {
				if acc.Authorize(sum, func(s string) share.AccessObject { return rs.config }) {
					cmap[id] = scanUtils.ImageBench2REST(c.cmds, c.secrets, c.setIDPerm, tagMap)
					nmap[id] = images2IDNames(rs, sum)
				}
			}
		}
	}

	return cmap, nmap, nil
}

func (m *scanMethod) getAllRegistryImageReport(id string, vpf scanUtils.VPFInterface, showTag string, tagMap map[string][]string, acc *access.AccessControl) (*api.RESTScanReport, error) {
	rpt, _ := m.GetRegistryImageReport(common.RegistryRepoScanName, id, vpf, showTag, tagMap, acc)
	if rpt != nil {
		return rpt, nil
	}

	rpt, _ = m.GetRegistryImageReport(common.RegistryFedRepoScanName, id, vpf, showTag, tagMap, acc)
	if rpt != nil {
		return rpt, nil
	}

	regs := regMapToArray(true, true)
	for _, rs := range regs {
		rpt, _ = m.GetRegistryImageReport(rs.config.Name, id, vpf, showTag, tagMap, acc)
		if rpt != nil {
			return rpt, nil
		}
	}

	return nil, common.ErrObjectNotFound
}

func (m *scanMethod) GetRegistryImageReport(name, id string, vpf scanUtils.VPFInterface, showTag string, tagMap map[string][]string, acc *access.AccessControl) (*api.RESTScanReport, error) {
	var rs *Registry
	var ok bool

	if name == common.RegistryAllName {
		return m.getAllRegistryImageReport(id, vpf, showTag, tagMap, acc)
	}

	if name == common.RegistryRepoScanName {
		rs = repoScanRegistry
	} else if name == common.RegistryFedRepoScanName {
		rs = repoFedScanRegistry
	} else if rs, ok = regMapLookup(name); !ok {
		if !acc.Authorize(&share.CLUSRegistryConfig{Name: name}, nil) {
			return nil, common.ErrObjectAccessDenied
		}
		return nil, common.ErrObjectNotFound
	}

	var sum *share.CLUSRegistryImageSummary

	rs.stateLock()
	defer rs.stateUnlock()
	if !acc.Authorize(rs.config, nil) {
		return nil, common.ErrObjectAccessDenied
	} else if sum, ok = rs.summary[id]; !ok {
		return nil, common.ErrObjectNotFound
	} else if !acc.Authorize(sum, func(s string) share.AccessObject { return rs.config }) {
		return nil, common.ErrObjectAccessDenied
	}

	var rrpt api.RESTScanReport

	if vpf != nil {
		if c, ok := rs.cache[id]; ok {
			sdb := scanUtils.GetScannerDB()

			rrpt.Envs = c.envs
			rrpt.Labels = c.labels
			rrpt.Cmds = c.cmds

			refreshScanCache(rs, id, sum, c, vpf)

			reportVuls, reportModules, err := db.GetVulnerabilityModule(id)
			if err != nil {
				return nil, err
			}

			localVulTraits := scanUtils.ExtractVulnerability(reportVuls)
			vpf.FilterVulTraits(localVulTraits, images2IDNames(rs, sum))
			rrpt.Vuls = scanUtils.FillVulTraits(sdb.CVEDB, sum.BaseOS, localVulTraits, showTag, false)

			// The checks are still to be filtered
			rrpt.Checks = scanUtils.ImageBench2REST(c.cmds, c.secrets, c.setIDPerm, tagMap)

			rrpt.Secrets = make([]*api.RESTScanSecret, 0)
			if !rs.config.DisableFiles && c.secrets != nil {
				for _, s := range c.secrets {
					rrpt.Secrets = append(rrpt.Secrets, scanUtils.ScanSecrets2REST(s))
				}
			}

			rrpt.SetIDs = make([]*api.RESTScanSetIdPerm, 0)
			for _, p := range c.setIDPerm {
				rrpt.SetIDs = append(rrpt.SetIDs, scanUtils.ScanSetIdPerm2REST(p))
			}

			rrpt.Modules = make([]*api.RESTScanModule, len(reportModules))
			for i, m := range reportModules {
				rrpt.Modules[i] = scanUtils.ScanModule2REST(m)
			}

			rrpt.SignatureInfo = &api.RESTScanSignatureInfo{
				VerificationTimestamp: c.signatureVerificationTimestamp,
			}

			rrpt.SignatureInfo.Verifiers = make([]string, len(c.signatureVerifiers))
			copy(rrpt.SignatureInfo.Verifiers, c.signatureVerifiers)
		}
	}

	return &rrpt, nil
}

func (m *scanMethod) GetRegistryLayersReport(name, id string, vpf scanUtils.VPFInterface, showTag string, acc *access.AccessControl) (*api.RESTScanLayersReport, error) {
	var rs *Registry
	var ok bool

	if name == common.RegistryRepoScanName {
		rs = repoScanRegistry
	} else if name == common.RegistryFedRepoScanName {
		rs = repoFedScanRegistry
	} else if rs, ok = regMapLookup(name); !ok {
		if !acc.Authorize(&share.CLUSRegistryConfig{Name: name}, nil) {
			return nil, common.ErrObjectAccessDenied
		}
		return nil, common.ErrObjectNotFound
	}

	var sum *share.CLUSRegistryImageSummary

	rs.stateLock()
	defer rs.stateUnlock()
	if !acc.Authorize(rs.config, nil) {
		return nil, common.ErrObjectAccessDenied
	} else if sum, ok = rs.summary[id]; !ok {
		return nil, common.ErrObjectNotFound
	} else if !acc.Authorize(sum, func(s string) share.AccessObject { return rs.config }) {
		return nil, common.ErrObjectAccessDenied
	}

	key := share.CLUSRegistryImageDataKey(name, id)
	if report := clusHelper.GetScanReport(key); report == nil {
		return nil, common.ErrObjectNotFound
	} else {
		sdb := scanUtils.GetScannerDB()
		idns := images2IDNames(rs, sum)

		layers := make([]*api.RESTScanLayer, len(report.Layers))
		for j, layer := range report.Layers {
			// Because cache doesn't save vul. trait of layers, we have to filtered them every time.
			rvuls := make([]*api.RESTVulnerability, len(layer.Vuls))
			for i, vul := range layer.Vuls {
				rvuls[i] = scanUtils.ScanVul2REST(sdb.CVEDB, sum.BaseOS, vul)
			}
			rvuls = vpf.FilterVulREST(rvuls, idns, showTag)

			// we don't return secret in the report
			// var rsecrets []*api.RESTScanSecret
			// if !rs.config.DisableFiles && layer.Secrets != nil {
			// 	rsecrets = make([]*api.RESTScanSecret, 0)
			// 	for _, s := range layer.Secrets.Logs {
			// 		rsecrets = append(rsecrets, scanUtils.ScanSecrets2REST(s))
			// 	}
			// }
			layers[j] = &api.RESTScanLayer{Digest: layer.Digest, Cmds: layer.Cmds, Vuls: rvuls /*Secrets: rsecrets,*/, Size: layer.Size}
		}
		return &api.RESTScanLayersReport{Layers: layers}, nil
	}
}

func (m *scanMethod) GetRegistryImageSummary(name string, vpf scanUtils.VPFInterface, acc *access.AccessControl) []*api.RESTRegistryImageSummary {
	list := make([]*api.RESTRegistryImageSummary, 0)

	var rs *Registry
	var ok bool

	if name == common.RegistryRepoScanName {
		rs = repoScanRegistry
	} else if name == common.RegistryFedRepoScanName {
		rs = repoFedScanRegistry
	} else if rs, ok = regMapLookup(name); !ok {
		return list
	}

	rs.stateLock()
	defer rs.stateUnlock()
	if !acc.Authorize(rs.config, nil) {
		return list
	} else {
		for id, sum := range rs.summary {
			if !acc.Authorize(sum, func(s string) share.AccessObject { return rs.config }) {
				continue
			}

			cache := rs.cache[id]
			rsum := image2RESTSummary(rs, id, sum, cache, vpf)
			for _, image := range sum.Images {
				s := *rsum
				if image.Domain != "" {
					s.Domain = image.Domain
				} else if domains, _ := rs.config.GetDomain(nil); len(domains) != 0 && domains[0] != share.HiddenFedDomain {
					s.Domain = domains[0]
				}
				s.Repository = image.Repo
				s.Tag = image.Tag
				list = append(list, &s)
			}
		}
		return list
	}
}

func (m *scanMethod) GetRegistry(name string, acc *access.AccessControl) (*api.RESTRegistry, error) {
	if rs, ok := regMapLookup(name); !ok {
		if !acc.Authorize(&share.CLUSRegistryConfig{Name: name}, nil) {
			return nil, common.ErrObjectAccessDenied
		}
		return nil, common.ErrObjectNotFound
	} else if !acc.Authorize(rs.config, nil) {
		return nil, common.ErrObjectAccessDenied
	} else {
		return rs.getConfig(acc), nil
	}
}

func (m *scanMethod) GetRegistrySummary(name string, acc *access.AccessControl) (*api.RESTRegistrySummary, error) {
	rs, ok := regMapLookup(name)

	if !ok {
		if !acc.Authorize(&share.CLUSRegistryConfig{Name: name}, nil) {
			return nil, common.ErrObjectAccessDenied
		}
		return nil, common.ErrObjectNotFound
	} else if !acc.Authorize(rs.config, nil) {
		return nil, common.ErrObjectAccessDenied
	} else {
		return rs.getConfigSummary(acc), nil
	}
}

func (m *scanMethod) GetAllRegistrySummary(scope string, acc *access.AccessControl) []*api.RESTRegistrySummary {
	var getLocal, getFed bool

	if scope == share.ScopeLocal {
		getLocal = true
	} else if scope == share.ScopeFed {
		getFed = true
	} else if scope == share.ScopeAll {
		getLocal = true
		getFed = true
	} else {
		return nil
	}

	regs := regMapToArray(getLocal, getFed)

	list := make([]*api.RESTRegistrySummary, 0)
	for _, rs := range regs {
		if !acc.Authorize(rs.config, nil) {
			continue
		}

		list = append(list, rs.getConfigSummary(acc))
	}

	return list
}

func (m *scanMethod) GetFedRegistryCache(getCfg, getNames bool) ([]*share.CLUSRegistryConfig, utils.Set) {
	regReadLock()
	defer regReadUnlock()

	var list []*share.CLUSRegistryConfig
	var names utils.Set

	if getCfg {
		regs := regMapToArray(false, true)

		list = make([]*share.CLUSRegistryConfig, 0, len(regs))

		for _, rs := range regs {
			cfg := *rs.config
			for _, p := range []*string{&cfg.Username, &cfg.Password, &cfg.AuthToken, &cfg.GitlabApiUrl, &cfg.GitlabPrivateToken, &cfg.IBMCloudAccount, &cfg.IBMCloudTokenURL} {
				if *p != "" {
					*p = "****"
				}
			}
			cfg.Domains = nil
			cfg.CreaterDomains = nil
			cfg.ParsedFilters = nil
			if rs.config.AwsKey != nil {
				cfg.AwsKey = &share.CLUSAWSAccountKey{
					ID:              "****",
					AccessKeyID:     "****",
					SecretAccessKey: "****",
					Region:          rs.config.AwsKey.Region,
				}
			}
			cfg.GcrKey = nil
			cfg.CfgType = share.FederalCfg
			list = append(list, &cfg)
		}
	}
	if getNames {
		names = utils.NewSet()
		for _, rs := range regMap {
			if strings.HasPrefix(rs.config.Name, api.FederalGroupPrefix) {
				names.Add(rs.config.Name)
			}
		}
	}

	return list, names
}

func (m *scanMethod) CheckRegistry(name string) bool {
	regReadLock()
	defer regReadUnlock()

	_, ok := regMap[name]
	return ok
}

func (m *scanMethod) StartRegistry(name string) error {
	rs, ok := regMapLookup(name)
	if !ok {
		return common.ErrObjectNotFound
	}

	rs.stateLock()
	defer rs.stateUnlock()
	if rs.state.Status != api.RegistryStatusScanning {
		// stopScan() will be called
		state := &share.CLUSRegistryState{Status: api.RegistryStatusScanning, StartedAt: time.Now().Unix()}
		if err := clusHelper.PutRegistryState(rs.config.Name, state); err != nil {
			return err
		}
	}
	return nil
}

func (m *scanMethod) StopRegistry(name string) error {
	rs, ok := regMapLookup(name)
	if !ok {
		return common.ErrObjectNotFound
	}

	rs.stateLock()
	defer rs.stateUnlock()
	if rs.state.Status == api.RegistryStatusScanning {
		// stopScan() will be called
		state := &share.CLUSRegistryState{Status: api.RegistryStatusIdle, ErrMsg: rs.state.ErrMsg}
		if err := clusHelper.PutRegistryState(rs.config.Name, state); err != nil {
			return err
		}
	}
	return nil
}

func (m *scanMethod) TestRegistry(ctx context.Context, config *share.CLUSRegistryConfig, tracer httptrace.HTTPTrace) error {
	// Get the password because it is obfuscated when sending back to UI
	if config.Username != "" && config.Password == "" && config.Name != "" {
		if rs, ok := regMapLookup(config.Name); ok && rs.config != nil {
			config.Password = rs.config.Password
		}
	}

	rs := newRegistry(config)
	rs.driver.SetTracer(tracer)

	rs.driver.GetTracer().SetPhase("Test registry connection")
	err, _ := rs.driver.Login(rs.config)
	if err != nil {
		rs.driver.GetTracer().GotError(fmt.Sprintf("Test registry connection failed: %s", err.Error()))
		return err
	}

	sctx := &scanContext{ctx: ctx}
	imageMap, _, err := rs.getScanImages(sctx, rs.driver, true)
	if err == context.Canceled {
		rs.driver.GetTracer().GotError("Test registry canceled")
		return err
	}

	// Sort the image list
	list := make([]*share.CLUSImage, 0)
	for _, s := range imageMap {
		for i := range s.Iter() {
			img := i.(share.CLUSImage)
			// url in order to scan the individual image
			if img.RegMod == "" {
				img.RegMod = config.Registry
			}
			if config.Type == share.RegistryTypeJFrog && config.JfrogMode == share.JFrogModeSubdomain {
				if slash := strings.Index(img.Repo, "/"); slash >= 0 {
					img.Repo = img.Repo[slash+1:]
				}
			}
			list = append(list, &img)
		}
	}

	sort.Slice(list, func(s, t int) bool {
		if list[s].RegMod < list[t].RegMod {
			return true
		} else if list[s].RegMod > list[t].RegMod {
			return false
		} else if list[s].Repo < list[t].Repo {
			return true
		} else if list[s].Repo > list[t].Repo {
			return false
		} else if list[s].Tag == "latest" {
			return true
		} else if list[t].Tag == "latest" {
			return false
		} else if list[s].Tag > list[t].Tag {
			// tag from newer to older
			return true
		} else {
			return false
		}
	})

	var comment string
	for _, img := range list {
		comment = fmt.Sprintf("%sRegistry: %s, repository: %s, tag: %s\n", comment, img.RegMod, img.Repo, img.Tag)
	}
	tracer.AddComment(api.HTTPTestStepImage, comment)

	if len(list) > 1 {
		tracer.SetPhase(fmt.Sprintf("Discovered %d image", len(list)))
	} else {
		tracer.SetPhase(fmt.Sprintf("Discovered %d images", len(list)))
	}

	return nil
}

func (m *scanMethod) GetRegistryImagesIDs(name string, vpf scanUtils.VPFInterface, showTag string, acc *access.AccessControl) ([]string, error) {
	var rs *Registry
	var ok bool

	if name == common.RegistryRepoScanName {
		rs = repoScanRegistry
	} else if name == common.RegistryFedRepoScanName {
		rs = repoFedScanRegistry
	} else if rs, ok = regMapLookup(name); !ok {
		return nil, common.ErrObjectNotFound
	}

	rs.stateLock()
	defer rs.stateUnlock()
	if !acc.Authorize(rs.config, nil) {
		return nil, common.ErrObjectAccessDenied
	}

	allowed := make([]string, 0)

	if acc.HasGlobalPermissions(share.PERM_REG_SCAN, 0) {
		// To avoid authorize for every image - run faster.
		for id := range rs.cache {
			if _, ok := rs.summary[id]; ok {
				allowed = append(allowed, id)
			}
		}
	} else {
		for id := range rs.cache {
			if sum, ok := rs.summary[id]; ok {
				if acc.Authorize(sum, func(s string) share.AccessObject { return rs.config }) {
					allowed = append(allowed, id)
				}
			}
		}
	}

	return allowed, nil
}

func fillImageVulModule(rs *Registry, id string, image *imageSummary, vpf scanUtils.VPFInterface) error {
	vuls, modules, err := db.GetVulnerabilityModule(id)
	if err != nil {
		return err
	}

	image.modules = modules
	localVulTraits := scanUtils.ExtractVulnerability(vuls)
	if sum, ok := rs.summary[id]; ok && sum.Status == api.ScanStatusFinished {
		vpf.FilterVulTraits(localVulTraits, images2IDNames(rs, sum))
		for _, v := range localVulTraits {
			if !v.IsFiltered() {
				image.vulNames.Add(v.Name)
			}
		}
	}
	return nil
}

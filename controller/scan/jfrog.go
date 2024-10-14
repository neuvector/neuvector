package scan

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/common"
	"github.com/neuvector/neuvector/controller/rpc"
	"github.com/neuvector/neuvector/share"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/scan/registry"
	"github.com/neuvector/neuvector/share/utils"
)

var jfrogRepoRegexp = regexp.MustCompile(`<a href="([a-zA-Z0-9\-\._]+)\/*">([a-zA-Z0-9\-\._]+)\/*</a>`)

type jfrogRepo struct {
	url  string
	repo string
}

type jfrogDir struct {
	Key         string `json:"key"`
	Description string `json:"description"`
	DirType     string `json:"type"`
	URL         string `json:"url"`
	PackageType string `json:"packageType"`
}

type jfrog struct {
	base
	mode         string
	aql          bool
	subdomainURL map[string]string
	isSubdomain  bool
}

type aqlFolder struct {
	Repo string `json:"repo"`
	Path string `json:"path"`
	Name string `json:"name"`
}

// type aqlRange struct {
// 	Start int `json:"start_pos"`
// 	End   int `json:"end_post"`
// 	Total int `json:"total"`
// }

type aqlFolderResult struct {
	Folders []aqlFolder `json:"results"`
	// Range   aqlRange    `json:"range"`
}

func (r *jfrog) Login(cfg *share.CLUSRegistryConfig) (error, string) {
	r.mode = cfg.JfrogMode
	if r.mode == share.JFrogModeSubdomain {
		r.subdomainURL = make(map[string]string)
	}

	r.newRegClient(cfg.Registry, cfg.Username, cfg.Password)
	r.rc.Alive()
	return nil, ""
}

func (r *jfrog) getSubdomainRepoList(jdirs []jfrogDir, org, name string, limit int) ([]*share.CLUSImage, error) {
	repos := make([]*share.CLUSImage, 0)
	ur, err := url.Parse(r.base.regURL)
	if err != nil {
		return nil, err
	}

	// NOTE: in subdomain mode, the filter is either * or to start with subdomain name
	whichURL := -1
	myRC := r.rc
	defer func() { r.rc = myRC }()

	for _, dir := range jdirs {
		if dir.PackageType != "" && dir.PackageType != "Docker" && dir.PackageType != "docker" {
			continue
		}

		if org != "" && org != dir.Key {
			continue
		}

		var url1, url2 string
		if ur.Port() != "" {
			url1 = fmt.Sprintf("%s://%s:%s/artifactory/api/docker/%s/", ur.Scheme, ur.Hostname(), ur.Port(), dir.Key)
			url2 = fmt.Sprintf("%s://%s.%s:%s/", ur.Scheme, dir.Key, ur.Hostname(), ur.Port())
		} else {
			url1 = fmt.Sprintf("%s://%s/artifactory/api/docker/%s/", ur.Scheme, ur.Hostname(), dir.Key)
			url2 = fmt.Sprintf("%s://%s.%s/", ur.Scheme, dir.Key, ur.Hostname())
		}
		for i, newURL := range []string{url1, url2} {
			if whichURL != -1 && whichURL != i {
				continue
			}

			smd.scanLog.WithFields(log.Fields{
				"org": org, "subdomain": dir.Key, "type": dir.DirType, "url": dir.URL, "registry": newURL,
			}).Debug("Get repo list ...")

			r.rc = scanUtils.NewRegClient(newURL, "", r.base.username, r.base.password, r.base.proxy, r.tracer)
			if rps, err := r.base.GetRepoList(org, name, limit); err == nil {
				if !strings.Contains(name, "*") {
					// although repo has no wildcard, we need wait until here so we have the correct subdomain URL
					r.subdomainURL[dir.Key] = newURL
					return []*share.CLUSImage{{
						RegMod: newURL, Repo: fmt.Sprintf("%s/%s", org, name),
					}}, nil
				}

				for _, repo := range rps {
					repo.RegMod = newURL
					repo.Repo = dir.Key + "/" + repo.Repo
					repos = append(repos, repo)
				}

				r.subdomainURL[dir.Key] = newURL
				whichURL = i
				smd.scanLog.WithFields(log.Fields{"repositories": len(rps)}).Debug()
			} else {
				smd.scanLog.Debug("Get subdomain repository fail")
			}
		}
	}
	return repos, nil
}

func (r *jfrog) GetRepoList(org, name string, limit int) ([]*share.CLUSImage, error) {
	smd.scanLog.WithFields(log.Fields{"mode": r.mode, "registry": r.base.regURL}).Debug("")
	if r.mode == share.JFrogModePort {
		return r.base.GetRepoList(org, name, limit)
	}

	jdirs, err := r.getJFrogDirUrl()
	if err != nil {
		return nil, err
	} else if len(jdirs) == 0 {
		return r.base.GetRepoList(org, name, limit)
	}

	repos := make([]*share.CLUSImage, 0)
	if r.mode == share.JFrogModeSubdomain {
		if !r.isSubdomain {
			// we cannot tell the difference between the host and subdomain url
			// a trick here to get the catalog of subdomain. host will fail, subdomain success
			if repos, err := r.rc.Repositories(); err == nil {
				list := make([]*share.CLUSImage, len(repos))
				for i, repo := range repos {
					list[i] = &share.CLUSImage{Repo: repo}
				}
				return list, nil
			} else {
				r.isSubdomain = true
				return r.getSubdomainRepoList(jdirs, org, name, limit)
			}
		} else {
			return r.getSubdomainRepoList(jdirs, org, name, limit)
		}
	}

	if !strings.Contains(name, "*") {
		if org == "" {
			return []*share.CLUSImage{{Repo: name}}, nil
		} else {
			return []*share.CLUSImage{{Repo: fmt.Sprintf("%s/%s", org, name)}}, nil
		}
	}
	dirs := make([]jfrogRepo, 0)
	for _, jdir := range jdirs {
		if org == "" || jdir.Key == org {
			dirs = append(dirs, jfrogRepo{jdir.URL, jdir.Key})
		}
	}
	for len(dirs) > 0 {
		var cdir jfrogRepo
		cdir, dirs = dirs[0], dirs[1:]
		newRepos, err := r.getJFrogDirRepos(cdir.url, cdir.repo)
		if err != nil {
			continue
		}
		for _, rp := range newRepos {
			if isDir, err := r.isJFrogDir(rp.url); err == nil {
				if isDir {
					dirs = append(dirs, rp)
				} else {
					repos = append(repos, &share.CLUSImage{Repo: strings.TrimPrefix(rp.repo, "/")})
				}
			}
		}
	}

	return repos, nil
}

func getSubdomainFromRepo(repo string) (string, string) {
	if a := strings.Index(repo, "/"); a > 0 {
		return repo[:a], repo[a+1:]
	}
	return "", ""
}

func (r *jfrog) GetTagList(domain, repo, tag string) ([]string, error) {
	smd.scanLog.Debug()

	rc := r.rc
	if r.mode == share.JFrogModeSubdomain && r.isSubdomain {
		sub, subRepo := getSubdomainFromRepo(repo)
		if url, ok := r.subdomainURL[sub]; ok {
			if r.regURL != url {
				rc = scanUtils.NewRegClient(url, "", r.base.username, r.base.password, r.base.proxy, r.tracer)
			}
		} else {
			smd.scanLog.WithFields(log.Fields{"subdomain": sub}).Error("connot find the subdomain")
			return nil, fmt.Errorf("cannot find subdomain from repository, subdomain=%s", sub)
		}
		repo = subRepo
	}
	return rc.Tags(repo)
}

func (r *jfrog) GetAllImages() (map[share.CLUSImage][]string, error) {
	smd.scanLog.Debug()

	if r.mode != share.JFrogModeSubdomain || !r.aql {
		return nil, common.ErrUnsupported
	}

	r.isSubdomain = true

	aqlUrl := r.url("artifactory/api/search/aql")
	aql := `items.find({"repo":{"$match":"*"},"type":"folder"}).include("repo","path","name").sort({"$desc":["repo","path","name"]})`

	var resp *http.Response
	var redirs int
	for {
		req, err := http.NewRequest("POST", aqlUrl, strings.NewReader(aql))
		if err != nil {
			return nil, err
		}

		req.Header.Set("Content-Type", "text/plain")

		resp, err = r.rc.Client.Do(req)
		if err != nil {
			smd.scanLog.WithFields(log.Fields{"error": err}).Error("Failed to send aql query")
			return nil, err
		}
		defer resp.Body.Close()

		// redirect once at most
		if resp.StatusCode/100 == 3 && redirs == 0 {
			if u := resp.Header.Get("Location"); u != "" {
				aqlUrl = u
				redirs++
			} else {
				break
			}
		} else {
			break
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		smd.scanLog.WithFields(log.Fields{"error": err}).Error("Failed to read aql query result")
		return nil, err
	}

	var result aqlFolderResult
	err = json.Unmarshal(body, &result)
	if err != nil {
		smd.scanLog.WithFields(log.Fields{"error": err}).Error("Failed to unmarshal aql query result")
		return nil, err
	}

	// remove path-only items, because the folders are sorted in descending order, we check if the later item's
	// repo/path/name is an earlier item's repo/path
	var path, full string
	var curRepo *share.CLUSImage
	images := make(map[share.CLUSImage][]string, 0)
	folders := utils.NewSet()
	for _, f := range result.Folders {
		if f.Path == "." {
			continue
		} else {
			full = fmt.Sprintf("%s/%s/%s", f.Repo, f.Path, f.Name)
		}
		if folders.Contains(full) {
			continue
		}

		// Add
		repo := fmt.Sprintf("%s/%s", f.Repo, f.Path)
		if curRepo != nil && curRepo.Repo == repo {
			images[*curRepo] = append(images[*curRepo], f.Name)
		} else {
			url := fmt.Sprintf("%sartifactory/api/docker/%s/", r.base.regURL, f.Repo)
			curRepo = &share.CLUSImage{RegMod: url, Repo: repo}
			images[*curRepo] = []string{f.Name}
			r.subdomainURL[f.Repo] = url
		}

		path = fmt.Sprintf("%s/%s", f.Repo, f.Path)
		folders.Add(path)
	}

	return images, nil
}

func (r *jfrog) GetImageMeta(ctx context.Context, domain, repo, tag string) (*scanUtils.ImageInfo, share.ScanErrorCode) {
	rc := r.rc
	if r.mode == share.JFrogModeSubdomain && r.isSubdomain {
		sub, subRepo := getSubdomainFromRepo(repo)
		if url, ok := r.subdomainURL[sub]; ok {
			if r.regURL != url {
				rc = scanUtils.NewRegClient(url, "", r.base.username, r.base.password, r.base.proxy, r.tracer)
			}
		} else {
			smd.scanLog.WithFields(log.Fields{"subdomain": sub}).Error("connot find the subdomain")
		}
		repo = subRepo
	}
	rinfo, errCode := rc.GetImageInfo(ctx, repo, tag, registry.ManifestRequest_Default)
	return rinfo, errCode
}

func (r *jfrog) ScanImage(scanner string, ctx context.Context, id, digest, repo, tag string, scanTypesRequired share.ScanTypeMap) *share.ScanResult {
	newURL := r.regURL
	if r.mode == share.JFrogModeSubdomain && r.isSubdomain {
		sub, subRepo := getSubdomainFromRepo(repo)
		if ur, ok := r.subdomainURL[sub]; ok {
			newURL = ur
		} else {
			smd.scanLog.WithFields(log.Fields{"subdomain": sub}).Error("connot find the subdomain")
		}
		repo = subRepo
	}
	req := &share.ScanImageRequest{
		Registry:           newURL,
		Username:           r.username,
		Password:           r.password,
		Repository:         repo,
		Tag:                tag,
		Proxy:              r.proxy,
		ScanLayers:         r.scanLayers,
		ScanSecrets:        r.scanSecrets,
		ScanTypesRequested: &scanTypesRequired,
	}
	result, err := rpc.ScanImage(scanner, ctx, req)
	if result == nil {
		// rpc request not made
		smd.scanLog.WithFields(log.Fields{"error": err}).Error()
		result = &share.ScanResult{Error: share.ScanErrorCode_ScanErrNetwork}
	} else if err != nil {
		smd.scanLog.WithFields(log.Fields{"error": err}).Error()
	}
	return result
}

func (r *jfrog) getJFrogDirUrl() ([]jfrogDir, error) {
	repoUrl := r.url("artifactory/api/repositories")
	smd.scanLog.WithFields(log.Fields{"url": repoUrl}).Debug()

	resp, err := r.rc.Client.Get(repoUrl)
	if err != nil {
		smd.scanLog.WithFields(log.Fields{"error": err}).Error("Failed to get repo dir")
		return nil, err
	}
	defer resp.Body.Close()

	var jfrogDirs []jfrogDir
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		smd.scanLog.WithFields(log.Fields{"error": err}).Error("Failed to read repo dir")
		return nil, err
	}

	err = json.Unmarshal(data, &jfrogDirs)
	if err != nil {
		smd.scanLog.WithFields(log.Fields{"error": err}).Error("Failed to unmarshal repo dir")
		return nil, err
	}

	smd.scanLog.WithFields(log.Fields{"dir-count": len(jfrogDirs)}).Debug()
	return jfrogDirs, nil
}

func (r *jfrog) getJFrogDirRepos(repoUrl, dir string) ([]jfrogRepo, error) {
	resp, err := r.rc.Client.Get(repoUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	repos := make([]jfrogRepo, 0)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()

		match := jfrogRepoRegexp.FindAllStringSubmatch(line, 1)
		if len(match) > 0 {
			s := match[0]
			if len(s) < 2 || s[1] != s[2] {
				continue
			}
			if s[1] != ".." {
				repos = append(repos, jfrogRepo{repoUrl + "/" + s[1], dir + "/" + s[1]})
			}
		}
	}
	return repos, nil
}

func (r *jfrog) isJFrogDir(repoUrl string) (bool, error) {
	resp, err := r.rc.Client.Get(repoUrl)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	repos := make([]string, 0)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()

		match := jfrogRepoRegexp.FindAllStringSubmatch(line, 1)
		if len(match) > 0 {
			s := match[0]
			if len(s) < 2 || s[1] != s[2] {
				continue
			}

			if s[1] == ".." {
				continue
			}
			// suppose no repo name as latest
			if s[1] == "latest" {
				return false, nil
			}
			if isTag, err := r.isJFrogTag(repoUrl + "/" + s[1]); err == nil && isTag {
				return false, nil
			}
			repos = append(repos, s[1])
		}
	}
	if len(repos) > 0 {
		return true, nil
	} else {
		return false, fmt.Errorf("Empty directory")
	}
}

func (r *jfrog) isJFrogTag(repoUrl string) (bool, error) {
	resp, err := r.rc.Client.Get(repoUrl)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()

		match := jfrogRepoRegexp.FindAllStringSubmatch(line, 1)
		if len(match) > 0 {
			s := match[0]
			if len(s) < 2 || s[1] != s[2] {
				continue
			}
			if s[1] == "manifest.json" {
				return true, nil
			}
		} else {
			continue
		}
	}
	return false, nil
}

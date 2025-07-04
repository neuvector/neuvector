package scan

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
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
	mode              string
	aql               bool
	subdomainURL      map[string]string
	subdomainInRegURL string
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

	if err := r.newRegClient(cfg.Registry, cfg.Username, cfg.Password); err != nil {
		return err, err.Error()
	}

	if _, err := r.rc.Alive(); err != nil {
		return err, err.Error()
	}
	return nil, ""
}

func (r *jfrog) getSubdomainRepoList(jdirs []jfrogDir, org, name string, limit int) ([]*share.CLUSImage, error) {
	repos := make([]*share.CLUSImage, 0)
	ur, err := url.Parse(r.base.regURL)
	if err != nil {
		return nil, err
	}

	// NOTE: in subdomain mode,
	// 1. if "{subdomain}." is not the prefix of registry url, the filter either contains "*" or must start with "{subdomain}/"
	// 2. if "{subdomain}." is the prefix of registry url, the filter either contains "*", or can start with "{subdomain}/" or not
	whichURL := -1
	myRC := r.rc
	defer func() { r.rc = myRC }()

	for _, dir := range jdirs {
		if dir.PackageType != "" && strings.ToLower(dir.PackageType) != "docker" {
			continue
		}

		if r.subdomainInRegURL != "" {
			if r.subdomainInRegURL != dir.Key {
				continue
			}
		} else {
			if org != "" && org != dir.Key {
				continue
			}
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
				"org": org, "name": name, "subdomain": dir.Key, "type": dir.DirType, "url": dir.URL, "registry": newURL,
			}).Debug("Get repo list ...")

			r.rc = scanUtils.NewRegClient(newURL, "", r.base.username, r.base.password, r.base.proxy, r.tracer)
			if rps, err := r.base.GetRepoList(org, name, limit); err == nil {
				if !strings.Contains(name, "*") {
					if len(rps) == 0 {
						return nil, nil
					}
					// although repo has no wildcard, we need wait until here so we have the correct subdomain URL
					r.subdomainURL[dir.Key] = newURL
					rps[0].RegMod = newURL
					if r.subdomainInRegURL == "" && org == "" {
						// when subdomain value is not the prefix in registry url, repo(no wildcard) must have "{subdomain}/" as prefix
						rps[0].Repo = fmt.Sprintf("%s/%s", dir.Key, name)
					}
					return []*share.CLUSImage{rps[0]}, nil
				}

				for _, repo := range rps {
					repo.RegMod = newURL
					if r.subdomainInRegURL == "" {
						// when subdomain value is not the prefix in registry url, repo(no wildcard) must have "{subdomain}/" as prefix
						repo.Repo = dir.Key + "/" + repo.Repo
					}
					repos = append(repos, repo)
				}

				r.subdomainURL[dir.Key] = newURL
				whichURL = i
				smd.scanLog.WithFields(log.Fields{"repositories": len(rps)}).Debug()
			} else {
				smd.scanLog.WithFields(log.Fields{"newURL": newURL}).Debug("Get subdomain repository fail")
			}
		}
	}
	return repos, nil
}

func (r *jfrog) GetRepoList(org, name string, limit int) ([]*share.CLUSImage, error) {
	smd.scanLog.WithFields(log.Fields{"mode": r.mode, "registry": r.base.regURL}).Debug()
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
		if r.subdomainInRegURL == "" {
			// we cannot tell the difference between the host and subdomain url
			// a trick here to get the catalog of subdomain. host will fail, subdomain success
			if _, err := r.rc.Repositories(); err == nil {
				// when subdomain value is the prefix in registry url, like http://{subdomain}.{hostname-FQDN}/,
				// registry filter could contain subdomain as prefix or not
				r.subdomainInRegURL = getSubdomainFromRegURL(r.base.regURL)
				repoPrefixToRevert := ""
				if r.subdomainInRegURL != "" && org != "" && org != r.subdomainInRegURL {
					// in 5.4.4(-), if registry filter is not "*", it must have prefix "{subdomain}/"
					// so we need to make sure filter has prefix "{subdomain}/" before calling r.getSubdomainRepoList()
					name = fmt.Sprintf("%s/%s", org, name)
					repoPrefixToRevert = fmt.Sprintf("%s/", r.subdomainInRegURL)
					org = r.subdomainInRegURL
				}
				rps, err := r.getSubdomainRepoList(jdirs, org, name, limit)
				if repoPrefixToRevert != "" {
					for _, repo := range rps {
						repo.Repo = strings.TrimPrefix(repo.Repo, repoPrefixToRevert)
					}
				} else if r.subdomainInRegURL != "" && org != "" && org == r.subdomainInRegURL {
					// if registry filter has non-empty org(from filter) that is equal to "{subdomain}",
					// we need to make sure image.repo contains the prefix "{subdomain}/" as that the image is not filtered out later
					for _, repo := range rps {
						prefix := org + "/"
						if !strings.HasPrefix(repo.Repo, prefix) {
							repo.Repo = prefix + repo.Repo
						}
					}
				}
				return rps, err
			} else {
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

func getSubdomainFromRegURL(regURL string) string {
	parsedURL, err := url.Parse(regURL)
	if err != nil {
		return ""
	}
	hostname := parsedURL.Hostname()
	if ipAddr := net.ParseIP(hostname); ipAddr == nil {
		if a := strings.Index(hostname, "."); a > 0 {
			return hostname[:a]
		}
	}
	return ""
}

func getSubdomainFromRepo(repo string) (string, string) {
	if a := strings.Index(repo, "/"); a > 0 {
		return repo[:a], repo[a+1:]
	}
	return "", ""
}

// GetArtifactoryTags is designed to work with a new API endpoint provided by JFrog.
func (r *jfrog) GetArtifactoryTags(repositoryStr string, rc *scanUtils.RegClient) ([]string, error) {
	var key string
	var repository string

	tags := make([]string, 0)
	if r.mode == share.JFrogModeSubdomain {
		key = r.subdomainInRegURL
		repository = repositoryStr
		if r.subdomainInRegURL == "" {
			found := false
			key, repository, found = strings.Cut(repositoryStr, "/")
			if !found {
				return tags, fmt.Errorf("invalid repository format: %v", repositoryStr)
			}
		} else {
			if sub, subRepo := getSubdomainFromRepo(repositoryStr); sub == r.subdomainInRegURL {
				repository = subRepo
			}
		}
	} else {
		var found bool
		key, repository, found = strings.Cut(repositoryStr, "/")
		if !found {
			return tags, fmt.Errorf("invalid repository format: %v", repositoryStr)
		}
	}

	url, err := r.url("/artifactory/api/docker/%s/v2/%s/tags/list", key, repository)
	if err != nil {
		return nil, err
	}
	return rc.FetchTagsPaginated(url, repositoryStr)
}

func (r *jfrog) getSubdomainUrlFromRepo(repo string) (string, string, error) {
	smd.scanLog.Debug()

	if r.mode != share.JFrogModeSubdomain {
		return "", "", common.ErrUnsupported
	}

	subdomain, subrepo := getSubdomainFromRepo(repo)
	if r.subdomainInRegURL == "" || (subdomain != "" && r.subdomainInRegURL == subdomain) {
		repo = subrepo
	} else if r.subdomainInRegURL != "" && (subdomain == "" || r.subdomainInRegURL != subdomain) {
		subdomain = r.subdomainInRegURL
	}
	url, ok := r.subdomainURL[subdomain]
	if !ok {
		return "", "", fmt.Errorf("cannot find subdomain %s from repository %s", subdomain, repo)
	}

	return url, repo, nil
}

func (r *jfrog) GetTagList(domain, repo, tag string) ([]string, error) {
	smd.scanLog.Debug()

	rc := r.rc
	if r.mode == share.JFrogModeSubdomain {
		url, subRepo, err := r.getSubdomainUrlFromRepo(repo)
		if err != nil {
			smd.scanLog.WithFields(log.Fields{"err": err}).Error()
			return nil, err
		}
		if r.regURL != url {
			rc = scanUtils.NewRegClient(url, "", r.base.username, r.base.password, r.base.proxy, r.tracer)
		}
		repo = subRepo
	}

	// GetArtifactoryTags fetches tags fetch tags using the Artifactory API (introduced in JFrog 4.4.3)
	if tags, err := r.GetArtifactoryTags(repo, rc); len(tags) > 0 || err != nil {
		return tags, err
	}

	// Fallback to the original `Tags` API if the Artifactory API fails or returns no tags
	smd.scanLog.WithFields(log.Fields{"repo": repo}).Debug("Falling back to rc.Tags API")
	return rc.Tags(repo)
}

func (r *jfrog) GetAllImages() (map[share.CLUSImage][]string, error) {
	smd.scanLog.Debug()

	if r.mode != share.JFrogModeSubdomain || !r.aql {
		return nil, common.ErrUnsupported
	}

	r.subdomainInRegURL = ""

	aqlUrl, err := r.url("artifactory/api/search/aql")
	if err != nil {
		return nil, err
	}

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
	if r.mode == share.JFrogModeSubdomain {
		url, subRepo, err := r.getSubdomainUrlFromRepo(repo)
		if err != nil {
			smd.scanLog.WithFields(log.Fields{"err": err}).Error()
		} else if r.regURL != url {
			rc = scanUtils.NewRegClient(url, "", r.base.username, r.base.password, r.base.proxy, r.tracer)
		}
		repo = subRepo
	}
	rinfo, errCode := rc.GetImageInfo(ctx, repo, tag, registry.ManifestRequest_Default)
	return rinfo, errCode
}

func (r *jfrog) ScanImage(scanner string, ctx context.Context, id, digest, repo, tag string, scanTypesRequired share.ScanTypeMap) *share.ScanResult {
	newURL := r.regURL
	if r.mode == share.JFrogModeSubdomain {
		url, subRepo, err := r.getSubdomainUrlFromRepo(repo)
		if err != nil {
			smd.scanLog.WithFields(log.Fields{"err": err}).Error()
		} else {
			newURL = url
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
	repoUrl, err := r.url("artifactory/api/repositories")
	if err != nil {
		return nil, err
	}
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

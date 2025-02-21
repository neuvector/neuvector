package scan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/neuvector/neuvector/share"
)

const (
	_githubApiPackagesEndpointFormat = "https://api.github.com/%s/%s/packages" //https://api.github.com/NAMESPACE_TYPE/NAMESPACE/packages
	_githubApiPageNumQueryParam      = "page"
	_githubApiPerPageQueryParam      = "per_page"
	_githubApiPackageTypeQueryParam  = "package_type"
	_githubApiDefaultPageNum         = 1
	_githubApiDefaultPerPage         = 30
	_githubApiPackageTypeContainer   = "container"
	_githubApiVersionHeaderKey       = "X-GitHub-Api-Version"
	_gitHubApiVersion                = "2022-11-28"
	_githubApiAcceptHeaderName       = "accept"
	_githubApiMediaType              = "application/vnd.github+json"
	_githubApiNamespaceTypeOrgs      = "orgs"
	_githubApiNamespaceTypeUsers     = "users"
)

type github struct {
	base
}

func (g *github) GetRepoList(org, name string, limit int) ([]*share.CLUSImage, error) {
	if org == "*" {
		return nil, errors.New("org filter \"*\" is not supported for github container registry")
	}

	// smd.scanLog.Debug()
	if !strings.Contains(name, "*") {
		if org == "" {
			return []*share.CLUSImage{{Repo: name}}, nil
		} else {
			return []*share.CLUSImage{{Repo: fmt.Sprintf("%s/%s", org, name)}}, nil
		}
	}

	var githubPackages []GithubApiPackage
	var err error

	githubPackages, err = g.getAllPackagesInNamespace(_githubApiNamespaceTypeOrgs, org)
	if err != nil {
		if strings.Contains(err.Error(), "http: non-successful response") {
			githubPackages, err = g.getAllPackagesInNamespace(_githubApiNamespaceTypeUsers, org)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("could not get packages from github api: %w", err)
	}

	repoList := []*share.CLUSImage{}
	for _, githubPackage := range githubPackages {
		if githubPackage.Type != _githubApiPackageTypeContainer {
			continue
		}
		repoList = append(repoList, &share.CLUSImage{
			Repo: fmt.Sprintf("%s/%s", org, githubPackage.Name),
		})
	}

	return repoList, nil
}

type GithubApiPackage struct {
	Name string `json:"name"`
	Type string `json:"package_type"`
}

func (g *github) getAllPackagesInNamespace(namespaceType string, namespace string) ([]GithubApiPackage, error) {
	allPackages := []GithubApiPackage{}
	var newPackages []GithubApiPackage
	var err error
	nextPage := _githubApiDefaultPageNum
	for nextPage != 0 {
		newPackages, nextPage, err = g.getPageOfPackagesInNamespace(namespaceType, namespace, nextPage)
		if err != nil {
			return nil, fmt.Errorf("could not get page %d of github packages: %w", nextPage, err)
		}
		allPackages = append(allPackages, newPackages...)
	}
	return allPackages, nil
}

func (g *github) getPageOfPackagesInNamespace(namespaceType string, namespace string, pageNumber int) ([]GithubApiPackage, int, error) {
	formattedUrl := fmt.Sprintf(_githubApiPackagesEndpointFormat, namespaceType, namespace)
	reqUrl, err := url.Parse(formattedUrl)
	if err != nil {
		return nil, 0, fmt.Errorf("could not parse github package url: %w", err)
	}

	v := url.Values{}
	v.Set(_githubApiPageNumQueryParam, strconv.Itoa(pageNumber))
	v.Set(_githubApiPerPageQueryParam, strconv.Itoa(_githubApiDefaultPerPage))
	v.Set(_githubApiPackageTypeQueryParam, _githubApiPackageTypeContainer)
	reqUrl.RawQuery = v.Encode()

	req, err := http.NewRequest("GET", reqUrl.String(), nil)
	if err != nil {
		return nil, 0, fmt.Errorf("could not make request object: %w", err)
	}

	req.SetBasicAuth(g.base.username, g.base.password)
	req.Header.Add(_githubApiVersionHeaderKey, _gitHubApiVersion)
	req.Header.Add(_githubApiAcceptHeaderName, _githubApiMediaType)

	resp, err := g.rc.Client.DoWithRetry(req, 1)
	if err != nil {
		return nil, 0, fmt.Errorf("could not do request to get all repositories: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("received error code from github api: %d", resp.StatusCode)
	}

	packages := []GithubApiPackage{}
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("could not read response body: %w", err)
	}
	err = json.Unmarshal(respBytes, &packages)
	if err != nil {
		return nil, 0, fmt.Errorf("could not unmarshall response body json: %w", err)
	}

	nextPage := 0
	if strings.Contains(resp.Header.Get("link"), "rel=\"next\"") {
		nextPage = pageNumber + 1
	}

	return packages, nextPage, nil
}

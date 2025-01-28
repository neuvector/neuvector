package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/neuvector/neuvector/share"
	log "github.com/sirupsen/logrus"
)

const totalCounterHeaderCanonicalForm string = "X-Total-Count"
const defaultRepositoryPageSize int = 10

type harbor struct {
	base
}

type HarborApiProject struct {
	Id         int     `json:"id"`
	RegistryId *string `json:"registry_id"`
}

func (proj *HarborApiProject) IsProxyCacheProject() bool {
	return proj.RegistryId != nil
}

type HarborApiRepository struct {
	FullName  string `json:"name"`
	ProjectId int    `json:"project_id"`
}

// TODO: the splits in projectName() and repoName() are duplicated, perform only once
func (harborRepo *HarborApiRepository) projectName() (string, error) {
	splitName := strings.Split(harborRepo.FullName, "/")
	if len(splitName) < 2 {
		// a harbor repo should always have the project name
		// prefixed which means this should never happen
		// but handling for the sake of robustness
		return "", fmt.Errorf("could not parse project name for project repository \"%s\"", harborRepo.FullName)
	}
	// A Harbor project is not allowed to have forward-slash
	// characters, so the first one we run into in a repository
	// name delimits the harbor project name that repo belongs to
	return splitName[0], nil
}

func (harborRepo *HarborApiRepository) repoName() string {
	splitName := strings.Split(harborRepo.FullName, "/")
	if len(splitName) < 2 {
		return harborRepo.FullName
	}
	return strings.Join(splitName[1:], "/")
}

func (h *harbor) GetAllImages() (map[share.CLUSImage][]string, error) {
	repositories, err := h.getAllRepositories()
	if err != nil {
		return nil, fmt.Errorf("could not get repositories from harbor api: %w", err)
	}

	images := map[share.CLUSImage][]string{}
	for _, repository := range repositories {
		image := share.CLUSImage{
			Repo: repository.FullName,
		}
		tags, err := h.getTagsForRepository(repository)
		if err != nil {
			return nil, fmt.Errorf("could not get tags for repository %s from harbor api: %w", repository.FullName, err)
		}
		images[image] = tags
	}

	return images, nil
}

func (h *harbor) getAllRepositories() ([]HarborApiRepository, error) {
	pageNum := 1
	pageWhereTotalCountChanged := -1
	allFetchedRepositories := []HarborApiRepository{}
	totalReposInRegistry := -1
	for {
		if pageNum == pageWhereTotalCountChanged {
			// we've already appended the repos for this page in a previous iteration
			pageNum++
			continue
		}
		repositoriesForPage, totalCount, err := h.getPageOfRepositories(pageNum)
		if err != nil {
			return nil, fmt.Errorf("could not get page %d of harbor repositories: %w", pageNum, err)
		}
		if totalReposInRegistry == -1 {
			totalReposInRegistry = totalCount
		} else if totalReposInRegistry != totalCount {
			// number of repos changed while we were querying registry
			// rerun query for all previous pages as well
			pageWhereTotalCountChanged = pageNum
			pageNum = 0
			allFetchedRepositories = []HarborApiRepository{}
			totalReposInRegistry = totalCount
		}

		allFetchedRepositories = append(allFetchedRepositories, repositoriesForPage...)
		if len(allFetchedRepositories) >= totalReposInRegistry {
			break
		} else if len(repositoriesForPage) == 0 {
			return nil, fmt.Errorf("received unexpected empty response from harbor registry for repositories page %d", pageNum)
		}
		pageNum++
	}

	return allFetchedRepositories, nil
}

func (h *harbor) getPageOfRepositories(pageNum int) ([]HarborApiRepository, int, error) {
	rawUrl, err := url.JoinPath(h.base.regURL, "api/v2.0/repositories")
	if err != nil {
		return nil, 0, fmt.Errorf("could not join repository request url: %w", err)
	}
	reqUrl, err := url.Parse(rawUrl)
	if err != nil {
		return nil, 0, fmt.Errorf("could not parse repository request url: %w", err)
	}
	v := url.Values{}
	v.Set("page", strconv.Itoa(pageNum))
	v.Set("page_size", strconv.Itoa(defaultRepositoryPageSize))
	reqUrl.RawQuery = v.Encode()
	req, err := http.NewRequest("GET", reqUrl.String(), nil)
	if err != nil {
		return nil, 0, fmt.Errorf("could not make request object: %w", err)
	}
	req.SetBasicAuth(h.base.username, h.base.password)
	req.Header.Add("accept", "application/json")
	resp, err := h.rc.Client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("could not do request to get all repositories: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("received error code from harbor api: %d", resp.StatusCode)
	}
	harborRepositories := []HarborApiRepository{}
	// TODO: more efficiently deal with large responses, instead of reading all into a byte slice
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("could not read response body: %w", err)
	}
	err = json.Unmarshal(respBytes, &harborRepositories)
	if err != nil {
		return nil, 0, fmt.Errorf("could not unmarshall response body json: %w", err)
	}
	totalCountHeader := resp.Header.Get(totalCounterHeaderCanonicalForm)
	if totalCountHeader == "" {
		return nil, 0, fmt.Errorf("could not retrieve total count header from response")
	}
	totalCount, err := strconv.Atoi(totalCountHeader)
	if err != nil {
		return nil, 0, fmt.Errorf("could not parse total count header \"%s\" to int: %w", totalCountHeader, err)
	}
	return harborRepositories, totalCount, nil
}

type HarborApiArtifact struct {
	Tags []HarborApiTag `json:"tags"`
}

type HarborApiTag struct {
	Name string `json:"name"`
}

func (h *harbor) getTagsForRepository(repository HarborApiRepository) ([]string, error) {
	log.WithField("repository", repository.FullName).Debug("getting tags for repository")
	projectName, err := repository.projectName()
	if err != nil {
		return nil, fmt.Errorf("could not get project name: %w", err)
	}
	if projectName == "" {
		return nil, fmt.Errorf("cannot parse project name for project/repository: %s", repository.FullName)
	}

	// the harbor api requires the repo name (which tends to contain a slash) to be url encoded twice
	// example: a/b -> a%2Fb -> a%252Fb
	encodedRepoName := url.PathEscape(url.PathEscape(repository.repoName()))
	reqUrl, err := url.JoinPath(h.base.regURL, "api/v2.0/projects", projectName, "repositories", encodedRepoName, "artifacts")
	if err != nil {
		return nil, fmt.Errorf("could not generate artifact request url: %w", err)
	}
	req, err := http.NewRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("could not make request object: %w", err)
	}
	req.URL.RawQuery = "with_tag=true" // required to include image tags in response
	req.SetBasicAuth(h.base.username, h.base.password)
	req.Header.Add("accept", "application/json")
	resp, err := h.rc.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not do request to get all artifacts for repo %s: %w", repository.FullName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received error code from harbor api: %d", resp.StatusCode)
	}

	harborArtifacts := []HarborApiArtifact{}
	// TODO: more efficiently deal with large responses, instead of reading all into a byte slice
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read response body: %w", err)
	}
	err = json.Unmarshal(respBytes, &harborArtifacts)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshall response body json: %w", err)
	}

	tagsForRepo := []string{}
	seenTags := map[string]bool{}

	for _, artifact := range harborArtifacts {
		for _, tag := range artifact.Tags {
			if seen := seenTags[tag.Name]; seen {
				continue
			}
			tagsForRepo = append(tagsForRepo, tag.Name)
		}
	}

	return tagsForRepo, nil
}

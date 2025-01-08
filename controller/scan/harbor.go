package scan

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/neuvector/neuvector/share"
)

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
func (harborRepo *HarborApiRepository) projectName() string {
	splitRepoName := strings.Split(harborRepo.FullName, "/")
	if len(splitRepoName) < 2 {
		// a harbor repo should always have the project name
		// prefixed which means this should never happen
		// but handling for the sake of robustness
		return ""
	}
	// A Harbor project is not allowed to have forward-slash
	// characters, so the first one we run into in a repository
	// name delimits the harbor project name that repo belongs to
	return splitRepoName[0]
}

func (harborRepo *HarborApiRepository) repoName() string {
	splitRepoName := strings.Split(harborRepo.FullName, "/")
	if len(splitRepoName) < 2 {
		return harborRepo.FullName
	}
	return strings.Join(splitRepoName[1:], "/")
}

func (h *harbor) GetAllImages() (map[share.CLUSImage][]string, error) {
	repositories, err := h.getAllRepositories()
	if err != nil {
		return nil, fmt.Errorf("could not get repositories from harbor api: %s", err.Error())
	}

	images := map[share.CLUSImage][]string{}
	for _, repository := range repositories {
		image := share.CLUSImage{
			Repo: repository.FullName,
		}
		tags, err := h.getTagsForRepository(repository)
		if err != nil {
			return nil, fmt.Errorf("could not get tags for repository %s from harbor api: %s", repository.FullName, err.Error())
		}
		images[image] = tags
	}

	return images, nil
}

// TODO: deal with large registries, implement pagination/chunked responses?
func (h *harbor) getAllRepositories() ([]HarborApiRepository, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v2.0/repositories", h.base.regURL), nil)
	if err != nil {
		return nil, fmt.Errorf("could not make request object: %s", err.Error())
	}
	basicEncoding := base64.StdEncoding
	basicAuthToken := basicEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", h.base.username, h.base.password)))
	req.Header.Add("authorization", fmt.Sprintf("Basic %s", basicAuthToken))
	req.Header.Add("accept", "application/json")
	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not do request to get all repositories: %s", err.Error())
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received error code from harbor api: %d", resp.StatusCode)
	}
	harborRepositories := []HarborApiRepository{}
	// TODO: more efficiently deal with large responses, instead of reading all into a byte slice
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read response body: %s", err.Error())
	}
	err = json.Unmarshal(respBytes, &harborRepositories)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshall response body json: %s", err.Error())
	}
	return harborRepositories, nil
}

type HarborApiArtifact struct {
	Tags []HarborApiTag `json:"tags"`
}

type HarborApiTag struct {
	Name string `json:"name"`
}

func (h *harbor) getTagsForRepository(repository HarborApiRepository) ([]string, error) {
	fmt.Printf("getting tags for repository: %s\n", repository.FullName)
	projectName := repository.projectName()
	if projectName == "" {
		return nil, fmt.Errorf("cannot parse project name for project/repository: %s", repository.FullName)
	}

	// the harbor api requires the repo name (which tends to contain a slash) to be url encoded twice
	// example: a/b -> a%2Fb -> a%252Fb
	encodedRepoName := url.PathEscape(url.PathEscape(repository.repoName()))
	artifactEndpoint := fmt.Sprintf("api/v2.0/projects/%s/repositories/%s/artifacts?with_tag=true", repository.projectName(), encodedRepoName)
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/%s", h.base.regURL, artifactEndpoint), nil)
	if err != nil {
		return nil, fmt.Errorf("could not make request object: %s", err.Error())
	}

	basicEncoding := base64.StdEncoding
	basicAuthToken := basicEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", h.base.username, h.base.password)))
	req.Header.Add("authorization", fmt.Sprintf("Basic %s", basicAuthToken))
	req.Header.Add("accept", "application/json")
	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not do request to get all artifacts for repo %s: %s", repository.FullName, err.Error())
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received error code from harbor api: %d", resp.StatusCode)
	}

	harborArtifacts := []HarborApiArtifact{}
	// TODO: more efficiently deal with large responses, instead of reading all into a byte slice
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read response body: %s", err.Error())
	}
	fmt.Println(string(respBytes))
	err = json.Unmarshal(respBytes, &harborArtifacts)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshall response body json: %s", err.Error())
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

package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/httpclient"
	log "github.com/sirupsen/logrus"
)

type harbor struct {
	base
	client http.Client
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

func newHarbor(baseDriver base) *harbor {
	client := &http.Client{
		Timeout: gitTimeout,
	}

	t, err := httpclient.GetTransport(baseDriver.proxy)
	if err != nil {
		log.WithError(err).Warn("failed to get transport")
	} else {
		client.Transport = t
	}

	return &harbor{
		base:   baseDriver,
		client: *client,
	}
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

// TODO: deal with large registries, implement pagination/chunked responses?
func (h *harbor) getAllRepositories() ([]HarborApiRepository, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v2.0/repositories", h.base.regURL), nil)
	if err != nil {
		return nil, fmt.Errorf("could not make request object: %w", err)
	}
	req.SetBasicAuth(h.base.username, h.base.password)
	req.Header.Add("accept", "application/json")
	client := http.DefaultClient
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not do request to get all repositories: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("received error code from harbor api: %d", resp.StatusCode)
	}
	harborRepositories := []HarborApiRepository{}
	// TODO: more efficiently deal with large responses, instead of reading all into a byte slice
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read response body: %w", err)
	}
	err = json.Unmarshal(respBytes, &harborRepositories)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshall response body json: %w", err)
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
	artifactEndpoint := fmt.Sprintf("api/v2.0/projects/%s/repositories/%s/artifacts?with_tag=true", projectName, encodedRepoName)
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/%s", h.base.regURL, artifactEndpoint), nil)
	if err != nil {
		return nil, fmt.Errorf("could not make request object: %w", err)
	}
	req.SetBasicAuth(h.base.username, h.base.password)
	req.Header.Add("accept", "application/json")
	client := http.DefaultClient
	resp, err := client.Do(req)
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

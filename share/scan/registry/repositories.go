package registry

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	registrytypes "github.com/docker/docker/api/types/registry"
	log "github.com/sirupsen/logrus"
)

type repositoriesResponse struct {
	Repositories []string `json:"repositories"`
}

type Repository struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	IsPublic  bool   `json:"is_public"`
}
type quayRepositoriesResponse struct {
	Repositories []Repository `json:"repositories"`
}

func (r *Registry) parseQuayRepositories(response quayRepositoriesResponse) []string {
	repos := make([]string, 0)
	for _, repo := range response.Repositories {
		repos = append(repos, fmt.Sprintf("%s/%s", repo.Namespace, repo.Name))
	}
	return repos
}

func (r *Registry) QuayRepositories(namespace string) ([]string, error) {
	url := r.url("/api/v1/repository?namespace=%s&public=true", namespace)
	repos := make([]string, 0)

	var response quayRepositoriesResponse
	var err error

	r.Client.SetTimeout(longTimeout)
	for {
		log.WithFields(log.Fields{"url": url}).Debug()
		if !strings.HasPrefix(url, r.URL) {
			url = r.URL + url
		}

		url, err = r.getPaginatedJson(url, &response)
		switch err {
		case ErrNoMorePages:
			repos = append(repos, r.parseQuayRepositories(response)...)
			return repos, nil
		case nil:
			repos = append(repos, r.parseQuayRepositories(response)...)
			continue
		default:
			log.WithFields(log.Fields{"error": err}).Debug() // Debug level, as we are trying different URLs
			return nil, err
		}
	}
}

func (r *Registry) Repositories() ([]string, error) {
	url := r.url("/v2/_catalog")
	repos := make([]string, 0)

	var response repositoriesResponse
	var err error

	r.Client.SetTimeout(longTimeout)
	for {
		log.WithFields(log.Fields{"url": url}).Debug()
		if !strings.HasPrefix(url, r.URL) {
			url = r.URL + url
		}

		url, err = r.getPaginatedJson(url, &response)
		switch err {
		case ErrNoMorePages:
			repos = append(repos, response.Repositories...)
			return repos, nil
		case nil:
			repos = append(repos, response.Repositories...)
			continue
		default:
			log.WithFields(log.Fields{"error": err}).Debug() // Debug level, as we are trying different URLs
			return nil, err
		}
	}
}

func (r *Registry) Search(term string, limit int) ([]string, error) {
	u := r.url("/v1/search?q=%s&n=%s", url.QueryEscape(term), url.QueryEscape(fmt.Sprintf("%d", limit)))
	resp, err := r.Client.Get(u)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Unexpected status code %d", resp.StatusCode)
	}
	result := new(registrytypes.SearchResults)
	if err = json.NewDecoder(resp.Body).Decode(result); err != nil {
		return nil, err
	}
	list := make([]string, len(result.Results))
	for i, sr := range result.Results {
		list[i] = sr.Name
	}
	return list, err
}

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

func (registry *Registry) Repositories() ([]string, error) {
	url := registry.url("/v2/_catalog")
	repos := make([]string, 0, 10)
	var err error //We create this here, otherwise url will be rescoped with :=
	var response repositoriesResponse
	for {
		log.WithFields(log.Fields{"url": url}).Debug()
		if !strings.HasPrefix(url, registry.URL) {
			url = registry.URL + url
		}
		url, err = registry.getPaginatedJson(url, &response)
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

func (registry *Registry) Search(term string, limit int) ([]string, error) {
	u := registry.url("/v1/search?q=" + url.QueryEscape(term) + "&n=" + url.QueryEscape(fmt.Sprintf("%d", limit)))
	resp, err := registry.Client.Get(u)
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

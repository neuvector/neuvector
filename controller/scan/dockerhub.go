package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/neuvector/neuvector/share"
)

type dockerhubRegistryQuery struct {
	Count    int                         `json:"count"`
	Next     string                      `json:"next"`
	Previous string                      `json:"previous"`
	Results  []dockerhubRepositoryRecord `json:"results"`
}

type dockerhubRepositoryRecord struct {
	User           string `json:"user"`
	Name           string `json:"name"`
	Namespace      string `json:"namespace"`
	RepositoryType string `json:"repository_type"`
	Status         int    `json:"status"`
	Description    string `json:"description"`
	IsPrivate      bool   `json:"is_private"`
	IsAutomated    bool   `json:"is_automated"`
	CanEdit        bool   `json:"can_edit"`
	StarCount      int    `json:"star_count"`
	PullCount      int    `json:"pull_count"`
	LastUpdated    string `json:"last_updated"`
}

type dockerhub struct {
	base
}

func (r dockerhub) GetRepoList(org, name string, limit int) ([]*share.CLUSImage, error) {
	smd.scanLog.Debug()

	if !strings.Contains(name, "*") {
		if org == "" {
			return []*share.CLUSImage{{Repo: fmt.Sprintf("library/%s", name)}}, nil
		} else {
			return []*share.CLUSImage{{Repo: fmt.Sprintf("%s/%s", org, name)}}, nil
		}
	}

	u := r.url("v2/repositories/%s/?page_size=%d", org, limit)
	resp, err := r.rc.Client.Get(u)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Unexpected status code %d", resp.StatusCode)
	}

	var regQuery dockerhubRegistryQuery
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(data, &regQuery)
	if err != nil {
		return nil, err
	}

	list := make([]*share.CLUSImage, len(regQuery.Results))
	for i, sr := range regQuery.Results {
		list[i] = &share.CLUSImage{Repo: org + "/" + sr.Name}
	}
	return list, err
}

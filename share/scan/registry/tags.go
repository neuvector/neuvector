package registry

import (
	log "github.com/sirupsen/logrus"
)

type tagsResponse struct {
	Tags []string `json:"tags"`
}

func (registry *Registry) Tags(repository string) ([]string, error) {
	var err error
	url := registry.url("/v2/%s/tags/list", repository)
	tags := make([]string, 0)
	var response tagsResponse
	for {
		log.WithFields(log.Fields{"url": url, "repository": repository}).Debug()
		url, err = registry.getPaginatedJson(url, &response)
		switch err {
		case ErrNoMorePages:
			tags = append(tags, response.Tags...)
			return tags, nil
		case nil:
			tags = append(tags, response.Tags...)
			continue
		default:
			return tags, nil
		}
	}
}

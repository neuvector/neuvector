package scan

import (
	"fmt"

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
	Name      string `json:"name"`
	ProjectId int    `json:"project_id"`
}

func (h *harbor) GetAllImages() (map[share.CLUSImage][]string, error) {
	repositories, err := h.getAllRepositories()
	if err != nil {
		return nil, fmt.Errorf("could not get repositories from harbor api: %s", err.Error())
	}

	images := map[share.CLUSImage][]string{}
	for _, repository := range repositories {
		image := share.CLUSImage{
			Repo: repository.Name,
		}
		tags, err := h.getTagsForRepository(repository)
		if err != nil {
			return nil, fmt.Errorf("could not get tags for repository %s from harbor api: %s", repository.Name, err.Error())
		}
		images[image] = tags
	}

	return images, nil
}

func (h *harbor) getAllRepositories() ([]HarborApiRepository, error) {
	return nil, nil
}

func (h *harbor) getTagsForRepository(repository HarborApiRepository) ([]string, error) {
	return nil, nil
}

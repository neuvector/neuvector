package remote_repository

import (
	"errors"
	"fmt"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/cache"
	"github.com/neuvector/neuvector/share"
	log "github.com/sirupsen/logrus"
)

type Export struct {
	DefaultFilePath string
	Options         *api.RESTRemoteExportOptions
	Content         []byte
	Cacher          cache.CacheInterface
	AccessControl   *access.AccessControl
}

func (exp *Export) Do() error {
	log.Info("Initiating remote export.")

	if exp.Options.RemoteRepositoryNickname == "" {
		return errors.New("no remote repository nickname provided for remote export")
	}

	if exp.AccessControl == nil {
		log.Error("no access control object set for export")
		return errors.New("invalid internal configuration")
	}

	if exp.Cacher == nil {
		log.Error("no cluster helper field set for export")
		return errors.New("invalid internal configuration")
	}

	systemConfig := exp.Cacher.GetSystemConfig(exp.AccessControl)
	if systemConfig == nil {
		return fmt.Errorf("could not retrieve remote export repository \"%s\" from clus, denied read access to system config", exp.Options.RemoteRepositoryNickname)
	}

	var remoteRepository *api.RESTRemoteRepository
	for _, systemConfigRepo := range systemConfig.RemoteRepositories {
		if exp.Options.RemoteRepositoryNickname == systemConfigRepo.Nickname {
			remoteRepository = &systemConfigRepo
		}
	}
	if remoteRepository == nil || remoteRepository.GitHubConfiguration == nil {
		return fmt.Errorf("could not retrieve remote export repository \"%s\"", exp.Options.RemoteRepositoryNickname)
	}

	if remoteRepository.Provider == share.RemoteRepositoryProvider_GitHub {
		exportFilePath := exp.DefaultFilePath
		if exp.Options.FilePath != "" {
			exportFilePath = exp.Options.FilePath
		}

		githubExport, err := NewGitHubExport(exportFilePath, exp.Content, exportFilePath, *remoteRepository.GitHubConfiguration)
		if err != nil {
			return fmt.Errorf("could not initialize github export object: %s", err.Error())
		}

		err = githubExport.Do()
		if err != nil {
			return fmt.Errorf("could not do github export: %s", err.Error())
		}
	} else {
		return fmt.Errorf("unsupported provider for export: %s", remoteRepository.Provider)
	}

	log.Info("Remote export successful.")
	return nil
}

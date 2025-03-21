package remote_repository

import (
	"errors"
	"fmt"
	"net/http"

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

	if remoteRepository == nil {
		return fmt.Errorf("could not retrieve remote export repository \"%s\"", exp.Options.RemoteRepositoryNickname)
	} else if !remoteRepository.Enable {
		return fmt.Errorf("remote export repository \"%s\" is disabled", exp.Options.RemoteRepositoryNickname)
	}

	if remoteRepository.Provider == share.RemoteRepositoryProvider_GitHub && remoteRepository.GitHubConfiguration == nil {
		return errors.New("github configuration missing cannot be nil for github provider")
	}

	if remoteRepository.Provider == share.RemoteRepositoryProvider_AzureDevops && remoteRepository.AzureDevopsConfiguration == nil {
		return errors.New("azure devops configuration cannot be nil for azure devops provider")
	}

	exportFilePath := exp.DefaultFilePath
	if exp.Options.FilePath != "" {
		exportFilePath = exp.Options.FilePath
	}
	commitMessage := exportFilePath
	if exp.Options.Comment != "" {
		commitMessage = exp.Options.Comment
	}

	if remoteRepository.Provider == share.RemoteRepositoryProvider_GitHub {
		githubExport, err := NewGitHubExport(exportFilePath, exp.Content, commitMessage, *remoteRepository.GitHubConfiguration)
		if err != nil {
			return fmt.Errorf("could not initialize github export object: %s", err.Error())
		}

		err = githubExport.Do()
		if err != nil {
			return fmt.Errorf("could not do github export: %s", err.Error())
		}
	} else if remoteRepository.Provider == share.RemoteRepositoryProvider_AzureDevops {
		export := azureDevopsExport{
			repoConfig:    *remoteRepository.AzureDevopsConfiguration,
			exportOptions: *exp.Options,
			content:       exp.Content,
			client:        http.DefaultClient,
		}
		err := export.Do()
		if err != nil {
			return fmt.Errorf("could not do azure devops export: %w", err)
		}
	} else {
		return fmt.Errorf("unsupported provider for export: %s", remoteRepository.Provider)
	}

	log.Info("Remote export successful.")
	return nil
}

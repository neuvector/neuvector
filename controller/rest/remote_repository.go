package rest

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/julienschmidt/httprouter"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	log "github.com/sirupsen/logrus"
)

func handlerRemoteRepositoryPost(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSRemoteRepository{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	body, _ := io.ReadAll(r.Body)
	var remoteRepository api.RESTRemoteRepository
	err := json.Unmarshal(body, &remoteRepository)
	if err != nil {
		msg := fmt.Sprintf("Could not unmarshal request body: %s", err.Error())
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
		return
	} else if !isObjectNameValid(remoteRepository.Nickname) {
		e := "Invalid characters in nickname"
		log.WithFields(log.Fields{"nickname": remoteRepository.Nickname}).Error(e)
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, e)
		return
	}

	// in 5.3, only an alias of "default" is allowed
	if remoteRepository.Nickname != "default" {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "the only supported name is default")
		return
	}

	if remoteRepository.Provider != share.RemoteRepositoryProvider_GitHub {
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "the only supported provider is github")
		return
	}

	repo := share.CLUSRemoteRepository{
		Nickname: remoteRepository.Nickname,
		Provider: remoteRepository.Provider,
		Comment:  remoteRepository.Comment,
		Enable:   remoteRepository.Enable,
	}
	if remoteRepository.GitHubConfiguration != nil {
		githubCfg := *remoteRepository.GitHubConfiguration
		repo.GitHubConfiguration = &share.RemoteRepository_GitHubConfiguration{
			RepositoryOwnerUsername:          githubCfg.RepositoryOwnerUsername,
			RepositoryName:                   githubCfg.RepositoryName,
			RepositoryBranchName:             githubCfg.RepositoryBranchName,
			PersonalAccessToken:              githubCfg.PersonalAccessToken,
			PersonalAccessTokenCommitterName: githubCfg.PersonalAccessTokenCommitterName,
			PersonalAccessTokenEmail:         githubCfg.PersonalAccessTokenEmail,
		}
	}

	lock, err := clusHelper.AcquireLock(share.CLUSLockServerKey, clusterLockWait)
	if err != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, err.Error())
		return
	}
	defer clusHelper.ReleaseLock(lock)

	systemConfig, rev := clusHelper.GetSystemConfigRev(acc)
	if systemConfig == nil {
		restRespAccessDenied(w, login)
		return
	}

	for i := range systemConfig.RemoteRepositories {
		if systemConfig.RemoteRepositories[i].Nickname == remoteRepository.Nickname {
			e := "duplicate remote repository alias"
			log.WithFields(log.Fields{"alias": remoteRepository.Nickname}).Error(e)
			restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "duplicate remote repository alias")
			return
		}
	}

	systemConfig.RemoteRepositories = append(systemConfig.RemoteRepositories, repo)
	err = clusHelper.PutSystemConfigRev(systemConfig, rev)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "rev": rev}).Error("could not update system config")
	}

	restRespSuccess(w, r, nil, acc, login, &remoteRepository, "Create Remote Export Repository")
}

func handlerRemoteRepositoryDelete(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSRemoteRepository{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	lock, err := clusHelper.AcquireLock(share.CLUSLockServerKey, clusterLockWait)
	if err != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, err.Error())
		return
	}
	defer clusHelper.ReleaseLock(lock)

	systemConfig, rev := clusHelper.GetSystemConfigRev(acc)
	if systemConfig == nil {
		restRespAccessDenied(w, login)
		return
	}

	var found bool
	targetNickname := ps.ByName("nickname")
	for i := range systemConfig.RemoteRepositories {
		if systemConfig.RemoteRepositories[i].Nickname == targetNickname {
			s := len(systemConfig.RemoteRepositories)
			systemConfig.RemoteRepositories[i] = systemConfig.RemoteRepositories[s-1]
			systemConfig.RemoteRepositories = systemConfig.RemoteRepositories[:s-1]
			found = true
			break
		}
	}

	if !found {
		log.WithFields(log.Fields{"name": targetNickname}).Error("remote repository not found")
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "remote repository not found")
		return
	}

	err = clusHelper.PutSystemConfigRev(systemConfig, rev)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "rev": rev}).Error("could not update system config")
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster, "could not delete remote repository")
	}

	msg := fmt.Sprintf("Deleted remote repository \"%s\"", targetNickname)
	restRespSuccess(w, r, nil, acc, login, nil, msg)
}

func handlerRemoteRepositoryPatch(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	log.WithFields(log.Fields{"URL": r.URL.String()}).Debug()
	defer r.Body.Close()

	acc, login := getAccessControl(w, r, "")
	if acc == nil {
		return
	} else if !acc.Authorize(&share.CLUSRemoteRepository{}, nil) {
		restRespAccessDenied(w, login)
		return
	}

	body, _ := io.ReadAll(r.Body)
	var rconf api.RESTRemoteRepositoryConfigData
	err := json.Unmarshal(body, &rconf)
	if err != nil || rconf.Config == nil {
		msg := fmt.Sprintf("Could not unmarshal request body: %s", err.Error())
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
		return
	}

	remoteRepositoryUpdates := rconf.Config

	lock, err := clusHelper.AcquireLock(share.CLUSLockServerKey, clusterLockWait)
	if err != nil {
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailLockCluster, err.Error())
		return
	}
	defer clusHelper.ReleaseLock(lock)

	systemConfig, rev := clusHelper.GetSystemConfigRev(acc)
	if systemConfig == nil {
		restRespAccessDenied(w, login)
		return
	}

	var found bool
	targetNickname := ps.ByName("nickname")
	for i := range systemConfig.RemoteRepositories {
		if systemConfig.RemoteRepositories[i].Nickname == targetNickname {
			updatedRemoteRepository, err := getUpdatedRemoteRepository(systemConfig.RemoteRepositories[i], remoteRepositoryUpdates)
			if err != nil {
				msg := fmt.Sprintf("could not update remote repository: %s", err.Error())
				restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, msg)
				return
			}
			systemConfig.RemoteRepositories[i] = updatedRemoteRepository
			found = true
			break
		}
	}

	if !found {
		log.WithFields(log.Fields{"name": targetNickname}).Error("remote repository not found")
		restRespErrorMessage(w, http.StatusBadRequest, api.RESTErrInvalidRequest, "remote repository not found")
		return
	}

	err = clusHelper.PutSystemConfigRev(systemConfig, rev)
	if err != nil {
		msg := fmt.Sprintf("Could not save updated remote repository to kv store: %s", err.Error())
		log.WithFields(log.Fields{"rev": rev}).Error(msg)
		restRespErrorMessage(w, http.StatusInternalServerError, api.RESTErrFailWriteCluster, msg)
		return
	}

	msg := fmt.Sprintf("Updated remote repository \"%s\"", targetNickname)
	restRespSuccess(w, r, nil, acc, login, &remoteRepositoryUpdates, msg)
}

// TODO: turn this into a generic function that is directed via struct tags
func getUpdatedRemoteRepository(base share.CLUSRemoteRepository, updates *api.RESTRemoteRepositoryConfig) (share.CLUSRemoteRepository, error) {
	isSet := func(s *string) bool {
		return s != nil
	}

	if updates.Enable != nil {
		base.Enable = *updates.Enable
	}

	if base.Provider == share.RemoteRepositoryProvider_GitHub {
		if isSet(updates.Comment) {
			base.Comment = *updates.Comment
		}
		if isSet(updates.GitHubConfiguration.RepositoryOwnerUsername) {
			base.GitHubConfiguration.RepositoryOwnerUsername = *updates.GitHubConfiguration.RepositoryOwnerUsername
		}
		if isSet(updates.GitHubConfiguration.RepositoryName) {
			base.GitHubConfiguration.RepositoryName = *updates.GitHubConfiguration.RepositoryName
		}
		if isSet(updates.GitHubConfiguration.RepositoryBranchName) {
			base.GitHubConfiguration.RepositoryBranchName = *updates.GitHubConfiguration.RepositoryBranchName
		}
		if isSet(updates.GitHubConfiguration.PersonalAccessToken) {
			base.GitHubConfiguration.PersonalAccessToken = *updates.GitHubConfiguration.PersonalAccessToken
		}
		if isSet(updates.GitHubConfiguration.PersonalAccessTokenCommitterName) {
			base.GitHubConfiguration.PersonalAccessTokenCommitterName = *updates.GitHubConfiguration.PersonalAccessTokenCommitterName
		}
		if isSet(updates.GitHubConfiguration.PersonalAccessTokenEmail) {
			base.GitHubConfiguration.PersonalAccessTokenEmail = *updates.GitHubConfiguration.PersonalAccessTokenEmail
		}
	}

	if base.Provider != "github" {
		return share.CLUSRemoteRepository{}, errors.New(`only "github" provider is allowed`)
	}

	if !base.IsValid() {
		return share.CLUSRemoteRepository{}, errors.New("updates result in invalid object")
	}
	return base, nil
}

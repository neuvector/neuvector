package scan

import (
	"errors"
	"testing"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/httptrace"
)

func TestGithubApiGetAllRepos(t *testing.T) {
	// TODO: should use some sort of configuration file + command line option for tests like these
	t.Skip() // remove this and replace the blank strings below to test
	cfg := &share.CLUSRegistryConfig{
		Type:        share.RegistryTypeGitHub,
		Registry:    "",
		Username:    "",
		Password:    "",
		IgnoreProxy: true,
	}
	githubDriver := newRegistryDriver(cfg, true, new(httptrace.NopTracer))
	err, errMsg := githubDriver.Login(cfg)
	if err != nil {
		t.Errorf("received error during login: %s with message %s", err.Error(), errMsg)
	}

	repoList, err := githubDriver.GetRepoList("rancher", "*", 0)
	if err != nil {
		t.Logf("%v\n", errors.Unwrap(err))
		t.Errorf("error when getting repo list: %v", err)
	}

	if len(repoList) == 0 {
		t.Errorf("did not expect empty repo list: %v", repoList)
	}

	for _, image := range repoList {
		t.Logf("CLUSImage.Repo: %s\n", image.Repo)
	}
}

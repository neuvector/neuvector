package remote_repository

import (
	"net/http"
	"testing"

	"github.com/neuvector/neuvector/controller/api"
)

func TestAzureDevopsExport(t *testing.T) {
	t.Skip()
	organizationName := ""
	projectName := ""
	repoName := ""
	branchName := ""
	personalAccessToken := ""
	content := ""
	remoteRepositoryNickname := ""
	filePath := ""
	comment := ""

	exp := azureDevopsExport{
		repoConfig: api.RESTRemoteRepo_AzureDevopsConfig{
			OrganizationName:    &organizationName,
			ProjectName:         &projectName,
			RepoName:            &repoName,
			BranchName:          &branchName,
			PersonalAccessToken: &personalAccessToken,
		},
		content: []byte(content),
		client:  http.DefaultClient,
		exportOptions: api.RESTRemoteExportOptions{
			RemoteRepositoryNickname: remoteRepositoryNickname,
			FilePath:                 filePath,
			Comment:                  comment,
		},
	}

	err := exp.Do()
	if err != nil {
		t.Errorf("could not do azure devops export: %s", err.Error())
	}
}

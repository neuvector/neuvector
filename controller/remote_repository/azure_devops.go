package remote_repository

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share/utils"
)

var ErrBranchDoesNotExist = errors.New("branch does not exist")
var ErrFileAlreadyExists = errors.New("file already exists at path")
var AzureApiAlreadyExistsErrorFormat = "The path '%s' specified in the add operation already exists. Please specify a new path."

const (
	AzureApiPushOperationAdd  = "add"
	AzureApiPushOperationEdit = "edit"
)

const (
	AzureApiRepoEndpointRefs   = "refs"
	AzureApiRepoEndpointPushes = "pushes"
)

// Get Refs Schema
type AzureDevopsApi_RefsReponse struct {
	Value []AzureDevopsApi_Ref `json:"value"`
}

type AzureDevopsApi_Ref struct {
	Name     string `json:"name"`
	ObjectId string `json:"objectId"`
}

func (ref *AzureDevopsApi_Ref) Branch() string {
	if len(ref.Name) == 0 {
		return ""
	}
	splitName := strings.Split(ref.Name, "/")
	return splitName[len(splitName)-1]
}

// Push Request Schema
type AzureDevopsApi_RepoPushRequest struct {
	RefUpdates []RefUpdates `json:"refUpdates"`
	Commits    []Commits    `json:"commits"`
}
type RefUpdates struct {
	Name        string `json:"name"`
	OldObjectID string `json:"oldObjectId"`
}
type Item struct {
	Path string `json:"path"`
}
type NewContent struct {
	Content     string `json:"content"`
	ContentType string `json:"contentType"`
}
type Changes struct {
	ChangeType string     `json:"changeType"`
	Item       Item       `json:"item"`
	NewContent NewContent `json:"newContent"`
}
type Commits struct {
	Comment string    `json:"comment"`
	Changes []Changes `json:"changes"`
}

type azureDevopsExport struct {
	repoConfig    api.RESTRemoteRepo_AzureDevopsConfig
	content       []byte
	client        *http.Client
	exportOptions api.RESTRemoteExportOptions
}

func (exp *azureDevopsExport) Do() error {
	ref, err := exp.getRef()
	if err != nil {
		return fmt.Errorf("could not get appropriate ref during export: %w", err)
	}
	err = exp.pushFileToRepo(ref, AzureApiPushOperationAdd)
	if errors.Is(err, ErrFileAlreadyExists) {
		err = exp.pushFileToRepo(ref, AzureApiPushOperationEdit)
	}
	if err != nil {
		return fmt.Errorf("could not push file to repo: %w", err)
	}
	return nil
}

func (exp *azureDevopsExport) getRef() (AzureDevopsApi_Ref, error) {
	url := exp.Url(AzureApiRepoEndpointRefs)

	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return AzureDevopsApi_Ref{}, fmt.Errorf("could not instantiate request object: %w", err)
	}

	request.SetBasicAuth("", *exp.repoConfig.PersonalAccessToken)
	response, err := exp.client.Do(request)
	if err != nil {
		return AzureDevopsApi_Ref{}, fmt.Errorf("could not do request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return AzureDevopsApi_Ref{}, fmt.Errorf("received unexpected status code %d", response.StatusCode)
	}

	responseBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return AzureDevopsApi_Ref{}, fmt.Errorf("could not read response bytes: %w", err)
	}

	var resp AzureDevopsApi_RefsReponse
	err = json.Unmarshal(responseBytes, &resp)
	if err != nil {
		return AzureDevopsApi_Ref{}, fmt.Errorf("could not unmarshal response json: %w", err)
	}

	for _, ref := range resp.Value {
		if ref.Branch() == *exp.repoConfig.BranchName {
			return ref, nil
		}
	}

	return AzureDevopsApi_Ref{}, fmt.Errorf("could not find ref for branch %s: %w", *exp.repoConfig.BranchName, ErrBranchDoesNotExist)
}

func (exp *azureDevopsExport) pushFileToRepo(ref AzureDevopsApi_Ref, pushOperation string) error {
	commitComment := exp.exportOptions.Comment
	if commitComment == "" {
		commitComment = fmt.Sprintf("import %s", exp.exportOptions.FilePath)
	}
	requestBody := AzureDevopsApi_RepoPushRequest{
		RefUpdates: []RefUpdates{
			{
				Name:        ref.Name,
				OldObjectID: ref.ObjectId,
			},
		},
		Commits: []Commits{
			{
				Comment: commitComment,
				Changes: []Changes{
					{
						ChangeType: pushOperation,
						Item: Item{
							Path: exp.exportOptions.FilePath,
						},
						NewContent: NewContent{
							Content:     string(exp.content),
							ContentType: "rawtext",
						},
					},
				},
			},
		},
	}

	requestBodyJSON, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("could not marshal request body into json: %w", err)
	}

	url := exp.Url(AzureApiRepoEndpointPushes)

	request, err := http.NewRequest("POST", url, utils.NopCloser(bytes.NewReader(requestBodyJSON)))
	if err != nil {
		return fmt.Errorf("could not instantiate request object: %w", err)
	}

	request.SetBasicAuth("", *exp.repoConfig.PersonalAccessToken)

	response, err := exp.client.Do(request)
	if err != nil {
		return fmt.Errorf("could not do request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusCreated {
		if response.StatusCode == 400 {
			responseBytes, err := io.ReadAll(response.Body)
			if err != nil {
				return fmt.Errorf("could not read response bytes: %w", err)
			}
			expectedAlreadyExistsMessage := fmt.Sprintf(AzureApiAlreadyExistsErrorFormat, exp.exportOptions.FilePath)
			if strings.Contains(string(responseBytes), expectedAlreadyExistsMessage) {
				return ErrFileAlreadyExists
			}
		}
		return fmt.Errorf("received unexpected status code %d", response.StatusCode)
	}

	return nil
}

func (exp *azureDevopsExport) Url(endpoint string) string {
	return fmt.Sprintf(
		"https://dev.azure.com/%s/%s/_apis/git/repositories/%s/%s?api-version=6.0",
		*exp.repoConfig.OrganizationName,
		*exp.repoConfig.ProjectName,
		*exp.repoConfig.RepoName,
		endpoint,
	)
}

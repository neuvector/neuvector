package remote_repository

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

const githubApiVersion = "2022-11-28"
const githubRepoContentUrl = "https://api.github.com/repos/%s/%s/contents/%s"

const ErrGitHubRateLimitReached = "github rate limit reached"

type gitHubAPI_Comitter struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type gitHubAPI_PutRepoContent_RequestBody struct {
	Message   string             `json:"message"`
	Branch    string             `json:"branch"`
	Committer gitHubAPI_Comitter `json:"comitter"`
	Content   string             `json:"content"`
	SHA       string             `json:"sha"`
}

type gitHubAPI_GetRepoContent_ResponseBody struct {
	Sha string `json:"sha"`
}

type githubRepo struct {
	owner  string
	name   string
	branch string
}

type githubCommitter struct {
	name                string
	email               string
	personalAccessToken string
}

type GitHubExport struct {
	repo          githubRepo
	committer     githubCommitter
	commitMessage string
	filePath      string
	fileContents  []byte
	exportUrl     *url.URL
	getUrl        *url.URL
	Config        *share.RemoteRepository_GitHubConfiguration
}

func (exp GitHubExport) Do() error {
	client := http.DefaultClient
	request := exp.getBaseRequest(http.MethodPut)
	request.Method = http.MethodPut

	encodedFileContents := make([]byte, base64.StdEncoding.EncodedLen(len(exp.fileContents)))
	base64.StdEncoding.Encode(encodedFileContents, []byte(exp.fileContents))

	existingFileSha, githubVer, err := exp.getExistingFileSha()
	if err != nil {
		return fmt.Errorf("could not retrieve sha for file at filepath %s: %s", exp.filePath, err.Error())
	}

	if githubVer == "github.v3" {
		hasher := sha1.New()
		hasher.Write([]byte(fmt.Sprintf("blob %d\x00%s", len(exp.fileContents), exp.fileContents)))
		newFileSha := hex.EncodeToString(hasher.Sum(nil))
		if existingFileSha != "" && newFileSha == existingFileSha {
			return fmt.Errorf("exported content is same as the file content on remote repository")
		}
	}

	requestBody := gitHubAPI_PutRepoContent_RequestBody{
		Message: exp.commitMessage,
		Committer: gitHubAPI_Comitter{
			Name:  exp.committer.name,
			Email: exp.committer.email,
		},
		Branch:  exp.repo.branch,
		Content: string(encodedFileContents),
		SHA:     existingFileSha,
	}

	requestBodyJSON, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("could not marshal request body into json: %s", err.Error())
	}

	request.Body = utils.NopCloser(bytes.NewReader(requestBodyJSON))

	response, err := client.Do(&request)
	if err != nil {
		return fmt.Errorf("could not do request: %s", err.Error())
	}

	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated {
		if response.Header.Get("x-ratelimit-remaining") == "0" {
			msg := ErrGitHubRateLimitReached
			if limitResetDate := getRateLimitResetDate(response.Header.Get("x-ratelimit-reset")); limitResetDate != nil {
				msg = fmt.Sprintf("%s, rate limit will reset at %s", msg, limitResetDate.String())
			}
			return errors.New(msg)
		} else {
			return fmt.Errorf("non-OK status response: %v", response)
		}
	}

	return nil
}

func getRateLimitResetDate(rateLimitResetHeader string) *time.Time {
	if rateLimitResetHeader == "" {
		return nil
	}
	rateLimitEpoch, err := strconv.ParseInt(rateLimitResetHeader, 10, 64)
	if err != nil {
		return nil
	}
	rateLimitResetDate := time.Unix(rateLimitEpoch, 0)
	return &rateLimitResetDate
}

func (exp GitHubExport) getExistingFileSha() (string, string, error) {
	client := http.DefaultClient

	req := exp.getBaseRequest(http.MethodGet)
	req.Method = http.MethodGet

	resp, err := client.Do(&req)
	if err != nil {
		return "", "", fmt.Errorf("could not do request: %s", err.Error())
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return "", "", nil
		}
		return "", "", fmt.Errorf("could not retrieve file contents from github api, received status code \"%d\"", resp.StatusCode)
	}

	var body []byte
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("error reading response body: %s", err.Error())
	}

	err = resp.Body.Close()
	if err != nil {
		return "", "", fmt.Errorf("error closing response body: %s", err.Error())
	}

	var githubVer string
	if values, ok := resp.Header["X-Github-Media-Type"]; ok {
		for _, v := range values {
			for _, s := range strings.Split(v, "; ") {
				if strings.HasPrefix(s, "github.") {
					githubVer = s
				}
			}
		}
	}

	githubApiFile := &gitHubAPI_GetRepoContent_ResponseBody{}
	err = json.Unmarshal(body, githubApiFile)
	if err != nil {
		return "", githubVer, fmt.Errorf("error unmarshalling response json: %s", err.Error())
	}

	return githubApiFile.Sha, githubVer, nil
}

func (exp GitHubExport) getBaseRequest(method string) http.Request {
	baseRequest := http.Request{
		Header: http.Header{},
	}
	if method == http.MethodGet {
		baseRequest.URL = exp.getUrl
	} else {
		baseRequest.URL = exp.exportUrl
	}
	baseRequest.Header.Add("Accept", "application/vnd.github+json")
	baseRequest.Header.Add("Authorization", fmt.Sprintf("Bearer %s", exp.committer.personalAccessToken))
	baseRequest.Header.Add("X-GitHub-Api-Version", githubApiVersion)
	return baseRequest
}

func NewGitHubExport(filePath string, fileContents []byte, commitMessage string, config api.RESTRemoteRepo_GitHubConfig) (GitHubExport, error) {
	var getUrl *url.URL
	exportUrl, err := url.Parse(fmt.Sprintf(githubRepoContentUrl, config.RepositoryOwnerUsername, config.RepositoryName, filePath))
	if err == nil {
		getUrl, err = url.Parse(fmt.Sprintf("%s?ref=%s", exportUrl.String(), config.RepositoryBranchName))
	}
	if err != nil {
		return GitHubExport{}, fmt.Errorf("could not parse url for new remote export object: %s", err.Error())
	}

	return GitHubExport{
		repo: githubRepo{
			owner:  config.RepositoryOwnerUsername,
			name:   config.RepositoryName,
			branch: config.RepositoryBranchName,
		},
		committer: githubCommitter{
			name:                config.PersonalAccessTokenCommitterName,
			email:               config.PersonalAccessTokenEmail,
			personalAccessToken: config.PersonalAccessToken,
		},
		filePath:      filePath,
		fileContents:  fileContents,
		commitMessage: commitMessage,
		exportUrl:     exportUrl,
		getUrl:        getUrl,
	}, nil
}

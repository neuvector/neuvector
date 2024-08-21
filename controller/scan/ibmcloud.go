package scan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
)

const grantType = "urn:ibm:params:oauth:grant-type:apikey"

type ibmcloud struct {
	base
	account       string // get from cmd: ibmcloud cr info
	iamOauthToken string
	apiClient     *http.Client
	images        map[string][]*ibmImage
}

type ibmImage struct {
	RepoTags []string `json:"RepoTags"`
}

func (r *ibmcloud) ibmUrl(pathTemplate string, args ...interface{}) string {
	pathSuffix := fmt.Sprintf(pathTemplate, args...)
	ur := fmt.Sprintf("%s%s", r.regURL, pathSuffix)
	return ur
}

type authToken struct {
	AccessToken string `json:"access_token"`
}

func (r *ibmcloud) newApiClient(password, ibmTokenUrl string) error {
	var err error
	r.apiClient = newHttpClient(r.proxy)
	if err = r.aquireToken(password, ibmTokenUrl); err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "x509:") {
		r.apiClient = newHttpClient(r.proxy)
		return r.aquireToken(password, ibmTokenUrl)
	} else {
		return err
	}
}

func (r *ibmcloud) aquireToken(password, ibmTokenUrl string) error {
	params := url.Values{}
	params.Add("grant_type", grantType)
	params.Add("apikey", password)

	var data []byte
	data = []byte(params.Encode())

	request, err := http.NewRequest("POST", ibmTokenUrl, bytes.NewReader(data))

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")

	response, err := r.apiClient.Do(request)
	if err != nil {
		smd.scanLog.WithFields(log.Fields{"error": err}).Error("get IBM Cloud IAM access token fail")
		return err
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		smd.scanLog.WithFields(log.Fields{"StatusCode": response.StatusCode}).Debug("aquire token fail")
		return fmt.Errorf("fail to get the IBM Cloud IAM access token")
	}

	var authToken authToken
	decoder := json.NewDecoder(response.Body)
	err = decoder.Decode(&authToken)
	if err != nil {
		return err
	}
	r.iamOauthToken = authToken.AccessToken
	return nil
}

func (r *ibmcloud) Login(cfg *share.CLUSRegistryConfig) (error, string) {
	r.account = cfg.IBMCloudAccount

	if err := r.newApiClient(cfg.Password, cfg.IBMCloudTokenURL); err != nil {
		return err, err.Error()
	}

	r.newRegClient(cfg.Registry, cfg.Username, cfg.Password)

	r.images = make(map[string][]*ibmImage)
	return nil, ""
}

func (r *ibmcloud) getImages() ([]ibmImage, error) {
	ur := r.ibmUrl("api/v1/images")
	smd.scanLog.WithFields(log.Fields{"url": ur}).Debug("")

	request, err := http.NewRequest("GET", ur, nil)
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", r.iamOauthToken))
	request.Header.Set("Account", r.account)
	resp, err := r.apiClient.Do(request)
	if err != nil {
		smd.scanLog.WithFields(log.Fields{"error": err}).Debug("get images fail")
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var repos []ibmImage
	err = json.Unmarshal(data, &repos)
	if err != nil {
		return nil, err
	}
	return repos, nil
}

func (r *ibmcloud) GetRepoList(org, name string, limit int) ([]*share.CLUSImage, error) {
	smd.scanLog.Debug("")
	if !strings.Contains(name, "*") {
		if org == "" {
			return []*share.CLUSImage{&share.CLUSImage{Repo: name}}, nil
		} else {
			return []*share.CLUSImage{&share.CLUSImage{Repo: fmt.Sprintf("%s/%s", org, name)}}, nil
		}
	}
	images, err := r.getImages()
	if err != nil {
		return nil, err
	}
	r.images = make(map[string][]*ibmImage)
	repos := make([]*share.CLUSImage, 0)
	for _, im := range images {
		image := &ibmImage{RepoTags: im.RepoTags}
		for _, rep := range im.RepoTags {
			if repo := getRepoName(rep); repo != "" {
				if ims, ok := r.images[repo]; ok {
					ims = append(ims, image)
					r.images[repo] = ims
				} else {
					r.images[repo] = []*ibmImage{image}
				}
			}
		}
	}
	for rep, _ := range r.images {
		image := &share.CLUSImage{Repo: rep}
		repos = append(repos, image)
	}
	return repos, nil
}

func (r *ibmcloud) GetTagList(doamin, repo, tag string) ([]string, error) {
	smd.scanLog.Debug("")
	images, ok := r.images[repo]
	if !ok {
		return nil, fmt.Errorf("repository for tag not found")
	}
	tags := make([]string, 0)
	for _, image := range images {
		for _, rep := range image.RepoTags {
			if name := getRepoName(rep); name == repo {
				if a := strings.LastIndex(rep, ":"); a > 0 {
					tag := rep[a+1:]
					tags = append(tags, tag)
				}
			}
		}
	}
	return tags, nil
}

func getRepoName(repo string) string {
	var name string
	// remove the hostname
	if a := strings.Index(repo, "/"); a > 0 {
		name = repo[a+1:]
	}

	if a := strings.LastIndex(name, ":"); a > 0 {
		name = name[:a]
	}

	return name
}

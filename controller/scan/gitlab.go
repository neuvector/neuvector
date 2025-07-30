package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/httpclient"
	"github.com/neuvector/neuvector/share/utils"
)

const gitTimeout = 20 * time.Second
const apiVersion = "api/v4"
const noNextPageURL = ""

type gitlab struct {
	base
	apiUrl       string
	privateToken string
	gitlabClient *http.Client
	repoIdMap    map[string]*gitRepo
}

type gitProject struct {
	ID                int    `json:"id"`
	Name              string `json:"name"`
	Path              string `json:"path"`
	PathWithNamespace string `json:"path_with_namespace"`
	WebURL            string `json:"web_url"`
}

type gitGroup struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Path string `json:"path"`
}

type gitUser struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
}

type gitRepository struct {
	ID        int       `json:"id"`
	Name      string    `json:"name"`
	Path      string    `json:"path"`
	Location  string    `json:"location"`
	CreatedAt time.Time `json:"created_at"`
}

type gitTag struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Location string `json:"location"`
}

type gitRepo struct {
	project int
	repo    int
}

func (r *gitlab) gitUrl(pathTemplate string, args ...interface{}) string {
	pathSuffix := fmt.Sprintf(pathTemplate, args...)
	ur := fmt.Sprintf("%s%s%s", r.apiUrl, apiVersion, pathSuffix)
	return ur
}

func newHttpClient(proxy string) *http.Client {
	client := &http.Client{
		Timeout: gitTimeout,
	}

	t, err := httpclient.GetTransport(proxy)
	if err != nil {
		log.WithError(err).Warn("failed to get transport")
		return nil
	}
	client.Transport = t

	return client
}

func (r *gitlab) newGitlabClient() {
	var proxy string
	if !r.ignoreProxy {
		proxy = GetProxy(r.apiUrl)
	}
	r.gitlabClient = newHttpClient(proxy)
}

func (r *gitlab) Login(cfg *share.CLUSRegistryConfig) (error, string) {
	r.apiUrl = cfg.GitlabApiUrl
	r.privateToken = cfg.GitlabPrivateToken

	r.newGitlabClient()
	if err := r.newRegClient(cfg.Registry, cfg.Username, cfg.Password); err != nil {
		return err, err.Error()
	}

	if _, err := r.rc.Alive(); err != nil {
		return err, err.Error()
	}

	r.repoIdMap = make(map[string]*gitRepo)
	return nil, ""
}

func (r *gitlab) getData(ur string) ([]byte, string, error) {
	request, _ := http.NewRequest("GET", ur, nil)
	request.Header.Add("PRIVATE-TOKEN", r.privateToken)
	resp, err := r.gitlabClient.Do(request)
	if err != nil {
		return nil, noNextPageURL, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, noNextPageURL, err
	}
	nextURL := noNextPageURL
	// support query with pagination
outerLoop:
	for _, h := range []string{"Link", "link"} {
		if links := resp.Header.Get(h); links != "" {
			// example of Link header: <http://.....>; rel="next", <http://.....>; rel="first", <http://.....>; rel="last"
			for _, pair := range strings.Split(links, ",") {
				pair = strings.TrimSpace(pair)
				if ss := strings.Split(pair, ";"); len(ss) == 2 {
					relStr := strings.TrimSpace(ss[1])
					if relStr == `rel="next"` {
						nextURL = strings.TrimSpace(ss[0])
						nextURL = strings.Trim(nextURL, "<>")
						break outerLoop
					}
				}
			}
		}
	}
	if len(data) == 0 {
		data = []byte("[]")
	}
	return data, nextURL, nil
}

func getResources[V gitUser | gitGroup | gitRepository | gitTag](r *gitlab, ur string) ([]V, error) {
	var all []V

	for {
		smd.scanLog.WithFields(log.Fields{"url": ur}).Debug()
		data, nextURL, err := r.getData(ur)
		if err == nil {
			var resources []V
			if err = json.Unmarshal(data, &resources); err == nil {
				if len(resources) == 0 {
					nextURL = noNextPageURL
				} else {
					all = append(all, resources...)
				}
			}
		}
		if nextURL == noNextPageURL {
			if len(all) > 0 {
				err = nil
			}
			return all, err
		}
		ur = nextURL
	}
}

func (r *gitlab) getUsers() ([]gitUser, error) {
	ur := r.gitUrl("/users")
	return getResources[gitUser](r, ur)
}

func (r *gitlab) getGroups() ([]gitGroup, error) {
	ur := r.gitUrl("/groups")
	return getResources[gitGroup](r, ur)
}

func (r *gitlab) getProjectResources(ur string, all []gitProject) ([]gitProject, error) {
	var e error

	for {
		smd.scanLog.WithFields(log.Fields{"url": ur}).Debug()
		data, nextURL, err := r.getData(ur)
		if err == nil {
			var projects []gitProject
			if err = json.Unmarshal(data, &projects); err == nil {
				if len(projects) == 0 {
					nextURL = noNextPageURL
				} else {
					all = append(all, projects...)
				}
			}
		}
		if nextURL == noNextPageURL {
			if len(all) == 0 && err != nil {
				e = err
			}
			break
		}
		ur = nextURL
	}

	return all, e
}

func (r *gitlab) getProjects() ([]gitProject, error) {
	var all []gitProject
	var projectErr, userProjectErr, groupProjectErr error
	var err error

	ur := r.gitUrl("/projects")
	if all, err = r.getProjectResources(ur, all); err != nil {
		projectErr = err
	}

	// get user projects
	if users, err := r.getUsers(); len(users) > 0 {
		for _, user := range users {
			ur = r.gitUrl("/users/%d/projects", user.ID)
			if all, err = r.getProjectResources(ur, all); err != nil {
				userProjectErr = err
			}
		}
	} else if err != nil {
		userProjectErr = err
	}
	ur = r.gitUrl("/users/%s/projects", r.username)
	if all, err = r.getProjectResources(ur, all); err != nil {
		userProjectErr = err
	}

	// get group projects
	if groups, err := r.getGroups(); len(groups) > 0 {
		for _, group := range groups {
			ur = r.gitUrl("/groups/%d/projects?include_subgroups=true", group.ID)
			if all, err = r.getProjectResources(ur, all); err != nil {
				groupProjectErr = err
			}
		}
	} else if err != nil {
		groupProjectErr = err
	}

	if len(all) == 0 {
		if projectErr != nil {
			return nil, projectErr
		} else if userProjectErr != nil {
			return nil, userProjectErr
		} else if groupProjectErr != nil {
			return nil, groupProjectErr
		}
	}

	// remove duplication
	ids := utils.NewSet()
	projects := make([]gitProject, 0)
	for _, p := range all {
		if !ids.Contains(p.ID) {
			ids.Add(p.ID)
			projects = append(projects, p)
		}
	}
	return projects, nil
}

func (r *gitlab) getRepos(id int) ([]gitRepository, error) {
	ur := r.gitUrl("/projects/%d/registry/repositories", id)
	return getResources[gitRepository](r, ur)
}

func (r *gitlab) getTags(id, repo int) ([]gitTag, error) {
	ur := r.gitUrl("/projects/%d/registry/repositories/%d/tags", id, repo)
	return getResources[gitTag](r, ur)
}

func (r *gitlab) GetRepoList(org, name string, limit int) ([]*share.CLUSImage, error) {
	smd.scanLog.Debug("")

	repos := make([]*share.CLUSImage, 0)
	projects, err := r.getProjects()
	if err != nil {
		return nil, err
	}

	for _, project := range projects {
		rps, err := r.getRepos(project.ID)
		if err != nil {
			smd.scanLog.WithFields(log.Fields{"error": err, "project": project.PathWithNamespace}).Error()
			continue
		}
		for _, rp := range rps {
			repos = append(repos, &share.CLUSImage{Repo: rp.Path})
			r.repoIdMap[rp.Path] = &gitRepo{project: project.ID, repo: rp.ID}
		}
	}

	return repos, nil
}

func (r *gitlab) GetTagList(doamin, repo, tag string) ([]string, error) {
	smd.scanLog.Debug("")

	if rp, ok := r.repoIdMap[repo]; ok {
		if tags, err := r.getTags(rp.project, rp.repo); err == nil {
			ts := make([]string, len(tags))
			for i, tag := range tags {
				ts[i] = tag.Name
			}
			return ts, nil
		} else {
			return nil, err
		}
	}
	return nil, fmt.Errorf("cannot find the repository in map")
}

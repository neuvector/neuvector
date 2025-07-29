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

	if links := resp.Header.Get("Link"); links != "" {
		// example of Link header: <http://.....>; rel="next", <http://.....>; rel="first", <http://.....>; rel="last"
		for _, pair := range strings.Split(links, ",") {
			pair = strings.TrimSpace(pair)
			if ss := strings.Split(pair, ";"); len(ss) == 2 {
				relStr := strings.TrimSpace(ss[1])
				if relStr == `rel="next"` {
					nextURL = strings.TrimSpace(ss[0])
					nextURL = strings.Trim(nextURL, "<>")
					break
				}
			}
		}
	}
	if len(data) == 0 {
		data = []byte("[]")
	}
	return data, nextURL, nil
}

func (r *gitlab) getUsers() ([]gitUser, error) {
	var all []gitUser

	ur := r.gitUrl("/users")
	for {
		smd.scanLog.WithFields(log.Fields{"url": ur}).Debug()
		data, nextURL, err := r.getData(ur)
		if err == nil {
			var users []gitUser
			if err = json.Unmarshal(data, &users); err == nil {
				if len(users) == 0 {
					nextURL = noNextPageURL
				} else {
					all = append(all, users...)
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

func (r *gitlab) getGroups() ([]gitGroup, error) {
	var all []gitGroup

	ur := r.gitUrl("/groups")
	for {
		smd.scanLog.WithFields(log.Fields{"url": ur}).Debug()
		data, nextURL, err := r.getData(ur)
		if err == nil {
			var groups []gitGroup
			if err = json.Unmarshal(data, &groups); err == nil {
				if len(groups) == 0 {
					nextURL = noNextPageURL
				} else {
					all = append(all, groups...)
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

func (r *gitlab) getProjects() ([]gitProject, error) {
	var all []gitProject
	var e1, e2, e3 error

	ur := r.gitUrl("/projects")
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
				e1 = err
			}
			break
		}
		ur = nextURL
	}

	// get user projects
	if users, err := r.getUsers(); len(users) > 0 {
		for _, user := range users {
			ur = r.gitUrl("/users/%d/projects", user.ID)
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
						e2 = err
					}
					break
				}
				ur = nextURL
			}
		}
	} else if err != nil {
		e2 = err
	}
	ur = r.gitUrl("/users/%s/projects", r.username)
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
				e2 = err
			}
			break
		}
		ur = nextURL
	}

	// get group projects
	if groups, err := r.getGroups(); len(groups) > 0 {
		for _, group := range groups {
			ur = r.gitUrl("/groups/%d/projects?include_subgroups=true", group.ID)
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
						e3 = err
					}
					break
				}
				ur = nextURL
			}
		}
	} else if err != nil {
		e3 = err
	}

	if len(all) == 0 {
		if e1 != nil {
			return nil, e1
		} else if e2 != nil {
			return nil, e2
		} else if e3 != nil {
			return nil, e3
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
	var all []gitRepository

	ur := r.gitUrl("/projects/%d/registry/repositories", id)
	for {
		smd.scanLog.WithFields(log.Fields{"url": ur}).Debug()
		data, nextURL, err := r.getData(ur)
		if err == nil {
			var repos []gitRepository
			if err = json.Unmarshal(data, &repos); err == nil {
				if len(repos) == 0 {
					nextURL = noNextPageURL
				} else {
					all = append(all, repos...)
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

func (r *gitlab) getTags(id, repo int) ([]gitTag, error) {
	var all []gitTag

	ur := r.gitUrl("/projects/%d/registry/repositories/%d/tags", id, repo)
	for {
		smd.scanLog.WithFields(log.Fields{"url": ur}).Debug()
		data, nextURL, err := r.getData(ur)
		if err == nil {
			var tags []gitTag
			if err = json.Unmarshal(data, &tags); err == nil {
				if len(tags) == 0 {
					nextURL = noNextPageURL
				} else {
					all = append(all, tags...)
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

package registry

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"

	manifestV1 "github.com/docker/distribution/manifest/schema1"
	manifestV2 "github.com/docker/distribution/manifest/schema2"
	digest "github.com/opencontainers/go-digest"
	log "github.com/sirupsen/logrus"
)

const (
	MediaTypeOCIManifest = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeOCIIndex    = "application/vnd.oci.image.index.v1+json"

	MediaTypeOCIMissingManifest = "Accept header does not support OCI manifests"
	MediaTypeOCIMissingIndex    = "Accept header does not support OCI indexes"
)

type ManifestInfo struct {
	SignedManifest *manifestV1.SignedManifest
	Digest         string
	RunAsRoot      bool
	Author         string
	Envs           []string
	Cmds           []string
	Labels         map[string]string
}

func (r *Registry) ManifestRequest(ctx context.Context, repository, reference string, schema int) (string, []byte, error) {
	url := r.url("/v2/%s/manifests/%s", repository, reference)
	log.WithFields(log.Fields{"url": url, "repository": repository, "ref": reference, "schema": schema}).Debug()

	r.Client.SetTimeout(nonDataTimeout)

	var resp *http.Response
	var req *http.Request
	var err error
	retry := 0
	withOCIManifest := false
	withOCIIndex := false
	for retry < retryTimes {
		req, err = http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return "", nil, err
		}
		switch schema {
		case 1:
			req.Header.Add("Accept", manifestV1.MediaTypeManifest)
			req.Header.Add("Accept", manifestV1.MediaTypeSignedManifest)
			if withOCIManifest {
				req.Header.Add("Accept", MediaTypeOCIManifest)
			}
			if withOCIIndex {
				req.Header.Add("Accept", MediaTypeOCIIndex)
			}
		case 2:
			req.Header.Add("Accept", manifestV2.MediaTypeManifest)
			if withOCIManifest {
				req.Header.Add("Accept", MediaTypeOCIManifest)
			}
			if withOCIIndex {
				req.Header.Add("Accept", MediaTypeOCIIndex)
			}
		default:
			return "", nil, errors.New("Unsupported manifest schema version")
		}

		reqWithContext := req.WithContext(ctx)
		resp, err = r.Client.Do(reqWithContext)
		if err == nil {
			break
		}

		if ctx.Err() == context.Canceled {
			return "", nil, ctx.Err()
		}

		if !withOCIManifest && strings.Contains(strings.ToLower(err.Error()), strings.ToLower(MediaTypeOCIMissingManifest)) {
			withOCIManifest = true
		} else if !withOCIIndex && strings.Contains(strings.ToLower(err.Error()), strings.ToLower(MediaTypeOCIMissingIndex)) {
			withOCIIndex = true
		} else {
			retry++
		}
	}
	if err != nil {
		return "", nil, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err
	}

	dg, _ := digest.Parse(resp.Header.Get("Docker-Content-Digest"))

	return string(dg), body, nil
}

func (r *Registry) Manifest(ctx context.Context, repository, reference string) (*ManifestInfo, error) {
	dg, body, err := r.ManifestRequest(ctx, repository, reference, 1)
	if err != nil {
		return nil, err
	}

	mi, err := r.parseHistory(body)
	if err != nil {
		return nil, err
	}

	signedManifest := &manifestV1.SignedManifest{}
	err = signedManifest.UnmarshalJSON(body)
	if err != nil {
		// for nexus no signatures in the response
		var manifest manifestV1.Manifest
		if err := json.Unmarshal(body, &manifest); err != nil {
			return nil, err
		}
		signedManifest.Manifest = manifest
	}
	mi.SignedManifest = signedManifest
	mi.Digest = dg
	return mi, nil
}

func (r *Registry) ManifestV2(ctx context.Context, repository, reference string) (*manifestV2.DeserializedManifest, string, error) {
	dg, body, err := r.ManifestRequest(ctx, repository, reference, 2)
	if err != nil {
		return nil, "", err
	}

	deserialized := &manifestV2.DeserializedManifest{}
	err = deserialized.UnmarshalJSON(body)
	if err != nil {
		return nil, "", err
	}
	return deserialized, dg, nil
}

type manifestData struct {
	SchemaVersion int    `json:"schemaVersion"`
	Name          string `json:"name"`
	Tag           string `json:"tag"`
	Architecture  string `json:"architecture"`
	FsLayers      []struct {
		BlobSum string `json:"blobSum"`
	} `json:"fsLayers"`
	History []struct {
		V1Compatibility string `json:"v1Compatibility"`
	} `json:"history"`
	Signatures []struct {
		Header struct {
			Jwk struct {
				Crv string `json:"crv"`
				Kid string `json:"kid"`
				Kty string `json:"kty"`
				X   string `json:"x"`
				Y   string `json:"y"`
			} `json:"jwk"`
			Alg string `json:"alg"`
		} `json:"header"`
		Signature string `json:"signature"`
		Protected string `json:"protected"`
	} `json:"signatures"`
}

type containerConfigData struct {
	ID              string    `json:"id"`
	Author          string    `json:"author"`
	Parent          string    `json:"parent"`
	Created         time.Time `json:"created"`
	ContainerConfig struct {
		Env    []string          `json:"Env"`
		Cmd    []string          `json:"Cmd"`
		Labels map[string]string `json:"Labels"`
	} `json:"container_config"`
	Config struct {
		Env    []string          `json:"Env"`
		Cmd    []string          `json:"Cmd"`
		Labels map[string]string `json:"Labels"`
	} `json:"config"`
}

type containerConfig2Data struct {
	ID      string    `json:"id"`
	Parent  string    `json:"parent"`
	Created time.Time `json:"created"`
	Cmd     struct {
		ContainerConfig string `json:"container_config"`
	} `json:"Cmd"`
}

var userRegexp = regexp.MustCompile(`USER \[([a-zA-Z0-9_\-\.]+)\]`)

func (r *Registry) parseHistory(body []byte) (*ManifestInfo, error) {
	var manData manifestData
	var userFound bool

	info := ManifestInfo{RunAsRoot: true, Labels: make(map[string]string)}
	if err := json.Unmarshal(body, &manData); err == nil {
		for _, comp := range manData.History {
			v1com := comp.V1Compatibility
			var cmd string
			var confData containerConfigData
			if err := json.Unmarshal([]byte(v1com), &confData); err == nil {
				if info.Author == "" {
					info.Author = confData.Author
				}
				if len(confData.ContainerConfig.Cmd) > 0 {
					cmd = strings.Join(confData.ContainerConfig.Cmd, " ")
				} else if len(confData.Config.Cmd) > 0 {
					cmd = strings.Join(confData.ContainerConfig.Cmd, " ")
				}
				if confData.ContainerConfig.Env != nil {
					info.Envs = append(info.Envs, confData.ContainerConfig.Env...)
				} else if confData.Config.Env != nil {
					info.Envs = append(info.Envs, confData.ContainerConfig.Env...)
				}
				if confData.ContainerConfig.Labels != nil {
					for k, v := range confData.ContainerConfig.Labels {
						info.Labels[k] = v
					}
				} else if confData.Config.Labels != nil {
					for k, v := range confData.Config.Labels {
						info.Labels[k] = v
					}
				}
			}
			// for nexus registry has different cmd json format
			var conf2Data containerConfig2Data
			if err := json.Unmarshal([]byte(v1com), &conf2Data); err == nil {
				if conf2Data.Cmd.ContainerConfig != "" {
					cmd = conf2Data.Cmd.ContainerConfig
				}
			}

			info.Cmds = append(info.Cmds, cmd)
			if !userFound {
				r := userRegexp.FindStringSubmatch(cmd)
				if len(r) == 2 {
					if r[1] == "root" {
						info.RunAsRoot = true
					} else {
						info.RunAsRoot = false
					}
					userFound = true
				}
			}
		}
	} else {
		return nil, err
	}
	return &info, nil
}

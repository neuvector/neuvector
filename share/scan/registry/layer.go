package registry

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/docker/distribution"
	digest "github.com/opencontainers/go-digest"
	log "github.com/sirupsen/logrus"
)

const dataTimeout = 10 * time.Minute
const retryTimes = 3

func (registry *Registry) DownloadLayer(ctx context.Context, repository string, digest digest.Digest) (io.ReadCloser, int64, error) {
	url := registry.url("/v2/%s/blobs/%s", repository, digest)
	log.WithFields(log.Fields{"url": url, "repository": repository, "digest": digest}).Debug()

	registry.Client.SetTimeout(dataTimeout)

	var resp *http.Response
	var req *http.Request
	var err error
	retry := 0
	for retry < retryTimes {
		req, err = http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, -1, err
		}
		reqWithContext := req.WithContext(ctx)

		resp, err = registry.Client.Do(reqWithContext)
		if err == nil {
			return resp.Body, resp.ContentLength, nil
		}

		log.WithFields(log.Fields{"error": err}).Error()
		if ctx.Err() == context.Canceled {
			return nil, -1, ctx.Err()
		}

		retry++
	}

	return nil, -1, err
}

func (registry *Registry) UploadLayer(repository string, digest digest.Digest, content io.Reader) error {
	uploadUrl, err := registry.initiateUpload(repository)
	if err != nil {
		return err
	}
	q := uploadUrl.Query()
	q.Set("digest", digest.String())
	uploadUrl.RawQuery = q.Encode()

	log.WithFields(log.Fields{"url": uploadUrl, "repository": repository, "digest": digest}).Debug()

	upload, err := http.NewRequest("PUT", uploadUrl.String(), content)
	if err != nil {
		return err
	}
	upload.Header.Set("Content-Type", "application/octet-stream")

	_, err = registry.Client.Do(upload)
	return err
}

func (registry *Registry) HasLayer(repository string, digest digest.Digest) (bool, error) {
	checkUrl := registry.url("/v2/%s/blobs/%s", repository, digest)
	log.WithFields(log.Fields{"url": checkUrl, "repository": repository, "digest": digest}).Debug()

	registry.Client.SetTimeout(nonDataTimeout)
	resp, err := registry.Client.Head(checkUrl)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err == nil {
		return resp.StatusCode == http.StatusOK, nil
	}

	urlErr, ok := err.(*url.Error)
	if !ok {
		return false, err
	}
	httpErr, ok := urlErr.Err.(*HttpStatusError)
	if !ok {
		return false, err
	}
	if httpErr.Response.StatusCode == http.StatusNotFound {
		return false, nil
	}

	return false, err
}

func (registry *Registry) LayerMetadata(repository string, digest digest.Digest) (distribution.Descriptor, error) {
	checkUrl := registry.url("/v2/%s/blobs/%s", repository, digest)
	log.WithFields(log.Fields{"url": checkUrl, "repository": repository, "digest": digest}).Debug()

	registry.Client.SetTimeout(nonDataTimeout)
	resp, err := registry.Client.Head(checkUrl)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return distribution.Descriptor{}, err
	}

	return distribution.Descriptor{
		Digest: digest,
		Size:   resp.ContentLength,
	}, nil
}

func (registry *Registry) initiateUpload(repository string) (*url.URL, error) {
	initiateUrl := registry.url("/v2/%s/blobs/uploads/", repository)
	log.WithFields(log.Fields{"url": initiateUrl, "repository": repository}).Debug()

	resp, err := registry.Client.Post(initiateUrl, "application/octet-stream", nil)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}

	location := resp.Header.Get("Location")
	locationUrl, err := url.Parse(location)
	if err != nil {
		return nil, err
	}
	return locationUrl, nil
}

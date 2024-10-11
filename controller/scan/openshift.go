package scan

import (
	"context"
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/controller/resource"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/global"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/scan/registry"
)

const unusedAccount string = "UNUSED"
const renewTokenDuration time.Duration = time.Duration(time.Minute * 30)

type openshift struct {
	regCfg      *share.CLUSRegistryConfig
	lastLoginAt time.Time
	base
}

func (r *openshift) Login(cfg *share.CLUSRegistryConfig) (error, string) {
	if r.regCfg != nil && time.Since(r.lastLoginAt) < renewTokenDuration {
		return nil, ""
	}

	r.regCfg = cfg
	if cfg.AuthWithToken {
		smd.scanLog.WithFields(log.Fields{"registry": r.regCfg.Name}).Debug("Login with token")
		r.lastLoginAt = time.Now()
		r.newRegClient(cfg.Registry, unusedAccount, cfg.AuthToken)
		r.rc.Alive()
		return nil, ""
	} else {
		username, token, err := global.ORCH.Login(cfg.Username, cfg.Password)
		if err != nil {
			return err, err.Error()
		}

		smd.scanLog.WithFields(log.Fields{"registry": r.regCfg.Name}).Debug("Login succeeded")
		r.lastLoginAt = time.Now()
		r.newRegClient(cfg.Registry, username, token)
		return nil, ""
	}
}

func (r *openshift) Logout(force bool) {
	if !force || r.regCfg == nil {
		return
	}

	smd.scanLog.WithFields(log.Fields{"registry": r.regCfg.Name}).Debug("Force logout")
	if !r.regCfg.AuthWithToken {
		global.ORCH.Logout(r.username, r.password)
	}
	r.lastLoginAt = time.Time{} // reset timer
}

func (r *openshift) renewToken() error {
	if time.Since(r.lastLoginAt) > renewTokenDuration {
		smd.scanLog.WithFields(log.Fields{"registry": r.regCfg.Name}).Debug("Renew")

		r.Logout(true)
		err, _ := r.Login(r.regCfg)
		return err
	}

	return nil
}

func (r *openshift) GetRepoList(org, name string, limit int) ([]*share.CLUSImage, error) {
	smd.scanLog.Debug()

	var list []*share.CLUSImage

	if !strings.Contains(name, "*") {
		var repo string

		if org == "" {
			repo = name
		} else {
			repo = fmt.Sprintf("%s/%s", org, name)
		}

		list = make([]*share.CLUSImage, 0)

		ibMutex.RLock()
		defer ibMutex.RUnlock()

		for img := range imageBank {
			if repo == img.Repo {
				dup := img
				list = append(list, &dup)
			}
		}
	} else {
		ibMutex.RLock()
		defer ibMutex.RUnlock()

		list = make([]*share.CLUSImage, len(imageBank))

		i := 0
		for img := range imageBank {
			dup := img
			list[i] = &dup
			i++
		}
	}

	return list, nil
}

func (r *openshift) GetTagList(domain, repo, tag string) ([]string, error) {
	smd.scanLog.Debug()

	list := make([]string, 0)

	ibMutex.RLock()
	defer ibMutex.RUnlock()

	for img, tags := range imageBank {
		if img.Repo == repo && (domain == "" || img.Domain == domain) {
			for tag := range tags.Iter() {
				list = append(list, tag.(resource.ImageTag).Tag)
			}
		}
	}

	return list, nil
}

func (r *openshift) GetImageMeta(ctx context.Context, domain, repo, tag string) (*scanUtils.ImageInfo, share.ScanErrorCode) {
	img := share.CLUSImage{Repo: repo, Domain: domain, Tag: tag}
	ibMutex.RLock()
	meta, ok := imageMetaBank[img]
	ibMutex.RUnlock()
	if ok {
		return meta, share.ScanErrorCode_ScanErrNone
	}

	if err := r.renewToken(); err != nil {
		smd.scanLog.WithFields(log.Fields{"registry": r.regCfg.Name, "error": err}).Error()
		return nil, share.ScanErrorCode_ScanErrContainerAPI
	}

	rinfo, errCode := r.rc.GetImageInfo(ctx, repo, tag, registry.ManifestRequest_Default)

	if errCode == share.ScanErrorCode_ScanErrNone {
		ibMutex.Lock()
		imageMetaBank[img] = rinfo
		ibMutex.Unlock()
	}
	return rinfo, errCode
}

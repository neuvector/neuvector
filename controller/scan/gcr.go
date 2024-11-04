package scan

import (
	"github.com/neuvector/neuvector/share"
)

const gcrDefaultUsername = "_json_key"

type gcrDriver struct {
	base
}

func (r *gcrDriver) Login(cfg *share.CLUSRegistryConfig) (error, string) {
	if err := r.newRegClient(cfg.Registry, gcrDefaultUsername, cfg.GcrKey.JsonKey); err != nil {
		return err, err.Error()
	}

	if _, err := r.rc.Alive(); err != nil {
		return err, err.Error()
	}

	return nil, ""
}

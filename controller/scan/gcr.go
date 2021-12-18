package scan

import (
	"github.com/neuvector/neuvector/share"
)

const gcrDefaultUsername = "_json_key"

type gcrDriver struct {
	base
}

func (r *gcrDriver) Login(cfg *share.CLUSRegistryConfig) (error, string) {
	r.newRegClient(cfg.Registry, gcrDefaultUsername, cfg.GcrKey.JsonKey)
	r.rc.Alive()
	return nil, ""
}

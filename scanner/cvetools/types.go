package cvetools

import (
	"sync"

	"github.com/neuvector/neuvector/scanner/common"
	"github.com/neuvector/neuvector/scanner/detectors"
	"github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
)

type updateData struct {
	Redhat bool
	Debian bool
	Ubuntu bool
	Alpine bool
	Amazon bool
	Oracle bool
}

type CveTools struct {
	TbPath          string
	RtSock          string
	CveDBVersion    string
	CveDBCreateTime string
	UpdateMux       sync.RWMutex
	Update          updateData
	SupportOs       utils.Set
	ScanTool        *scan.ScanUtil
}

type vulShortReport struct {
	Vs common.VulShort
	Ft detectors.FeatureVersion
}

type vulFullReport struct {
	Vf common.VulFull
	Ft detectors.FeatureVersion
}

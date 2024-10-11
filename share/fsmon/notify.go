package fsmon

import (
	"regexp"
	"sync"
)

type NotifyCallback func(path string, mask uint32, params interface{}, pInfo *ProcInfo)

type filterRegex struct {
	path      string
	regex     *regexp.Regexp
	recursive bool
}

type IFile struct {
	path    string
	mask    uint64
	cb      NotifyCallback
	params  interface{}
	wd      int
	dir     bool
	files   map[string]interface{}
	filter  *filterRegex
	protect bool // access control
	learnt  bool // discover mode
	userAdd bool
	lastChg int64 // unix time
}

type fNotify struct {
	mux sync.RWMutex
}

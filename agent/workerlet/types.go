package workerlet

import (
	"os"
	"time"

	"github.com/neuvector/neuvector/share"
)

const WalkerApp = "/usr/local/bin/pathWalker"
const WalkerBasePath = "/tmp/walk"
const RequestJson = "request.json" // default request file
const ResultJson = "result1.json"  // default output file
const ResultJson2 = "result2.json" // default output file

type WalkPathRequest struct {
	Pid      int           `json:"pid"`
	Path     string        `json:"path"`
	ExecOnly bool          `json:"ExecOnly"`
	Timeout  time.Duration `json:"Timeout"`
	Dirs     []string      `json:"Directories"`
}

type WalkGetPackageRequest struct {
	Pid          int                  `json:"pid"`
	Id           string               `json:"id"`
	Kernel       string               `json:"kernel"`
	ObjType      share.ScanObjectType `json:"objType"`
	PidHost      bool                 `json:"pidHost"`
	K8sAppString string               `json:"k8sAppRscString"`
}

type WalkSecretRequest struct {
	Pid         int     `json:"pid"`
	MaxFileSize int     `json:"maxSize"`    // default: 0 as 4kb, -1 as any size
	MiniWeight  float64 `json:"miniWeight"` // minimum portion of a secret file, excluding x.509, <= 0.0: no minimum
	TimeoutSec  uint    `json:"timeout"`    // in seconds
}

type FInfo struct {
	Name    string      `json:"name"`
	Size    int64       `json:"size"`
	Mode    os.FileMode `json:"mode"`
	ModTime time.Time   `json:"modTime"`
	IsDir   bool        `json:"isDir"`
}

type DirData struct {
	Dir  string `json:"dir"`
	Info FInfo  `json:"FileInfo"`
}

type FileData struct {
	File   string `json:"file"`
	IsExec bool   `json:"isExec"`
	Hash   uint32 `json:"Hash"`
	Info   FInfo  `json:"FileInfo"`
}

type WalkPathResult struct {
	Dirs  []*DirData  `json:"dirs"`
	Files []*FileData `json:"files"`
}

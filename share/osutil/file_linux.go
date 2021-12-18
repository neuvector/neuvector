package osutil

import (
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/utils"
)

const (
	linkMaxLayers     = 5
	fileSizeHashLimit = 16 * 1024
	fileHashKeep      = 8
)

// true is package file, to trigger re-scan
var packageFiles utils.Set = utils.NewSet(
	"/var/lib/dpkg/status",
	"/var/lib/rpm/Packages",
	"/lib/apk/db/installed",
)

type FileInfoExt struct {
	ContainerId string
	Path        string
	Link        string
	FileMode    os.FileMode
	Size        int64
	Hash        [fileHashKeep]byte
	Filter      interface{}
	Children    []*FileInfoExt
	Protect     bool
	UserAdded   bool
}

//try to get sym link
func GetContainerRealFilePath(pid int, path string) (string, error) {
	retry := 0
	for retry < linkMaxLayers {
		linkPath, err := os.Readlink(path)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Debug("Read file link fail")
			return "", err
		}
		if !filepath.IsAbs(linkPath) {
			path = filepath.Dir(path) + "/" + linkPath
			path = filepath.Clean(path)
		} else {
			path = global.SYS.ContainerFilePath(pid, linkPath)
		}
		finfo, err := os.Lstat(path)
		if err == nil && (finfo.Mode()&os.ModeSymlink) == 0 {
			return path, nil
		}
		retry++
	}
	return "", fmt.Errorf("Get file symlink fail")
}

func GetExePathFromLink(pid int) (string, error) {
	filename := global.SYS.ContainerProcFilePath(pid, "/exe")
	path, err := os.Readlink(filename)
	if err != nil {
		return "", err
	}
	return path, nil
}

func GetFileHash(filepath string) ([fileHashKeep]byte, error) {
	//only hash the first 16k, if the file is too large
	buf := make([]byte, fileSizeHashLimit)
	f, err := os.Open(filepath)
	if err != nil {
		return [fileHashKeep]byte{}, err
	}
	defer f.Close()
	if n, err := f.Read(buf); err == nil {
		sh := sha256.Sum256(buf[:n])
		var ha [fileHashKeep]byte
		for i, v := range sh {
			if i >= fileHashKeep {
				break
			}
			ha[i] = v
		}
		return ha, nil
	} else {
		if err.Error() == "EOF" { // it is there but an empty file
			err = nil
		}
		return [fileHashKeep]byte{}, err
	}
}

func IsPackageLib(path string) bool {
	return packageFiles.Contains(path)
}

func GetFileInfoExtFromPid(root, pid int) []*FileInfoExt {
	if path, err := GetExePathFromLink(pid); err == nil {
		filePath := global.SYS.ContainerFilePath(root, path)
		return GetFileInfoExtFromPath(root, filePath, "", false, true) // TODO: user-added?
	} else {
		return nil
	}
}

//get the file information, if the file is a symlink, return both the symlink and the real file
func GetFileInfoExtFromPath(root int, path string, flt interface{}, protect, userAdded bool) []*FileInfoExt {
	files := make([]*FileInfoExt, 0)
	if info, err := os.Lstat(path); err == nil {
		finfo := &FileInfoExt{
			FileMode:  info.Mode(),
			Size:      info.Size(),
			Path:      path,
			Filter:    flt,
			Protect:   protect,
			UserAdded: userAdded,
		}
		//for symlink, we need to watch two of them, symlink and the real file
		//read the link and create a seperated file info.
		if (finfo.FileMode & os.ModeSymlink) != 0 {
			if rpath, err := GetContainerRealFilePath(root, path); err == nil {
				finfo.Link = rpath
				rinfo := &FileInfoExt{
					Path:    rpath,
					Filter:  flt,
					Protect: protect,
				}
				if info, err := os.Lstat(rpath); err == nil {
					rinfo.FileMode = info.Mode()
					rinfo.Size = info.Size()
					if rinfo.Hash, err = GetFileHash(rpath); err == nil {
						files = append(files, rinfo)
					}
				}
			} else {
				log.WithFields(log.Fields{"path": path, "err": err}).Debug("Get File symlink fail")
			}
		}
		//read the hash for all files
		if finfo.Hash, err = GetFileHash(finfo.Path); err == nil {
			files = append(files, finfo)
		}
		return files
	} else {
		return nil
	}
}

func HashZero(hash [fileHashKeep]byte) bool {
	return hash == [fileHashKeep]byte{}
}

func parseFilter(filter string) (string, string) {
	ss := strings.Split(filter, "/")
	var base string

	for _, s := range ss {
		if s == "" {
			continue
		}
		if strings.Contains(s, "*") {
			break
		}
		base += "/" + s
	}
	filter = strings.Replace(filter, ".", "\\.", -1)
	regexStr := strings.Replace(filter, "*", ".*", -1)
	return base, regexStr
}

func GetFileDirInfo(file string) FileInfoExt {
	dir := filepath.Dir(file)
	if info, err := os.Stat(dir); err == nil {
		return FileInfoExt{
			FileMode: info.Mode(),
			Path:     dir,
		}
	}
	return FileInfoExt{}
}

/////////
const ErrorNotDirectory string = "src is not a directory"

// CopyFile copies the contents of the file named src to the file named
// by dst. The file will be created if it does not already exist. If the
// destination file exists, all it's contents will be replaced by the contents
// of the source file. The file mode will be copied from the source and
// the copied data is synced/flushed to stable storage.
func CopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst) // remove existing file, too
	if err != nil {
		return err
	}

	defer func() {
		if e := out.Close(); e != nil {
			err = e
		}
	}()

	if _, err = io.Copy(out, in); err != nil {
		return err
	}

	if err = out.Sync(); err != nil {
		return err
	}

	si, err := os.Stat(src)
	if err != nil {
		return err
	}

	if err = os.Chmod(dst, si.Mode()); err != nil {
		return err
	}

	return err
}

// CopyDir recursively copies a directory tree, attempting to preserve permissions.
// Source directory must exist, destination directory must *not* exist.
// Symlinks are ignored and skipped.
func CopyDir(src string, dst string) error {
	src = filepath.Clean(src)
	dst = filepath.Clean(dst)
	si, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !si.IsDir() {
		return fmt.Errorf(ErrorNotDirectory)
	}

	// overwrite it even it already exists
	err = os.MkdirAll(dst, si.Mode())
	if err != nil {
		return err
	}

	entries, err := ioutil.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())
		if entry.IsDir() {
			err = CopyDir(srcPath, dstPath)
			if err != nil { // recursive
				return err
			}
		} else {
			// Skip symlinks
			if entry.Mode()&os.ModeSymlink != 0 {
				continue
			}

			err = CopyFile(srcPath, dstPath)
			if err != nil {
				return err
			}
		}
	}

	return err
}

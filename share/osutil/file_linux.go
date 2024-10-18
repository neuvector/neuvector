package osutil

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
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
	"/var/lib/rpm/Packages.db",
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

func fileExists(path string) bool {
	_, err := os.Lstat(path)
	if err == nil {
		// No error, file exists and is accessible
		return true
	}

	if errors.Is(err, os.ErrNotExist) {
		return false
	}

	if os.IsPermission(err) {
		log.WithError(err).Error("Permission error accessing file")
		return false
	}

	// Other types of errors
	log.WithError(err).Error("")
	return false
}

func extractProcRootPath(pid int, input string, inTest bool) (string, error) {
	if inTest {
		// Since we use os.MkdirTemp("", "proc") to mock proc file system
		// Regular expression to match the pattern /proc/[number]/root/
		re := regexp.MustCompile(`.*/proc/\d+/root/`)
		matches := re.FindStringSubmatch(input)

		if len(matches) == 0 {
			return "", fmt.Errorf("no match found")
		}
		return matches[0], nil
	} else {
		return fmt.Sprintf(global.SYS.GetProcDir()+"%d/root", pid), nil
	}
}

// GetContainerRealFilePath resolves the real file path of a container file from a given symlink.
// It handles nested symlinks and detects circular references to prevent infinite loops.
// Input: pid (process id), symlinkPath (path of the symlink)
// Output: real file path (string) or an error if the resolution fails.
func GetContainerRealFilePath(pid int, symlinkPath string, inTest bool) (string, error) {
	var symlink, procRoot, currentPath, resolvedPath string
	var err error

	// Flag to check if the current path is under the process root.
	var underProcRoot bool

	// Keeps track of already visited symlinks to detect loops.
	visitedSymlink := make(map[string]struct{})
	currentPath = symlinkPath

	// Nest symlink would look for the the symlink for many times, we limit it to 5 layer of searching of its symlink.
	layer := 0
	for ; layer < linkMaxLayers; layer++ {
		underProcRoot = false

		if _, exists := visitedSymlink[currentPath]; exists {
			return "", fmt.Errorf("Error: Circular symlink detected. The symlink structure creates a loop and cannot be resolved.")
		}

		if !fileExists(currentPath) {
			log.WithError(err).Debug("File not exist")
			return "", err
		}

		if symlink, err = os.Readlink(currentPath); err != nil {
			log.WithError(err).Debug("Read file link fail")
			return "", err
		}

		if procRoot, err = extractProcRootPath(pid, currentPath, inTest); err != nil {
			log.WithError(err).Debug("Get Proc Root Path fail")
			return "", err
		}

		// if absolute symlink, we will join with procroot directly.
		if filepath.IsAbs(symlink) {
			resolvedPath = filepath.Join(procRoot, symlink)
			underProcRoot = true
		} else {
			parts := strings.Split(symlink, "/")
			for i := range parts {
				partialSymlink := strings.Join(parts[i:], "/")
				resolvedPath = filepath.Join(filepath.Dir(currentPath), partialSymlink)
				// Assume the first resolved path under proc root is the correct path
				if strings.HasPrefix(resolvedPath, procRoot) {
					underProcRoot = true
					break
				}
			}
		}

		visitedSymlink[currentPath] = struct{}{}
		if underProcRoot {
			// nest link
			finfo, err := os.Lstat(resolvedPath)
			if err != nil {
				log.WithError(err).Debug("failed to read resolvedPath")
				return "", err
			}
			if finfo.Mode()&os.ModeSymlink == 0 {
				// Not a symlink
				return resolvedPath, nil
			}
			currentPath = resolvedPath
		} else {
			return "", errors.New("failed to resolve symlink")
		}
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

// get the file information, if the file is a symlink, return both the symlink and the real file
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
			if rpath, err := GetContainerRealFilePath(root, path, false); err == nil {
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

/*
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
*/

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

// ///////
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
		return errors.New(string(ErrorNotDirectory))
	}

	// overwrite it even it already exists
	err = os.MkdirAll(dst, si.Mode())
	if err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
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
			if entry.Type()&os.ModeSymlink != 0 {
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

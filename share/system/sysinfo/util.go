// Copyright © 2016 Zlatko Čalušić
//
// Use of this source code is governed by an MIT-style license that can be found in the LICENSE file.

package sysinfo

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func joinLink(root, link, dir string) string {
	var path string
	if filepath.IsAbs(link) {
		path = filepath.Join(root, link)
	} else {
		path = filepath.Join(dir, link)
		path = filepath.Join(root, path)
	}
	return path
}

// Read one-liner text files, strip newline.
func slurpFile(path string) string {
	path = fmt.Sprintf("%s%s", rootPathPrefix, path)
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(data))
}

// Write one-liner text files, add newline, ignore errors (best effort).
func spewFile(path string, data string, perm os.FileMode) {
	path = fmt.Sprintf("%s%s", rootPathPrefix, path)
	_ = os.WriteFile(path, []byte(data+"\n"), perm)
}

func openFile(path string) (*os.File, error) {
	rpath := filepath.Join(rootPathPrefix, path)
	if link, err := os.Readlink(rpath); err == nil {
		rpath = joinLink(rootPathPrefix, link, filepath.Dir(path))
	}
	return os.Open(rpath)
}

func statFile(path string) (os.FileInfo, error) {
	path = fmt.Sprintf("%s%s", rootPathPrefix, path)
	return os.Stat(path)
}

func readLink(path string) (string, error) {
	path = fmt.Sprintf("%s%s", rootPathPrefix, path)
	return os.Readlink(path)
}

func lstatFile(path string) (os.FileInfo, error) {
	path = fmt.Sprintf("%s%s", rootPathPrefix, path)
	return os.Lstat(path)
}

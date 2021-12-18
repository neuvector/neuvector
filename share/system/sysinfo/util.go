// Copyright © 2016 Zlatko Čalušić
//
// Use of this source code is governed by an MIT-style license that can be found in the LICENSE file.

package sysinfo

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

// Read one-liner text files, strip newline.
func slurpFile(path string) string {
	path = fmt.Sprintf("%s%s", rootPathPrefix, path)
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(data))
}

// Write one-liner text files, add newline, ignore errors (best effort).
func spewFile(path string, data string, perm os.FileMode) {
	path = fmt.Sprintf("%s%s", rootPathPrefix, path)
	_ = ioutil.WriteFile(path, []byte(data+"\n"), perm)
}

func openFile(path string) (*os.File, error) {
	path = fmt.Sprintf("%s%s", rootPathPrefix, path)
	return os.Open(path)
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

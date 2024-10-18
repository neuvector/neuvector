// Copyright 2015 clair authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

var (
	// ErrCouldNotExtract occurs when an extraction fails.
	ErrCouldNotExtract = errors.New("could not extract the archive")
	ErrRequestCanceled = errors.New("request conceled")

	// ErrExtractedFileTooBig occurs when a file to extract is too big.
	ErrExtractedFileTooBig = errors.New("could not extract one or more files from the archive: file too big")

	ErrCouldNotWriteToDisk = errors.New("could not write to disk")

	readLen = 6 // max bytes to sniff

	gzipHeader  = []byte{0x1f, 0x8b}
	bzip2Header = []byte{0x42, 0x5a, 0x68}
	xzHeader    = []byte{0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00}
)

// XzReader is an io.ReadCloser which decompresses xz compressed data.
type XzReader struct {
	io.ReadCloser
	cmd     *exec.Cmd
	closech chan error
}

type TarFileInfo struct {
	Name string
	Body []byte
}

// NewXzReader shells out to a command line xz executable (if
// available) to decompress the given io.Reader using the xz
// compression format and returns an *XzReader.
// It is the caller's responsibility to call Close on the XzReader when done.
func NewXzReader(r io.Reader) (*XzReader, error) {
	rpipe, wpipe := io.Pipe()
	ex, err := exec.LookPath("xz")
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(ex, "--decompress", "--stdout")

	closech := make(chan error)

	cmd.Stdin = r
	cmd.Stdout = wpipe

	go func() {
		err := cmd.Run()
		wpipe.CloseWithError(err)
		closech <- err
	}()

	return &XzReader{rpipe, cmd, closech}, nil
}

func (r *XzReader) Close() error {
	r.ReadCloser.Close()
	if err := r.cmd.Process.Kill(); err != nil {
		var path string
		if r.cmd != nil {
			path = r.cmd.Path
		}
		log.WithFields(log.Fields{"err": err, "path": path}).Error()
	}
	return <-r.closech
}

// TarReadCloser embeds a *tar.Reader and the related io.Closer
// It is the caller's responsibility to call Close on TarReadCloser when
// done.
type TarReadCloser struct {
	*tar.Reader
	io.Closer
}

func (r *TarReadCloser) Close() error {
	return r.Closer.Close()
}

// SelectivelyExtractArchive extracts the specified files and folders
// from targz data read from the given reader and store them in a map indexed by file paths
func SelectivelyExtractArchive(r io.Reader, selected func(string) bool, maxFileSize int64) (map[string][]byte, error) {
	data := make(map[string][]byte)

	extract := func(filename string, size int64, reader io.ReadCloser) error {
		// File size limit
		if maxFileSize > 0 && size > maxFileSize {
			// for some big jar file, just skip it
			log.WithFields(log.Fields{"size": size, "filename": filename}).Error("file too big")
			return nil
		}
		d, _ := io.ReadAll(reader)
		data[filename] = d
		return nil
	}

	err := extractTarFile(r, selected, extract)
	if err != nil {
		return data, err
	}

	return data, nil
}

func SelectivelyExtractToFiles(r io.Reader, dir string, selected func(string) bool, maxFileSize int64) (map[string]string, error) {
	data := make(map[string]string)

	extract := func(filename string, size int64, reader io.ReadCloser) error {
		// File size limit
		if maxFileSize > 0 && size > maxFileSize {
			// for some big jar file, just skip it
			log.WithFields(log.Fields{"size": size, "filename": filename}).Error("file too big")
			return nil
		}
		tmpfile, err := os.CreateTemp(dir, "extract")
		if err != nil {
			log.WithFields(log.Fields{"err": err, "filename": filename}).Error("write to temp file fail")
			return nil
		}
		if nb, err := io.Copy(tmpfile, reader); err != nil || nb == 0 {
			if err != nil {
				log.WithFields(log.Fields{"err": err, "filename": filename}).Error("copy file fail")
			}
			return nil
		}
		tmpfile.Close()
		data[filename] = tmpfile.Name()
		return nil
	}

	err := extractTarFile(r, selected, extract)
	if err != nil {
		return data, err
	}

	return data, nil
}

func EnsureBaseDir(fpath string) error {
	baseDir := filepath.Dir(fpath)
	info, err := os.Stat(baseDir)
	if err == nil && info.IsDir() {
		return nil
	}
	return os.MkdirAll(baseDir, 0755)
}

func ExtractAllArchiveToFiles(path string, r io.Reader, maxFileSize int64, encryptKey []byte) error {
	tr, err := getTarReader(r)
	if err != nil {
		return ErrCouldNotExtract
	}
	defer tr.Close()

	// For each element in the archive
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return ErrCouldNotExtract
		}

		// Get element filename
		filename := hdr.Name
		filename = strings.TrimPrefix(filename, "./")

		// File size limit
		if maxFileSize > 0 && hdr.Size > maxFileSize {
			return ErrExtractedFileTooBig
		}

		// Extract the element
		if hdr.Typeflag == tar.TypeReg {
			data, _ := io.ReadAll(tr)

			if encryptKey != nil {
				data, _ = Encrypt(encryptKey, data)
			}

			err = os.WriteFile(path+filename, data, 0400)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func ExtractAllArchive(dst string, r io.Reader, maxFileSize int64) (int64, error) {
	var untarSize int64

	tr, err := getTarReader(r)
	if err != nil {
		return untarSize, err
	}
	defer tr.Close()

	for {
		header, err := tr.Next()
		switch {
		// if no more files are found return
		case err == io.EOF:
			return untarSize, nil

		// return any other error
		case err != nil:
			return untarSize, err

		// if the header is nil, just skip it (not sure how this happens)
		case header == nil:
			continue
		}

		// the target location where the dir/file should be created
		// "aufs" might have issue to create file like. ".abc.txt"
		names := strings.Split(header.Name, "/")
		for i, name := range names {
			if len(name) > 1 && name[0] == '.' {
				names[i] = "_" + name
			}
		}

		target := filepath.Join(dst, strings.Join(names, "/"))

		// the following switch could also be done using fi.Mode(), not sure if there
		// a benefit of using one vs. the other.
		// fi := header.FileInfo()
		// File size limit
		if maxFileSize > 0 && header.Size > maxFileSize {
			return untarSize, ErrExtractedFileTooBig
		}
		untarSize += header.Size

		// check the file type
		switch header.Typeflag {
		// if its a dir and it doesn't exist create it
		case tar.TypeDir:
			if _, err := os.Stat(target); err != nil {
				if err := os.MkdirAll(target, 0755); err != nil {
					log.WithFields(log.Fields{"err": err, "target": target}).Error("mkdirall")
					return untarSize, err
				}
			}

			// only way to put setuid and setgid back into the new file
			err = os.Chmod(target, header.FileInfo().Mode()|0755) // forced read/write-able
			if err != nil {
				log.WithFields(log.Fields{"err": err, "path": header.Name}).Error("chmod")
			}

		// if it's a file create it
		case tar.TypeReg:
			if err := EnsureBaseDir(target); err != nil {
				log.WithFields(log.Fields{"err": err, "target": target}).Error("basedir")
				return untarSize, err
			}

			f, err := os.Create(target)
			if err != nil {
				log.WithFields(log.Fields{"err": err, "target": target}).Error("create")
				return untarSize, err
			}

			// copy over contents
			if _, err := io.Copy(f, tr); err != nil {
				log.WithFields(log.Fields{"err": err}).Error("copy")
				return untarSize, err
			}
			// manually close here after each file operation; defering would cause each file close
			// to wait until all operations have completed.
			f.Close()

			// only way to put setuid and setgid back into the new file
			err = os.Chmod(target, header.FileInfo().Mode()|0444) // forced read-able
			if err != nil {
				log.WithFields(log.Fields{"err": err, "path": header.Name}).Error("chmod")
			}
		}
	}
}

// getTarReader returns a TarReaderCloser associated with the specified io.Reader.
//
// Gzip/Bzip2/XZ detection is done by using the magic numbers:
// Gzip: the first two bytes should be 0x1f and 0x8b. Defined in the RFC1952.
// Bzip2: the first three bytes should be 0x42, 0x5a and 0x68. No RFC.
// XZ: the first three bytes should be 0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00. No RFC.
func getTarReader(r io.Reader) (*TarReadCloser, error) {
	br := bufio.NewReader(r)
	header, err := br.Peek(readLen)
	if err == nil {
		switch {
		case bytes.HasPrefix(header, gzipHeader):
			gr, err := gzip.NewReader(br)
			if err != nil {
				return nil, err
			}
			return &TarReadCloser{tar.NewReader(gr), gr}, nil
		case bytes.HasPrefix(header, bzip2Header):
			bzip2r := io.NopCloser(bzip2.NewReader(br))
			return &TarReadCloser{tar.NewReader(bzip2r), bzip2r}, nil
		case bytes.HasPrefix(header, xzHeader):
			xzr, err := NewXzReader(br)
			if err != nil {
				return nil, err
			}
			return &TarReadCloser{tar.NewReader(xzr), xzr}, nil
		}
	}

	dr := io.NopCloser(br)
	return &TarReadCloser{tar.NewReader(dr), dr}, nil
}

func MakeTar(files []TarFileInfo) (*bytes.Buffer, error) {
	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)
	defer tw.Close()
	for _, file := range files {
		hdr := &tar.Header{
			Name:     file.Name,
			Mode:     0655,
			Typeflag: '0',
			Size:     int64(len(file.Body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write([]byte(file.Body)); err != nil {
			return nil, err
		}
	}
	return buf, nil
}

func SelectivelyExtractModules(r io.Reader, lastfix string, maxFileSize int64) (map[string][]byte, error) {
	data := make(map[string][]byte)

	// Create a tar or tar/tar-gzip/tar-bzip2/tar-xz reader
	tr, err := getTarReader(r)
	if err != nil {
		return data, ErrCouldNotExtract
	}
	defer tr.Close()

	// For each element in the archive
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return data, ErrCouldNotExtract
		}

		// Get element filename
		filename := hdr.Name
		filename = strings.TrimPrefix(filename, "./")

		// Determine if we should extract the element
		if !strings.HasSuffix(filename, lastfix) {
			continue
		}
		// File size limit
		if maxFileSize > 0 && hdr.Size > maxFileSize {
			return data, ErrExtractedFileTooBig
		}

		// Extract the element
		if hdr.Typeflag == tar.TypeReg {
			d, _ := io.ReadAll(tr)
			data[filename] = d
		}
	}

	return data, nil
}

// func SelectivelyExtractToFile(r io.Reader, prefix string, toExtract []string, dir string) (map[string]string, error) {
func SelectivelyExtractToFile(r io.Reader, selected func(string) bool, dir string) (map[string]string, error) {
	files := make(map[string]string)

	extract := func(filename string, size int64, reader io.ReadCloser) error {
		fpath := dir + "/" + strings.Replace(filename, "/", "_", -1)
		f, err := os.Create(fpath)
		if err != nil {
			return ErrCouldNotWriteToDisk
		}
		defer f.Close()

		_, err = io.Copy(f, reader)
		if err != nil {
			return ErrCouldNotWriteToDisk
		}
		files[filename] = fpath
		return nil
	}

	err := extractTarFile(r, selected, extract)
	if err != nil {
		return files, err
	}
	return files, nil
}

func extractTarFile(r io.Reader, selected func(string) bool, extract func(string, int64, io.ReadCloser) error) error {
	// canceled context only reports when reading the response.

	// Create a tar or tar/tar-gzip/tar-bzip2/tar-xz reader
	tr, err := getTarReader(r)
	if err == context.Canceled {
		log.Info("Request canceled")
		return ErrRequestCanceled
	} else if err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		return ErrCouldNotExtract
	}
	defer tr.Close()

	// For each element in the archive
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err == context.Canceled {
			log.Info("Request canceled")
			return ErrRequestCanceled
		} else if err != nil {
			log.WithFields(log.Fields{"error": err}).Error()
			return ErrCouldNotExtract
		}

		// Get element filename
		filename := hdr.Name
		filename = strings.TrimPrefix(filename, "./")

		// Determine if we should extract the element
		if selected(filename) {
			// Extract the element
			if hdr.Typeflag == tar.TypeReg ||
				hdr.Typeflag == tar.TypeLink ||
				hdr.Typeflag == tar.TypeSymlink {
				if err := extract(filename, hdr.Size, tr); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// Unzip will decompress a zip archive, moving all files and folders
// within the zip file (parameter 1) to an output directory (parameter 2).
func Unzip(src string, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {

		fpath := filepath.Join(dest, f.Name)

		// Check for ZipSlip. More Info: http://bit.ly/2MsjAWE
		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("%s: illegal file path", fpath)
		}

		if f.Mode().IsDir() {
			// Make Folder
			if err := os.MkdirAll(fpath, os.ModePerm); err != nil {
				log.WithFields(log.Fields{"err": err, "fpath": fpath}).Error()
			}
			continue
		}

		// skip non-regular files
		if !f.Mode().IsRegular() {
			continue
		}

		// Make File
		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode()|0444)
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)

		// Close the file without defer to close before next iteration of loop
		outFile.Close()
		rc.Close()

		if err != nil {
			return err
		}
	}
	return nil
}

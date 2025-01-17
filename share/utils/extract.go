package utils

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/coreos/clair/pkg/tarutil"
	log "github.com/sirupsen/logrus"
)

var (
	ErrRequestCanceled     = errors.New("request conceled")
	ErrCouldNotWriteToDisk = errors.New("could not write to disk")
)

// ExtractAllArchiveData extracts all files and folders
// from targz data read from the given reader and store them in a map indexed by file paths
func ExtractAllArchiveData(r io.Reader) (map[string][]byte, error) {
	data := make(map[string][]byte)

	selected := func(filename string) bool {
		return true
	}

	extract := func(filename string, size int64, reader io.ReadCloser) error {
		// File size limit
		if size > tarutil.MaxExtractableFileSize {
			log.WithFields(log.Fields{"size": size, "filename": filename}).Error("file too big")
			return tarutil.ErrExtractedFileTooBig
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

func EnsureBaseDir(fpath string) error {
	baseDir := filepath.Dir(fpath)
	info, err := os.Stat(baseDir)
	if err == nil && info.IsDir() {
		return nil
	}
	return os.MkdirAll(baseDir, 0755)
}

func ExtractAllArchiveToFiles(path string, r io.Reader, encryptKey []byte) error {
	tr, err := tarutil.NewTarReadCloser(r)
	if err != nil {
		return tarutil.ErrCouldNotExtract
	}
	defer tr.Close()

	// For each element in the archive
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return tarutil.ErrCouldNotExtract
		}

		// Get element filename
		filename := hdr.Name
		filename = strings.TrimPrefix(filename, "./")

		// File size limit
		if hdr.Size > tarutil.MaxExtractableFileSize {
			return tarutil.ErrExtractedFileTooBig
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

func ExtractAllArchive(dst string, r io.Reader) (int64, error) {
	var untarSize int64

	tr, err := tarutil.NewTarReadCloser(r)
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
		if header.Size > tarutil.MaxExtractableFileSize {
			return untarSize, tarutil.ErrExtractedFileTooBig
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

func MakeTar(files tarutil.FilesMap) (*bytes.Buffer, error) {
	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)
	defer tw.Close()
	for name, body := range files {
		hdr := &tar.Header{
			Name:     name,
			Mode:     0655,
			Typeflag: tar.TypeReg,
			Size:     int64(len(body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			return nil, err
		}
	}
	return buf, nil
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
	tr, err := tarutil.NewTarReadCloser(r)
	if err == context.Canceled {
		log.Info("Request canceled")
		return ErrRequestCanceled
	} else if err != nil {
		log.WithFields(log.Fields{"error": err}).Error()
		return tarutil.ErrCouldNotExtract
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
			return tarutil.ErrCouldNotExtract
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

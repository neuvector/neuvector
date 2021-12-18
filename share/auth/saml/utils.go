package saml

import (
	"bytes"
	"compress/flate"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/nu7hatch/gouuid"
)

func getID() string {
	u, _ := uuid.NewV4()
	return fmt.Sprintf("_%s", u.String())
}

func compressString(in string) string {
	buf := new(bytes.Buffer)
	compressor, _ := flate.NewWriter(buf, 9)
	compressor.Write([]byte(in))
	compressor.Close()
	return buf.String()
}

func decompressString(in string) string {
	buf := new(bytes.Buffer)
	decompressor := flate.NewReader(strings.NewReader(in))
	io.Copy(buf, decompressor)
	decompressor.Close()
	return buf.String()
}

func compress(in []byte) []byte {
	buf := new(bytes.Buffer)
	compressor, _ := flate.NewWriter(buf, 9)
	compressor.Write(in)
	compressor.Close()
	return buf.Bytes()
}

func decompress(in []byte) []byte {
	buf := new(bytes.Buffer)
	decompressor := flate.NewReader(bytes.NewReader(in))
	io.Copy(buf, decompressor)
	decompressor.Close()
	return buf.Bytes()
}

func loadCertificate(cert string) string {
	re := regexp.MustCompile("---(.*)CERTIFICATE(.*)---")
	out := re.ReplaceAllString(cert, "")
	out = strings.Trim(out, " \n")
	out = strings.Replace(out, "\n", "", -1)

	return out
}

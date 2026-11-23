package scan

import (
	"archive/zip"
	"bytes"
	"sort"
	"testing"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
	"github.com/stretchr/testify/require"
)

func buildTestJar(t *testing.T, files map[string]string) *zip.Reader {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		w, err := zw.Create(name)
		require.NoError(t, err)
		_, err = w.Write([]byte(files[name]))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	require.NoError(t, err)
	return zr
}

func pomProperties(groupId, artifactId, version string) string {
	return "groupId=" + groupId + "\nartifactId=" + artifactId + "\nversion=" + version + "\n"
}

func TestParseJarPackageManifestCoveredByPom(t *testing.T) {
	tests := []struct {
		name    string
		files   map[string]string
		modules []string
	}{
		{
			// io.modelcontextprotocol.sdk:mcp has no vendor in its manifest. The
			// "jar:mcp" fallback collided with the DB key derived from "python:mcp".
			name: "manifest fallback covered by pom.properties is dropped",
			files: map[string]string{
				"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\nImplementation-Title: mcp\nImplementation-Version: 1.1.1\n",
				"META-INF/maven/io.modelcontextprotocol.sdk/mcp/pom.properties": pomProperties("io.modelcontextprotocol.sdk", "mcp", "1.1.1"),
			},
			modules: []string{"io.modelcontextprotocol.sdk:mcp"},
		},
		{
			// Legacy jars without pom.properties still rely on the "jar:" fallback.
			name: "manifest fallback without pom.properties is kept",
			files: map[string]string{
				"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\nImplementation-Title: log4j-core\nImplementation-Version: 2.14.1\n",
			},
			modules: []string{"jar:log4j-core"},
		},
		{
			// A pom.properties of a different artifact (e.g. a shaded dependency)
			// does not identify the jar itself.
			name: "manifest fallback with unrelated pom.properties is kept",
			files: map[string]string{
				"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\nImplementation-Title: common\nImplementation-Version: 1.59.0\n",
				"META-INF/maven/com.squareup.okhttp3/okhttp/pom.properties": pomProperties("com.squareup.okhttp3", "okhttp", "4.12.0"),
			},
			modules: []string{"com.squareup.okhttp3:okhttp", "jar:common"},
		},
		{
			// Only the ambiguous "jar:" fallback is affected; a resolved vendor is kept.
			name: "manifest with resolved vendor is kept",
			files: map[string]string{
				"META-INF/MANIFEST.MF":                           "Manifest-Version: 1.0\nImplementation-Vendor-Id: org.example\nImplementation-Title: demo\nImplementation-Version: 1.0.0\n",
				"META-INF/maven/com.example/demo/pom.properties": pomProperties("com.example", "demo", "1.0.0"),
			},
			modules: []string{"com.example:demo", "org.example:demo"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			const jarPath = "usr/share/app/lib/test-1.0.jar"
			s := NewScanApps(true, &share.ParsingCaps{JarAutoModuleName: true})
			s.parseJarPackage(buildTestJar(t, tc.files), jarPath, jarPath, jarPath, 0, utils.NewSet())

			var modules []string
			for _, pkg := range s.pkgs[jarPath] {
				modules = append(modules, pkg.ModuleName)
			}
			sort.Strings(modules)
			require.Equal(t, tc.modules, modules)
		})
	}
}

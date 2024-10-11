package scan

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share/utils"
)

const (
	AppFileName = "apps_pkg"

	nodeModules1 = "/usr/lib/node_modules"
	nodeModules2 = "/usr/local/lib/node_modules"
	nodeModules  = "node_modules"
	nodePackage  = "package.json"
	nodeJs       = "npm"

	wpname           = "Wordpress"
	WPVerFileSuffix  = "wp-includes/version.php"
	wpVersionMaxSize = 4 * 1024
	ComposerFile     = "/composer.lock"

	jar         = "jar"
	jarMaxDepth = 2

	javaPOMproperty        = "/pom.properties"
	javaPOMgroupId         = "groupId="
	javaPOMartifactId      = "artifactId="
	javaPOMversion         = "version="
	javaManifest           = "MANIFEST.MF"
	javaMnfstMaxLines      = 20
	javaMnfstImplVendorId  = "Implementation-Vendor-Id:"
	javaMnfstImplVersion   = "Implementation-Version:"
	javaMnfstImplTitle     = "Implementation-Title:"
	javaMnfstBundleVendor  = "Bundle-Vendor:"
	javaMnfstBundleVersion = "Bundle-Version:"
	javaMnfstBundleSymName = "Bundle-SymbolicName:"
	javaMnfstBundleName    = "Bundle-Name:"

	python            = "python"
	ruby              = "ruby"
	dotnetDepsMaxSize = 10 * 1024 * 1024

	golang = "golang"

	// R language
	rlang           = "r"
	rDefaultPath    = "usr/lib/R/library/"
	rDefaultPath2   = "usr/local/lib/R/library/"
	rRepositoryPath = "usr/local/lib/R/site-library/"
	rDescFileName   = "DESCRIPTION"
)

// var verRegexp = regexp.MustCompile(`<([a-zA-Z0-9\.]+)>([0-9\.]+)</([a-zA-Z0-9\.]+)>`)
var pyRegexp = regexp.MustCompile(`/([a-zA-Z0-9_\.]+)-([a-zA-Z0-9\.]+)[\-a-zA-Z0-9\.]*\.(egg-info\/PKG-INFO|dist-info\/WHEEL)$`)
var rubyRegexp = regexp.MustCompile(`/([a-zA-Z0-9_\-]+)-([0-9\.]+)\.gemspec$`)

type ComposerLock struct {
	Packages    []ComposerPackage `json:"packages"`
	DevPackages []ComposerPackage `json:"packages-dev"`
}

type ComposerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type AppPackage struct {
	AppName    string `json:"app_name"`
	ModuleName string `json:"module_name"`
	Version    string `json:"version"`
	FileName   string `json:"file_name"`
}

/*
type mvnProject struct {
	Parent       mvnParent       `xml:"parent"`
	ArtifactId   string          `xml:"artifactId"`
	Dependencies []mvnDependency `xml:"dependencies>dependency"`
}

type mvnParent struct {
	GroupId    string `xml:"groupId"`
	ArtifactId string `xml:"artifactId"`
	Version    string `xml:"version"`
}

type mvnDependency struct {
	GroupId    string `xml:"groupId"`
	ArtifactId string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}
*/

type dotnetDependency struct {
	Deps map[string]string `json:"dependencies"`
}

type dotnetRuntime struct {
	Name      string `json:"name"`
	Signature string `json:"signature"`
}

type dotnetPackage struct {
	Runtime dotnetRuntime                          `json:"runtimeTarget"`
	Targets map[string]map[string]dotnetDependency `json:"targets"`
}

type ScanApps struct {
	pkgs    map[string][]AppPackage // AppPackage set
	replace bool
}

func NewScanApps(v2 bool) *ScanApps {
	return &ScanApps{pkgs: make(map[string][]AppPackage), replace: v2}
}

func IsAppsPkgFile(filename, fullpath string) bool {
	if isNodejs(filename) || IsJava(filename) || isPython(filename) ||
		isRuby(filename) || isDotNet(filename) || isWordpress(filename) || isPhpComposer(filename) || IsRlangPackage(filename) {
		return true
	}
	// Keep golang check at last as it requires reading file data
	return isGolang(filename, fullpath)
}

func (s *ScanApps) name() string {
	return AppFileName
}

func (s *ScanApps) Data() map[string][]AppPackage {
	return s.pkgs
}

func (s *ScanApps) marshal() []byte {
	buf := new(bytes.Buffer)
	for _, pkg := range s.pkgs {
		// write by 64-entry chunk, so we don't hit the scanner limit when reading it
		for len(pkg) > 64 {
			if b, err := json.Marshal(pkg[:64]); err == nil {
				buf.WriteString(fmt.Sprintf("%s\n", string(b)))
			}
			pkg = pkg[64:]
		}
		if len(pkg) > 0 {
			if b, err := json.Marshal(pkg); err == nil {
				buf.WriteString(fmt.Sprintf("%s\n", string(b)))
			}
		}
	}
	return buf.Bytes()
}

func (s *ScanApps) ExtractAppPkg(filename, fullpath string) {
	if _, ok := s.pkgs[filename]; ok && !s.replace {
		return
	}

	if isNodejs(filename) {
		s.parseNodePackage(filename, fullpath)
	} else if IsJava(filename) {
		if r, err := zip.OpenReader(fullpath); err == nil {
			dedup := utils.NewSet()
			s.parseJarPackage(&r.Reader, filename, filename, fullpath, 0, dedup)
			r.Close()
		} else {
			log.WithFields(log.Fields{"err": err}).Error("open jar file fail")
		}
	} else if isPython(filename) {
		s.parsePythonPackage(filename)
	} else if isRuby(filename) {
		s.parseRubyPackage(filename)
	} else if isDotNet(filename) {
		s.parseDotNetPackage(filename, fullpath)
	} else if isWordpress(filename) {
		s.parseWordpressPackage(filename, fullpath)
	} else if isPhpComposer(filename) {
		s.parsePhpComposerJson(filename, fullpath)
	} else if IsRlangPackage(filename) {
		s.parseRLangPackage(filename, fullpath)
	} else {
		s.parseGolangPackage(filename, fullpath)
	}
}

func (s *ScanApps) DerivePkg(data map[string][]byte) []AppPackage {
	f, hasFile := data[s.name()]
	if !hasFile {
		return nil
	}

	pkgs := make([]AppPackage, 0)
	scanner := bufio.NewScanner(strings.NewReader(string(f[:])))
	for scanner.Scan() {
		line := scanner.Text()
		var list []AppPackage
		if err := json.Unmarshal([]byte(line), &list); err == nil {
			pkgs = append(pkgs, list...)
		} else {
			log.WithFields(log.Fields{"err": err, "line": line}).Error("unmarshal app pkg fail")
		}
	}
	return pkgs
}

func isExe(info os.FileInfo) bool {
	return info.Mode().IsRegular() && (info.Mode()&0111) != 0
}

func isGolang(filename, fullpath string) bool {
	info, err := os.Stat(fullpath)
	if err != nil || !isExe(info) {
		return false
	}

	f, err := openExe(fullpath)
	if err != nil {
		return false
	}
	defer f.Close()

	_, _, err = readRawBuildInfo(f, true)

	return err == nil
}

func (s *ScanApps) parseGolangPackage(filename, fullpath string) {
	f, err := openExe(fullpath)
	if err != nil {
		return
	}
	defer f.Close()

	_, mod, err := readRawBuildInfo(f, false)
	if err != nil {
		return
	}

	bi, err := parseBuildInfo(mod)
	if err != nil {
		log.WithFields(log.Fields{"file": filename, "error": err.Error()}).Error("parse error")
		return
	}

	pkgs := make([]AppPackage, len(bi.Deps))
	for i, m := range bi.Deps {
		if m.Replace != nil {
			m = m.Replace
		}

		pkg := AppPackage{
			AppName:    golang,
			ModuleName: fmt.Sprintf("go:%s", m.Path),
			Version:    strings.TrimPrefix(m.Version, "v"),
			FileName:   filename,
		}
		pkgs[i] = pkg
	}
	s.pkgs[filename] = pkgs
}

func isNodejs(filename string) bool {
	return strings.Contains(filename, nodeModules) &&
		strings.HasSuffix(filename, nodePackage)
}

func (s *ScanApps) parseNodePackage(filename, fullpath string) {
	var version string
	var name string
	inputFile, err := os.Open(fullpath)
	if err != nil {
		log.WithFields(log.Fields{"err": err, "fullpath": fullpath, "filename": filename}).Debug("read file fail")
		return
	}
	defer inputFile.Close()

	scanner := bufio.NewScanner(inputFile)
	for scanner.Scan() {
		s := scanner.Text()
		if strings.HasPrefix(s, "  \"version\":") {
			a := len("  \"version\": \"")
			b := strings.LastIndex(s, "\"")
			if b < 0 {
				continue
			}
			version = s[a:b]
		} else if strings.HasPrefix(s, "  \"name\": \"") {
			a := len("  \"name\": \"")
			b := strings.LastIndex(s, "\"")
			if b < 0 {
				continue
			}
			name = s[a:b]
		}
		if name != "" && version != "" {
			break
		}
	}

	if name == "" || version == "" {
		return
	}

	// Cannot change the filename, which is the key of s.pkgs and used for resolve
	// overwrite among layers
	// filename = strings.Replace(filename, "/package.json", "", -1)
	pkg := AppPackage{
		AppName:    nodeJs,
		ModuleName: name,
		Version:    version,
		FileName:   filename,
	}
	s.pkgs[filename] = []AppPackage{pkg}
}

func IsJava(filename string) bool {
	return strings.HasSuffix(filename, ".war") ||
		strings.HasSuffix(filename, ".jar") ||
		strings.HasSuffix(filename, ".ear")
}

func parseJarManifestFile(path string, rc io.Reader) (*AppPackage, error) {
	var vendorId, version, title, symName string
	var vendorSet, titleSet bool
	var lineCount int

	scanner := bufio.NewScanner(rc)
	for scanner.Scan() {
		line := scanner.Text()

		if len(line) == 0 && lineCount > 0 {
			// if we reach an empty line, the first section is done
			break
		}
		if !strings.HasPrefix(line, " ") {
			lineCount++
			if lineCount > javaMnfstMaxLines {
				break
			}
		}

		switch {
		case strings.HasPrefix(line, javaMnfstImplVendorId):
			// preferred vendor name
			vendorId = strings.TrimSpace(strings.TrimPrefix(line, javaMnfstImplVendorId))
			vendorSet = true
		case strings.HasPrefix(line, javaMnfstImplVersion):
			version = strings.TrimSpace(strings.TrimPrefix(line, javaMnfstImplVersion))
		case strings.HasPrefix(line, javaMnfstImplTitle):
			// preferred title name
			title = strings.TrimSpace(strings.TrimPrefix(line, javaMnfstImplTitle))
			title = strings.Split(title, ";")[0]
			titleSet = true
		case strings.HasPrefix(line, javaMnfstBundleVendor):
			if !vendorSet {
				vendorId = strings.TrimSpace(strings.TrimPrefix(line, javaMnfstBundleVendor))
			}
		case strings.HasPrefix(line, javaMnfstBundleVersion):
			version = strings.TrimSpace(strings.TrimPrefix(line, javaMnfstBundleVersion))
		case strings.HasPrefix(line, javaMnfstBundleSymName):
			symName = strings.TrimSpace(strings.TrimPrefix(line, javaMnfstBundleSymName))
		case strings.HasPrefix(line, javaMnfstBundleName):
			if !titleSet {
				title = strings.TrimSpace(strings.TrimPrefix(line, javaMnfstBundleName))
				title = strings.Split(title, ";")[0]
			}
		}

		if len(version) > 0 && titleSet && vendorSet {
			// stop we have all the fields confirmed
			break
		}
	}

	if symName != "" {
		if s := strings.LastIndex(symName, ";"); s > 0 {
			symName = symName[:s]
		}
		if symName == "org.apache.tomcat-embed-core" {
			// NVSHAS-8730
			vendorId = "org.apache.tomcat.embed"
			title = "tomcat-embed-core"
		} else if symName == "org.postgresql.jdbc" && title == "PostgreSQL JDBC Driver" {
			// NVSHAS-8757
			vendorId = "org.postgresql"
			title = "postgresql"
		} else if len(vendorId) == 0 || vendorId[0] == '%' || len(title) == 0 || title[0] == '%' {
			if dot := strings.LastIndex(symName, "."); dot > 0 {
				vendorId = symName[:dot]
				title = symName[dot+1:]
			}
		}
	}

	if len(vendorId) == 0 || vendorId[0] == '%' {
		vendorId = "jar"
	}

	// Suppress incomplete entries as we can't use them later.
	if title == "" || title == "jar" || version == "" {
		return nil, errors.New("Missing title or version")
	}

	pkg := AppPackage{
		AppName:    jar,
		FileName:   path,
		ModuleName: fmt.Sprintf("%s:%s", vendorId, title),
		Version:    version,
	}

	return &pkg, nil
}

func (s *ScanApps) parseJarPackage(r *zip.Reader, origJar, filename, fullpath string, depth int, dedup utils.Set) {
	// in-memory unzip the jar file then walk through.
	tempDir, err := os.MkdirTemp("", "")
	if err == nil {
		defer os.RemoveAll(tempDir)
	} else {
		log.WithFields(log.Fields{"fullpath": fullpath}).Error("unable to create temp dir")
	}

	path := origJar
	if depth > 0 {
		path = origJar + ":" + filename
	}
	pkgs := make(map[string][]AppPackage)
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if IsJava(f.Name) {
			if depth+1 >= jarMaxDepth {
				continue
			}
			// Parse jar file recursively
			if jarFile, err := f.Open(); err == nil {
				dstPath := filepath.Join(tempDir, filepath.Base(f.Name)) // retain the filename
				if dstFile, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode()); err == nil {
					if _, err := io.Copy(dstFile, jarFile); err == nil {
						dstFile.Close()
						if jarReader, err := zip.OpenReader(dstPath); err == nil {
							s.parseJarPackage(&jarReader.Reader, origJar, f.Name, dstPath, depth+1, dedup)
							jarReader.Close()
						}
					} else {
						dstFile.Close()
						log.WithFields(log.Fields{"dst": dstPath, "filename": filename, "err": err}).Error("unable to copy jar file")
					}
					err := os.Remove(dstPath)
					if err != nil {
						log.WithFields(log.Fields{"dst": dstPath, "filename": filename, "err": err}).Error("unable to remove dst path")
					}
				} else {
					log.WithFields(log.Fields{"dst": dstPath, "err": err}).Error("unable to create dst file")
				}
				jarFile.Close()
			} else {
				log.WithFields(log.Fields{"fullpath": fullpath, "filename": filename, "depth": depth, "err": err}).Error("open jar file fail")
			}
		} else if strings.HasSuffix(f.Name, javaPOMproperty) {
			var groupId, version, artifactId string
			rc, err := f.Open()
			if err != nil {
				log.WithFields(log.Fields{"err": err}).Error("open pom property fail")
				continue
			}

			scanner := bufio.NewScanner(rc)
			for scanner.Scan() {
				line := scanner.Text()
				switch {
				case strings.HasPrefix(line, javaPOMgroupId):
					groupId = strings.TrimSpace(strings.TrimPrefix(line, javaPOMgroupId))
				case strings.HasPrefix(line, javaPOMversion):
					version = strings.TrimSpace(strings.TrimPrefix(line, javaPOMversion))
				case strings.HasPrefix(line, javaPOMartifactId):
					artifactId = strings.TrimSpace(strings.TrimPrefix(line, javaPOMartifactId))
				}

				if len(groupId) > 0 && len(version) > 0 && len(artifactId) > 0 {
					break
				}
			}

			rc.Close()

			if groupId == "" || version == "" || artifactId == "" || artifactId == "jar" {
				log.WithFields(log.Fields{"path": path}).Info("Missing artifactId, groupId, or version")
				continue
			}

			pkg := AppPackage{
				AppName:    jar,
				FileName:   path,
				ModuleName: fmt.Sprintf("%s:%s", groupId, artifactId),
				Version:    version,
			}

			key := fmt.Sprintf("%s-%s-%s", pkg.FileName, pkg.ModuleName, pkg.Version)
			if !dedup.Contains(key) {
				dedup.Add(key)
				if _, ok := pkgs[path]; !ok {
					pkgs[path] = []AppPackage{pkg}
				} else {
					pkgs[path] = append(pkgs[path], pkg)
				}
			}
		} else if strings.HasSuffix(f.Name, javaManifest) {
			rc, err := f.Open()
			if err != nil {
				log.WithFields(log.Fields{"err": err}).Error("open manifest file fail")
				continue
			}

			if pkg, err := parseJarManifestFile(path, rc); err == nil {
				key := fmt.Sprintf("%s-%s-%s", pkg.FileName, pkg.ModuleName, pkg.Version)
				if !dedup.Contains(key) {
					dedup.Add(key)
					if _, ok := pkgs[path]; !ok {
						pkgs[path] = []AppPackage{*pkg}
					} else {
						pkgs[path] = append(pkgs[path], *pkg)
					}
				}
			}

			rc.Close()
		}
	}

	for filename, pkg := range pkgs {
		s.pkgs[filename] = pkg
	}
}

func isPython(filename string) bool {
	return pyRegexp.MatchString(filename)
}

func isRuby(filename string) bool {
	return rubyRegexp.MatchString(filename)
}

func isDotNet(filename string) bool {
	return strings.HasSuffix(filename, ".deps.json")
}

func isWordpress(filename string) bool {
	return strings.HasSuffix(filename, WPVerFileSuffix)
}

func isPhpComposer(filename string) bool {
	return strings.HasSuffix(filename, ComposerFile)
}

func IsRlangPackage(filename string) bool {
	if filepath.Base(filename) != rDescFileName {
		return false
	}
	return strings.HasPrefix(filename, rDefaultPath) || strings.HasPrefix(filename, rRepositoryPath) || strings.HasPrefix(filename, rDefaultPath2)
}

func (s *ScanApps) parsePhpComposerJson(filename string, filepath string) {
	data := ComposerLock{}
	//extract json data
	bytes, err := os.ReadFile(filepath)
	if err != nil {
		log.WithFields(log.Fields{"err": err, "file": filename}).Error("failed to read composer.lock file")
		return
	}
	err = json.Unmarshal(bytes, &data)
	if err != nil {
		log.WithFields(log.Fields{"err": err, "file": filename}).Error("failed to unmarshal json data from composer.lock file")
		return
	}
	//convert json data to one or more AppPackage
	for _, composerPackage := range data.Packages {
		packageNameSplit := strings.Split(composerPackage.Name, "/")
		packageName := packageNameSplit[len(packageNameSplit)-1]
		appPackage := AppPackage{
			AppName:    "php",
			ModuleName: fmt.Sprintf("php:%s", packageName),
			Version:    composerPackage.Version,
			FileName:   filename,
		}
		//add each AppPackage to s.pkgs map, append if entry already exists.
		if _, ok := s.pkgs[filename]; !ok {
			s.pkgs[filename] = []AppPackage{appPackage}
		} else {
			s.pkgs[filename] = append(s.pkgs[filename], appPackage)
		}
	}
}

func (s *ScanApps) parsePythonPackage(filename string) {
	match := pyRegexp.FindAllStringSubmatch(filename, 1)
	if len(match) > 0 {
		sub := match[0]
		name := sub[1]
		ver := sub[2]
		var pkgPath string
		pkgPath = strings.TrimSuffix(filename, ".egg-info/PKG-INFO")
		pkgPath = strings.TrimSuffix(pkgPath, ".dist-info/WHEEL")
		pkg := AppPackage{
			AppName:    python,
			ModuleName: fmt.Sprintf("python:%s", name),
			Version:    ver,
			FileName:   pkgPath,
		}
		s.pkgs[filename] = []AppPackage{pkg}
	}
}

func (s *ScanApps) parseRubyPackage(filename string) {
	match := rubyRegexp.FindAllStringSubmatch(filename, 1)
	if len(match) > 0 {
		sub := match[0]
		name := sub[1]
		ver := sub[2]
		pkgPath := strings.TrimSuffix(filename, ".gemspec")
		pkg := AppPackage{
			AppName:    ruby,
			ModuleName: ruby + ":" + name,
			Version:    ver,
			FileName:   pkgPath,
		}
		s.pkgs[filename] = []AppPackage{pkg}
	}
}

func (s *ScanApps) parseWordpressPackage(filename, fullpath string) {
	if fi, err := os.Stat(fullpath); err != nil {
		log.WithFields(log.Fields{"err": err, "fullpath": fullpath, "filename": filename}).Error("Failed to stat file")
		return
	} else if fi.Size() > wpVersionMaxSize {
		log.WithFields(log.Fields{"max": wpVersionMaxSize, "fullpath": fullpath, "filename": filename}).Error("File size too large")
		return
	}

	inputFile, err := os.Open(fullpath)
	if err != nil {
		log.WithFields(log.Fields{"err": err, "fullpath": fullpath, "filename": filename}).Debug("Open file fail")
		return
	}
	defer inputFile.Close()

	scanner := bufio.NewScanner(inputFile)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "$wp_version = '") {
			a := len("$wp_version = '")
			b := strings.LastIndex(line, "'")
			if b > a {
				version := line[a:b]
				pkg := AppPackage{
					AppName:    wpname,
					ModuleName: wpname,
					Version:    version,
					FileName:   filename,
				}
				s.pkgs[filename] = []AppPackage{pkg}
				return
			}
		}
	}
}

func (s *ScanApps) parseDotNetPackage(filename, fullpath string) {
	if fi, err := os.Stat(fullpath); err != nil {
		log.WithFields(log.Fields{"err": err, "fullpath": fullpath, "filename": filename}).Error("Failed to stat file")
		return
	} else if fi.Size() > dotnetDepsMaxSize {
		log.WithFields(log.Fields{"max": dotnetDepsMaxSize, "fullpath": fullpath, "filename": filename}).Error("File size too large")
		return
	}

	var dotnet dotnetPackage

	if data, err := os.ReadFile(fullpath); err != nil {
		log.WithFields(log.Fields{"err": err, "fullpath": fullpath, "filename": filename}).Error("Failed to read file")
		return
	} else if err = json.Unmarshal(data, &dotnet); err != nil {
		log.WithFields(log.Fields{"err": err, "fullpath": fullpath, "filename": filename}).Error("Failed to unmarshal file")
		return
	}

	var coreVersion string
	dedup := utils.NewSet()
	pkgs := make([]AppPackage, 0)
	/*
		// Not reliable
		if strings.HasPrefix(dotnet.Runtime.Name, ".NETCoreApp") {
			tokens := strings.Split(dotnet.Runtime.Name, ",")
			for _, token := range tokens {
				// .NETCoreApp,Version=v3.1/linux-x64, .NETCoreApp,Version=v3.1
				if strings.HasPrefix(token, "Version=v") {
					version := token[9:]
					if o := strings.Index(version, "/"); o != -1 {
						version = version[:o]
					}
					coreVersion = version
					break
				}
			}
		}
	*/

	// parse filename
	tokens := strings.Split(filename, "/")
	for i, token := range tokens {
		if token == "Microsoft.NETCore.App" || token == "Microsoft.AspNetCore.App" {
			if i < len(tokens)-1 {
				coreVersion = tokens[i+1]
			}
			break
		}
	}

	if targets, ok := dotnet.Targets[dotnet.Runtime.Name]; ok {
		for target, dep := range targets {
			// "Microsoft.NETCore.App/3.1.15-servicing.21214.3"
			// it is possible that there are multiple core versions in different dependencies
			//    Microsoft.NETCore.App/2.2.8   ==> 2.2.8
			//    Microsoft.AspNetCore.ApplicationInsights.HostingStartup/2.2.0 ==> 2.2.0 (x)
			if strings.HasPrefix(target, "Microsoft.NETCore.App/") || strings.HasPrefix(target, "Microsoft.AspNetCore.App/") {
				if o := strings.Index(target, "/"); o != -1 {
					version := target[o+1:]
					if o = strings.Index(version, "-"); o != -1 {
						version = version[:o]
					}
					coreVersion = version
				}
			}

			for app, v := range dep.Deps {
				key := fmt.Sprintf("%s-%s", ".NET:"+app, v)
				if !dedup.Contains(key) {
					dedup.Add(key)
					pkg := AppPackage{
						AppName:    ".NET",
						ModuleName: ".NET:" + app,
						Version:    v,
						FileName:   filename,
					}
					pkgs = append(pkgs, pkg)
				}
			}
		}
	}

	if coreVersion != "" {
		key := fmt.Sprintf("%s-%s", ".NET:Core", coreVersion)
		if !dedup.Contains(key) {
			dedup.Add(key)
			pkg := AppPackage{
				AppName:    ".NET",
				ModuleName: ".NET:Core",
				Version:    coreVersion,
				FileName:   filename,
			}
			pkgs = append(pkgs, pkg)
		}
	}

	if len(pkgs) > 0 {
		s.pkgs[filename] = pkgs
	}
}

func (s *ScanApps) parseRLangPackage(filename, fullpath string) {
	if _, err := os.Stat(fullpath); err != nil {
		log.WithFields(log.Fields{"err": err, "fullpath": fullpath, "filename": filename}).Error("Failed to stat file")
		return
	}

	var name, version, repository string

	inputFile, err := os.Open(fullpath)
	if err != nil {
		log.WithFields(log.Fields{"err": err, "fullpath": fullpath, "filename": filename}).Debug("Open file fail")
		return
	}
	defer inputFile.Close()

	scanner := bufio.NewScanner(inputFile)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Package: ") {
			name = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
		} else if strings.HasPrefix(line, "Version: ") {
			version = strings.TrimSpace(strings.TrimPrefix(line, "Version: "))
		} else if strings.HasPrefix(line, "Repository:") {
			repository = strings.TrimSpace(strings.TrimPrefix(line, "Repository: "))
		}
	}

	if name != "" {
		var rname string
		if repository == "" {
			rname = name
		} else {
			rname = fmt.Sprintf("%s-%s", repository, name)
		}
		pkg := AppPackage{
			AppName:    rlang,
			ModuleName: strings.ToLower(rname),
			Version:    version,
			FileName:   strings.TrimSuffix(filename, "/"+rDescFileName),
		}
		s.pkgs[filename] = []AppPackage{pkg}
	}
}

package scan

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"os"
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
	nodeJs       = "node.js"

	wpname           = "Wordpress"
	WPVerFileSuffix  = "wp-includes/version.php"
	wpVersionMaxSize = 4 * 1024

	jar                = "jar"
	javaPOMXML         = "/pom.xml"
	pomReadSize        = 1024 * 1024
	javaServerInfo     = "/ServerInfo.properties"
	serverInfoMaxLines = 100
	tomcatName         = "Tomcat"

	python            = "python"
	ruby              = "ruby"
	dotnetDepsMaxSize = 10 * 1024 * 1024
)

var verRegexp = regexp.MustCompile(`<([a-zA-Z0-9\.]+)>([0-9\.]+)</([a-zA-Z0-9\.]+)>`)
var pyRegexp = regexp.MustCompile(`/([a-zA-Z0-9_\.]+)-([a-zA-Z0-9\.]+)[\-a-zA-Z0-9\.]*\.(egg-info\/PKG-INFO|dist-info\/WHEEL)$`)
var rubyRegexp = regexp.MustCompile(`/([a-zA-Z0-9_\-]+)-([0-9\.]+)\.gemspec$`)

type AppPackage struct {
	AppName    string `json:"app_name"`
	ModuleName string `json:"module_name"`
	Version    string `json:"version"`
	FileName   string `json:"file_name"`
	InBase     bool   `json:"in_base"`
}

type mvnProject struct {
	Parent       mvnParent       `xml:"parent"`
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
	dedup   utils.Set               // Used by some apps to remove duplicated modules
	pkgs    map[string][]AppPackage // AppPackage set
	replace bool
}

func NewScanApps(v2 bool) *ScanApps {
	return &ScanApps{pkgs: make(map[string][]AppPackage), dedup: utils.NewSet(), replace: v2}
}

func isAppsPkgFile(filename string) bool {
	// log.WithFields(log.Fields{"filename": filename}).Error("==================")
	return isNodejs(filename) || isJavaJar(filename) || isPython(filename) ||
		isRuby(filename) || isDotNet(filename) || isWordpress(filename)
}

func (s *ScanApps) name() string {
	return AppFileName
}

func (s *ScanApps) empty() bool {
	return len(s.pkgs) == 0
}

func (s *ScanApps) data() map[string][]AppPackage {
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

func (s *ScanApps) extractAppPkg(filename, fullpath string) {
	if _, ok := s.pkgs[filename]; ok && !s.replace {
		return
	}

	if isNodejs(filename) {
		s.parseNodePackage(filename, fullpath)
	} else if isJavaJar(filename) {
		s.parseJarPackage(filename, fullpath)
	} else if isPython(filename) {
		s.parsePythonPackage(filename)
	} else if isRuby(filename) {
		s.parseRubyPackage(filename)
	} else if isDotNet(filename) {
		s.parseDotNetPackage(filename, fullpath)
	} else if isWordpress(filename) {
		s.parseWordpressPackage(filename, fullpath)
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

func isJavaJar(filename string) bool {
	return strings.HasSuffix(filename, ".war") ||
		strings.HasSuffix(filename, ".jar") ||
		strings.HasSuffix(filename, ".ear")
}

func (s *ScanApps) parseJarPackage(filename, fullpath string) {
	r, err := zip.OpenReader(fullpath)
	if err != nil {
		log.WithFields(log.Fields{"err": err}).Error("open jar file fail")
		return
	}
	defer r.Close()

	pkgs := make(map[string][]AppPackage)
	for _, f := range r.File {
		if strings.HasSuffix(f.Name, javaServerInfo) {
			rc, err := f.Open()
			if err != nil {
				log.WithFields(log.Fields{"err": err, "file": f.Name}).Error("Open file fail")
				continue
			}
			defer rc.Close()

			scanner := bufio.NewScanner(rc)
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "server.info=") {
					prod := strings.TrimPrefix(line, "server.info=")
					if strings.HasPrefix(prod, "Apache Tomcat/") {
						if ver := strings.TrimPrefix(prod, "Apache Tomcat/"); len(ver) > 0 {
							pkg := AppPackage{
								AppName:    tomcatName,
								ModuleName: tomcatName,
								Version:    ver,
								FileName:   filename,
							}
							pkgs[filename] = []AppPackage{pkg}
						}
					}
				}
			}
		} else if strings.HasSuffix(f.Name, javaPOMXML) {
			rc, err := f.Open()
			if err != nil {
				log.WithFields(log.Fields{"err": err}).Error("open pom.xml file fail")
				continue
			}
			defer rc.Close()

			txt := make([]byte, pomReadSize)
			n, err := io.ReadFull(rc, txt)
			if err != nil && err != io.ErrUnexpectedEOF {
				log.WithFields(log.Fields{"err": err}).Error("read pom.xml file fail")
				continue
			}
			d := xml.NewDecoder(bytes.NewReader(txt[:n]))
			if d == nil {
				log.WithFields(log.Fields{"file": f.Name}).Error("New pom.xml decoder fail")
				continue
			}
			var proj mvnProject
			err = d.Decode(&proj)
			if err != nil {
				log.WithFields(log.Fields{"file": f.Name}).Error("Decode pom.xml fail")
				continue
			}

			verMap := make(map[string]string)
			scanner := bufio.NewScanner(bytes.NewReader(txt[:n]))
			for scanner.Scan() {
				line := scanner.Text()
				match := verRegexp.FindAllStringSubmatch(line, 1)
				if len(match) > 0 {
					s := match[0]
					v1 := s[1]
					ver := s[2]
					v2 := s[3]
					if v1 == v2 && v1 != "version" {
						verMap[v1] = ver
					}
				}
			}

			if proj.Parent.GroupId != "" && proj.Parent.ArtifactId != "" && proj.Parent.Version != "" {
				if strings.HasPrefix(proj.Parent.Version, "${") && strings.HasSuffix(proj.Parent.Version, "}") {
					rver := proj.Parent.Version[2 : len(proj.Parent.Version)-1]
					v, ok := verMap[rver]
					if !ok {
						continue
					}
					proj.Parent.Version = v
				}

				pkg := AppPackage{
					AppName:    jar,
					ModuleName: proj.Parent.GroupId + "." + proj.Parent.ArtifactId,
					Version:    proj.Parent.Version,
					FileName:   filename,
				}
				if list, ok := pkgs[filename]; ok {
					pkgs[filename] = append(list, pkg)
				} else {
					pkgs[filename] = []AppPackage{pkg}
				}
			}

			for _, dep := range proj.Dependencies {
				if dep.GroupId != "" && dep.ArtifactId != "" && dep.Version != "" && dep.Scope != "test" {
					if strings.HasPrefix(dep.Version, "${") && strings.HasSuffix(dep.Version, "}") {
						rver := dep.Version[2 : len(dep.Version)-1]
						v, ok := verMap[rver]
						if !ok {
							continue
						}
						dep.Version = v
					}

					pkg := AppPackage{
						AppName:    jar,
						ModuleName: dep.GroupId + "." + dep.ArtifactId,
						Version:    dep.Version,
						FileName:   filename,
					}
					if list, ok := pkgs[filename]; ok {
						pkgs[filename] = append(list, pkg)
					} else {
						pkgs[filename] = []AppPackage{pkg}
					}
				}
			}
		}
	}

	for filename, list := range pkgs {
		s.pkgs[filename] = list
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

func (s *ScanApps) parsePythonPackage(filename string) {
	match := pyRegexp.FindAllStringSubmatch(filename, 1)
	if len(match) > 0 {
		sub := match[0]
		name := sub[1]
		ver := sub[2]
		var pkgPath string
		pkgPath = strings.TrimRight(filename, ".egg-info/PKG-INFO")
		pkgPath = strings.TrimRight(pkgPath, ".dist-info/WHEEL")
		pkg := AppPackage{
			AppName:    python,
			ModuleName: python + ":" + name,
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
		var pkgPath string
		pkgPath = strings.TrimRight(filename, ".gemspec")
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

	return
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

	if data, err := ioutil.ReadFile(fullpath); err != nil {
		log.WithFields(log.Fields{"err": err, "fullpath": fullpath, "filename": filename}).Error("Failed to read file")
		return
	} else if err = json.Unmarshal(data, &dotnet); err != nil {
		log.WithFields(log.Fields{"err": err, "fullpath": fullpath, "filename": filename}).Error("Failed to unmarshal file")
		return
	}

	var coreVersion string

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
				// log.WithFields(log.Fields{"core": coreVersion, "filename": filename}).Error("-------")
			}
			break
		}
	}

	if targets, ok := dotnet.Targets[dotnet.Runtime.Name]; ok {
		for target, dep := range targets {
			// "Microsoft.NETCore.App/3.1.15-servicing.21214.3"
			if strings.HasPrefix(target, "Microsoft.NETCore.App") || strings.HasPrefix(target, "Microsoft.AspNetCore.App") {
				if o := strings.Index(target, "/"); o != -1 {
					version := target[o+1:]
					if o = strings.Index(version, "-"); o != -1 {
						version = version[:o]
					}
					coreVersion = version
					// log.WithFields(log.Fields{"core": coreVersion, "target": target, "filename": filename}).Error("==================")
				}
			}

			for app, v := range dep.Deps {
				pkg := AppPackage{
					AppName:    ".NET",
					ModuleName: ".NET:" + app,
					Version:    v,
					FileName:   filename,
				}

				// There can be several files that list the same dependency, such as .NET Core, so to dedup them
				key := fmt.Sprintf("%s-%s-%s", pkg.AppName, pkg.ModuleName, pkg.Version)
				if !s.dedup.Contains(key) {
					s.dedup.Add(key)
					pkgs = append(pkgs, pkg)
				}
			}
		}
	}

	if coreVersion != "" {
		pkg := AppPackage{
			AppName:    ".NET",
			ModuleName: ".NET:Core",
			Version:    coreVersion,
			FileName:   filename,
		}

		// There can be several files that list the same dependency, such as .NET Core, so to dedup them
		key := fmt.Sprintf("%s-%s-%s", pkg.AppName, pkg.ModuleName, pkg.Version)
		if !s.dedup.Contains(key) {
			s.dedup.Add(key)
			pkgs = append(pkgs, pkg)
		}
	}

	if len(pkgs) > 0 {
		s.pkgs[filename] = pkgs
	}
}

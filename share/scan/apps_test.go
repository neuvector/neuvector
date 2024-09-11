package scan

import (
	"strings"
	"testing"
)

func TestParsePythonPackage(t *testing.T) {
	tests := []string{
		"/usr/lib/python2.7/argparse.egg-info/PKG-INFO",
		"/usr/lib/python2.7/lib-dynload/Python-2.7.egg-info/PKG-INFO",
		"/usr/lib/python2.7/wsgiref.egg-info/PKG-INFO",
		"/usr/lib/python2.7/dist-packages/PyGObject-3.30.1.egg-info/PKG-INFO",
		"/usr/lib/python2.7/dist-packages/SecretStorage-2.3.1.egg-info/PKG-INFO",
		"/usr/lib/python2.7/dist-packages/keyrings.alt-3.1.egg-info/PKG-INFO",
		"/usr/lib/python2.7/dist-packages/pip-9.0.1.egg-info/PKG-INFO",
		"/usr/lib/python3/dist-packages/systemd_python-234.egg-info/PKG-INFO",
		"/usr/lib/python3/dist-packages/PyYAML-3.12.egg-info/PKG-INFO",
		"/usr/lib/python2.7/site-packages/setuptools-39.1.0.post20180508-py2.7.egg-info/PKG-INFO",
		"/usr/lib/python2.7/site-packages/meld3-1.0.2-py2.7.egg-info/PKG-INFO",
		"/usr/lib/python2.7/site-packages/prettytable-0.7.2-py2.7.egg-info/PKG-INFO",
		"/usr/lib/python2.7/site-packages/cmd2-0.6.8-py2.7.egg-info/PKG-INFO",
		"/usr/lib/python2.7/site-packages/supervisor-3.3.4-py2.7.egg-info/PKG-INFO",
		"usr/lib/python2.7/site-packages/chardet-3.0.4.dist-info/WHEEL",
		"usr/lib/python2.7/site-packages/idna-2.6.dist-info/WHEEL",
		"usr/lib/python2.7/site-packages/certifi-2018.11.29.dist-info/WHEEL",
		"usr/lib/python2.7/site-packages/urllib3-1.22.dist-info/WHEEL",
		"usr/lib/python2.7/site-packages/click-6.7.dist-info/WHEEL",
		"usr/lib/python2.7/site-packages/six-1.10.0.dist-info/WHEEL",
		"usr/lib/python2.7/site-packages/pyparsing-2.3.0.dist-info/WHEEL",
		"usr/lib/python2.7/site-packages/requests-2.18.4.dist-info/WHEEL",
	}
	results := map[string]AppPackage{
		"python:Python":         {ModuleName: "python:Python", Version: "2.7"},
		"python:PyGObject":      {ModuleName: "python:PyGObject", Version: "3.30.1"},
		"python:SecretStorage":  {ModuleName: "python:SecretStorage", Version: "2.3.1"},
		"python:keyrings.alt":   {ModuleName: "python:keyrings.alt", Version: "3.1"},
		"python:pip":            {ModuleName: "python:pip", Version: "9.0.1"},
		"python:systemd_python": {ModuleName: "python:systemd_python", Version: "234"},
		"python:PyYAML":         {ModuleName: "python:PyYAML", Version: "3.12"},
		"python:setuptools":     {ModuleName: "python:setuptools", Version: "39.1.0.post20180508"},
		"python:meld3":          {ModuleName: "python:meld3", Version: "1.0.2"},
		"python:prettytable":    {ModuleName: "python:prettytable", Version: "0.7.2"},
		"python:cmd2":           {ModuleName: "python:cmd2", Version: "0.6.8"},
		"python:supervisor":     {ModuleName: "python:supervisor", Version: "3.3.4"},
		"python:chardet":        {ModuleName: "python:chardet", Version: "3.0.4"},
		"python:idna":           {ModuleName: "python:idna", Version: "2.6"},
		"python:certifi":        {ModuleName: "python:certifi", Version: "2018.11.29"},
		"python:urllib3":        {ModuleName: "python:urllib3", Version: "1.22"},
		"python:click":          {ModuleName: "python:click", Version: "6.7"},
		"python:six":            {ModuleName: "python:six", Version: "1.10.0"},
		"python:pyparsing":      {ModuleName: "python:pyparsing", Version: "2.3.0"},
		"python:requests":       {ModuleName: "python:requests", Version: "2.18.4"},
	}
	ap := NewScanApps(false)
	for _, tt := range tests {
		ap.parsePythonPackage(tt)
	}
	data := make(map[string][]byte)
	data[ap.name()] = ap.marshal()
	pkgs := ap.DerivePkg(data)
	for _, pkg := range pkgs {
		if pk, ok := results[pkg.ModuleName]; !ok || pk.ModuleName != pkg.ModuleName || pk.Version != pkg.Version {
			t.Errorf("Incorrect pkg: %v:%v --- %v:%v\n", pk.ModuleName, pk.Version, pkg.ModuleName, pkg.Version)
		}
	}
	for name, pk := range results {
		found := false
		for _, pkg := range pkgs {
			if name == pkg.ModuleName {
				if pk.ModuleName != pkg.ModuleName || pk.Version != pkg.Version {
					t.Errorf("Incorrect pkg: %v:%v --- %v:%v\n", pk.ModuleName, pk.Version, pkg.ModuleName, pkg.Version)
				}
				found = true
				break
			}
		}
		if !found {
			t.Errorf("not found pkg: %v:%v\n", pk.ModuleName, pk.Version)
		}
	}
}

func TestParseRubyPackage(t *testing.T) {
	tests := []string{
		"/usr/local/lib/ruby/gems/2.6.0/specifications/power_assert-1.1.3.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/net-telnet-0.2.0.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/csv-3.0.4.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/fiddle-1.0.0.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/date-2.0.0.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/zlib-1.0.0.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/matrix-0.1.0.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/rdoc-6.1.0.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/strscan-1.0.0.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/ostruct-0.1.0.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/scanf-1.0.0.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/sync-0.5.0.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/forwardable-1.2.0.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/tracer-0.1.0.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/io-console-0.4.7.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/bigdecimal-1.4.1.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/psych-3.1.0.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/stringio-0.0.2.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/ipaddr-1.2.2.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/bundler-1.17.2.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/e2mmap-0.1.0.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/fcntl-1.0.0.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/logger-1.3.0.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/mutex_m-0.1.0.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/rss-0.2.7.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/openssl-2.1.2.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/etc-1.0.1.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/prime-0.1.0.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/gdbm-2.0.0.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/cmath-1.0.0.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/shell-0.7.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/irb-1.0.0.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/webrick-1.4.2.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/fileutils-1.1.0.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/dbm-1.0.0.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/thwait-0.1.0.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/sdbm-1.0.0.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/json-2.1.0.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/default/rexml-3.1.9.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/minitest-5.11.3.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/test-unit-3.2.9.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/rake-12.3.2.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/did_you_mean-1.3.0.gemspec",
		"/usr/local/lib/ruby/gems/2.6.0/specifications/xmlrpc-0.3.0.gemspec",
	}
	results := map[string]AppPackage{
		"ruby:power_assert": {ModuleName: "ruby:power_assert", Version: "1.1.3"},
		"ruby:net-telnet":   {ModuleName: "ruby:net-telnet", Version: "0.2.0"},
		"ruby:csv":          {ModuleName: "ruby:csv", Version: "3.0.4"},
		"ruby:fiddle":       {ModuleName: "ruby:fiddle", Version: "1.0.0"},
		"ruby:date":         {ModuleName: "ruby:date", Version: "2.0.0"},
		"ruby:zlib":         {ModuleName: "ruby:zlib", Version: "1.0.0"},
		"ruby:matrix":       {ModuleName: "ruby:matrix", Version: "0.1.0"},
		"ruby:rdoc":         {ModuleName: "ruby:rdoc", Version: "6.1.0"},
		"ruby:strscan":      {ModuleName: "ruby:strscan", Version: "1.0.0"},
		"ruby:ostruct":      {ModuleName: "ruby:ostruct", Version: "0.1.0"},
		"ruby:scanf":        {ModuleName: "ruby:scanf", Version: "1.0.0"},
		"ruby:sync":         {ModuleName: "ruby:sync", Version: "0.5.0"},
		"ruby:forwardable":  {ModuleName: "ruby:forwardable", Version: "1.2.0"},
		"ruby:tracer":       {ModuleName: "ruby:tracer", Version: "0.1.0"},
		"ruby:io-console":   {ModuleName: "ruby:io-console", Version: "0.4.7"},
		"ruby:bigdecimal":   {ModuleName: "ruby:bigdecimal", Version: "1.4.1"},
		"ruby:psych":        {ModuleName: "ruby:psych", Version: "3.1.0"},
		"ruby:stringio":     {ModuleName: "ruby:stringio", Version: "0.0.2"},
		"ruby:ipaddr":       {ModuleName: "ruby:ipaddr", Version: "1.2.2"},
		"ruby:bundler":      {ModuleName: "ruby:bundler", Version: "1.17.2"},
		"ruby:e2mmap":       {ModuleName: "ruby:e2mmap", Version: "0.1.0"},
		"ruby:fcntl":        {ModuleName: "ruby:fcntl", Version: "1.0.0"},
		"ruby:logger":       {ModuleName: "ruby:logger", Version: "1.3.0"},
		"ruby:mutex_m":      {ModuleName: "ruby:mutex_m", Version: "0.1.0"},
		"ruby:rss":          {ModuleName: "ruby:rss", Version: "0.2.7"},
		"ruby:openssl":      {ModuleName: "ruby:openssl", Version: "2.1.2"},
		"ruby:etc":          {ModuleName: "ruby:etc", Version: "1.0.1"},
		"ruby:prime":        {ModuleName: "ruby:prime", Version: "0.1.0"},
		"ruby:gdbm":         {ModuleName: "ruby:gdbm", Version: "2.0.0"},
		"ruby:cmath":        {ModuleName: "ruby:cmath", Version: "1.0.0"},
		"ruby:shell":        {ModuleName: "ruby:shell", Version: "0.7"},
		"ruby:irb":          {ModuleName: "ruby:irb", Version: "1.0.0"},
		"ruby:webrick":      {ModuleName: "ruby:webrick", Version: "1.4.2"},
		"ruby:fileutils":    {ModuleName: "ruby:fileutils", Version: "1.1.0"},
		"ruby:dbm":          {ModuleName: "ruby:dbm", Version: "1.0.0"},
		"ruby:thwait":       {ModuleName: "ruby:thwait", Version: "0.1.0"},
		"ruby:sdbm":         {ModuleName: "ruby:sdbm", Version: "1.0.0"},
		"ruby:json":         {ModuleName: "ruby:json", Version: "2.1.0"},
		"ruby:rexml":        {ModuleName: "ruby:rexml", Version: "3.1.9"},
		"ruby:minitest":     {ModuleName: "ruby:minitest", Version: "5.11.3"},
		"ruby:test-unit":    {ModuleName: "ruby:test-unit", Version: "3.2.9"},
		"ruby:rake":         {ModuleName: "ruby:rake", Version: "12.3.2"},
		"ruby:did_you_mean": {ModuleName: "ruby:did_you_mean", Version: "1.3.0"},
		"ruby:xmlrpc":       {ModuleName: "ruby:xmlrpc", Version: "0.3.0"},
	}
	ap := NewScanApps(false)
	for _, tt := range tests {
		ap.parseRubyPackage(tt)
	}
	data := make(map[string][]byte)
	data[ap.name()] = ap.marshal()
	pkgs := ap.DerivePkg(data)
	for _, pkg := range pkgs {
		if pk, ok := results[pkg.ModuleName]; !ok || pk.ModuleName != pkg.ModuleName || pk.Version != pkg.Version {
			t.Errorf("Incorrect pkg: %v:%v --- %v:%v\n", pk.ModuleName, pk.Version, pkg.ModuleName, pkg.Version)
		}
	}
	for name, pk := range results {
		found := false
		for _, pkg := range pkgs {
			if name == pkg.ModuleName {
				if pk.ModuleName != pkg.ModuleName || pk.Version != pkg.Version {
					t.Errorf("Incorrect pkg: %v:%v --- %v:%v\n", pk.ModuleName, pk.Version, pkg.ModuleName, pkg.Version)
				}
				found = true
				break
			}
		}
		if !found {
			t.Errorf("not found pkg: %v:%v\n", pk.ModuleName, pk.Version)
		}
	}
}

func TestParseJarPackage(t *testing.T) {
	// NVSHAS-8757
	m := `
Manifest-Version: 1.0
Automatic-Module-Name: org.postgresql.jdbc
Bundle-Activator: org.postgresql.osgi.PGBundleActivator
Bundle-Copyright: Copyright (c) 2003-2020, PostgreSQL Global Developme
 nt Group
Bundle-Description: Java JDBC driver for PostgreSQL database
Bundle-DocURL: https://jdbc.postgresql.org/
Bundle-License: BSD-2-Clause
Bundle-ManifestVersion: 2
Bundle-Name: PostgreSQL JDBC Driver
Bundle-SymbolicName: org.postgresql.jdbc
Bundle-Vendor: PostgreSQL Global Development Group
Bundle-Version: 42.2.23
`
	r := strings.NewReader(m)
	pkg, _ := parseJarManifestFile("", r)
	if pkg.ModuleName != "org.postgresql:postgresql" {
		t.Errorf("Wrong jar package: %+v\n", pkg)
	}

	m = `
Manifest-Version: 1.0
Bundle-ManifestVersion: 2
Bundle-Name: tomcat-embed-core
Bundle-SymbolicName: org.apache.tomcat-embed-core
Bundle-Version: 10.1.11
Implementation-Title: Apache Tomcat
Implementation-Vendor: Apache Software Foundation
Implementation-Version: 10.1.11
Specification-Title: Apache Tomcat
Specification-Vendor: Apache Software Foundation
Specification-Version: 10.1
X-Compile-Source-JDK: 11
X-Compile-Target-JDK: 11
`
	r = strings.NewReader(m)
	pkg, _ = parseJarManifestFile("", r)
	if pkg.ModuleName != "org.apache.tomcat.embed:tomcat-embed-core" && pkg.Version != "10.1.11" {
		t.Errorf("Wrong jar package: %+v\n", pkg)
	}

	m = `
Manifest-Version: 1.0
Ant-Version: Apache Ant 1.10.6
Created-By: 1.8.0_201-b09 (Oracle Corporation)
Main-Class: com.sun.jna.Native
Implementation-Title: com.sun.jna
Implementation-Vendor: JNA Development Team
Implementation-Version: 5.5.0 (b0)
Specification-Title: Java Native Access (JNA)
Specification-Vendor: JNA Development Team
Specification-Version: 5
Automatic-Module-Name: com.sun.jna
Bundle-Category: jni
Bundle-ManifestVersion: 2
Bundle-Name: jna
Bundle-Description: JNA Library
Bundle-SymbolicName: com.sun.jna
Bundle-Version: 5.5.0
Bundle-RequiredExecutionEnvironment: JavaSE-1.6
Bundle-Vendor: JNA Development Team
Bundle-ActivationPolicy: lazy
`
	r = strings.NewReader(m)
	pkg, _ = parseJarManifestFile("", r)
	if pkg.ModuleName != "JNA Development Team:com.sun.jna" && pkg.Version != "5.5.0" {
		t.Errorf("Wrong jar package: %+v\n", pkg)
	}
}

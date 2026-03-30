package scan

import (
	"testing"

	_ "github.com/glebarez/go-sqlite"
	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
	"github.com/stretchr/testify/assert"
)

func TestSLESPackageList(t *testing.T) {
	db, err := rpmdb.Open("testdata/Packages.sles")
	if err != nil {
		t.Error(err.Error())
	} else {
		defer db.Close()
	}

	pkgs, err := db.ListPackages()
	if err != nil {
		t.Error(err.Error())
	}

	if len(pkgs) != 159 {
		t.Errorf("incorrect package count: %d\n", len(pkgs))
	}

	for _, pkg := range pkgs {
		switch pkg.Name {
		case "java-11-openjdk":
			if pkg.Version != "11.0.13.0" || pkg.Release != "3.68.1" {
				t.Errorf("incorrect package version: %s-%s\n", pkg.Version, pkg.Release)
			}
		}
	}
}

func TestUbiPackageList(t *testing.T) {
	db, err := rpmdb.Open("testdata/Packages.ubi")
	if err != nil {
		t.Errorf("%s", err.Error())
	} else {
		defer db.Close()
	}

	pkgs, err := db.ListPackages()
	if err != nil {
		t.Errorf("%s", err.Error())
	}

	if len(pkgs) != 180 {
		t.Errorf("incorrect package count: %d\n", len(pkgs))
	}

	for _, pkg := range pkgs {
		switch pkg.Name {
		case "redhat-release":
			if pkg.Version != "8.1" || pkg.Release != "3.3.el8" {
				t.Errorf("incorrect package version: %s-%s\n", pkg.Version, pkg.Release)
			}
		case "json-glib":
			if pkg.Version != "1.4.4" || pkg.Release != "1.el8" {
				t.Errorf("incorrect package version: %s-%s\n", pkg.Version, pkg.Release)
			}
		}
	}
}

func TestFedoraPackageList(t *testing.T) {
	db, err := rpmdb.Open("testdata/rpmdb.sqlite.fedora")
	if err != nil {
		t.Errorf("%s", err.Error())
	} else {
		defer db.Close()
	}

	pkgs, err := db.ListPackages()
	assert.NoError(t, err)
	assert.Len(t, pkgs, 142, "incorrect package count")
	assert.NotNil(t, pkgs, "package list should not be nil")

	var fedoraPkg *rpmdb.PackageInfo
loop:
	for _, pkg := range pkgs {
		switch pkg.Name {
		case "fedora-release-common":
			fedoraPkg = pkg
			break loop
		}
	}
	assert.NotNil(t, fedoraPkg)

	assert.Equal(t, "fedora-release-common", fedoraPkg.Name)
	assert.Equal(t, "43", fedoraPkg.Version)
	assert.Equal(t, "26", fedoraPkg.Release)
}

package scan

import (
	"testing"

	rpmdb "github.com/neuvector/go-rpmdb/pkg"
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

package osutil

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	log "github.com/sirupsen/logrus"
)

type MockFile struct {
	Pid          int
	SymlinkFile  string
	SymlinkFolders map[string]string
	DirsToCreate []string
	Symlink      string
	Exist        bool
	ResolvePath  string
	ExpectResult string
}

func PrepareCircularLayerSymlink(root string) []MockFile {
	return []MockFile{
		// length 1 cycle
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin", "C1P1"),
			Symlink:      "../bin/C1P1",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Error: Circular symlink detected. The symlink structure creates a loop and cannot be resolved.",
		},

		// length 2 cycle
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin", "C2P1"),
			Symlink:      "../bin/C2P2",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Error: Circular symlink detected. The symlink structure creates a loop and cannot be resolved.",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin", "C2P2"),
			Symlink:      "./../bin/C2P1",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Error: Circular symlink detected. The symlink structure creates a loop and cannot be resolved.",
		},

		// length 3 cycle
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin", "C3P1"),
			Symlink:      "../bin/C3P2",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Error: Circular symlink detected. The symlink structure creates a loop and cannot be resolved.",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin", "C3P2"),
			Symlink:      "./../bin/C3P3",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Error: Circular symlink detected. The symlink structure creates a loop and cannot be resolved.",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin", "C3P3"),
			Symlink:      "../bin/C3P1",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Error: Circular symlink detected. The symlink structure creates a loop and cannot be resolved.",
		},

		// length 4 cycle => fit the rule
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin", "C4P1"),
			Symlink:      "../bin/C4P2",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Error: Circular symlink detected. The symlink structure creates a loop and cannot be resolved.",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin", "C4P2"),
			Symlink:      "./../bin/C4P3",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Error: Circular symlink detected. The symlink structure creates a loop and cannot be resolved.",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin", "C4P3"),
			Symlink:      "../bin/C4P4",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Error: Circular symlink detected. The symlink structure creates a loop and cannot be resolved.",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin", "C4P4"),
			Symlink:      "../bin/C4P1",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Error: Circular symlink detected. The symlink structure creates a loop and cannot be resolved.",
		},

		// length 5 cycle => break the rule
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin", "C5P1"),
			Symlink:      "../bin/C4P1",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Get file symlink fail",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin", "C5P2"),
			Symlink:      "./../bin/C5P3",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Get file symlink fail",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin", "C5P3"),
			Symlink:      "../bin/C5P4",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Get file symlink fail",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin", "C5P4"),
			Symlink:      "../bin/C5P5",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Get file symlink fail",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin", "C5P5"),
			Symlink:      "./../bin/C5P1",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Get file symlink fail",
		},

		// length 6 cycle => break the rule
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin", "C6P1"),
			Symlink:      "../bin/C6P2",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Get file symlink fail",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin", "C6P2"),
			Symlink:      "./../bin/C6P3",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Get file symlink fail",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin", "C6P3"),
			Symlink:      "../bin/C6P4",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Get file symlink fail",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin", "C6P4"),
			Symlink:      "../bin/C6P5",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Get file symlink fail",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin", "C6P5"),
			Symlink:      "./../bin/C6P6",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Get file symlink fail",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin", "C6P6"),
			Symlink:      "../bin/C6P1",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Get file symlink fail",
		},

		// random access to one of the cycle, say cycle with length 2
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin", "CRP1"),
			Symlink:      "../bin/C2P1",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Error: Circular symlink detected. The symlink structure creates a loop and cannot be resolved.",
		},
	}
}

func PrepareNestLayerSymlink(root string) []MockFile {
	return []MockFile{
		// one layer
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin", "rpmNest"),
			Symlink:      "../bin/rpmverify",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "1", "root", "bin", "rpm"),
			ExpectResult: "",
		},
		{
			Pid:          2,
			SymlinkFile:  filepath.Join(root, "proc", "2", "root", "bin", "rpmNest"),
			Symlink:      "./../bin/rpmverify",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "2", "root", "bin", "rpm"),
			ExpectResult: "",
		},
		{
			Pid:          3,
			SymlinkFile:  filepath.Join(root, "proc", "3", "root", "bin", "rpmNest"),
			Symlink:      "../../bin/rpmverify",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "3", "root", "bin", "rpm"),
			ExpectResult: "",
		},
		{
			Pid:          4,
			SymlinkFile:  filepath.Join(root, "proc", "4", "root", "bin", "rpmNest"),
			Symlink:      "../../../bin/rpmverify",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "4", "root", "bin", "rpm"),
			ExpectResult: "",
		},
		{
			Pid:          5,
			SymlinkFile:  filepath.Join(root, "proc", "5", "root", "bin", "rpmNest"),
			Symlink:      "./../../../bin/rpmverify",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "5", "root", "bin", "rpm"),
			ExpectResult: "",
		},
		{
			Pid:          6,
			SymlinkFile:  filepath.Join(root, "proc", "6", "root", "bin", "rpmNest"),
			Symlink:      "../../bin/notExist",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "lstat " + filepath.Join(root, "proc", "6", "root", "bin", "rpm") + ": no such file or directory",
		},
		{
			Pid:          7,
			SymlinkFile:  filepath.Join(root, "proc", "7", "root", "bin", "rpmNest"),
			Symlink:      "../../bin/rpmquery",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "bin", "pwd"),
			ExpectResult: "lstat " + filepath.Join(root, "proc", "7", "root", filepath.Join(root, "bin", "pwd")) + ": no such file or directory",
		},

		// two layer
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin", "rpmNest1"),
			Symlink:      "../bin/rpmNest",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "1", "root", "bin", "rpm"),
			ExpectResult: "",
		},
		{
			Pid:          2,
			SymlinkFile:  filepath.Join(root, "proc", "2", "root", "bin", "rpmNest1"),
			Symlink:      "./../bin/rpmNest",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "2", "root", "bin", "rpm"),
			ExpectResult: "",
		},
		{
			Pid:          3,
			SymlinkFile:  filepath.Join(root, "proc", "3", "root", "bin", "rpmNest1"),
			Symlink:      "../../bin/rpmNest",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "3", "root", "bin", "rpm"),
			ExpectResult: "",
		},
		{
			Pid:          4,
			SymlinkFile:  filepath.Join(root, "proc", "4", "root", "bin", "rpmNest1"),
			Symlink:      "../../../bin/rpmNest",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "4", "root", "bin", "rpm"),
			ExpectResult: "",
		},
		{
			Pid:          5,
			SymlinkFile:  filepath.Join(root, "proc", "5", "root", "bin", "rpmNest1"),
			Symlink:      "./../../../bin/rpmNest",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "5", "root", "bin", "rpm"),
			ExpectResult: "",
		},
		{
			Pid:          6,
			SymlinkFile:  filepath.Join(root, "proc", "6", "root", "bin", "rpmNest1"),
			Symlink:      "../../bin/rpmNest",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "lstat " + filepath.Join(root, "proc", "6", "root", "bin", "rpm") + ": no such file or directory",
		},
		{
			Pid:          7,
			SymlinkFile:  filepath.Join(root, "proc", "7", "root", "bin", "rpmNest1"),
			Symlink:      "../../bin/rpmNest",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "bin", "pwd"),
			ExpectResult: "lstat " + filepath.Join(root, "proc", "7", "root", filepath.Join(root, "bin", "pwd")) + ": no such file or directory",
		},
	}
}

func PrepareSingleLayerAbsSymlink(root string) []MockFile {
	return []MockFile{
		// absolute path
		{
			Pid:          8,
			SymlinkFile:  filepath.Join(root, "proc", "8", "root", "bin", "rpmverify"),
			Symlink:      filepath.Join("/bin", "rpm"),
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "8", "root", "bin", "rpm"),
			ExpectResult: "",
		},
		{
			Pid:          9,
			SymlinkFile:  filepath.Join(root, "proc", "9", "root", "bin", "rpmverify"),
			Symlink:      filepath.Join("/bin", "neu", "vector", "rpm"),
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "9", "root", "bin", "neu", "vector", "rpm"),
			ExpectResult: "",
		},
		{
			Pid:          10,
			SymlinkFile:  filepath.Join(root, "proc", "10", "root", "bin", "rpmverify"),
			Symlink:      filepath.Join("/bin", "rpm"),
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "lstat " + filepath.Join(root, "proc", "10", "root", "bin", "rpm") + ": no such file or directory",
		},
		{
			Pid:          11,
			SymlinkFile:  filepath.Join(root, "proc", "11", "root", "bin", "rpmverify"),
			Symlink:      filepath.Join("/bin", "neu", "vector", "rpm"),
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "11", "root", "bin", "rpm"),
			ExpectResult: "lstat " + filepath.Join(root, "proc", "11", "root", "bin", "neu", "vector", "rpm") + ": no such file or directory",
		},
		{
			Pid:          12,
			SymlinkFile:  filepath.Join(root, "proc", "12", "root", "bin", "rpmverify"),
			Symlink:      filepath.Join("/a", "b", "..", "..", "..", "bin", "rpm"),
			Exist:        true,
			ResolvePath:  filepath.Join(root, "bin", "rpm"),
			ExpectResult: "lstat " + filepath.Join(root, "proc", "12", "root", "bin", "rpm") + ": no such file or directory",
		},
		{
			Pid:          13,
			SymlinkFile:  filepath.Join(root, "proc", "13", "root", "bin", "rpmverify"),
			Symlink:      filepath.Join("/current", "utils", "rpm"),
			DirsToCreate: []string {
				filepath.Join(root, "proc", "13", "root", "current"),
				filepath.Join(root, "proc", "13", "root", "test"),
				filepath.Join(root, "proc", "13", "root", "test", "v2", "nvbin"),
				filepath.Join(root, "proc", "13", "root", "test", "v2", "utils"),
			},
			SymlinkFolders : map[string]string{
				filepath.Join(root, "proc", "13", "root", "current"): filepath.Join("test", "v1"),
				filepath.Join(root, "proc", "13", "root", "test", "v1"): filepath.Join("test", "v2"),
				filepath.Join(root, "proc", "13", "root", "test", "v2", "utils"): filepath.Join("test", "v2", "nvbin"),
			},
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "13", "root", "test", "v2", "nvbin", "rpm"),
			ExpectResult: "",
		},
		{
			Pid:          14,
			SymlinkFile:  filepath.Join(root, "proc", "14", "root", "bin", "rpmverify"),
			Symlink:      filepath.Join("/current", "utils", "rpm"),
			DirsToCreate: []string {
				filepath.Join(root, "proc", "14", "root", "current"),
				filepath.Join(root, "proc", "14", "root", "test"),
				filepath.Join(root, "proc", "14", "root", "test", "v2", "nvbin"),
				filepath.Join(root, "proc", "14", "root", "test", "v2", "utils"),
			},
			SymlinkFolders : map[string]string{
				filepath.Join(root, "proc", "14", "root", "current"): filepath.Join("test", "v1"),
				filepath.Join(root, "proc", "14", "root", "test", "v1"): filepath.Join("test", "v2"),
				filepath.Join(root, "proc", "14", "root", "test", "v2", "utils"): filepath.Join("test", "v2", "nvbin"),
			},
			Exist:        false,
			ResolvePath:  filepath.Join(root, "proc", "14", "root", "test", "v2", "nvbin", "rpm"),
			ExpectResult: "lstat " + filepath.Join(root, "proc", "14", "root", "current", "utils", "rpm") + ": no such file or directory",
		},
		{
			Pid:          19,
			SymlinkFile:  filepath.Join(root, "proc", "19", "root", "bin", "rpmverify"),
			Symlink:      filepath.Join("/current", "utils", "rpm"),
			DirsToCreate: []string {
				filepath.Join(root, "proc", "19", "root", "current"),
				filepath.Join(root, "proc", "19", "root", "test"),
				filepath.Join(root, "proc", "19", "root", "nv"),
				filepath.Join(root, "proc", "19", "root", "test", "v2", "nvbin"),
				filepath.Join(root, "proc", "19", "root", "test", "v2", "utils"),
			},
			SymlinkFolders : map[string]string{
				filepath.Join(root, "proc", "19", "root", "current"): filepath.Join("test", "v1"),
				filepath.Join(root, "proc", "19", "root", "nv"): filepath.Join("test"),
				filepath.Join(root, "proc", "19", "root", "test", "v1"): filepath.Join("test", "v2"),
				filepath.Join(root, "proc", "19", "root", "test", "v2", "utils"): filepath.Join("test", "v2", "nvbin"),
			},
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "19", "root", "test", "v2", "nvbin", "rpm"),
			ExpectResult: "",
		},
		{
			Pid:          20,
			SymlinkFile:  filepath.Join(root, "proc", "20", "root", "bin", "rpmverify"),
			Symlink:      filepath.Join("/current", "utils", "rpm"),
			DirsToCreate: []string {
				filepath.Join(root, "proc", "20", "root", "current"),
				filepath.Join(root, "proc", "20", "root", "test"),
				filepath.Join(root, "proc", "19", "root", "nv"),
				filepath.Join(root, "proc", "20", "root", "test", "v2", "nvbin"),
				filepath.Join(root, "proc", "20", "root", "test", "v2", "utils"),
			},
			SymlinkFolders : map[string]string{
				filepath.Join(root, "proc", "20", "root", "current"): filepath.Join("test", "v1"),
				filepath.Join(root, "proc", "20", "root", "nv"): filepath.Join("test"),
				filepath.Join(root, "proc", "20", "root", "test", "v1"): filepath.Join("test", "v2"),
				filepath.Join(root, "proc", "20", "root", "test", "v2", "utils"): filepath.Join("test", "v2", "nvbin"),
			},
			Exist:        false,
			ResolvePath:  filepath.Join(root, "proc", "20", "root", "test", "v2", "nvbin", "rpm"),
			ExpectResult: "lstat " + filepath.Join(root, "proc", "20", "root", "current", "utils", "rpm") + ": no such file or directory",
		},
	}
}

func PrepareSingleLayerSymlink(root string) []MockFile {
	return []MockFile{
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin", "rpmverify"),
			Symlink:      "../bin/rpm",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "1", "root", "bin", "rpm"),
			ExpectResult: "",
		},
		{
			Pid:          2,
			SymlinkFile:  filepath.Join(root, "proc", "2", "root", "bin", "rpmverify"),
			Symlink:      "./../bin/rpm",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "2", "root", "bin", "rpm"),
			ExpectResult: "",
		},
		{
			Pid:          3,
			SymlinkFile:  filepath.Join(root, "proc", "3", "root", "bin", "rpmverify"),
			Symlink:      "../../bin/rpm",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "3", "root", "bin", "rpm"),
			ExpectResult: "",
		},
		{
			Pid:          4,
			SymlinkFile:  filepath.Join(root, "proc", "4", "root", "bin", "rpmverify"),
			Symlink:      "../../../bin/rpm",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "4", "root", "bin", "rpm"),
			ExpectResult: "",
		},
		{
			Pid:          5,
			SymlinkFile:  filepath.Join(root, "proc", "5", "root", "bin", "rpmverify"),
			Symlink:      "./../../../bin/rpm",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "5", "root", "bin", "rpm"),
			ExpectResult: "",
		},
		{
			Pid:          6,
			SymlinkFile:  filepath.Join(root, "proc", "6", "root", "bin", "notExist"),
			Symlink:      "../../bin/rpm",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "lstat " + filepath.Join(root, "proc", "6", "root", "bin", "rpm") + ": no such file or directory",
		},
		{
			Pid:          7,
			SymlinkFile:  filepath.Join(root, "proc", "7", "root", "bin", "rpmquery"),
			Symlink:      filepath.Join(root, "bin", "pwd"),
			Exist:        true,
			ResolvePath:  filepath.Join(root, "bin", "pwd"),
			ExpectResult: "lstat " + filepath.Join(root, "proc", "7", "root", filepath.Join(root, "bin", "pwd")) + ": no such file or directory",
		},
		{
			Pid:          15,
			SymlinkFile:  filepath.Join(root, "proc", "15", "root", "bin", "rpmverify"),
			Symlink:      filepath.Join("..", "..", "current", "utils", "rpm"),
			DirsToCreate: []string {
				filepath.Join(root, "proc", "15", "root", "current"),
				filepath.Join(root, "proc", "15", "root", "test"),
				filepath.Join(root, "proc", "15", "root", "test", "v2", "nvbin"),
				filepath.Join(root, "proc", "15", "root", "test", "v2", "utils"),
			},
			SymlinkFolders : map[string]string{
				filepath.Join(root, "proc", "15", "root", "current"): filepath.Join("test", "v1"),
				filepath.Join(root, "proc", "15", "root", "test", "v1"): filepath.Join("test", "v2"),
				filepath.Join(root, "proc", "15", "root", "test", "v2", "utils"): filepath.Join("test", "v2", "nvbin"),
			},
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "15", "root", "test", "v2", "nvbin", "rpm"),
			ExpectResult: "",
		},
		{
			Pid:          16,
			SymlinkFile:  filepath.Join(root, "proc", "16", "root", "bin", "rpmverify"),
			Symlink:      filepath.Join("..", "..", "current", "utils", "rpm"),
			DirsToCreate: []string {
				filepath.Join(root, "proc", "16", "root", "current"),
				filepath.Join(root, "proc", "16", "root", "test"),
				filepath.Join(root, "proc", "16", "root", "test", "v2", "nvbin"),
				filepath.Join(root, "proc", "16", "root", "test", "v2", "utils"),
			},
			SymlinkFolders : map[string]string{
				filepath.Join(root, "proc", "16", "root", "current"): filepath.Join("test", "v1"),
				filepath.Join(root, "proc", "16", "root", "test", "v1"): filepath.Join("test", "v2"),
				filepath.Join(root, "proc", "16", "root", "test", "v2", "utils"): filepath.Join("test", "v2", "nvbin"),
			},
			Exist:        false,
			ResolvePath:  filepath.Join(root, "proc", "16", "root", "test", "v2", "nvbin", "rpm"),
			ExpectResult: "lstat " + filepath.Join(root, "proc", "16", "root", "current", "utils", "rpm") + ": no such file or directory",
		},
		{
			Pid:          17,
			SymlinkFile:  filepath.Join(root, "proc", "17", "root", "bin", "rpmverify"),
			Symlink:      filepath.Join("..", "..", "current", "utils", "rpm"),
			DirsToCreate: []string {
				filepath.Join(root, "proc", "17", "root", "current"),
				filepath.Join(root, "proc", "17", "root", "test"),
				filepath.Join(root, "proc", "17", "root", "nv"),
				filepath.Join(root, "proc", "17", "root", "test", "v2", "nvbin"),
				filepath.Join(root, "proc", "17", "root", "test", "v2", "utils"),
			},
			SymlinkFolders : map[string]string{
				filepath.Join(root, "proc", "17", "root", "current"): filepath.Join("nv", "v1"),
				filepath.Join(root, "proc", "17", "root", "nv"): filepath.Join("test"),
				filepath.Join(root, "proc", "17", "root", "test", "v1"): filepath.Join("test", "v2"),
				filepath.Join(root, "proc", "17", "root", "test", "v2", "utils"): filepath.Join("test", "v2", "nvbin"),
			},
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "17", "root", "test", "v2", "nvbin", "rpm"),
			ExpectResult: "",
		},
		{
			Pid:          18,
			SymlinkFile:  filepath.Join(root, "proc", "18", "root", "bin", "rpmverify"),
			Symlink:      filepath.Join("..", "..", "current", "utils", "rpm"),
			DirsToCreate: []string {
				filepath.Join(root, "proc", "18", "root", "current"),
				filepath.Join(root, "proc", "18", "root", "test"),
				filepath.Join(root, "proc", "18", "root", "nv"),
				filepath.Join(root, "proc", "18", "root", "test", "v2", "nvbin"),
				filepath.Join(root, "proc", "18", "root", "test", "v2", "utils"),
			},
			SymlinkFolders : map[string]string{
				filepath.Join(root, "proc", "18", "root", "current"): filepath.Join("nv", "v1"),
				filepath.Join(root, "proc", "18", "root", "nv"): filepath.Join("test"),
				filepath.Join(root, "proc", "18", "root", "test", "v1"): filepath.Join("test", "v2"),
				filepath.Join(root, "proc", "18", "root", "test", "v2", "utils"): filepath.Join("test", "v2", "nvbin"),
			},
			Exist:        false,
			ResolvePath:  filepath.Join(root, "proc", "18", "root", "test", "v2", "nvbin", "rpm"),
			ExpectResult: "lstat " + filepath.Join(root, "proc", "18", "root", "current", "utils", "rpm") + ": no such file or directory",
		},
	}
}

func PrepareMockFilesMetaData(root string) []MockFile {
	mockFilesMetaData := append(PrepareSingleLayerSymlink(root), PrepareSingleLayerAbsSymlink(root)...)
	mockFilesMetaData = append(mockFilesMetaData, PrepareNestLayerSymlink(root)...)
	mockFilesMetaData = append(mockFilesMetaData, PrepareCircularLayerSymlink(root)...)
	return mockFilesMetaData
}

func initMockFileSystem(root string, mockFileMetaDatas []MockFile) error {
	for _, mockFileMetaData := range mockFileMetaDatas {

		if err := os.MkdirAll(filepath.Dir(mockFileMetaData.SymlinkFile), 0755); err != nil {
			return err
		}

		if err := os.Symlink(mockFileMetaData.Symlink, mockFileMetaData.SymlinkFile); err != nil {
			log.WithFields(log.Fields{"mockFileMetaData.SymlinkFile": mockFileMetaData.SymlinkFile, "mockFileMetaData.Symlink": mockFileMetaData.Symlink, "err": err}).Info("Failed to create symlink:")
			return err
		}

		for _, dir := range mockFileMetaData.DirsToCreate {
			if err := os.MkdirAll(dir, 0755); err != nil {
				log.WithFields(log.Fields{"dir": dir, "err": err}).Debug("Failed to create directory:")
				return err
			}
		}

		for link, target := range mockFileMetaData.SymlinkFolders {
			if _, err := os.Lstat(link); err == nil {
				if rmErr := os.Remove(link); rmErr != nil {
					log.WithFields(log.Fields{"link": link, "err": rmErr}).Debug("Failed to to remove existing link/file:")
					continue
				}
			} else if !os.IsNotExist(err) {
				log.WithFields(log.Fields{"link": link, "err": err}).Debug("Failed to check if link exists:")
				continue
			}
	
			if err := os.Symlink(target, link); err != nil {
				log.WithFields(log.Fields{"from": link, "to": target, "err": err}).Debug("Failed to create symlink:")
			}
		}

		if mockFileMetaData.Exist {
			if err := os.MkdirAll(filepath.Dir(mockFileMetaData.ResolvePath), 0755); err != nil {
				log.WithFields(log.Fields{"mockFileMetaData.ResolvePath": mockFileMetaData.ResolvePath, "err": err}).Info("Failed to create parent directory of mockFileMetaData.ResolvePath:")
				return err
			}
			if _, err := os.Create(mockFileMetaData.ResolvePath); err != nil {
				log.WithFields(log.Fields{"mockFileMetaData.ResolvePath": mockFileMetaData.ResolvePath, "err": err}).Info("Failed to create mockFileMetaData.ResolvePath:")
				return err
			}
		}
	}

	return nil
}

func TestGetContainerRealFilePath(t *testing.T) {
	// Define the base directory for the test, using a temporary directory
	// create a /proc/ like folder then mimic the link.
	// type of test cases
	// 1. one layer of symlink
	// 2. abs path for symlink
	// 3. append another layer on type 1, make it a nest link
	// 4. circular link
	tempDir, err := ioutil.TempDir("", "proc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	mockFileMetaDatas := PrepareMockFilesMetaData(tempDir)

	if err := initMockFileSystem(tempDir, mockFileMetaDatas); err != nil {
		t.Errorf("Error: initMockFileSystem failure: %s \n", err)
	}

	for _, mockFileMetaData := range mockFileMetaDatas {
		if resolvePath, err := GetContainerRealFilePath(mockFileMetaData.Pid, mockFileMetaData.SymlinkFile, true); err != nil {
			if err.Error() != mockFileMetaData.ExpectResult {
				t.Errorf("Error: Unknown failure: %s, expect: %s\n", err.Error(), mockFileMetaData.ExpectResult)
			}
		} else if resolvePath != mockFileMetaData.ResolvePath {
			t.Errorf("Error: failed to reolve the path of %s with result %s\n", mockFileMetaData.ResolvePath, resolvePath)
		}
	}
}

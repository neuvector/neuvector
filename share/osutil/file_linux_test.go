package osutil

import (
	"os"
	"testing"
	"path/filepath"
	"io/ioutil"

	log "github.com/sirupsen/logrus"
)

type MockFile struct {
	Pid 		  int
	SymlinkFile   string
	Symlink 	  string
	Exist  		  bool
	ResolvePath   string
	ExpectResult  string
}

func PrepareCircularLayerSymlink(root string) []MockFile {
	return []MockFile{
		// length 1 cycle 
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin","C1P1"),
			Symlink:      "../bin/C1P1",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Error: Circular symlink detected. The symlink structure creates a loop and cannot be resolved.",
		},

		// length 2 cycle 
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin","C2P1"),
			Symlink:      "../bin/C2P2",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Error: Circular symlink detected. The symlink structure creates a loop and cannot be resolved.",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin","C2P2"),
			Symlink:      "./../bin/C2P1",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Error: Circular symlink detected. The symlink structure creates a loop and cannot be resolved.",
		},

		// length 3 cycle
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin","C3P1"),
			Symlink:      "../bin/C3P2",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Error: Circular symlink detected. The symlink structure creates a loop and cannot be resolved.",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin","C3P2"),
			Symlink:      "./../bin/C3P3",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Error: Circular symlink detected. The symlink structure creates a loop and cannot be resolved.",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin","C3P3"),
			Symlink:      "../bin/C3P1",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Error: Circular symlink detected. The symlink structure creates a loop and cannot be resolved.",
		},

		// length 4 cycle => fit the rule
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin","C4P1"),
			Symlink:      "../bin/C4P2",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Error: Circular symlink detected. The symlink structure creates a loop and cannot be resolved.",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin","C4P2"),
			Symlink:      "./../bin/C4P3",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Error: Circular symlink detected. The symlink structure creates a loop and cannot be resolved.",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin","C4P3"),
			Symlink:      "../bin/C4P4",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Error: Circular symlink detected. The symlink structure creates a loop and cannot be resolved.",
		},		
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin","C4P4"),
			Symlink:      "../bin/C4P1",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Error: Circular symlink detected. The symlink structure creates a loop and cannot be resolved.",
		},

		// length 5 cycle => break the rule
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin","C5P1"),
			Symlink:      "../bin/C4P1",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Get file symlink fail",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin","C5P2"),
			Symlink:      "./../bin/C5P3",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Get file symlink fail",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin","C5P3"),
			Symlink:      "../bin/C5P4",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Get file symlink fail",
		},		
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin","C5P4"),
			Symlink:      "../bin/C5P5",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Get file symlink fail",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin","C5P5"),
			Symlink:      "./../bin/C5P1",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Get file symlink fail",
		},

		// length 6 cycle => break the rule
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin","C6P1"),
			Symlink:      "../bin/C6P2",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Get file symlink fail",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin","C6P2"),
			Symlink:      "./../bin/C6P3",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Get file symlink fail",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin","C6P3"),
			Symlink:      "../bin/C6P4",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Get file symlink fail",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin","C6P4"),
			Symlink:      "../bin/C6P5",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Get file symlink fail",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin","C6P5"),
			Symlink:      "./../bin/C6P6",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Get file symlink fail",
		},
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin","C6P6"),
			Symlink:      "../bin/C6P1",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Get file symlink fail",
		},

		// random access to one of the cycle, say cycle with length 2
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin","CRP1"),
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
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin","rpmNest"),
			Symlink:      "../bin/rpmverify",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "1", "root", "bin","rpm"),
			ExpectResult: "",
		},
		{
			Pid:          2,
			SymlinkFile:  filepath.Join(root, "proc", "2", "root", "bin","rpmNest"),
			Symlink:      "./../bin/rpmverify",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "2", "root", "bin","rpm"),
			ExpectResult: "",
		},
		{
			Pid:          3,
			SymlinkFile:  filepath.Join(root, "proc", "3", "root", "bin","rpmNest"),
			Symlink:      "../../bin/rpmverify",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "3", "root", "bin","rpm"),
			ExpectResult: "",
		},
		{
			Pid:          4,
			SymlinkFile:  filepath.Join(root, "proc", "4", "root", "bin","rpmNest"),
			Symlink:      "../../../bin/rpmverify",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "4", "root", "bin","rpm"),
			ExpectResult: "",
		},
		{
			Pid:          5,
			SymlinkFile:  filepath.Join(root, "proc", "5", "root", "bin","rpmNest"),
			Symlink:      "./../../../bin/rpmverify",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "5", "root", "bin","rpm"),
			ExpectResult: "",
		},
		{
			Pid:          6,
			SymlinkFile:  filepath.Join(root, "proc", "6", "root", "bin","rpmNest"),
			Symlink:      "../../bin/notExist",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Get file symlink fail",
		},
		{
			Pid:          7,
			SymlinkFile:  filepath.Join(root, "proc", "7", "root", "bin","rpmNest"),
			Symlink:      "../../bin/rpmquery",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "bin", "pwd"),
			ExpectResult: "Get file symlink fail",
		},

		// two layer 
		{
			Pid:          1,
			SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin","rpmNest1"),
			Symlink:      "../bin/rpmNest",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "1", "root", "bin","rpm"),
			ExpectResult: "",
		},
		{
			Pid:          2,
			SymlinkFile:  filepath.Join(root, "proc", "2", "root", "bin","rpmNest1"),
			Symlink:      "./../bin/rpmNest",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "2", "root", "bin","rpm"),
			ExpectResult: "",
		},
		{
			Pid:          3,
			SymlinkFile:  filepath.Join(root, "proc", "3", "root", "bin","rpmNest1"),
			Symlink:      "../../bin/rpmNest",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "3", "root", "bin","rpm"),
			ExpectResult: "",
		},
		{
			Pid:          4,
			SymlinkFile:  filepath.Join(root, "proc", "4", "root", "bin","rpmNest1"),
			Symlink:      "../../../bin/rpmNest",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "4", "root", "bin","rpm"),
			ExpectResult: "",
		},
		{
			Pid:          5,
			SymlinkFile:  filepath.Join(root, "proc", "5", "root", "bin","rpmNest1"),
			Symlink:      "./../../../bin/rpmNest",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "proc", "5", "root", "bin","rpm"),
			ExpectResult: "",
		},
		{
			Pid:          6,
			SymlinkFile:  filepath.Join(root, "proc", "6", "root", "bin","rpmNest1"),
			Symlink:      "../../bin/rpmNest",
			Exist:        false,
			ResolvePath:  "",
			ExpectResult: "Get file symlink fail",
		},
		{
			Pid:          7,
			SymlinkFile:  filepath.Join(root, "proc", "7", "root", "bin","rpmNest1"),
			Symlink:      "../../bin/rpmNest",
			Exist:        true,
			ResolvePath:  filepath.Join(root, "bin", "pwd"),
			ExpectResult: "Get file symlink fail",
		},
	}
}

func PrepareSingleLayerSymlink(root string) []MockFile {
    return []MockFile{
        {
            Pid:          1,
            SymlinkFile:  filepath.Join(root, "proc", "1", "root", "bin","rpmverify"),
            Symlink:      "../bin/rpm",
            Exist:        true,
            ResolvePath:  filepath.Join(root, "proc", "1", "root", "bin","rpm"),
            ExpectResult: "",
        },
        {
            Pid:          2,
            SymlinkFile:  filepath.Join(root, "proc", "2", "root", "bin","rpmverify"),
            Symlink:      "./../bin/rpm",
            Exist:        true,
            ResolvePath:  filepath.Join(root, "proc", "2", "root", "bin","rpm"),
            ExpectResult: "",
        },
        {
            Pid:          3,
            SymlinkFile:  filepath.Join(root, "proc", "3", "root", "bin","rpmverify"),
            Symlink:      "../../bin/rpm",
            Exist:        true,
            ResolvePath:  filepath.Join(root, "proc", "3", "root", "bin","rpm"),
            ExpectResult: "",
        },
		{
            Pid:          4,
            SymlinkFile:  filepath.Join(root, "proc", "4", "root", "bin","rpmverify"),
            Symlink:      "../../../bin/rpm",
            Exist:        true,
            ResolvePath:  filepath.Join(root, "proc", "4", "root", "bin","rpm"),
            ExpectResult: "",
        },
		{
            Pid:          5,
            SymlinkFile:  filepath.Join(root, "proc", "5", "root", "bin","rpmverify"),
            Symlink:      "./../../../bin/rpm",
            Exist:        true,
            ResolvePath:  filepath.Join(root, "proc", "5", "root", "bin","rpm"),
            ExpectResult: "",
        },
        {
            Pid:          6,
            SymlinkFile:  filepath.Join(root, "proc", "6", "root", "bin","notExist"),
            Symlink:      "../../bin/rpm",
            Exist:        false,
            ResolvePath:  "",
            ExpectResult: "Get file symlink fail",
        },
        {
            Pid:          7,
            SymlinkFile:  filepath.Join(root, "proc", "7", "root", "bin","rpmquery"),
            Symlink:      filepath.Join(root, "bin", "pwd"),
            Exist:        true,
            ResolvePath:  filepath.Join(root, "bin", "pwd"),
            ExpectResult: "Get file symlink fail",
        },
	}
}

func PrepareMockFilesMetaData(root string) []MockFile {
	mockFilesMetaData := append(PrepareSingleLayerSymlink(root), PrepareNestLayerSymlink(root)...)
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
		} else {
			log.WithFields(log.Fields{"mockFileMetaData.SymlinkFile": mockFileMetaData.SymlinkFile, "mockFileMetaData.Symlink": mockFileMetaData.Symlink, "err": err}).Info("Success to create symlink:")
		}

		if mockFileMetaData.Exist {
			if err := os.MkdirAll(filepath.Dir(mockFileMetaData.ResolvePath), 0755); err != nil {
				return err
			}
			if _, err := os.Create(mockFileMetaData.ResolvePath); err != nil {
				log.WithFields(log.Fields{"mockFileMetaData.ResolvePath": mockFileMetaData.ResolvePath, "err": err}).Info("Failed to create mockFileMetaData.ResolvePath:")
				return err
			} else {
				log.WithFields(log.Fields{"mockFileMetaData.ResolvePath": mockFileMetaData.ResolvePath, "err": err}).Info("Success to create mockFileMetaData.ResolvePath:")
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
	// 2. append another layer on type 1, make it a nest link
	// 3. circular link
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
		if resolvePath, err := GetContainerRealFilePath(mockFileMetaData.Pid, mockFileMetaData.SymlinkFile); err != nil {
			if err.Error() != mockFileMetaData.ExpectResult {
				t.Errorf("Error: Unknown failure %s, expect %s\n", err.Error(), mockFileMetaData.ExpectResult)
			}
		} else if resolvePath != mockFileMetaData.ResolvePath {
			t.Errorf("Error: failed to reolve the path of %s with result %s\n", mockFileMetaData.ResolvePath, resolvePath)
		}
	}
}
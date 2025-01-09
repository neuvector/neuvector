package scan

import "testing"

func TestHarborRepositoryProjectName(t *testing.T) {
	type projectNameTestCase struct {
		fullName         string
		shouldError      bool
		expectedRepoName string
	}
	testCases := []projectNameTestCase{
		{
			fullName:         "testproject/testorg/testrepo",
			expectedRepoName: "testproject",
		},
		{
			fullName:    "invalidprojectname",
			shouldError: true,
		},
		{
			fullName:    "",
			shouldError: true,
		},
	}

	for _, testCase := range testCases {
		repo := HarborApiRepository{
			FullName: testCase.fullName,
		}
		got, err := repo.projectName()
		if err != nil {
			if testCase.shouldError {
				continue
			}
			t.Errorf("received error for valid name \"%s\": %s", testCase.fullName, err.Error())
		}
		if got != testCase.expectedRepoName {
			t.Errorf("unexpected repo name for %s: got %s, expected %s", testCase.fullName, got, testCase.expectedRepoName)
		}
	}
}

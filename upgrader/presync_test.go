package main

import (
	"errors"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/scheme"
	clienttesting "k8s.io/client-go/testing"
	"sigs.k8s.io/yaml"
)

const MAX_REQUEST = 100

var ErrInjected = errors.New("random error")

func ErrorInjector(t *testing.T, clientInit func() *fake.FakeDynamicClient, f func(ctx *cli.Context, client dynamic.Interface, injected *bool) bool) {
	for i := 0; i < MAX_REQUEST; i++ {

		num := 0
		//obj :=
		injected := false
		handler := func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {

			defer func() {
				num++
			}()

			if num == i {
				injected = true
				t.Logf("Injected error #%d verb: %s", num, action.GetVerb())
				return true, nil, ErrInjected
			}
			t.Logf("Normal operation #%d verb: %s", num, action.GetVerb())
			return false, nil, nil
		}
		var client *fake.FakeDynamicClient
		testdata := loadObjectList(t, "03-forced-errors/01-testdata.yaml")
		testdata = append(testdata, loadObject(t, "02-create-upgrader-job/00-cronjob.yaml"))
		if clientInit == nil {
			client = fake.NewSimpleDynamicClient(scheme.Scheme,
				testdata...,
			)
		} else {
			client = clientInit()
		}
		client.Fake.PrependReactor("create", "*", handler)
		client.Fake.PrependReactor("get", "*", handler)
		// Note: we couldn't deal with list for now because it's used in goroutine of watcher, which will automatically retry.
		//client.Fake.PrependReactor("list", "*", handler)
		client.Fake.PrependReactor("patch", "*", handler)
		client.Fake.PrependReactor("update", "*", handler)
		client.Fake.PrependReactor("delete", "*", handler)

		ctx := cli.NewContext(nil, nil, nil)

		require.NoError(t, batchv1.AddToScheme(scheme.Scheme))

		if cont := f(ctx, client, &injected); !cont {
			break
		}
	}
}

func loadJob(t *testing.T, filename string) *batchv1.Job {
	var ret batchv1.Job
	content, err := os.ReadFile(path.Join("./testdata", filename))
	assert.Nil(t, err)
	err = yaml.Unmarshal(content, &ret)
	assert.Nil(t, err)
	return &ret
}

func loadObject(t *testing.T, filename string) runtime.Object {
	var obj map[string]interface{}
	content, err := os.ReadFile(path.Join("./testdata", filename))
	assert.Nil(t, err)

	err = yaml.Unmarshal(content, &obj)

	assert.Nil(t, err)
	return &unstructured.Unstructured{
		Object: obj,
	}
}

func loadObjectList(t *testing.T, filename string) []runtime.Object {
	var obj map[string]interface{}
	var ret []runtime.Object
	content, err := os.ReadFile(path.Join("./testdata", filename))
	assert.Nil(t, err)

	err = yaml.Unmarshal(content, &obj)

	assert.Nil(t, err)
	for _, item := range obj["items"].([]interface{}) {
		data := item.(map[string]interface{})
		ret = append(ret, &unstructured.Unstructured{
			Object: data,
		})
	}
	return ret
}

func TestIsFreshInstall(t *testing.T) {
	require.NoError(t, corev1.AddToScheme(scheme.Scheme))

	for _, tc := range []struct {
		TestData    string
		Expected    bool
		ExpectedErr bool
	}{
		{
			TestData:    "01-fresh-install/01-normal-deployment.yaml",
			Expected:    true,
			ExpectedErr: false,
		},
		{
			TestData:    "01-fresh-install/02-during-rolling-update.yaml",
			Expected:    false,
			ExpectedErr: false,
		},
		{
			TestData:    "01-fresh-install/03-no-owner-reference.yaml",
			Expected:    false,
			ExpectedErr: true,
		},
		{
			TestData:    "01-fresh-install/04-no-owner-reference.yaml",
			Expected:    false,
			ExpectedErr: true,
		},
		{
			TestData:    "01-fresh-install/05-two-owner-reference.yaml",
			Expected:    false,
			ExpectedErr: true,
		},
	} {
		ctx := cli.NewContext(nil, nil, nil)
		client := fake.NewSimpleDynamicClient(scheme.Scheme,
			loadObjectList(t, tc.TestData)...,
		)
		isFreshInstall, err := IsFreshInstall(ctx.Context, client, "neuvector")
		if tc.ExpectedErr {
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
		}

		assert.Equal(t, tc.Expected, isFreshInstall)
	}
}

func TestCreateJob(t *testing.T) {
	require.NoError(t, corev1.AddToScheme(scheme.Scheme))
	require.NoError(t, batchv1.AddToScheme(scheme.Scheme))

	for _, tc := range []struct {
		TestData     string
		ExpectedData string
		ExpectedErr  bool
	}{
		{
			// A job exists
			TestData:     "02-create-upgrader-job/01-existing-upgrade-job.yaml",
			ExpectedData: "02-create-upgrader-job/01-expected-job.yaml",
			ExpectedErr:  false,
		},
		{
			// No existing job.
			TestData:     "",
			ExpectedData: "02-create-upgrader-job/02-expected-job.yaml",
			ExpectedErr:  false,
		},
	} {
		ctx := cli.NewContext(nil, nil, nil)
		var testdata []runtime.Object
		if tc.TestData != "" {
			testdata = loadObjectList(t, tc.TestData)
		}

		testdata = append(testdata, loadObject(t, "02-create-upgrader-job/00-cronjob.yaml"))

		client := fake.NewSimpleDynamicClient(scheme.Scheme,
			testdata...,
		)
		job, err := CreatePostSyncJob(ctx.Context, client, "neuvector", "uid", false)

		expectedJob := loadJob(t, tc.ExpectedData)
		job.CreationTimestamp = v1.Time{}
		expectedJob.CreationTimestamp = v1.Time{}

		if tc.ExpectedErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			assert.Equal(t, expectedJob, job)
		}
	}
}

func TestCreateJobWithForcedK8sError(t *testing.T) {

	ErrorInjector(t, nil, func(ctx *cli.Context, client dynamic.Interface, injected *bool) bool {
		job, err := CreatePostSyncJob(ctx.Context, client, "neuvector", "uid2", false)

		if *injected {
			assert.Nil(t, job)
			assert.ErrorIs(t, err, ErrInjected)
		} else {
			assert.NotNil(t, job)
			require.NoError(t, err)
			return false
		}
		return true
	})
}

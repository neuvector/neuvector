package main

import (
	"context"
	"io/ioutil"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/yaml"
)

func TestDetermineMigrationStep(t *testing.T) {
	for _, tc := range []struct {
		Name              string
		TestData          *corev1.Secret
		ExpectedStep      int
		ExpectedCompleted bool
		ExpectedErr       bool
	}{
		{
			Name: "Step#0.  Not migrated yet.",
			TestData: &corev1.Secret{
				Data: map[string][]byte{
					ACTIVE_SECRET_PREFIX + CACERT_FILENAME: []byte("A"),
					ACTIVE_SECRET_PREFIX + CERT_FILENAME:   []byte("B"),
					ACTIVE_SECRET_PREFIX + KEY_FILENAME:    []byte("C"),

					DEST_SECRET_PREFIX + CACERT_FILENAME: []byte("A"),
					DEST_SECRET_PREFIX + CERT_FILENAME:   []byte("B"),
					DEST_SECRET_PREFIX + KEY_FILENAME:    []byte("C"),

					NEW_SECRET_PREFIX + CACERT_FILENAME: []byte("D"),
					NEW_SECRET_PREFIX + CERT_FILENAME:   []byte("E"),
					NEW_SECRET_PREFIX + KEY_FILENAME:    []byte("F"),
				},
			},
			ExpectedStep:      0,
			ExpectedCompleted: false,
			ExpectedErr:       false,
		},
		{
			Name: "Step#1.  Have combined CA.",
			TestData: &corev1.Secret{
				Data: map[string][]byte{
					ACTIVE_SECRET_PREFIX + CACERT_FILENAME: []byte("A\nD"),
					ACTIVE_SECRET_PREFIX + CERT_FILENAME:   []byte("B"),
					ACTIVE_SECRET_PREFIX + KEY_FILENAME:    []byte("C"),

					DEST_SECRET_PREFIX + CACERT_FILENAME: []byte("A"),
					DEST_SECRET_PREFIX + CERT_FILENAME:   []byte("B"),
					DEST_SECRET_PREFIX + KEY_FILENAME:    []byte("C"),

					NEW_SECRET_PREFIX + CACERT_FILENAME: []byte("D"),
					NEW_SECRET_PREFIX + CERT_FILENAME:   []byte("E"),
					NEW_SECRET_PREFIX + KEY_FILENAME:    []byte("F"),
				},
			},
			ExpectedStep:      1,
			ExpectedCompleted: false,
			ExpectedErr:       false,
		},
		{
			Name: "Step#2: Have combined CA and cert/key.",
			TestData: &corev1.Secret{
				Data: map[string][]byte{
					ACTIVE_SECRET_PREFIX + CACERT_FILENAME: []byte("A\nD"),
					ACTIVE_SECRET_PREFIX + CERT_FILENAME:   []byte("E"),
					ACTIVE_SECRET_PREFIX + KEY_FILENAME:    []byte("F"),

					DEST_SECRET_PREFIX + CACERT_FILENAME: []byte("A"),
					DEST_SECRET_PREFIX + CERT_FILENAME:   []byte("B"),
					DEST_SECRET_PREFIX + KEY_FILENAME:    []byte("C"),

					NEW_SECRET_PREFIX + CACERT_FILENAME: []byte("D"),
					NEW_SECRET_PREFIX + CERT_FILENAME:   []byte("E"),
					NEW_SECRET_PREFIX + KEY_FILENAME:    []byte("F"),
				},
			},
			ExpectedStep:      2,
			ExpectedCompleted: false,
			ExpectedErr:       false,
		},
		{
			Name: "Step#3.  Already migrated except setting dest.",
			TestData: &corev1.Secret{
				Data: map[string][]byte{
					ACTIVE_SECRET_PREFIX + CACERT_FILENAME: []byte("D"),
					ACTIVE_SECRET_PREFIX + CERT_FILENAME:   []byte("E"),
					ACTIVE_SECRET_PREFIX + KEY_FILENAME:    []byte("F"),

					DEST_SECRET_PREFIX + CACERT_FILENAME: []byte("A"),
					DEST_SECRET_PREFIX + CERT_FILENAME:   []byte("B"),
					DEST_SECRET_PREFIX + KEY_FILENAME:    []byte("C"),

					NEW_SECRET_PREFIX + CACERT_FILENAME: []byte("D"),
					NEW_SECRET_PREFIX + CERT_FILENAME:   []byte("E"),
					NEW_SECRET_PREFIX + KEY_FILENAME:    []byte("F"),
				},
			},
			ExpectedStep:      3,
			ExpectedCompleted: false,
			ExpectedErr:       false,
		},
		{
			Name: "Already migrated",
			TestData: &corev1.Secret{
				Data: map[string][]byte{
					ACTIVE_SECRET_PREFIX + CACERT_FILENAME: []byte("A"),
					ACTIVE_SECRET_PREFIX + CERT_FILENAME:   []byte("B"),
					ACTIVE_SECRET_PREFIX + KEY_FILENAME:    []byte("C"),

					DEST_SECRET_PREFIX + CACERT_FILENAME: []byte("A"),
					DEST_SECRET_PREFIX + CERT_FILENAME:   []byte("B"),
					DEST_SECRET_PREFIX + KEY_FILENAME:    []byte("C"),

					NEW_SECRET_PREFIX + CACERT_FILENAME: []byte("A"),
					NEW_SECRET_PREFIX + CERT_FILENAME:   []byte("B"),
					NEW_SECRET_PREFIX + KEY_FILENAME:    []byte("C"),
				},
			},
			ExpectedStep:      0,
			ExpectedCompleted: true,
			ExpectedErr:       false,
		},
		{
			Name: "Only has active certs",
			TestData: &corev1.Secret{
				Data: map[string][]byte{
					ACTIVE_SECRET_PREFIX + CACERT_FILENAME: []byte("A"),
					ACTIVE_SECRET_PREFIX + CERT_FILENAME:   []byte("B"),
					ACTIVE_SECRET_PREFIX + KEY_FILENAME:    []byte("C"),
				},
			},
			ExpectedStep:      0,
			ExpectedCompleted: false,
			ExpectedErr:       true,
		},
		{
			Name: "Only has dest certs",
			TestData: &corev1.Secret{
				Data: map[string][]byte{
					DEST_SECRET_PREFIX + CACERT_FILENAME: []byte("A"),
					DEST_SECRET_PREFIX + CERT_FILENAME:   []byte("B"),
					DEST_SECRET_PREFIX + KEY_FILENAME:    []byte("C"),
				},
			},
			ExpectedStep:      0,
			ExpectedCompleted: false,
			ExpectedErr:       true,
		},
		{
			Name: "Only has new certs",
			TestData: &corev1.Secret{
				Data: map[string][]byte{
					NEW_SECRET_PREFIX + CACERT_FILENAME: []byte("A"),
					NEW_SECRET_PREFIX + CERT_FILENAME:   []byte("B"),
					NEW_SECRET_PREFIX + KEY_FILENAME:    []byte("C"),
				},
			},
			ExpectedStep:      0,
			ExpectedCompleted: false,
			ExpectedErr:       true,
		},
	} {
		t.Log(tc.Name)
		step, completed, err := DetermineMigrationStep(tc.TestData)
		if tc.ExpectedErr {
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
			assert.Equal(t, tc.ExpectedCompleted, completed)
			assert.Equal(t, tc.ExpectedStep, step)
		}
	}
}

func GetUpgradeTestCases(t *testing.T) []struct {
	Name        string
	TestData    runtime.Object
	Expected    bool
	ExpectedErr bool
} {
	return []struct {
		Name        string
		TestData    runtime.Object
		Expected    bool
		ExpectedErr bool
	}{
		{
			Name:        "Happy case",
			TestData:    loadObject(t, "04-upgrade-internal-certs/02-synced-secret.yaml"),
			Expected:    true,
			ExpectedErr: false,
		},
		{
			Name:        "Stage0 with new cert updated",
			TestData:    loadObject(t, "04-upgrade-internal-certs/03-stage0-new-cert-available.yaml"),
			Expected:    true,
			ExpectedErr: false,
		},
		{
			Name:        "Stage1 (combined ca)",
			TestData:    loadObject(t, "04-upgrade-internal-certs/04-stage1-combined-ca.yaml"),
			Expected:    true,
			ExpectedErr: false,
		},

		{
			Name:        "Stage2 (combined ca + new cert/key)",
			TestData:    loadObject(t, "04-upgrade-internal-certs/05-stage2-combinedca-new-cert-key.yaml"),
			Expected:    true,
			ExpectedErr: false,
		},

		{
			Name:        "Stage3 (all are synced except dst secret)",
			TestData:    loadObject(t, "04-upgrade-internal-certs/06-stage3-new-ca-cert-key.yaml"),
			Expected:    true,
			ExpectedErr: false,
		},
	}
}

func TestUpgradeInternalCerts(t *testing.T) {
	tcs := GetUpgradeTestCases(t)
	for _, tc := range tcs {
		t.Log(tc.Name)
		var data []runtime.Object
		data = append(data, loadObjectList(t, "04-upgrade-internal-certs/01-deployments.yaml")...)
		data = append(data, tc.TestData)
		client := fake.NewSimpleDynamicClient(scheme.Scheme,
			data...,
		)
		err := UpgradeInternalCerts(context.Background(), client, "neuvector", "neuvector-internal-certs", time.Hour)
		if tc.ExpectedErr {
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
		}
	}
}

// Run all migration steps with errors injected.
// Note: Reflector wouldn't return error for this type of injected errors.  As a workaround, error is not injected in List API.
func TestUpgradeInternalCerts_ForcedError(t *testing.T) {
	tcs := GetUpgradeTestCases(t)
	for _, tc := range tcs {
		t.Log(tc.Name)

		ErrorInjector(t,
			func() *fake.FakeDynamicClient {
				var data []runtime.Object
				data = append(data, loadObjectList(t, "04-upgrade-internal-certs/01-deployments.yaml")...)
				data = append(data, tc.TestData)
				client := fake.NewSimpleDynamicClient(scheme.Scheme,
					data...,
				)
				return client
			},
			func(ctx *cli.Context, client dynamic.Interface, injected *bool) bool {
				err := UpgradeInternalCerts(context.Background(), client, "neuvector", "neuvector-internal-certs", time.Hour)

				if *injected {
					assert.ErrorIs(t, err, ErrInjected)
					t.Log(err)
				} else {
					assert.Nil(t, err)
					return false
				}
				return true
			})
	}
}

func loadSecret(t *testing.T, filename string) *corev1.Secret {
	var ret corev1.Secret
	content, err := ioutil.ReadFile(path.Join("./testdata", filename))
	assert.Nil(t, err)
	err = yaml.Unmarshal(content, &ret)
	assert.Nil(t, err)
	return &ret
}

func TestShouldUpgradeInternalCert(t *testing.T) {
	// Empty secret
	updateCA, updateCert, err := ShouldUpgradeInternalCert(context.Background(), &corev1.Secret{}, time.Hour*24*365*20)
	assert.Nil(t, err)
	assert.True(t, updateCA)
	assert.True(t, updateCert)

	// Negative threshold, which will only upgrade cert when it's expired for 20 years.
	updateCA, updateCert, err = ShouldUpgradeInternalCert(context.Background(), loadSecret(t, "05-should-upgrade-certs/01-secret.yaml"), -time.Hour*24*365*20)
	assert.Nil(t, err)
	assert.False(t, updateCA)
	assert.False(t, updateCert)

	// Big threshold, which will almost upgrade the cert for these 20 years.
	updateCA, updateCert, err = ShouldUpgradeInternalCert(context.Background(), loadSecret(t, "05-should-upgrade-certs/01-secret.yaml"), time.Hour*24*365*20)
	assert.Nil(t, err)
	assert.True(t, updateCA)
	assert.True(t, updateCert)

	// Create a certificate
	corev1.AddToScheme(scheme.Scheme)
	client := fake.NewSimpleDynamicClient(scheme.Scheme,
		loadObject(t, "05-should-upgrade-certs/02-empty-secret.yaml"),
	)
	secret, err := InitializeInternalSecret(context.Background(),
		client,
		"neuvector",
		"neuvector-internal-certs",
		true,
		false,
		loadSecret(t, "05-should-upgrade-certs/02-empty-secret.yaml"),
		CertConfig{
			CACertValidityDuration: time.Hour * 24,
			CertValidityDuration:   time.Hour * 24,
			RSAKeyLength:           4096,
		})
	assert.Nil(t, err)
	assert.NotNil(t, secret)

	updateCA, updateCert, err = ShouldUpgradeInternalCert(context.Background(), secret, 0)
	assert.Nil(t, err)
	assert.False(t, updateCA)
	assert.False(t, updateCert)
}

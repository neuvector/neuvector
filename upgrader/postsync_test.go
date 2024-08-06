package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/scheme"
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

var (
	inprogressSecret = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				INTERNAL_SECRET_ROTATION_ANNOTATION: "enabled",
			},
		},
		Data: map[string][]byte{
			NEW_SECRET_PREFIX + CACERT_FILENAME: []byte("newca"),
			NEW_SECRET_PREFIX + CERT_FILENAME:   []byte("newcert"),
			NEW_SECRET_PREFIX + KEY_FILENAME:    []byte("newkey"),

			DEST_SECRET_PREFIX + CACERT_FILENAME: []byte("ca"),
			DEST_SECRET_PREFIX + CERT_FILENAME:   []byte("cert"),
			DEST_SECRET_PREFIX + KEY_FILENAME:    []byte("key"),

			ACTIVE_SECRET_PREFIX + CACERT_FILENAME: []byte("ca"),
			ACTIVE_SECRET_PREFIX + CERT_FILENAME:   []byte("cert"),
			ACTIVE_SECRET_PREFIX + KEY_FILENAME:    []byte("key"),
		},
	}
	pre54secret = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{},
		},
		Data: map[string][]byte{},
	}

	post54secret = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				INTERNAL_SECRET_ROTATION_ANNOTATION: "enabled",
			},
		},
		Data: map[string][]byte{
			NEW_SECRET_PREFIX + CACERT_FILENAME: []byte("ca"),
			NEW_SECRET_PREFIX + CERT_FILENAME:   []byte("cert"),
			NEW_SECRET_PREFIX + KEY_FILENAME:    []byte("key"),

			DEST_SECRET_PREFIX + CACERT_FILENAME: []byte("ca"),
			DEST_SECRET_PREFIX + CERT_FILENAME:   []byte("cert"),
			DEST_SECRET_PREFIX + KEY_FILENAME:    []byte("key"),

			ACTIVE_SECRET_PREFIX + CACERT_FILENAME: []byte("ca"),
			ACTIVE_SECRET_PREFIX + CERT_FILENAME:   []byte("cert"),
			ACTIVE_SECRET_PREFIX + KEY_FILENAME:    []byte("key"),
		},
	}

	post54disabledSecret = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				INTERNAL_SECRET_ROTATION_ANNOTATION: "disabled",
			},
		},
		Data: map[string][]byte{},
	}
)

func TestGenerateCertificateFreshInstall(t *testing.T) {
	corev1.AddToScheme(scheme.Scheme)
	client := fake.NewSimpleDynamicClient(scheme.Scheme,
		loadObject(t, "05-should-upgrade-certs/02-empty-secret.yaml"),
	)

	ic := InternalCertUpgrader{
		namespace:              "neuvector",
		secretName:             "neuvector-internal-certs",
		client:                 client,
		renewThreshold:         10 * 365 * 24 * time.Hour,
		CACertValidityDuration: time.Hour * 24,
		CertValidityDuration:   time.Hour * 24,
		RSAKeyLength:           1024,
		enableRotation:         true,
		freshInstall:           true,
	}

	// No secret is created.
	secret, needRotation, err := ic.GenerateInitialSecret(context.Background(), nil)
	assert.Nil(t, err)
	assert.False(t, needRotation)
	assert.NotNil(t, secret)

	// Old empty secret exists
	secret, needRotation, err = ic.GenerateInitialSecret(context.Background(), &corev1.Secret{})
	assert.Nil(t, err)
	assert.False(t, needRotation)
	assert.NotNil(t, secret)

	// Old secrets
	secret, needRotation, err = ic.GenerateInitialSecret(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				INTERNAL_SECRET_ROTATION_ANNOTATION: "enabled",
			},
		},
	})
	assert.Nil(t, err)
	assert.False(t, needRotation)
	assert.NotNil(t, secret)

	secret, needRotation, err = ic.GenerateInitialSecret(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				INTERNAL_SECRET_ROTATION_ANNOTATION: "disabled",
			},
		},
	})
	assert.Nil(t, err)
	assert.False(t, needRotation)
	assert.NotNil(t, secret)

	secret, needRotation, err = ic.GenerateInitialSecret(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{},
		},
	})
	assert.Nil(t, err)
	assert.False(t, needRotation)
	assert.NotNil(t, secret)

	// Old secret with certificate
	secret, needRotation, err = ic.GenerateInitialSecret(context.Background(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				INTERNAL_SECRET_ROTATION_ANNOTATION: "enabled",
			},
		},
		Data: map[string][]byte{
			NEW_SECRET_PREFIX + CACERT_FILENAME: []byte("ca"),
			NEW_SECRET_PREFIX + CERT_FILENAME:   []byte("cert"),
			NEW_SECRET_PREFIX + KEY_FILENAME:    []byte("key"),

			DEST_SECRET_PREFIX + CACERT_FILENAME: []byte("ca"),
			DEST_SECRET_PREFIX + CERT_FILENAME:   []byte("cert"),
			DEST_SECRET_PREFIX + KEY_FILENAME:    []byte("key"),

			ACTIVE_SECRET_PREFIX + CACERT_FILENAME: []byte("ca"),
			ACTIVE_SECRET_PREFIX + CERT_FILENAME:   []byte("cert"),
			ACTIVE_SECRET_PREFIX + KEY_FILENAME:    []byte("key"),
		},
	})
	assert.Nil(t, err)
	assert.False(t, needRotation)
	assert.Nil(t, secret)

	//ic.GenerateInitialSecret(context.Background(), &corev1.Secret{})

}

func TestGenerateCertificateUpgrade(t *testing.T) {
	corev1.AddToScheme(scheme.Scheme)
	client := fake.NewSimpleDynamicClient(scheme.Scheme,
		loadObject(t, "05-should-upgrade-certs/02-empty-secret.yaml"),
	)

	ic := InternalCertUpgrader{
		namespace:              "neuvector",
		secretName:             "neuvector-internal-certs",
		client:                 client,
		renewThreshold:         10 * 365 * 24 * time.Hour,
		CACertValidityDuration: time.Hour * 24,
		CertValidityDuration:   time.Hour * 24,
		RSAKeyLength:           1024,
		enableRotation:         true,
		freshInstall:           false,
	}

	// Upgrade from post-5.4
	secret, needRotation, err := ic.GenerateInitialSecret(context.Background(), &post54secret)
	assert.Nil(t, err)
	assert.True(t, needRotation)
	assert.NotNil(t, secret)
	assert.NotEqual(t, secret.Data[NEW_SECRET_PREFIX+CACERT_FILENAME], secret.Data[DEST_SECRET_PREFIX+CACERT_FILENAME])

	// Upgrade from post-5.4 with rotation disabled
	secret, needRotation, err = ic.GenerateInitialSecret(context.Background(), &post54disabledSecret)
	assert.Nil(t, err)
	assert.True(t, needRotation)
	assert.NotNil(t, secret)
	assert.NotEqual(t, secret.Data[NEW_SECRET_PREFIX+CACERT_FILENAME], secret.Data[DEST_SECRET_PREFIX+CACERT_FILENAME])

	// Upgrade from pre-5.4
	secret, needRotation, err = ic.GenerateInitialSecret(context.Background(), &pre54secret)
	assert.Nil(t, err)
	assert.True(t, needRotation)
	assert.NotNil(t, secret)
	assert.NotEqual(t, secret.Data[NEW_SECRET_PREFIX+CACERT_FILENAME], secret.Data[DEST_SECRET_PREFIX+CACERT_FILENAME])
}

func TestGenerateCertificateUpgradeWithRotationDisabled(t *testing.T) {
	corev1.AddToScheme(scheme.Scheme)
	client := fake.NewSimpleDynamicClient(scheme.Scheme,
		loadObject(t, "05-should-upgrade-certs/02-empty-secret.yaml"),
	)

	ic := InternalCertUpgrader{
		namespace:              "neuvector",
		secretName:             "neuvector-internal-certs",
		client:                 client,
		renewThreshold:         10 * 365 * 24 * time.Hour,
		CACertValidityDuration: time.Hour * 24,
		CertValidityDuration:   time.Hour * 24,
		RSAKeyLength:           1024,
		enableRotation:         false,
		freshInstall:           false,
	}

	// Upgrade from pre-5.4
	secret, needRotation, err := ic.GenerateInitialSecret(context.Background(), &pre54secret)
	assert.Nil(t, err)
	assert.False(t, needRotation)
	assert.NotNil(t, secret)
	assert.Equal(t, "disabled", secret.Annotations[INTERNAL_SECRET_ROTATION_ANNOTATION])

	// Upgrade from post-5.4
	secret, needRotation, err = ic.GenerateInitialSecret(context.Background(), &post54secret)
	assert.Nil(t, err)
	assert.False(t, needRotation)
	assert.Nil(t, secret)

	// Upgrade from post-5.4 with rotation disabled
	secret, needRotation, err = ic.GenerateInitialSecret(context.Background(), &post54disabledSecret)
	assert.Nil(t, err)
	assert.False(t, needRotation)
	assert.Nil(t, secret)
}

func TestUpdateInitialSecretIfRequired(t *testing.T) {
	corev1.AddToScheme(scheme.Scheme)
	client := fake.NewSimpleDynamicClient(scheme.Scheme,
		loadObject(t, "05-should-upgrade-certs/02-empty-secret.yaml"),
	)

	ic := InternalCertUpgrader{
		namespace:              "neuvector",
		secretName:             "neuvector-internal-certs",
		client:                 client,
		renewThreshold:         10 * 365 * 24 * time.Hour,
		CACertValidityDuration: time.Hour * 24,
		CertValidityDuration:   time.Hour * 24,
		RSAKeyLength:           1024,
		enableRotation:         true,
		freshInstall:           false,
	}

	secret, needRotation, err := ic.UpdateInitialSecretIfRequired(context.Background(), &inprogressSecret)

	assert.Nil(t, err)
	assert.True(t, needRotation)
	assert.Nil(t, secret)

	secret, needRotation, err = ic.UpdateInitialSecretIfRequired(context.Background(), &pre54secret)

	assert.Nil(t, err)
	assert.True(t, needRotation)
	assert.NotNil(t, secret)
	assert.NotEqual(t, secret.Data[NEW_SECRET_PREFIX+CACERT_FILENAME], secret.Data[DEST_SECRET_PREFIX+CACERT_FILENAME])

	// Upgrade from post-5.4
	secret, needRotation, err = ic.GenerateInitialSecret(context.Background(), &post54secret)
	assert.Nil(t, err)
	assert.True(t, needRotation)
	assert.NotNil(t, secret)
	assert.NotEqual(t, secret.Data[NEW_SECRET_PREFIX+CACERT_FILENAME], secret.Data[DEST_SECRET_PREFIX+CACERT_FILENAME])

	// Upgrade from post-5.4 with rotation disabled
	secret, needRotation, err = ic.GenerateInitialSecret(context.Background(), &post54disabledSecret)
	assert.Nil(t, err)
	assert.True(t, needRotation)
	assert.NotNil(t, secret)
	assert.NotEqual(t, secret.Data[NEW_SECRET_PREFIX+CACERT_FILENAME], secret.Data[DEST_SECRET_PREFIX+CACERT_FILENAME])

}

func TestUpdateInitialSecretIfRequiredWithRotationDisabled(t *testing.T) {
	corev1.AddToScheme(scheme.Scheme)
	client := fake.NewSimpleDynamicClient(scheme.Scheme,
		loadObject(t, "05-should-upgrade-certs/02-empty-secret.yaml"),
	)

	ic := InternalCertUpgrader{
		namespace:              "neuvector",
		secretName:             "neuvector-internal-certs",
		client:                 client,
		renewThreshold:         10 * 365 * 24 * time.Hour,
		CACertValidityDuration: time.Hour * 24,
		CertValidityDuration:   time.Hour * 24,
		RSAKeyLength:           1024,
		enableRotation:         false,
		freshInstall:           false,
	}

	secret, needRotation, err := ic.UpdateInitialSecretIfRequired(context.Background(), &inprogressSecret)

	assert.Nil(t, err)
	assert.True(t, needRotation)
	assert.Nil(t, secret)

	secret, needRotation, err = ic.UpdateInitialSecretIfRequired(context.Background(), &pre54secret)

	assert.Nil(t, err)
	assert.False(t, needRotation)
	assert.NotNil(t, secret)

	// Upgrade from post-5.4
	secret, needRotation, err = ic.GenerateInitialSecret(context.Background(), &post54secret)
	assert.Nil(t, err)
	assert.False(t, needRotation)
	assert.Nil(t, secret)

	// Upgrade from post-5.4 with rotation disabled
	secret, needRotation, err = ic.GenerateInitialSecret(context.Background(), &post54disabledSecret)
	assert.Nil(t, err)
	assert.False(t, needRotation)
	assert.Nil(t, secret)

}

func TestTriggerRotation(t *testing.T) {
	corev1.AddToScheme(scheme.Scheme)
	client := fake.NewSimpleDynamicClient(scheme.Scheme,
		loadObject(t, "05-should-upgrade-certs/02-empty-secret.yaml"),
	)

	ic := InternalCertUpgrader{
		namespace:              "neuvector",
		secretName:             "neuvector-internal-certs",
		client:                 client,
		renewThreshold:         10 * 365 * 24 * time.Hour,
		CACertValidityDuration: time.Hour * 24,
		CertValidityDuration:   time.Hour * 24,
		RSAKeyLength:           1024,
		enableRotation:         true,
		freshInstall:           false,
	}

	err := ic.TriggerRotation(context.Background())
	assert.Nil(t, err)
}

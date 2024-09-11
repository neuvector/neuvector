package rest

import (
	nvsysadmission "github.com/neuvector/neuvector/controller/nvk8sapi/nvvalidatewebhookcfg/admission"
	"github.com/neuvector/neuvector/share/utils"

	"testing"
)

func TestParseReqImageName(t *testing.T) {
	preTest()

	type testImage struct {
		image             string
		expectedRegistry  string
		expectedImageRepo string
		expectedImageTag  string
	}

	{
		defaultRegistries = utils.NewSet("https://index.docker.io/", "https://registry.hub.docker.com/", "https://registry-1.docker.io/") // all on lower-case

		admContainerInfo := &nvsysadmission.AdmContainerInfo{Image: "docker.io/iperf"}
		parseReqImageName(admContainerInfo)
		if admContainerInfo.ImageRegistry.Intersect(defaultRegistries).Cardinality() != 3 || admContainerInfo.ImageRepo != "library/iperf" || admContainerInfo.ImageTag != "latest" {
			t.Errorf("Unexpected parseReqImageName result(%+v) for: %+v\n", admContainerInfo, admContainerInfo.Image)
		}

		testImages := []*testImage{
			{
				image:             "10.1.127.3:5000/neuvector/toolbox/selvam_coreos_http",
				expectedRegistry:  "https://10.1.127.3:5000/",
				expectedImageRepo: "neuvector/toolbox/selvam_coreos_http",
				expectedImageTag:  "latest",
			},
			{
				image:             "10.1.127.3:5000/neuvector/toolbox/selvam_coreos_http:RELEASE",
				expectedRegistry:  "https://10.1.127.3:5000/",
				expectedImageRepo: "neuvector/toolbox/selvam_coreos_http",
				expectedImageTag:  "RELEASE",
			},
			{
				image:             "10.1.127.3/library/ubuntu:2.51a",
				expectedRegistry:  "https://10.1.127.3/",
				expectedImageRepo: "library/ubuntu",
				expectedImageTag:  "2.51a",
			},
		}
		for _, testImage := range testImages {
			admContainerInfo.Image = testImage.image
			parseReqImageName(admContainerInfo)
			if admContainerInfo.ImageRegistry.Cardinality() != 1 || !admContainerInfo.ImageRegistry.Contains(testImage.expectedRegistry) ||
				admContainerInfo.ImageRepo != testImage.expectedImageRepo || admContainerInfo.ImageTag != testImage.expectedImageTag {
				t.Errorf("Unexpected parseReqImageName result(%+v) for: %+v\n", admContainerInfo, admContainerInfo.Image)
				break
			}
		}
	}

	{
		admContainerInfo := &nvsysadmission.AdmContainerInfo{}
		testImages := []*testImage{
			{
				image:             "docker-registry.default.svc:5000/php-demo-test/php-demo:9331d393add1b2bc0f984e31c4ff75d30938ecadc5cdcca433c3ffaff1c42e43",
				expectedRegistry:  "https://docker-registry.default.svc:5000/",
				expectedImageRepo: "php-demo-test/php-demo",
				expectedImageTag:  "9331d393add1b2bc0f984e31c4ff75d30938ecadc5cdcca433c3ffaff1c42e43",
			},
			{
				image:             "docker-registry.default.svc:5000/php-demo-test/php-demo@sha256:9331d393add1b2bc0f984e31c4ff75d30938ecadc5cdcca433c3ffaff1c42e43",
				expectedRegistry:  "https://docker-registry.default.svc:5000/",
				expectedImageRepo: "php-demo-test/php-demo",
				expectedImageTag:  "sha256:9331d393add1b2bc0f984e31c4ff75d30938ecadc5cdcca433c3ffaff1c42e43",
			},
		}
		for _, testImage := range testImages {
			admContainerInfo.Image = testImage.image
			parseReqImageName(admContainerInfo)
			if admContainerInfo.ImageRegistry.Cardinality() != 1 || !admContainerInfo.ImageRegistry.Contains(testImage.expectedRegistry) ||
				admContainerInfo.ImageRepo != testImage.expectedImageRepo || admContainerInfo.ImageTag != testImage.expectedImageTag {
				t.Errorf("Unexpected parseReqImageName result(%+v) for: %+v\n", admContainerInfo, admContainerInfo.Image)
			}
		}
	}

	postTest()
}

/* we don't skip any UPDATE request anymore in case some critical properties are changed in yaml file that should not be allowed by admission control rules
func TestWalkThruContainersForSkipUpdateLog(t *testing.T) {
	preTest()
	_, testFileName, _, _ := runtime.Caller(0)

	for i := 0; i < 1; i++ {
		dataFileName := filepath.Join(filepath.Dir(testFileName), "data", "request_update_deployment.json")
		data, err := os.ReadFile(dataFileName)
		if err != nil {
			t.Errorf("Read test data error: %s (%s)\n", dataFileName, err)
		}
		ar := admissionv1beta1.AdmissionReview{}
		if err := json.Unmarshal(data, &ar); err == nil {
			var deployment, oldDeployment appsv1.Deployment
			var objectMeta, oldObjectMeta *metav1.ObjectMeta
			var podTemplateSpec, oldPodTemplateSpec *corev1.PodTemplateSpec

			req := ar.Request
			if err := json.Unmarshal(req.Object.Raw, &deployment); err != nil {
				t.Errorf("Unexpected test data: %s (%s)\n", dataFileName, err)
				break
			}
			if err := json.Unmarshal(req.OldObject.Raw, &oldDeployment); err != nil {
				t.Errorf("Unexpected test data: %s (%s)\n", dataFileName, err)
				break
			}
			oldObjectMeta = &oldDeployment.ObjectMeta
			oldPodTemplateSpec = &oldDeployment.Spec.Template
			objectMeta = &deployment.ObjectMeta
			podTemplateSpec = &deployment.Spec.Template

			var stamps api.AdmCtlTimeStamps
			admResObject, _ := parseAdmRequest(req, objectMeta, podTemplateSpec)
			oldContainers, _ := parseAdmReqOldObj(req, oldObjectMeta, oldPodTemplateSpec)
			admResult := walkThruContainers(admission.NvAdmValidateType, admResObject, oldContainers, OPERATION_UPDATE, &stamps)
		} else {
			t.Errorf("Unexpected test data: %s (%s)\n", dataFileName, err)
		}
	}
	postTest()
}
*/

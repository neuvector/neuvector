package e2e_test

import "testing"

func TestNeuVectorDeployment(t *testing.T) {
	testEnv.Test(t, getNeuVectorDeploymentFeature())
}

func TestNeuVectorLogin(t *testing.T) {
	testEnv.Test(t, getNeuVectorLoginFeature())
}

func TestNeuVectorProcessProfile(t *testing.T) {
	testEnv.Test(t, getProcessProfileFeature())
}

func TestNeuVectorScannerCVEDB(t *testing.T) {
	testEnv.Test(t, getScannerCVEDBFeature())
}

func TestNeuVectorWorkloadScan(t *testing.T) {
	testEnv.Test(t, getScannerWorkloadScanFeature())
}

func TestNeuVectorAdmissionRuleLifecycle(t *testing.T) {
	testEnv.Test(t, getAdmissionRuleLifecycleFeature())
}

func TestNeuVectorAdmissionAssessment(t *testing.T) {
	testEnv.Test(t, getAdmissionAssessmentFeature())
}

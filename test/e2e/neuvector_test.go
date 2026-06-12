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

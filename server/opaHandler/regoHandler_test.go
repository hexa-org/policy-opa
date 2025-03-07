package opaHandler

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	infoModel2 "github.com/hexa-org/policy-opa/api/infoModel"
	opaTools "github.com/hexa-org/policy-opa/client/hexaOpaClient"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/config"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/userHandler"
	"github.com/hexa-org/policy-opa/pkg/bundleTestSupport"
	"github.com/stretchr/testify/assert"
)

func TestOpaHandler(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	userFile := filepath.Join(file, "../../../deployments/authZen/users.json")
	dataFile := filepath.Join(file, "../../../deployments/authZen/data.json")
	dataBytes, err := os.ReadFile(dataFile)
	bundleDir := bundleTestSupport.InitTestBundlesDir(dataBytes)
	defer bundleTestSupport.Cleanup(bundleDir)

	pip := userHandler.NewUserPIP(userFile)

	_ = os.Setenv(config.EnvBundleDir, bundleDir)
	// Testing with Beth
	user := pip.GetUser("CiRmZDM2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs")
	assert.NotNil(t, user, "Get User")

	handler, _ := NewRegoHandler(bundleDir)

	claims := make(map[string]interface{})
	claims["email"] = user.Email
	claims["picture"] = user.Picture
	claims["name"] = user.Name
	claims["id"] = user.Id

	subject := opaTools.SubjectInfo{
		Roles:  user.Roles,
		Sub:    user.Id,
		Claims: claims,
		Type:   "jwt",
	}

	actions := []string{"can_read_todos"}
	reqParams := opaTools.ReqParams{
		ActionUris:  actions,
		ResourceIds: []string{"todo"},
	}

	input := infoModel2.AzInfo{
		Req:      &reqParams,
		Subject:  &subject,
		Resource: infoModel2.ResourceInfo{},
	}

	results, err := handler.Evaluate(input)
	assert.NoError(t, err, "Evaluation completes")
	assert.NotNil(t, results, "Results returned")

	opaRes := handler.ProcessResults(results)

	assert.Equal(t, true, opaRes.Allow, "allowed is true")
	assert.Greater(t, len(opaRes.AllowSet), 0, "At least one rule")
	assert.Greater(t, len(opaRes.ActionRights), 0, "At least one right")

	actions = []string{"can_create_todo"}
	reqParams.ActionUris = actions

	results, err = handler.Evaluate(input)
	assert.NoError(t, err, "Evaluation completes")
	assert.NotNil(t, results, "Results returned")

	opaRes = handler.ProcessResults(results)

	assert.Equal(t, false, opaRes.Allow, "allowed is true")
	assert.Equal(t, len(opaRes.AllowSet), 0, "No allows rule")
	assert.Equal(t, len(opaRes.ActionRights), 0, "No right")

	// now with morty
	user = pip.GetUser("CiRmZDE2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs")
	assert.NotNil(t, user, "Get User")

	claims = make(map[string]interface{})
	claims["email"] = user.Email
	claims["picture"] = user.Picture
	claims["name"] = user.Name
	claims["id"] = user.Id

	subject = opaTools.SubjectInfo{
		Roles:  user.Roles,
		Sub:    user.Id,
		Claims: claims,
		Type:   "jwt",
	}

	input = infoModel2.AzInfo{
		Req:      &reqParams,
		Subject:  &subject,
		Resource: infoModel2.ResourceInfo{},
	}

	results, err = handler.Evaluate(input)
	assert.NoError(t, err, "Evaluation completes")
	assert.NotNil(t, results, "Results returned")

	opaRes = handler.ProcessResults(results)

	assert.Equal(t, true, opaRes.Allow, "allowed is true")
	assert.Greater(t, len(opaRes.AllowSet), 0, "At least one rule")
	assert.Greater(t, len(opaRes.ActionRights), 0, "At least one right")

	assert.True(t, handler.HealthCheck(), "Check healthcheck works")
}

func TestOpaHandler_StartupValidateBundle(t *testing.T) {
	policyPath := filepath.Join(bundleTestSupport.GetTestBundlePath("./test/badDataBundle"), "bundle", "data.json")
	databytes, err := os.ReadFile(policyPath)
	assert.NoError(t, err, "Check no error reading policy")
	bundleDir := bundleTestSupport.InitTestBundlesDir(databytes)
	defer bundleTestSupport.Cleanup(bundleDir)
	_ = os.Setenv(config.EnvBundleDir, bundleDir)

	handler, err := NewRegoHandlerWithValidation(bundleDir, "", "")
	assert.Error(t, err, "unexpected end of JSON input")
	assert.Nil(t, handler, "Should be nil due to error")

}

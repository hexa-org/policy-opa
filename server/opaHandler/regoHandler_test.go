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

	bundleDir := bundleTestSupport.InitTestBundlesDir(nil)
	defer bundleTestSupport.Cleanup(bundleDir)

	dataBytes, err := os.ReadFile(dataFile)
	_ = os.WriteFile(filepath.Join(bundleDir, "bundle", "data.json"), dataBytes, 0755)
	pip := userHandler.NewUserPIP(userFile)

	_ = os.Setenv(config.EnvBundleDir, bundleDir)
	// Testing with Beth
	user := pip.GetUser("CiRmZDM2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs")
	assert.NotNil(t, user, "Get User")

	handler := NewRegoHandler(bundleDir)

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

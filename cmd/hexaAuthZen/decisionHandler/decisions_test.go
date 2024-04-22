package decisionHandler

import (
	"net/http"

	"os"
	"testing"

	"github.com/hexa-org/policy-opa/api/infoModel"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/config"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/userHandler"
	"github.com/hexa-org/policy-opa/pkg/bundleTestSupport"
	"github.com/stretchr/testify/assert"
)

func TestHandleEvaluation(t *testing.T) {
	bundleDir := bundleTestSupport.InitTestBundlesDir(t)
	defer bundleTestSupport.Cleanup(bundleDir)

	_ = os.Setenv(config.EnvBundleDir, bundleDir)
	_ = os.Setenv(config.EnvAuthUserPipFile, userHandler.DefaultUserPipFile)

	decisionHandler := NewDecisionHandler()

	body := infoModel.AuthRequest{
		Subject: infoModel.SubjectInfo{Identity: "CiRmZDM2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"},
		Action:  infoModel.ActionInfo{Name: "can_read_todos"},
	}

	resp, err, stat := decisionHandler.ProcessDecision(body)
	assert.Equal(t, http.StatusOK, stat, "Request processed ok")
	assert.Nil(t, err)
	assert.True(t, resp.Decision, "Decision is true")

	resp, err, stat = decisionHandler.ProcessDecision(infoModel.AuthRequest{})
	assert.Nil(t, err)
	assert.False(t, resp.Decision)
	assert.Equal(t, http.StatusOK, stat, "Request processed ok")
}

func TestHandleQueryEvaluation(t *testing.T) {
	bundleDir := bundleTestSupport.InitTestBundlesDir(t)
	defer bundleTestSupport.Cleanup(bundleDir)

	_ = os.Setenv(config.EnvBundleDir, bundleDir)
	_ = os.Setenv(config.EnvAuthUserPipFile, userHandler.DefaultUserPipFile)
	decisionHandler := NewDecisionHandler()

	body := infoModel.QueryRequest{
		Subject: infoModel.SubjectInfo{Identity: "CiRmZDM2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"},
		Queries: []infoModel.QueryItem{{
			Action: "can_update_todo",
		}},
	}

	resp, err, stat := decisionHandler.ProcessQueryDecision(body, nil)
	assert.Nil(t, resp)
	assert.Nil(t, err)
	assert.Equal(t, stat, http.StatusNotImplemented)

}

func TestHealthCheck(t *testing.T) {
	bundleDir := bundleTestSupport.InitTestBundlesDir(t)
	defer bundleTestSupport.Cleanup(bundleDir)

	_ = os.Setenv(config.EnvBundleDir, bundleDir)
	_ = os.Setenv(config.EnvAuthUserPipFile, userHandler.DefaultUserPipFile)
	decisionHandler := NewDecisionHandler()

	assert.True(t, decisionHandler.HealthCheck())
}

func TestReload(t *testing.T) {
	bundleDir := bundleTestSupport.InitTestBundlesDir(t)
	defer bundleTestSupport.Cleanup(bundleDir)

	_ = os.Setenv(config.EnvBundleDir, bundleDir)
	_ = os.Setenv(config.EnvAuthUserPipFile, userHandler.DefaultUserPipFile)
	decisionHandler := NewDecisionHandler()

	assert.Nil(t, decisionHandler.ProcessUploadOpa())
	// Note: the handlers_test will do the  negative test.
}

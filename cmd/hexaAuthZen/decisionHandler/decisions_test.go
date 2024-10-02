package decisionHandler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"runtime"

	"os"
	"testing"

	"github.com/hexa-org/policy-opa/api/infoModel"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/config"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/userHandler"
	"github.com/hexa-org/policy-opa/pkg/bundleTestSupport"
	"github.com/stretchr/testify/assert"
)

func TestHandleEvaluation(t *testing.T) {
	// This test should cause the decision handler to create a brand new AuthZen bundle
	bundleDir := bundleTestSupport.InitTestEmptyBundleDir(t)
	defer bundleTestSupport.Cleanup(bundleDir)

	_ = os.Setenv(config.EnvBundleDir, bundleDir)
	_ = os.Setenv(config.EnvAuthUserPipFile, userHandler.DefaultUserPipFile)

	decisionHandler := NewDecisionHandler()

	body := infoModel.EvaluationItem{
		Subject: &infoModel.SubjectInfo{Id: "CiRmZDM2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"},
		Action:  &infoModel.ActionInfo{Name: "can_read_todos"},
	}

	resp, err, stat := decisionHandler.ProcessDecision(body)
	assert.Equal(t, http.StatusOK, stat, "Request processed ok")
	assert.Nil(t, err)
	assert.True(t, resp.Decision, "Decision is true")

	resp, err, stat = decisionHandler.ProcessDecision(infoModel.EvaluationItem{})
	assert.Nil(t, err)
	assert.False(t, resp.Decision)
	assert.Equal(t, http.StatusOK, stat, "Request processed ok")
}

func TestHandleQueryEvaluation(t *testing.T) {
	bundleDir := bundleTestSupport.InitTestBundlesDir(nil)
	defer bundleTestSupport.Cleanup(bundleDir)

	_ = os.Setenv(config.EnvBundleDir, bundleDir)
	_ = os.Setenv(config.EnvAuthUserPipFile, userHandler.DefaultUserPipFile)
	decisionHandler := NewDecisionHandler()

	items := []infoModel.EvaluationItem{
		{
			Action: &infoModel.ActionInfo{Name: "can_read_todos"},
		},
		{
			Action: &infoModel.ActionInfo{Name: "can_update_todo"},
		},
	}
	body := infoModel.QueryRequest{
		EvaluationItem: &infoModel.EvaluationItem{
			Subject: &infoModel.SubjectInfo{Id: "CiRmZDM2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"},
			Resource: &infoModel.ResourceInfo{
				Id: "todo",
			},
		},
		Evaluations: &infoModel.EvaluationBlock{
			Items: &items,
		},
	}

	resp, err, stat := decisionHandler.ProcessQueryDecision(body, nil)
	assert.NotNil(t, resp)
	assert.NotNil(t, resp.Evaluations)
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, stat, "Request processed ok")
	assert.Len(t, *resp.Evaluations, 2)

	assert.True(t, (*resp.Evaluations)[0].Decision, "Should be allowed")
	assert.False(t, (*resp.Evaluations)[1].Decision, "Should not be allowed")
}

func TestHealthCheck(t *testing.T) {
	bundleDir := bundleTestSupport.InitTestBundlesDir(nil)
	defer bundleTestSupport.Cleanup(bundleDir)

	_ = os.Setenv(config.EnvBundleDir, bundleDir)
	_ = os.Setenv(config.EnvAuthUserPipFile, userHandler.DefaultUserPipFile)
	decisionHandler := NewDecisionHandler()

	assert.True(t, decisionHandler.HealthCheck())
}

func TestReload(t *testing.T) {
	bundleDir := bundleTestSupport.InitTestBundlesDir(nil)
	defer bundleTestSupport.Cleanup(bundleDir)

	_ = os.Setenv(config.EnvBundleDir, bundleDir)
	_ = os.Setenv(config.EnvAuthUserPipFile, userHandler.DefaultUserPipFile)
	decisionHandler := NewDecisionHandler()

	assert.Nil(t, decisionHandler.ProcessUploadOpa())
	// Note: the handlers_test will do the  negative test.
}

type testItem struct {
	Request  infoModel.EvaluationItem `json:"request"`
	Expected bool                     `json:"expected"`
}

type testQuery struct {
	Request  infoModel.QueryRequest       `json:"request"`
	Expected []infoModel.DecisionResponse `json:"expected"`
}
type testSet struct {
	Evaluation  []testItem  `json:"evaluation"`
	Evaluations []testQuery `json:"evaluations"`
}

func runAuthZenSet(t *testing.T, name string, file string, decisionHandler *DecisionHandler) {
	t.Helper()
	testBytes, err := os.ReadFile(file)
	assert.NoError(t, err)

	var tests testSet
	err = json.Unmarshal(testBytes, &tests)
	assert.NoError(t, err)
	fmt.Println("Executing Single Decision Requests...")
	for k, test := range tests.Evaluation {
		t.Run(fmt.Sprintf("%s-single-%d", name, k), func(t *testing.T) {
			resp, err, status := decisionHandler.ProcessDecision(test.Request)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, status, "Request processed ok")
			assert.NotNil(t, resp)
			assert.Equal(t, test.Expected, resp.Decision, "Decision should match")
		})
	}

	fmt.Println("Executing Multi Decision Requests...")
	for k, test := range tests.Evaluations {
		t.Run(fmt.Sprintf("%s-query-%d", name, k), func(t *testing.T) {
			resp, err, status := decisionHandler.ProcessQueryDecision(test.Request, nil)
			assert.NoError(t, err)
			assert.Equal(t, http.StatusOK, status, "Request processed ok")
			assert.NotNil(t, resp)
			results := *resp.Evaluations
			for k, result := range test.Expected {
				assert.Equal(t, result.Decision, results[k].Decision, "Decision should match")
			}

		})
	}
}

func TestAuthZen(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	authzenPolicy := filepath.Join(file, "../../resources/data.json")

	tests := []struct {
		Name string
		File string
	}{
		{Name: "1.0-Preview", File: filepath.Join(file, "../../resources/decisions-1.0-preview.json")},
		{Name: "1.0-implementers-draft", File: filepath.Join(file, "../../resources/decisions-1.0-implementers-draft.json")},
		{Name: "1.1-preview", File: filepath.Join(file, "../../resources/decisions-1.1-preview.json")},
	}

	policyBytes, err := os.ReadFile(authzenPolicy)
	assert.NoError(t, err)
	bundleDir := bundleTestSupport.InitTestBundlesDir(policyBytes)

	defer bundleTestSupport.Cleanup(bundleDir)

	_ = os.Setenv(config.EnvBundleDir, bundleDir)
	_ = os.Setenv(config.EnvAuthUserPipFile, userHandler.DefaultUserPipFile)
	decisionHandler := NewDecisionHandler()

	for _, test := range tests {
		fmt.Printf(fmt.Sprintf("Running tests for: %s", test.Name))
		runAuthZenSet(t, test.Name, test.File, decisionHandler)
	}

}

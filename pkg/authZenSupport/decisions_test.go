package authZenSupport

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
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
	_ = os.Setenv(config.EnvAuthUserPipFile, userHandler.DefaultUserPipFile())

	decisionHandler, _ := NewDecisionHandler()

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
	_ = os.Setenv(config.EnvAuthUserPipFile, userHandler.DefaultUserPipFile())
	decisionHandler, _ := NewDecisionHandler()

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
	assert.Len(t, resp.Evaluations, 2)

	assert.True(t, (resp.Evaluations)[0].Decision, "Should be allowed")
	assert.False(t, (resp.Evaluations)[1].Decision, "Should not be allowed")
}

func TestHealthCheck(t *testing.T) {
	bundleDir := bundleTestSupport.InitTestBundlesDir(nil)
	defer bundleTestSupport.Cleanup(bundleDir)

	_ = os.Setenv(config.EnvBundleDir, bundleDir)
	_ = os.Setenv(config.EnvAuthUserPipFile, userHandler.DefaultUserPipFile())
	decisionHandler, _ := NewDecisionHandler()

	assert.True(t, decisionHandler.HealthCheck())
}

func TestReload(t *testing.T) {
	bundleDir := bundleTestSupport.InitTestBundlesDir(nil)
	defer bundleTestSupport.Cleanup(bundleDir)

	_ = os.Setenv(config.EnvBundleDir, bundleDir)
	_ = os.Setenv(config.EnvAuthUserPipFile, userHandler.DefaultUserPipFile())
	decisionHandler, _ := NewDecisionHandler()

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
			results := resp.Evaluations
			for k, result := range test.Expected {
				assert.Equal(t, result.Decision, results[k].Decision, "Decision should match")
			}

		})
	}
}

func TestAuthZen(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	authzenPolicy := filepath.Join(file, "../resources/data.json")

	tests := []struct {
		Name string
		File string
	}{
		{Name: "1.0-Preview", File: filepath.Join(file, "../resources/decisions-1.0-preview.json")},
		{Name: "1.0-implementers-draft", File: filepath.Join(file, "../resources/decisions-1.0-implementers-draft.json")},
		{Name: "1.1-preview", File: filepath.Join(file, "../resources/decisions-1.1-preview.json")},
	}

	policyBytes, err := os.ReadFile(authzenPolicy)
	assert.NoError(t, err)
	bundleDir := bundleTestSupport.InitTestBundlesDir(policyBytes)

	defer bundleTestSupport.Cleanup(bundleDir)

	_ = os.Setenv(config.EnvBundleDir, bundleDir)
	_ = os.Setenv(config.EnvAuthUserPipFile, userHandler.DefaultUserPipFile())
	decisionHandler, _ := NewDecisionHandler()

	for _, test := range tests {
		fmt.Println(fmt.Sprintf("Running tests for: %s", test.Name))
		runAuthZenSet(t, test.Name, test.File, decisionHandler)
	}
}

func TestEmptyActionAndObject(t *testing.T) {

	policies := `{
  "policies": [
    {
      "meta": {
        "policyId": "GetAnyAction",
        "version": "0.7",
        "description": "Get the list of todos. Always returns true for every user??"
      },
      "subjects": [
        "anyAuthenticated"
      ],
      "actions": [
      ],
      "object": "todo"
    },
    {
      "meta": {
        "policyId": "NoObject",
        "version": "0.7",
        "description": "Test that missing object matches"
      },
      "subjects": [
        "anyAuthenticated"
      ],
      "actions": [
        "can_read_user"
      ]
    },
    {
      "meta": {
        "policyId": "EmptyObject",
        "version": "0.7",
        "description": "Test that empty object can match"
      },
      "subjects": [
        "anyAuthenticated"
      ],
      "actions": [
        "can_read_user"
      ],
      "object": "todo"
    },
    {
      "meta": {
        "policyId": "ShouldNotMatch",
        "version": "0.7",
        "description": "This rule should not match for this test"
      },
      "subjects": [
        "anyAuthenticated"
      ],
      "actions": [
        "get_todo"
      ],
      "object": "todo"
    }
  ]
}`

	bundleDir := bundleTestSupport.InitTestBundlesDir([]byte(policies))

	testItemStr := `{
      "request": {
        "subject": {
          "type": "user",
          "id": "CiRmZDA2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"
        },
        "action": {
          "name": "can_read_user"
        },
        "resource": {
          "type": "user",
          "id": "beth@the-smiths.com"
        }
      },
      "expected": true
    }`

	var testItem testItem
	err := json.Unmarshal([]byte(testItemStr), &testItem)
	assert.NoError(t, err)

	defer bundleTestSupport.Cleanup(bundleDir)

	_ = os.Setenv(config.EnvBundleDir, bundleDir)
	_ = os.Setenv(config.EnvAuthUserPipFile, userHandler.DefaultUserPipFile())

	_ = os.Setenv(config.EnvAuthZenDecDetail, ResultDetail)
	decisionHandler, _ := NewDecisionHandler()

	input := decisionHandler.createInputObjectSimple(testItem.Request, &[]string{"todo"})

	results, err := decisionHandler.regoHandler.Evaluate(input)
	assert.NoError(t, err)
	result := decisionHandler.regoHandler.ProcessResults(results)
	assert.Len(t, result.AllowSet, 3)
}

func TestAuthZen_BadPolicy(t *testing.T) {
	policyPath := filepath.Join(bundleTestSupport.GetTestBundlePath("./test/badDataBundle"), "bundle", "data.json")
	databytes, err := os.ReadFile(policyPath)
	assert.NoError(t, err, "Check no error reading policy")
	bundleDir := bundleTestSupport.InitTestBundlesDir(databytes)
	defer bundleTestSupport.Cleanup(bundleDir)
	_ = os.Setenv(config.EnvBundleDir, bundleDir)
	_ = os.Setenv(config.EnvAuthUserPipFile, userHandler.DefaultUserPipFile())

	handler, err := NewDecisionHandler()
	assert.Error(t, err, "unexpected end of JSON input")
	assert.Nil(t, handler, "Should be nil due to error")

}

func testBundleData() []byte {
	_, file, _, _ := runtime.Caller(0)
	dataFile := filepath.Join(file, "../../../deployments/authZen/data.json")
	dataBytes, _ := os.ReadFile(dataFile)
	return dataBytes
}

func testUserData() []byte {
	_, file, _, _ := runtime.Caller(0)
	userFile := filepath.Join(file, "../../../deployments/authZen/users.json")
	userBytes, _ := os.ReadFile(userFile)
	return userBytes
}

func TestHandleEvaluationOnDemand(t *testing.T) {
	decisionHandler, err := NewDecisionHandlerOnDemand(testBundleData(), testUserData())
	assert.NoError(t, err)

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

func TestHandleQueryEvaluationOnDemand(t *testing.T) {
	decisionHandler, err := NewDecisionHandlerOnDemand(testBundleData(), testUserData())
	assert.NoError(t, err)

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
	assert.Len(t, resp.Evaluations, 2)

	assert.True(t, (resp.Evaluations)[0].Decision, "Should be allowed")
	assert.False(t, (resp.Evaluations)[1].Decision, "Should not be allowed")
}

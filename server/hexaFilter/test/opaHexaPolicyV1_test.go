package hexaFilter_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/hexa-org/policy-opa/api/infoModel"
	"github.com/hexa-org/policy-opa/pkg/bundleTestSupport"
	"github.com/hexa-org/policy-opa/pkg/decisionsupportproviders"
	"github.com/hexa-org/policy-opa/server/opaHandler"
	"github.com/hexa-org/policy-opa/tests/utils"
	"github.com/stretchr/testify/assert"

	"testing"
	"time"
)

/*
This test suite tests Hexa IDQL Support with OPA which is implemented in Rego (bundle/hexaPolicyV2.rego)
*/

const dataV1Path = "bundle/bundle_test/data-V1.json"

func TestIdqlBasic(t *testing.T) {

	server := utils.SetUpMockServer("verifyme", "", false, t)

	client := &http.Client{Timeout: time.Second * 10}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/testpath?a=b&c=d", server.Addr), nil)
	if err != nil {
		assert.Error(t, err)
	}
	req.SetBasicAuth("testUser", "good&bad")
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	body, _ := io.ReadAll(resp.Body)

	inputStr := string(body)
	fmt.Println("input = " + inputStr)

	results := RunRego(t, body, dataV1Path, nil)
	if results == nil {
		log.Fatalln("Received nil OPA results!")
	}

	allowSet, _ := ProcessResults(t, results)

	assert.Contains(t, allowSet, "TestBasicCanary")          // This policy has no codnition
	assert.Contains(t, allowSet, "TestBasicCanaryCondition") // THis policy matches on "ip sw 127"
	assert.Contains(t, allowSet, "TestIPMaskCanary")
	assert.Contains(t, allowSet, "TestIPMaskCanaryNotDelete")
	assert.NotContains(t, allowSet, "TestIPMaskCanaryPOST")
	utils.StopServer(t, server)

}

func TestIdqlJwt(t *testing.T) {
	key := "sercrethatmaycontainch@r$32chars!"
	server := utils.SetUpMockServer(key, "", false, t)

	client := &http.Client{Timeout: time.Minute * 2}

	toknstr, err := utils.GenerateBearerToken(key, "TestUser", time.Now().Add(time.Minute*1))
	if err != nil {
		log.Fatalln(err)
	}
	authz := "Bearer " + toknstr
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/testpath?a=b&c=d", server.Addr), nil)
	if err != nil {
		assert.Error(t, err)
	}
	req.Header.Set("Authorization", authz)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	body, _ := io.ReadAll(resp.Body)
	inputStr := string(body)
	fmt.Println("input = " + inputStr)

	results := RunRego(t, body, dataV1Path, nil)
	if results == nil {
		log.Fatalln("Received nil OPA results!")
	}

	fmt.Println("Expecting: TestIPMaskCanary, TestIPMaskCanaryNotDelete, TestJwtCanary, TestJwtMember")

	allowSet, _ := ProcessResults(t, results)
	assert.True(t, len(allowSet) == 4, "confirm 4 matches")
	assert.Contains(t, allowSet, "TestJwtCanary")
	assert.Contains(t, allowSet, "TestJwtMember")
	assert.NotContains(t, allowSet, "TestJwtRole")
	utils.StopServer(t, server)
}

func TestIdqlIp(t *testing.T) {
	key := "sercrethatmaycontainch@r$32chars!"
	server := utils.SetUpMockServer(key, "", false, t)

	client := &http.Client{Timeout: time.Minute * 2}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/testpath?a=b&c=d", server.Addr), nil)
	if err != nil {
		assert.Error(t, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	body, _ := io.ReadAll(resp.Body)
	inputStr := string(body)
	fmt.Println("input = " + inputStr)

	results := RunRego(t, body, dataV1Path, nil)
	if results == nil {
		log.Fatalln("Received nil OPA results!")
	}

	/*
		This test should return 2 policy matches (TestIPMaskCanary and TestIPMaskCanaryNotDelete) where each match has 3 actions
		decisions enumerated for a total of 6 (create,get, and not edit)
	*/

	allowSet, actionRights := ProcessResults(t, results)

	assert.Equal(t, 6, len(actionRights))
	assert.Equal(t, 2, len(allowSet))

	utils.StopServer(t, server)
}

/*
	This test should invoke the idql rule that permits based on IP address alone.  In the first test the URL should be

allowed as it matches one of the actions, the second should be disallowed because PUT is excluded. A third test tries
a delete which should also be refused as it is not explicitly enabled.
*/
func TestIdqlIpActions(t *testing.T) {
	key := "sercrethatmaycontainch@r$32chars!"
	server := utils.SetUpMockServer(key, "", false, t)

	client := &http.Client{Timeout: time.Minute * 2}

	// Test #1, Basic Auth GET request allowed by IP Address match against rule id "TestIPMaskCanary"
	fmt.Println("\nGET Test ")
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/testpath?a=b&c=d", server.Addr), nil)
	if err != nil {
		assert.Error(t, err)
	}
	req.SetBasicAuth("testUser", "good&bad")

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	body, _ := io.ReadAll(resp.Body)
	inputStr := string(body)
	fmt.Println("input = " + inputStr)

	results := RunRego(t, body, dataV1Path, nil)
	if results == nil {
		log.Fatalln("Received nil OPA results!")
	}

	allowSet, actionRights := ProcessResults(t, results)

	assert.Equal(t, 12, len(actionRights))
	assert.Equal(t, 4, len(allowSet))

	// -----------------------
	// Test #2, A PUT requests that should be passed based on TeestBasicCanary match
	fmt.Println("\nPUT Test Should be allowed based on TestBasicCanary rather than TestIPCanary")
	dummy := bytes.NewBufferString("Hello world")
	req, err = http.NewRequest(http.MethodPut, fmt.Sprintf("http://%s/testpath?a=b&c=d", server.Addr), dummy)
	if err != nil {
		assert.Error(t, err)
	}
	req.SetBasicAuth("testUser", "good&bad")

	resp, err = client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	body, _ = io.ReadAll(resp.Body)
	inputStr = string(body)
	fmt.Println("input = " + inputStr)

	results = RunRego(t, body, dataV1Path, nil)
	if results == nil {
		log.Fatalln("Received nil OPA results!")
	}

	allowSet, actionRights = ProcessResults(t, results)

	assert.Equal(t, 6, len(actionRights))
	assert.Equal(t, 2, len(allowSet))

	// -----------------------
	// Test #3, A PUT requests that should be passed based on TeestBasicCanary match
	fmt.Println("\nPUT Test without Basic Auth - Should fail as PUT not allowed for TestIPMaskCanary")
	dummy = bytes.NewBufferString("Hello world")
	req, err = http.NewRequest(http.MethodPut, fmt.Sprintf("http://%s/testpath?a=b&c=d", server.Addr), dummy)
	if err != nil {
		assert.Error(t, err)
	}

	resp, err = client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	body, _ = io.ReadAll(resp.Body)
	inputStr = string(body)
	fmt.Println("input = " + inputStr)

	results = RunRego(t, body, dataV1Path, nil)
	if results == nil {
		log.Fatalln("Received nil OPA results!")
	}

	allowSet, actionRights = ProcessResults(t, results)

	assert.Equal(t, 0, len(actionRights))
	assert.Equal(t, 0, len(allowSet))

	utils.StopServer(t, server)
}

func TestIdqlMember(t *testing.T) {
	key := "sercrethatmaycontainch@r$32chars!"
	server := utils.SetUpMockServer(key, "", false, t)
	fmt.Println("\nGET Test with token and role")
	client := &http.Client{Timeout: time.Minute * 2}

	toknstr, err := utils.GenerateBearerToken(key, "JwtAlice", time.Now().Add(time.Minute*1))
	if err != nil {
		log.Fatalln(err)
	}
	authz := "Bearer " + toknstr
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/testpath?a=b&c=d", server.Addr), nil)
	if err != nil {
		assert.Error(t, err)
	}
	req.Header.Set("Authorization", authz)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	body, _ := io.ReadAll(resp.Body)
	inputStr := string(body)
	fmt.Println("input = " + inputStr)

	results := RunRego(t, body, dataV1Path, nil)
	if results == nil {
		log.Fatalln("Received nil OPA results!")
	}

	allowSet, actionRights := ProcessResults(t, results)

	assert.Equal(t, 12, len(actionRights))
	assert.Equal(t, 4, len(allowSet))
	assert.Contains(t, allowSet, "TestJwtMember")

	utils.StopServer(t, server)
}

// TestIdqlDenyRule tests that a condition rule with an action deny takes precedence
func TestIdqlDenyRule(t *testing.T) {
	key := "sercrethatmaycontainch@r$32chars!"
	server := utils.SetUpMockServer(key, "", false, t)
	fmt.Println("\nGET Test with token and role")
	client := &http.Client{Timeout: time.Minute * 2}

	toknstr, err := utils.GenerateBearerToken(key, "mrdenial", time.Now().Add(time.Minute*1))
	if err != nil {
		log.Fatalln(err)
	}
	authz := "Bearer " + toknstr
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/testpath?a=b&c=d", server.Addr), nil)
	if err != nil {
		assert.Error(t, err)
	}
	req.Header.Set("Authorization", authz)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	body, _ := io.ReadAll(resp.Body)
	inputStr := string(body)
	fmt.Println("input = " + inputStr)

	results := RunRego(t, body, dataV1Path, nil)
	if results == nil {
		log.Fatalln("Received nil OPA results!")
	}

	allowSet, actionRights := ProcessResults(t, results)

	assert.Equal(t, 12, len(actionRights))
	assert.Equal(t, 4, len(allowSet))
	assert.Equal(t, 1, len(results.DenySet))
	assert.Contains(t, results.DenySet, "TestDenyUserWithRule")
	assert.NotContains(t, allowSet, "TestDenyUserWithRule")
	assert.NotContains(t, results.DenySet, "TestDenyRule")
	assert.False(t, results.Allow, "Should be false as in deny!")
	utils.StopServer(t, server)
}

// TestIdqlDenyRule tests that a condition with action set to deny is processed (no rule value)
func TestIdqlDenyAction(t *testing.T) {
	key := "sercrethatmaycontainch@r$32chars!"
	server := utils.SetUpMockServer(key, "", false, t)
	fmt.Println("\nGET Test with token and role")
	client := &http.Client{Timeout: time.Minute * 2}

	toknstr, err := utils.GenerateBearerToken(key, "testdenyrule", time.Now().Add(time.Minute*1))
	if err != nil {
		log.Fatalln(err)
	}
	authz := "Bearer " + toknstr
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/testpath?a=b&c=d", server.Addr), nil)
	if err != nil {
		assert.Error(t, err)
	}
	req.Header.Set("Authorization", authz)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	body, _ := io.ReadAll(resp.Body)
	inputStr := string(body)
	fmt.Println("input = " + inputStr)

	results := RunRego(t, body, dataV1Path, nil)
	if results == nil {
		log.Fatalln("Received nil OPA results!")
	}

	allowSet, actionRights := ProcessResults(t, results)

	assert.Equal(t, 12, len(actionRights))
	assert.Equal(t, 4, len(allowSet))
	assert.Equal(t, 1, len(results.DenySet))
	assert.Contains(t, results.DenySet, "TestDenyRule")
	assert.NotContains(t, allowSet, "TestDenyRule")
	assert.NotContains(t, allowSet, "TestDenyUserWithRule")
	assert.False(t, results.Allow, "Should be false as in deny!")
	utils.StopServer(t, server)
}

func TestIdqlRole(t *testing.T) {
	key := "sercrethatmaycontainch@r$32chars!"
	server := utils.SetUpMockServer(key, "", false, t)
	fmt.Println("\nGET Test with token and role")
	client := &http.Client{Timeout: time.Minute * 2}

	toknstr, err := utils.GenerateBearerToken(key, "BasicBob", time.Now().Add(time.Minute*5))
	if err != nil {
		log.Fatalln(err)
	}
	authz := "Bearer " + toknstr
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/testpath?a=b&c=d", server.Addr), nil)
	if err != nil {
		assert.Error(t, err)
	}
	req.Header.Set("Authorization", authz)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	body, _ := io.ReadAll(resp.Body)
	inputStr := string(body)
	fmt.Println("input = " + inputStr)

	results := RunRego(t, body, dataV1Path, nil)
	if results == nil {
		log.Fatalln("Received nil OPA results!")
	}

	allowSet, actionRights := ProcessResults(t, results)

	assert.Equal(t, 14, len(actionRights))
	assert.Equal(t, 5, len(allowSet))
	assert.Contains(t, allowSet, "TestJwtRole")
	assert.Contains(t, allowSet, "TestJwtMember")

	utils.StopServer(t, server)
}

const EntityPolicyTest = `{
  "policies": [
    {
      "meta": {
        "policyId": "TestEntityEquals",
        "version": "0.7",
        "date": "2021-08-01 21:32:44 UTC",
        "description": "Access enabling a specific customer"
      },
      "subjects": [
        "Customer:alicebob"
      ],
      "object": "CanaryProfileService"
    },
    {
      "meta": {
        "policyId": "TestEntityIs",
        "version": "0.7",
        "date": "2021-08-01 21:32:44 UTC",
        "description": "access enabling anyone who is a customer"
      },
      "subjects": [
        "Customer:"
      ],
      "object": "CanaryProfileService"
    }
]}`

func TestSubjectEntity(t *testing.T) {
	key := "sercrethatmaycontainch@r$32chars!"
	server := utils.SetUpMockServer(key, "", false, t)

	client := &http.Client{Timeout: time.Minute * 2}

	fmt.Println("Running Positive Entity Tests")
	toknstr, err := utils.GenerateBearerToken(key, "Customer:alicebob", time.Now().Add(time.Minute*1))
	if err != nil {
		log.Fatalln(err)
	}
	authz := "Bearer " + toknstr
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/testpath?a=b&c=d", server.Addr), nil)
	if err != nil {
		assert.Error(t, err)
	}
	req.Header.Set("Authorization", authz)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	body, _ := io.ReadAll(resp.Body)
	inputStr := string(body)
	fmt.Println("input = " + inputStr)

	results := RunRego(t, body, dataV1Path, []byte(EntityPolicyTest))
	if results == nil {
		log.Fatalln("Received nil OPA results!")
	}

	assert.Equal(t, "0.8.5", results.HexaRegoVersion, "Must be 0.8.5")

	allowSet, _ := ProcessResults(t, results)
	assert.True(t, len(allowSet) == 2, "confirm 2 matches")
	assert.Contains(t, allowSet, "TestEntityEquals")
	assert.Contains(t, allowSet, "TestEntityIs")

	fmt.Println("Running Negative Entity Tests")

	toknstr, err = utils.GenerateBearerToken(key, "Employee:alicebob", time.Now().Add(time.Minute*1))
	if err != nil {
		log.Fatalln(err)
	}
	authz = "Bearer " + toknstr
	req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/testpath?a=b&c=d", server.Addr), nil)
	if err != nil {
		assert.Error(t, err)
	}
	req.Header.Set("Authorization", authz)
	resp, err = client.Do(req)
	if err != nil {
		log.Fatalln(err)
	}
	body, _ = io.ReadAll(resp.Body)
	inputStr = string(body)
	fmt.Println("input = " + inputStr)

	results = RunRego(t, body, dataV1Path, []byte(EntityPolicyTest))
	if results == nil {
		log.Fatalln("Received nil OPA results!")
	}

	allowSet, _ = ProcessResults(t, results)
	assert.Equal(t, 0, len(allowSet), "confirm 0 matches")
	assert.Equal(t, 2, results.PoliciesEvaluated, "Should be 2 policies evaluated")
	utils.StopServer(t, server)
}

func RunRego(t *testing.T, inputByte []byte, dataPath string, policyBytes []byte) *decisionsupportproviders.HexaOpaResult {
	t.Helper()

	if policyBytes == nil {
		dataBytes, err := os.ReadFile(dataPath)
		if err != nil {
			assert.Fail(t, "error reading data file: "+err.Error())
		}
		policyBytes = dataBytes
	}

	bundleDir := bundleTestSupport.InitTestBundlesDir(policyBytes)
	defer func(path string) {
		err := os.RemoveAll(path)
		if err != nil {
			t.Error("Failed to clean up after test: " + err.Error())
		}
	}(bundleDir)

	regoHandler, err := opaHandler.NewRegoHandlerWithValidation(bundleDir, "", "")
	if err != nil {
		assert.Fail(t, "Failed to create rego handler")
	}

	var input infoModel.AzInfo
	err = json.Unmarshal(inputByte, &input)
	if err != nil {
		assert.Fail(t, "Error parsing input data: "+err.Error())
	}

	results, err := regoHandler.Evaluate(input)
	if err != nil {
		assert.Fail(t, "Error evaluating policy: "+err.Error())
	}

	return regoHandler.ProcessResults(results)
	/*
	   regoHandle := rego.New(
	       rego.EnablePrintStatements(true),
	       rego.Query("data.hexaPolicy"),
	       rego.Package("hexaPolicy"),
	       rego.LoadBundle(bundleDir),
	       rego.Input(&input),
	       rego.Function2(
	           &rego.Function{
	               Name:             hexaFilter.PluginName,
	               Decl:             types.NewFunction(types.Args(types.A, types.S), types.S),
	               Memoize:          true,
	               Nondeterministic: true,
	           },
	           func(_ rego.BuiltinContext, a, b *ast.Term) (*ast.Term, error) {

	               var expression, input string

	               if err := ast.As(a.Value, &expression); err != nil {
	                   return nil, err
	               }
	               // expression = a.Value.String()
	               input = b.Value.String()

	               res, err := conditionEvaluator.Evaluate(expression, input)

	               return ast.BooleanTerm(res), err

	           }),
	       rego.Trace(true),
	   )

	   resultSet, err := regoHandle.Eval(ctx)
	   if err != nil {
	       assert.Fail(t, "Error evaluating rego: "+err.Error())
	   }

	   // rego.PrintTraceWithLocation(os.Stdout, regoHandle)

	   ctx.Done()

	*/
}

func ProcessResults(t *testing.T, results *decisionsupportproviders.HexaOpaResult) ([]string, []string) {
	t.Helper()

	if results.PolicyErrors != nil && len(results.PolicyErrors) != 0 {
		errBytes, _ := json.MarshalIndent(results.PolicyErrors, "", " ")
		t.Error(fmt.Sprintf("Received policy parse errors:\n%s", string(errBytes)))
		t.Fail()
	}

	resBytes, _ := json.MarshalIndent(results, "", " ")
	t.Log(fmt.Sprintf("Received results:\n%s", string(resBytes)))

	return results.AllowSet, results.ActionRights
}

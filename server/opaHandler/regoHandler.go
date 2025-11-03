/*
Package opaHandler is used by the hexaAuthZen server package to process OPA rego based decisions in an all-in-one
demonstration deployment. When an AuthZen decision request is received, the request is parsed and transformed into an OPA
decision request which this handler processes.
*/
package opaHandler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hexa-org/policy-mapper/pkg/hexapolicy/pimValidate"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicysupport"
	"github.com/hexa-org/policy-opa/api/infoModel"
	"github.com/hexa-org/policy-opa/client/hexaOpaClient"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/config"
	"github.com/hexa-org/policy-opa/pkg/decisionsupportproviders"
	"github.com/hexa-org/policy-opa/server/conditionEvaluator"
	"github.com/hexa-org/policy-opa/server/hexaFilter"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown"
	"github.com/open-policy-agent/opa/types"
	log "golang.org/x/exp/slog"
)

type RegoHandler struct {
	query     *rego.PreparedEvalQuery
	rego      *rego.Rego
	bundleDir string
	validator *pimValidate.Validator
	Tracer    *topdown.BufferTracer
}

func (h *RegoHandler) HealthCheck() bool {
	// Runs a check to see if OPA is still working
	input := hexaOpaClient.OpaInfo{}
	eval, err := h.query.Eval(context.Background(), rego.EvalInput(input))
	if err != nil {
		fmt.Println("Health check failed: " + err.Error())
		return false
	}
	return eval != nil
}

func (h *RegoHandler) ValidateBundle() error {
	dataFile := filepath.Join(h.bundleDir, "bundle", "data.json")

	pols, err := hexapolicysupport.ParsePolicyFile(dataFile)
	if err != nil {
		return err
	}

	policyBytes, _ := os.ReadFile(dataFile)

	if policyBytes == nil || pols == nil || len(pols) == 0 {
		return errors.New("no parseable policy")
	}

	var valErrs []pimValidate.ValidationError
	if h.validator != nil {
		valErrs = h.validator.ValidatePolicyByAst(policyBytes)

		if valErrs != nil && len(valErrs) > 0 {
			sb := strings.Builder{}
			sb.WriteString("Error:\n")
			for _, valErr := range valErrs {
				sb.WriteString(valErr.String())
				sb.WriteString("\n")
			}
			log.Error(sb.String())
			return errors.New(sb.String())
		}
	}
	return err
}

func (h *RegoHandler) ReloadRego() error {
	debug := os.Getenv(decisionsupportproviders.EnvOpaDebug)
	if debug != "" && strings.EqualFold(debug, "debug") {
		h.Tracer = topdown.NewBufferTracer()
	}
	ctx := context.Background()

	regoHandle := rego.New(
		rego.EnablePrintStatements(true),
		rego.Query("data.hexaPolicy"),
		rego.Package("hexaPolicy"),
		rego.LoadBundle(h.bundleDir),
		rego.Trace(true),
		// rego.Module("bundle/hexaPolicyV2.rego", regoString),
		// rego.Store(store),
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
	)

	query, err := regoHandle.PrepareForEval(ctx)
	if err != nil {
		msg := fmt.Sprintf("OPA error parsing rego: %s", err.Error())
		fmt.Println(msg)
		return err
		// this either leaves the old rego intact or the server has failed to start.
	}
	h.rego = regoHandle
	h.query = &query
	return nil
}

// NewRegoHandler instantiate a new OPA processor instance for making policy decisions.
//
// Parameters:
// bundleDir is the path to a directory containing hexa policy to be evaluated along with hexaPolicy.rego
func NewRegoHandler(bundleDir string) (*RegoHandler, error) {
	return NewRegoHandlerWithValidation(bundleDir, "", "")
}

// NewRegoHandlerWithValidation instantiates a new OPA processor instance for making policy decisions.
func NewRegoHandlerWithValidation(bundleDir string, // bundleDir is the path to a directory containing hexa policy to be evaluated along with hexaPolicy.rego
	policyModelFile string, // policyModelFile is the path to a file containing a Hexa Policy Information Model which can be used to validate policies on startup or reload. When policyModelFile is blank (""), policy will not be validated
	defaultNamespace string, // defaultNamespace is the default namespace for policy entities.
	// E.g. PhotoApp:User:name vs. User:name with default namespace "PhotoApp"
) (*RegoHandler, error) {

	if bundleDir == "" {
		// If a relative path is used, then join with the current executable path...
		fmt.Println("Environment variable AUTHZEN_BUNDLE_DIR not defined, defaulting..")
		bundleDir = config.DefBundlePath
	}

	var validator *pimValidate.Validator
	if policyModelFile != "" {
		// Initialize the validator
		pimBytes, err := os.ReadFile(policyModelFile)
		if err != nil {
			return nil, errors.New("Error reading policy model file: " + err.Error())
		}
		validator, err = pimValidate.NewValidator(pimBytes, defaultNamespace)
		if err != nil {
			return nil, errors.New("Error parsing poliyc information model: " + err.Error())
		}

	}

	handler := &RegoHandler{
		bundleDir: bundleDir,
		validator: validator,
	}

	// this checks that the policy is parsable Hexa IDQL
	err := handler.ValidateBundle()
	if err != nil {
		return nil, err
	}

	err = handler.ReloadRego()

	return handler, err

}

func (h *RegoHandler) CheckBundleDir() error {
	return nil
}

func (h *RegoHandler) Evaluate(input infoModel.AzInfo) (rego.ResultSet, error) {
	// inputBytes, _ := json.MarshalIndent(input, "", " ")
	// fmt.Println(string(inputBytes))

	if h.query == nil {
		return nil, errors.New("OPA query handler not ready")
	}
	return h.query.Eval(context.Background(), rego.EvalInput(input))
}

func (h *RegoHandler) ProcessResults(results rego.ResultSet) *decisionsupportproviders.HexaOpaResult {
	if results == nil {
		return nil
	}
	resBytes, err := json.Marshal(results[0].Expressions[0].Value)

	opaResult := decisionsupportproviders.HexaOpaResult{}
	err = json.Unmarshal(resBytes, &opaResult)
	if err != nil {
		config.ServerLog.Print("error converting result: " + err.Error())
	}
	/*
		for k, v := range result.Value.(map[string]interface{}) {
			if k == "action_rights" {
				actionRights := strings.FieldsFunc(fmt.Sprintf("%v", v), func(r rune) bool {
					return strings.ContainsRune("[ ]", r)
				})
				opaResult.ActionRights = actionRights
			}
			if k == "allow_set" {
				allowSet := strings.FieldsFunc(fmt.Sprintf("%v", v), func(r rune) bool {
					return strings.ContainsRune("[ ]", r)
				})
				opaResult.AllowSet = allowSet
			}
			if k == "allow" {
				opaResult.Allow = v.(bool)
			}
			if k == "hexa_rego_version" {

				opaResult.HexaRegoVersion = v.(string)
			}
			if k == "policies_evaluated" {
				value := 0
				err := json.Unmarshal(v, &value)
				if err != nil {
					config.ServerLog.Print("error convertin result: " + err.Error())
				}
			}
		}

	*/

	return &opaResult
}

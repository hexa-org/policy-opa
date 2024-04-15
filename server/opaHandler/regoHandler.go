package opaHandler

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hexa-org/policy-opa/api/infoModel"
	"github.com/hexa-org/policy-opa/client/hexaOpaClient"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/config"
	"github.com/hexa-org/policy-opa/server/conditionEvaluator"
	"github.com/hexa-org/policy-opa/server/hexaFilter"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
)

type RegoHandler struct {
	query     *rego.PreparedEvalQuery
	rego      *rego.Rego
	bundleDir string
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

func (h *RegoHandler) ReloadRego() error {
	ctx := context.Background()
	regoHandle := rego.New(
		rego.EnablePrintStatements(true),
		rego.Query("data.hexaPolicy"),
		rego.Package("hexaPolicy"),
		rego.LoadBundle(filepath.Join(h.bundleDir, "bundle")),
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
		rego.Trace(true),
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

func NewRegoHandler() *RegoHandler {
	bundleDir := os.Getenv(config.EnvBundleDir)
	if bundleDir == "" {
		// If a relative path is used, then join with the current executable path...
		fmt.Println("Environment variable AUTHZEN_BUNDLE_DIR not defined, defaulting..")
		bundleDir = config.DefBundlePath
	}

	// TODO: Check if bundleDir is empty. If so, create a default bundle

	handler := &RegoHandler{
		bundleDir: bundleDir,
	}

	err := handler.ReloadRego()
	if err != nil {
		panic(err.Error())
	}
	return handler
}

func (h *RegoHandler) Evaluate(input infoModel.AzInfo) (rego.ResultSet, error) {
	// inputBytes, _ := json.MarshalIndent(input, "", " ")
	// fmt.Println(string(inputBytes))
	if h.query == nil {
		return nil, errors.New("OPA query handler not ready")
	}
	return h.query.Eval(context.Background(), rego.EvalInput(input))
}

func (h *RegoHandler) ProcessResults(results rego.ResultSet) (string, []string, []string) {
	if results == nil {
		return "", []string{}, []string{}
	}
	var rights string
	var allowString string
	allowed := "false"
	result := results[0].Expressions[0]
	for k, v := range result.Value.(map[string]interface{}) {
		if k == "actionRights" {
			rights = fmt.Sprintf("%v", v)
		}
		if k == "allowSet" {
			allowString = fmt.Sprintf("%v", v)
		}
		if k == "allow" {
			allowed = fmt.Sprintf("%v", v)
		}
	}
	actionRights := strings.FieldsFunc(rights, func(r rune) bool {
		return strings.ContainsRune("[ ]", r)
	})
	allowSet := strings.FieldsFunc(allowString, func(r rune) bool {
		return strings.ContainsRune("[ ]", r)
	})
	fmt.Println("allowed:     \t" + allowed)
	fmt.Println("actionRights:\t" + rights)
	fmt.Println("allowSet:    \t" + allowString)

	return allowed, allowSet, actionRights
}

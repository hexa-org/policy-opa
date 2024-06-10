package main

// THis code built based on: https://www.openpolicyagent.org/docs/latest/extensions/

import (
	"os"

	"github.com/hexa-org/policy-opa/pkg/keysupport"
	"github.com/hexa-org/policy-opa/server/conditionEvaluator"
	"github.com/hexa-org/policy-opa/server/hexaFilter"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/cmd"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
	"golang.org/x/exp/slog"
)

func main() {
	// Configure JSON logger which is the normal OPA log format.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	logger.Info("Starting Hexa extended OPA Server")
	logger.Info("registering plugin " + hexaFilter.PluginName)
	rego.RegisterBuiltin2(
		&rego.Function{
			Name:             hexaFilter.PluginName,
			Decl:             types.NewFunction(types.Args(types.A, types.S), types.S),
			Memoize:          false, // function may get called several times in same query for different expressions
			Nondeterministic: true,
		},
		func(_ rego.BuiltinContext, a, b *ast.Term) (*ast.Term, error) {

			var expression, input string

			if err := ast.As(a.Value, &expression); err != nil {
				return nil, err
			}
			input = b.Value.String()

			res, err := conditionEvaluator.Evaluate(expression, input)

			return ast.BooleanTerm(res), err

		})

	// Read the hexa environment variables and auto-gen keys if necessary
	keyConfig := keysupport.GetKeyConfig()
	keyConfig.InitializeKeys()
	keysupport.CheckCaInstalled(nil) // If HEXA_CA_CERT is defined, the root will be installed.
	// Start OPA Server
	if err := cmd.RootCommand.Execute(); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}

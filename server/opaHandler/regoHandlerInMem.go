package opaHandler

import (
	"context"
	"encoding/json"
	"errors"
	"log"

	"github.com/hexa-org/policy-mapper/providers/openpolicyagent"
	"github.com/hexa-org/policy-opa/api/infoModel"
	"github.com/hexa-org/policy-opa/client/hexaOpaClient"
	"github.com/hexa-org/policy-opa/pkg/decisionsupportproviders"
	"github.com/hexa-org/policy-opa/server/conditionEvaluator"
	"github.com/hexa-org/policy-opa/server/hexaFilter"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/types"
	"github.com/open-policy-agent/opa/util"
)

// RegoHandlerInMem handles evaluation based on an in-memory bundle.
type RegoHandlerInMem struct {
	query    *rego.PreparedEvalQuery
	rego     *rego.Rego
	data     []byte
	hexaRego []byte
}

func (h *RegoHandlerInMem) HealthCheck() bool {
	// Runs a check to see if OPA is still working
	input := hexaOpaClient.OpaInfo{}
	eval, err := h.query.Eval(context.Background(), rego.EvalInput(input))
	if err != nil {
		log.Printf("Health check failed: %s", err.Error())
		return false
	}
	return eval != nil
}

func (h *RegoHandlerInMem) ReloadRego() error {
	ctx := context.Background()

	var bundleJson map[string]interface{}
	if err := util.UnmarshalJSON(h.data, &bundleJson); err != nil {
		return err
	}

	store := inmem.NewFromObject(bundleJson)
	regoHandle := rego.New(
		rego.EnablePrintStatements(true),
		rego.Query("data.hexaPolicy"),
		rego.Package("hexaPolicy"),
		rego.Trace(true),
		rego.Module("bundle/hexaPolicy.rego", string(h.hexaRego)),
		rego.Store(store),
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
				input = b.Value.String()

				res, err := conditionEvaluator.Evaluate(expression, input)

				return ast.BooleanTerm(res), err

			}),
	)

	query, err := regoHandle.PrepareForEval(ctx)
	if err != nil {
		log.Printf("OPA error parsing rego: %s", err.Error())
		return err
	}
	h.rego = regoHandle
	h.query = &query
	return nil
}

func (h *RegoHandlerInMem) Evaluate(input infoModel.AzInfo) (rego.ResultSet, error) {
	if h.query == nil {
		return nil, errors.New("OPA query handler not ready")
	}
	return h.query.Eval(context.Background(), rego.EvalInput(input))
}

func (h *RegoHandlerInMem) ProcessResults(results rego.ResultSet) *decisionsupportproviders.HexaOpaResult {
	if results == nil {
		return nil
	}
	resBytes, err := json.Marshal(results[0].Expressions[0].Value)
	if err != nil {
		log.Printf("error converting result: %s", err.Error())
		return nil
	}

	opaResult := decisionsupportproviders.HexaOpaResult{}
	if err := json.Unmarshal(resBytes, &opaResult); err != nil {
		log.Printf("error converting result: %s", err.Error())
		return nil
	}

	return &opaResult
}

// NewRegoHandlerInMem instantiates a new OPA processor instance for making policy decisions.
func NewRegoHandlerInMem(
	data []byte,
) (*RegoHandlerInMem, error) {

	// TODO: validate policy
	dataBytes, hexaRego := openpolicyagent.BundleBytes(data)
	handler := &RegoHandlerInMem{data: dataBytes, hexaRego: hexaRego}
	if err := handler.ReloadRego(); err != nil {
		return nil, err
	}

	return handler, nil
}

package conditionEvaluator

import (
	"errors"
	"fmt"
	"log"
	"reflect"

	"github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions"
	filter "github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions/parser"
	"github.com/hexa-org/policy-mapper/pkg/hexapolicy/types"

	// "github.com/hexa-org/policy-mapper/policySupport/conditions"
	// "github.com/hexa-org/policy-mapper/policySupport/filter"
	"github.com/tidwall/gjson"
)

/*
Evaluate takes in an IDQL expression, parses it, and then compares against the input provided.
'input' is a JSON structure containing data provided by the client using OpaTools.PrepareInput
*/
func Evaluate(expression string, input string) (bool, error) {
	ast, err := conditions.ParseExpressionAst(expression)
	if err != nil {
		log.Print("condition evaluation error: " + err.Error())
		return false, err
	}
	return evalWalk(ast, input)
}

func convertGjsonToValue(res gjson.Result) types.Value {
	var val types.Value
	switch res.Type {
	case gjson.Number:
		val, _ = types.NewNumeric(res.String())
		return val
	case gjson.String:
		// This could be a date or string
		val = types.NewString(res.String())
		return val

	case gjson.False, gjson.True:
		return types.NewBoolean(res.String())
	case gjson.Null:
		return nil
	case gjson.JSON:
		if res.IsArray() {
			var values []types.ComparableValue
			for _, gsonValue := range res.Array() {
				aVal := convertGjsonToValue(gsonValue)
				switch v := aVal.(type) {
				case types.ComparableValue:
					values = append(values, v)
				default:
					// value is ignored
					fmt.Println(fmt.Sprintf("Input value contains a nested array or object within an array: %s", res.String()))
				}

			}
			return types.NewArray(values)
		}
		fmt.Println(fmt.Sprintf("Unexpected JSON comparison object (type %s): %s", res.Type.String(), res.String()))
		return nil
	}
	fmt.Println(fmt.Sprintf("Unexpected comparison object (type %s): %s", res.Type.String(), res.String()))
	return nil
}

func getAttributeValue(input string, value types.Value) types.Value {
	if value == nil {
		return nil
	} // This typically happens with a presence (PR) expression

	// if it is a quoted value, just return it
	switch value := value.(type) {
	case types.Entity:
		if value.IsPath() {
			// lookup the path from the input
			res := gjson.Get(input, value.String())
			if res.Exists() {
				return convertGjsonToValue(res)
			}
			// if it doesn't exist, put in an empty placeholder
			return types.NewEmptyValue(value)
		}
		return value // return the entity
	default:
		return value
	}
}

func evalWalk(e filter.Expression, input string) (bool, error) {
	switch v := e.(type) {
	case filter.LogicalExpression:
		lhVal, err := evalWalk(v.Left, input)
		if err != nil {
			return false, err
		}
		if v.Operator == filter.AND {
			if !lhVal {
				return false, nil
			}
			return evalWalk(v.Right, input)
		}
		if lhVal {
			return true, nil
		}
		return evalWalk(v.Right, input)

	case filter.PrecedenceExpression:
		subExpression := v.Expression
		return evalWalk(subExpression, input)

	case filter.NotExpression:
		subExpression := v.Expression
		res, err := evalWalk(subExpression, input)
		return !res, err

	case filter.ValuePathExpression:
		return evalWalk(v.VPathFilter, input)
	case filter.AttributeExpression:
		return evalAttributeExpression(e.(filter.AttributeExpression), input)
	default:
		// etc...
	}

	errMsg := fmt.Sprintf("Unimplemented filter expression: %v", e)
	return false, errors.New(errMsg)
}

var ErrorIncompatible = errors.New("incompatible comparison types")

func compareArray(left types.Value, right types.Value, op filter.CompareOperator) (bool, error) {
	switch lVal := left.(type) {
	case types.Array:
		switch op {
		case filter.EQ:
			switch rVal := right.(type) {
			case types.Array:
				return reflect.DeepEqual(lVal, rVal), nil
			default:
				return false, nil
			}
		case filter.NE:
			switch rVal := right.(type) {
			case types.Array:
				return !reflect.DeepEqual(lVal, rVal), nil
			default:
				return true, nil
			}
		case filter.LT, filter.LE, filter.GT, filter.GE, filter.PR:
			return false, errors.New("invalid comparison for an array")
		case filter.IN:
			return compareArray(right, left, filter.CO) // reverse the operands and do a contains test
		case filter.CO:
			switch rVal := right.(type) {
			case types.Array:
				// All values in the right need to be present in the left
				for _, rValue := range rVal.Value().([]types.ComparableValue) {
					found := false
					for _, lValue := range lVal.Value().([]types.ComparableValue) {
						match, notOk := types.CompareValues(lValue, rValue, types.EQ)
						if notOk {
							return false, ErrorIncompatible
						}
						if match {
							found = true
							break
						}
					}
					if !found {
						return false, nil
					}
				}
				return true, nil

			case types.ComparableValue:
				found := false
				for _, aValue := range lVal.Value().([]types.ComparableValue) {
					switch compItem := aValue.(type) {
					case types.ComparableValue:
						match, notOk := types.CompareValues(compItem, rVal, types.EQ)
						if notOk {
							return false, ErrorIncompatible
						}
						if match {
							found = true
						}
					default:
						// if it is an entity we don't care
						// arrays of arrays not supported yet
					}
					if found {
						break
					}
				}
				return found, nil
			default:
				return false, ErrorIncompatible
			}
		}
	case types.ComparableValue:
		// left is comparable so right is array
		if op != filter.IN {
			return false, ErrorIncompatible
		}
		return compareArray(right, left, filter.CO)
	}
	return false, ErrorIncompatible
}

/*
evalCompareValues performs the binary logic compare operation specified by the operator. note that the compare value
from the parser is always in string form from the original expression.
*/
func evalCompareValues(left types.Value, right types.Value, op filter.CompareOperator) (bool, error) {
	switch val := left.(type) {
	case types.Array:
		return compareArray(left, right, op)
	case types.ComparableValue:
		if string(op) == types.PR {
			return left.Value() != nil, nil
		}
		switch rVal := right.(type) {
		case types.Array:
			return compareArray(left, right, op)
		case types.ComparableValue:
			res, notOk := types.CompareValues(val, rVal, string(op))
			if notOk {
				return res, errors.New("incompatible comparison values")
			}
			return res, nil
		}

	}

	leftType := "undefined"
	rightType := "undefined"
	leftType = fmt.Sprintf("%s(%s)", types.TypeName(left.ValueType()), left.String())

	if right != nil {
		rightType = fmt.Sprintf("%s(%s)", types.TypeName(right.ValueType()), right.String())
	}
	return false, errors.New(fmt.Sprintf("invalid comparison: %s %s %s", leftType, op, rightType))
}

func evalAttributeExpression(e filter.AttributeExpression, input string) (bool, error) {

	leftValue := getAttributeValue(input, e.AttributePath)
	if leftValue == nil {
		return false, errors.New(fmt.Sprintf("invalid attribute %s", e.AttributePath))
	}

	compValue := getAttributeValue(input, e.CompareValue)

	return evalCompareValues(leftValue, compValue, e.Operator)
}

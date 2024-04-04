package conditionEvaluator

import (
	"errors"
	"fmt"
	"strconv"

	"strings"

	"github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions"
	filter "github.com/hexa-org/policy-mapper/pkg/hexapolicy/conditions/parser"

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
		return false, err
	}
	return evalWalk(*ast, input)
}

func getAttributeValue(input string, path string) gjson.Result {
	// if it is a quoted value, just return it
	if strings.HasPrefix(path, "\"") && strings.HasSuffix(path, "\"") {
		return gjson.Result{
			Type: gjson.String,
			Str:  path[1 : len(path)-1],
		}
	}

	res := gjson.Get(input, path)

	if res.Type == gjson.Null {
		return gjson.Result{
			Type: gjson.String,
			Str:  path,
		}
	}
	return res
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

func evalCompareNil(compValue interface{}, op filter.CompareOperator) bool {
	switch op {
	case filter.EQ:
		return compValue == nil || compValue == ""
	case filter.GT, filter.LT, filter.GE, filter.LE, filter.SW, filter.EW, filter.CO, filter.IN:
		return false
	case filter.NE:
		return compValue != nil && compValue != ""
	case filter.PR:
		return false
	}
	fmt.Println("Unexpected compare operator for nil")
	return false
}

// SafeFloat returns a float value and indicates true if comparable as a float.
func safeFloat(result gjson.Result) (float64, bool) {
	switch result.Type {
	default:
		return 0, false
	case gjson.True:
		return 1, true
	case gjson.String:
		n, err := strconv.ParseFloat(result.Str, 64)
		if err != nil {
			return n, false
		}
		return n, true
	case gjson.Number:
		return result.Num, true
	}
}

/*
evalCompareValues performs the binary logic compare operation specified by the operator. note that the compare value
from the parser is always in string form from the original expression.
*/
func evalCompareValues(attrValue gjson.Result, compValue gjson.Result, op filter.CompareOperator) (bool, error) {
	if !attrValue.Exists() {
		return evalCompareNil(compValue, op), nil
	}

	if compValue.IsArray() {
		match := false
		for _, val := range compValue.Array() {
			res, err := evalCompareValues(attrValue, val, op)
			if err != nil {
				fmt.Println(err.Error())
			}
			if res {
				match = true
				break
			}
		}
		return match, nil
	}

	if attrValue.Type == gjson.Number || compValue.Type == gjson.Number {
		leftFloat, isNum := safeFloat(attrValue)
		if isNum {
			if !compValue.Exists() {
				return evalCompareNil(attrValue, op), nil
			}
			rightFloat, isNum := safeFloat(compValue)
			if isNum {
				return evalCompareFloat(op, leftFloat, rightFloat), nil
			}
		}
		return false, errors.New("invalid number comparison")
	}

	if attrValue.Type == gjson.String {
		return evalCompareStrings(op, attrValue.Str, compValue.String()), nil
	}

	return false, errors.New("Undefined attribute input type: " + fmt.Sprint(attrValue))
}

func evalAttributeExpression(e filter.AttributeExpression, input string) (bool, error) {
	path := e.AttributePath
	leftValue := getAttributeValue(input, path)
	// TODO: May have to support inverted values (input attribute on right)

	compValue := getAttributeValue(input, e.CompareValue)

	if leftValue.IsArray() {
		match := false
		for _, val := range leftValue.Array() {
			res, err := evalCompareValues(val, compValue, e.Operator)
			if err != nil {
				fmt.Println(err.Error())
			}
			if res {
				match = true
				break
			}
		}
		return match, nil
	}

	return evalCompareValues(leftValue, compValue, e.Operator)
}

func evalCompareStrings(op filter.CompareOperator, attrVal string, compVal string) bool {
	switch op {
	case filter.EQ, filter.IN:
		return strings.EqualFold(attrVal, compVal)
	case filter.LT:
		return attrVal < compVal
	case filter.GT:
		return attrVal > compVal
	case filter.LE:
		return attrVal <= compVal
	case filter.GE:
		return attrVal >= compVal
	case filter.CO:
		return strings.Contains(attrVal, compVal)
	case filter.PR:
		return attrVal != ""
	case filter.SW:
		return strings.HasPrefix(attrVal, compVal)
	case filter.EW:
		return strings.HasSuffix(attrVal, compVal)
	case filter.NE:
		return attrVal != compVal
	}
	fmt.Printf("Unexpected comparison operator: %v", op)
	return false
}

/*
evalCompareInt replaced by float compare
func evalCompareInt(op filter.CompareOperator, attrVal int, compVal int) bool {
	switch op {
	case filter.EQ:
		return attrVal == compVal
	case filter.NE:
		return attrVal != compVal
	case filter.LT:
		return attrVal < compVal
	case filter.GT:
		return attrVal > compVal
	case filter.LE:
		return attrVal <= compVal
	case filter.GE:
		return attrVal >= compVal
	default:
		return false
	}
}
*/

func evalCompareFloat(op filter.CompareOperator, attrVal float64, compVal float64) bool {
	switch op {
	case filter.EQ:
		return attrVal == compVal
	case filter.NE:
		return attrVal != compVal
	case filter.LT:
		return attrVal < compVal
	case filter.GT:
		return attrVal > compVal
	case filter.LE:
		return attrVal <= compVal
	case filter.GE:
		return attrVal >= compVal
	default:
		return false
	}
}

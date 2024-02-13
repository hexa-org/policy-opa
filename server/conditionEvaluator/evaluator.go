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
Evaluate takes in an IDQL expression, parses it, and than compares against the input provided.
'input' is a JSON structure containing data provided by the client using OpaTools.PrepareInput
*/
func Evaluate(expression string, input string) (bool, error) {
	ast, err := conditions.ParseExpressionAst(expression)
	if err != nil {
		return false, err
	}
	return evalWalk(*ast, input)
}

func getAttributeValue(input string, path string) interface{} {
	res := gjson.Get(input, path)
	return res.Value()
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

/*
evalCompareVals performs the binary logic compare operation specified by the operator. note that the compare value
from the parser is always in string form from the original expression.
*/
func evalCompareVals(attrValue interface{}, compValue string, op filter.CompareOperator) (bool, error) {
	if attrValue == nil {
		return evalCompareNil(compValue, op), nil
	}

	switch v := attrValue.(type) {
	case string:
		return evalCompareStrings(op, attrValue.(string), compValue), nil

	case int:
		iValue, err := strconv.Atoi(compValue)
		if err != nil {
			return false, err
		}
		return evalCompareInt(op, v, iValue), nil
	case float32:
		fValue, err := strconv.ParseFloat(compValue, 32)
		if err != nil {
			return false, err
		}
		return evalCompareFloat(op, float64(v), fValue), nil
	case float64:
		fValue, err := strconv.ParseFloat(compValue, 64)
		if err != nil {
			return false, err
		}
		return evalCompareFloat(op, v, fValue), nil
	}
	return false, errors.New("Undefined attribute input type: " + fmt.Sprint(attrValue))
}

func evalAttributeExpression(e filter.AttributeExpression, input string) (bool, error) {
	path := e.AttributePath
	attrValue := getAttributeValue(input, path)

	compValue := e.CompareValue
	switch av := attrValue.(type) {

	case string, int, float32, float64, nil:
		return evalCompareVals(attrValue, compValue, e.Operator)

	case []interface{}:
		match := false
		for _, v := range av {
			res, err := evalCompareVals(v, compValue, e.Operator)
			if err != nil {
				fmt.Println(err.Error())
			}
			if res {
				match = true
			}
		}
		return match, nil
	default:
		msg := fmt.Sprintf("AttributePath type %t not implemented for compare: %v", av, compValue)
		fmt.Println(msg)
		return false, errors.New(msg)
	}

}

func evalCompareStrings(op filter.CompareOperator, attrVal string, compVal string) bool {
	switch op {
	case filter.EQ:
		return attrVal == compVal
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

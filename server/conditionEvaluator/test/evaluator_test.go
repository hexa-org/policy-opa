package test

import (
	"fmt"
	"github.com/hexa-org/policy-opa/server/conditionEvaluator"
	"github.com/stretchr/testify/assert"
	"testing"
)

var input = `
{
	"req":{
		"ip":"127.0.0.1:58810",
		"protocol":"HTTP/1.1",
		"method":"GET",
		"path":"/testpath",
		"param":{
			"a":["b"],
			"c":["d"]
		},
		"header":{
			"Accept-Encoding":["gzip"],
			"Authorization":["Basic dGVzdFVzZXI6Z29vZCZiYWQ="],
			"User-Agent":["Go-http-client/1.1"]
		},
		"time":"2022-12-02T11:17:27.91208-08:00"
	},
	"subject":{
		"type":"basic",
		"sub":"testUser"
	},
	"level" : 4,
}`

type testType struct {
	Filter    string
	Result    bool
	ErrorTest string
}

var tests = []testType{
	{"subject.sub pr", true, ""},
	{"req.ip sw \"192.0.0.1\"", false, ""},
	{"req.param.a eq \"b\"", true, ""},
	{"req.param.c eq \"b\"", false, ""},
	{"req.param.c gt \"b\"", true, ""},
	{"subject.sub eq testUser and req.param.c gt \"b\"", true, ""},
	{"a.b eq testNoAttribute and req.param.c gt \"b\"", false, ""},
	{"level eq 4", true, ""},
	{"level ne 4", false, ""},
}

func TestEvaluate(t *testing.T) {
	fmt.Println("Input: ")
	fmt.Println(input)

	for k, test := range tests {
		t.Run(test.Filter, func(t *testing.T) {
			fmt.Println(fmt.Sprintf("Test: [%v]", k))

			fmt.Println(fmt.Sprintf("Filter:\t%s", test.Filter))
			res, err := conditionEvaluator.Evaluate(test.Filter, input)
			if err != nil {
				if err.Error() != test.ErrorTest {
					t.Errorf("Unexpected test error %v", err)
				}
				fmt.Printf("Received expected error: " + test.ErrorTest)
			}
			assert.Equal(t, test.Result, res, "Evaluation match confirmation")

		})
	}

}

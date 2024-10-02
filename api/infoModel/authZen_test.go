package infoModel

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

var requestSimple = `{
  "subject": {
    "type": "user",
    "id": "alice@acmecorp.com"
  },
  "action": {
    "name": "can_read",
    "properties": {
      "method": "GET"
    }
  },
  "resource": {
    "type": "account",
    "id": "123"
  },
  "context": {
    "time": "1985-10-26T01:22-07:00"
  }
}`

var requestWithArray = `{
  "evaluations": [
    {
      "subject": {
        "type": "user",
        "id": "alice@acmecorp.com"
      },
      "action": {
        "name": "can_read"
      },
      "resource": {
        "type": "document",
        "id": "boxcarring.md"
      },
      "context": {
        "time": "2024-05-31T15:22-07:00"
      }
    },
    {
      "subject": {
        "type": "user",
        "id": "alice@acmecorp.com"
      },
      "action": {
        "name": "can_read"
      },
      "resource": {
        "type": "document",
        "id": "subject-search.md"
      },
      "context": {
        "time": "2024-05-31T15:22-07:00"
      }
    },
    {
      "subject": {
        "type": "user",
        "id": "alice@acmecorp.com"
      },
      "action": {
        "name": "can_read"
      },
      "resource": {
        "type": "document",
        "id": "resource-search.md"
      },
      "context": {
        "time": "2024-05-31T15:22-07:00"
      }
    }
  ]
}`

var requestWithMap = `{
  "subject": {
    "type": "user",
    "id": "alice@acmecorp.com"
  },
  "context": {
    "time": "2024-05-31T15:22-07:00"
  },
  "evaluations": {
    "eval-1": {
      "action": {
        "name": "can_read"
      },
      "resource": {
        "type": "document",
        "id": "boxcarring.md"
      }
    },
    "eval-2": {
      "action": {
        "name": "can_read"
      },
      "resource": {
        "type": "document",
        "id": "subject-search.md"
      }
    },
    "eval-3": {
      "action": {
        "name": "can_read"
      },
      "resource": {
        "type": "document",
        "id": "resource-search.md"
      }
    }
  }
}`

var requestWithArrayDefaults = `{
  "action": {
    "name": "can_read"
  },
  "resource": {
    "type": "document",
    "id": "boxcarring.md"
  },
  "evaluations": [
    {
      "subject": {
        "type": "user",
        "id": "alice@acmecorp.com"
      },
      "context": {
        "time": "2024-05-31T15:22-07:00"
      }
    },
    {
      "subject": {
        "type": "user",
        "id": "bob@acmecorp.com"
      },
      "context": {
        "time": "2024-05-31T15:22-07:00"
      }
    }
  ]
}`

func TestEvalParseSimple(t *testing.T) {
	var req QueryRequest

	err := json.Unmarshal([]byte(requestSimple), &req)
	assert.Nil(t, err)

	assert.Nil(t, req.Evaluations, "Should be slices")

	items := req.EvaluationItems()
	assert.Len(t, items, 1, "Should be 1")

	marshalRequest, err := json.MarshalIndent(req, "", "  ")
	assert.Nil(t, err)
	assert.Equal(t, requestSimple, string(marshalRequest))
}

func TestEvalParseExampleArray(t *testing.T) {
	var req QueryRequest

	err := json.Unmarshal([]byte(requestWithArray), &req)
	assert.Nil(t, err)

	assert.False(t, req.Evaluations.IsMap(), "Should be slices")
	assert.Len(t, req.Evaluations.GetItemSlice(), 3)
	assert.Nil(t, req.Evaluations.GetItemMap(), "should be no map")

	items := req.EvaluationItems()
	assert.Len(t, items, 3, "Should be 3")

	assert.NotNil(t, items[0].Subject, "Should be subject")
	assert.NotNil(t, items[0].Action, "Should be action")
	assert.NotNil(t, items[0].Resource, "Should be resource")
	assert.NotNil(t, items[0].Context, "Should be context")

	marshalRequest, err := json.MarshalIndent(req, "", "  ")
	assert.Nil(t, err)
	assert.Equal(t, requestWithArray, string(marshalRequest))
}

func TestEvalParseMap(t *testing.T) {
	var reqMap QueryRequest
	err := json.Unmarshal([]byte(requestWithMap), &reqMap)
	assert.Nil(t, err)
	assert.True(t, reqMap.Evaluations.IsMap(), "Should be map")
	assert.Len(t, reqMap.Evaluations.GetItemSlice(), 3)
	assert.Len(t, reqMap.Evaluations.GetItemMap(), 3)

	items := reqMap.EvaluationItems()
	assert.Len(t, items, 3, "Should be 3")

	assert.NotNil(t, items[0].Subject, "Should be subject")
	assert.NotNil(t, items[0].Action, "Should be action")
	assert.NotNil(t, items[0].Resource, "Should be resource")
	assert.NotNil(t, items[0].Context, "Should be context")

	assert.Equal(t, "alice@acmecorp.com", items[0].Subject.Id)

	marshalMap, err := json.MarshalIndent(reqMap, "", "  ")
	assert.Nil(t, err)
	assert.Equal(t, requestWithMap, string(marshalMap), "Map should match")
}

func TestEvalParseArrayDefaults(t *testing.T) {
	var reqMap QueryRequest
	err := json.Unmarshal([]byte(requestWithArrayDefaults), &reqMap)
	assert.Nil(t, err)
	assert.False(t, reqMap.Evaluations.IsMap(), "Should be array")
	assert.Len(t, reqMap.Evaluations.GetItemSlice(), 2)
	assert.Len(t, reqMap.Evaluations.GetItemMap(), 0)

	items := reqMap.EvaluationItems()
	assert.Len(t, items, 2, "Should be 2")

	assert.NotNil(t, items[0].Subject, "Should be subject")
	assert.NotNil(t, items[0].Action, "Should be action")
	assert.NotNil(t, items[0].Resource, "Should be resource")
	assert.NotNil(t, items[0].Context, "Should be context")

	assert.Equal(t, "alice@acmecorp.com", items[0].Subject.Id)
	assert.Equal(t, "bob@acmecorp.com", items[1].Subject.Id)
	assert.Equal(t, "can_read", items[1].Action.Name)
	assert.Equal(t, "boxcarring.md", items[0].Resource.Id)

	marshalMap, err := json.MarshalIndent(reqMap, "", "  ")
	assert.Nil(t, err)
	assert.Equal(t, requestWithArrayDefaults, string(marshalMap), "Map should match")
}

var responseSimple = `{
  "decision": true,
  "context": {
    "id": "0",
    "reason_admin": {
      "en": "Request failed policy C076E82F"
    },
    "reason_user": {
      "en-403": "Insufficient privileges. Contact your administrator",
      "es-403": "Privilegios insuficientes. Póngase en contacto con su administrador"
    }
  }
}`

var responseMulti = `{
  "evaluations": [
    {
      "decision": true
    },
    {
      "decision": false,
      "context": {
        "reason": "resource not found"
      }
    },
    {
      "decision": false,
      "context": {
        "reason": "Subject is a viewer of the resource"
      }
    }
  ]
}`

func TestEvalResponseSimple(t *testing.T) {
	var resp DecisionResponse

	err := json.Unmarshal([]byte(responseSimple), &resp)
	assert.Nil(t, err)

	assert.True(t, resp.Decision, "decision should be true")

	adminReason := resp.Context.GetSubProperty("reason_admin", "en")
	fmt.Println(fmt.Sprintf("%v", adminReason))
	assert.Equal(t, "Request failed policy C076E82F", adminReason)

}

func TestEvalResponseQuery(t *testing.T) {
	var resp EvaluationsResponse

	err := json.Unmarshal([]byte(responseMulti), &resp)
	assert.Nil(t, err)

	assert.NotNil(t, resp.Evaluations, "Evaluations should NOT be nil")

	evaluations := *resp.Evaluations

	assert.Len(t, evaluations, 3, "should be 3 evaluation responses")
	decision := evaluations[1]
	assert.False(t, decision.Decision, "should be false/denied")

	reason := decision.Context.GetPropertyString("reason")
	// fmt.Println(fmt.Sprintf("%v", reason))
	assert.Equal(t, "resource not found", reason)

}

func TestParseSimple10(t *testing.T) {
	reqPreview10 := `{
                "subject": {
                    "type": "user",
                    "id": "morty@the-citadel.com",
                    "identity": "CiRmZDE2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"
                },
                "action": {
                    "name": "can_delete_todo"
                },
                "resource": {
                    "type": "todo",
                    "id": "7240d0db-8ff0-41ec-98b2-34a096273b9f",
                    "ownerID": "morty@the-citadel.com"
                }
            }`

	var req EvaluationItem

	err := json.Unmarshal([]byte(reqPreview10), &req)
	assert.Nil(t, err)

	assert.NotNil(t, req)
	assert.Equal(t, "CiRmZDE2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs", req.Subject.Id, "identity should be mapped to id")
	assert.NotNil(t, req.Resource.Properties, "Properties should be defined")
	assert.Equal(t, "morty@the-citadel.com", req.Resource.Properties["ownerID"])
}

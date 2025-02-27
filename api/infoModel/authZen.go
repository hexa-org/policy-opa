package infoModel

// These structures based on draft AuthZen API spec: https://github.com/openid/authzen/blob/api-spec-evaluation-edits/api/authorization-api-1_0.md
import (
	"bytes"
	"encoding/json"
	"fmt"
)

type propertiesInfo map[string]interface{}

type SubjectInfo struct {
	Type       string         `json:"type,omitempty"`
	Id         string         `json:"id,omitempty"`
	UserID     string         `json:"userID,omitempty"`
	Properties propertiesInfo `json:"properties,omitempty"`
}

func (e *SubjectInfo) UnmarshalJSON(data []byte) error {

	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return err
	}
	for k, v := range rawMap {
		switch k {
		case "id":
			var id string
			if err := json.Unmarshal(v, &id); err != nil {
				return err
			}
			e.Id = id
		case "type":
			var sType string
			if err := json.Unmarshal(v, &sType); err != nil {
				return err
			}
			e.Type = sType
		case "properties":
			var properties propertiesInfo
			if err := json.Unmarshal(v, &properties); err != nil {
				return err
			}
			e.Properties = properties
		}
	}
	// if the 1.0 identity exists, use it to override to 1.1's 'id' attribute
	identity, exist := rawMap["identity"]
	if exist {
		var id string
		if err := json.Unmarshal(identity, &id); err != nil {
			return err
		}
		e.Id = id
	}
	uid, exist := rawMap["userID"]
	if exist {
		if e.Properties == nil {
			e.Properties = propertiesInfo{}
		}
		e.Properties["uid"] = uid
	}

	return nil
}

type ResourceInfo struct {
	Type       string         `json:"type,omitempty"`
	Id         string         `json:"id,omitempty"`
	Properties propertiesInfo `json:"properties,omitempty"`
}

func (r *ResourceInfo) UnmarshalJSON(data []byte) error {
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return err
	}
	for k, v := range rawMap {
		switch k {
		case "type":
			var rType string
			if err := json.Unmarshal(v, &rType); err != nil {
				return err
			}
			r.Type = rType
		case "id":
			var id string
			if err := json.Unmarshal(v, &id); err != nil {
				return err
			}
			r.Id = id
		case "properties":
			var properties propertiesInfo
			if err := json.Unmarshal(v, &properties); err != nil {
				return err
			}
			r.Properties = properties
		}

	}
	rawOid, exist := rawMap["ownerID"]
	if exist {
		if r.Properties == nil {
			r.Properties = propertiesInfo{}
		}
		var oid string
		if err := json.Unmarshal(rawOid, &oid); err != nil {
			return err
		}
		r.Properties["ownerID"] = oid
	}
	return nil
}

type ActionInfo struct {
	Name       string         `json:"name,omitempty"`
	Properties propertiesInfo `json:"properties,omitempty"`
}

type ContextInfo propertiesInfo

func (c ContextInfo) GetPropertyString(id string) string {
	return fmt.Sprintf("%v", c[id])
}

func (c ContextInfo) GetProperty(id string) interface{} {
	return c[id]
}

func (c ContextInfo) GetSubProperty(id, sub string) string {
	subMap := c.GetProperty(id)
	switch item := subMap.(type) {
	case map[string]interface{}:
		return fmt.Sprintf("%v", item[sub])
	default:
		return ""
	}
}

type EvaluationItem struct {
	Subject  *SubjectInfo  `json:"subject,omitempty"`
	Action   *ActionInfo   `json:"action,omitempty"`
	Resource *ResourceInfo `json:"resource,omitempty"`
	Context  *ContextInfo  `json:"context,omitempty"`
}

type EvaluationBlock struct {
	Items   *[]EvaluationItem         `json:"-"`
	ItemMap map[string]EvaluationItem `json:"-"`
}

func (e *EvaluationBlock) IsMap() bool {
	return e.ItemMap != nil
}

func (e *EvaluationBlock) GetItemMap() map[string]EvaluationItem {
	return e.ItemMap
}

func (e *EvaluationBlock) GetItemSlice() []EvaluationItem {
	if e.IsMap() {
		items := []EvaluationItem{}
		for _, v := range e.ItemMap {
			items = append(items, v)
		}
		return items
	}
	return *e.Items
}

func (e EvaluationBlock) MarshalJSON() ([]byte, error) {

	if e.IsMap() {
		return json.Marshal(e.ItemMap)
	}
	return json.Marshal(e.Items)
}

func (e *EvaluationBlock) UnmarshalJSON(data []byte) error {
	// This logic handles two possible forms where evaluations is an array of evaluationItem or is a map[<id>]EvaluationItem
	var items []json.RawMessage
	if err := json.Unmarshal(data, &items); err != nil {
		// try  map
		var rawMap map[string]json.RawMessage
		if err := json.Unmarshal(data, &rawMap); err != nil {
			return err
		}
		itemMap := make(map[string]EvaluationItem, len(rawMap))
		for k, v := range rawMap {
			var item EvaluationItem
			if err := json.Unmarshal(v, &item); err != nil {
				return err
			}
			itemMap[k] = item
		}
		e.ItemMap = itemMap
		return nil
	}
	itemSlice := make([]EvaluationItem, len(items))
	for k, v := range items {
		var item EvaluationItem
		if err := json.Unmarshal(v, &item); err != nil {
			return err
		}
		itemSlice[k] = item
	}
	e.Items = &itemSlice
	return nil
}

// QueryRequest is used to make multiple decisions via the evaluations endpoint
type QueryRequest struct {
	*EvaluationItem
	Evaluations *EvaluationBlock `json:"evaluations,omitempty"`
}

func (q QueryRequest) MarshalJSON() ([]byte, error) {
	itemBytes := []byte("{}")
	var err error
	if q.EvaluationItem != nil {
		itemBytes, err = json.Marshal(q.EvaluationItem)
		if err != nil {
			return nil, err
		}
	}

	eBlockBytes := []byte("{}")
	if q.Evaluations != nil {
		eBlockBytes, err = q.Evaluations.MarshalJSON()
		if err != nil {
			return nil, err
		}
	}

	byteBuf := bytes.NewBufferString("{")

	if len(itemBytes) > 2 {
		// only write if there is an item (omit empty)
		byteBuf.Write(itemBytes[1 : len(itemBytes)-1])
		if len(eBlockBytes) > 2 {
			byteBuf.WriteString(",")
		}
	}
	if len(eBlockBytes) > 2 {
		// only write if there is an EvaluationBlock (omit empty)
		byteBuf.Write([]byte("\"evaluations\":"))
		byteBuf.Write(eBlockBytes)
	}
	byteBuf.Write([]byte("}"))
	return byteBuf.Bytes(), nil
}

func applyDefault(def *EvaluationItem, item EvaluationItem) EvaluationItem {
	if def == nil {
		return item
	}
	ret := EvaluationItem{}

	if item.Context == nil {
		ret.Context = def.Context
	} else {
		ret.Context = item.Context
	}

	if item.Subject == nil {
		ret.Subject = def.Subject
	} else {
		ret.Subject = item.Subject
	}

	if item.Action == nil {
		ret.Action = def.Action
	} else {
		ret.Action = item.Action
	}
	if item.Resource == nil {
		ret.Resource = def.Resource
	} else {
		ret.Resource = item.Resource
	}
	return ret
}

func (q QueryRequest) EvaluationItems() []EvaluationItem {
	if q.Evaluations == nil {
		// this is the legacy mode
		return []EvaluationItem{*q.EvaluationItem}
	}
	if q.Evaluations.Items != nil {
		ret := make([]EvaluationItem, len(*q.Evaluations.Items))
		for i, item := range *q.Evaluations.Items {
			ret[i] = applyDefault(q.EvaluationItem, item)
		}
		return ret
	}
	ret := make([]EvaluationItem, len(q.Evaluations.ItemMap))
	i := 0
	for _, item := range q.Evaluations.ItemMap {
		ret[i] = applyDefault(q.EvaluationItem, item)
		i++
	}
	return ret
}

type DecisionResponse struct {
	Decision    bool              `json:"decision"`
	ReasonAdmin map[string]string `json:"reason_admin,omitempty"`
	ReasonUser  map[string]string `json:"reason_user,omitempty"`
	Context     *ContextInfo      `json:"context,omitempty"`
}

type EvaluationsResponse struct {
	Evaluations []DecisionResponse `json:"evaluations,omitempty"`
}

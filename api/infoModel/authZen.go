package infoModel

// These structures based on draft AuthZen API spec: https://github.com/openid/authzen/blob/api-spec-evaluation-edits/api/authorization-api-1_0.md
import (
	"encoding/json"
	"time"
)

type SubjectInfo struct {
	Identity   string `json:"identity,omitempty"`
	Username   string `json:"username,omitempty"`
	Jwt        string `json:"jwt,omitempty"`
	IpAddress  string `json:"ipAddress,omitempty"`
	DeviceId   string `json:"deviceId,omitempty"`
	Department string `json:"department,omitempty"`
}

type ResourceInfo struct {
	Id   string `json:"id,omitempty"`
	Type string `json:"type"`
	json.RawMessage
}

type ActionInfo struct {
	Name   string `json:"name,omitempty"`
	Method string `json:"method,omitempty"`
}

type ContextInfo struct {
	json.RawMessage // no spec
}

type QueryItem struct {
	Action   string       `json:"action"`
	Resource ResourceInfo `json:"resource"`
}

type QueryRequest struct {
	Subject SubjectInfo `json:"subject"`
	Queries []QueryItem `json:"queries"`
}

type AuthRequest struct {
	Subject  SubjectInfo  `json:"subject"`
	Action   ActionInfo   `json:"action,omitempty"`
	Resource ResourceInfo `json:"resource,omitempty"`
	Context  ContextInfo  `json:"context,omitempty"`
}

type QueryDecision struct {
	Action   string        `json:"action"`
	Resource ResourceInfo  `json:"resource"`
	Decision bool          `json:"decision"`
	Reasons  []json.Number `json:"reasons"`
}

type SimpleResponse struct {
	Decision bool `json:"decision"`
}

type ReasonObject struct {
	Id          json.Number       `json:"id"`
	ReasonAdmin map[string]string `json:"reason_admin,omitempty"`
	ReasonUser  map[string]string `json:"reason_user,omitempty"`
}

type EvaluationsResponse struct {
	Iat      time.Time       `json:"iat,omitempty"`
	Exp      time.Time       `json:"exp,omitempty"`
	Subject  SubjectInfo     `json:"subject,omitempty"`
	Decision []QueryDecision `json:"decision"`
	Reasons  []ReasonObject  `json:"reasons,omitempty"`
}

/*
 "request": {
        "subject": {
          "identity": "CiRmZDA2MTRkMy1jMzlhLTQ3ODEtYjdiZC04Yjk2ZjVhNTEwMGQSBWxvY2Fs"
        },
        "action": {
          "name": "can_create_todo"
        },
        "resource": {
          "type": "todo"
        }
      },
*/

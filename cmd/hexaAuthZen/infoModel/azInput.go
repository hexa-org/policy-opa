package infoModel

import "github.com/hexa-org/policy-opa/client/hexaOpaClient"

type AzInfo struct {
	Req      *hexaOpaClient.ReqParams   `json:"req"`
	Subject  *hexaOpaClient.SubjectInfo `json:"subject"`
	Resource ResourceInfo               `json:"resource"`
}

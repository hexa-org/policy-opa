package decisionsupport

import "net/http"

type DecisionProvider interface {
	BuildInput(r *http.Request, actionUris []string, resourceUris []string) (any interface{}, err error)
	Allow(any interface{}) (bool, error)
}

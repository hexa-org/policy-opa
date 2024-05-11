package decisionsupport

import (
	"net/http"
	"strings"
)

type DecisionSupport struct {
	Provider     DecisionProvider
	Unauthorized http.HandlerFunc
	Skip         []string
	ActionMap    map[string]string // ActionMap converts a path into an actionUri (map[path]=urivalue
	ResourceMap  map[string]string // ResourceMap converts a path into an resourceUri (map[path]=urivalue
	ResourceId   string            // ResourceId if set is passed as part of buildInput overriding ResourceMap
}

func (d *DecisionSupport) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, s := range d.Skip {
			if strings.HasPrefix(r.RequestURI, s) {
				next.ServeHTTP(w, r)
				return
			}
		}

		var actionUris, resourceIds []string

		if d.ResourceId != "" {
			resourceIds = []string{d.ResourceId}
		} else {
			resource, exist := d.ResourceMap[r.URL.Path]
			if exist {
				resourceIds = append(resourceIds, resource)
			}
		}

		action, exist := d.ActionMap[r.URL.Path]
		if exist {
			actionUris = append(actionUris, action)
		}

		// log.Println("Building decision request info.")
		input, inputErr := d.Provider.BuildInput(r, actionUris, resourceIds)
		if inputErr != nil {
			d.Unauthorized(w, r)
			return
		}

		// log.Println("Checking authorization.")
		allow, err := d.Provider.Allow(input)
		if !allow || err != nil {
			d.Unauthorized(w, r)
		} else {
			next.ServeHTTP(w, r)
		}
	})
}

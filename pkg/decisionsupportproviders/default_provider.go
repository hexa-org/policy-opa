package decisionsupportproviders

import "net/http"

type DefaultProvider struct {
}

func (d DefaultProvider) BuildInput(_ *http.Request, _ []string, _ []string) (any interface{}, err error) {

	panic("implement me")
}

func (d DefaultProvider) Allow(_ interface{}) (bool, error) {

	panic("implement me")
}

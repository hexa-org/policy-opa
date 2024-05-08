package decisionsupportproviders_test

import (
	"testing"

	"github.com/hexa-org/policy-opa/pkg/decisionsupportproviders"
	"github.com/stretchr/testify/assert"
)

func TestDefaultProvider_BuildInput(t *testing.T) {
	provider := decisionsupportproviders.DefaultProvider{}
	assert.Panics(t, func() { _, _ = provider.BuildInput(nil, nil, nil) })
}

func TestDefaultProvider_Allow(t *testing.T) {
	provider := decisionsupportproviders.DefaultProvider{}
	assert.Panics(t, func() { _, _ = provider.Allow(nil) })
}

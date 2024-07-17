package mockopasupport

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/hexa-org/policy-opa/client/hexaOpaClient"
	"github.com/hexa-org/policy-opa/pkg/decisionsupportproviders"
	"github.com/stretchr/testify/assert"
)

func TestNewMockOPA(t *testing.T) {
	ts := NewMockOPA(t, nil)
	defer ts.Shutdown()

	assert.NotNil(t, ts)

	req, _ := http.NewRequest("GET", "http://demo.hexa.org:8886/dashboard", nil)

	opaInput := hexaOpaClient.PrepareInput(req, []string{"root"}, []string{"hexaIndustries"})
	input := decisionsupportproviders.OpaRestQuery{
		Input: *opaInput,
	}

	bodyBytes, err := json.Marshal(input)
	rs, err := ts.Server.Client().Post(ts.GetQueryUrl(), "application/json", bytes.NewBuffer(bodyBytes))
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, http.StatusOK, rs.StatusCode)
	defer rs.Body.Close()
	body, err := io.ReadAll(rs.Body)
	if err != nil {
		t.Fatal(err)
	}
	assert.NotNil(t, body)
}

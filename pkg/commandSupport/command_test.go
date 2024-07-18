package commandSupport

import (
	"fmt"
	"io"
	"path"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/hexa-org/policy-mapper/pkg/keysupport"
	"github.com/hexa-org/policy-mapper/pkg/tokensupport"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/config"
	"github.com/stretchr/testify/assert"
)

func TestDemoFlow(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	certPath := fmt.Sprintf("%s=%s", keysupport.EnvCertDirectory, filepath.Join(path.Dir(file), "../../.certs"))
	bundlePath := fmt.Sprintf("%s=%s", config.EnvBundleDir, filepath.Join(path.Dir(file), "../../deployments/authZen/bundles"))
	userPip := fmt.Sprintf("%s=%s", config.EnvAuthUserPipFile, filepath.Join(path.Dir(file), "../../deployments/authZen/users.json"))
	tokenMode := fmt.Sprintf("%s=%s", tokensupport.EnvTknEnforceMode, tokensupport.ModeEnforceAnonymous)

	authZenCmd, outBuf := MakeCmd("/cmd/hexaAuthZen/main.go", []string{"PORT=8999", certPath, "HEXA_TLS_ENABLED=false", bundlePath, userPip, tokenMode})

	err := StartCmd(authZenCmd, 8999)
	assert.Nil(t, err)
	// startCmd(orchestrator, 8885)

	AssertContains(t, "http://localhost:8999/", "Hexa Authzen Test Server")

	StopCmds(authZenCmd)

	outBytes, err := io.ReadAll(outBuf)
	assert.NoError(t, err)
	assert.Contains(t, string(outBytes), "Server[HexaAuthZen] listening on :8999")
	fmt.Println("output:\n" + string(outBytes) + "\n")

}

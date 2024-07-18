package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hexa-org/policy-mapper/pkg/tokensupport"
	"github.com/stretchr/testify/assert"
)

func TestHelp(t *testing.T) {
	args := map[string]string{"help": "true"}

	res := execArgs(args)

	assert.Contains(t, res, "hexakey generates certificates and tokens for use with the Hexa Bundle Server and AuthZen servers")
}

func TestNothing(t *testing.T) {
	res := execArgs(map[string]string{})
	assert.Contains(t, res, "Missing -type=jwt or -type=tls, see -help")
}

func TestTls(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "hexakey-*")
	assert.NoError(t, err)
	defer func(path string) {
		_ = os.RemoveAll(path)
	}(tempDir)
	args := map[string]string{"type": "tls", "dir": tempDir}
	res := execArgs(args)
	fmt.Println(res)
	_, err = os.Stat(filepath.Join(tempDir, "ca-key.pem"))
	assert.False(t, os.IsNotExist(err), "Check file exists")
	// repeat for pre-existing
}

func TestToken(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "hexakey-*")
	assert.NoError(t, err)
	defer func(path string) {
		_ = os.RemoveAll(path)
	}(tempDir)
	args := map[string]string{"type": "jwt", "action": "init", "dir": tempDir}
	res := execArgs(args)
	assert.Contains(t, res, fmt.Sprintf("Token public and private keys generated in %s", tempDir))
	fmt.Println(res)
	_, err = os.Stat(filepath.Join(tempDir, "issuer-cert.pem"))
	assert.False(t, os.IsNotExist(err), "Check file exists")

	args = map[string]string{"type": "jwt", "action": "issue", "dir": tempDir, "scopes": "bundle,root", "mail": "test@example.com"}
	res = execArgs(args)
	assert.Contains(t, res, "Bearer token issue")

	keyfile := filepath.Join(tempDir, "issuer-priv.pem")
	args = map[string]string{"type": "jwt", "action": "issue", "keyfile": keyfile, "scopes": "bundle,root", "mail": "test@example.com"}
	res = execArgs(args)
	assert.Contains(t, res, "Bearer token issue")

	// New dir
	newDir := filepath.Join(tempDir, "subDir")
	args = map[string]string{"type": "jwt", "action": "init", "dir": newDir, "scopes": "bundle,root", "mail": "test@example.com"}
	res = execArgs(args)
	assert.Contains(t, res, fmt.Sprintf("Token public and private keys generated in %s", newDir))
}

func TestTokenNeg(t *testing.T) {
	tempDir, _ := os.MkdirTemp("", "hexakey-*")
	defer func(path string) {
		_ = os.RemoveAll(path)
	}(tempDir)

	// bad action arg
	args := map[string]string{"type": "jwt", "action": "token", "dir": tempDir, "scopes": "bundle,root", "mail": "test@example.com"}
	res := execArgs(args)
	assert.Contains(t, res, "Select -action=init or -action=issue\n")

	// no private key
	argsIssue := map[string]string{"type": "jwt", "dir": tempDir, "action": "issue", "scopes": "bundle,root", "mail": "test@example.com"}
	res = execArgs(argsIssue)
	assert.Contains(t, res, "issuer-priv.pem: no such file or directory")

	args = map[string]string{"type": "jwt", "action": "init", "dir": tempDir}
	res = execArgs(args)
	assert.Contains(t, res, fmt.Sprintf("Token public and private keys generated in %s", tempDir))

	// bad scope
	argsBadScope := map[string]string{"type": "jwt", "dir": tempDir, "action": "issue", "scopes": "wrong", "mail": "test@example.com"}
	res = execArgs(argsBadScope)
	assert.Contains(t, res, "Invalid scope [wrong] detected.")

	// no email
	argsBadEmail := map[string]string{"type": "jwt", "dir": tempDir, "action": "issue", "scopes": tokensupport.ScopeBundle}
	res = execArgs(argsBadEmail)
	assert.Contains(t, res, "An email address (-mail) is required for the user of the token")

}

func execArgs(args map[string]string) string {
	old := os.Stdout

	r, w, _ := os.Pipe()
	os.Stdout = w

	for k, v := range args {

		err := flag.Set(k, v)
		if err != nil {
			fmt.Println(err.Error())
		}
	}

	start()

	/*
	   outChan := make(chan string)
	   // copy the output in a separate goroutine so printing can't block indefinitely
	   go func() {
	       var buf bytes.Buffer
	       io.Copy(&buf, r)
	       outChan <- buf.String()
	   }()

	   // back to normal state

	*/
	os.Stdout = old
	_ = w.Close()
	out, _ := io.ReadAll(r)
	_ = r.Close()

	// output := <-outChan
	// close(outChan)

	resetFlags()
	return string(out)

}

func resetFlags() {
	flag.VisitAll(func(f *flag.Flag) {
		if strings.Contains(f.Name, "test") {
			return
		}
		_ = f.Value.Set(f.DefValue)
	})
}

package tokensupport

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type testSuite struct {
	suite.Suite
	keyDir      string
	keyfile     string
	Handler     *TokenHandler
	bundleToken string
	azToken     string
}

func TestTokenGenerator(t *testing.T) {
	path, _ := os.MkdirTemp("", "token-*")

	_ = os.Setenv(EnvTknKeyDirectory, path)
	_ = os.Unsetenv(EnvTknPubKeyFile)
	_ = os.Unsetenv(EnvTknPrivateKeyFile)

	handler, err := GenerateIssuerKeys("authzen", false)
	assert.NoError(t, err, "Check no error generating issuer")
	assert.Equal(t, "authzen", handler.TokenIssuer, "Check issuer set")
	s := testSuite{
		Suite:   suite.Suite{},
		keyDir:  path,
		keyfile: handler.PrivateKeyPath,
		Handler: handler,
	}
	suite.Run(t, &s)

	s.cleanup()
}

func (s *testSuite) cleanup() {
	_ = os.RemoveAll(s.keyDir)
}

func (s *testSuite) TestGenerateIssuer() {

	assert.Equal(s.T(), s.keyDir, filepath.Clean(s.Handler.KeyDir), "Check key directory")
	assert.NotNil(s.T(), s.Handler.PublicKey, "Public key created")
	dir, err := os.ReadDir(s.keyDir)
	assert.NoError(s.T(), err, "able to read key dir")
	numFiles := len(dir)
	assert.Greater(s.T(), numFiles, 1, "should be at least 2 files")
}

func (s *testSuite) TestLoadExisting() {

	handler2, err := LoadIssuer("authzen")
	assert.NoError(s.T(), err, "No error on load")
	assert.NotNil(s.T(), handler2.PrivateKey, "Check private key loaded")
}

func (s *testSuite) TestIssueAndValidateToken() {
	fmt.Println("Loading validator...")
	_ = os.Unsetenv(EnvTknKeyDirectory)
	_ = os.Unsetenv(EnvTknPrivateKeyFile)
	_ = os.Setenv(EnvTknPubKeyFile, filepath.Join(s.keyDir, DefTknPublicKeyFile))
	validator, err := TokenValidator("authzen")
	assert.NoError(s.T(), err, "No error on load")
	assert.NotNil(s.T(), validator, "Check validator not null")
	assert.Equal(s.T(), ModeEnforceAll, validator.Mode, "Check mode is enforce ALL by default")

	fmt.Println("Issuing token...")

	tokenString, err := s.Handler.IssueToken([]string{ScopeBundle}, "test@example.com")
	assert.NoError(s.T(), err, "No error issuing token")
	assert.NotEmpty(s.T(), tokenString, "Token has a value")
	s.bundleToken = tokenString

	tokenString, err = s.Handler.IssueToken([]string{ScopeDecision}, "test@example.com")
	assert.NoError(s.T(), err, "No error issuing token")
	assert.NotEmpty(s.T(), tokenString, "Token has a value")
	fmt.Println("Token issued:\n" + tokenString)
	s.azToken = tokenString // save for the next test

	req, _ := http.NewRequest("GET", "example.com", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	fmt.Println("Validate token...")

	fmt.Println("  Positive check")
	jwt, status := validator.ValidateAuthorization(req, []string{ScopeDecision})
	assert.Equal(s.T(), http.StatusOK, status, "Check status ok")
	email := jwt.Email
	assert.Equal(s.T(), "test@example.com", email, "Check email parsed")

	fmt.Println("  Negative checks")

	// Token should be valid but wrong scope
	jwt, status = validator.ValidateAuthorization(req, []string{ScopeBundle})
	assert.Equal(s.T(), http.StatusForbidden, status, "Check forbidden")

	// Token not valid
	req.Header.Del("Authorization")
	req.Header.Set("Authorization", "Bearer bleh"+tokenString)
	jwt, status = validator.ValidateAuthorization(req, []string{ScopeDecision})
	assert.Equal(s.T(), http.StatusUnauthorized, status, "Check unauthorized")
	assert.Nil(s.T(), jwt, "JWT should be nil")

	// no authorization
	req.Header.Del("Authorization")
	jwt, status = validator.ValidateAuthorization(req, []string{ScopeDecision})
	assert.Equal(s.T(), http.StatusUnauthorized, status, "Check unauthorized")
	assert.Nil(s.T(), jwt, "JWT should be nil")

	// No authorization type
	req.Header.Set("Authorization", tokenString)
	jwt, status = validator.ValidateAuthorization(req, []string{ScopeDecision})
	assert.Equal(s.T(), http.StatusUnauthorized, status, "Check unauthorized")
	assert.Nil(s.T(), jwt, "JWT should be nil")
}

func (s *testSuite) TestValidateMode() {
	fmt.Println("Loading validator...")
	_ = os.Unsetenv(EnvTknKeyDirectory)
	_ = os.Unsetenv(EnvTknPrivateKeyFile)
	_ = os.Setenv(EnvTknPubKeyFile, filepath.Join(s.keyDir, DefTknPublicKeyFile))
	_ = os.Setenv(EnvTknEnforceMode, ModeEnforceBundle)

	validator, err := TokenValidator("authzen")
	assert.NoError(s.T(), err, "No error on load")
	assert.NotNil(s.T(), validator, "Check validator not null")
	assert.Equal(s.T(), ModeEnforceBundle, validator.Mode, "Check mode is enforce BUNDLE")

	fmt.Println("Validate token...")

	fmt.Println("  Positive check")

	fmt.Println("    Anonymous")
	req, _ := http.NewRequest("GET", "example.com", nil)
	jwt, status := validator.ValidateAuthorization(req, []string{ScopeDecision})
	assert.Equal(s.T(), http.StatusOK, status, "Check status ok")
	assert.Nil(s.T(), jwt, "JWT should be nil")

	fmt.Println("    Az scope token")
	req.Header.Set("Authorization", "Bearer "+s.azToken)
	jwt, status = validator.ValidateAuthorization(req, []string{ScopeDecision})
	assert.Equal(s.T(), http.StatusOK, status, "Check status ok")
	assert.Equal(s.T(), http.StatusOK, status, "Check status ok")
	assert.Nil(s.T(), jwt, "JWT should be nil")

	fmt.Println("    Bundle token")
	req.Header.Set("Authorization", "Bearer "+s.bundleToken)
	jwt, status = validator.ValidateAuthorization(req, []string{ScopeBundle})
	assert.Equal(s.T(), http.StatusOK, status, "Check status ok")
	email := jwt.Email
	assert.Equal(s.T(), "test@example.com", email, "Check email parsed")

	fmt.Println("  Negative checks")

	// Token should be valid but wrong scope
	req.Header.Set("Authorization", "Bearer "+s.azToken)
	jwt, status = validator.ValidateAuthorization(req, []string{ScopeBundle})
	assert.Equal(s.T(), http.StatusForbidden, status, "Check forbidden")

}

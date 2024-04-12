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
	keyDir  string
	keyfile string
	Handler *TokenHandler
}

func TestTokenGenerator(t *testing.T) {
	path, _ := os.MkdirTemp("", "token-*")
	keyfile := filepath.Join(path, DefTknPrivFileName)
	handler, err := GenerateIssuer("authzen", keyfile)
	assert.NoError(t, err, "Check no error generating issuer")
	assert.Equal(t, "authzen", handler.TokenIssuer, "Check issuer set")
	s := testSuite{
		Suite:   suite.Suite{},
		keyDir:  path,
		keyfile: keyfile,
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

	handler2, err := LoadIssuer("authzen", s.keyfile)
	assert.NoError(s.T(), err, "No error on load")
	assert.NotNil(s.T(), handler2.PrivateKey, "Check private key loaded")
}

func (s *testSuite) TestIssueAndValidateToken() {
	fmt.Println("Loading validator...")
	validator, err := TokenValidator("authzen", filepath.Join(s.keyDir, TknIssuePubKeyFile))
	assert.NoError(s.T(), err, "No error on load")
	assert.NotNil(s.T(), validator, "Check validator not null")

	fmt.Println("Issuing token...")
	tokenString, err := s.Handler.IssueToken([]string{ScopeDecision}, "test@example.com")
	assert.NoError(s.T(), err, "No error issuing token")
	assert.NotEmpty(s.T(), tokenString, "Token has a value")
	fmt.Println("Token issued:\n" + tokenString)

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

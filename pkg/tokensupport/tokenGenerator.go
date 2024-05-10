package tokensupport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	ScopeBundle          string = "bundle"
	ScopeDecision        string = "az"
	ScopeAdmin           string = "root"
	EnvTknKeyDirectory   string = "TKN_DIRECTORY"
	EnvTknPrivateKeyFile string = "TKN_PRIVKEYFILE"
	EnvTknPubKeyFile     string = "TKN_PUBKEYFILE"

	DefTknPrivateKeyFile string = "issuer-priv.pem"
	DefTknPublicKeyFile  string = "issuer-cert.pem"
	EnvTknEnforceMode    string = "TKN_MODE"
	EnvTknIssuer         string = "TKN_ISSUER"

	ModeEnforceAnonymous = "ANON"
	ModeEnforceBundle    = "BUNDLE"
	ModeEnforceAll       = "ALL"
)

type JwtAuthToken struct {
	Scopes []string `json:"roles,omitempty"`
	Email  string   `json:"email,omitempty"`
	jwt.RegisteredClaims
}

type TokenHandler struct {
	TokenIssuer    string
	PrivateKey     *rsa.PrivateKey
	PublicKey      keyfunc.Keyfunc
	KeyDir         string
	PrivateKeyPath string
	PublicKeyPath  string
	Mode           string
}

func (a *TokenHandler) PrivateKeyExists() bool {
	stat, err := os.Stat(a.PrivateKeyPath)
	return err == nil && !stat.IsDir()
}

func getConfig() *TokenHandler {
	validationString := os.Getenv(EnvTknEnforceMode)
	var validationMode string

	switch strings.ToUpper(validationString) {
	case ModeEnforceAll:
		validationMode = ModeEnforceAll
	case ModeEnforceBundle:
		validationMode = ModeEnforceBundle
	case ModeEnforceAnonymous:
		validationMode = ModeEnforceAnonymous
	default:
		validationMode = ModeEnforceAll
	}

	privateKeyPath := os.Getenv(EnvTknPrivateKeyFile)
	publicKeyPath := os.Getenv(EnvTknPubKeyFile)
	keyDir := os.Getenv(EnvTknKeyDirectory)
	if keyDir == "" {
		if privateKeyPath == "" {
			if publicKeyPath == "" {
				// Default everything
				home := os.Getenv("HOME")
				fmt.Println(fmt.Sprintf("HOME=[%s]", home))
				keyDir = filepath.Join(home, "./.certs")
				fmt.Println(fmt.Sprintf("Setting default key directory of: %s", keyDir))
			} else {
				// This is likely just a validator
				keyDir = filepath.Dir(publicKeyPath)
			}
		} else {
			// This is likely an issuer
			keyDir = filepath.Dir(privateKeyPath)
		}
	}

	fmt.Println("Using key directory: " + keyDir)
	err := os.MkdirAll(keyDir, 0755)
	if err != nil {
		panic(fmt.Sprintf("Was unable to open or create certificate directory(%s):%s", keyDir, err))
	}

	if privateKeyPath == "" {
		privateKeyPath = filepath.Join(keyDir, DefTknPrivateKeyFile)
	}

	if publicKeyPath == "" {
		publicKeyPath = filepath.Join(keyDir, DefTknPublicKeyFile)
	}
	return &TokenHandler{
		KeyDir:         keyDir,
		PublicKeyPath:  publicKeyPath,
		PrivateKeyPath: privateKeyPath,
		Mode:           validationMode,
	}

}

func TokenValidator(name string) (*TokenHandler, error) {
	valConfig := getConfig()

	pemBytes, err := os.ReadFile(valConfig.PublicKeyPath)
	if err != nil {
		// If we are not enforcing then issuer does not matter
		if valConfig.Mode == ModeEnforceAnonymous {
			return valConfig, nil
		}

		return nil, errors.New(fmt.Sprintf("Unalbe to load public key (%s): %s", valConfig.PublicKeyPath, err.Error()))
	}

	derBlock, _ := pem.Decode(pemBytes)
	publicKey, err := x509.ParsePKCS1PublicKey(derBlock.Bytes)
	if err != nil {
		return nil, err
	}

	pubKeyFunc := convertJWKS(name, publicKey)
	valConfig.TokenIssuer = name
	valConfig.PublicKey = pubKeyFunc
	return valConfig, nil
}

func convertJWKS(name string, pubKey *rsa.PublicKey) keyfunc.Keyfunc {

	jwk, _ := jwkset.NewJWKFromKey(pubKey, jwkset.JWKOptions{
		Metadata: jwkset.JWKMetadataOptions{
			ALG: "RS256",
			KID: name,
		},
	})

	store := jwkset.NewMemoryStorage()
	_ = store.KeyWrite(context.Background(), jwk)

	options := keyfunc.Options{
		Storage: store,
		Ctx:     context.Background(),
	}

	jwks, _ := keyfunc.New(options)

	return jwks

}

func (a *TokenHandler) loadIssuer(name string) error {
	pemBytes, err := os.ReadFile(a.PrivateKeyPath)
	if err != nil {
		return err
	}

	derBlock, _ := pem.Decode(pemBytes)

	privateKey, err := x509.ParsePKCS1PrivateKey(derBlock.Bytes)
	if err != nil {
		return err
	}
	a.TokenIssuer = name
	a.PrivateKey = privateKey
	a.PublicKey = convertJWKS(name, &privateKey.PublicKey)

	return nil
}

func LoadIssuer(name string) (*TokenHandler, error) {
	handler := getConfig()
	return handler, handler.loadIssuer(name)
}

/*
GenerateIssuerKeys will create a new JWT issuer private and public key set. Set keepExisting to
true to enable auto-generation on first execution.
*/
func GenerateIssuerKeys(name string, keepExisting bool) (*TokenHandler, error) {
	handler := getConfig()

	if handler.PrivateKeyExists() && keepExisting {
		// This enables docker services to auto generate on first execution.
		return handler, handler.loadIssuer(name)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Println("Unexpected crypto error generating keys: " + err.Error())
		os.Exit(-1)
	}
	privateKeyPEM := new(bytes.Buffer)
	_ = pem.Encode(privateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	publicKey := privateKey.PublicKey

	pubKeyBytes := x509.MarshalPKCS1PublicKey(&publicKey)
	pubKeyPEM := new(bytes.Buffer)
	_ = pem.Encode(pubKeyPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: pubKeyBytes,
	})

	err = os.WriteFile(handler.PrivateKeyPath, privateKeyPEM.Bytes(), 0644)
	if err != nil {
		fmt.Printf("Error writing key file: %s", err.Error())
		return nil, err
	}

	pubKeyFile := filepath.Join(handler.KeyDir, DefTknPublicKeyFile)
	err = os.WriteFile(pubKeyFile, pubKeyPEM.Bytes(), 0644)

	handler.TokenIssuer = name
	handler.PrivateKey = privateKey
	handler.PublicKey = convertJWKS(name, &publicKey)
	return handler, nil
}

func (a *TokenHandler) IssueToken(scopes []string, email string) (string, error) {
	if a.PrivateKey == nil {
		return "", errors.New("validation mode only")
	}
	exp := time.Now().AddDate(0, 6, 0)
	tokenInfo := JwtAuthToken{
		Scopes: scopes,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(exp),
			Audience:  []string{a.TokenIssuer},
			Issuer:    a.TokenIssuer,
			ID:        uuid.New().String(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, tokenInfo)
	token.Header["typ"] = "jwt"
	token.Header["kid"] = a.TokenIssuer
	return token.SignedString(a.PrivateKey)
}

// ValidateAuthorization evaluates the authorization header and checks to see if the correct scope is asserted.
// 200 OK means authorized. Forbidden returned if wrong scope, otherwise unauthorized
func (a *TokenHandler) ValidateAuthorization(r *http.Request, scopes []string) (*JwtAuthToken, int) {
	switch a.Mode {
	case ModeEnforceAnonymous:
		return nil, http.StatusOK // Anonymous mode should only be used for testing!
	case ModeEnforceBundle:
		// If the request is for a decision, and we are enforcing bundle only, return success
		if scopeMatch(scopes, []string{ScopeDecision}) {
			return nil, http.StatusOK // Decisions can proceed without authorization
		}
	default:
		// continue enforcement.
	}

	authorization := r.Header.Get("Authorization")
	if authorization == "" {
		return nil, http.StatusUnauthorized
	}

	parts := strings.Split(authorization, " ")
	if len(parts) < 2 {
		return nil, http.StatusUnauthorized
	}
	if strings.EqualFold(parts[0], "bearer") {

		tkn, err := a.ParseAuthToken(parts[1])
		if err != nil {
			log.Printf("Authorization invalid: [%s]\n", err.Error())
			return nil, http.StatusUnauthorized
		}

		if tkn.IsScopeMatch(scopes) {
			return tkn, http.StatusOK
		}
		return nil, http.StatusForbidden
	}
	log.Printf("Received invalid authorization: %s\n", parts[0])
	return nil, http.StatusUnauthorized
}

// ParseAuthToken parses and validates an authorization token. An *JwtAuthToken is only returned if the token was validated otherwise nil
func (a *TokenHandler) ParseAuthToken(tokenString string) (*JwtAuthToken, error) {
	if a.PublicKey == nil {
		return nil, errors.New("no public key provided to validate authorization token")
	}

	// In case of cut/paste error, trim extra spaces
	tokenString = strings.TrimSpace(tokenString)

	valid := true

	token, err := jwt.ParseWithClaims(tokenString, &JwtAuthToken{}, a.PublicKey.Keyfunc)
	if err != nil {
		log.Printf("Error validating token: %s", err.Error())
		valid = false
	}
	if token == nil || token.Header["typ"] != "jwt" {
		log.Printf("token is not an authorization token (JWT)")
		return nil, errors.New("token type is not an authorization token (`jwt`)")
	}

	if claims, ok := token.Claims.(*JwtAuthToken); ok && valid {
		return claims, nil
	}

	return nil, err
}

func scopeMatch(scopesAccepted []string, scopesHave []string) bool {
	for _, acceptedScope := range scopesAccepted {
		for _, scope := range scopesHave {
			if strings.EqualFold(scope, ScopeAdmin) {
				return true
			}
			if strings.EqualFold(scope, acceptedScope) {
				return true
			}

		}
	}
	return false
}

func (t *JwtAuthToken) IsScopeMatch(scopesAccepted []string) bool {
	return scopeMatch(scopesAccepted, t.Scopes)
}

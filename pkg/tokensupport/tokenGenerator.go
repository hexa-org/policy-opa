package tokensupport

import (
	"bytes"
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

	"github.com/MicahParks/keyfunc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

const (
	ScopeBundle        string = "bundle"
	ScopeDecision      string = "az"
	ScopeAdmin         string = "root"
	EnvTknKeyDirectory string = "AUTHZEN_TKN_DIRECTORY"
	EnvTknPrivKeyFile  string = "AUTHZEN_TKN_PRIVKEYFILE"
	EnvAllowAnon       string = "AUTHZEN_TKN_DISABLE"
	DefTknPrivFileName string = "issuer-priv.pem"
	TknIssuePubKeyFile string = "issuer-cert.pem"
)

type JwtAuthToken struct {
	Scopes []string `json:"roles,omitempty"`
	Email  string   `json:"email,omitempty"`
	jwt.RegisteredClaims
}

type TokenHandler struct {
	TokenIssuer       string
	PrivateKey        *rsa.PrivateKey
	PublicKey         *keyfunc.JWKS
	KeyDir            string
	PrivKeyPath       string
	DisableValidation bool
}

func getConfig(privKeyfile string) *TokenHandler {
	disableValidationString := os.Getenv(EnvAllowAnon)
	disableValidation := false
	if disableValidationString != "" && strings.EqualFold(disableValidationString, "true") {
		disableValidation = true
	}

	dirPath := os.Getenv(EnvTknKeyDirectory)
	if privKeyfile == "" {
		privKeyfile = os.Getenv(EnvTknPrivKeyFile)
		if privKeyfile == "" {
			if dirPath == "" {
				file := os.Getenv("HOME")
				dirPath = filepath.Join(file, "./.certs")
			}
			privKeyfile = filepath.Join(dirPath, DefTknPrivFileName)
		}
	}
	if dirPath == "" {
		dirPath, _ = filepath.Split(privKeyfile)
	}

	fmt.Println("Using key directory: " + dirPath)
	err := os.MkdirAll(dirPath, 0755)
	if err != nil {
		panic(fmt.Sprintf("Was unable to open or create certificate directory(%s):%s", dirPath, err))
	}

	return &TokenHandler{
		KeyDir:            dirPath,
		PrivKeyPath:       privKeyfile,
		DisableValidation: disableValidation,
	}
}

func TokenValidator(name string, publicKeyFile string) (*TokenHandler, error) {
	pemBytes, err := os.ReadFile(publicKeyFile)
	if err != nil {
		return nil, err
	}

	derBlock, _ := pem.Decode(pemBytes)
	publicKey, err := x509.ParsePKCS1PublicKey(derBlock.Bytes)
	if err != nil {
		return nil, err
	}

	pubKey := convertJWKS(name, publicKey)

	return &TokenHandler{
		TokenIssuer: name,
		PublicKey:   pubKey,
	}, nil

}

func convertJWKS(name string, pubKey *rsa.PublicKey) *keyfunc.JWKS {
	givenKey := keyfunc.NewGivenRSACustomWithOptions(pubKey, keyfunc.GivenKeyOptions{
		Algorithm: "RS256",
	})
	givenKeys := make(map[string]keyfunc.GivenKey)
	givenKeys[name] = givenKey
	return keyfunc.NewGiven(givenKeys)
}

func LoadIssuer(name string, privateKeyFile string) (*TokenHandler, error) {
	handler := getConfig(privateKeyFile)
	pemBytes, err := os.ReadFile(handler.PrivKeyPath)
	if err != nil {
		return nil, err
	}

	derBlock, _ := pem.Decode(pemBytes)

	privateKey, err := x509.ParsePKCS1PrivateKey(derBlock.Bytes)
	if err != nil {
		return nil, err
	}
	handler.TokenIssuer = name
	handler.PrivateKey = privateKey
	handler.PublicKey = convertJWKS(name, &privateKey.PublicKey)
	return handler, nil
}

func GenerateIssuer(name string, privateKeyFile string) (*TokenHandler, error) {
	handler := getConfig(privateKeyFile)

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

	err = os.WriteFile(handler.PrivKeyPath, privateKeyPEM.Bytes(), 0644)
	if err != nil {
		fmt.Printf("Error writing key file: %s", err.Error())
		return nil, err
	}

	pubKeyFile := filepath.Join(handler.KeyDir, TknIssuePubKeyFile)
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
	if a.DisableValidation {
		return nil, http.StatusOK // Anonymous mode should only be used for testing!
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
		return nil, errors.New("ERROR: No public key provided to validate authorization token.")
	}

	// In case of cut/paste error, trim extra spaces
	tokenString = strings.TrimSpace(tokenString)

	valid := true

	token, err := jwt.ParseWithClaims(tokenString, &JwtAuthToken{}, a.PublicKey.Keyfunc)
	if err != nil {
		log.Printf("Error validating token: %s", err.Error())
		valid = false
	}
	if token.Header["typ"] != "jwt" {
		log.Printf("token is not an authorization token (JWT)")
		return nil, errors.New("token type is not an authorization token (`jwt`)")
	}

	if claims, ok := token.Claims.(*JwtAuthToken); ok && valid {
		return claims, nil
	}

	return nil, err
}

func (t *JwtAuthToken) IsScopeMatch(scopesAccepted []string) bool {

	for _, acceptedScope := range scopesAccepted {
		for _, scope := range t.Scopes {
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

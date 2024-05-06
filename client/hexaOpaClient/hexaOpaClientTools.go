package hexaOpaClient

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ReqParams provides information about the request made to an application requesting authorization
type ReqParams struct {
	ClientIp    string              `json:"ip,omitempty"`       // ClientIp is the network address of the requestor
	Protocol    string              `json:"protocol,omitempty"` // Protocol is typically HTTP
	Host        string              `json:"host,omitempty"`     // Host is the domain used in the request
	Method      string              `json:"method,omitempty"`   // Method is typically the HTTP method
	Path        string              `json:"path"`               // Path is the request path of the URL
	QueryParam  map[string][]string `json:"param"`              // QueryParam are the parsed query parameters (ie. after ?)
	Header      map[string][]string `json:"header,omitempty"`   // Header includes all the request headers
	Time        time.Time           `json:"time"`               // Time of the received request
	ActionUris  []string            `json:"actionUris"`         // ActionUris are the Action Uris being requested
	ResourceIds []string            `json:"resourceIds"`        // ResourceIds are the resources the client represents
}

// SubjectInfo describes information known about an authenticated subject
type SubjectInfo struct {
	Roles     []string               `json:"roles,omitempty"`   // Roles are the roles associated with the subject (e.g. asserted in JWT token)
	Claims    map[string]interface{} `json:"claims,omitempty"`  // Claims received about the subject (e.g. from a JWT token or directory)
	Expires   time.Time              `json:"expires,omitempty"` // Expires represents the expiry time of the JWT
	Type      string                 `json:"type,omitempty"`    // Type is the type of authentication: either anonymous|basic|jwt|...
	Sub       string                 `json:"sub,omitempty"`     // Sub is the subject. For JWT the 'sub' claim, for other sources just the authenticated username
	Issuer    string                 `json:"iss,omitempty"`     // Issuer is the issuer of the authentication token
	Audience  []string               `json:"aud,omitempty"`     // Audience the aud value ot a JWT
	IssuedAt  time.Time              `json:"iat,omitempty"`     // IssuedAt is the time the JWT presented was issued
	NotBefore time.Time              `json:"nbf,omitempty"`     // NotBefore For post-dated JWTs, the time after which a token is valid
}

// OpaInfo is the input information structure to be provided to OPA for processing
type OpaInfo struct {
	Req     *ReqParams   `json:"req"`     // Req describes information about the request
	Subject *SubjectInfo `json:"subject"` // Subject provides information known about an authenticated subject
}

// OpaInput used to construct a JSON marshalled "input" structure to be fed to an OPA Query endpoint. This
// structure builds a standardize set of input parameters for use with Hexa Policy
type OpaInput struct {
	Input OpaInfo `json:"input"`
}

type HexaClaims struct {
	*jwt.RegisteredClaims
	Roles string `json:"roles"`
}

func PrepareSubjectInfo(r *http.Request) (*SubjectInfo, error) {

	verifyKey := os.Getenv("OPATOOLS_JWTVERIFYKEY")

	hexaClaims := HexaClaims{}

	info := SubjectInfo{}
	authz := r.Header.Get("Authorization")
	if authz != "" {
		parts := strings.Split(authz, " ")
		if strings.EqualFold(parts[0], "bearer") {
			bearer := parts[1]

			// At this point, this assumes the bearer token is a JWT (not always true!)

			if verifyKey == "" {
				log.Println("Verify key undefined (OPATOOLS_JWTVERIFYKEY)")
				return nil, errors.New("Token verify misconfigured")
			} else {
				// Try to verify as signed JWT
				_, err := jwt.ParseWithClaims(bearer, &hexaClaims, func(token *jwt.Token) (interface{}, error) {
					return []byte(verifyKey), nil
				})

				if err != nil {
					log.Println("Token parsing/validation failed: " + err.Error())
					info.MapJwtClaims(hexaClaims, fmt.Sprintf("Invalid (%s)", err.Error()))
					return &info, err
				}
			}

			info.MapJwtClaims(hexaClaims, "jwt")

		} else if strings.EqualFold(parts[0], "basic") {
			username, _, ok := r.BasicAuth()
			if ok {
				info.Type = "basic"
				info.Sub = username
			}
		} else {
			// This is done for diagnostic purposes
			// Sanitize the message
			msg := "Unsupported authorization type:" +
				strings.Replace(strings.Replace(parts[0], "\n", "", -1), "\r", "", -1)
			log.Println(msg)
		}
	} else {
		info.Type = "Anonymous"
	}

	return &info, nil
}

func (info *SubjectInfo) MapJwtClaims(claims HexaClaims, tknType string) {
	info.Type = tknType
	info.Sub = claims.Subject
	info.Audience = claims.Audience
	nbf := claims.NotBefore
	if nbf != nil {
		info.NotBefore = nbf.Time
	}
	iat := claims.IssuedAt
	if iat != nil {
		info.IssuedAt = iat.Time
	}
	info.Issuer = claims.Issuer
	eat := claims.ExpiresAt
	if eat != nil {
		info.Expires = eat.Time
	}

	roleStr := claims.Roles
	info.Roles = strings.Split(strings.ToLower(roleStr), " ")
}

func PrepareReqParams(r *http.Request, actionUris []string, resourceUris []string) *ReqParams {
	var resp ReqParams
	resp.ClientIp = r.RemoteAddr
	resp.Time = time.Now()

	resp.Path = r.URL.Path
	resp.QueryParam = r.URL.Query()
	resp.Protocol = r.Proto
	resp.Host = r.Host
	resp.Method = r.Method
	resp.Header = r.Header
	resp.ActionUris = actionUris
	resp.ResourceIds = resourceUris
	return &resp
}

// PrepareInput takes request information and prepares an "input" structure for use with HexaPolicy and OPA.
func PrepareInput(r *http.Request, actionUris []string, resourceUris []string) *OpaInfo {
	var inputData OpaInfo
	inputData.Req = PrepareReqParams(r, actionUris, resourceUris)
	inputData.Subject, _ = PrepareSubjectInfo(r)

	return &inputData
}

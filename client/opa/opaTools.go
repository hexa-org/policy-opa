package opaTools

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type ReqParams struct {
	ClientIp   string              `json:"ip"`
	Protocol   string              `json:"protocol"`
	Method     string              `json:"method"`
	Path       string              `json:"path"`
	QueryParam map[string][]string `json:"param"`
	Header     map[string][]string `json:"header,omitempty"`
	Time       time.Time           `json:"time"` //Unix time
}

type SubjectInfo struct {
	ProvId    string                 `json:"provId,omitempty"`
	Roles     []string               `json:"roles,omitempty"`
	Claims    map[string]interface{} `json:"claims,omitempty"`
	Expires   int64                  `json:"expires,omitempty"`
	Type      string                 `json:"type,omitempty"`
	Sub       string                 `json:"sub,omitempty"`
	Issuer    string                 `json:"iss,omitempty"`
	Audience  string                 `json:"aud,omitempty"`
	IssuedAt  int64                  `json:"iat,omitempty"` //Unix time
	NotBefore int64                  `json:"nbf,omitempty"`
}

type OpaInfo struct {
	Req     *ReqParams   `json:"req"`
	Subject *SubjectInfo `json:"subject"`
}

// OpaInput used to construct a JSON marshallable "input" structure to be fed to an OPA Query endpoint. This
// structure builds a standardize set of input parameters for use with Hexa Policy
type OpaInput struct {
	Input OpaInfo `json:"input"`
}

type HexaClaims struct {
	*jwt.StandardClaims
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

			info.MapJwtClaims(hexaClaims, "Bearer+JWT")

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
	info.NotBefore = claims.NotBefore
	info.IssuedAt = claims.IssuedAt
	info.Issuer = claims.Issuer
	info.Expires = claims.ExpiresAt

	roleStr := claims.Roles
	info.Roles = strings.Split(strings.ToLower(roleStr), " ")
}

func PrepareReqParams(r *http.Request) *ReqParams {
	var resp ReqParams
	resp.ClientIp = r.RemoteAddr
	resp.Time = time.Now()

	resp.Path = r.URL.Path
	resp.QueryParam = r.URL.Query()
	resp.Protocol = r.Proto
	resp.Method = r.Method
	resp.Header = r.Header

	return &resp
}

// PrepareInput takes request information and prepares an "input" structure for use with HexaPolicy and OPA.
func PrepareInput(r *http.Request) *OpaInfo {
	var inputData OpaInfo
	inputData.Req = PrepareReqParams(r)
	inputData.Subject, _ = PrepareSubjectInfo(r)

	return &inputData
}

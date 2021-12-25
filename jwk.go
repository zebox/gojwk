// This package implement work with asymmetric encryption for toke issue and validate.
// A publish public key (using JWKS) to validate the JWT tokens they issue.
// For more information see https://datatracker.ietf.org/doc/html/rfc7517

package jwk

import (
	"encoding/json"
)

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (j *JWK) ToString() string {
	jwkBuffer, err := json.Marshal(j)
	if err != nil {
		return ""
	}
	return string(jwkBuffer)
}

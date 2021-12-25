// This package implement work with asymmetric encryption for toke issue and validate.
// A publish public key (using JWKS) to validate the JWT tokens they issue.
// For more information see https://datatracker.ietf.org/doc/html/rfc7517

package jwk

type JWK struct {
	KTY string `json:"kty"`
	KID string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

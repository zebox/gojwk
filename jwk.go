// This package implement work with asymmetric encryption for toke issue and validate.
// A publish public key (using JWKS) to validate the JWT tokens they issue.
// For more information see https://datatracker.ietf.org/doc/html/rfc7517

package gojwk

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
	"math/big"
)

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS is a list of JWK keys
type JWKS []jwk

// NewJWK is main constructor for create JWK from raw public key, accept pointer to *rsa.PublicKey
func NewJWK(publicKey *rsa.PublicKey) (JWK jwk, err error) {
	keys, err := NewKeys()
	if err != nil {
		return JWK, err
	}
	keys.publicKey = publicKey
	JWK, err = keys.JWK()
	if err != nil {
		return JWK, errors.Wrap(err, "failed get JWK from public key")
	}
	return JWK, nil
}

// PublicKey return raw public key from JWK
func (j *jwk) PublicKey() (*rsa.PublicKey, error) {
	return j.parsePublicKey()
}

// parsePublicKey from jwk to RSA public key
func (j *jwk) parsePublicKey() (*rsa.PublicKey, error) {

	bufferN, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(j.N) // decode modulus
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode public key modulus (n)")
	}

	bufferE, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(j.E) // decode exponent
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode public key exponent (e)")
	}

	// create rsa public key from jwk data
	publicKey := &rsa.PublicKey{
		N: big.NewInt(0).SetBytes(bufferN),
		E: int(big.NewInt(0).SetBytes(bufferE).Int64()),
	}
	return publicKey, nil
}

// ToString convert JWK object to JSON string
func (j *jwk) ToString() string {
	jwkBuffer, err := json.Marshal(j)
	if err != nil {
		return ""
	}
	return string(jwkBuffer)
}

// KeyFunc use for JWT sign verify with specific public key
func (j *jwk) KeyFunc(token *jwt.Token) (interface{}, error) {

	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("get JWT kid header not found")
	}
	if j.Kid != keyID {
		return nil, errors.Errorf("hasn't jwk with kid [%s] for check", keyID)
	}
	publicKey, err := j.parsePublicKey()
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}

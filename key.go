package jwk

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

// Key using for create and validate token signature
type key struct {
	opts       options // main options for key pair create
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
	jwk        JWK
}

// GenerateKeys create new key pair
func (k *key) GenerateKeys() (err error) {
	reader := rand.Reader

	k.opts.bitSize = 2048 // TODO: REMOVE THIS

	if k.privateKey, err = rsa.GenerateKey(reader, k.opts.bitSize); err != nil {
		return errors.Wrapf(err, "failed to generate new key pair")
	}

	k.publicKey = &k.privateKey.PublicKey

	// check and try generated a key pair
	if k.opts.storage != nil {
		if err = k.opts.storage.Save(k.privateKey); err != nil {
			return err
		}
	}

	return nil
}

// Loader will load a key pair from storage if one defined
func (k *key) Load() (err error) {
	if k.opts.storage == nil {
		return errors.New("private key loader undefined")
	}

	if k.privateKey, err = k.opts.storage.Load(); err != nil {
		return errors.Wrapf(err, "failed to load private key")
	}
	k.publicKey = &k.privateKey.PublicKey

	return nil
}

// JWK create json key value
func (k *key) JWK() (JWK, error) {

	if k.publicKey == nil {
		return JWK{}, errors.New("public key should be defined")
	}

	// convert to modulus
	n := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(k.publicKey.N.Bytes())

	// convert to exponent
	eBuff := make([]byte, 4)
	binary.LittleEndian.PutUint32(eBuff, uint32(k.publicKey.E))
	e := base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(eBuff)

	// create kid from public key modulus
	h := sha1.New()
	h.Write([]byte(n))
	kidBytes := h.Sum(nil)
	kid := base64.StdEncoding.EncodeToString(kidBytes)

	k.jwk = JWK{Alg: "RS256", Kty: "RSA", Use: "sig", Kid: kid[:4], N: n, E: e[:4]}

	return k.jwk, nil
}

// Private return private key for sign jwt
func (k *key) Private() *rsa.PrivateKey {
	return k.privateKey
}

// KeyFunc use for JWT sign verify with specific public key
func (k *key) KeyFunc(token *jwt.Token) (interface{}, error) {

	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("get JWT kid header not found")
	}
	if k.jwk.Kid != keyID {
		return nil, errors.Errorf("hasn't JWK with kid [%s] for check", keyID)
	}
	return k.publicKey, nil
}

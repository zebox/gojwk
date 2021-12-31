package gojwk

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

type keyStorage interface {
	Load() (*rsa.PrivateKey, error) // implement loader for a private RSA Key
	Save(key *rsa.PrivateKey) error // implement storage a Key pair
}

// Key using for create and validate token signature
type Key struct {

	// Key identification for detect and use Key
	KeyID string

	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey

	jwk JWK

	// Key bit size value, set in Options, default - 2048
	bitSize int

	// define saver and loader Key pair function
	// storage required has path to public and private Key file which will load from disk
	storage keyStorage
}

// NewKeys create new Key pair
func NewKeys(options ...Options) (keysPair *Key, err error) {

	// define Key and default values
	keysPair = &Key{
		bitSize: 2048,
	}

	// parse keysPair options
	for _, opt := range options {
		opt(keysPair)
	}

	// force encrypt with Key 128-bits or more
	if keysPair.bitSize < 128 {
		return nil, errors.New("bit size invalid and should has length 128 or more")
	}
	// check external keysPair defined and try load them
	if keysPair.storage != nil {
		if keysPair.privateKey, err = keysPair.storage.Load(); err != nil {
			return keysPair, errors.Wrapf(err, "failed to load private Key")
		}
		keysPair.publicKey = &keysPair.privateKey.PublicKey
	}

	return keysPair, nil
}

// GenerateKeys new keys pair and save if external storage field defined
func (k *Key) GenerateKeys() (err error) {
	reader := rand.Reader

	if k.privateKey, err = rsa.GenerateKey(reader, k.bitSize); err != nil {
		return errors.Wrapf(err, "failed to generate new Key pair")
	}

	k.publicKey = &k.privateKey.PublicKey
	k.KeyID = k.kid()
	// check for external Key storage defined and try save new Key
	if k.storage != nil {
		if err = k.storage.Save(k.privateKey); err != nil {
			return err
		}
	}

	return nil
}

// JWK create JSON Web Key from public Key
func (k *Key) JWK() (jwk JWK, err error) {
	return NewJWK(k.publicKey)
}

// Private return private Key for sign jwt
func (k *Key) Private() *rsa.PrivateKey {
	return k.privateKey
}

// KeyFunc use for JWT sign verify with specific public Key
func (k *Key) KeyFunc(token *jwt.Token) (interface{}, error) {

	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("get JWT kid header not found")
	}
	if k.jwk.Kid != keyID {
		return nil, errors.Errorf("hasn't JWK with kid [%s] for check", keyID)
	}
	return k.publicKey, nil
}

// kid return Key ID of public key for map with JWK
func (k *Key) kid() string {
	n := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(k.publicKey.N.Bytes())

	// create kid from public Key modulus
	h := sha1.New()
	h.Write([]byte(n))
	kidBytes := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(kidBytes)[:4]

}

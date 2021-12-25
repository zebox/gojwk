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

type keyStorage interface {
	Load() (*rsa.PrivateKey, error) // implement loader for a private RSA key
	Save(key *rsa.PrivateKey) error // implement storage a key pair
}

// Key using for create and validate token signature
type key struct {
	opts Options // main Options for key pair create

	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey

	jwk jwk

	// key bit size value, set in Options, default - 2048
	bitSize int

	// set path to part of public key file if need load it from disk
	publicKeyPath string

	// set path to private key file if need load it from disk
	privateKeyPath string

	// define saver and loader key pair function
	storage keyStorage
}

// NewKeys create new key pair
func NewKeys(options ...Options) (keysPair *key, err error) {

	// define key and default values
	keysPair = &key{
		bitSize: 2048,
	}

	// parse keysPair options
	for _, opt := range options {
		opt(keysPair)
	}

	// force encrypt with key 128-bits or more
	if keysPair.bitSize < 128 {
		return nil, errors.New("bit size invalid and should has length 128 or more")
	}
	// check external keysPair defined and try load them
	if keysPair.storage != nil {
		if keysPair.privateKey, err = keysPair.storage.Load(); err != nil {
			return nil, errors.Wrapf(err, "failed to load private key")
		}
		keysPair.publicKey = &keysPair.privateKey.PublicKey
	}

	return keysPair, nil
}

// GenerateKeys new keys pair and save if external storage field defined
func (k *key) GenerateKeys() (err error) {
	reader := rand.Reader

	if k.privateKey, err = rsa.GenerateKey(reader, k.bitSize); err != nil {
		return errors.Wrapf(err, "failed to generate new key pair")
	}

	k.publicKey = &k.privateKey.PublicKey

	// check for external key storage defined and try save new key
	if k.storage != nil {
		if err = k.storage.Save(k.privateKey); err != nil {
			return err
		}
	}

	return nil
}

// jwk create json key value
func (k *key) JWK() (jwk, error) {

	if k.publicKey == nil {
		return jwk{}, errors.New("public key should be defined")
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

	k.jwk = jwk{Alg: "RS256", Kty: "RSA", Use: "sig", Kid: kid[:4], N: n, E: e[:4]}

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
		return nil, errors.Errorf("hasn't jwk with kid [%s] for check", keyID)
	}
	return k.publicKey, nil
}

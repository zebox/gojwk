package gojwk

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"github.com/golang-jwt/jwt"
	"github.com/pkg/errors"
)

type keyStorage interface {
	Load() (*rsa.PrivateKey, error)                // implement loader for a private RSA Key pairs from storage provider
	Save(key *rsa.PrivateKey, certCA []byte) error // implement save a Key pairs and root certificates bundle to storage provider
}

// Key using for create and validate token signature
type Key struct {

	// Key identification for detect and use Key
	KeyID string

	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey

	//  Certificate and  Certificate Authority
	certCARoot []byte

	// json web key need for using in keyFunc for JWT sign check with Key instance
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

	return keysPair, nil
}

// Generate new keys pair and save if external storage field defined
func (k *Key) Generate() (err error) {
	reader := rand.Reader

	if k.privateKey, err = rsa.GenerateKey(reader, k.bitSize); err != nil {
		return errors.Wrapf(err, "failed to generate new Key pair")
	}

	k.publicKey = &k.privateKey.PublicKey
	k.KeyID = k.kid()

	return nil
}

// Save keys pair to provider storage if it defined
func (k *Key) Save() error {
	// check for external Key storage defined and try save new Key
	if k.storage != nil {
		return k.storage.Save(k.privateKey, k.certCARoot)
	}
	return errors.New("storage provider undefined")
}

// Load trying loading private and public key pair from storage provider
func (k *Key) Load() (err error) {

	if k.storage == nil {
		return errors.New("failed to load key pair, storage provider undefined")
	}

	if k.privateKey, err = k.storage.Load(); err != nil {
		return errors.Wrap(err, "failed to load private key")
	}
	// assign public key from private
	k.publicKey = &k.privateKey.PublicKey
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

func (k *Key) CreateCAROOT(ca *x509.Certificate) error {
	if k.privateKey == nil {
		return errors.New("private key shouldn't be nil when CA create")
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, k.publicKey, k.privateKey)
	if err != nil {
		return errors.Wrap(err, "failed to create certificate")
	}

	caPEM := new(bytes.Buffer)
	err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	if err != nil {
		return errors.Wrap(err, "failed to encode certificate CA to PEM bytes")
	}

	caPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(k.privateKey),
	})
	if err != nil {
		return errors.Wrap(err, "failed to encode private key certificate to PEM bytes")
	}

	// assign certificates bytes to CA ROOT field
	k.certCARoot = caPEM.Bytes()

	return nil
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

package jwk

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"github.com/pkg/errors"
)

// Key using for create and validate token signature
type key struct {
	opts       options // main options for key pair create
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
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
func (k *key) JWK() (string, error) {

	if k.publicKey == nil {
		return "", errors.New("public key should be defined")
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

	jwk := JWK{Alg: "RS256", Kty: "RSA", Use: "sig", Kid: kid[:4], N: n, E: e[:4]}

	return jwk.ToString(), nil
}

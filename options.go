package jwk

import "crypto/rsa"

type keyStorage interface {
	Load() (*rsa.PrivateKey, error) // implement loader for a private RSA key
	Save(key *rsa.PrivateKey) error // implement storage a key pair
}

// Main options for JWKS
type options struct {

	// key bit size value, set in options, default - 2048
	bitSize int

	// set path to part of public key file if need load it from disk
	publicKeyPath string

	// set path to private key file if need load it from disk
	privateKeyPath string

	// define saver and loader key pair function
	storage keyStorage
}

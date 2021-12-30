// file storage provider allow save and load RSA private key file to/from file
// It provider implemented keyStorage interface for using with key package
package storage

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/pkg/errors"
	"io"
	"log"
	"os"
)

type FileStorage struct {
	publicKeyPath  string // path to public key file
	privateKeyPath string // path to private key file
}

// NewFileStorage accept path to private and public key files
// File path doesn't check in constructor because files can be generate by 'key' package in future
func NewFileStorage(privateKeyPath, publicKeyPath string) FileStorage {
	return FileStorage{
		privateKeyPath: privateKeyPath,
		publicKeyPath:  publicKeyPath,
	}
}

// Save will saving private and public Key to file
// A public key need save separately for using in isolated web-service as JWK
func (fs FileStorage) Save(key *rsa.PrivateKey) error {
	privateKeyFile, err := os.Create(fs.privateKeyPath)
	if err != nil {
		return errors.Wrap(err, "failed to save private key")
	}

	// close file on exit and check for it for error returned
	defer func() {
		if err := privateKeyFile.Close(); err != nil {
			log.Printf("failed to close private key file %v", err)
		}
	}()

	// processing with public key
	publicKeyFile, err := os.Create(fs.publicKeyPath)
	if err != nil {
		return errors.Wrap(err, "failed to save private key")
	}

	defer func() {
		if err := publicKeyFile.Close(); err != nil {
			log.Printf("failed to close public key file %v", err)
		}
	}()
	b, err := getBytesPEM(key)
	if err != nil {
		return err
	}

	if _, err = privateKeyFile.Write(b); err != nil {
		return errors.Wrap(err, "failed to save private key to file")
	}

	b, err = getBytesPEM(key.Public())
	if err != nil {
		return err
	}

	if _, err = publicKeyFile.Write(b); err != nil {
		return errors.Wrap(err, "failed to save public key to file")
	}

	return nil
}

// Load will loading privateKey from PEM-file
func (fs FileStorage) Load() (*rsa.PrivateKey, error) {
	// path to private key file is required and throw error if path doesn't set
	if fs.privateKeyPath == "" {
		return nil, errors.New("path to private key must be set")
	}

	privateKeyFile, err := os.Open(fs.privateKeyPath)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to load private key from file %s", fs.privateKeyPath)
	}

	defer func() {
		if err = privateKeyFile.Close(); err != nil {
			log.Printf("failed to close private key file, err: %v", err)
		}
	}()

	privateKeyData, err := io.ReadAll(privateKeyFile)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read data from private key file")
	}

	// before create private key need read PEM blocks from key data
	pemBlock, _ := pem.Decode(privateKeyData)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read pem block from private key data")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create private key from file data")
	}
	return privateKey.(*rsa.PrivateKey), nil
}

func getBytesPEM(key interface{}) ([]byte, error) {
	switch key.(type) {
	case *rsa.PrivateKey:
		keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, errors.New("failed to marshal private key to bytes")
		}
		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: keyBytes,
			},
		), nil
	case *rsa.PublicKey:
		keyBytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return nil, errors.Wrap(err, "failed parse public key to PEM bytes encode")
		}
		return pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: keyBytes,
			},
		), nil
	}
	return nil, errors.New("failed key file type for bytes encode")
}

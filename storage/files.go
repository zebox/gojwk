package storage

import (
	"crypto/rsa"
	"github.com/pkg/errors"
	"log"
	"os"
)

type FileStorage struct {
	publicKeyPath  string // path to public key file
	privateKeyPath string // path to private key file
}

// NewFileStorage accept path to private and public key files
// File path doesn't check in constructor because files can be generate by 'key' package in future
func NewFileStorage(private, public string) FileStorage {
	return FileStorage{
		privateKeyPath: private,
		publicKeyPath:  public,
	}
}

func (fs *FileStorage) Save(key *rsa.PrivateKey) error {
	file, err := os.Create(fs.privateKeyPath)
	if err != nil {
		return errors.Wrap(err, "failed to save private key")
	}

	// close fo on exit and check for its returned error
	defer func() {
		if err := file.Close(); err != nil {
			log.Printf("failed to close file %v", err)
		}
	}()
	return nil
}

package storage

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

const (
	testPrivateKeyPath = "./test_private.key"
	testPublicKeyPath  = "./test_public.key"
)

func TestNewFileStorage(t *testing.T) {

	testFS := FileStorage{
		privateKeyPath: testPrivateKeyPath,
		publicKeyPath:  testPublicKeyPath,
	}
	fs := NewFileStorage(testPrivateKeyPath, testPublicKeyPath)
	assert.Equal(t, testFS, fs)
}

func TestFileStorage_Save(t *testing.T) {
	reader := rand.Reader

	privateKey, err := rsa.GenerateKey(reader, 1024)
	require.NoError(t, err)
	require.NotNil(t, privateKey)

	fs := NewFileStorage(testPrivateKeyPath, testPublicKeyPath)
	err = fs.Save(privateKey)
	require.NoError(t, err)

	defer deleteTestFile(t)

	_, err = os.Stat(testPrivateKeyPath)
	assert.NoError(t, err)

	_, err = os.Stat(testPublicKeyPath)
	assert.NoError(t, err)

}

func TestFileStorage_Load(t *testing.T) {
	reader := rand.Reader

	privateKey, err := rsa.GenerateKey(reader, 1024)
	require.NoError(t, err)
	require.NotNil(t, privateKey)

	fs := NewFileStorage(testPrivateKeyPath, testPublicKeyPath)
	err = fs.Save(privateKey)
	require.NoError(t, err)
	defer deleteTestFile(t)

	loadedPrivateKey, err := fs.Load()
	require.NoError(t, err)
	assert.NotNil(t, loadedPrivateKey)

	assert.NotNil(t, loadedPrivateKey.Public())
}

func deleteTestFile(t *testing.T) {
	err := os.Remove(testPrivateKeyPath)
	assert.NoError(t, err)

	err = os.Remove(testPublicKeyPath)
	assert.NoError(t, err)
}

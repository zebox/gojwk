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
	testRootPath   = "./"
	testPrivateKey = "test_private.key"
	testPublicKey  = "test_public.key"
)

func TestNewFileStorage(t *testing.T) {

	testFS := FileStorage{
		rootPath:   testRootPath,
		privateKey: testPrivateKey,
		publicKey:  testPublicKey,
	}
	fs := NewFileStorage(testRootPath, testPrivateKey, testPublicKey)
	assert.Equal(t, testFS, fs)
}

func TestFileStorage_Save(t *testing.T) {
	reader := rand.Reader

	privateKey, err := rsa.GenerateKey(reader, 1024)
	require.NoError(t, err)
	require.NotNil(t, privateKey)

	fs := NewFileStorage(testRootPath, testPrivateKey, testPublicKey)
	err = fs.Save(privateKey, nil)
	require.NoError(t, err)

	defer deleteTestFile(t)

	_, err = os.Stat(testPrivateKey)
	assert.NoError(t, err)

	_, err = os.Stat(testPublicKey)
	assert.NoError(t, err)

}

func TestFileStorage_Load(t *testing.T) {
	reader := rand.Reader

	privateKey, err := rsa.GenerateKey(reader, 1024)
	require.NoError(t, err)
	require.NotNil(t, privateKey)

	fs := NewFileStorage(testRootPath, testPrivateKey, testPublicKey)
	err = fs.Save(privateKey, nil)
	require.NoError(t, err)
	defer deleteTestFile(t)

	loadedPrivateKey, err := fs.Load()
	require.NoError(t, err)
	assert.NotNil(t, loadedPrivateKey)

	assert.NotNil(t, loadedPrivateKey.Public())
}

func deleteTestFile(t *testing.T) {
	err := os.Remove(testRootPath + testPrivateKey)
	assert.NoError(t, err)

	err = os.Remove(testRootPath + testPublicKey)
	assert.NoError(t, err)
}

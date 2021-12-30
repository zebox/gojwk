package gojwk

import (
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zebox/gojwk/storage"
	"os"
	"testing"
	"time"
)

const (
	testPrivateKeyPath = "./test_private.key"
	testPublicKeyPath  = "./test_public.key"
)

func TestNewKeys(t *testing.T) {
	k, err := NewKeys()
	require.NoError(t, err)
	require.NotNil(t, k)
}

func TestNewKeys_withCustomBitSize(t *testing.T) {
	k, err := NewKeys(BitSize(128))
	require.NoError(t, err)
	require.NotNil(t, k)

	err = k.GenerateKeys()
	require.NoError(t, err)
	assert.NotNil(t, k.privateKey)

	k, err = NewKeys(BitSize(127))
	require.Error(t, err)
	assert.NotNil(t, k)
}

func TestNewKeys_withStorage(t *testing.T) {

	fs := storage.NewFileStorage(testPrivateKeyPath, testPublicKeyPath)
	keys, err := NewKeys(Storage(fs))
	require.Error(t, err)
	assert.NotNil(t, keys)

	err = keys.GenerateKeys()
	require.NoError(t, err)

	defer deleteTestFile(t)

	_, err = os.Stat(testPrivateKeyPath)
	assert.NoError(t, err)

	_, err = os.Stat(testPublicKeyPath)
	assert.NoError(t, err)

	// testing loading key with New constructor
	keys, err = NewKeys(Storage(fs))
	assert.NoError(t, err)
	assert.NotNil(t, keys)

}

func TestKey_GenerateKeys(t *testing.T) {

	k, err := NewKeys()
	require.NoError(t, err)
	require.NotNil(t, k)

	err = k.GenerateKeys()
	require.NoError(t, err)

	assert.NotNil(t, k.publicKey)
	assert.NotNil(t, k.privateKey)
}

func TestKey_JWK(t *testing.T) {

	k, err := NewKeys()
	require.NoError(t, err)
	require.NotNil(t, k)

	err = k.GenerateKeys()
	require.NoError(t, err)
	assert.NotNil(t, k.publicKey)
	assert.NotNil(t, k.privateKey)

	jwk, err := k.JWK()
	t.Log(jwk)

	assert.NoError(t, err)
	assert.NotEmpty(t, jwk)
}

func TestKey_signJWT(t *testing.T) {
	claims := &jwt.MapClaims{
		"iss":   "http://go.localhost.test",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Second * 30).Unix(),
		"aud":   "zebox/gojwk",
		"sub":   "user_id",
		"email": "test@example.go",
	}

	k, err := NewKeys()
	require.NoError(t, err)

	err = k.GenerateKeys()
	require.NoError(t, err)
	assert.NotNil(t, k.publicKey)
	assert.NotNil(t, k.privateKey)

	tkn := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	jwk, err := k.JWK()
	t.Log(jwk.ToString())
	assert.NoError(t, err)
	assert.NotEmpty(t, jwk)

	tkn.Header["alg"] = jwk.Alg
	tkn.Header["kid"] = jwk.Kid

	tokenString, err := tkn.SignedString(k.Private())
	require.NoError(t, err)
	assert.NotEmpty(t, tokenString)
	t.Log(tokenString)

	checkClaims := &jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, checkClaims, jwk.KeyFunc)

	assert.NoError(t, err)
	assert.NotNil(t, token)
}

func deleteTestFile(t *testing.T) {
	err := os.Remove(testPrivateKeyPath)
	assert.NoError(t, err)

	err = os.Remove(testPublicKeyPath)
	assert.NoError(t, err)
}

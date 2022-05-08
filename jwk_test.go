package gojwk

import (
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestNewJWK(t *testing.T) {
	k, err := NewKeys()
	require.NoError(t, err)
	require.NotNil(t, k)

	err = k.Generate()
	require.NoError(t, err)
	kJWK, err := k.JWK()
	assert.NoError(t, err)

	testJWK, err := NewJWK(k.publicKey)
	require.NoError(t, err)
	assert.Equal(t, kJWK, testJWK)

	_, err = NewJWK(nil)
	assert.Error(t, err)

}

func TestJwk_PublicKey(t *testing.T) {
	k, err := NewKeys()
	require.NoError(t, err)
	require.NotNil(t, k)

	err = k.Generate()
	require.NoError(t, err)
	kJWK, err := k.JWK()
	assert.NoError(t, err)

	publicKey, err := kJWK.PublicKey()
	assert.NoError(t, err)
	assert.Equal(t, k.publicKey, publicKey)

}

func TestJwk_ToString(t *testing.T) {
	k, err := NewKeys()
	require.NoError(t, err)
	require.NotNil(t, k)

	err = k.Generate()
	require.NoError(t, err)
	kJWK, err := k.JWK()
	assert.NoError(t, err)
	strJWK := kJWK.ToString()
	t.Logf(strJWK)
	assert.Greater(t, len(strJWK), 0)
}

func TestJWKS_ToString(t *testing.T) {
	k1, err := NewKeys()
	require.NoError(t, err)
	require.NotNil(t, k1)
	err = k1.Generate()
	require.NoError(t, err)

	k2, err := NewKeys()
	require.NoError(t, err)
	require.NotNil(t, k2)
	err = k2.Generate()
	require.NoError(t, err)

	k3, err := NewKeys()
	require.NoError(t, err)
	require.NotNil(t, k3)
	err = k3.Generate()
	require.NoError(t, err)

	jwk1, err := k1.JWK()
	assert.NoError(t, err)
	jwk2, err := k1.JWK()
	assert.NoError(t, err)
	jwk3, err := k1.JWK()
	assert.NoError(t, err)

	jwks := JWKS{}
	jwks = append(jwks, jwk1, jwk2, jwk3)
	assert.Equal(t, len(jwks), 3)

	strJWKS := jwks.ToString()
	assert.Greater(t, len(strJWKS), 0)
	t.Logf(strJWKS)

}

func TestJWK_KeyFunc(t *testing.T) {
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

	err = k.Generate()
	require.NoError(t, err)
	assert.NotNil(t, k.publicKey)
	assert.NotNil(t, k.privateKey)

	tkn := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	jwk, err := k.JWK()
	t.Log(jwk.ToString())
	assert.NoError(t, err)
	assert.NotEmpty(t, jwk)
	tkn.Header["alg"] = jwk.Alg

	pubKey, errFunc := jwk.KeyFunc(tkn)
	assert.Error(t, errFunc)
	assert.Nil(t, pubKey)

	tkn.Header["kid"] = "fake_kid"

	pubKey, errFunc = jwk.KeyFunc(tkn)
	assert.Error(t, errFunc)
	assert.Nil(t, pubKey)

	tkn.Header["kid"] = jwk.Kid
	pubKey, errFunc = jwk.KeyFunc(tkn)
	assert.NoError(t, errFunc)
	assert.NotNil(t, pubKey)

}

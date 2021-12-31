package gojwk

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
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

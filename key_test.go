package jwk

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestKey_GenerateKeys(t *testing.T) {
	k := key{}
	err := k.GenerateKeys()
	require.NoError(t, err)

	assert.NotNil(t,k.publicKey)
	assert.NotNil(t,k.privateKey)
}

func TestKey_JWK(t *testing.T) {
	k := key{}
	err := k.GenerateKeys()
	require.NoError(t, err)

	assert.NotNil(t,k.publicKey)
	assert.NotNil(t,k.privateKey)

	jwk,err:=k.JWK()
	t.Log(jwk)

	assert.NoError(t,err)
	assert.NotEmpty(t,jwk)


}
package gojwk

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zebox/gojwk/storage"
	"math/big"
	"os"
	"testing"
	"time"
)

const (
	testRootPath   = "./"
	testPrivateKey = "test_private.key"
	testPublicKey  = "test_public.key"
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

	err = k.Generate()
	require.NoError(t, err)
	assert.NotNil(t, k.privateKey)

	k, err = NewKeys(BitSize(127))
	require.Error(t, err)
	assert.Nil(t, k)
}

func TestNewKeys_withStorage(t *testing.T) {

	fs := storage.NewFileStorage(testRootPath, testPrivateKey, testPublicKey)
	keys, err := NewKeys(Storage(fs))
	require.NoError(t, err)
	assert.NotNil(t, keys)

	err = keys.Generate()
	require.NoError(t, err)
	require.NoError(t, keys.Save())
	defer deleteTestFile(t)

	_, err = os.Stat(testRootPath + testPrivateKey)
	assert.NoError(t, err)

	_, err = os.Stat(testPublicKey)
	assert.NoError(t, err)

}

func TestKey_GenerateKeys(t *testing.T) {

	k, err := NewKeys()
	require.NoError(t, err)
	require.NotNil(t, k)

	err = k.Generate()
	require.NoError(t, err)

	assert.NotNil(t, k.publicKey)
	assert.NotNil(t, k.privateKey)

}

func TestKey_CreateCACertificate(t *testing.T) {
	fs := storage.NewFileStorage(testRootPath, testPrivateKey, testPublicKey)
	keys, err := NewKeys(Storage(fs))
	require.NoError(t, err)
	assert.NotNil(t, keys)
	assert.NoError(t, keys.Generate())

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"TEST, INC."},
			Country:       []string{"RU"},
			Province:      []string{""},
			Locality:      []string{"Krasnodar"},
			StreetAddress: []string{"Krasnaya"},
			PostalCode:    []string{"350000"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Second * 30),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	assert.NoError(t, keys.CreateCAROOT(ca))
	assert.NotNil(t, keys.CertCA())

}

func TestPEMBytes(t *testing.T) {
	keys, err := NewKeys()
	require.NoError(t, err)
	assert.NotNil(t, keys)
	assert.NoError(t, keys.Generate())

	privatePemBytes, err := PEMBytes(keys.privateKey)
	assert.NoError(t, err)
	assert.NotNil(t, privatePemBytes)

	publicPemBytes, err := PEMBytes(keys.publicKey)
	assert.NoError(t, err)
	assert.NotNil(t, publicPemBytes)
}

func TestKeys_CertCA(t *testing.T) {
	keys, err := NewKeys()
	require.NoError(t, err)
	assert.NotNil(t, keys)

	assert.NoError(t, keys.Generate())
	assert.Nil(t, keys.certCARoot)

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"TEST, INC."},
			Country:       []string{"RU"},
			Province:      []string{""},
			Locality:      []string{"Krasnodar"},
			StreetAddress: []string{"Krasnaya"},
			PostalCode:    []string{"350000"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Second * 30),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	assert.NoError(t, keys.CreateCAROOT(ca))
	assert.NotNil(t, keys.certCARoot)

}
func TestKey_Save(t *testing.T) {
	fs := storage.NewFileStorage(testRootPath, testPrivateKey, testPublicKey)
	keys, err := NewKeys(Storage(fs))
	require.NoError(t, err)
	assert.NotNil(t, keys)

	err = keys.Generate()

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"TEST, INC."},
			Country:       []string{"RU"},
			Province:      []string{""},
			Locality:      []string{"Krasnodar"},
			StreetAddress: []string{"Krasnaya"},
			PostalCode:    []string{"350000"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Second * 30),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	assert.NoError(t, keys.CreateCAROOT(ca))
	require.NoError(t, err)

	require.NoError(t, keys.Save())
	defer deleteTestFile(t)
	// check files for exist on a filesystem
	_, err = os.Stat(testRootPath + testPrivateKey)
	assert.NoError(t, err)

	_, err = os.Stat(testRootPath + testPublicKey)
	assert.NoError(t, err)

	CAPath := fmt.Sprintf("%sCA_%s.crt", testRootPath, testPublicKey)
	_, err = os.Stat(CAPath)
	assert.NoError(t, err)

	err = os.Remove(CAPath)
	assert.NoError(t, err)

	keys, err = NewKeys()
	require.NoError(t, err)

	err = keys.Save()
	assert.Error(t, err)

}

func TestKey_Load(t *testing.T) {
	fs := storage.NewFileStorage(testRootPath, testPrivateKey, testPublicKey)
	keys, err := NewKeys(Storage(fs))
	require.NoError(t, err)
	assert.NotNil(t, keys)

	err = keys.Generate()
	require.NoError(t, err)
	require.NoError(t, keys.Save())
	defer deleteTestFile(t)

	_, err = os.Stat(testRootPath + testPrivateKey)
	assert.NoError(t, err)

	_, err = os.Stat(testRootPath + testPublicKey)
	assert.NoError(t, err)

	// trying load key pair from file storage provider
	keys, err = NewKeys(Storage(fs))
	assert.NoError(t, err)
	assert.Nil(t, keys.publicKey)
	assert.Nil(t, keys.privateKey)

	assert.NoError(t, keys.Load())
	assert.NotNil(t, keys.publicKey)
	assert.NotNil(t, keys.privateKey)

	keys.storage = nil
	assert.Error(t, keys.Load())

}
func TestKey_JWK(t *testing.T) {

	k, err := NewKeys()
	require.NoError(t, err)
	require.NotNil(t, k)

	err = k.Generate()
	require.NoError(t, err)
	assert.NotNil(t, k.publicKey)
	assert.NotNil(t, k.privateKey)

	jwk, err := k.JWK()
	t.Log(jwk)

	assert.NoError(t, err)
	assert.NotEmpty(t, jwk)
	assert.Equal(t, k.KeyID, jwk.Kid)

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
	err := os.Remove(testRootPath + testPrivateKey)
	assert.NoError(t, err)

	err = os.Remove(testRootPath + testPublicKey)
	assert.NoError(t, err)
}

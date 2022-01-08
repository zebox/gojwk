// Base example which demonstrate using JWK for access to service using JWT signed with Keys.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt"
	"github.com/zebox/gojwk"
	"github.com/zebox/gojwk/storage"
)

type token struct {
	JWT string `json:"jwt"`
}

func main() {

	ctx, ctxCancel := context.WithCancel(context.Background())
	keys, jwk, err := initKeys()

	if err != nil {
		panic(err)
	}

	// get PEM from private key
	pemByte, err := x509.MarshalPKCS8PrivateKey(keys.Private())
	if err != nil {
		panic(err)
	}

	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: pemByte,
	})

	// create server certificate
	serverCert, err := tls.X509KeyPair(keys.CertCA(), certPrivKeyPEM.Bytes())
	if err != nil {
		panic(err)
	}

	serverTLSConf := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	// init http server and routes
	var httpServer = &http.Server{
		Addr:              fmt.Sprintf(":%d", 8899),
		Handler:           createRouter(keys, jwk),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		TLSConfig:         serverTLSConf,
	}

	// shutting down server
	go func() {
		<-ctx.Done()
		httpServer.Shutdown(context.Background())
	}()

	// starting server
	go func() {
		if err = httpServer.ListenAndServeTLS("./keys/CA_public.key.crt", "./keys/private.key"); err != nil {
			fmt.Printf("[ERROR] failed to start http server %v\n", err)
			return
		}
	}()

	defer ctxCancel()
	time.Sleep(time.Second) // waiting for server start

	// try to get JWT
	token, err := getToken(ctx, keys)
	if err != nil {
		fmt.Printf("[ERROR]: %v\n", err)
		return
	}
	fmt.Printf("Token: %s\n", token)

	// try to get data from service1 with JWT
	data, err := getService(ctx, token, keys)
	if err != nil {
		fmt.Printf("[ERROR]: %v\n", err)
		return
	}

	fmt.Printf("Data: %s\n", data)
}

func getToken(ctx context.Context, keys *gojwk.Keys) (tkn token, err error) {
	url := "https://127.0.0.1:8899/token"

	// create trusted certs pool for client request
	certpool := x509.NewCertPool()
	certpool.AppendCertsFromPEM(keys.CertCA())
	clientTLSConf := &tls.Config{
		RootCAs: certpool,
	}

	transport := &http.Transport{
		TLSClientConfig: clientTLSConf,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	req, _ := http.NewRequestWithContext(ctx, "POST", url, nil)
	req.Header.Add("Accept", "application/json")

	req.SetBasicAuth("test", "test")

	resp, err := client.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		log.Printf("[ERROR]  failed to get token %+v", err)
		return tkn, err
	}

	if resp.StatusCode != 200 {
		log.Printf("[ERROR] [HTTP CODE: %d]failed to get token: %+v", resp.StatusCode, err)
		return tkn, err
	}

	err = json.NewDecoder(resp.Body).Decode(&tkn)

	if err != nil {
		log.Printf("[ERROR] failed read body of response: %+v", err)
		return tkn, err
	}
	return tkn, nil
}

func getService(ctx context.Context, jwt token, keys *gojwk.Keys) (string, error) {
	url := "https://127.0.0.1:8899/service1"

	// create trusted certs pool for client request
	certpool := x509.NewCertPool()
	certpool.AppendCertsFromPEM(keys.CertCA())
	clientTLSConf := &tls.Config{
		RootCAs: certpool,
	}
	transport := &http.Transport{
		TLSClientConfig: clientTLSConf,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", jwt.JWT))

	resp, err := client.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}

	if err != nil || resp.StatusCode != 200 {
		log.Printf("[ERROR] [HTTP CODE: %d]failed to get token: %+v", resp.StatusCode, err)
		return "", err
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR] failed read body of response: %+v", err)
		return "", err
	}
	return string(b), nil
}

func createRouter(keys *gojwk.Keys, jwk *gojwk.JWK) *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	r.Post("/token", func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		w.Header().Add("Content-Type", "application/json")
		if !ok {
			w.Header().Add("WWW-Authenticate", `Basic realm="Username and password required"`)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"message": "No basic auth present"}`))
			return
		}

		if !isAuthorised(username, password) {
			w.Header().Add("WWW-Authenticate", `Basic realm="Give username and password"`)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"message": "Invalid username or password"}`))
			return
		}
		// create token claims
		claims := &jwt.MapClaims{
			"iss":   "http://go.localhost.test",
			"iat":   time.Now().Unix(),
			"exp":   time.Now().Add(time.Second * 30).Unix(),
			"aud":   "zebox/gojwk",
			"sub":   "user_id",
			"email": "test@example.go",
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["alg"] = jwk.Alg
		token.Header["kid"] = jwk.Kid

		// sign JWT with private key
		tokenString, err := token.SignedString(keys.Private())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write([]byte(fmt.Sprintf(`{"jwt":"%s"}`, tokenString)))
	})

	r.Get("/service1", func(w http.ResponseWriter, r *http.Request) {

		tokenHeaderValue := r.Header.Get("Authorization")
		tokenString := strings.Split(tokenHeaderValue, "Bearer ")

		// check JWT with JWK public key
		_, err := jwt.Parse(tokenString[1], jwk.KeyFunc)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"message": "Token invalid"}`))
			return
		}

		w.Header().Add("Content-Type", "application/json")
		w.Write([]byte(fmt.Sprintf(`{"access":true}`)))
	})

	return r
}

// Init keys pair and JWK
func initKeys() (keys *gojwk.Keys, jwk *gojwk.JWK, err error) {

	fileStore := storage.NewFileStorage("./keys", "private.key", "public.key")
	keys, err = gojwk.NewKeys(gojwk.Storage(fileStore))

	if err != nil {
		// skip error handle because Load failed and will generate in next step
	}

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
		NotAfter:              time.Now().AddDate(5, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// add Subject Alternative Name for requested IP and Domain
	// it prevent untasted error with client request
	// https://oidref.com/2.5.29.17
	ca.IPAddresses = append(ca.IPAddresses, net.ParseIP("127.0.0.1"))
	ca.IPAddresses = append(ca.IPAddresses, net.ParseIP("::"))
	ca.DNSNames = append(ca.DNSNames, "localhost")

	// check keys for exist in the storage provider path
	if err = keys.Load(); err != nil {

		// if keys doesn't exist or load fail then create new
		if err = keys.Generate(); err != nil {
			return nil, nil, err
		}

		// create CA certificate for created keys pair
		if err = keys.CreateCAROOT(ca); err != nil {
			return nil, nil, err
		}

		// if new keys pair created successfully save they to defined storage
		if err = keys.Save(); err != nil {
			return nil, nil, err
		}

	}

	if err = keys.CreateCAROOT(ca); err != nil {
		return nil, nil, err
	}
	// gets a JWK
	j, err := keys.JWK()
	jwk = &j // map as pointer

	if err != nil {
		return nil, nil, err
	}
	return keys, jwk, nil
}

// check credentials
func isAuthorised(username, password string) bool {
	return username == "test" && password == "test"
}

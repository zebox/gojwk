// Base example which demonstrate using JWK for access to service using JWT signed with Keys.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt"
	"github.com/zebox/gojwk"
	"github.com/zebox/gojwk/storage"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
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

	// init http server and routes
	var httpServer = &http.Server{
		Addr:              fmt.Sprintf(":%d", 8899),
		Handler:           createRouter(keys, jwk),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	// shutting down server
	go func() {
		<-ctx.Done()
		httpServer.Shutdown(context.Background())
	}()

	// starting server
	go func() {
		_ = httpServer.ListenAndServe()
	}()

	defer ctxCancel()
	time.Sleep(time.Second) // waiting for server start

	// try to get JWT
	token, err := getToken(ctx)
	if err != nil {
		fmt.Printf("[ERROR]: %v\n", err)
		return
	}
	fmt.Printf("Token: %s\n", token)

	// try to get data from service1 with JWT
	data, err := getService(ctx, token)
	if err != nil {
		fmt.Printf("[ERROR]: %v\n", err)
		return
	}

	fmt.Printf("Data: %s\n", data)
}

func getToken(ctx context.Context) (tkn token, err error) {
	url := "http://127.0.0.1:8899/token"
	client := &http.Client{Timeout: 5 * time.Second}

	req, _ := http.NewRequestWithContext(ctx, "POST", url, nil)
	req.Header.Add("Accept", "application/json")

	req.SetBasicAuth("test", "test")

	resp, err := client.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}

	if err != nil || resp.StatusCode != 200 {
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

func getService(ctx context.Context, jwt token) (string, error) {
	url := "http://127.0.0.1:8899/service1"
	client := &http.Client{Timeout: 5 * time.Second}

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

func createRouter(keys *gojwk.Key, jwk *gojwk.JWK) *chi.Mux {
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
func initKeys() (keys *gojwk.Key, jwk *gojwk.JWK, err error) {

	fileStore := storage.NewFileStorage("keys/private.key", "keys/public.key")
	keys, err = gojwk.NewKeys(gojwk.Storage(fileStore))

	if err != nil {
		// skip error handle because Load failed and will generate in next step
	}

	// if keys doesn't exist create new
	if keys.Private() == nil {
		if err := keys.Generate(); err != nil {
			return nil, nil, err
		}
	}

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

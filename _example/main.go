// Base example which demonstrate using JWK for access to service using JWT signed with Keys.
package main

import (
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt"
	"github.com/zebox/gojwk"
	"github.com/zebox/gojwk/storage"
	"net/http"
	"strings"
	"time"
)

func main() {

	keys, jwk, err := initKeys()

	if err != nil {
		panic(err)
	}

	_ = http.ListenAndServe(":3000", createRouter(keys, jwk))

}

func createRouter(keys *gojwk.Key, jwk *gojwk.JWK) *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	r.Get("/auth", func(w http.ResponseWriter, r *http.Request) {
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

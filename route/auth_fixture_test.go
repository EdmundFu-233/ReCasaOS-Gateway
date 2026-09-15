package route

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/IceWhaleTech/CasaOS-Common/utils/jwt"
	"gotest.tools/v3/assert"
)

var (
	authFixtureOnce sync.Once
	authPrivateKey  *ecdsa.PrivateKey
	authPublicKey   *ecdsa.PublicKey
	authToken       string
	authJWKSServer  *httptest.Server
)

func authFixtures(t *testing.T) {
	t.Helper()
	authFixtureOnce.Do(func() {
		privateKey, publicKey, err := jwt.GenerateKeyPair()
		if err != nil {
			panic(err)
		}
		token, err := jwt.GetAccessToken("gateway-tester", privateKey, 7)
		if err != nil {
			panic(err)
		}
		padded := func(value []byte) []byte {
			out := make([]byte, 32)
			copy(out[32-len(value):], value)
			return out
		}
		body, err := json.Marshal(jwt.JWKS{Keys: []jwt.JWK{{
			Kty: "EC",
			Crv: "P-256",
			X:   base64.RawURLEncoding.EncodeToString(padded(publicKey.X.Bytes())),
			Y:   base64.RawURLEncoding.EncodeToString(padded(publicKey.Y.Bytes())),
		}}})
		if err != nil {
			panic(err)
		}
		authJWKSServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/"+jwt.JWKSPath {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
		}))
		authPrivateKey, authPublicKey, authToken = privateKey, publicKey, token
	})
}

// plantAddressFile points the JWKS lookup at the fixture server. The
// external package caches the key for 10 seconds, so all tests in this
// package share one keypair.
func plantAddressFile(t *testing.T, runtimeDir string) {
	t.Helper()
	authFixtures(t)
	assert.NilError(t, os.WriteFile(
		filepath.Join(runtimeDir, "user-service.url"),
		[]byte(authJWKSServer.URL),
		0o600,
	))
}

func bearerRequest(t *testing.T, method, target, body string, withToken bool) *http.Request {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, target, reader)
	assert.NilError(t, err)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if withToken {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}
	return req
}

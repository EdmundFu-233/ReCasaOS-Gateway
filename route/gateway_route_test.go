package route

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/IceWhaleTech/CasaOS-Common/model"
	"github.com/IceWhaleTech/CasaOS-Gateway/service"
	"gotest.tools/v3/assert"
)

func gatewayTestSetup(t *testing.T) (*GatewayRoute, *httptest.Server, *string) {
	t.Helper()
	var seenXFF string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenXFF = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)

	tmpdir, err := os.MkdirTemp("", "casaos-gateway-proxy-test")
	assert.NilError(t, err)
	t.Cleanup(func() { os.RemoveAll(tmpdir) })

	state := service.NewState()
	assert.NilError(t, state.SetRuntimePath(tmpdir))
	management := service.NewManagementService(state)
	assert.NilError(t, management.CreateRoute(&model.Route{Path: "/app", Target: backend.URL}, "tester"))

	return NewGatewayRoute(management), backend, &seenXFF
}

func TestGatewayStripsSpoofedForwardingHeaders(t *testing.T) {
	handler, _, seenXFF := gatewayTestSetup(t)

	req, err := http.NewRequest(http.MethodGet, "/app/data", nil)
	assert.NilError(t, err)
	// Untrusted Internet peer spoofs every identity header.
	req.RemoteAddr = "203.0.113.7:1234"
	req.Header.Set("X-Forwarded-For", "10.9.9.9")
	req.Header.Set("X-Real-IP", "10.9.9.9")
	req.Header.Set("Forwarded", "for=10.9.9.9")
	req.Header.Set("X-Forwarded-Host", "evil.example")

	w := httptest.NewRecorder()
	handler.GetRoute().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// The backend sees the real peer, never the spoofed values.
	assert.Equal(t, "203.0.113.7, 203.0.113.7", *seenXFF)
}

func TestGatewayHonorsTrustedProxyChain(t *testing.T) {
	tmpdir, err := os.MkdirTemp("", "casaos-gateway-proxy-test")
	assert.NilError(t, err)
	defer os.RemoveAll(tmpdir)

	var seenXFF string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenXFF = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	state := service.NewState()
	assert.NilError(t, state.SetRuntimePath(tmpdir))
	policy, err := service.NewRoutePolicy("127.0.0.1/32", "127.0.0.1/32,::1/128", 24*time.Hour)
	assert.NilError(t, err)
	management := service.NewManagementServiceWithPolicy(state, policy)
	assert.NilError(t, management.CreateRoute(&model.Route{Path: "/app", Target: backend.URL}, "tester"))

	req, err := http.NewRequest(http.MethodGet, "/app/data", nil)
	assert.NilError(t, err)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 127.0.0.1")

	w := httptest.NewRecorder()
	NewGatewayRoute(management).GetRoute().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// Rightmost untrusted client preserved, trusted proxy appended.
	assert.Equal(t, "203.0.113.7, 127.0.0.1", seenXFF)
}

func TestGatewayUnknownPathIs404(t *testing.T) {
	handler, _, _ := gatewayTestSetup(t)

	req, err := http.NewRequest(http.MethodGet, "/nope", nil)
	assert.NilError(t, err)
	req.RemoteAddr = "203.0.113.7:1234"

	w := httptest.NewRecorder()
	handler.GetRoute().ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGatewaySegmentBoundary(t *testing.T) {
	handler, _, _ := gatewayTestSetup(t)

	// "/app" must not serve "/application": prefix without boundary is 404.
	req, err := http.NewRequest(http.MethodGet, "/application", nil)
	assert.NilError(t, err)
	req.RemoteAddr = "203.0.113.7:1234"

	w := httptest.NewRecorder()
	handler.GetRoute().ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)

	// Sub-paths on the boundary proxy through.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "proxied")
	}))
	defer backend.Close()

	req, err = http.NewRequest(http.MethodGet, "/app/sub", nil)
	assert.NilError(t, err)
	req.RemoteAddr = "203.0.113.7:1234"
	w = httptest.NewRecorder()
	handler.GetRoute().ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

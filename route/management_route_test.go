package route

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/IceWhaleTech/CasaOS-Common/utils/logger"
	"github.com/labstack/echo/v4"

	"github.com/IceWhaleTech/CasaOS-Common/model"
	"github.com/IceWhaleTech/CasaOS-Gateway/service"
	"gotest.tools/v3/assert"
)

var (
	_router       http.Handler
	_state        *service.State
	_serviceToken string
)

func init() {
	logger.LogInitConsoleOnly()
}

func setup(t *testing.T) func(t *testing.T) {
	tmpdir, _ := os.MkdirTemp("", "casaos-gateway-route-test")

	_state = service.NewState()
	if err := _state.SetRuntimePath(tmpdir); err != nil {
		t.Fatal(err)
	}
	plantAddressFile(t, tmpdir)
	serviceToken, err := service.GenerateServiceToken(tmpdir)
	if err != nil {
		t.Fatal(err)
	}
	if err := _state.SetServiceToken(serviceToken); err != nil {
		t.Fatal(err)
	}
	_serviceToken = serviceToken

	management := service.NewManagementService(_state)
	managementRoute := NewManagementRoute(management)
	_router = managementRoute.GetRoute()

	return func(t *testing.T) {
		management = nil
		_router = nil
		os.RemoveAll(tmpdir)
	}
}

func TestPing(t *testing.T) {
	defer setup(t)(t)

	w := httptest.NewRecorder()

	req, _ := http.NewRequest(http.MethodGet, "/ping", nil)

	_router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCreateRoute(t *testing.T) {
	defer setup(t)(t)

	route := &model.Route{
		Path:   "/test",
		Target: "http://localhost:8080",
	}

	body, err := json.Marshal(route)
	assert.NilError(t, err)

	req := bearerRequest(t, http.MethodPost, "/v1/gateway/routes", string(body), true)
	req.RemoteAddr = "127.0.0.1:0"

	w := httptest.NewRecorder()
	_router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	req = bearerRequest(t, http.MethodGet, "/v1/gateway/routes", "", true)
	w = httptest.NewRecorder()
	_router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var routes []*model.Route

	decoder := json.NewDecoder(w.Body)

	err = decoder.Decode(&routes)
	assert.NilError(t, err)
	assert.Equal(t, 1, len(routes))
	assert.Equal(t, route.Path, routes[0].Path)
	assert.Equal(t, route.Target, routes[0].Target)
}

func TestManagementRequiresBearerToken(t *testing.T) {
	defer setup(t)(t)

	// Loopback without credentials must not rewire the gateway.
	payload := `{"path":"/evil","target":"http://127.0.0.1:8080/"}`
	req := bearerRequest(t, http.MethodPost, "/v1/gateway/routes", payload, false)
	req.RemoteAddr = "127.0.0.1:0"
	w := httptest.NewRecorder()
	_router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Query-string tokens are never accepted, even when valid.
	req = bearerRequest(t, http.MethodPost, "/v1/gateway/routes?token="+authToken, payload, false)
	req.RemoteAddr = "127.0.0.1:0"
	w = httptest.NewRecorder()
	_router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Readers need credentials too: topology is not public.
	req = bearerRequest(t, http.MethodGet, "/v1/gateway/routes", "", false)
	req.RemoteAddr = "127.0.0.1:0"
	w = httptest.NewRecorder()
	_router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Port changes need credentials too.
	req = bearerRequest(t, http.MethodPut, "/v1/gateway/port", `{"port":"123"}`, false)
	req.RemoteAddr = "127.0.0.1:0"
	w = httptest.NewRecorder()
	_router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRouteDeleteAndRenewFlow(t *testing.T) {
	defer setup(t)(t)

	payload := `{"path":"/app","target":"http://127.0.0.1:8080/"}`
	req := bearerRequest(t, http.MethodPost, "/v1/gateway/routes", payload, true)
	w := httptest.NewRecorder()
	_router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	// Renew the live registration.
	req = bearerRequest(t, http.MethodPost, "/v1/gateway/routes/renew", `{"path":"/app"}`, true)
	w = httptest.NewRecorder()
	_router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)

	// Renewing an unknown path is 404, not a silent create.
	req = bearerRequest(t, http.MethodPost, "/v1/gateway/routes/renew", `{"path":"/missing"}`, true)
	w = httptest.NewRecorder()
	_router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)

	// Delete removes durably.
	req = bearerRequest(t, http.MethodDelete, "/v1/gateway/routes", `{"path":"/app"}`, true)
	w = httptest.NewRecorder()
	_router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)

	// Deleting again is 404: removal is not resurrected.
	req = bearerRequest(t, http.MethodDelete, "/v1/gateway/routes", `{"path":"/app"}`, true)
	w = httptest.NewRecorder()
	_router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)

	req = bearerRequest(t, http.MethodGet, "/v1/gateway/routes", "", true)
	w = httptest.NewRecorder()
	_router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	var routes []*model.Route
	assert.NilError(t, json.NewDecoder(w.Body).Decode(&routes))
	assert.Equal(t, 0, len(routes))
}

func TestCORSSameOriginByDefault(t *testing.T) {
	defer setup(t)(t)

	req := bearerRequest(t, http.MethodGet, "/v1/gateway/routes", "", true)
	req.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	_router.ServeHTTP(w, req)
	assert.Equal(t, "", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSAllowlist(t *testing.T) {
	tmpdir, _ := os.MkdirTemp("", "casaos-gateway-cors-test")
	defer os.RemoveAll(tmpdir)

	state := service.NewState()
	assert.NilError(t, state.SetRuntimePath(tmpdir))
	plantAddressFile(t, tmpdir)

	management := service.NewManagementService(state)
	handler := NewManagementRouteWithCORS(management, []string{"https://console.example"}).GetRoute()

	req := bearerRequest(t, http.MethodGet, "/v1/gateway/routes", "", true)
	req.Header.Set("Origin", "https://console.example")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, "https://console.example", w.Header().Get("Access-Control-Allow-Origin"))

	req = bearerRequest(t, http.MethodGet, "/v1/gateway/routes", "", true)
	req.Header.Set("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, "", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestChangePort(t *testing.T) {
	defer setup(t)(t)

	actualPort := ""

	_state.OnGatewayPortChange(func(s string) error {
		actualPort = s
		return nil
	})

	expectedPort := "123"

	// set
	request := &model.ChangePortRequest{
		Port: expectedPort,
	}

	body, err := json.Marshal(request)
	assert.NilError(t, err)

	req := bearerRequest(t, http.MethodPut, "/v1/gateway/port", string(body), true)
	req.RemoteAddr = "127.0.0.1:0"

	w := httptest.NewRecorder()
	_router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, expectedPort, actualPort)

	// get
	req = bearerRequest(t, http.MethodGet, "/v1/gateway/port", "", true)

	w = httptest.NewRecorder()
	_router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result *model.Result
	decoder := json.NewDecoder(w.Body)

	err = decoder.Decode(&result)
	assert.NilError(t, err)
	assert.Equal(t, expectedPort, result.Data)
}

func TestChangePortNegative(t *testing.T) {
	defer setup(t)(t)

	expectedPort := "123"

	// set
	request := &model.ChangePortRequest{
		Port: expectedPort,
	}

	body, err := json.Marshal(request)
	assert.NilError(t, err)

	req := bearerRequest(t, http.MethodPut, "/v1/gateway/port", string(body), true)
	req.RemoteAddr = "127.0.0.1:0"

	w := httptest.NewRecorder()
	_router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, expectedPort, "123")

	// get
	req = bearerRequest(t, http.MethodGet, "/v1/gateway/port", "", true)
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

	w = httptest.NewRecorder()
	_router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result *model.Result
	decoder := json.NewDecoder(w.Body)

	err = decoder.Decode(&result)
	assert.NilError(t, err)
	assert.Equal(t, expectedPort, result.Data)

	// emulate error
	_state.OnGatewayPortChange(func(_ string) error {
		return errors.New("error")
	})

	// set
	request.Port = "456"

	body, err = json.Marshal(request)
	assert.NilError(t, err)

	req = bearerRequest(t, http.MethodPut, "/v1/gateway/port", string(body), true)
	req.RemoteAddr = "127.0.0.1:0"

	w = httptest.NewRecorder()
	_router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, expectedPort, "123")

	// get
	req = bearerRequest(t, http.MethodGet, "/v1/gateway/port", "", true)

	w = httptest.NewRecorder()
	_router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	decoder = json.NewDecoder(w.Body)

	err = decoder.Decode(&result)
	assert.NilError(t, err)
	assert.Equal(t, expectedPort, result.Data)
}

// The local service credential lets in-stack component clients manage routes
// without a user JWT, while user JWTs remain a separate owner identity.
func TestServiceTokenManagesRoutes(t *testing.T) {
	defer setup(t)(t)

	payload := `{"path":"/service-route","target":"http://127.0.0.1:8080/"}`

	req, err := http.NewRequest(http.MethodPost, "/v1/gateway/routes", strings.NewReader(payload))
	assert.NilError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+_serviceToken)
	req.RemoteAddr = "127.0.0.1:0"

	w := httptest.NewRecorder()
	_router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	// The service-owned route cannot be taken over by a user JWT owner.
	req = bearerRequest(t, http.MethodPost, "/v1/gateway/routes", payload, true)
	req.RemoteAddr = "127.0.0.1:0"
	w = httptest.NewRecorder()
	_router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)

	// The service credential can renew and delete its own route.
	renew := `{"path":"/service-route"}`
	req, err = http.NewRequest(http.MethodPost, "/v1/gateway/routes/renew", strings.NewReader(renew))
	assert.NilError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+_serviceToken)
	w = httptest.NewRecorder()
	_router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)

	req, err = http.NewRequest(http.MethodDelete, "/v1/gateway/routes", strings.NewReader(renew))
	assert.NilError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+_serviceToken)
	w = httptest.NewRecorder()
	_router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestWrongServiceTokenIsRejected(t *testing.T) {
	defer setup(t)(t)

	payload := `{"path":"/wrong-token","target":"http://127.0.0.1:8080/"}`
	req, err := http.NewRequest(http.MethodPost, "/v1/gateway/routes", strings.NewReader(payload))
	assert.NilError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
	req.RemoteAddr = "127.0.0.1:0"

	w := httptest.NewRecorder()
	_router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestServiceTokenIsNotAcceptedWithoutSetup(t *testing.T) {
	defer setup(t)(t)

	// An empty active token never matches, even against an empty presented
	// token: fail closed instead of authenticating everyone.
	assert.Assert(t, !service.ServiceTokenMatches("", ""))
	assert.Assert(t, !service.ServiceTokenMatches(_serviceToken, ""))
}

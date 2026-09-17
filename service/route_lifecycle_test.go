package service

import (
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/IceWhaleTech/CasaOS-Common/model"
	"gotest.tools/assert"
)

func lifecycleState(t *testing.T) (*State, string) {
	t.Helper()
	tmpdir, err := os.MkdirTemp("", "casaos-gateway-lifecycle-test")
	assert.NilError(t, err)
	t.Cleanup(func() { os.RemoveAll(tmpdir) })
	state := NewState()
	assert.NilError(t, state.SetRuntimePath(tmpdir))
	return state, tmpdir
}

func TestRouteOwnershipConflict(t *testing.T) {
	state, _ := lifecycleState(t)
	management := NewManagementService(state)

	assert.NilError(t, management.CreateRoute(&model.Route{Path: "/a", Target: "http://127.0.0.1:8080"}, "alice"))
	err := management.CreateRoute(&model.Route{Path: "/a", Target: "http://127.0.0.1:8081"}, "bob")
	assert.Error(t, err, ErrRouteOwned.Error())

	// Same owner re-registers (lease refresh) without conflict.
	assert.NilError(t, management.CreateRoute(&model.Route{Path: "/a", Target: "http://127.0.0.1:8081"}, "alice"))
	routes := management.GetRoutes()
	assert.Equal(t, 1, len(routes))
	assert.Equal(t, "http://127.0.0.1:8081", routes[0].Target)
}

func TestRouteRenewAndDelete(t *testing.T) {
	state, _ := lifecycleState(t)
	management := NewManagementService(state)

	assert.NilError(t, management.CreateRoute(&model.Route{Path: "/a", Target: "http://127.0.0.1:8080"}, "alice"))
	assert.NilError(t, management.RenewRoute("/a", "alice"))
	assert.Error(t, management.RenewRoute("/a", "bob"), ErrRouteOwned.Error())
	assert.Error(t, management.RenewRoute("/missing", "alice"), ErrRouteNotFound.Error())
	assert.Error(t, management.DeleteRoute("/a", "bob"), ErrRouteOwned.Error())
	assert.Error(t, management.DeleteRoute("/missing", "alice"), ErrRouteNotFound.Error())
	assert.NilError(t, management.DeleteRoute("/a", "alice"))
	assert.Equal(t, 0, len(management.GetRoutes()))
}

func TestDeletedRouteStaysDeletedAcrossRestart(t *testing.T) {
	state, dir := lifecycleState(t)
	management := NewManagementService(state)

	assert.NilError(t, management.CreateRoute(&model.Route{Path: "/a", Target: "http://127.0.0.1:8080"}, "alice"))
	assert.NilError(t, management.CreateRoute(&model.Route{Path: "/b", Target: "http://127.0.0.1:8081"}, "alice"))
	assert.NilError(t, management.DeleteRoute("/a", "alice"))

	restarted := NewManagementService(state)
	routes := restarted.GetRoutes()
	assert.Equal(t, 1, len(routes))
	assert.Equal(t, "/b", routes[0].Path)
	assert.Assert(t, restarted.GetProxy("/a") == nil)

	// The routes file itself must not contain the removed path.
	content, err := os.ReadFile(filepath.Join(dir, RoutesFile))
	assert.NilError(t, err)
	assert.Assert(t, !containsString(string(content), "/a"))
}

func containsString(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

func TestExpiredRoutesDie(t *testing.T) {
	state, _ := lifecycleState(t)
	policy, err := NewRoutePolicy("127.0.0.1/32,::1/128", "127.0.0.1/32,::1/128", time.Minute)
	assert.NilError(t, err)
	management := NewManagementServiceWithPolicy(state, policy)

	assert.NilError(t, management.CreateRoute(&model.Route{Path: "/a", Target: "http://127.0.0.1:8080"}, "alice"))
	// Force expiry by backdating the entry, then verify lookup drops it.
	entry := management.entries["/a"]
	entry.ExpiresAt = time.Now().Add(-time.Second).Unix()

	assert.Assert(t, management.GetProxy("/a") == nil)
	assert.Equal(t, 0, len(management.GetRoutes()))
	assert.Error(t, management.RenewRoute("/a", "alice"), ErrRouteNotFound.Error())

	// A restart must not resurrect the expired path either.
	restarted := NewManagementServiceWithPolicy(state, policy)
	assert.Equal(t, 0, len(restarted.GetRoutes()))
}

func TestLegacyImportIsBounded(t *testing.T) {
	state, dir := lifecycleState(t)
	legacy := `{
		"/keep": "http://127.0.0.1:8080",
		"/evil": "http://169.254.169.254/",
		"relative": "http://127.0.0.1:8081",
		"/ftp": "ftp://127.0.0.1:21/"
	}`
	assert.NilError(t, os.WriteFile(filepath.Join(dir, RoutesFile), []byte(legacy), 0o600))

	management := NewManagementService(state)
	routes := management.GetRoutes()
	assert.Equal(t, 1, len(routes))
	assert.Equal(t, "/keep", routes[0].Path)
	entry := management.entries["/keep"]
	assert.Equal(t, legacyRouteOwner, entry.Owner)
	remaining := time.Until(time.Unix(entry.ExpiresAt, 0))
	assert.Assert(t, remaining > 700*time.Hour && remaining <= legacyImportLease)
}

// Legacy-imported routes have no principal that can renew or delete them.
// Only the in-stack service identities may adopt one; a user JWT owner must
// not be able to displace a component route after an upgrade.
func TestCreateRouteAdoptsLegacyOwnedRoute(t *testing.T) {
	state, dir := lifecycleState(t)
	legacy := `{"/keep": "http://127.0.0.1:8080"}`
	assert.NilError(t, os.WriteFile(filepath.Join(dir, RoutesFile), []byte(legacy), 0o600))

	management := NewManagementService(state)
	assert.Equal(t, legacyRouteOwner, management.entries["/keep"].Owner)

	assert.Error(t, management.CreateRoute(&model.Route{Path: "/keep", Target: "http://127.0.0.1:8081"}, "uid-7"), ErrRouteOwned.Error())
	assert.Equal(t, legacyRouteOwner, management.entries["/keep"].Owner)

	assert.NilError(t, management.CreateRoute(&model.Route{Path: "/keep", Target: "http://127.0.0.1:8081"}, ServiceOwner))
	assert.Equal(t, ServiceOwner, management.entries["/keep"].Owner)
	assert.Equal(t, "http://127.0.0.1:8081", management.entries["/keep"].Target)

	// A user owner still cannot take over the adopted route.
	assert.Error(t, management.CreateRoute(&model.Route{Path: "/keep", Target: "http://127.0.0.1:8082"}, "uid-7"), ErrRouteOwned.Error())
}

// Service and self routes are re-registered by their live owners at startup,
// so they are never persisted and never inherited across a restart.
func TestServiceRoutesAreNotPersisted(t *testing.T) {
	state, dir := lifecycleState(t)
	management := NewManagementService(state)

	assert.NilError(t, management.CreateRoute(&model.Route{Path: "/v1/file", Target: "http://127.0.0.1:8080"}, ServiceOwner))
	assert.NilError(t, management.CreateRoute(&model.Route{Path: "/", Target: "http://127.0.0.1:8081"}, SelfRouteOwner))
	assert.NilError(t, management.CreateRoute(&model.Route{Path: "/user", Target: "http://127.0.0.1:8082"}, "uid-7"))

	content, err := os.ReadFile(filepath.Join(dir, RoutesFile))
	assert.NilError(t, err)
	assert.Assert(t, containsString(string(content), "/user"))
	assert.Assert(t, !containsString(string(content), "/v1/file"))
	assert.Assert(t, !containsString(string(content), `"/"`))

	restarted := NewManagementService(state)
	assert.Assert(t, restarted.GetProxy("/v1/file") == nil)
	assert.Assert(t, restarted.GetProxy("/") == nil)
	assert.Assert(t, restarted.GetProxy("/user") != nil)
}

// Service and self routes do not carry a lease: their owners re-register them
// and a dead owner cannot leave a stale persisted entry.
func TestServiceRoutesDoNotExpire(t *testing.T) {
	state, _ := lifecycleState(t)
	policy, err := NewRoutePolicy("127.0.0.1/32,::1/128", "127.0.0.1/32,::1/128", time.Minute)
	assert.NilError(t, err)
	management := NewManagementServiceWithPolicy(state, policy)

	assert.NilError(t, management.CreateRoute(&model.Route{Path: "/v1/file", Target: "http://127.0.0.1:8080"}, ServiceOwner))
	entry := management.entries["/v1/file"]
	entry.ExpiresAt = time.Now().Add(-time.Hour).Unix()

	assert.Assert(t, management.GetProxy("/v1/file") != nil)
	assert.Equal(t, ServiceOwner, management.RouteOwner("/v1/file"))
}

func TestTargetValidation(t *testing.T) {
	state, _ := lifecycleState(t)
	management := NewManagementService(state)

	forbidden := []string{
		"http://169.254.169.254/",          // cloud metadata
		"http://10.0.0.1:8080/",            // private network
		"http://192.168.1.1/",              // missing port is also rejected
		"http://example.com:8080/",         // DNS names rejected
		"ftp://127.0.0.1:21/",              // scheme
		"http://user:pass@127.0.0.1:8080/", // userinfo
		"http://127.0.0.1:8080/?q=1",       // query
		"http://127.0.0.1:8080/#f",         // fragment
		"http://127.0.0.1/",                // missing port
		"http://[::ffff:10.0.0.1]:8080/",   // mapped private
		"http://224.0.0.1:8080/",           // multicast
		"not-a-url",
		"",
	}
	for _, target := range forbidden {
		err := management.CreateRoute(&model.Route{Path: "/t", Target: target}, "alice")
		assert.Assert(t, err != nil, "target %q must be rejected", target)
	}

	allowed := []string{
		"http://127.0.0.1:8080",
		"https://127.0.0.1:443/",
		"http://localhost:8080/",
		"http://[::1]:8080/",
	}
	for _, target := range allowed {
		assert.NilError(t, management.CreateRoute(&model.Route{Path: "/t", Target: target}, "alice"))
		assert.NilError(t, management.DeleteRoute("/t", "alice"))
	}
}

func TestTargetCIDRExtension(t *testing.T) {
	state, _ := lifecycleState(t)
	policy, err := NewRoutePolicy("127.0.0.1/32", "10.0.0.0/8", 24*time.Hour)
	assert.NilError(t, err)
	management := NewManagementServiceWithPolicy(state, policy)

	assert.NilError(t, management.CreateRoute(&model.Route{Path: "/t", Target: "http://10.1.2.3:8080/"}, "alice"))
	err = management.CreateRoute(&model.Route{Path: "/u", Target: "http://192.168.1.1:8080/"}, "alice")
	assert.Assert(t, err != nil)
}

func TestPathValidation(t *testing.T) {
	state, _ := lifecycleState(t)
	management := NewManagementService(state)

	invalid := []string{"", "relative", "/a/../b", "/a//b", "/a/./b", "/a/", "/with space", "/with?query"}
	for _, routePath := range invalid {
		err := management.CreateRoute(&model.Route{Path: routePath, Target: "http://127.0.0.1:8080"}, "alice")
		assert.Assert(t, err != nil, "path %q must be rejected", routePath)
	}
}

func TestMatchSegment(t *testing.T) {
	cases := []struct {
		request, prefix string
		want            bool
	}{
		{"/", "/", true},
		{"/anything", "/", true},
		{"/ab", "/ab", true},
		{"/ab/c", "/ab", true},
		{"/abcd", "/ab", false},
		{"/ab-cd", "/ab", false},
		{"/a", "/ab", false},
		{"/v1/gateway/port", "/v1/gateway/port", true},
		{"/v1/gateway/ports", "/v1/gateway/port", false},
	}
	for _, tc := range cases {
		assert.Equal(t, MatchSegment(tc.request, tc.prefix), tc.want, "request=%q prefix=%q", tc.request, tc.prefix)
	}
}

func TestClientIPResolution(t *testing.T) {
	policy, err := NewRoutePolicy("127.0.0.1/32,::1/128,10.0.0.0/8", "", 24*time.Hour)
	assert.NilError(t, err)

	// Untrusted peer: forwarding headers ignored.
	assert.Equal(t, "203.0.113.7", policy.ClientIP("203.0.113.7:1234", "10.9.9.9", ""))
	// Loopback peer (trusted): rightmost untrusted wins.
	assert.Equal(t, "203.0.113.7", policy.ClientIP("127.0.0.1:1234", "203.0.113.7, 127.0.0.1", ""))
	// Fully trusted chain falls back to X-Real-IP, then peer.
	assert.Equal(t, "10.1.1.1", policy.ClientIP("127.0.0.1:1234", "10.1.1.1, 10.2.2.2", ""))
	assert.Equal(t, "10.9.9.9", policy.ClientIP("127.0.0.1:1234", "", "10.9.9.9"))
	assert.Equal(t, "127.0.0.1", policy.ClientIP("127.0.0.1:1234", "", ""))
	// Garbage never becomes identity.
	assert.Equal(t, "", policy.ClientIP("not-an-address", "also-garbage", ""))
	// IPv6 loopback peer trusted.
	assert.Equal(t, "203.0.113.7", policy.ClientIP("[::1]:1234", "203.0.113.7", ""))
}

func TestParseRouteLeaseTTL(t *testing.T) {
	ttl, err := ParseRouteLeaseTTL("24h")
	assert.NilError(t, err)
	assert.Equal(t, 24*time.Hour, ttl)
	for _, raw := range []string{"", "30s", "1000h", "abc", "-1h", "0"} {
		_, err := ParseRouteLeaseTTL(raw)
		assert.Assert(t, err != nil, "ttl %q must be rejected", raw)
	}
}

func TestPolicyValidation(t *testing.T) {
	_, err := NewRoutePolicy("not-a-cidr", "", 24*time.Hour)
	assert.Assert(t, err != nil)
	_, err = NewRoutePolicy("", "", 30*time.Second)
	assert.Assert(t, err != nil)
	_, err = NewRoutePolicy("", "", 0)
	assert.Assert(t, err != nil)
}

func TestManagementConcurrentHammer(t *testing.T) {
	state, _ := lifecycleState(t)
	management := NewManagementService(state)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			path := "/hammer"
			owner := "owner"
			_ = management.CreateRoute(&model.Route{Path: path, Target: "http://127.0.0.1:8080"}, owner)
			_ = management.GetProxy(path)
			_ = management.GetRoutes()
			_ = management.RenewRoute(path, owner)
			_ = management.DeleteRoute(path, owner)
			_ = n
		}(i)
	}
	wg.Wait()
}

func TestSanitizeRemovesCDNIdentityHeaders(t *testing.T) {
	header := map[string][]string{
		"True-Client-Ip":   {"9.9.9.9"},
		"Cf-Connecting-Ip": {"8.8.8.8"},
		"X-Client-Ip":      {"7.7.7.7"},
	}
	h := http.Header(header)
	SanitizeProxyHeaders(h, "203.0.113.7")
	for _, key := range []string{"True-Client-Ip", "Cf-Connecting-Ip", "X-Client-Ip"} {
		if got := h.Get(key); got != "" {
			t.Fatalf("%s survived sanitization: %q", key, got)
		}
	}
	if got := h.Get("X-Forwarded-For"); got != "203.0.113.7" {
		t.Fatalf("X-Forwarded-For = %q", got)
	}
}

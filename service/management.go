package service

import (
	"encoding/json"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/IceWhaleTech/CasaOS-Common/model"
	"github.com/IceWhaleTech/CasaOS-Common/utils/logger"
	"go.uber.org/zap"
)

const RoutesFile = "routes.json"

type routesFile struct {
	Version int          `json:"version"`
	Routes  []RouteEntry `json:"routes"`
}

// Management owns the leased route table. Registrations carry an owner and
// a lease: expired entries are dropped on lookup, removal deletes durably,
// and restarts only resurrect live entries. A removed path never comes back
// on its own.
type Management struct {
	mu      sync.Mutex
	entries map[string]*RouteEntry
	proxies map[string]*httputil.ReverseProxy
	policy  *RoutePolicy

	State *State
}

// NewManagementService builds a Management with the default deny-by-default
// policy: loopback peers and targets only, 24-hour leases. Production uses
// NewManagementServiceWithPolicy with operator configuration.
func NewManagementService(state *State) *Management {
	policy, err := NewRoutePolicy("127.0.0.1/32,::1/128", "127.0.0.1/32,::1/128", 24*time.Hour)
	if err != nil {
		panic(err)
	}
	return NewManagementServiceWithPolicy(state, policy)
}

// NewManagementServiceWithPolicy builds a Management over operator policy.
func NewManagementServiceWithPolicy(state *State, policy *RoutePolicy) *Management {
	if policy == nil {
		panic("nil route policy")
	}
	management := &Management{
		entries: make(map[string]*RouteEntry),
		proxies: make(map[string]*httputil.ReverseProxy),
		policy:  policy,
		State:   state,
	}
	for _, entry := range loadRouteEntries(filepath.Join(state.GetRuntimePath(), RoutesFile), policy) {
		management.adopt(entry)
	}
	return management
}

func (g *Management) adopt(entry RouteEntry) {
	targetURL, err := url.Parse(entry.Target)
	if err != nil {
		logger.Error("Failed to parse route target", zap.Any("error", err), zap.String("path", entry.Path))
		return
	}
	stored := entry
	g.entries[entry.Path] = &stored
	g.proxies[entry.Path] = httputil.NewSingleHostReverseProxy(targetURL)
}

// CreateRoute registers or re-registers a path under the authenticated
// owner. Re-registration by the same owner refreshes the lease (this is how
// the gateway keeps its own routes alive); a different owner gets
// ErrRouteOwned instead of a silent takeover.
func (g *Management) CreateRoute(route *model.Route, owner string) error {
	entry, err := g.policy.ValidateRegistration(route.Path, route.Target, owner)
	if err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepLocked()
	if existing, taken := g.entries[entry.Path]; taken && existing.Owner != owner {
		return ErrRouteOwned
	}
	g.adopt(entry)
	return g.persistLocked()
}

// RenewRoute extends one live registration. Only the owning identity may
// renew; expired paths must be re-created.
func (g *Management) RenewRoute(routePath, owner string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepLocked()
	entry, ok := g.entries[routePath]
	if !ok {
		return ErrRouteNotFound
	}
	if entry.Owner != owner {
		return ErrRouteOwned
	}
	now := g.policy.now().Unix()
	entry.ExpiresAt = now + int64(g.policy.leaseTTL/time.Second)
	entry.RenewedAt = now
	return g.persistLocked()
}

// DeleteRoute removes one registration durably. Only the owning identity
// may remove; the removal is persisted immediately so restarts cannot
// resurrect the path.
func (g *Management) DeleteRoute(routePath, owner string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepLocked()
	entry, ok := g.entries[routePath]
	if !ok {
		return ErrRouteNotFound
	}
	if entry.Owner != owner {
		return ErrRouteOwned
	}
	delete(g.entries, routePath)
	delete(g.proxies, routePath)
	return g.persistLocked()
}

// GetRoutes lists live registrations as plain path/target pairs.
func (g *Management) GetRoutes() []*model.Route {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepLocked()
	routes := make([]*model.Route, 0, len(g.entries))
	for _, entry := range g.entries {
		routes = append(routes, &model.Route{
			Path:   entry.Path,
			Target: entry.Target,
		})
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].Path < routes[j].Path })
	return routes
}

// GetProxy returns the longest live prefix match on a segment boundary.
func (g *Management) GetProxy(path string) *httputil.ReverseProxy {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sweepLocked()
	paths := make([]string, 0, len(g.proxies))
	for registered := range g.proxies {
		paths = append(paths, registered)
	}
	sort.Slice(paths, func(i, j int) bool { return len(paths[i]) > len(paths[j]) })
	for _, prefix := range paths {
		if MatchSegment(path, prefix) {
			return g.proxies[prefix]
		}
	}
	return nil
}

// Policy exposes the active route policy for request handling.
func (g *Management) Policy() *RoutePolicy {
	return g.policy
}

func (g *Management) sweepLocked() {
	now := g.policy.now()
	dropped := false
	for registered, entry := range g.entries {
		if entry.Expired(now) {
			logger.Error("Dropping expired gateway route", zap.String("path", registered), zap.String("owner", entry.Owner))
			delete(g.entries, registered)
			delete(g.proxies, registered)
			dropped = true
		}
	}
	if dropped {
		if err := g.persistLocked(); err != nil {
			logger.Error("Failed to persist route sweep", zap.Any("error", err))
		}
	}
}

func (g *Management) persistLocked() error {
	routesFilePath := filepath.Join(g.State.GetRuntimePath(), RoutesFile)
	entries := make([]RouteEntry, 0, len(g.entries))
	for _, entry := range g.entries {
		entries = append(entries, *entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	content, err := json.Marshal(routesFile{Version: routesFileVersion, Routes: entries})
	if err != nil {
		return err
	}
	return os.WriteFile(routesFilePath, content, 0o600)
}

func loadRouteEntries(routesFilepath string, policy *RoutePolicy) []RouteEntry {
	content, err := os.ReadFile(routesFilepath)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Error("Failed to load routes", zap.Any("error", err), zap.Any("filepath", routesFilepath))
		}
		return nil
	}
	var file routesFile
	if err := json.Unmarshal(content, &file); err == nil && file.Version == routesFileVersion {
		live := make([]RouteEntry, 0, len(file.Routes))
		now := policy.now()
		for _, entry := range file.Routes {
			if ValidateRoutePath(entry.Path) != nil || ValidateRouteOwner(entry.Owner) != nil {
				logger.Error("Dropping malformed persisted route", zap.String("path", entry.Path))
				continue
			}
			if policy.ValidateRouteTarget(entry.Target) != nil {
				logger.Error("Dropping persisted route with forbidden target", zap.String("path", entry.Path))
				continue
			}
			if entry.Expired(now) {
				logger.Error("Dropping expired persisted route", zap.String("path", entry.Path))
				continue
			}
			live = append(live, entry)
		}
		return live
	}
	return importLegacyRoutes(content, policy)
}

// importLegacyRoutes adopts the pre-lease map format with a bounded lease so
// upgraded systems keep working while every route gains an expiry. Anything
// unparsable is dropped, never resurrected.
func importLegacyRoutes(content []byte, policy *RoutePolicy) []RouteEntry {
	legacy := make(map[string]string)
	if err := json.Unmarshal(content, &legacy); err != nil {
		logger.Error("Failed to parse routes file in any known format")
		return nil
	}
	now := policy.now().Unix()
	entries := make([]RouteEntry, 0, len(legacy))
	for routePath, target := range legacy {
		if ValidateRoutePath(routePath) != nil || policy.ValidateRouteTarget(target) != nil {
			logger.Error("Dropping legacy route that violates current policy", zap.String("path", routePath))
			continue
		}
		logger.Error("Importing legacy route with a bounded lease; re-register to refresh", zap.String("path", routePath))
		entries = append(entries, RouteEntry{
			Path:      routePath,
			Target:    target,
			Owner:     legacyRouteOwner,
			ExpiresAt: now + int64(legacyImportLease/time.Second),
			RenewedAt: now,
		})
	}
	return entries
}

func (g *Management) GetGatewayPort() string {
	return g.State.GetGatewayPort()
}

func (g *Management) SetGatewayPort(port string) error {
	if err := g.State.SetGatewayPort(port); err != nil {
		return err
	}

	return nil
}

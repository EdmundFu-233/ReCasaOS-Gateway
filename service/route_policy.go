package service

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

const (
	maxRoutePathBytes  = 256
	maxRouteOwnerBytes = 128
	minRouteLeaseTTL   = time.Minute
	maxRouteLeaseTTL   = 720 * time.Hour
	legacyImportLease  = 2160 * time.Hour
	SelfRouteOwner     = "gateway-self"
	legacyRouteOwner   = "migrated-legacy"
	routesFileVersion  = 2
)

var (
	// ErrInvalidRoute reports a malformed path, target, or owner. It never
	// carries the offending value.
	ErrInvalidRoute = errors.New("invalid gateway route")
	// ErrRouteOwned reports a path registered to a different owner. Removal
	// and renewal require the owning identity.
	ErrRouteOwned = errors.New("gateway route is owned by another identity")
	// ErrRouteNotFound reports renewal or removal of an unknown or expired
	// path.
	ErrRouteNotFound = errors.New("gateway route not found")
	// ErrRouteTargetForbidden reports a target outside the loopback range
	// and the configured target CIDRs.
	ErrRouteTargetForbidden = errors.New("gateway route target is forbidden")
)

// RouteEntry is one leased route registration. The lease makes stale routes
// die on their own: expiry is checked on every lookup, persistence only
// carries live entries, and removal is durable across restarts.
type RouteEntry struct {
	Path      string `json:"path"`
	Target    string `json:"target"`
	Owner     string `json:"owner"`
	ExpiresAt int64  `json:"expires_at"`
	RenewedAt int64  `json:"renewed_at"`
}

// Expired reports whether the entry is dead at the given time.
func (entry RouteEntry) Expired(now time.Time) bool {
	return !now.Before(time.Unix(entry.ExpiresAt, 0))
}

// RoutePolicy validates registrations and derives client identity. It is
// constructed once from operator configuration; a nil policy is never valid.
type RoutePolicy struct {
	trustedProxies []*net.IPNet
	targetCIDRs    []*net.IPNet
	leaseTTL       time.Duration
	now            func() time.Time
}

// NewRoutePolicy parses comma-separated CIDR lists and a lease TTL. Empty
// CIDR lists mean none; loopback targets are always allowed regardless of
// the target list.
func NewRoutePolicy(trustedProxyCIDRs, targetCIDRs string, leaseTTL time.Duration) (*RoutePolicy, error) {
	if leaseTTL < minRouteLeaseTTL || leaseTTL > maxRouteLeaseTTL {
		return nil, ErrInvalidRoute
	}
	trusted, err := parseCIDRList(trustedProxyCIDRs)
	if err != nil {
		return nil, err
	}
	targets, err := parseCIDRList(targetCIDRs)
	if err != nil {
		return nil, err
	}
	return &RoutePolicy{
		trustedProxies: trusted,
		targetCIDRs:    targets,
		leaseTTL:       leaseTTL,
		now:            time.Now,
	}, nil
}

// ParseRouteLeaseTTL parses durations like "24h" within the allowed range.
func ParseRouteLeaseTTL(raw string) (time.Duration, error) {
	ttl, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil || ttl < minRouteLeaseTTL || ttl > maxRouteLeaseTTL {
		return 0, ErrInvalidRoute
	}
	return ttl, nil
}

// LeaseTTL reports the configured lease duration.
func (policy *RoutePolicy) LeaseTTL() time.Duration {
	if policy == nil {
		return 0
	}
	return policy.leaseTTL
}

func parseCIDRList(raw string) ([]*net.IPNet, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}
	parts := strings.Split(trimmed, ",")
	networks := make([]*net.IPNet, 0, len(parts))
	for _, part := range parts {
		cidr := strings.TrimSpace(part)
		if cidr == "" {
			return nil, ErrInvalidRoute
		}
		if !strings.Contains(cidr, "/") {
			address := net.ParseIP(cidr)
			if address == nil {
				return nil, ErrInvalidRoute
			}
			if address.To4() != nil {
				cidr += "/32"
			} else {
				cidr += "/128"
			}
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, ErrInvalidRoute
		}
		networks = append(networks, network)
	}
	return networks, nil
}

// ValidateRegistration checks one route registration and stamps its lease.
// The caller supplies the authenticated owner; empty owners are rejected so
// every live route has someone responsible for renewing or removing it.
// Reserved namespaces may only be registered by their owning identity: the
// dashboard root and the management subtree belong to the gateway itself,
// and the public-files tombstone belongs to the in-stack root service.
func (policy *RoutePolicy) ValidateRegistration(routePath, target, owner string) (RouteEntry, error) {
	if policy == nil {
		return RouteEntry{}, ErrInvalidRoute
	}
	if err := ValidateRoutePath(routePath); err != nil {
		return RouteEntry{}, err
	}
	if err := policy.ValidateRouteTarget(target); err != nil {
		return RouteEntry{}, err
	}
	if err := ValidateRouteOwner(owner); err != nil {
		return RouteEntry{}, err
	}
	if required, reserved := reservedRouteOwner(routePath); reserved && owner != required {
		return RouteEntry{}, ErrRouteOwned
	}
	now := policy.now().Unix()
	return RouteEntry{
		Path:      routePath,
		Target:    target,
		Owner:     owner,
		ExpiresAt: now + int64(policy.leaseTTL/time.Second),
		RenewedAt: now,
	}, nil
}

// reservedRouteOwner reports the only identity that may register a reserved
// namespace. The dashboard root and the management subtree are served by the
// gateway itself; the public-files path is a 404 tombstone that only the
// in-stack root service may claim, so no user JWT or component can shadow
// them.
func reservedRouteOwner(routePath string) (string, bool) {
	if routePath == "/" || routePath == "/v1/gateway" || strings.HasPrefix(routePath, "/v1/gateway/") {
		return SelfRouteOwner, true
	}
	if routePath == "/public-files" || strings.HasPrefix(routePath, "/public-files/") {
		return ServiceOwner, true
	}
	return "", false
}

// ValidateRoutePath requires an absolute, clean, bounded path. Cleaning is
// never applied silently: a path that is not already canonical is rejected
// so "/a/../b" cannot smuggle a registration for "/b".
func ValidateRoutePath(routePath string) error {
	if routePath == "" || len(routePath) > maxRoutePathBytes || routePath[0] != '/' {
		return ErrInvalidRoute
	}
	if strings.ContainsRune(routePath, 0) || strings.Contains(routePath, "//") {
		return ErrInvalidRoute
	}
	if path.Clean(routePath) != routePath {
		return ErrInvalidRoute
	}
	for i := 0; i < len(routePath); i++ {
		switch character := routePath[i]; {
		case character >= 'a' && character <= 'z',
			character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9',
			character == '-', character == '.', character == '_',
			character == '~', character == '/', character == ':',
			character == '@':
		default:
			return ErrInvalidRoute
		}
	}
	return nil
}

// ValidateRouteOwner requires a bounded printable owner identity.
func ValidateRouteOwner(owner string) error {
	if owner == "" || len(owner) > maxRouteOwnerBytes {
		return ErrInvalidRoute
	}
	for i := 0; i < len(owner); i++ {
		switch character := owner[i]; {
		case character >= 'a' && character <= 'z',
			character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9',
			character == '-', character == '.', character == '_':
		default:
			return ErrInvalidRoute
		}
	}
	return nil
}

// ValidateRouteTarget admits only loopback targets plus the configured
// target CIDRs. DNS names other than localhost are rejected so admission
// never depends on resolution, and link-local, metadata, and multicast
// addresses cannot be reached through the gateway.
func (policy *RoutePolicy) ValidateRouteTarget(target string) error {
	if policy == nil {
		return ErrInvalidRoute
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed == nil {
		return ErrInvalidRoute
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ErrInvalidRoute
	}
	if parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" {
		return ErrInvalidRoute
	}
	host := parsed.Hostname()
	if host == "" {
		return ErrInvalidRoute
	}
	port := parsed.Port()
	if port == "" {
		return ErrInvalidRoute
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	address := net.ParseIP(host)
	if address == nil {
		return ErrRouteTargetForbidden
	}
	if address.IsLoopback() {
		return nil
	}
	for _, network := range policy.targetCIDRs {
		if network.Contains(address) {
			return nil
		}
	}
	return ErrRouteTargetForbidden
}

// MatchSegment reports whether requestPath falls under routePrefix on a
// segment boundary. The root prefix matches everything; "/ab" no longer
// matches "/abcd".
func MatchSegment(requestPath, routePrefix string) bool {
	if routePrefix == "/" {
		return strings.HasPrefix(requestPath, "/")
	}
	return requestPath == routePrefix || strings.HasPrefix(requestPath, routePrefix+"/")
}

// ClientIP derives the client address from the direct peer and forwarding
// headers. Forwarding headers are believed only when the peer itself is a
// configured trusted proxy; otherwise the peer address is the client. When
// several proxies chain, the rightmost untrusted address wins and the rest
// of the chain is discarded rather than trusted.
func (policy *RoutePolicy) ClientIP(remoteAddr, forwardedFor, realIP string) string {
	peer, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		peer = remoteAddr
	}
	peerAddress := net.ParseIP(strings.TrimSpace(peer))
	if policy == nil || peerAddress == nil || !policy.trustedPeer(peerAddress) {
		if peerAddress != nil {
			return peerAddress.String()
		}
		return ""
	}
	chain := parseForwardedChain(forwardedFor)
	if address := rightmostUntrusted(chain, policy.trustedProxies); address != "" {
		return address
	}
	if len(chain) > 0 {
		// Every chain entry is a trusted proxy: the leftmost entry is
		// the client as reported by the first trusted proxy.
		return chain[0]
	}
	if parsed := net.ParseIP(strings.TrimSpace(realIP)); parsed != nil {
		return parsed.String()
	}
	return peerAddress.String()
}

func (policy *RoutePolicy) trustedPeer(address net.IP) bool {
	for _, network := range policy.trustedProxies {
		if network.Contains(address) {
			return true
		}
	}
	return false
}

func parseForwardedChain(forwardedFor string) []string {
	parts := strings.Split(forwardedFor, ",")
	chain := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" || strings.Contains(trimmed, "/") {
			continue
		}
		if parsed := net.ParseIP(trimmed); parsed != nil {
			chain = append(chain, parsed.String())
		}
	}
	return chain
}

func rightmostUntrusted(chain []string, trusted []*net.IPNet) string {
	for index := len(chain) - 1; index >= 0; index-- {
		address := net.ParseIP(chain[index])
		if address == nil {
			continue
		}
		trustedAddress := false
		for _, network := range trusted {
			if network.Contains(address) {
				trustedAddress = true
				break
			}
		}
		if !trustedAddress {
			return address.String()
		}
	}
	return ""
}

// SanitizeProxyHeaders strips every inbound client-identity header before a
// request is proxied, then records the derived client IP as the single
// X-Forwarded-For value. Backends therefore never see spoofed identity, and
// the reverse proxy appends the direct peer on top of a known-good base.
// Beyond the standard forwarding headers, common CDN/proxy client-IP
// headers are removed as well: any backend trusting them would otherwise
// accept spoofed identity straight from the client.
func SanitizeProxyHeaders(header http.Header, clientIP string) {
	header.Del("X-Forwarded-For")
	header.Del("X-Forwarded-Host")
	header.Del("X-Forwarded-Proto")
	header.Del("X-Forwarded-Port")
	header.Del("X-Real-Ip")
	header.Del("X-Real-IP")
	header.Del("X-Client-Ip")
	header.Del("X-Client-IP")
	header.Del("True-Client-Ip")
	header.Del("True-Client-IP")
	header.Del("Cf-Connecting-Ip")
	header.Del("CF-Connecting-IP")
	header.Del("Forwarded")
	header.Del("Forwarded-For")
	if clientIP != "" {
		header.Set("X-Forwarded-For", clientIP)
	}
}

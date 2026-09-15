package route

import (
	"net/http"

	"github.com/IceWhaleTech/CasaOS-Common/utils/logger"
	"github.com/IceWhaleTech/CasaOS-Gateway/service"
	"go.uber.org/zap"
)

type GatewayRoute struct {
	management *service.Management
}

func NewGatewayRoute(management *service.Management) *GatewayRoute {
	return &GatewayRoute{
		management: management,
	}
}

func (g *GatewayRoute) GetRoute() *http.ServeMux {
	gatewayMux := http.NewServeMux()
	gatewayMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ping" {
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte("pong from gateway service")); err != nil {
				logger.Error("Failed to `pong` in resposne to `ping`", zap.Any("error", err))
			}
			return
		}

		proxy := g.management.GetProxy(r.URL.Path)

		if proxy == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Derive the client IP from the direct peer plus forwarding
		// headers believed only from configured trusted proxies, then
		// strip every inbound identity header so backends never see
		// spoofed client addresses.
		policy := g.management.Policy()
		clientIP := policy.ClientIP(
			r.RemoteAddr,
			r.Header.Get("X-Forwarded-For"),
			r.Header.Get("X-Real-IP"),
		)
		service.SanitizeProxyHeaders(r.Header, clientIP)

		proxy.ServeHTTP(w, r)
	})

	return gatewayMux
}

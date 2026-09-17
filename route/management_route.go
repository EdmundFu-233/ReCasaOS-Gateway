package route

import (
	"crypto/ecdsa"
	"net/http"
	"strconv"
	"strings"

	"github.com/IceWhaleTech/CasaOS-Common/external"
	"github.com/IceWhaleTech/CasaOS-Common/model"
	"github.com/IceWhaleTech/CasaOS-Common/utils/common_err"
	"github.com/IceWhaleTech/CasaOS-Common/utils/jwt"
	"github.com/IceWhaleTech/CasaOS-Gateway/service"
	"github.com/labstack/echo/v4"
	echo_middleware "github.com/labstack/echo/v4/middleware"
)

const ownerHeader = "X-Authenticated-User"

// accessTokenIssuer is the only JWT issuer accepted for route management.
// Refresh tokens are signed by the same user-service key but carry the
// "refresh" issuer and must never act as an owner credential.
const accessTokenIssuer = "casaos"

// ManagementRoute serves the route registry. Every mutating and disclosing
// endpoint requires a bearer access token or the local service credential:
// loopback and query-string tokens are never accepted, so a local process
// without credentials cannot rewire the gateway.
type ManagementRoute struct {
	management *service.Management
	origins    []string
}

func NewManagementRoute(management *service.Management) *ManagementRoute {
	return NewManagementRouteWithCORS(management, nil)
}

// NewManagementRouteWithCORS restricts browser-credentialed access to the
// exact origins listed. An empty list means same-origin only: no CORS
// headers are emitted.
func NewManagementRouteWithCORS(management *service.Management, origins []string) *ManagementRoute {
	return &ManagementRoute{
		management: management,
		origins:    origins,
	}
}

func (m *ManagementRoute) GetRoute() http.Handler {
	e := echo.New()
	e.HideBanner = true

	if len(m.origins) > 0 {
		e.Use((echo_middleware.CORSWithConfig(echo_middleware.CORSConfig{
			AllowOrigins:     m.origins,
			AllowMethods:     []string{echo.POST, echo.GET, echo.OPTIONS, echo.PUT, echo.DELETE},
			AllowHeaders:     []string{echo.HeaderAuthorization, echo.HeaderContentLength, echo.HeaderContentType, echo.HeaderOrigin, echo.HeaderXRequestedWith},
			ExposeHeaders:    []string{echo.HeaderContentLength},
			MaxAge:           600,
			AllowCredentials: true,
		})))
	}

	e.GET("/ping", func(ctx echo.Context) error {
		return ctx.JSON(http.StatusOK, echo.Map{
			"message": "pong from management service",
		})
	})

	m.buildV1Group(e)

	return e
}

func (m *ManagementRoute) jwtMiddleware() echo.MiddlewareFunc {
	return echo_middleware.JWTWithConfig(echo_middleware.JWTConfig{
		// No Skipper: local peers authenticate exactly like remote ones.
		// Source locality is transport detail, never identity.
		// Missing, malformed, and invalid credentials all answer 401 so
		// failures are indistinguishable.
		ErrorHandler: func(_ error) error {
			return echo.ErrUnauthorized
		},
		ParseTokenFunc: func(token string, c echo.Context) (interface{}, error) {
			// The local service credential authenticates in-stack component
			// clients (the root service) that cannot present a user JWT. The
			// token is generated per process start and readable only by the
			// owning service UID.
			if service.ServiceTokenMatches(token, m.management.State.GetServiceToken()) {
				c.Request().Header.Set(ownerHeader, service.ServiceOwner)
				return nil, nil
			}
			valid, claims, err := jwt.Validate(token, func() (*ecdsa.PublicKey, error) { return external.GetPublicKey(m.management.State.GetRuntimePath()) })
			if err != nil || !valid || claims == nil || claims.Issuer != accessTokenIssuer {
				return nil, echo.ErrUnauthorized
			}
			c.Request().Header.Set(ownerHeader, "uid-"+strconv.Itoa(claims.ID))
			return claims, nil
		},
		// Authorization header only. Query-string tokens leak into logs,
		// history, and referers and are never accepted.
		TokenLookup: "header:Authorization:Bearer ",
	})
}

func ownerOf(ctx echo.Context) string {
	return strings.TrimSpace(ctx.Request().Header.Get(ownerHeader))
}

func (m *ManagementRoute) buildV1Group(e *echo.Echo) {
	v1Group := e.Group("/v1")
	v1GatewayGroup := v1Group.Group("/gateway", m.jwtMiddleware())

	v1GatewayGroup.GET("/routes", func(ctx echo.Context) error {
		return ctx.JSON(http.StatusOK, m.management.GetRoutes())
	})

	v1GatewayGroup.POST("/routes", func(ctx echo.Context) error {
		var route *model.Route
		if err := ctx.Bind(&route); err != nil || route == nil {
			return ctx.JSON(http.StatusBadRequest, model.Result{
				Success: common_err.CLIENT_ERROR,
				Message: "invalid route",
			})
		}
		if err := m.management.CreateRoute(route, ownerOf(ctx)); err != nil {
			return routeError(ctx, err)
		}
		return ctx.NoContent(http.StatusCreated)
	})

	v1GatewayGroup.POST("/routes/renew", func(ctx echo.Context) error {
		var request struct {
			Path string `json:"path"`
		}
		if err := ctx.Bind(&request); err != nil {
			return ctx.JSON(http.StatusBadRequest, model.Result{
				Success: common_err.CLIENT_ERROR,
				Message: "invalid request",
			})
		}
		if err := m.management.RenewRoute(request.Path, ownerOf(ctx)); err != nil {
			return routeError(ctx, err)
		}
		return ctx.NoContent(http.StatusNoContent)
	})

	v1GatewayGroup.DELETE("/routes", func(ctx echo.Context) error {
		var request struct {
			Path string `json:"path"`
		}
		if err := ctx.Bind(&request); err != nil {
			return ctx.JSON(http.StatusBadRequest, model.Result{
				Success: common_err.CLIENT_ERROR,
				Message: "invalid request",
			})
		}
		if err := m.management.DeleteRoute(request.Path, ownerOf(ctx)); err != nil {
			return routeError(ctx, err)
		}
		return ctx.NoContent(http.StatusNoContent)
	})

	v1GatewayGroup.GET("/port", func(ctx echo.Context) error {
		return ctx.JSON(http.StatusOK, model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
			Data:    m.management.GetGatewayPort(),
		})
	})

	v1GatewayGroup.PUT("/port", func(ctx echo.Context) error {
		var request *model.ChangePortRequest
		if err := ctx.Bind(&request); err != nil || request == nil {
			return ctx.JSON(http.StatusBadRequest, model.Result{
				Success: common_err.CLIENT_ERROR,
				Message: "invalid request",
			})
		}
		if err := m.management.SetGatewayPort(request.Port); err != nil {
			return ctx.JSON(http.StatusInternalServerError, model.Result{
				Success: common_err.SERVICE_ERROR,
				Message: "failed to change port",
			})
		}
		return ctx.JSON(http.StatusOK, model.Result{
			Success: common_err.SUCCESS,
			Message: common_err.GetMsg(common_err.SUCCESS),
		})
	})
}

func routeError(ctx echo.Context, err error) error {
	switch err {
	case service.ErrRouteOwned:
		return ctx.JSON(http.StatusForbidden, model.Result{
			Success: common_err.CLIENT_ERROR,
			Message: "route is owned by another identity",
		})
	case service.ErrRouteNotFound:
		return ctx.JSON(http.StatusNotFound, model.Result{
			Success: common_err.CLIENT_ERROR,
			Message: "route not found",
		})
	default:
		return ctx.JSON(http.StatusBadRequest, model.Result{
			Success: common_err.CLIENT_ERROR,
			Message: "invalid route",
		})
	}
}

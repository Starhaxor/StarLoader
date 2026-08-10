package httpapi

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/netip"
	"time"

	"github.com/starloader/backend/internal/service"
)

type LoginService interface {
	Login(context.Context, service.LoginInput) (service.PendingChallenge, error)
}

type DeviceVerificationService interface {
	Verify(context.Context, service.VerifyInput) (service.VerifiedSession, error)
}

type RouterConfig struct {
	Login               LoginService
	DeviceVerification  DeviceVerificationService
	HealthCheck         func(context.Context) error
	HealthCheckTimeout  time.Duration
	LoginTimeout        time.Duration
	DeviceVerifyTimeout time.Duration
	TrustedProxies      []netip.Prefix
	Logger              *log.Logger
	RateLimitMaxKeys    int
	Now                 func() time.Time
}

type Router struct {
	login               LoginService
	deviceVerification  DeviceVerificationService
	healthCheck         func(context.Context) error
	healthCheckTimeout  time.Duration
	loginTimeout        time.Duration
	deviceVerifyTimeout time.Duration
	trustedProxies      []netip.Prefix
	loginLimiter        *ipRateLimiter
	sessionLimiter      *ipRateLimiter
	handler             http.Handler
}

func NewRouter(config RouterConfig) *Router {
	logger := config.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	healthCheckTimeout := config.HealthCheckTimeout
	if healthCheckTimeout <= 0 {
		healthCheckTimeout = 2 * time.Second
	}
	loginTimeout := config.LoginTimeout
	if loginTimeout <= 0 {
		loginTimeout = 10 * time.Second
	}
	deviceVerifyTimeout := config.DeviceVerifyTimeout
	if deviceVerifyTimeout <= 0 {
		deviceVerifyTimeout = 10 * time.Second
	}
	router := &Router{
		login:               config.Login,
		deviceVerification:  config.DeviceVerification,
		healthCheck:         config.HealthCheck,
		healthCheckTimeout:  healthCheckTimeout,
		loginTimeout:        loginTimeout,
		deviceVerifyTimeout: deviceVerifyTimeout,
		trustedProxies:      append([]netip.Prefix(nil), config.TrustedProxies...),
		loginLimiter:        newIPRateLimiter(5, time.Minute, config.RateLimitMaxKeys, config.Now),
		sessionLimiter:      newIPRateLimiter(10, time.Minute, config.RateLimitMaxKeys, config.Now),
	}
	router.handler = requestIDMiddleware(recoveryMiddleware(logger, http.HandlerFunc(router.route)))
	return router
}

func (router *Router) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	router.handler.ServeHTTP(writer, request)
}

func (router *Router) route(writer http.ResponseWriter, request *http.Request) {
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/v1/auth/login":
		router.handleLogin(writer, request)
	case request.Method == http.MethodPost && request.URL.Path == "/v1/device/verify":
		router.handleDeviceVerify(writer, request)
	case request.Method == http.MethodGet && request.URL.Path == "/healthz":
		router.handleHealth(writer, request)
	case request.URL.Path == "/v1/auth/login" || request.URL.Path == "/v1/device/verify" || request.URL.Path == "/healthz":
		writeError(writer, request, http.StatusMethodNotAllowed, "INVALID_REQUEST", "method not allowed")
	default:
		writeError(writer, request, http.StatusNotFound, "INVALID_REQUEST", "not found")
	}
}

func (router *Router) handleHealth(writer http.ResponseWriter, request *http.Request) {
	if router.healthCheck != nil {
		ctx, cancel := context.WithTimeout(request.Context(), router.healthCheckTimeout)
		defer cancel()
		if err := router.healthCheck(ctx); err != nil {
			writeError(writer, request, http.StatusServiceUnavailable, "SERVER_ERROR", "service unavailable")
			return
		}
	}
	writeJSON(writer, http.StatusOK, struct {
		OK bool `json:"ok"`
	}{OK: true})
}

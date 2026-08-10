package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/starloader/backend/internal/config"
	"github.com/starloader/backend/internal/httpapi"
	"github.com/starloader/backend/internal/security"
	"github.com/starloader/backend/internal/service"
	"github.com/starloader/backend/internal/store"
)

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run() error {
	configuration, err := config.Load()
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	trustedProxies := make([]netip.Prefix, 0)
	for _, configuredProxy := range strings.Split(os.Getenv("TRUSTED_PROXIES"), ",") {
		configuredProxy = strings.TrimSpace(configuredProxy)
		if configuredProxy == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(configuredProxy)
		if err != nil {
			return errors.New("configuration error: TRUSTED_PROXIES contains an invalid network")
		}
		trustedProxies = append(trustedProxies, prefix)
	}

	applicationCtx, cancelApplication := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancelApplication()
	pool, err := pgxpool.New(applicationCtx, configuration.DatabaseURL)
	if err != nil {
		return errors.New("database configuration failed")
	}
	defer pool.Close()
	startupCtx, cancelStartup := context.WithTimeout(applicationCtx, 10*time.Second)
	defer cancelStartup()
	if err := pool.Ping(startupCtx); err != nil {
		return errors.New("database connection failed")
	}

	repository := store.New(pool)
	loginService := service.NewLoginService(repository, []byte(configuration.LicenseHMACKey), configuration.Product)
	privateKey, err := security.ParseEd25519PrivateKey(configuration.Ed25519PrivateKey)
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}
	tokenIssuer, err := security.NewTokenIssuer(privateKey, configuration.LicenseIssuer, configuration.LicenseAudience, configuration.Product)
	if err != nil {
		return errors.New("configuration error: invalid token issuer configuration")
	}
	deviceService := service.NewDeviceService(service.NewStoreDeviceRepository(repository), service.DeviceServiceConfig{
		HardwareHMACKey: []byte(configuration.HardwareHMACKey),
		TokenIssuer:     tokenIssuer,
		Issuer:          configuration.LicenseIssuer,
		Audience:        configuration.LicenseAudience,
		Product:         configuration.Product,
	})
	router := httpapi.NewRouter(httpapi.RouterConfig{
		Login:              loginService,
		DeviceVerification: deviceService,
		LoginTimeout:       configuration.LoginTimeout,
		TrustedProxies:     trustedProxies,
		Logger:             log.Default(),
		HealthCheck:        pool.Ping,
	})
	address := strings.TrimSpace(os.Getenv("SERVER_ADDR"))
	if address == "" {
		address = ":8080"
	}
	server := newHTTPServer(address, router, applicationCtx)

	log.Printf("license service listening on %s", address)
	if err := serveUntilStopped(applicationCtx, cancelApplication, server, 10*time.Second); err != nil {
		return fmt.Errorf("server stopped: %w", err)
	}
	return nil
}

func newHTTPServer(address string, handler http.Handler, applicationCtx context.Context) *http.Server {
	return &http.Server{
		Addr:    address,
		Handler: handler,
		BaseContext: func(net.Listener) context.Context {
			return applicationCtx
		},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
}

type managedHTTPServer interface {
	Shutdown(context.Context) error
	Close() error
}

type runningHTTPServer interface {
	managedHTTPServer
	ListenAndServe() error
}

func serveUntilStopped(applicationCtx context.Context, cancelApplication context.CancelFunc, server runningHTTPServer, gracePeriod time.Duration) error {
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case <-applicationCtx.Done():
		return shutdownServer(server, cancelApplication, gracePeriod)
	case err := <-serverErrors:
		cancelApplication()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func shutdownServer(server managedHTTPServer, cancelApplication context.CancelFunc, gracePeriod time.Duration) error {
	cancelApplication()
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), gracePeriod)
	defer cancelShutdown()
	if err := server.Shutdown(shutdownCtx); err != nil {
		if closeErr := server.Close(); closeErr != nil {
			return errors.Join(err, closeErr)
		}
		return err
	}
	return nil
}

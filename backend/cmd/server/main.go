package main

import (
	"context"
	"errors"
	"log"
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
	"github.com/starloader/backend/internal/service"
	"github.com/starloader/backend/internal/store"
)

func main() {
	configuration, err := config.Load()
	if err != nil {
		log.Fatal("configuration error: ", err)
	}

	trustedProxies := make([]netip.Prefix, 0)
	for _, configuredProxy := range strings.Split(os.Getenv("TRUSTED_PROXIES"), ",") {
		configuredProxy = strings.TrimSpace(configuredProxy)
		if configuredProxy == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(configuredProxy)
		if err != nil {
			log.Fatal("configuration error: TRUSTED_PROXIES contains an invalid network")
		}
		trustedProxies = append(trustedProxies, prefix)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	pool, err := pgxpool.New(ctx, configuration.DatabaseURL)
	if err != nil {
		log.Fatal("database configuration failed")
	}
	defer pool.Close()
	startupCtx, cancelStartup := context.WithTimeout(ctx, 10*time.Second)
	defer cancelStartup()
	if err := pool.Ping(startupCtx); err != nil {
		log.Fatal("database connection failed")
	}

	repository := store.New(pool)
	loginService := service.NewLoginService(repository, []byte(configuration.LicenseHMACKey), configuration.Product)
	router := httpapi.NewRouter(httpapi.RouterConfig{
		Login:          loginService,
		TrustedProxies: trustedProxies,
		Logger:         log.Default(),
		HealthCheck:    pool.Ping,
	})
	address := strings.TrimSpace(os.Getenv("SERVER_ADDR"))
	if address == "" {
		address = ":8080"
	}
	server := &http.Server{
		Addr:              address,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	serverErrors := make(chan error, 1)
	go func() {
		log.Printf("license service listening on %s", address)
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Print("server shutdown failed")
		}
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatal("server stopped unexpectedly: ", err)
		}
	}
}

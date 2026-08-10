package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/starloader/backend/internal/httpapi"
	"github.com/starloader/backend/internal/service"
)

func TestApplicationContextCancellationStopsActiveLoginHandler(t *testing.T) {
	applicationCtx, cancelApplication := context.WithCancel(context.Background())
	serviceStarted := make(chan struct{})
	serviceCanceled := make(chan error, 1)
	loginService := loginServiceFunc(func(ctx context.Context, _ service.LoginInput) (service.PendingChallenge, error) {
		close(serviceStarted)
		<-ctx.Done()
		serviceCanceled <- ctx.Err()
		return service.PendingChallenge{}, ctx.Err()
	})
	router := httpapi.NewRouter(httpapi.RouterConfig{
		Login:        loginService,
		LoginTimeout: time.Hour,
	})
	server := newHTTPServer(":0", router, applicationCtx)
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{"email":"a@b.c","password":"x","license_key":"K","device_fingerprint":"F"}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(server.BaseContext(nil))
	rr := httptest.NewRecorder()
	handlerDone := make(chan struct{})
	go func() {
		server.Handler.ServeHTTP(rr, req)
		close(handlerDone)
	}()

	waitForTestSignal(t, serviceStarted, "login service to start")
	cancelApplication()
	waitForTestSignal(t, handlerDone, "login handler to stop")

	if err := <-serviceCanceled; !errors.Is(err, context.Canceled) {
		t.Fatalf("service context error = %v, want canceled", err)
	}
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}
}

func TestShutdownTimeoutForceClosesServer(t *testing.T) {
	applicationCtx, cancelApplication := context.WithCancel(context.Background())
	server := &shutdownRecorder{applicationCtx: applicationCtx}

	err := shutdownServer(server, cancelApplication, 10*time.Millisecond)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdownServer() error = %v, want deadline exceeded", err)
	}
	if !server.cancelObserved {
		t.Fatal("Shutdown() began before the application context was canceled")
	}
	if server.shutdownCalls != 1 || server.closeCalls != 1 {
		t.Fatalf("calls: Shutdown=%d Close=%d, want 1 each", server.shutdownCalls, server.closeCalls)
	}
}

func TestServeUntilStoppedReturnsUnexpectedListenerFailure(t *testing.T) {
	applicationCtx, cancelApplication := context.WithCancel(context.Background())
	listenErr := errors.New("bind failed")
	server := &listenFailureServer{err: listenErr}

	err := serveUntilStopped(applicationCtx, cancelApplication, server, 10*time.Millisecond)

	if !errors.Is(err, listenErr) {
		t.Fatalf("serveUntilStopped() error = %v, want %v", err, listenErr)
	}
	if !errors.Is(applicationCtx.Err(), context.Canceled) {
		t.Fatalf("application context error = %v, want canceled", applicationCtx.Err())
	}
}

type loginServiceFunc func(context.Context, service.LoginInput) (service.PendingChallenge, error)

func (login loginServiceFunc) Login(ctx context.Context, input service.LoginInput) (service.PendingChallenge, error) {
	return login(ctx, input)
}

type shutdownRecorder struct {
	applicationCtx context.Context
	cancelObserved bool
	shutdownCalls  int
	closeCalls     int
}

type listenFailureServer struct {
	err error
}

func (server *listenFailureServer) ListenAndServe() error {
	return server.err
}

func (*listenFailureServer) Shutdown(context.Context) error {
	return nil
}

func (*listenFailureServer) Close() error {
	return nil
}

func (server *shutdownRecorder) Shutdown(ctx context.Context) error {
	server.shutdownCalls++
	server.cancelObserved = errors.Is(server.applicationCtx.Err(), context.Canceled)
	<-ctx.Done()
	return ctx.Err()
}

func (server *shutdownRecorder) Close() error {
	server.closeCalls++
	return nil
}

func waitForTestSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

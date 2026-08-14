package adminauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/starloader/backend/internal/domain"
	"github.com/starloader/backend/internal/security"
)

type fakeStore struct {
	account          *domain.AdminAccount
	findErr          error
	createSessionErr error
	loadErr          error
	createdSessions  []domain.NewAdminSession
	auditEntries     []domain.NewAuditLog
	revokedSessionID string
}

func (f *fakeStore) FindAdminAccountByEmail(_ context.Context, email string) (*domain.AdminAccount, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	if f.account == nil || f.account.Email != email {
		return nil, domain.ErrAdminNotFound
	}
	return f.account, nil
}

func (f *fakeStore) CreateAdminSession(_ context.Context, input domain.NewAdminSession) (*domain.AdminSession, error) {
	if f.createSessionErr != nil {
		return nil, f.createSessionErr
	}
	f.createdSessions = append(f.createdSessions, input)
	return &domain.AdminSession{ID: "session-id", AdminAccountID: input.AdminAccountID, TokenSHA256: input.TokenSHA256}, nil
}

func (f *fakeStore) LoadActiveAdminSession(_ context.Context, tokenSHA256 []byte) (*domain.AdminSession, *domain.AdminAccount, error) {
	if f.loadErr != nil {
		return nil, nil, f.loadErr
	}
	if len(f.createdSessions) == 0 {
		return nil, nil, domain.ErrAdminSessionNotFound
	}
	last := f.createdSessions[len(f.createdSessions)-1]
	if f.revokedSessionID != "" {
		return nil, nil, domain.ErrAdminSessionNotFound
	}
	if !bytes.Equal(last.TokenSHA256, tokenSHA256) {
		return nil, nil, domain.ErrAdminSessionNotFound
	}
	return &domain.AdminSession{ID: "session-id", AdminAccountID: last.AdminAccountID}, f.account, nil
}

func (f *fakeStore) RevokeAdminSession(_ context.Context, sessionID string) error {
	f.revokedSessionID = sessionID
	return nil
}

func (f *fakeStore) AppendAuditLog(_ context.Context, input domain.NewAuditLog) error {
	f.auditEntries = append(f.auditEntries, input)
	return nil
}

func newTestAccount(t *testing.T, password string) *domain.AdminAccount {
	t.Helper()
	hash, err := security.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	return &domain.AdminAccount{ID: "admin-id", Email: "root@example.com", PasswordHash: hash, Status: domain.AdminStatusActive}
}

func newTestService(store Store) *Service {
	return New(store, Config{SessionTTL: time.Hour})
}

func TestLoginIssuesTokenPersistsDigestAndAudits(t *testing.T) {
	store := &fakeStore{account: newTestAccount(t, "correct admin password")}
	service := newTestService(store)

	token, account, err := service.Login(context.Background(), "root@example.com", "correct admin password", "10.0.0.1", "test-agent")
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != sessionTokenBytes*2 {
		t.Fatalf("token length = %d, want %d hex characters", len(token), sessionTokenBytes*2)
	}
	if account.Email != "root@example.com" {
		t.Fatalf("account = %#v", account)
	}
	if len(store.createdSessions) != 1 {
		t.Fatalf("created sessions = %d, want 1", len(store.createdSessions))
	}
	tokenBytes, _ := hex.DecodeString(token)
	digest := sha256.Sum256(tokenBytes)
	if !bytes.Equal(store.createdSessions[0].TokenSHA256, digest[:]) {
		t.Fatal("persisted token digest does not match the issued token")
	}
	if len(store.auditEntries) != 1 || store.auditEntries[0].Action != actionLogin || store.auditEntries[0].AdminAccountID != "admin-id" {
		t.Fatalf("audit entries = %#v", store.auditEntries)
	}
	if store.auditEntries[0].IPSHA256 == "" {
		t.Fatal("login audit entry is missing the hashed IP")
	}
}

func TestLoginRejectsWrongPasswordWithGenericError(t *testing.T) {
	store := &fakeStore{account: newTestAccount(t, "correct admin password")}
	service := newTestService(store)

	_, _, err := service.Login(context.Background(), "root@example.com", "wrong password", "10.0.0.1", "")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login() error = %v, want invalid credentials", err)
	}
	if len(store.auditEntries) != 1 || store.auditEntries[0].Action != actionLoginFailed {
		t.Fatalf("audit entries = %#v", store.auditEntries)
	}
}

func TestLoginRejectsUnknownEmailWithGenericError(t *testing.T) {
	store := &fakeStore{}
	service := newTestService(store)

	_, _, err := service.Login(context.Background(), "nobody@example.com", "any password", "10.0.0.1", "")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login() error = %v, want invalid credentials", err)
	}
	if len(store.auditEntries) != 1 || store.auditEntries[0].Action != actionLoginFailed || store.auditEntries[0].ActorEmail != "nobody@example.com" {
		t.Fatalf("audit entries = %#v", store.auditEntries)
	}
	if store.auditEntries[0].AdminAccountID != "" {
		t.Fatal("failed login for unknown email must not reference an account")
	}
}

func TestLoginRejectsDisabledAccount(t *testing.T) {
	account := newTestAccount(t, "correct admin password")
	account.Status = domain.AdminStatusDisabled
	store := &fakeStore{account: account}
	service := newTestService(store)

	_, _, err := service.Login(context.Background(), "root@example.com", "correct admin password", "10.0.0.1", "")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login() error = %v, want invalid credentials", err)
	}
	if len(store.createdSessions) != 0 {
		t.Fatal("disabled account must not receive a session")
	}
}

func TestAuthenticateResolvesIssuedToken(t *testing.T) {
	store := &fakeStore{account: newTestAccount(t, "correct admin password")}
	service := newTestService(store)
	token, _, err := service.Login(context.Background(), "root@example.com", "correct admin password", "10.0.0.1", "")
	if err != nil {
		t.Fatal(err)
	}

	session, account, err := service.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if session.ID != "session-id" || account.Email != "root@example.com" {
		t.Fatalf("session = %#v, account = %#v", session, account)
	}
}

func TestAuthenticateRejectsMalformedTokens(t *testing.T) {
	store := &fakeStore{account: newTestAccount(t, "correct admin password")}
	service := newTestService(store)

	for _, token := range []string{"", "zz", "00", string(make([]byte, 200))} {
		if _, _, err := service.Authenticate(context.Background(), token); !errors.Is(err, domain.ErrAdminSessionNotFound) {
			t.Fatalf("Authenticate(%q) error = %v, want session not found", token, err)
		}
	}
}

func TestLogoutRevokesTheSessionAndAudits(t *testing.T) {
	store := &fakeStore{account: newTestAccount(t, "correct admin password")}
	service := newTestService(store)
	token, _, err := service.Login(context.Background(), "root@example.com", "correct admin password", "10.0.0.1", "")
	if err != nil {
		t.Fatal(err)
	}

	if err := service.Logout(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	if store.revokedSessionID != "session-id" {
		t.Fatalf("revoked session = %q, want session-id", store.revokedSessionID)
	}
	last := store.auditEntries[len(store.auditEntries)-1]
	if last.Action != actionLogout || last.AdminAccountID != "admin-id" {
		t.Fatalf("logout audit entry = %#v", last)
	}
}

func TestLogoutIsIdempotentForUnknownTokens(t *testing.T) {
	store := &fakeStore{}
	service := newTestService(store)
	if err := service.Logout(context.Background(), "unknown-token"); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
}

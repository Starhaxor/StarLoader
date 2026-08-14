// Package adminauth implements dashboard administrator authentication,
// fully separate from end-user license authentication.
package adminauth

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/starloader/backend/internal/domain"
	"github.com/starloader/backend/internal/security"
)

// ErrInvalidCredentials is the single generic login failure; it never reveals
// whether the account exists or the password was wrong.
var ErrInvalidCredentials = errors.New("invalid admin credentials")

const (
	sessionTokenBytes   = 32
	maxStoredUserAgent  = 200
	actionLogin         = "ADMIN_LOGIN"
	actionLoginFailed   = "ADMIN_LOGIN_FAILED"
	actionLogout        = "ADMIN_LOGOUT"
)

// Store is the persistence boundary for admin authentication.
type Store interface {
	FindAdminAccountByEmail(ctx context.Context, email string) (*domain.AdminAccount, error)
	CreateAdminSession(ctx context.Context, input domain.NewAdminSession) (*domain.AdminSession, error)
	LoadActiveAdminSession(ctx context.Context, tokenSHA256 []byte) (*domain.AdminSession, *domain.AdminAccount, error)
	RevokeAdminSession(ctx context.Context, sessionID string) error
	AppendAuditLog(ctx context.Context, input domain.NewAuditLog) error
}

type Config struct {
	SessionTTL time.Duration
	Random     io.Reader
	Now        func() time.Time
}

type Service struct {
	store      Store
	sessionTTL time.Duration
	random     io.Reader
	now        func() time.Time
	dummyOnce  sync.Once
	dummyHash  string
}

func New(store Store, config Config) *Service {
	if store == nil {
		panic("adminauth store is required")
	}
	if config.SessionTTL <= 0 {
		config.SessionTTL = 12 * time.Hour
	}
	if config.Random == nil {
		config.Random = cryptorand.Reader
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Service{store: store, sessionTTL: config.SessionTTL, random: config.Random, now: config.Now}
}

// SessionTTL reports how long issued admin sessions live.
func (s *Service) SessionTTL() time.Duration {
	return s.sessionTTL
}

// Login verifies credentials and issues an opaque session token. Only the
// SHA-256 digest of the token is persisted; every outcome is audited.
func (s *Service) Login(ctx context.Context, email, password, ipAddress, userAgent string) (string, *domain.AdminAccount, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	userAgent = truncateUserAgent(userAgent)

	account, err := s.store.FindAdminAccountByEmail(ctx, email)
	if errors.Is(err, domain.ErrAdminNotFound) {
		s.verifyDummyPassword(password)
		if auditErr := s.audit(ctx, domain.NewAuditLog{
			ActorEmail: email, Action: actionLoginFailed, IPSHA256: hashIP(ipAddress), UserAgent: userAgent,
		}); auditErr != nil {
			return "", nil, auditErr
		}
		return "", nil, ErrInvalidCredentials
	}
	if err != nil {
		return "", nil, fmt.Errorf("admin login: %w", err)
	}
	if account.Status != domain.AdminStatusActive {
		if auditErr := s.audit(ctx, domain.NewAuditLog{
			AdminAccountID: account.ID, ActorEmail: account.Email, Action: actionLoginFailed,
			IPSHA256: hashIP(ipAddress), UserAgent: userAgent,
		}); auditErr != nil {
			return "", nil, auditErr
		}
		return "", nil, ErrInvalidCredentials
	}

	passwordOK, verifyErr := security.VerifyPassword(account.PasswordHash, password)
	if verifyErr != nil || !passwordOK {
		if auditErr := s.audit(ctx, domain.NewAuditLog{
			AdminAccountID: account.ID, ActorEmail: account.Email, Action: actionLoginFailed,
			IPSHA256: hashIP(ipAddress), UserAgent: userAgent,
		}); auditErr != nil {
			return "", nil, auditErr
		}
		return "", nil, ErrInvalidCredentials
	}

	tokenValue := make([]byte, sessionTokenBytes)
	if _, err := io.ReadFull(s.random, tokenValue); err != nil {
		return "", nil, fmt.Errorf("generate admin session token: %w", err)
	}
	tokenDigest := sha256.Sum256(tokenValue)
	if _, err := s.store.CreateAdminSession(ctx, domain.NewAdminSession{
		AdminAccountID: account.ID,
		TokenSHA256:    tokenDigest[:],
		IPAddress:      ipAddress,
		UserAgent:      userAgent,
		ExpiresAt:      s.now().Add(s.sessionTTL),
	}); err != nil {
		return "", nil, fmt.Errorf("create admin session: %w", err)
	}
	if err := s.audit(ctx, domain.NewAuditLog{
		AdminAccountID: account.ID, ActorEmail: account.Email, Action: actionLogin,
		IPSHA256: hashIP(ipAddress), UserAgent: userAgent,
	}); err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(tokenValue), account, nil
}

// Authenticate resolves a presented session token to an active session and
// its account.
func (s *Service) Authenticate(ctx context.Context, token string) (*domain.AdminSession, *domain.AdminAccount, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(token))
	if err != nil || len(raw) != sessionTokenBytes {
		return nil, nil, domain.ErrAdminSessionNotFound
	}
	tokenDigest := sha256.Sum256(raw)
	session, account, err := s.store.LoadActiveAdminSession(ctx, tokenDigest[:])
	if err != nil {
		return nil, nil, err
	}
	return session, account, nil
}

// Logout revokes the presented session. Unknown or already revoked tokens are
// accepted silently so logout stays idempotent.
func (s *Service) Logout(ctx context.Context, token string) error {
	session, account, err := s.Authenticate(ctx, token)
	if err != nil {
		return nil
	}
	if err := s.store.RevokeAdminSession(ctx, session.ID); err != nil {
		return fmt.Errorf("admin logout: %w", err)
	}
	return s.audit(ctx, domain.NewAuditLog{
		AdminAccountID: account.ID, ActorEmail: account.Email, Action: actionLogout,
	})
}

func (s *Service) audit(ctx context.Context, entry domain.NewAuditLog) error {
	if err := s.store.AppendAuditLog(ctx, entry); err != nil {
		return fmt.Errorf("audit admin activity: %w", err)
	}
	return nil
}

// verifyDummyPassword performs a throwaway Argon2id verification when the
// account does not exist so timing does not reveal account membership.
func (s *Service) verifyDummyPassword(password string) {
	s.dummyOnce.Do(func() {
		hash, err := security.HashPassword("starloader-admin-dummy-password")
		if err == nil {
			s.dummyHash = hash
		}
	})
	if s.dummyHash == "" {
		return
	}
	_, _ = security.VerifyPassword(s.dummyHash, password)
}

func truncateUserAgent(userAgent string) string {
	userAgent = strings.TrimSpace(userAgent)
	if len(userAgent) > maxStoredUserAgent {
		return userAgent[:maxStoredUserAgent]
	}
	return userAgent
}

func hashIP(ipAddress string) string {
	ipAddress = strings.TrimSpace(ipAddress)
	if ipAddress == "" || ipAddress == "unknown" {
		return ""
	}
	digest := sha256.Sum256([]byte(ipAddress))
	return hex.EncodeToString(digest[:])
}

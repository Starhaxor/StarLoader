// Package adminauth implements dashboard administrator authentication,
// fully separate from end-user license authentication.
package adminauth

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/starloader/backend/internal/domain"
	"github.com/starloader/backend/internal/security"
)

var (
	// ErrInvalidCredentials is the single generic login failure; it never
	// reveals whether the account exists or the password was wrong.
	ErrInvalidCredentials = errors.New("invalid admin credentials")
	// ErrInvalidMFACode covers both wrong TOTP codes and unknown recovery
	// codes with one generic message.
	ErrInvalidMFACode = errors.New("invalid mfa code")
	// ErrMFAChallengeExpired signals a stale or replayed challenge token.
	ErrMFAChallengeExpired = errors.New("mfa challenge expired")
	// ErrMFANotEnrolled rejects MFA completion for accounts without TOTP.
	ErrMFANotEnrolled = errors.New("mfa not enrolled")
	// ErrMFAAlreadyEnrolled rejects repeated enrollment confirmation.
	ErrMFAAlreadyEnrolled = errors.New("mfa already enrolled")
)

const (
	sessionTokenBytes  = 32
	challengeTokenBytes = 32
	maxStoredUserAgent = 200
	actionLogin        = "ADMIN_LOGIN"
	actionLoginFailed  = "ADMIN_LOGIN_FAILED"
	actionLogout       = "ADMIN_LOGOUT"
	actionMFAEnrolled  = "ADMIN_MFA_ENROLLED"
	actionMFADisabled  = "ADMIN_MFA_DISABLED"
	// RecoveryCodeCount is how many single-use recovery codes enrollment
	// issues; they are only shown once.
	RecoveryCodeCount = 10
	recoveryCodeBytes = 8
)

// recoveryAlphabet avoids ambiguous glyphs (0/O, 1/I/L).
const recoveryAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// Store is the persistence boundary for admin authentication.
type Store interface {
	FindAdminAccountByEmail(ctx context.Context, email string) (*domain.AdminAccount, error)
	FindAdminAccountByID(ctx context.Context, adminID string) (*domain.AdminAccount, error)
	CreateAdminSession(ctx context.Context, input domain.NewAdminSession) (*domain.AdminSession, error)
	LoadActiveAdminSession(ctx context.Context, tokenSHA256 []byte) (*domain.AdminSession, *domain.AdminAccount, error)
	RevokeAdminSession(ctx context.Context, sessionID string) error
	AppendAuditLog(ctx context.Context, input domain.NewAuditLog) error
	CreateAdminMFAChallenge(ctx context.Context, input domain.NewAdminMFAChallenge) (*domain.AdminMFAChallenge, error)
	ConsumeAdminMFAChallenge(ctx context.Context, tokenSHA256 []byte) (*domain.AdminMFAChallenge, error)
	StartAdminTOTPEnrollment(ctx context.Context, adminID, secret string) error
	ConfirmAdminTOTPEnrollment(ctx context.Context, adminID string) error
	DisableAdminMFA(ctx context.Context, adminID string) error
	ReplaceAdminRecoveryCodes(ctx context.Context, adminID string, codeHashes [][]byte) error
	ConsumeAdminRecoveryCode(ctx context.Context, adminID string, codeSHA256 []byte) error
	RevokeAllAdminSessions(ctx context.Context, adminID string) error
}

type Config struct {
	SessionTTL   time.Duration
	ChallengeTTL time.Duration
	Random       io.Reader
	Now          func() time.Time
}

// LoginResult carries either a finished session (Token) or a pending MFA
// challenge (ChallengeToken) after successful password verification.
type LoginResult struct {
	Token          string
	ChallengeToken string
	MFARequired    bool
	Account        *domain.AdminAccount
}

type Service struct {
	store        Store
	sessionTTL   time.Duration
	challengeTTL time.Duration
	random       io.Reader
	now          func() time.Time
	dummyOnce    sync.Once
	dummyHash    string
}

func New(store Store, config Config) *Service {
	if store == nil {
		panic("adminauth store is required")
	}
	if config.SessionTTL <= 0 {
		config.SessionTTL = 12 * time.Hour
	}
	if config.ChallengeTTL <= 0 {
		config.ChallengeTTL = 5 * time.Minute
	}
	if config.Random == nil {
		config.Random = cryptorand.Reader
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Service{
		store:        store,
		sessionTTL:   config.SessionTTL,
		challengeTTL: config.ChallengeTTL,
		random:       config.Random,
		now:          config.Now,
	}
}

// SessionTTL reports how long issued admin sessions live.
func (s *Service) SessionTTL() time.Duration {
	return s.sessionTTL
}

// Login verifies credentials. Accounts with enrolled TOTP receive a
// short-lived challenge token instead of a session; the session is issued by
// CompleteMFA. Every outcome is audited.
func (s *Service) Login(ctx context.Context, email, password, ipAddress, userAgent string) (LoginResult, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	userAgent = truncateUserAgent(userAgent)

	account, err := s.store.FindAdminAccountByEmail(ctx, email)
	if errors.Is(err, domain.ErrAdminNotFound) {
		s.verifyDummyPassword(password)
		if auditErr := s.audit(ctx, domain.NewAuditLog{
			ActorEmail: email, Action: actionLoginFailed, IPSHA256: hashIP(ipAddress), UserAgent: userAgent,
		}); auditErr != nil {
			return LoginResult{}, auditErr
		}
		return LoginResult{}, ErrInvalidCredentials
	}
	if err != nil {
		return LoginResult{}, fmt.Errorf("admin login: %w", err)
	}
	if account.Status != domain.AdminStatusActive {
		if auditErr := s.audit(ctx, domain.NewAuditLog{
			AdminAccountID: account.ID, ActorEmail: account.Email, Action: actionLoginFailed,
			IPSHA256: hashIP(ipAddress), UserAgent: userAgent,
		}); auditErr != nil {
			return LoginResult{}, auditErr
		}
		return LoginResult{}, ErrInvalidCredentials
	}

	passwordOK, verifyErr := security.VerifyPassword(account.PasswordHash, password)
	if verifyErr != nil || !passwordOK {
		if auditErr := s.audit(ctx, domain.NewAuditLog{
			AdminAccountID: account.ID, ActorEmail: account.Email, Action: actionLoginFailed,
			IPSHA256: hashIP(ipAddress), UserAgent: userAgent,
		}); auditErr != nil {
			return LoginResult{}, auditErr
		}
		return LoginResult{}, ErrInvalidCredentials
	}

	if account.MFAEnrolled {
		challengeToken, challengeErr := s.issueChallenge(ctx, account, ipAddress, userAgent)
		if challengeErr != nil {
			return LoginResult{}, challengeErr
		}
		return LoginResult{ChallengeToken: challengeToken, MFARequired: true, Account: account}, nil
	}

	tokenValue, err := s.createSession(ctx, account, ipAddress, userAgent, actionLogin)
	if err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Token: tokenValue, Account: account}, nil
}

// CompleteMFA finishes a password-verified login with either a TOTP code or a
// single-use recovery code. The challenge is consumed exactly once.
func (s *Service) CompleteMFA(ctx context.Context, challengeToken, code, recoveryCode, ipAddress, userAgent string) (string, *domain.AdminAccount, error) {
	userAgent = truncateUserAgent(userAgent)
	rawToken, err := hex.DecodeString(strings.TrimSpace(challengeToken))
	if err != nil || len(rawToken) != challengeTokenBytes {
		return "", nil, ErrMFAChallengeExpired
	}
	challengeDigest := sha256.Sum256(rawToken)
	challenge, err := s.store.ConsumeAdminMFAChallenge(ctx, challengeDigest[:])
	if errors.Is(err, domain.ErrAdminMFAChallengeNotFound) {
		return "", nil, ErrMFAChallengeExpired
	}
	if err != nil {
		return "", nil, fmt.Errorf("complete admin mfa: %w", err)
	}
	account, err := s.loadActiveAccount(ctx, challenge.AdminAccountID)
	if err != nil {
		return "", nil, err
	}
	if !account.MFAEnrolled || account.TOTPSecret == "" {
		return "", nil, ErrMFANotEnrolled
	}

	switch {
	case strings.TrimSpace(recoveryCode) != "":
		digest := sha256.Sum256([]byte(normalizeRecoveryCode(recoveryCode)))
		if consumeErr := s.store.ConsumeAdminRecoveryCode(ctx, account.ID, digest[:]); consumeErr != nil {
			if errors.Is(consumeErr, domain.ErrAdminRecoveryCodeNotFound) {
				s.auditMFAFailure(ctx, account, ipAddress, userAgent, "recovery")
				return "", nil, ErrInvalidMFACode
			}
			return "", nil, fmt.Errorf("consume recovery code: %w", consumeErr)
		}
	case strings.TrimSpace(code) != "":
		if !security.ValidateTOTPCode(account.TOTPSecret, code, s.now()) {
			s.auditMFAFailure(ctx, account, ipAddress, userAgent, "totp")
			return "", nil, ErrInvalidMFACode
		}
	default:
		return "", nil, ErrInvalidMFACode
	}

	tokenValue, err := s.createSession(ctx, account, ipAddress, userAgent, actionLogin)
	if err != nil {
		return "", nil, err
	}
	return tokenValue, account, nil
}

// StartMFAEnrollment generates and stores a pending TOTP secret for an
// authenticated administrator and returns it with the provisioning URI.
func (s *Service) StartMFAEnrollment(ctx context.Context, account *domain.AdminAccount, issuer string) (secret, provisioningURI string, err error) {
	if account.MFAEnrolled {
		return "", "", ErrMFAAlreadyEnrolled
	}
	secret, err = security.GenerateTOTPSecret(s.random)
	if err != nil {
		return "", "", err
	}
	if err := s.store.StartAdminTOTPEnrollment(ctx, account.ID, secret); err != nil {
		return "", "", fmt.Errorf("start mfa enrollment: %w", err)
	}
	return secret, security.TOTPProvisioningURI(secret, account.Email, issuer), nil
}

// ConfirmMFAEnrollment validates the first TOTP code, activates MFA and
// returns the one-time recovery codes.
func (s *Service) ConfirmMFAEnrollment(ctx context.Context, account *domain.AdminAccount, code, ipAddress, userAgent string) ([]string, error) {
	if account.MFAEnrolled {
		return nil, ErrMFAAlreadyEnrolled
	}
	if account.TOTPSecret == "" {
		return nil, ErrMFANotEnrolled
	}
	if !security.ValidateTOTPCode(account.TOTPSecret, code, s.now()) {
		return nil, ErrInvalidMFACode
	}
	plainCodes, digests, err := generateRecoveryCodes(s.random)
	if err != nil {
		return nil, err
	}
	if err := s.store.ReplaceAdminRecoveryCodes(ctx, account.ID, digests); err != nil {
		return nil, fmt.Errorf("store recovery codes: %w", err)
	}
	if err := s.store.ConfirmAdminTOTPEnrollment(ctx, account.ID); err != nil {
		return nil, fmt.Errorf("confirm mfa enrollment: %w", err)
	}
	if err := s.audit(ctx, domain.NewAuditLog{
		AdminAccountID: account.ID, ActorEmail: account.Email, Action: actionMFAEnrolled,
		IPSHA256: hashIP(ipAddress), UserAgent: truncateUserAgent(userAgent),
	}); err != nil {
		return nil, err
	}
	return plainCodes, nil
}

// DisableMFA turns MFA off after re-verifying the account password, deletes
// the recovery codes and revokes every active session of the account.
func (s *Service) DisableMFA(ctx context.Context, account *domain.AdminAccount, password, ipAddress, userAgent string) error {
	passwordOK, err := security.VerifyPassword(account.PasswordHash, password)
	if err != nil || !passwordOK {
		return ErrInvalidCredentials
	}
	if err := s.store.DisableAdminMFA(ctx, account.ID); err != nil {
		return fmt.Errorf("disable mfa: %w", err)
	}
	if err := s.store.RevokeAllAdminSessions(ctx, account.ID); err != nil {
		return fmt.Errorf("revoke sessions after mfa disable: %w", err)
	}
	return s.audit(ctx, domain.NewAuditLog{
		AdminAccountID: account.ID, ActorEmail: account.Email, Action: actionMFADisabled,
		IPSHA256: hashIP(ipAddress), UserAgent: truncateUserAgent(userAgent),
	})
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

func (s *Service) issueChallenge(ctx context.Context, account *domain.AdminAccount, ipAddress, userAgent string) (string, error) {
	tokenValue := make([]byte, challengeTokenBytes)
	if _, err := io.ReadFull(s.random, tokenValue); err != nil {
		return "", fmt.Errorf("generate mfa challenge token: %w", err)
	}
	digest := sha256.Sum256(tokenValue)
	if _, err := s.store.CreateAdminMFAChallenge(ctx, domain.NewAdminMFAChallenge{
		AdminAccountID: account.ID,
		TokenSHA256:    digest[:],
		IPAddress:      ipAddress,
		UserAgent:      userAgent,
		ExpiresAt:      s.now().Add(s.challengeTTL),
	}); err != nil {
		return "", fmt.Errorf("create mfa challenge: %w", err)
	}
	return hex.EncodeToString(tokenValue), nil
}

func (s *Service) createSession(ctx context.Context, account *domain.AdminAccount, ipAddress, userAgent, action string) (string, error) {
	tokenValue := make([]byte, sessionTokenBytes)
	if _, err := io.ReadFull(s.random, tokenValue); err != nil {
		return "", fmt.Errorf("generate admin session token: %w", err)
	}
	tokenDigest := sha256.Sum256(tokenValue)
	if _, err := s.store.CreateAdminSession(ctx, domain.NewAdminSession{
		AdminAccountID: account.ID,
		TokenSHA256:    tokenDigest[:],
		IPAddress:      ipAddress,
		UserAgent:      userAgent,
		ExpiresAt:      s.now().Add(s.sessionTTL),
	}); err != nil {
		return "", fmt.Errorf("create admin session: %w", err)
	}
	if err := s.audit(ctx, domain.NewAuditLog{
		AdminAccountID: account.ID, ActorEmail: account.Email, Action: action,
		IPSHA256: hashIP(ipAddress), UserAgent: userAgent,
	}); err != nil {
		return "", err
	}
	return hex.EncodeToString(tokenValue), nil
}

// loadActiveAccount re-reads the account behind a challenge so status and MFA
// state are fresh at completion time.
func (s *Service) loadActiveAccount(ctx context.Context, adminAccountID string) (*domain.AdminAccount, error) {
	account, err := s.store.FindAdminAccountByID(ctx, adminAccountID)
	if err != nil {
		return nil, fmt.Errorf("load challenge account: %w", err)
	}
	if account.Status != domain.AdminStatusActive {
		return nil, ErrInvalidCredentials
	}
	return account, nil
}

func (s *Service) auditMFAFailure(ctx context.Context, account *domain.AdminAccount, ipAddress, userAgent, method string) {
	_ = s.audit(ctx, domain.NewAuditLog{
		AdminAccountID: account.ID, ActorEmail: account.Email, Action: actionLoginFailed,
		IPSHA256: hashIP(ipAddress), UserAgent: truncateUserAgent(userAgent),
		Metadata: mustMarshal(map[string]string{"reason": "mfa_failed", "method": method}),
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

// generateRecoveryCodes returns plaintext codes paired with their SHA-256
// digests; only the digests are persisted.
func generateRecoveryCodes(random io.Reader) ([]string, [][]byte, error) {
	plain := make([]string, 0, RecoveryCodeCount)
	digests := make([][]byte, 0, RecoveryCodeCount)
	buffer := make([]byte, recoveryCodeBytes)
	for i := 0; i < RecoveryCodeCount; i++ {
		if _, err := io.ReadFull(random, buffer); err != nil {
			return nil, nil, fmt.Errorf("generate recovery codes: %w", err)
		}
		builder := make([]byte, 0, recoveryCodeBytes+1)
		for _, b := range buffer {
			builder = append(builder, recoveryAlphabet[int(b)%len(recoveryAlphabet)])
		}
		code := string(builder[:4]) + "-" + string(builder[4:])
		// Digest the normalized form so verification is insensitive to
		// separators and case entered by the administrator.
		digest := sha256.Sum256([]byte(normalizeRecoveryCode(code)))
		plain = append(plain, code)
		digests = append(digests, digest[:])
	}
	return plain, digests, nil
}

// normalizeRecoveryCode strips separators and case so "ABCD-EFGH" and
// "abcdefgh" verify identically.
func normalizeRecoveryCode(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	code = strings.ReplaceAll(code, "-", "")
	code = strings.ReplaceAll(code, " ", "")
	return code
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

// mustMarshal serializes small audit metadata; failure degrades to an empty
// object instead of breaking the primary operation.
func mustMarshal(value any) json.RawMessage {
	raw, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage("{}")
	}
	return raw
}

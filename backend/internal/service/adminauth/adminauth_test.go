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

	challenges    []domain.NewAdminMFAChallenge
	recoveryCodes [][]byte
	usedRecovery  [][]byte
	revokedAllFor string
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

func (f *fakeStore) FindAdminAccountByID(_ context.Context, adminID string) (*domain.AdminAccount, error) {
	if f.findErr != nil {
		return nil, f.findErr
	}
	if f.account == nil || f.account.ID != adminID {
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

func (f *fakeStore) RevokeAllAdminSessions(_ context.Context, adminID string) error {
	f.revokedAllFor = adminID
	return nil
}

func (f *fakeStore) AppendAuditLog(_ context.Context, input domain.NewAuditLog) error {
	f.auditEntries = append(f.auditEntries, input)
	return nil
}

func (f *fakeStore) CreateAdminMFAChallenge(_ context.Context, input domain.NewAdminMFAChallenge) (*domain.AdminMFAChallenge, error) {
	f.challenges = append(f.challenges, input)
	return &domain.AdminMFAChallenge{ID: "challenge-id", AdminAccountID: input.AdminAccountID, TokenSHA256: input.TokenSHA256, ExpiresAt: input.ExpiresAt}, nil
}

func (f *fakeStore) ConsumeAdminMFAChallenge(_ context.Context, tokenSHA256 []byte) (*domain.AdminMFAChallenge, error) {
	for index, challenge := range f.challenges {
		if bytes.Equal(challenge.TokenSHA256, tokenSHA256) {
			f.challenges = append(f.challenges[:index], f.challenges[index+1:]...)
			if !challenge.ExpiresAt.After(time.Now()) {
				return nil, domain.ErrAdminMFAChallengeNotFound
			}
			return &domain.AdminMFAChallenge{ID: "challenge-id", AdminAccountID: challenge.AdminAccountID, TokenSHA256: challenge.TokenSHA256, ExpiresAt: challenge.ExpiresAt}, nil
		}
	}
	return nil, domain.ErrAdminMFAChallengeNotFound
}

func (f *fakeStore) StartAdminTOTPEnrollment(_ context.Context, adminID, secret string) error {
	if f.account == nil || f.account.ID != adminID {
		return domain.ErrAdminNotFound
	}
	f.account.TOTPSecret = secret
	return nil
}

func (f *fakeStore) ConfirmAdminTOTPEnrollment(_ context.Context, adminID string) error {
	if f.account == nil || f.account.ID != adminID || f.account.TOTPSecret == "" {
		return domain.ErrAdminNotFound
	}
	f.account.MFAEnrolled = true
	return nil
}

func (f *fakeStore) DisableAdminMFA(_ context.Context, adminID string) error {
	if f.account == nil || f.account.ID != adminID {
		return domain.ErrAdminNotFound
	}
	f.account.TOTPSecret = ""
	f.account.MFAEnrolled = false
	return nil
}

func (f *fakeStore) ReplaceAdminRecoveryCodes(_ context.Context, adminID string, codeHashes [][]byte) error {
	if f.account == nil || f.account.ID != adminID {
		return domain.ErrAdminNotFound
	}
	f.recoveryCodes = append([][]byte(nil), codeHashes...)
	f.usedRecovery = nil
	return nil
}

func (f *fakeStore) ConsumeAdminRecoveryCode(_ context.Context, adminID string, codeSHA256 []byte) error {
	for _, digest := range f.recoveryCodes {
		if bytes.Equal(digest, codeSHA256) {
			for _, used := range f.usedRecovery {
				if bytes.Equal(used, codeSHA256) {
					return domain.ErrAdminRecoveryCodeNotFound
				}
			}
			f.usedRecovery = append(f.usedRecovery, codeSHA256)
			return nil
		}
	}
	return domain.ErrAdminRecoveryCodeNotFound
}

func newTestAccount(t *testing.T, password string) *domain.AdminAccount {
	t.Helper()
	hash, err := security.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	return &domain.AdminAccount{ID: "admin-id", Email: "root@example.com", PasswordHash: hash, Status: domain.AdminStatusActive, RoleName: domain.RoleOwner}
}

func newTestService(store Store) *Service {
	return New(store, Config{SessionTTL: time.Hour})
}

// enrolledAccount returns an account with a known TOTP secret already active.
func enrolledAccount(t *testing.T, password string) *domain.AdminAccount {
	t.Helper()
	account := newTestAccount(t, password)
	account.TOTPSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	account.MFAEnrolled = true
	return account
}

func TestLoginIssuesTokenPersistsDigestAndAudits(t *testing.T) {
	store := &fakeStore{account: newTestAccount(t, "correct admin password")}
	service := newTestService(store)

	result, err := service.Login(context.Background(), "root@example.com", "correct admin password", "10.0.0.1", "test-agent")
	if err != nil {
		t.Fatal(err)
	}
	if result.MFARequired || result.ChallengeToken != "" {
		t.Fatalf("unenrolled account must not receive a challenge: %#v", result)
	}
	if len(result.Token) != sessionTokenBytes*2 {
		t.Fatalf("token length = %d, want %d hex characters", len(result.Token), sessionTokenBytes*2)
	}
	if result.Account.Email != "root@example.com" {
		t.Fatalf("account = %#v", result.Account)
	}
	if len(store.createdSessions) != 1 {
		t.Fatalf("created sessions = %d, want 1", len(store.createdSessions))
	}
	tokenBytes, _ := hex.DecodeString(result.Token)
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

	_, err := service.Login(context.Background(), "root@example.com", "wrong password", "10.0.0.1", "")
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

	_, err := service.Login(context.Background(), "nobody@example.com", "any password", "10.0.0.1", "")
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

	_, err := service.Login(context.Background(), "root@example.com", "correct admin password", "10.0.0.1", "")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login() error = %v, want invalid credentials", err)
	}
	if len(store.createdSessions) != 0 {
		t.Fatal("disabled account must not receive a session")
	}
}

func TestLoginIssuesChallengeForEnrolledAccounts(t *testing.T) {
	store := &fakeStore{account: enrolledAccount(t, "correct admin password")}
	service := newTestService(store)

	result, err := service.Login(context.Background(), "root@example.com", "correct admin password", "10.0.0.1", "")
	if err != nil {
		t.Fatal(err)
	}
	if !result.MFARequired || result.Token != "" {
		t.Fatalf("enrolled account must receive a challenge, not a session: %#v", result)
	}
	if len(result.ChallengeToken) != challengeTokenBytes*2 {
		t.Fatalf("challenge token length = %d, want %d hex characters", len(result.ChallengeToken), challengeTokenBytes*2)
	}
	if len(store.createdSessions) != 0 {
		t.Fatal("no session may be issued before MFA completion")
	}
	if len(store.challenges) != 1 {
		t.Fatalf("stored challenges = %d, want 1", len(store.challenges))
	}
	tokenBytes, _ := hex.DecodeString(result.ChallengeToken)
	digest := sha256.Sum256(tokenBytes)
	if !bytes.Equal(store.challenges[0].TokenSHA256, digest[:]) {
		t.Fatal("persisted challenge digest does not match the issued token")
	}
}

func TestCompleteMFAIssuesSessionWithValidTOTP(t *testing.T) {
	store := &fakeStore{account: enrolledAccount(t, "correct admin password")}
	service := newTestService(store)

	result, err := service.Login(context.Background(), "root@example.com", "correct admin password", "10.0.0.1", "")
	if err != nil {
		t.Fatal(err)
	}
	code, err := security.TOTPCode(store.account.TOTPSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	token, account, err := service.CompleteMFA(context.Background(), result.ChallengeToken, code, "", "10.0.0.1", "")
	if err != nil {
		t.Fatalf("CompleteMFA() error = %v", err)
	}
	if len(token) != sessionTokenBytes*2 || account.Email != "root@example.com" {
		t.Fatalf("token length = %d, account = %#v", len(token), account)
	}
	if len(store.createdSessions) != 1 {
		t.Fatalf("created sessions = %d, want 1", len(store.createdSessions))
	}
	last := store.auditEntries[len(store.auditEntries)-1]
	if last.Action != actionLogin {
		t.Fatalf("last audit entry = %#v, want completed login", last)
	}
}

func TestCompleteMFARejectsInvalidCodeAndReplays(t *testing.T) {
	store := &fakeStore{account: enrolledAccount(t, "correct admin password")}
	service := newTestService(store)

	result, err := service.Login(context.Background(), "root@example.com", "correct admin password", "10.0.0.1", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.CompleteMFA(context.Background(), result.ChallengeToken, "000000", "", "10.0.0.1", ""); !errors.Is(err, ErrInvalidMFACode) {
		t.Fatalf("CompleteMFA() error = %v, want invalid mfa code", err)
	}
	// The challenge is consumed on failure; replaying it must fail as expired.
	code, err := security.TOTPCode(store.account.TOTPSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.CompleteMFA(context.Background(), result.ChallengeToken, code, "", "10.0.0.1", ""); !errors.Is(err, ErrMFAChallengeExpired) {
		t.Fatalf("replayed challenge error = %v, want expired", err)
	}
	if len(store.createdSessions) != 0 {
		t.Fatal("failed MFA must not create a session")
	}
}

func TestCompleteMFAAcceptsRecoveryCodeExactlyOnce(t *testing.T) {
	store := &fakeStore{account: enrolledAccount(t, "correct admin password")}
	service := newTestService(store)
	digest := sha256.Sum256([]byte(normalizeRecoveryCode("ABCD-EFGH")))
	if err := store.ReplaceAdminRecoveryCodes(context.Background(), "admin-id", [][]byte{digest[:]}); err != nil {
		t.Fatal(err)
	}

	result, err := service.Login(context.Background(), "root@example.com", "correct admin password", "10.0.0.1", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.CompleteMFA(context.Background(), result.ChallengeToken, "", "abcd efgh", "10.0.0.1", ""); err != nil {
		t.Fatalf("CompleteMFA() error = %v, want recovery code accepted", err)
	}

	// A second challenge with the same recovery code must fail: codes are
	// single-use.
	result, err = service.Login(context.Background(), "root@example.com", "correct admin password", "10.0.0.1", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.CompleteMFA(context.Background(), result.ChallengeToken, "", "ABCD-EFGH", "10.0.0.1", ""); !errors.Is(err, ErrInvalidMFACode) {
		t.Fatalf("reused recovery code error = %v, want invalid mfa code", err)
	}
}

func TestMFAEnrollmentConfirmsWithValidCodeAndIssuesRecoveryCodes(t *testing.T) {
	store := &fakeStore{account: newTestAccount(t, "correct admin password")}
	service := newTestService(store)

	secret, uri, err := service.StartMFAEnrollment(context.Background(), store.account, "KeyStar Admin")
	if err != nil {
		t.Fatal(err)
	}
	if secret == "" || uri == "" {
		t.Fatalf("secret = %q, uri = %q", secret, uri)
	}
	code, err := security.TOTPCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	recoveryCodes, err := service.ConfirmMFAEnrollment(context.Background(), store.account, code, "10.0.0.1", "")
	if err != nil {
		t.Fatalf("ConfirmMFAEnrollment() error = %v", err)
	}
	if len(recoveryCodes) != RecoveryCodeCount {
		t.Fatalf("recovery codes = %d, want %d", len(recoveryCodes), RecoveryCodeCount)
	}
	if !store.account.MFAEnrolled {
		t.Fatal("account must be marked enrolled after confirmation")
	}
	if len(store.recoveryCodes) != RecoveryCodeCount {
		t.Fatalf("stored recovery code digests = %d, want %d", len(store.recoveryCodes), RecoveryCodeCount)
	}
	last := store.auditEntries[len(store.auditEntries)-1]
	if last.Action != actionMFAEnrolled {
		t.Fatalf("last audit entry = %#v, want enrollment", last)
	}
}

func TestMFAEnrollmentRejectsInvalidCodeAndRepeatEnrollment(t *testing.T) {
	store := &fakeStore{account: newTestAccount(t, "correct admin password")}
	service := newTestService(store)

	if _, _, err := service.StartMFAEnrollment(context.Background(), store.account, "KeyStar Admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ConfirmMFAEnrollment(context.Background(), store.account, "000000", "10.0.0.1", ""); !errors.Is(err, ErrInvalidMFACode) {
		t.Fatalf("ConfirmMFAEnrollment() error = %v, want invalid code", err)
	}
	if store.account.MFAEnrolled {
		t.Fatal("invalid code must not enroll the account")
	}

	account := enrolledAccount(t, "correct admin password")
	enrolledStore := &fakeStore{account: account}
	enrolledService := newTestService(enrolledStore)
	if _, _, err := enrolledService.StartMFAEnrollment(context.Background(), account, "KeyStar Admin"); !errors.Is(err, ErrMFAAlreadyEnrolled) {
		t.Fatalf("StartMFAEnrollment() error = %v, want already enrolled", err)
	}
}

func TestDisableMFAVerifiesPasswordAndRevokesSessions(t *testing.T) {
	store := &fakeStore{account: enrolledAccount(t, "correct admin password")}
	service := newTestService(store)

	if err := service.DisableMFA(context.Background(), store.account, "wrong password", "10.0.0.1", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("DisableMFA() error = %v, want invalid credentials", err)
	}
	if !store.account.MFAEnrolled {
		t.Fatal("failed password verification must not disable MFA")
	}

	if err := service.DisableMFA(context.Background(), store.account, "correct admin password", "10.0.0.1", ""); err != nil {
		t.Fatalf("DisableMFA() error = %v", err)
	}
	if store.account.MFAEnrolled || store.account.TOTPSecret != "" {
		t.Fatal("MFA state must be cleared after disable")
	}
	if store.revokedAllFor != "admin-id" {
		t.Fatalf("revokedAllFor = %q, want admin-id", store.revokedAllFor)
	}
	last := store.auditEntries[len(store.auditEntries)-1]
	if last.Action != actionMFADisabled {
		t.Fatalf("last audit entry = %#v, want mfa disabled", last)
	}
}

func TestAuthenticateResolvesIssuedToken(t *testing.T) {
	store := &fakeStore{account: newTestAccount(t, "correct admin password")}
	service := newTestService(store)
	result, err := service.Login(context.Background(), "root@example.com", "correct admin password", "10.0.0.1", "")
	if err != nil {
		t.Fatal(err)
	}

	session, account, err := service.Authenticate(context.Background(), result.Token)
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
	result, err := service.Login(context.Background(), "root@example.com", "correct admin password", "10.0.0.1", "")
	if err != nil {
		t.Fatal(err)
	}

	if err := service.Logout(context.Background(), result.Token); err != nil {
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

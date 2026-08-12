package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/starloader/backend/internal/domain"
	"github.com/starloader/backend/internal/security"
)

func TestLoginCreatesShortLivedHashedChallenge(t *testing.T) {
	now := time.Date(2026, 8, 10, 9, 30, 0, 0, time.UTC)
	randomChallenge := bytes.Repeat([]byte{0x2a}, 32)
	repository := validLoginRepository(now)
	service := newTestLoginService(repository, bytes.NewReader(randomChallenge), now)

	pending, err := service.Login(context.Background(), LoginInput{
		Email:             "  PERSON@Example.COM ",
		Password:          "correct horse battery staple",
		DeviceFingerprint: "fingerprint",
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	if repository.foundEmail != "person@example.com" {
		t.Fatalf("FindUserByEmail() email = %q", repository.foundEmail)
	}
	if repository.foundLicenseUserID != "user-1" || repository.foundLicenseProduct != "StarLoader" {
		t.Fatalf("FindLicenseByUserAndProduct() arguments = %q, %q", repository.foundLicenseUserID, repository.foundLicenseProduct)
	}
	wantDigest := sha256.Sum256(randomChallenge)
	if !bytes.Equal(repository.pendingInput.ChallengeSHA256, wantDigest[:]) {
		t.Fatalf("CreatePendingSession() challenge = %x, want SHA-256 %x", repository.pendingInput.ChallengeSHA256, wantDigest)
	}
	if bytes.Equal(repository.pendingInput.ChallengeSHA256, randomChallenge) {
		t.Fatal("CreatePendingSession() received the plaintext challenge")
	}
	wantExpiry := now.Add(2 * time.Minute)
	if !repository.pendingInput.ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("CreatePendingSession() expiry = %s, want %s", repository.pendingInput.ExpiresAt, wantExpiry)
	}
	if pending.SessionID != "session-1" || !bytes.Equal(pending.Challenge, randomChallenge) || !pending.ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("Login() = %#v", pending)
	}
}

func TestLoginPolicyFailures(t *testing.T) {
	now := time.Date(2026, 8, 10, 9, 30, 0, 0, time.UTC)
	tests := []struct {
		name       string
		mutate     func(*fakeLoginRepository)
		passwordOK bool
		want       error
	}{
		{
			name: "unknown user",
			mutate: func(repository *fakeLoginRepository) {
				repository.userErr = domain.ErrUserNotFound
			},
			passwordOK: true,
			want:       ErrInvalidCredentials,
		},
		{name: "wrong password", passwordOK: false, want: ErrInvalidCredentials},
		{
			name: "inactive user",
			mutate: func(repository *fakeLoginRepository) {
				repository.user.Status = domain.UserStatusDisabled
			},
			passwordOK: true,
			want:       ErrInvalidCredentials,
		},
		{
			name: "unknown license",
			mutate: func(repository *fakeLoginRepository) {
				repository.licenseErr = domain.ErrLicenseNotFound
			},
			passwordOK: true,
			want:       ErrLicenseNotFound,
		},
		{
			name: "expired license timestamp",
			mutate: func(repository *fakeLoginRepository) {
				repository.license.ExpiresAt = now
			},
			passwordOK: true,
			want:       ErrLicenseExpired,
		},
		{
			name: "expired license status",
			mutate: func(repository *fakeLoginRepository) {
				repository.license.Status = domain.LicenseStatusExpired
			},
			passwordOK: true,
			want:       ErrLicenseExpired,
		},
		{
			name: "revoked license",
			mutate: func(repository *fakeLoginRepository) {
				repository.license.Status = domain.LicenseStatusRevoked
			},
			passwordOK: true,
			want:       ErrLicenseRevoked,
		},
		{
			name: "license belongs to another user",
			mutate: func(repository *fakeLoginRepository) {
				repository.license.UserID = "user-2"
			},
			passwordOK: true,
			want:       ErrInvalidCredentials,
		},
		{
			name: "wrong product",
			mutate: func(repository *fakeLoginRepository) {
				repository.license.Product = "AnotherProduct"
			},
			passwordOK: true,
			want:       ErrInvalidCredentials,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repository := validLoginRepository(now)
			if tt.mutate != nil {
				tt.mutate(repository)
			}
			service := newTestLoginService(repository, bytes.NewReader(bytes.Repeat([]byte{0x2a}, 32)), now)
			service.verifyPassword = func(string, string) (bool, error) { return tt.passwordOK, nil }

			_, err := service.Login(context.Background(), validLoginInput())
			if !errors.Is(err, tt.want) {
				t.Fatalf("Login() error = %v, want %v", err, tt.want)
			}
			if repository.createPendingCalls != 0 {
				t.Fatal("Login() persisted a challenge after policy rejection")
			}
		})
	}
}

func TestLoginRandomSourceFailureDoesNotCreateSession(t *testing.T) {
	now := time.Date(2026, 8, 10, 9, 30, 0, 0, time.UTC)
	repository := validLoginRepository(now)
	service := newTestLoginService(repository, bytes.NewReader([]byte("short")), now)

	_, err := service.Login(context.Background(), validLoginInput())
	if !errors.Is(err, ErrChallengeGeneration) {
		t.Fatalf("Login() error = %v, want %v", err, ErrChallengeGeneration)
	}
	if repository.createPendingCalls != 0 {
		t.Fatal("Login() persisted a session after random-source failure")
	}
}

func TestLoginUnknownUserStillPerformsPasswordWork(t *testing.T) {
	if _, err := security.VerifyPassword(dummyPasswordHash, "irrelevant"); err != nil {
		t.Fatalf("dummy password hash is invalid: %v", err)
	}
	now := time.Date(2026, 8, 10, 9, 30, 0, 0, time.UTC)
	repository := validLoginRepository(now)
	repository.userErr = domain.ErrUserNotFound
	service := newTestLoginService(repository, bytes.NewReader(bytes.Repeat([]byte{0x2a}, 32)), now)
	verificationCalls := 0
	service.verifyPassword = func(encoded, password string) (bool, error) {
		verificationCalls++
		if encoded == "" || password != "correct horse battery staple" {
			t.Fatalf("password verification inputs = %q, %q", encoded, password)
		}
		return false, nil
	}

	_, err := service.Login(context.Background(), validLoginInput())
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login() error = %v, want %v", err, ErrInvalidCredentials)
	}
	if verificationCalls != 1 {
		t.Fatalf("password verification calls = %d, want 1", verificationCalls)
	}
}

func validLoginInput() LoginInput {
	return LoginInput{
		Email:             "person@example.com",
		Password:          "correct horse battery staple",
		DeviceFingerprint: "fingerprint",
	}
}

func newTestLoginService(repository *fakeLoginRepository, random *bytes.Reader, now time.Time) *LoginService {
	service := NewLoginService(repository, "StarLoader")
	service.random = random
	service.now = func() time.Time { return now }
	service.verifyPassword = func(_, password string) (bool, error) {
		return password == "correct horse battery staple", nil
	}
	return service
}

func validLoginRepository(now time.Time) *fakeLoginRepository {
	return &fakeLoginRepository{
		user: &domain.User{
			ID:           "user-1",
			Email:        "person@example.com",
			PasswordHash: "stored-password-hash",
			Status:       domain.UserStatusActive,
		},
		license: &domain.License{
			ID:        "license-1",
			UserID:    "user-1",
			Product:   "StarLoader",
			Status:    domain.LicenseStatusActive,
			ExpiresAt: now.Add(24 * time.Hour),
		},
		pending: &domain.PendingSession{Session: domain.AuthSession{ID: "session-1"}},
	}
}

type fakeLoginRepository struct {
	user                *domain.User
	userErr             error
	license             *domain.License
	licenseErr          error
	pending             *domain.PendingSession
	pendingErr          error
	foundEmail          string
	foundLicenseUserID  string
	foundLicenseProduct string
	pendingInput        domain.NewPendingSession
	createPendingCalls  int
}

func (repository *fakeLoginRepository) FindUserByEmail(_ context.Context, email string) (*domain.User, error) {
	repository.foundEmail = email
	return repository.user, repository.userErr
}

func (repository *fakeLoginRepository) FindLicenseByUserAndProduct(_ context.Context, userID, product string) (*domain.License, error) {
	repository.foundLicenseUserID = userID
	repository.foundLicenseProduct = product
	return repository.license, repository.licenseErr
}

func (repository *fakeLoginRepository) CreatePendingSession(_ context.Context, input domain.NewPendingSession) (*domain.PendingSession, error) {
	repository.createPendingCalls++
	repository.pendingInput = input
	return repository.pending, repository.pendingErr
}

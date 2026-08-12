package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/starloader/backend/internal/domain"
	"github.com/starloader/backend/internal/security"
)

const (
	challengeLength   = 32
	challengeLifetime = 2 * time.Minute
	dummyPasswordHash = "$argon2id$v=19$m=65536,t=3,p=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

var (
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrLicenseNotFound     = errors.New("license not found")
	ErrLicenseExpired      = errors.New("license expired")
	ErrLicenseRevoked      = errors.New("license revoked")
	ErrChallengeGeneration = errors.New("challenge generation failed")
)

type LoginInput struct {
	Email             string
	Password          string
	DeviceFingerprint string
}

type PendingChallenge struct {
	SessionID string
	Challenge []byte
	ExpiresAt time.Time
}

type LoginRepository interface {
	FindUserByEmail(context.Context, string) (*domain.User, error)
	FindLicenseByUserAndProduct(context.Context, string, string) (*domain.License, error)
	CreatePendingSession(context.Context, domain.NewPendingSession) (*domain.PendingSession, error)
}

type LoginService struct {
	repository     LoginRepository
	product        string
	random         io.Reader
	now            func() time.Time
	verifyPassword func(string, string) (bool, error)
}

func NewLoginService(repository LoginRepository, product string) *LoginService {
	return &LoginService{
		repository:     repository,
		product:        product,
		random:         rand.Reader,
		now:            time.Now,
		verifyPassword: security.VerifyPassword,
	}
}

func (service *LoginService) Login(ctx context.Context, input LoginInput) (PendingChallenge, error) {
	if service == nil || service.repository == nil {
		return PendingChallenge{}, errors.New("login service is not configured")
	}

	email := strings.ToLower(strings.TrimSpace(input.Email))
	user, err := service.repository.FindUserByEmail(ctx, email)
	if errors.Is(err, domain.ErrUserNotFound) {
		// Match the expensive password work performed for a known user so the
		// response timing does not expose whether the email exists.
		_, _ = service.verifyPassword(dummyPasswordHash, input.Password)
		return PendingChallenge{}, ErrInvalidCredentials
	}
	if err != nil {
		return PendingChallenge{}, fmt.Errorf("find login user: %w", err)
	}
	if user == nil {
		return PendingChallenge{}, errors.New("find login user: repository returned nil user")
	}

	passwordOK, err := service.verifyPassword(user.PasswordHash, input.Password)
	if err != nil {
		return PendingChallenge{}, fmt.Errorf("verify login password: %w", err)
	}
	if !passwordOK || user.Status != domain.UserStatusActive {
		return PendingChallenge{}, ErrInvalidCredentials
	}

	license, err := service.repository.FindLicenseByUserAndProduct(ctx, user.ID, service.product)
	if errors.Is(err, domain.ErrLicenseNotFound) {
		return PendingChallenge{}, ErrLicenseNotFound
	}
	if err != nil {
		return PendingChallenge{}, fmt.Errorf("find login license: %w", err)
	}
	if license == nil {
		return PendingChallenge{}, errors.New("find login license: repository returned nil license")
	}
	if license.UserID != user.ID || license.Product != service.product {
		return PendingChallenge{}, ErrInvalidCredentials
	}
	if license.Status == domain.LicenseStatusRevoked {
		return PendingChallenge{}, ErrLicenseRevoked
	}
	now := service.now().UTC()
	if license.Status == domain.LicenseStatusExpired || !license.ExpiresAt.After(now) {
		return PendingChallenge{}, ErrLicenseExpired
	}
	if license.Status != domain.LicenseStatusActive {
		return PendingChallenge{}, ErrInvalidCredentials
	}

	challenge := make([]byte, challengeLength)
	if _, err := io.ReadFull(service.random, challenge); err != nil {
		return PendingChallenge{}, fmt.Errorf("%w: %v", ErrChallengeGeneration, err)
	}
	digest := sha256.Sum256(challenge)
	expiresAt := now.Add(challengeLifetime)
	pending, err := service.repository.CreatePendingSession(ctx, domain.NewPendingSession{
		UserID:          user.ID,
		LicenseID:       license.ID,
		ChallengeSHA256: digest[:],
		ExpiresAt:       expiresAt,
	})
	if err != nil {
		return PendingChallenge{}, fmt.Errorf("create login challenge: %w", err)
	}
	if pending == nil || pending.Session.ID == "" {
		return PendingChallenge{}, errors.New("create login challenge: repository returned invalid session")
	}

	return PendingChallenge{
		SessionID: pending.Session.ID,
		Challenge: challenge,
		ExpiresAt: expiresAt,
	}, nil
}

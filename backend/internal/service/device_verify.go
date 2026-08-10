package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/starloader/backend/internal/domain"
	"github.com/starloader/backend/internal/security"
	"github.com/starloader/backend/internal/store"
)

const (
	deviceMatchThreshold  = 70
	sessionTokenLifetime  = time.Hour
	maxSessionIDBytes     = 128
	maxHardwareValueBytes = 4096
)

var (
	ErrInvalidVerifyRequest   = errors.New("invalid device verification request")
	ErrChallengeExpired       = errors.New("challenge expired")
	ErrInvalidDeviceSignature = errors.New("invalid device signature")
	ErrDeviceLimitReached     = errors.New("device limit reached")
	ErrDeviceRevoked          = errors.New("device revoked")
)

type HardwareSignals struct {
	SMBIOSUUID        string
	MotherboardSerial string
	BIOSSerial        string
	SystemDiskSerial  string
	MachineGuid       string
	Fingerprint       string
}

type VerifyInput struct {
	SessionID          string
	Challenge          string
	ChallengeSignature string
	TPMPublicKey       string
	Hardware           HardwareSignals
}

type VerifiedSession struct {
	Token     string
	ExpiresAt time.Time
	LicenseID string
	DeviceID  string
}

type DeviceTransaction interface {
	PendingSession() domain.AuthSession
	PendingChallenge() domain.DeviceChallenge
	LockLicense(context.Context) (*domain.License, error)
	ListDevices(context.Context) ([]domain.Device, error)
	CreateDevice(context.Context, domain.NewDevice) (*domain.Device, error)
	UpdateDevice(context.Context, domain.UpdateDevice) error
	MarkSessionVerified(context.Context, time.Time) error
}

type DeviceRepository interface {
	WithLockedChallenge(context.Context, string, func(DeviceTransaction) error) error
}

type SessionTokenIssuer interface {
	Issue(security.SessionClaims) (string, error)
}

type DeviceServiceConfig struct {
	HardwareHMACKey []byte
	TokenIssuer     SessionTokenIssuer
	Issuer          string
	Audience        string
	Product         string
	Now             func() time.Time
}

type DeviceService struct {
	repository      DeviceRepository
	hardwareHMACKey []byte
	tokenIssuer     SessionTokenIssuer
	issuer          string
	audience        string
	product         string
	now             func() time.Time
}

type storeDeviceRepository struct {
	store *store.Store
}

func NewStoreDeviceRepository(repository *store.Store) DeviceRepository {
	return &storeDeviceRepository{store: repository}
}

func (repository *storeDeviceRepository) WithLockedChallenge(ctx context.Context, sessionID string, callback func(DeviceTransaction) error) error {
	if repository == nil || repository.store == nil {
		return errors.New("device repository is not configured")
	}
	return repository.store.WithLockedChallenge(ctx, sessionID, func(locked *store.LockedChallenge) error {
		return callback(locked)
	})
}

func NewDeviceService(repository DeviceRepository, config DeviceServiceConfig) *DeviceService {
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &DeviceService{
		repository: repository, hardwareHMACKey: append([]byte(nil), config.HardwareHMACKey...),
		tokenIssuer: config.TokenIssuer, issuer: config.Issuer, audience: config.Audience,
		product: config.Product, now: now,
	}
}

func (service *DeviceService) Verify(ctx context.Context, input VerifyInput) (VerifiedSession, error) {
	if service == nil || service.repository == nil || service.tokenIssuer == nil || len(service.hardwareHMACKey) == 0 ||
		strings.TrimSpace(service.issuer) == "" || strings.TrimSpace(service.audience) == "" || strings.TrimSpace(service.product) == "" {
		return VerifiedSession{}, errors.New("device service is not configured")
	}
	sessionID := strings.TrimSpace(input.SessionID)
	if sessionID == "" || len(sessionID) > maxSessionIDBytes || !hardwareInputIsBounded(input.Hardware) {
		return VerifiedSession{}, ErrInvalidVerifyRequest
	}
	challenge, err := decodeCanonicalBase64(input.Challenge, 32)
	if err != nil {
		return VerifiedSession{}, ErrInvalidVerifyRequest
	}
	publicKey, err := decodeCanonicalBase64(input.TPMPublicKey, 72)
	if err != nil {
		return VerifiedSession{}, ErrInvalidVerifyRequest
	}
	signature, err := decodeCanonicalBase64(input.ChallengeSignature, 64)
	if err != nil {
		return VerifiedSession{}, ErrInvalidVerifyRequest
	}
	presented := protectedDeviceInput(service.hardwareHMACKey, publicKey, input.Hardware)
	if presented.FingerprintHMAC == "" {
		return VerifiedSession{}, ErrInvalidVerifyRequest
	}
	now := service.now().UTC().Truncate(time.Second)
	var deviceID, licenseID, userID string
	err = service.repository.WithLockedChallenge(ctx, sessionID, func(transaction DeviceTransaction) error {
		session := transaction.PendingSession()
		deviceChallenge := transaction.PendingChallenge()
		if session.ID != sessionID || deviceChallenge.SessionID != sessionID {
			return ErrInvalidVerifyRequest
		}
		if session.Status != domain.SessionStatusPending {
			return domain.ErrChallengeConsumed
		}
		if !session.ExpiresAt.After(now) || !deviceChallenge.ExpiresAt.After(now) {
			return ErrChallengeExpired
		}
		digest := sha256.Sum256(challenge)
		if len(deviceChallenge.ChallengeSHA256) != sha256.Size || !hmac.Equal(digest[:], deviceChallenge.ChallengeSHA256) {
			return ErrInvalidDeviceSignature
		}
		if err := security.VerifyCNGP256(publicKey, challenge, signature); err != nil {
			return ErrInvalidDeviceSignature
		}

		license, err := transaction.LockLicense(ctx)
		if err != nil {
			return fmt.Errorf("lock verification license: %w", err)
		}
		if license.ID != session.LicenseID || license.UserID != session.UserID || license.Product != service.product {
			return ErrInvalidCredentials
		}
		if license.Status == domain.LicenseStatusRevoked {
			return ErrLicenseRevoked
		}
		if license.Status == domain.LicenseStatusExpired || !license.ExpiresAt.After(now) {
			return ErrLicenseExpired
		}
		if license.Status != domain.LicenseStatusActive {
			return ErrInvalidCredentials
		}

		devices, err := transaction.ListDevices(ctx)
		if err != nil {
			return fmt.Errorf("list verification devices: %w", err)
		}
		matched, activeCount, err := matchDevice(devices, presented)
		if err != nil {
			return err
		}
		if matched != nil {
			if err := transaction.UpdateDevice(ctx, domain.UpdateDevice{
				ID: matched.ID, SMBIOSUUIDHMAC: presented.SMBIOSUUIDHMAC,
				MotherboardSerialHMAC: presented.MotherboardSerialHMAC, BIOSSerialHMAC: presented.BIOSSerialHMAC,
				SystemDiskSerialHMAC: presented.SystemDiskSerialHMAC, MachineGuidHMAC: presented.MachineGuidHMAC,
				FingerprintHMAC: presented.FingerprintHMAC, SeenAt: now,
			}); err != nil {
				return fmt.Errorf("update verified device: %w", err)
			}
			deviceID = matched.ID
		} else {
			if activeCount >= license.MaxDevices {
				return ErrDeviceLimitReached
			}
			device, err := transaction.CreateDevice(ctx, domain.NewDevice{
				UserID: session.UserID, LicenseID: session.LicenseID,
				TPMPublicKey: publicKey, TPMPublicKeySHA256: presented.TPMPublicKeySHA256,
				SMBIOSUUIDHMAC: presented.SMBIOSUUIDHMAC, MotherboardSerialHMAC: presented.MotherboardSerialHMAC,
				BIOSSerialHMAC: presented.BIOSSerialHMAC, SystemDiskSerialHMAC: presented.SystemDiskSerialHMAC,
				MachineGuidHMAC: presented.MachineGuidHMAC, FingerprintHMAC: presented.FingerprintHMAC, SeenAt: now,
			})
			if err != nil {
				return fmt.Errorf("create verified device: %w", err)
			}
			if device == nil || device.ID == "" {
				return errors.New("create verified device: repository returned invalid device")
			}
			deviceID = device.ID
		}
		if err := transaction.MarkSessionVerified(ctx, now); err != nil {
			return fmt.Errorf("mark verified session: %w", err)
		}
		licenseID = license.ID
		userID = session.UserID
		return nil
	})
	if err != nil {
		return VerifiedSession{}, err
	}

	expiresAt := now.Add(sessionTokenLifetime)
	token, err := service.tokenIssuer.Issue(security.SessionClaims{
		Subject: userID, LicenseID: licenseID, DeviceID: deviceID, Product: service.product,
		Features: []string{}, Issuer: service.issuer, Audience: service.audience,
		IssuedAt: now, ExpiresAt: expiresAt,
	})
	if err != nil {
		return VerifiedSession{}, fmt.Errorf("issue verified session token: %w", err)
	}
	return VerifiedSession{Token: token, ExpiresAt: expiresAt, LicenseID: licenseID, DeviceID: deviceID}, nil
}

type protectedDevice struct {
	TPMPublicKeySHA256    []byte
	SMBIOSUUIDHMAC        string
	MotherboardSerialHMAC string
	BIOSSerialHMAC        string
	SystemDiskSerialHMAC  string
	MachineGuidHMAC       string
	FingerprintHMAC       string
}

func protectedDeviceInput(key, publicKey []byte, hardware HardwareSignals) protectedDevice {
	digest := sha256.Sum256(publicKey)
	return protectedDevice{
		TPMPublicKeySHA256:    digest[:],
		SMBIOSUUIDHMAC:        hashHardware(key, hardware.SMBIOSUUID),
		MotherboardSerialHMAC: hashHardware(key, hardware.MotherboardSerial),
		BIOSSerialHMAC:        hashHardware(key, hardware.BIOSSerial),
		SystemDiskSerialHMAC:  hashHardware(key, hardware.SystemDiskSerial),
		MachineGuidHMAC:       hashHardware(key, hardware.MachineGuid),
		FingerprintHMAC:       hashHardware(key, hardware.Fingerprint),
	}
}

func matchDevice(devices []domain.Device, presented protectedDevice) (*domain.Device, int, error) {
	presentedSignals := domain.DeviceSignals{
		TPM: hex.EncodeToString(presented.TPMPublicKeySHA256), SMBIOS: presented.SMBIOSUUIDHMAC,
		Motherboard: presented.MotherboardSerialHMAC, BIOS: presented.BIOSSerialHMAC,
		SystemDisk: presented.SystemDiskSerialHMAC, MachineGuid: presented.MachineGuidHMAC,
	}
	activeCount := 0
	var matched *domain.Device
	bestScore := -1
	for index := range devices {
		device := &devices[index]
		if device.Status == domain.DeviceStatusActive {
			activeCount++
		}
		if device.Status == domain.DeviceStatusRevoked && len(device.TPMPublicKeySHA256) == sha256.Size &&
			hmac.Equal(device.TPMPublicKeySHA256, presented.TPMPublicKeySHA256) {
			return nil, activeCount, ErrDeviceRevoked
		}
		score := domain.ScoreDevice(domain.DeviceSignals{
			TPM: hex.EncodeToString(device.TPMPublicKeySHA256), SMBIOS: device.SMBIOSUUIDHMAC,
			Motherboard: device.MotherboardSerialHMAC, BIOS: device.BIOSSerialHMAC,
			SystemDisk: device.SystemDiskSerialHMAC, MachineGuid: device.MachineGuidHMAC,
		}, presentedSignals)
		if score < deviceMatchThreshold {
			continue
		}
		if device.Status == domain.DeviceStatusRevoked {
			return nil, activeCount, ErrDeviceRevoked
		}
		if device.Status == domain.DeviceStatusActive && score > bestScore {
			matched = device
			bestScore = score
		}
	}
	return matched, activeCount, nil
}

func decodeCanonicalBase64(encoded string, exactBytes int) ([]byte, error) {
	if encoded == "" || len(encoded) != base64.StdEncoding.EncodedLen(exactBytes) {
		return nil, ErrInvalidVerifyRequest
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != exactBytes || base64.StdEncoding.EncodeToString(decoded) != encoded {
		return nil, ErrInvalidVerifyRequest
	}
	return decoded, nil
}

func hardwareInputIsBounded(hardware HardwareSignals) bool {
	for _, value := range []string{hardware.SMBIOSUUID, hardware.MotherboardSerial, hardware.BIOSSerial, hardware.SystemDiskSerial, hardware.MachineGuid, hardware.Fingerprint} {
		if !utf8.ValidString(value) || len(value) > maxHardwareValueBytes {
			return false
		}
	}
	return true
}

func hashHardware(key []byte, raw string) string {
	normalized := normalizeHardware(raw)
	if normalized == "" {
		return ""
	}
	return security.HMACHex(key, normalized)
}

func normalizeHardware(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	return strings.NewReplacer(" ", "", "-", "", "{", "", "}", "").Replace(value)
}

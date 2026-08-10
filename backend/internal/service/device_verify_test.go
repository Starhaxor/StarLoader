package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/starloader/backend/internal/domain"
	"github.com/starloader/backend/internal/security"
)

func TestDeviceVerifyFirstActivationHashesHardwareAndIssuesBoundToken(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	repository, input := newVerificationFixture(t, now, 1)
	service, verifier := newTestDeviceService(t, repository, now)

	verified, err := service.Verify(context.Background(), input)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !repository.consumed || repository.transaction.session.Status != domain.SessionStatusVerified {
		t.Fatalf("transaction did not verify session and consume challenge: %#v", repository)
	}
	if len(repository.transaction.devices) != 1 || verified.DeviceID != repository.transaction.devices[0].ID {
		t.Fatalf("activated devices = %#v; result = %#v", repository.transaction.devices, verified)
	}
	device := repository.transaction.devices[0]
	if device.SMBIOSUUIDHMAC != security.HMACHex([]byte("hardware-secret"), "SMBIOS1") ||
		device.MotherboardSerialHMAC != security.HMACHex([]byte("hardware-secret"), "BOARD1") ||
		device.FingerprintHMAC != security.HMACHex([]byte("hardware-secret"), "FINGERPRINT1") {
		t.Fatalf("device hardware was not normalized and HMACed: %#v", device)
	}
	for _, raw := range []string{"smbios-1", "board-1", "bios-1", "disk-1", "guid-1", "fingerprint-1"} {
		if strings.Contains(strings.ToLower(strings.Join([]string{
			device.SMBIOSUUIDHMAC, device.MotherboardSerialHMAC, device.BIOSSerialHMAC,
			device.SystemDiskSerialHMAC, device.MachineGuidHMAC, device.FingerprintHMAC,
		}, "|")), raw) {
			t.Fatalf("stored device contains raw hardware %q", raw)
		}
	}
	claims, err := verifier.Verify(verified.Token)
	if err != nil {
		t.Fatalf("issued token failed verification: %v", err)
	}
	if claims.Subject != "user-1" || claims.LicenseID != "license-1" || claims.DeviceID != device.ID ||
		claims.Product != "StarLoader" || claims.Issuer != "starloader" || claims.Audience != "starloader-client" ||
		!claims.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("token claims = %#v", claims)
	}
}

func TestDeviceVerifyScoreSeventyUpdatesExistingDevice(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	repository, input := newVerificationFixture(t, now, 1)
	tmpService, _ := newTestDeviceService(t, repository, now)
	if _, err := tmpService.Verify(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	existing := repository.transaction.devices[0]
	signingKey := repository.signingKey

	repository, input = newVerificationFixture(t, now, 1)
	repository.transaction.devices = []domain.Device{existing}
	challenge, err := base64.StdEncoding.DecodeString(input.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	publicBlob, signature := cngProof(t, signingKey, challenge)
	input.TPMPublicKey = base64.StdEncoding.EncodeToString(publicBlob)
	input.ChallengeSignature = base64.StdEncoding.EncodeToString(signature)
	input.Hardware.MotherboardSerial = "changed-board"
	input.Hardware.BIOSSerial = "changed-bios"
	input.Hardware.SystemDiskSerial = "changed-disk"
	input.Hardware.MachineGuid = "changed-guid"
	input.Hardware.Fingerprint = "changed-fingerprint"
	service, _ := newTestDeviceService(t, repository, now)

	verified, err := service.Verify(context.Background(), input)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if len(repository.transaction.devices) != 1 || verified.DeviceID != existing.ID {
		t.Fatalf("Verify() created a new device at score 70: %#v", repository.transaction.devices)
	}
	if repository.transaction.devices[0].MotherboardSerialHMAC == existing.MotherboardSerialHMAC {
		t.Fatal("accepted device signals were not refreshed")
	}
}

func TestDeviceVerifyFailuresDoNotConsumeChallenge(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	tests := []struct {
		name   string
		mutate func(*fakeDeviceRepository, *VerifyInput)
		want   error
	}{
		{name: "invalid signature", mutate: func(_ *fakeDeviceRepository, input *VerifyInput) {
			input.ChallengeSignature = base64.StdEncoding.EncodeToString(make([]byte, 64))
		}, want: ErrInvalidDeviceSignature},
		{name: "challenge hash mismatch", mutate: func(_ *fakeDeviceRepository, input *VerifyInput) {
			input.Challenge = base64.StdEncoding.EncodeToString([]byte("0123456789012345678901234567890X"))
		}, want: ErrInvalidDeviceSignature},
		{name: "expired challenge", mutate: func(repository *fakeDeviceRepository, _ *VerifyInput) {
			repository.transaction.challenge.ExpiresAt = now
		}, want: ErrChallengeExpired},
		{name: "session explicitly expired", mutate: func(repository *fakeDeviceRepository, _ *VerifyInput) {
			repository.transaction.session.Status = domain.SessionStatusExpired
		}, want: ErrChallengeExpired},
		{name: "revoked license", mutate: func(repository *fakeDeviceRepository, _ *VerifyInput) {
			repository.transaction.license.Status = domain.LicenseStatusRevoked
		}, want: ErrLicenseRevoked},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository, input := newVerificationFixture(t, now, 1)
			test.mutate(repository, &input)
			service, _ := newTestDeviceService(t, repository, now)
			_, err := service.Verify(context.Background(), input)
			if !errors.Is(err, test.want) {
				t.Fatalf("Verify() error = %v, want %v", err, test.want)
			}
			if repository.consumed || repository.transaction.session.Status == domain.SessionStatusVerified || len(repository.transaction.devices) != 0 {
				t.Fatalf("failed verification persisted state: %#v", repository)
			}
		})
	}
}

func TestDeviceVerifyEnforcesLimitAndRevocationTransactionally(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, test := range []struct {
		name           string
		status         domain.DeviceStatus
		match          bool
		revokedTPMOnly bool
		want           error
	}{
		{name: "different device at limit", status: domain.DeviceStatusActive, match: false, want: ErrDeviceLimitReached},
		{name: "matching revoked device", status: domain.DeviceStatusRevoked, match: true, want: ErrDeviceRevoked},
		{name: "revoked TPM remains denied after hardware changes", status: domain.DeviceStatusRevoked, match: true, revokedTPMOnly: true, want: ErrDeviceRevoked},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository, input := newVerificationFixture(t, now, 1)
			device := deviceFromInput(t, input, []byte("hardware-secret"), "existing")
			device.Status = test.status
			if !test.match {
				device.TPMPublicKeySHA256 = bytesOf(0x42, 32)
			}
			if test.revokedTPMOnly {
				device.SMBIOSUUIDHMAC = security.HMACHex([]byte("hardware-secret"), "CHANGED-SMBIOS")
				device.MotherboardSerialHMAC = security.HMACHex([]byte("hardware-secret"), "CHANGED-BOARD")
				device.BIOSSerialHMAC = security.HMACHex([]byte("hardware-secret"), "CHANGED-BIOS")
				device.SystemDiskSerialHMAC = security.HMACHex([]byte("hardware-secret"), "CHANGED-DISK")
				device.MachineGuidHMAC = security.HMACHex([]byte("hardware-secret"), "CHANGED-GUID")
			}
			repository.transaction.devices = []domain.Device{device}
			service, _ := newTestDeviceService(t, repository, now)

			_, err := service.Verify(context.Background(), input)
			if !errors.Is(err, test.want) {
				t.Fatalf("Verify() error = %v, want %v", err, test.want)
			}
			if repository.consumed || repository.transaction.session.Status == domain.SessionStatusVerified {
				t.Fatal("policy rejection consumed challenge or verified session")
			}
		})
	}
}

func TestDeviceVerifyRejectsOversizedOrNonCanonicalBase64BeforeTransaction(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, mutate := range []func(*VerifyInput){
		func(input *VerifyInput) { input.TPMPublicKey = strings.Repeat("A", 1024) },
		func(input *VerifyInput) { input.ChallengeSignature = "not base64" },
		func(input *VerifyInput) { input.Challenge = base64.RawStdEncoding.EncodeToString(bytesOf(1, 32)) },
	} {
		repository, input := newVerificationFixture(t, now, 1)
		mutate(&input)
		service, _ := newTestDeviceService(t, repository, now)
		if _, err := service.Verify(context.Background(), input); !errors.Is(err, ErrInvalidVerifyRequest) {
			t.Fatalf("Verify() error = %v, want invalid request", err)
		}
		if repository.calls != 0 {
			t.Fatal("invalid encoding reached transaction")
		}
	}
}

func TestDeviceVerifyUsesFullPrecisionPolicyClock(t *testing.T) {
	base := time.Now().UTC().Truncate(time.Second)
	now := base.Add(750 * time.Millisecond)
	alreadyExpired := base.Add(500 * time.Millisecond)
	for _, test := range []struct {
		name   string
		mutate func(*fakeDeviceTransaction)
		want   error
	}{
		{name: "session expired earlier in same second", mutate: func(transaction *fakeDeviceTransaction) {
			transaction.session.ExpiresAt = alreadyExpired
		}, want: ErrChallengeExpired},
		{name: "challenge expired earlier in same second", mutate: func(transaction *fakeDeviceTransaction) {
			transaction.challenge.ExpiresAt = alreadyExpired
		}, want: ErrChallengeExpired},
		{name: "license expired earlier in same second", mutate: func(transaction *fakeDeviceTransaction) {
			transaction.license.ExpiresAt = alreadyExpired
		}, want: ErrLicenseExpired},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository, input := newVerificationFixture(t, now, 1)
			test.mutate(repository.transaction)
			service, _ := newTestDeviceService(t, repository, now)

			_, err := service.Verify(context.Background(), input)
			if !errors.Is(err, test.want) {
				t.Fatalf("Verify() error = %v, want %v", err, test.want)
			}
			if repository.consumed {
				t.Fatal("subsecond expiry consumed challenge")
			}
		})
	}
}

type fakeDeviceRepository struct {
	transaction *fakeDeviceTransaction
	signingKey  *ecdsa.PrivateKey
	consumed    bool
	calls       int
}

func (repository *fakeDeviceRepository) WithLockedChallenge(_ context.Context, _ string, callback func(DeviceTransaction) error) error {
	repository.calls++
	if repository.consumed {
		return domain.ErrChallengeConsumed
	}
	beforeSession := repository.transaction.session
	beforeDevices := append([]domain.Device(nil), repository.transaction.devices...)
	if err := callback(repository.transaction); err != nil {
		repository.transaction.session = beforeSession
		repository.transaction.devices = beforeDevices
		return err
	}
	repository.consumed = true
	return nil
}

type fakeDeviceTransaction struct {
	session   domain.AuthSession
	challenge domain.DeviceChallenge
	license   domain.License
	devices   []domain.Device
}

func (transaction *fakeDeviceTransaction) PendingSession() domain.AuthSession {
	return transaction.session
}
func (transaction *fakeDeviceTransaction) PendingChallenge() domain.DeviceChallenge {
	return transaction.challenge
}
func (transaction *fakeDeviceTransaction) LockLicense(context.Context) (*domain.License, error) {
	return &transaction.license, nil
}
func (transaction *fakeDeviceTransaction) ListDevices(context.Context) ([]domain.Device, error) {
	return append([]domain.Device(nil), transaction.devices...), nil
}
func (transaction *fakeDeviceTransaction) CreateDevice(_ context.Context, input domain.NewDevice) (*domain.Device, error) {
	device := domain.Device{
		ID: "device-new", UserID: input.UserID, LicenseID: input.LicenseID,
		TPMPublicKey: append([]byte(nil), input.TPMPublicKey...), TPMPublicKeySHA256: append([]byte(nil), input.TPMPublicKeySHA256...),
		SMBIOSUUIDHMAC: input.SMBIOSUUIDHMAC, MotherboardSerialHMAC: input.MotherboardSerialHMAC,
		BIOSSerialHMAC: input.BIOSSerialHMAC, SystemDiskSerialHMAC: input.SystemDiskSerialHMAC,
		MachineGuidHMAC: input.MachineGuidHMAC, FingerprintHMAC: input.FingerprintHMAC,
		Status: domain.DeviceStatusActive, LastSeenAt: input.SeenAt,
	}
	transaction.devices = append(transaction.devices, device)
	return &transaction.devices[len(transaction.devices)-1], nil
}
func (transaction *fakeDeviceTransaction) UpdateDevice(_ context.Context, input domain.UpdateDevice) error {
	for index := range transaction.devices {
		if transaction.devices[index].ID == input.ID {
			transaction.devices[index].SMBIOSUUIDHMAC = input.SMBIOSUUIDHMAC
			transaction.devices[index].MotherboardSerialHMAC = input.MotherboardSerialHMAC
			transaction.devices[index].BIOSSerialHMAC = input.BIOSSerialHMAC
			transaction.devices[index].SystemDiskSerialHMAC = input.SystemDiskSerialHMAC
			transaction.devices[index].MachineGuidHMAC = input.MachineGuidHMAC
			transaction.devices[index].FingerprintHMAC = input.FingerprintHMAC
			transaction.devices[index].LastSeenAt = input.SeenAt
			return nil
		}
	}
	return errors.New("missing device")
}
func (transaction *fakeDeviceTransaction) MarkSessionVerified(_ context.Context, _ time.Time) error {
	transaction.session.Status = domain.SessionStatusVerified
	return nil
}

func newVerificationFixture(t *testing.T, now time.Time, maxDevices int) (*fakeDeviceRepository, VerifyInput) {
	t.Helper()
	challenge := []byte("01234567890123456789012345678901")
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicBlob, signature := cngProof(t, privateKey, challenge)
	digest := sha256.Sum256(challenge)
	transaction := &fakeDeviceTransaction{
		session:   domain.AuthSession{ID: "session-1", UserID: "user-1", LicenseID: "license-1", Status: domain.SessionStatusPending, ExpiresAt: now.Add(time.Minute)},
		challenge: domain.DeviceChallenge{ID: "challenge-1", SessionID: "session-1", ChallengeSHA256: digest[:], ExpiresAt: now.Add(time.Minute)},
		license:   domain.License{ID: "license-1", UserID: "user-1", Product: "StarLoader", Status: domain.LicenseStatusActive, MaxDevices: maxDevices, ExpiresAt: now.Add(24 * time.Hour)},
	}
	return &fakeDeviceRepository{transaction: transaction, signingKey: privateKey}, VerifyInput{
		SessionID: "session-1", Challenge: base64.StdEncoding.EncodeToString(challenge),
		ChallengeSignature: base64.StdEncoding.EncodeToString(signature), TPMPublicKey: base64.StdEncoding.EncodeToString(publicBlob),
		Hardware: HardwareSignals{SMBIOSUUID: " {smbios-1} ", MotherboardSerial: "board-1", BIOSSerial: "bios-1", SystemDiskSerial: "disk-1", MachineGuid: "guid-1", Fingerprint: "fingerprint-1"},
	}
}

func newTestDeviceService(t *testing.T, repository DeviceRepository, now time.Time) (*DeviceService, *security.TokenVerifier) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := security.NewTokenIssuer(privateKey, "starloader", "starloader-client", "StarLoader")
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := security.NewTokenVerifier(publicKey, "starloader", "starloader-client", "StarLoader")
	if err != nil {
		t.Fatal(err)
	}
	service := NewDeviceService(repository, DeviceServiceConfig{
		HardwareHMACKey: []byte("hardware-secret"), TokenIssuer: issuer,
		Issuer: "starloader", Audience: "starloader-client", Product: "StarLoader", Now: func() time.Time { return now },
	})
	return service, verifier
}

func cngProof(t *testing.T, privateKey *ecdsa.PrivateKey, challenge []byte) ([]byte, []byte) {
	t.Helper()
	blob := make([]byte, 72)
	binary.LittleEndian.PutUint32(blob[:4], 0x31534345)
	binary.LittleEndian.PutUint32(blob[4:8], 32)
	privateKey.X.FillBytes(blob[8:40])
	privateKey.Y.FillBytes(blob[40:72])
	digest := sha256.Sum256(challenge)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return blob, signature
}

func deviceFromInput(t *testing.T, input VerifyInput, key []byte, id string) domain.Device {
	t.Helper()
	publicBlob, err := base64.StdEncoding.DecodeString(input.TPMPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(publicBlob)
	return domain.Device{
		ID: id, UserID: "user-1", LicenseID: "license-1", TPMPublicKey: publicBlob, TPMPublicKeySHA256: digest[:],
		SMBIOSUUIDHMAC: security.HMACHex(key, "SMBIOS1"), MotherboardSerialHMAC: security.HMACHex(key, "BOARD1"),
		BIOSSerialHMAC: security.HMACHex(key, "BIOS1"), SystemDiskSerialHMAC: security.HMACHex(key, "DISK1"),
		MachineGuidHMAC: security.HMACHex(key, "GUID1"), FingerprintHMAC: security.HMACHex(key, "FINGERPRINT1"),
		Status: domain.DeviceStatusActive,
	}
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}

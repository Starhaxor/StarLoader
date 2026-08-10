package domain

import "time"

type UserStatus string

const (
	UserStatusActive   UserStatus = "active"
	UserStatusDisabled UserStatus = "disabled"
)

type User struct {
	ID           string
	Email        string
	PasswordHash string
	Status       UserStatus
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type NewUser struct {
	Email        string
	PasswordHash string
}

type LicenseStatus string

const (
	LicenseStatusActive  LicenseStatus = "active"
	LicenseStatusRevoked LicenseStatus = "revoked"
	LicenseStatusExpired LicenseStatus = "expired"
)

type License struct {
	ID          string
	LicenseHMAC string
	UserID      string
	Product     string
	Status      LicenseStatus
	MaxDevices  int
	ExpiresAt   time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type NewLicense struct {
	LicenseHMAC string
	UserID      string
	Product     string
	MaxDevices  int
	ExpiresAt   time.Time
}

type DeviceStatus string

const (
	DeviceStatusActive  DeviceStatus = "active"
	DeviceStatusRevoked DeviceStatus = "revoked"
)

type Device struct {
	ID                    string
	UserID                string
	LicenseID             string
	TPMPublicKey          []byte
	TPMPublicKeySHA256    []byte
	SMBIOSUUIDHMAC        string
	MotherboardSerialHMAC string
	BIOSSerialHMAC        string
	SystemDiskSerialHMAC  string
	MachineGuidHMAC       string
	FingerprintHMAC       string
	Status                DeviceStatus
	CreatedAt             time.Time
	UpdatedAt             time.Time
	LastSeenAt            time.Time
}

type NewDevice struct {
	UserID                string
	LicenseID             string
	TPMPublicKey          []byte
	TPMPublicKeySHA256    []byte
	SMBIOSUUIDHMAC        string
	MotherboardSerialHMAC string
	BIOSSerialHMAC        string
	SystemDiskSerialHMAC  string
	MachineGuidHMAC       string
	FingerprintHMAC       string
	SeenAt                time.Time
}

type UpdateDevice struct {
	ID                    string
	SMBIOSUUIDHMAC        string
	MotherboardSerialHMAC string
	BIOSSerialHMAC        string
	SystemDiskSerialHMAC  string
	MachineGuidHMAC       string
	FingerprintHMAC       string
	SeenAt                time.Time
}

type SessionStatus string

const (
	SessionStatusPending  SessionStatus = "pending"
	SessionStatusVerified SessionStatus = "verified"
	SessionStatusExpired  SessionStatus = "expired"
)

type AuthSession struct {
	ID        string
	UserID    string
	LicenseID string
	Status    SessionStatus
	ExpiresAt time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

type DeviceChallenge struct {
	ID              string
	SessionID       string
	ChallengeSHA256 []byte
	ExpiresAt       time.Time
	ConsumedAt      *time.Time
	CreatedAt       time.Time
}

// PendingSession is created atomically so a pending authentication session
// can never exist without its SHA-256 challenge record.
type PendingSession struct {
	Session   AuthSession
	Challenge DeviceChallenge
}

type NewPendingSession struct {
	UserID          string
	LicenseID       string
	ChallengeSHA256 []byte
	ExpiresAt       time.Time
}

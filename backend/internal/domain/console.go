package domain

import "time"

// ConsoleUser is the admin dashboard view of an end user, enriched with
// ownership counts so listing does not require per-row round trips.
type ConsoleUser struct {
	ID                 string
	Email              string
	Status             UserStatus
	LicenseCount       int
	DeviceCount        int
	ActiveSessionCount int
	LastLoginAt        *time.Time
	CreatedAt          time.Time
}

type ConsoleUserDetail struct {
	User     ConsoleUser
	Licenses []ConsoleLicense
	Devices  []ConsoleDevice
	Sessions []ConsoleSession
}

type ConsoleLicense struct {
	ID         string
	UserID     string
	UserEmail  string
	Product    string
	Status     LicenseStatus
	MaxDevices int
	ExpiresAt  time.Time
	CreatedAt  time.Time
}

// ConsoleDevice deliberately exposes no raw hardware identifiers; only the
// presence of each HWID component, the TPM key state and the lifecycle state
// are surfaced.
type ConsoleDevice struct {
	ID                   string
	UserID               string
	UserEmail            string
	LicenseID            string
	TPMRegistered        bool
	HasSMBIOSUUID        bool
	HasMotherboardSerial bool
	HasBIOSSerial        bool
	HasSystemDiskSerial  bool
	HasMachineGUID       bool
	Status               DeviceStatus
	CreatedAt            time.Time
	LastSeenAt           time.Time
}

// ConsoleDeviceDetail adds the TPM public key fingerprint (a SHA-256 digest,
// never the raw key) to the redacted console device view.
type ConsoleDeviceDetail struct {
	Device         ConsoleDevice
	Product        string
	TPMFingerprint string
}

type ConsoleSession struct {
	ID        string
	UserID    string
	UserEmail string
	LicenseID string
	Status    SessionStatus
	ExpiresAt time.Time
	CreatedAt time.Time
}

type ConsoleOverview struct {
	TotalUsers     int64
	ActiveLicenses int64
	ActiveDevices  int64
	ActiveSessions int64
	RecentAudit    []AuditLog
}

// DailyStat is one day of the dashboard activity series. Day is a UTC date
// in YYYY-MM-DD format.
type DailyStat struct {
	Day               string
	LicensesCreated   int64
	DevicesRegistered int64
	SessionsCreated   int64
	AuditEvents       int64
	AdminLogins       int64
}

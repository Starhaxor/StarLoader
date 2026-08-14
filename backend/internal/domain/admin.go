package domain

import (
	"encoding/json"
	"time"
)

type AdminAccountStatus string

const (
	AdminStatusActive   AdminAccountStatus = "active"
	AdminStatusDisabled AdminAccountStatus = "disabled"
	AdminStatusLocked   AdminAccountStatus = "locked"
)

// Console permissions enforced by the RBAC middleware. Roles carry a set of
// these strings; handlers never branch on role names.
const (
	PermOverviewRead   = "overview.read"
	PermUsersRead      = "users.read"
	PermUsersWrite     = "users.write"
	PermLicensesRead   = "licenses.read"
	PermLicensesWrite  = "licenses.write"
	PermDevicesRead    = "devices.read"
	PermDevicesWrite   = "devices.write"
	PermSessionsRead   = "sessions.read"
	PermSessionsWrite  = "sessions.write"
	PermAuditRead      = "audit.read"
	PermSecurityRead   = "security.read"
	PermAdminsRead     = "admins.read"
	PermAdminsWrite    = "admins.write"
	RoleOwner          = "owner"
	RoleViewer         = "viewer"
)

// Role is an RBAC role; permissions are stored as flat strings so checks stay
// data-driven.
type Role struct {
	ID          string
	Name        string
	Description string
	Permissions []string
	BuiltIn     bool
}

// AdminAccount is a dashboard administrator, fully separate from end users.
type AdminAccount struct {
	ID           string
	Email        string
	PasswordHash string
	Status       AdminAccountStatus
	RoleID       string
	RoleName     string
	Permissions  []string
	TOTPSecret   string
	MFAEnrolled  bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// HasPermission reports whether the account's role grants the permission.
func (account *AdminAccount) HasPermission(permission string) bool {
	for _, candidate := range account.Permissions {
		if candidate == permission {
			return true
		}
	}
	return false
}

type NewAdminAccount struct {
	Email        string
	PasswordHash string
	RoleName     string
}

// AdminSession stores only the SHA-256 digest of the bearer token; the raw
// token exists solely in the administrator's HttpOnly cookie.
type AdminSession struct {
	ID             string
	AdminAccountID string
	TokenSHA256    []byte
	IPAddress      string
	UserAgent      string
	ExpiresAt      time.Time
	CreatedAt      time.Time
	RevokedAt      *time.Time
}

type NewAdminSession struct {
	AdminAccountID string
	TokenSHA256    []byte
	IPAddress      string
	UserAgent      string
	ExpiresAt      time.Time
}

// AdminMFAChallenge bridges password verification and TOTP confirmation. The
// raw challenge token never touches the database.
type AdminMFAChallenge struct {
	ID             string
	AdminAccountID string
	TokenSHA256    []byte
	ExpiresAt      time.Time
	CreatedAt      time.Time
}

type NewAdminMFAChallenge struct {
	AdminAccountID string
	TokenSHA256    []byte
	IPAddress      string
	UserAgent      string
	ExpiresAt      time.Time
}

// SecurityEvent records an anomaly or security-relevant occurrence. Unlike
// audit logs it also covers unauthenticated activity (failed logins, CSRF
// rejections, rate limiting).
type SecurityEvent struct {
	ID             string
	Kind           string
	Severity       string
	AdminAccountID string
	ActorEmail     string
	IPSHA256       string
	UserAgent      string
	Metadata       json.RawMessage
	CreatedAt      time.Time
}

type NewSecurityEvent struct {
	Kind           string
	Severity       string
	AdminAccountID string
	ActorEmail     string
	IPSHA256       string
	UserAgent      string
	Metadata       json.RawMessage
}

// AuditLog is an immutable record of administrative activity.
type AuditLog struct {
	ID             string
	AdminAccountID string // empty when no account existed, e.g. failed login
	ActorEmail     string
	Action         string
	ResourceType   string
	ResourceID     string
	IPSHA256       string
	UserAgent      string
	Metadata       json.RawMessage
	CreatedAt      time.Time
}

type NewAuditLog struct {
	AdminAccountID string
	ActorEmail     string
	Action         string
	ResourceType   string
	ResourceID     string
	IPSHA256       string
	UserAgent      string
	Metadata       json.RawMessage
}

var (
	ErrAdminNotFound            = &NotFoundError{Entity: "admin account"}
	ErrAdminSessionNotFound     = &NotFoundError{Entity: "admin session"}
	ErrAdminMFAChallengeNotFound = &NotFoundError{Entity: "admin mfa challenge"}
	ErrAdminRecoveryCodeNotFound = &NotFoundError{Entity: "admin recovery code"}
	ErrRoleNotFound             = &NotFoundError{Entity: "role"}
)

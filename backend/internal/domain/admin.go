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

// AdminAccount is a dashboard administrator, fully separate from end users.
type AdminAccount struct {
	ID           string
	Email        string
	PasswordHash string
	Status       AdminAccountStatus
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type NewAdminAccount struct {
	Email        string
	PasswordHash string
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
	ErrAdminNotFound        = &NotFoundError{Entity: "admin account"}
	ErrAdminSessionNotFound = &NotFoundError{Entity: "admin session"}
)

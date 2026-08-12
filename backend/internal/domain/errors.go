package domain

import "errors"

// NotFoundError identifies a missing domain entity without exposing database
// implementation details.
type NotFoundError struct {
	Entity string
}

func (e *NotFoundError) Error() string {
	return e.Entity + " not found"
}

var (
	ErrUserNotFound         = &NotFoundError{Entity: "user"}
	ErrLicenseNotFound      = &NotFoundError{Entity: "license"}
	ErrLicenseAlreadyExists = errors.New("license already exists for user and product")
	ErrChallengeNotFound    = &NotFoundError{Entity: "challenge"}
)

// ChallengeConsumedError marks the single-use challenge conflict while
// remaining independent of PostgreSQL error details.
type ChallengeConsumedError struct{}

func (*ChallengeConsumedError) Error() string {
	return "challenge already consumed"
}

var ErrChallengeConsumed = &ChallengeConsumedError{}

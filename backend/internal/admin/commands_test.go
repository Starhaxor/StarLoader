package admin

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/starloader/backend/internal/domain"
)

func TestCreateUserHashesPasswordBeforeStoring(t *testing.T) {
	repository := &fakeUsers{}
	passwords := []string{"secure password", "secure password"}
	var output bytes.Buffer

	err := Run(context.Background(), []string{"create-user", "--email", "user@example.com"}, &output, repository, nil, nil, func() (string, error) {
		password := passwords[0]
		passwords = passwords[1:]
		return password, nil
	}, nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if repository.email != "user@example.com" || repository.passwordHash == "secure password" {
		t.Fatalf("stored email=%q passwordHash=%q", repository.email, repository.passwordHash)
	}
}

func TestCreateUserAcceptsPasswordStdinFlag(t *testing.T) {
	repository := &fakeUsers{}
	passwords := []string{"correct horse battery staple", "correct horse battery staple"}
	err := Run(context.Background(), []string{"create-user", "--email", "user@example.com", "--password-stdin"}, &bytes.Buffer{}, repository, nil, nil, func() (string, error) {
		password := passwords[0]
		passwords = passwords[1:]
		return password, nil
	}, nil, time.Now)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if repository.passwordHash == "" {
		t.Fatal("password hash was not persisted")
	}
}

func TestCreateLicensePrintsPlaintextOnlyAfterRepositorySuccess(t *testing.T) {
	repository := &fakeLicenses{}
	var output bytes.Buffer
	err := Run(context.Background(), []string{"create-license", "--user", "user@example.com", "--product", "StarLoader", "--days", "30", "--max-devices", "2"}, &output, nil, repository, nil, nil, bytes.NewReader([]byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	}), func() time.Time { return time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC) })
	if err != nil {
		t.Fatal(err)
	}
	if output.String() != "01234567-89ABCDEF-FEDCBA98-76543210\n" {
		t.Fatalf("output = %q", output.String())
	}
	if repository.normalized != "0123456789ABCDEFFEDCBA9876543210" || repository.expiresAt != time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC) || repository.maxDevices != 2 {
		t.Fatalf("repository = %#v", repository)
	}
}

func TestCreateLicenseDoesNotPrintPlaintextWhenRepositoryFails(t *testing.T) {
	repository := &fakeLicenses{err: errors.New("database unavailable")}
	var output bytes.Buffer
	err := Run(context.Background(), []string{"create-license", "--user", "user@example.com", "--product", "StarLoader", "--days", "1", "--max-devices", "1"}, &output, nil, repository, nil, nil, bytes.NewReader(make([]byte, 16)), time.Now)
	if err == nil {
		t.Fatal("Run() unexpectedly succeeded")
	}
	if output.Len() != 0 {
		t.Fatalf("output = %q", output.String())
	}
}

func TestCreateLicenseDoesNotPrintPlaintextWhenUserProductLicenseAlreadyExists(t *testing.T) {
	repository := &fakeLicenses{err: domain.ErrLicenseAlreadyExists}
	var output bytes.Buffer
	err := Run(context.Background(), []string{"create-license", "--user", "user@example.com", "--product", "StarLoader", "--days", "1", "--max-devices", "1"}, &output, nil, repository, nil, nil, bytes.NewReader(make([]byte, 16)), time.Now)
	if err == nil || !strings.Contains(err.Error(), "license already exists for user and product") {
		t.Fatalf("Run() error = %v", err)
	}
	if output.Len() != 0 || strings.Contains(output.String(), "00000000-00000000-00000000-00000000") {
		t.Fatalf("output contains plaintext license: %q", output.String())
	}
}

func TestCreateAdminHashesPasswordBeforeStoring(t *testing.T) {
	repository := &fakeAdmins{}
	passwords := []string{"long enough admin password", "long enough admin password"}

	err := Run(context.Background(), []string{"create-admin", "--email", "root@example.com"}, &bytes.Buffer{}, nil, nil, repository, func() (string, error) {
		password := passwords[0]
		passwords = passwords[1:]
		return password, nil
	}, nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if repository.email != "root@example.com" || repository.passwordHash == "" || repository.passwordHash == "long enough admin password" {
		t.Fatalf("stored email=%q passwordHash=%q", repository.email, repository.passwordHash)
	}
	if repository.roleName != "owner" {
		t.Fatalf("stored role = %q, want owner default", repository.roleName)
	}
}

func TestCreateAdminAcceptsViewerRole(t *testing.T) {
	repository := &fakeAdmins{}
	passwords := []string{"long enough admin password", "long enough admin password"}

	err := Run(context.Background(), []string{"create-admin", "--email", "viewer@example.com", "--role", "VIEWER"}, &bytes.Buffer{}, nil, nil, repository, func() (string, error) {
		password := passwords[0]
		passwords = passwords[1:]
		return password, nil
	}, nil, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if repository.roleName != "viewer" {
		t.Fatalf("stored role = %q, want viewer", repository.roleName)
	}
}

func TestCreateAdminRejectsUnknownRoles(t *testing.T) {
	repository := &fakeAdmins{}
	passwords := []string{"long enough admin password", "long enough admin password"}

	err := Run(context.Background(), []string{"create-admin", "--email", "root@example.com", "--role", "superadmin"}, &bytes.Buffer{}, nil, nil, repository, func() (string, error) {
		password := passwords[0]
		passwords = passwords[1:]
		return password, nil
	}, nil, time.Now)
	if err == nil || repository.passwordHash != "" {
		t.Fatalf("Run() error = %v, stored hash = %q", err, repository.passwordHash)
	}
}

func TestCreateAdminRejectsShortPasswords(t *testing.T) {
	repository := &fakeAdmins{}
	passwords := []string{"short-pass", "short-pass"}

	err := Run(context.Background(), []string{"create-admin", "--email", "root@example.com"}, &bytes.Buffer{}, nil, nil, repository, func() (string, error) {
		password := passwords[0]
		passwords = passwords[1:]
		return password, nil
	}, nil, time.Now)
	if err == nil || repository.passwordHash != "" {
		t.Fatalf("Run() error = %v, stored hash = %q", err, repository.passwordHash)
	}
}

func TestCreateAdminRejectsMismatchedConfirmation(t *testing.T) {
	repository := &fakeAdmins{}
	passwords := []string{"long enough admin password", "different confirmation"}

	err := Run(context.Background(), []string{"create-admin", "--email", "root@example.com"}, &bytes.Buffer{}, nil, nil, repository, func() (string, error) {
		password := passwords[0]
		passwords = passwords[1:]
		return password, nil
	}, nil, time.Now)
	if err == nil || repository.passwordHash != "" {
		t.Fatalf("Run() error = %v, stored hash = %q", err, repository.passwordHash)
	}
}

type fakeUsers struct {
	email        string
	passwordHash string
	err          error
}

func (f *fakeUsers) CreateUser(_ context.Context, email, passwordHash string) error {
	f.email, f.passwordHash = email, passwordHash
	return f.err
}

type fakeLicenses struct {
	normalized string
	userEmail  string
	product    string
	expiresAt  time.Time
	maxDevices int
	err        error
}

func (f *fakeLicenses) CreateLicense(_ context.Context, normalized, userEmail, product string, expiresAt time.Time, maxDevices int) error {
	f.normalized, f.userEmail, f.product, f.expiresAt, f.maxDevices = normalized, userEmail, product, expiresAt, maxDevices
	return f.err
}

type fakeAdmins struct {
	email        string
	passwordHash string
	roleName     string
	err          error
}

func (f *fakeAdmins) CreateAdminAccount(_ context.Context, email, passwordHash, roleName string) error {
	f.email, f.passwordHash, f.roleName = email, passwordHash, roleName
	return f.err
}

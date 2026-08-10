package admin

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestCreateUserHashesPasswordBeforeStoring(t *testing.T) {
	repository := &fakeUsers{}
	passwords := []string{"secure password", "secure password"}
	var output bytes.Buffer

	err := Run(context.Background(), []string{"create-user", "--email", "user@example.com"}, &output, repository, nil, func() (string, error) {
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
	err := Run(context.Background(), []string{"create-user", "--email", "user@example.com", "--password-stdin"}, &bytes.Buffer{}, repository, nil, func() (string, error) {
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
	err := Run(context.Background(), []string{"create-license", "--user", "user@example.com", "--product", "StarLoader", "--days", "30", "--max-devices", "2"}, &output, nil, repository, nil, bytes.NewReader([]byte{
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
	err := Run(context.Background(), []string{"create-license", "--user", "user@example.com", "--product", "StarLoader", "--days", "1", "--max-devices", "1"}, &output, nil, repository, nil, bytes.NewReader(make([]byte, 16)), time.Now)
	if err == nil {
		t.Fatal("Run() unexpectedly succeeded")
	}
	if output.Len() != 0 {
		t.Fatalf("output = %q", output.String())
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

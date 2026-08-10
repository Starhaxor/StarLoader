// Package admin implements non-interactive-safe administrative commands.
package admin

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/starloader/backend/internal/security"
	"golang.org/x/term"
)

// UserRepository is the persistence boundary for the create-user command.
type UserRepository interface {
	CreateUser(ctx context.Context, email, passwordHash string) error
}

// LicenseRepository is the persistence boundary for the create-license command.
// It receives only the normalized license, never its plaintext form.
type LicenseRepository interface {
	CreateLicense(ctx context.Context, normalized, userEmail, product string, expiresAt time.Time, maxDevices int) error
}

// PasswordReader is injected in tests. Production uses ReadPasswordFromTerminal.
type PasswordReader func() (string, error)

// Run parses and executes the supported administrative command. It prints a
// generated plaintext license exactly once, only after it was persisted.
func Run(ctx context.Context, args []string, output io.Writer, users UserRepository, licenses LicenseRepository, readPassword PasswordReader, random io.Reader, now func() time.Time) error {
	if len(args) == 0 {
		return errors.New("admin command is required")
	}
	if output == nil {
		return errors.New("admin output is required")
	}

	switch args[0] {
	case "create-user":
		return createUser(ctx, args[1:], users, readPassword)
	case "create-license":
		return createLicense(ctx, args[1:], output, licenses, random, now)
	default:
		return fmt.Errorf("unknown admin command %q", args[0])
	}
}

func createUser(ctx context.Context, args []string, users UserRepository, readPassword PasswordReader) error {
	if users == nil || readPassword == nil {
		return errors.New("create-user dependencies are required")
	}
	flags := flag.NewFlagSet("create-user", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	email := flags.String("email", "", "user email")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parse create-user flags: %w", err)
	}
	if strings.TrimSpace(*email) == "" {
		return errors.New("create-user requires --email")
	}
	password, err := readPassword()
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	confirmation, err := readPassword()
	if err != nil {
		return fmt.Errorf("read password confirmation: %w", err)
	}
	if password != confirmation {
		return errors.New("password confirmation does not match")
	}
	hash, err := security.HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	if err := users.CreateUser(ctx, *email, hash); err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

func createLicense(ctx context.Context, args []string, output io.Writer, licenses LicenseRepository, random io.Reader, now func() time.Time) error {
	if licenses == nil || now == nil {
		return errors.New("create-license dependencies are required")
	}
	flags := flag.NewFlagSet("create-license", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	user := flags.String("user", "", "user email")
	product := flags.String("product", "", "product")
	days := flags.Int("days", 0, "license duration in days")
	maxDevices := flags.Int("max-devices", 0, "maximum devices")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("parse create-license flags: %w", err)
	}
	if strings.TrimSpace(*user) == "" || strings.TrimSpace(*product) == "" {
		return errors.New("create-license requires --user and --product")
	}
	if *days <= 0 || *maxDevices <= 0 {
		return errors.New("create-license requires positive --days and --max-devices")
	}
	if random == nil {
		random = cryptorand.Reader
	}
	plain, normalized, err := security.GenerateLicense(random)
	if err != nil {
		return err
	}
	if err := licenses.CreateLicense(ctx, normalized, *user, *product, now().AddDate(0, 0, *days), *maxDevices); err != nil {
		return fmt.Errorf("create license: %w", err)
	}
	_, err = fmt.Fprintln(output, plain)
	return err
}

// ReadPasswordFromTerminal obtains a password without echoing it. The small
// PasswordReader boundary lets tests avoid requiring a terminal.
func ReadPasswordFromTerminal() (string, error) {
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	return string(password), err
}

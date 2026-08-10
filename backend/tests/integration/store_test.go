package integration_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/starloader/backend/internal/domain"
	"github.com/starloader/backend/internal/store"
)

func TestUserAndLicenseRoundTrip(t *testing.T) {
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Microsecond)
	pool := openTestPool(t, ctx)
	resetAndMigrate(t, ctx, pool)
	repository := store.New(pool)

	createdUser, err := repository.CreateUser(ctx, domain.NewUser{
		Email:        "person@example.com",
		PasswordHash: "$argon2id$v=19$test-hash",
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	if createdUser.ID == "" {
		t.Fatal("CreateUser() returned an empty ID")
	}

	foundUser, err := repository.FindUserByEmail(ctx, "person@example.com")
	if err != nil {
		t.Fatalf("FindUserByEmail() error = %v", err)
	}
	if foundUser.ID != createdUser.ID || foundUser.Email != "person@example.com" || foundUser.PasswordHash != "$argon2id$v=19$test-hash" || foundUser.Status != domain.UserStatusActive {
		t.Fatalf("FindUserByEmail() = %#v", foundUser)
	}

	expiresAt := base.Add(30 * 24 * time.Hour)
	licenseHMAC := "5c89e0aeacdc0f1e84682f1d9f4b7bc81c279466603fefb87941b21df91f5fd2"
	createdLicense, err := repository.CreateLicense(ctx, domain.NewLicense{
		LicenseHMAC: licenseHMAC,
		UserID:      createdUser.ID,
		Product:     "StarLoader",
		MaxDevices:  2,
		ExpiresAt:   expiresAt,
	})
	if err != nil {
		t.Fatalf("CreateLicense() error = %v", err)
	}

	foundLicense, err := repository.FindLicenseByHMAC(ctx, licenseHMAC)
	if err != nil {
		t.Fatalf("FindLicenseByHMAC() error = %v", err)
	}
	if foundLicense.ID != createdLicense.ID || foundLicense.UserID != createdUser.ID || foundLicense.LicenseHMAC != licenseHMAC || foundLicense.Product != "StarLoader" || foundLicense.Status != domain.LicenseStatusActive || foundLicense.MaxDevices != 2 || !foundLicense.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("FindLicenseByHMAC() = %#v", foundLicense)
	}
}

func TestUserRepositoryNormalizesEmail(t *testing.T) {
	ctx := context.Background()
	pool := openTestPool(t, ctx)
	resetAndMigrate(t, ctx, pool)
	repository := store.New(pool)

	created, err := repository.CreateUser(ctx, domain.NewUser{
		Email:        "  Person@Example.COM ",
		PasswordHash: "$argon2id$v=19$normalized-email",
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	if created.Email != "person@example.com" {
		t.Fatalf("CreateUser() email = %q", created.Email)
	}

	found, err := repository.FindUserByEmail(ctx, " PERSON@EXAMPLE.COM ")
	if err != nil {
		t.Fatalf("FindUserByEmail() error = %v", err)
	}
	if found.ID != created.ID {
		t.Fatalf("FindUserByEmail() ID = %q, want %q", found.ID, created.ID)
	}
}

func TestRepositoryNotFoundErrorsAreTyped(t *testing.T) {
	ctx := context.Background()
	pool := openTestPool(t, ctx)
	resetAndMigrate(t, ctx, pool)
	repository := store.New(pool)

	tests := []struct {
		name   string
		entity string
		find   func() error
	}{
		{
			name:   "user",
			entity: "user",
			find: func() error {
				_, err := repository.FindUserByEmail(ctx, "missing@example.com")
				return err
			},
		},
		{
			name:   "license",
			entity: "license",
			find: func() error {
				_, err := repository.FindLicenseByHMAC(ctx, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
				return err
			},
		},
		{
			name:   "challenge",
			entity: "challenge",
			find: func() error {
				return repository.WithLockedChallenge(ctx, "00000000-0000-0000-0000-000000000000", func(*store.LockedChallenge) error {
					return nil
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.find()
			var notFound *domain.NotFoundError
			if !errors.As(err, &notFound) || notFound.Entity != tt.entity {
				t.Fatalf("error = %v, want typed %s not-found error", err, tt.entity)
			}
		})
	}
}

func TestSchemaRejectsInvalidStatusesAndUnprotectedValues(t *testing.T) {
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Microsecond)
	pool := openTestPool(t, ctx)
	resetAndMigrate(t, ctx, pool)
	repository := store.New(pool)
	user, license := createUserAndLicense(t, ctx, repository, "constraints@example.com", base)

	invalidStatements := []struct {
		name string
		sql  string
		args []any
	}{
		{
			name: "unnormalized email",
			sql:  `insert into users (email, password_hash) values ('Mixed@Example.COM', 'hash')`,
		},
		{
			name: "invalid user status",
			sql:  `update users set status = 'unknown' where id = $1`,
			args: []any{user.ID},
		},
		{
			name: "invalid license status",
			sql:  `update licenses set status = 'unknown' where id = $1`,
			args: []any{license.ID},
		},
		{
			name: "non-positive device limit",
			sql:  `update licenses set max_devices = 0 where id = $1`,
			args: []any{license.ID},
		},
		{
			name: "non-HMAC license value",
			sql:  `update licenses set license_hmac = 'plaintext-license' where id = $1`,
			args: []any{license.ID},
		},
		{
			name: "invalid device status",
			sql: `insert into devices (
				user_id, license_id, tpm_public_key, tpm_public_key_sha256, fingerprint_hmac, status
			) values ($1, $2, $3, $4, $5, 'unknown')`,
			args: []any{user.ID, license.ID, []byte{0x01}, bytes.Repeat([]byte{0x02}, 32), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		},
		{
			name: "invalid session status",
			sql:  `insert into auth_sessions (user_id, license_id, status, expires_at) values ($1, $2, 'unknown', $3)`,
			args: []any{user.ID, license.ID, base.Add(2 * time.Minute)},
		},
	}

	for _, tt := range invalidStatements {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := pool.Exec(ctx, tt.sql, tt.args...); err == nil {
				t.Fatal("invalid database write unexpectedly succeeded")
			}
		})
	}
}

func TestMigrationDownAndUp(t *testing.T) {
	ctx := context.Background()
	pool := openTestPool(t, ctx)
	resetAndMigrate(t, ctx, pool)

	if err := store.MigrateDown(ctx, pool); err != nil {
		t.Fatalf("MigrateDown() error = %v", err)
	}
	assertTablesExist(t, ctx, pool, false)

	if err := store.MigrateUp(ctx, pool); err != nil {
		t.Fatalf("second MigrateUp() error = %v", err)
	}
	assertTablesExist(t, ctx, pool, true)
}

func TestConcurrentChallengeConsumptionHasExactlyOneConsumer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	base := time.Now().UTC().Truncate(time.Microsecond)
	pool := openTestPool(t, ctx)
	resetAndMigrate(t, ctx, pool)
	repository := store.New(pool)
	pending := createPendingSession(t, ctx, repository, base)

	firstConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire first connection: %v", err)
	}
	defer firstConn.Release()
	secondConn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire second connection: %v", err)
	}
	defer secondConn.Release()
	firstRepository := store.New(firstConn)
	secondRepository := store.New(secondConn)

	var secondBackendPID int
	if err := secondConn.QueryRow(ctx, `select pg_backend_pid()`).Scan(&secondBackendPID); err != nil {
		t.Fatalf("read second backend PID: %v", err)
	}

	firstLocked := make(chan struct{})
	releaseFirst := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseFirst) }) }
	defer release()
	secondStarted := make(chan struct{})
	secondCallbackRan := make(chan struct{}, 1)
	results := make(chan error, 2)
	go func() {
		results <- firstRepository.WithLockedChallenge(ctx, pending.Session.ID, func(*store.LockedChallenge) error {
			close(firstLocked)
			select {
			case <-releaseFirst:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	waitForSignal(t, ctx, firstLocked, "first callback to acquire the challenge lock")

	go func() {
		close(secondStarted)
		results <- secondRepository.WithLockedChallenge(ctx, pending.Session.ID, func(*store.LockedChallenge) error {
			secondCallbackRan <- struct{}{}
			return nil
		})
	}()
	waitForSignal(t, ctx, secondStarted, "second transaction to start")
	waitForBackendLock(t, ctx, pool, secondBackendPID)
	release()

	succeeded := 0
	consumed := 0
	for range 2 {
		err := receiveResult(t, ctx, results)
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, domain.ErrChallengeConsumed):
			consumed++
		default:
			t.Fatalf("WithLockedChallenge() error = %v", err)
		}
	}
	if succeeded != 1 || consumed != 1 {
		t.Fatalf("challenge results: succeeded=%d consumed=%d", succeeded, consumed)
	}
	select {
	case <-secondCallbackRan:
		t.Fatal("second callback ran after the first transaction consumed the challenge")
	default:
	}
	assertChallengeConsumedAfterCreation(t, ctx, pool, pending.Challenge)
}

func TestWithLockedChallengeRollsBackCallbackFailure(t *testing.T) {
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Microsecond)
	pool := openTestPool(t, ctx)
	resetAndMigrate(t, ctx, pool)
	repository := store.New(pool)
	pending := createPendingSession(t, ctx, repository, base)
	callbackErr := errors.New("verification failed")

	err := repository.WithLockedChallenge(ctx, pending.Session.ID, func(*store.LockedChallenge) error {
		return callbackErr
	})
	if !errors.Is(err, callbackErr) {
		t.Fatalf("WithLockedChallenge() error = %v, want %v", err, callbackErr)
	}

	var consumedAt *time.Time
	if err := pool.QueryRow(ctx, `select consumed_at from device_challenges where id = $1`, pending.Challenge.ID).Scan(&consumedAt); err != nil {
		t.Fatalf("read rolled-back consumed_at: %v", err)
	}
	if consumedAt != nil {
		t.Fatalf("failed callback persisted consumed_at %s", consumedAt)
	}

	err = repository.WithLockedChallenge(ctx, pending.Session.ID, func(locked *store.LockedChallenge) error {
		if locked.Challenge.ConsumedAt != nil {
			return domain.ErrChallengeConsumed
		}
		return nil
	})
	if err != nil {
		t.Fatalf("second WithLockedChallenge() error = %v", err)
	}
	assertChallengeConsumedAfterCreation(t, ctx, pool, pending.Challenge)
}

func TestSuccessfulLockedChallengeCallbackAlwaysConsumes(t *testing.T) {
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Microsecond)
	pool := openTestPool(t, ctx)
	resetAndMigrate(t, ctx, pool)
	repository := store.New(pool)
	pending := createPendingSession(t, ctx, repository, base)

	if err := repository.WithLockedChallenge(ctx, pending.Session.ID, func(*store.LockedChallenge) error {
		return nil
	}); err != nil {
		t.Fatalf("first WithLockedChallenge() error = %v", err)
	}

	callbackCalled := false
	err := repository.WithLockedChallenge(ctx, pending.Session.ID, func(*store.LockedChallenge) error {
		callbackCalled = true
		return nil
	})
	if !errors.Is(err, domain.ErrChallengeConsumed) {
		t.Fatalf("second WithLockedChallenge() error = %v, want %v", err, domain.ErrChallengeConsumed)
	}
	if callbackCalled {
		t.Fatal("callback ran for an already-consumed challenge")
	}

	assertChallengeConsumedAfterCreation(t, ctx, pool, pending.Challenge)
}

func TestLockedChallengeIDMutationCannotRedirectConsumption(t *testing.T) {
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Microsecond)
	pool := openTestPool(t, ctx)
	resetAndMigrate(t, ctx, pool)
	repository := store.New(pool)
	original := createPendingSession(t, ctx, repository, base)
	second, err := repository.CreatePendingSession(ctx, domain.NewPendingSession{
		UserID:          original.Session.UserID,
		LicenseID:       original.Session.LicenseID,
		ChallengeSHA256: bytes.Repeat([]byte{0x6b}, 32),
		ExpiresAt:       base.Add(3 * time.Minute),
	})
	if err != nil {
		t.Fatalf("CreatePendingSession() second error = %v", err)
	}

	err = repository.WithLockedChallenge(ctx, original.Session.ID, func(locked *store.LockedChallenge) error {
		locked.Challenge.ID = second.Challenge.ID
		return nil
	})
	if err != nil {
		t.Fatalf("WithLockedChallenge() error = %v", err)
	}

	originalConsumedAt := readChallengeConsumedAt(t, ctx, pool, original.Challenge.ID)
	secondConsumedAt := readChallengeConsumedAt(t, ctx, pool, second.Challenge.ID)
	if originalConsumedAt == nil {
		t.Error("original locked challenge remained unconsumed")
	}
	if secondConsumedAt != nil {
		t.Errorf("callback-selected challenge was consumed at %s", *secondConsumedAt)
	}

	replayCallbackRan := false
	err = repository.WithLockedChallenge(ctx, original.Session.ID, func(*store.LockedChallenge) error {
		replayCallbackRan = true
		return nil
	})
	if !errors.Is(err, domain.ErrChallengeConsumed) {
		t.Errorf("replay error = %v, want %v", err, domain.ErrChallengeConsumed)
	}
	if replayCallbackRan {
		t.Error("replay callback ran for the original challenge")
	}
}

func openTestPool(t *testing.T, ctx context.Context) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("TEST_DATABASE_URL must be set for PostgreSQL integration tests")
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("pgxpool.New() error = %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("database ping failed: %v", err)
	}
	return pool
}

func resetAndMigrate(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(ctx, "drop schema public cascade; create schema public"); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	if err := store.MigrateUp(ctx, pool); err != nil {
		t.Fatalf("MigrateUp() error = %v", err)
	}
}

func assertTablesExist(t *testing.T, ctx context.Context, pool *pgxpool.Pool, want bool) {
	t.Helper()
	for _, table := range []string{"users", "licenses", "devices", "auth_sessions", "device_challenges"} {
		var exists bool
		if err := pool.QueryRow(ctx, `select to_regclass('public.' || $1) is not null`, table).Scan(&exists); err != nil {
			t.Fatalf("look up table %s: %v", table, err)
		}
		if exists != want {
			t.Errorf("table %s exists = %t, want %t", table, exists, want)
		}
	}
}

func waitForSignal(t *testing.T, ctx context.Context, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-ctx.Done():
		t.Fatalf("timed out waiting for %s: %v", description, ctx.Err())
	}
}

func receiveResult(t *testing.T, ctx context.Context, results <-chan error) error {
	t.Helper()
	select {
	case err := <-results:
		return err
	case <-ctx.Done():
		t.Fatalf("timed out waiting for transaction result: %v", ctx.Err())
		return nil
	}
}

func waitForBackendLock(t *testing.T, ctx context.Context, pool *pgxpool.Pool, backendPID int) {
	t.Helper()
	const lockedChallengeQueryMarker = "/* starloader:with-locked-challenge */"
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()

	for {
		var waiting bool
		err := pool.QueryRow(ctx, `
			select exists (
				select 1
				from pg_stat_activity
				where pid = $1
				  and wait_event_type = 'Lock'
				  and query like '%' || $2 || '%'
			)`, backendPID, lockedChallengeQueryMarker).Scan(&waiting)
		if err != nil {
			t.Fatalf("inspect second backend lock wait: %v", err)
		}
		if waiting {
			return
		}
		select {
		case <-poll.C:
		case <-ctx.Done():
			t.Fatalf("second backend %d never reported a marked Lock wait: %v", backendPID, ctx.Err())
		}
	}
}

func assertChallengeConsumedAfterCreation(t *testing.T, ctx context.Context, pool *pgxpool.Pool, challenge domain.DeviceChallenge) {
	t.Helper()
	consumedAt := readChallengeConsumedAt(t, ctx, pool, challenge.ID)
	if consumedAt == nil {
		t.Fatal("challenge remained unconsumed")
	}
	if consumedAt.Before(challenge.CreatedAt) {
		t.Fatalf("consumed_at %s is before created_at %s", consumedAt, challenge.CreatedAt)
	}
}

func readChallengeConsumedAt(t *testing.T, ctx context.Context, pool *pgxpool.Pool, challengeID string) *time.Time {
	t.Helper()
	var consumedAt *time.Time
	if err := pool.QueryRow(ctx, `select consumed_at from device_challenges where id = $1`, challengeID).Scan(&consumedAt); err != nil {
		t.Fatalf("read consumed_at: %v", err)
	}
	return consumedAt
}

func createPendingSession(t *testing.T, ctx context.Context, repository *store.Store, base time.Time) *domain.PendingSession {
	t.Helper()
	user, license := createUserAndLicense(t, ctx, repository, "challenge@example.com", base)
	challengeSHA256 := bytes.Repeat([]byte{0x5a}, 32)
	pending, err := repository.CreatePendingSession(ctx, domain.NewPendingSession{
		UserID:          user.ID,
		LicenseID:       license.ID,
		ChallengeSHA256: challengeSHA256,
		ExpiresAt:       base.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatalf("CreatePendingSession() error = %v", err)
	}
	if !bytes.Equal(pending.Challenge.ChallengeSHA256, challengeSHA256) {
		t.Fatalf("stored challenge SHA-256 = %x", pending.Challenge.ChallengeSHA256)
	}
	return pending
}

func createUserAndLicense(t *testing.T, ctx context.Context, repository *store.Store, email string, base time.Time) (*domain.User, *domain.License) {
	t.Helper()
	user, err := repository.CreateUser(ctx, domain.NewUser{
		Email:        email,
		PasswordHash: "$argon2id$v=19$integration-hash",
	})
	if err != nil {
		t.Fatalf("CreateUser() error = %v", err)
	}
	license, err := repository.CreateLicense(ctx, domain.NewLicense{
		LicenseHMAC: "8f46bf9ec2d930aaae995b45ad6f7867ad5c8c8ef9b4b1e9c4ab325ce36af7ac",
		UserID:      user.ID,
		Product:     "StarLoader",
		MaxDevices:  1,
		ExpiresAt:   base.Add(30 * 24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateLicense() error = %v", err)
	}
	return user, license
}

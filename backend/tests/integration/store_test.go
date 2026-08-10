package integration_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/starloader/backend/internal/domain"
	"github.com/starloader/backend/internal/httpapi"
	"github.com/starloader/backend/internal/security"
	"github.com/starloader/backend/internal/service"
	"github.com/starloader/backend/internal/store"
)

func TestDeviceVerificationAcceptanceMatrix(t *testing.T) {
	t.Run("first activation repeat login and no raw hardware", func(t *testing.T) {
		fixture := newPostgresVerificationFixture(t, 1)
		key := generateP256Key(t)
		hardware := acceptanceHardware("raw-one")
		firstInput := fixture.newInput(t, key, hardware, fixture.now.Add(time.Minute))

		first, err := fixture.deviceService.Verify(fixture.ctx, firstInput)
		if err != nil {
			t.Fatalf("first Verify() error = %v", err)
		}
		claims, err := fixture.tokenVerifier.Verify(first.Token)
		if err != nil {
			t.Fatalf("Verify(token) error = %v", err)
		}
		if claims.Subject != fixture.user.ID || claims.LicenseID != fixture.license.ID || claims.DeviceID != first.DeviceID || claims.Product != "StarLoader" || claims.Issuer != "starloader" || claims.Audience != "starloader-client" || !claims.ExpiresAt.Equal(fixture.now.Add(time.Hour)) {
			t.Fatalf("token claims = %#v", claims)
		}

		repeatInput := fixture.newInput(t, key, hardware, fixture.now.Add(time.Minute))
		var capturedLogs strings.Builder
		router := httpapi.NewRouter(httpapi.RouterConfig{
			DeviceVerification: fixture.deviceService,
			Logger:             log.New(&capturedLogs, "", 0),
		})
		request := httptest.NewRequest(http.MethodPost, "/v1/device/verify", strings.NewReader(deviceVerificationJSON(t, repeatInput)))
		request.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("repeat HTTP status = %d, body = %s", recorder.Code, recorder.Body.String())
		}
		if capturedLogs.Len() != 0 {
			t.Fatalf("verification logged request data: %q", capturedLogs.String())
		}

		var deviceCount int
		if err := fixture.pool.QueryRow(fixture.ctx, `select count(*) from devices`).Scan(&deviceCount); err != nil {
			t.Fatal(err)
		}
		if deviceCount != 1 {
			t.Fatalf("device count after repeat login = %d, want 1", deviceCount)
		}
		assertNoRawHardwareInDatabase(t, fixture, hardware)
	})

	t.Run("score 65 is below threshold and reaches full-device limit", func(t *testing.T) {
		fixture := newPostgresVerificationFixture(t, 1)
		key := generateP256Key(t)
		original := acceptanceHardware("original")
		first := fixture.newInput(t, key, original, fixture.now.Add(time.Minute))
		if _, err := fixture.deviceService.Verify(fixture.ctx, first); err != nil {
			t.Fatal(err)
		}
		belowThreshold := acceptanceHardware("changed")
		belowThreshold.MotherboardSerial = original.MotherboardSerial
		input := fixture.newInput(t, key, belowThreshold, fixture.now.Add(time.Minute))

		_, err := fixture.deviceService.Verify(fixture.ctx, input)
		if !errors.Is(err, service.ErrDeviceLimitReached) {
			t.Fatalf("Verify() error = %v, want device limit", err)
		}
		assertChallengeUnconsumed(t, fixture, input.SessionID)
	})

	t.Run("score 70 accepts the existing device", func(t *testing.T) {
		fixture := newPostgresVerificationFixture(t, 1)
		key := generateP256Key(t)
		original := acceptanceHardware("original")
		firstInput := fixture.newInput(t, key, original, fixture.now.Add(time.Minute))
		first, err := fixture.deviceService.Verify(fixture.ctx, firstInput)
		if err != nil {
			t.Fatal(err)
		}
		threshold := acceptanceHardware("changed")
		threshold.SMBIOSUUID = original.SMBIOSUUID
		input := fixture.newInput(t, key, threshold, fixture.now.Add(time.Minute))

		verified, err := fixture.deviceService.Verify(fixture.ctx, input)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if verified.DeviceID != first.DeviceID {
			t.Fatalf("device ID = %q, want existing %q", verified.DeviceID, first.DeviceID)
		}
	})

	t.Run("invalid signature does not consume", func(t *testing.T) {
		fixture := newPostgresVerificationFixture(t, 1)
		input := fixture.newInput(t, generateP256Key(t), acceptanceHardware("invalid"), fixture.now.Add(time.Minute))
		input.ChallengeSignature = base64.StdEncoding.EncodeToString(make([]byte, 64))

		_, err := fixture.deviceService.Verify(fixture.ctx, input)
		if !errors.Is(err, service.ErrInvalidDeviceSignature) {
			t.Fatalf("Verify() error = %v, want invalid signature", err)
		}
		assertChallengeUnconsumed(t, fixture, input.SessionID)
		assertDeviceCount(t, fixture, 0)
	})

	t.Run("expired challenge does not consume", func(t *testing.T) {
		fixture := newPostgresVerificationFixture(t, 1)
		input := fixture.newInput(t, generateP256Key(t), acceptanceHardware("expired"), fixture.now)

		_, err := fixture.deviceService.Verify(fixture.ctx, input)
		if !errors.Is(err, service.ErrChallengeExpired) {
			t.Fatalf("Verify() error = %v, want expired", err)
		}
		assertChallengeUnconsumed(t, fixture, input.SessionID)
	})

	t.Run("replay is rejected", func(t *testing.T) {
		fixture := newPostgresVerificationFixture(t, 1)
		input := fixture.newInput(t, generateP256Key(t), acceptanceHardware("replay"), fixture.now.Add(time.Minute))
		if _, err := fixture.deviceService.Verify(fixture.ctx, input); err != nil {
			t.Fatal(err)
		}

		if _, err := fixture.deviceService.Verify(fixture.ctx, input); !errors.Is(err, domain.ErrChallengeConsumed) {
			t.Fatalf("replay error = %v, want consumed", err)
		}
	})

	t.Run("matching revoked device does not consume", func(t *testing.T) {
		fixture := newPostgresVerificationFixture(t, 1)
		key := generateP256Key(t)
		hardware := acceptanceHardware("revoked")
		firstInput := fixture.newInput(t, key, hardware, fixture.now.Add(time.Minute))
		first, err := fixture.deviceService.Verify(fixture.ctx, firstInput)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.pool.Exec(fixture.ctx, `update devices set status = 'revoked' where id = $1`, first.DeviceID); err != nil {
			t.Fatal(err)
		}
		input := fixture.newInput(t, key, acceptanceHardware("revoked-changed"), fixture.now.Add(time.Minute))

		_, err = fixture.deviceService.Verify(fixture.ctx, input)
		if !errors.Is(err, service.ErrDeviceRevoked) {
			t.Fatalf("Verify() error = %v, want revoked", err)
		}
		assertChallengeUnconsumed(t, fixture, input.SessionID)
	})

	t.Run("concurrent activations enforce one license slot", func(t *testing.T) {
		fixture := newPostgresVerificationFixture(t, 1)
		firstInput := fixture.newInput(t, generateP256Key(t), acceptanceHardware("concurrent-one"), fixture.now.Add(time.Minute))
		secondInput := fixture.newInput(t, generateP256Key(t), acceptanceHardware("concurrent-two"), fixture.now.Add(time.Minute))
		start := make(chan struct{})
		results := make(chan error, 2)
		for _, input := range []service.VerifyInput{firstInput, secondInput} {
			input := input
			go func() {
				<-start
				_, err := fixture.deviceService.Verify(fixture.ctx, input)
				results <- err
			}()
		}
		close(start)
		succeeded, limited := 0, 0
		for range 2 {
			select {
			case err := <-results:
				switch {
				case err == nil:
					succeeded++
				case errors.Is(err, service.ErrDeviceLimitReached):
					limited++
				default:
					t.Fatalf("concurrent Verify() error = %v", err)
				}
			case <-fixture.ctx.Done():
				t.Fatalf("timed out waiting for concurrent verification: %v", fixture.ctx.Err())
			}
		}
		if succeeded != 1 || limited != 1 {
			t.Fatalf("concurrent results: succeeded=%d limited=%d", succeeded, limited)
		}
		assertDeviceCount(t, fixture, 1)
		var consumedCount int
		if err := fixture.pool.QueryRow(fixture.ctx, `select count(*) from device_challenges where consumed_at is not null`).Scan(&consumedCount); err != nil {
			t.Fatal(err)
		}
		if consumedCount != 1 {
			t.Fatalf("consumed challenges = %d, want 1", consumedCount)
		}
	})
}

func TestGeneratedDatabaseIDsUseUUIDv7(t *testing.T) {
	fixture := newPostgresVerificationFixture(t, 1)
	input := fixture.newInput(t, generateP256Key(t), acceptanceHardware("uuid-v7"), fixture.now.Add(time.Minute))
	verified, err := fixture.deviceService.Verify(fixture.ctx, input)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	var challengeID string
	if err := fixture.pool.QueryRow(fixture.ctx, `select id::text from device_challenges where session_id = $1`, input.SessionID).Scan(&challengeID); err != nil {
		t.Fatalf("read challenge ID: %v", err)
	}
	for name, value := range map[string]string{
		"user": fixture.user.ID, "license": fixture.license.ID, "session": input.SessionID,
		"challenge": challengeID, "device": verified.DeviceID,
	} {
		t.Run(name, func(t *testing.T) { assertUUIDv7(t, value) })
	}
}

func assertUUIDv7(t *testing.T, value string) {
	t.Helper()
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' || value[14] != '7' || !strings.ContainsRune("89ab", rune(value[19])) {
		t.Fatalf("ID %q is not canonical UUIDv7", value)
	}
}

func TestVerificationLocksDeviceRowsAgainstConcurrentRevocation(t *testing.T) {
	fixture := newPostgresVerificationFixture(t, 1)
	key := generateP256Key(t)
	hardware := acceptanceHardware("row-lock")
	activated, err := fixture.deviceService.Verify(
		fixture.ctx,
		fixture.newInput(t, key, hardware, fixture.now.Add(time.Minute)),
	)
	if err != nil {
		t.Fatal(err)
	}
	pending := fixture.newInput(t, key, hardware, fixture.now.Add(time.Minute))

	verificationConn, err := fixture.pool.Acquire(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer verificationConn.Release()
	revocationConn, err := fixture.pool.Acquire(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer revocationConn.Release()
	var revocationPID int
	if err := revocationConn.QueryRow(fixture.ctx, `select pg_backend_pid()`).Scan(&revocationPID); err != nil {
		t.Fatal(err)
	}

	decisionRepository := store.New(verificationConn)
	rowsLocked := make(chan struct{})
	releaseDecision := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseDecision) }) }
	defer release()
	decisionErr := errors.New("decision complete without commit")
	decisionResult := make(chan error, 1)
	go func() {
		decisionResult <- decisionRepository.WithLockedChallenge(fixture.ctx, pending.SessionID, func(locked *store.LockedChallenge) error {
			if _, err := locked.LockLicense(fixture.ctx); err != nil {
				return err
			}
			devices, err := locked.ListDevices(fixture.ctx)
			if err != nil {
				return err
			}
			if len(devices) != 1 || devices[0].ID != activated.DeviceID {
				return fmt.Errorf("locked devices = %#v", devices)
			}
			close(rowsLocked)
			select {
			case <-releaseDecision:
				return decisionErr
			case <-fixture.ctx.Done():
				return fixture.ctx.Err()
			}
		})
	}()
	waitForSignal(t, fixture.ctx, rowsLocked, "verification transaction to read device rows")

	const revocationMarker = "/* task9:concurrent-device-revocation */"
	revocationResult := make(chan error, 1)
	go func() {
		_, err := revocationConn.Exec(fixture.ctx, `
			update `+revocationMarker+` devices
			set status = 'revoked'
			where id = $1`, activated.DeviceID)
		revocationResult <- err
	}()
	waitForBackendQueryLockOrCompletion(t, fixture.ctx, fixture.pool, revocationPID, revocationMarker, revocationResult)
	release()

	if err := receiveResult(t, fixture.ctx, decisionResult); !errors.Is(err, decisionErr) {
		t.Fatalf("verification decision error = %v, want %v", err, decisionErr)
	}
	if err := receiveResult(t, fixture.ctx, revocationResult); err != nil {
		t.Fatalf("revocation update error = %v", err)
	}
	assertChallengeUnconsumed(t, fixture, pending.SessionID)
	var status domain.DeviceStatus
	if err := fixture.pool.QueryRow(fixture.ctx, `select status from devices where id = $1`, activated.DeviceID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != domain.DeviceStatusRevoked {
		t.Fatalf("device status = %s, want revoked", status)
	}
}

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
			name: "UUIDv4 identifier",
			sql:  `insert into users (id, email, password_hash) values ('550e8400-e29b-41d4-a716-446655440000', 'uuidv4@example.com', 'hash')`,
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

func waitForBackendQueryLockOrCompletion(t *testing.T, ctx context.Context, pool *pgxpool.Pool, backendPID int, marker string, completed <-chan error) {
	t.Helper()
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()

	for {
		select {
		case err := <-completed:
			t.Fatalf("query completed before the verification decision released its device rows: %v", err)
		default:
		}
		var waiting bool
		if err := pool.QueryRow(ctx, `
			select exists (
				select 1 from pg_stat_activity
				where pid = $1 and wait_event_type = 'Lock' and query like '%' || $2 || '%'
			)`, backendPID, marker).Scan(&waiting); err != nil {
			t.Fatalf("inspect device-row lock wait: %v", err)
		}
		if waiting {
			return
		}
		select {
		case <-poll.C:
		case err := <-completed:
			t.Fatalf("query completed before the verification decision released its device rows: %v", err)
		case <-ctx.Done():
			t.Fatalf("backend %d never reported device-row lock wait: %v", backendPID, ctx.Err())
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

type postgresVerificationFixture struct {
	ctx           context.Context
	pool          *pgxpool.Pool
	repository    *store.Store
	deviceService *service.DeviceService
	tokenVerifier *security.TokenVerifier
	now           time.Time
	user          *domain.User
	license       *domain.License
}

func newPostgresVerificationFixture(t *testing.T, maxDevices int) *postgresVerificationFixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	now := time.Now().UTC().Truncate(time.Second)
	pool := openTestPool(t, ctx)
	resetAndMigrate(t, ctx, pool)
	repository := store.New(pool)
	user, err := repository.CreateUser(ctx, domain.NewUser{
		Email: "device-verification@example.com", PasswordHash: "$argon2id$v=19$integration-hash",
	})
	if err != nil {
		t.Fatal(err)
	}
	license, err := repository.CreateLicense(ctx, domain.NewLicense{
		LicenseHMAC: "a7a5cc218577a36a399be56de9ba9901391f73cc7446c6ee74846825fcc94343",
		UserID:      user.ID, Product: "StarLoader", MaxDevices: maxDevices, ExpiresAt: now.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
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
	deviceService := service.NewDeviceService(service.NewStoreDeviceRepository(repository), service.DeviceServiceConfig{
		HardwareHMACKey: []byte("integration-hardware-secret"), TokenIssuer: issuer,
		Issuer: "starloader", Audience: "starloader-client", Product: "StarLoader", Now: func() time.Time { return now },
	})
	return &postgresVerificationFixture{
		ctx: ctx, pool: pool, repository: repository, deviceService: deviceService,
		tokenVerifier: verifier, now: now, user: user, license: license,
	}
}

func (fixture *postgresVerificationFixture) newInput(t *testing.T, key *ecdsa.PrivateKey, hardware service.HardwareSignals, expiresAt time.Time) service.VerifyInput {
	t.Helper()
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(challenge)
	pending, err := fixture.repository.CreatePendingSession(fixture.ctx, domain.NewPendingSession{
		UserID: fixture.user.ID, LicenseID: fixture.license.ID, ChallengeSHA256: digest[:], ExpiresAt: expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	publicBlob, signature := postgresCNGProof(t, key, challenge)
	return service.VerifyInput{
		SessionID: pending.Session.ID, Challenge: base64.StdEncoding.EncodeToString(challenge),
		ChallengeSignature: base64.StdEncoding.EncodeToString(signature), TPMPublicKey: base64.StdEncoding.EncodeToString(publicBlob),
		Hardware: hardware,
	}
}

func generateP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func postgresCNGProof(t *testing.T, key *ecdsa.PrivateKey, challenge []byte) ([]byte, []byte) {
	t.Helper()
	blob := make([]byte, 72)
	binary.LittleEndian.PutUint32(blob[:4], 0x31534345)
	binary.LittleEndian.PutUint32(blob[4:8], 32)
	key.X.FillBytes(blob[8:40])
	key.Y.FillBytes(blob[40:72])
	digest := sha256.Sum256(challenge)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return blob, signature
}

func acceptanceHardware(suffix string) service.HardwareSignals {
	return service.HardwareSignals{
		SMBIOSUUID: "smbios-" + suffix, MotherboardSerial: "motherboard-" + suffix,
		BIOSSerial: "bios-" + suffix, SystemDiskSerial: "disk-" + suffix,
		MachineGuid: "guid-" + suffix, Fingerprint: "fingerprint-" + suffix,
	}
}

func deviceVerificationJSON(t *testing.T, input service.VerifyInput) string {
	t.Helper()
	body := struct {
		SessionID          string                         `json:"session_id"`
		Challenge          string                         `json:"challenge"`
		ChallengeSignature string                         `json:"challenge_signature"`
		TPMPublicKey       string                         `json:"tpm_public_key"`
		Hardware           deviceVerificationJSONHardware `json:"hardware"`
	}{
		SessionID: input.SessionID, Challenge: input.Challenge, ChallengeSignature: input.ChallengeSignature,
		TPMPublicKey: input.TPMPublicKey,
		Hardware: deviceVerificationJSONHardware{
			SMBIOSUUID: input.Hardware.SMBIOSUUID, MotherboardSerial: input.Hardware.MotherboardSerial,
			BIOSSerial: input.Hardware.BIOSSerial, SystemDiskSerial: input.Hardware.SystemDiskSerial,
			MachineGuid: input.Hardware.MachineGuid, Fingerprint: input.Hardware.Fingerprint,
		},
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

type deviceVerificationJSONHardware struct {
	SMBIOSUUID        string `json:"smbios_uuid"`
	MotherboardSerial string `json:"motherboard_serial"`
	BIOSSerial        string `json:"bios_serial"`
	SystemDiskSerial  string `json:"system_disk_serial"`
	MachineGuid       string `json:"machine_guid"`
	Fingerprint       string `json:"fingerprint"`
}

func assertChallengeUnconsumed(t *testing.T, fixture *postgresVerificationFixture, sessionID string) {
	t.Helper()
	var consumedAt *time.Time
	var status domain.SessionStatus
	if err := fixture.pool.QueryRow(fixture.ctx, `
		select c.consumed_at, s.status
		from device_challenges c join auth_sessions s on s.id = c.session_id
		where s.id = $1`, sessionID).Scan(&consumedAt, &status); err != nil {
		t.Fatal(err)
	}
	if consumedAt != nil || status != domain.SessionStatusPending {
		t.Fatalf("failed verification persisted consumed_at=%v status=%s", consumedAt, status)
	}
}

func assertDeviceCount(t *testing.T, fixture *postgresVerificationFixture, want int) {
	t.Helper()
	var count int
	if err := fixture.pool.QueryRow(fixture.ctx, `select count(*) from devices`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("device count = %d, want %d", count, want)
	}
}

func assertNoRawHardwareInDatabase(t *testing.T, fixture *postgresVerificationFixture, hardware service.HardwareSignals) {
	t.Helper()
	var stored string
	if err := fixture.pool.QueryRow(fixture.ctx, `
		select concat_ws('|', smbios_uuid_hmac, motherboard_serial_hmac, bios_serial_hmac,
			system_disk_serial_hmac, machine_guid_hmac, fingerprint_hmac)
		from devices limit 1`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{hardware.SMBIOSUUID, hardware.MotherboardSerial, hardware.BIOSSerial, hardware.SystemDiskSerial, hardware.MachineGuid, hardware.Fingerprint} {
		if raw != "" && strings.Contains(strings.ToLower(stored), strings.ToLower(raw)) {
			t.Fatalf("database contains raw hardware value %q", raw)
		}
	}
}

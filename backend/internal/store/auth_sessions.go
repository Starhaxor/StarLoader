package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/starloader/backend/internal/domain"
)

func (s *Store) CreatePendingSession(ctx context.Context, input domain.NewPendingSession) (*domain.PendingSession, error) {
	row := s.pool.QueryRow(ctx, `
		with new_session as (
			insert into auth_sessions (user_id, license_id, expires_at)
			values ($1, $2, $3)
			returning id, user_id, license_id, status, expires_at, created_at, updated_at
		), new_challenge as (
			insert into device_challenges (session_id, challenge_sha256, expires_at)
			select id, $4, $3 from new_session
			returning id, session_id, challenge_sha256, expires_at, consumed_at, created_at
		)
		select
			s.id::text, s.user_id::text, s.license_id::text, s.status, s.expires_at, s.created_at, s.updated_at,
			c.id::text, c.session_id::text, c.challenge_sha256, c.expires_at, c.consumed_at, c.created_at
		from new_session s
		join new_challenge c on c.session_id = s.id`,
		input.UserID, input.LicenseID, input.ExpiresAt, input.ChallengeSHA256)

	pending, err := scanPendingSession(row)
	if err != nil {
		return nil, fmt.Errorf("create pending session: %w", err)
	}
	return pending, nil
}

// LockedChallenge is valid only for the duration of a WithLockedChallenge
// callback. All mutations are executed by the same transaction that owns the
// row lock.
type LockedChallenge struct {
	Session   domain.AuthSession
	Challenge domain.DeviceChallenge
	tx        pgx.Tx
}

func (c *LockedChallenge) Consume(ctx context.Context, consumedAt time.Time) error {
	instant := consumedAt.UTC()
	tag, err := c.tx.Exec(ctx, `
		update device_challenges
		set consumed_at = $2
		where id = $1 and consumed_at is null`, c.Challenge.ID, instant)
	if err != nil {
		return fmt.Errorf("consume challenge: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return domain.ErrChallengeConsumed
	}
	c.Challenge.ConsumedAt = &instant
	return nil
}

// WithLockedChallenge serializes access to one session and challenge with
// SELECT FOR UPDATE. The callback and all LockedChallenge mutations commit or
// roll back as a unit.
func (s *Store) WithLockedChallenge(ctx context.Context, sessionID string, fn func(*LockedChallenge) error) error {
	if fn == nil {
		return errors.New("locked challenge callback is required")
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin locked challenge transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(context.Background())
		}
	}()

	locked, err := scanLockedChallenge(tx.QueryRow(ctx, `
		select
			s.id::text, s.user_id::text, s.license_id::text, s.status, s.expires_at, s.created_at, s.updated_at,
			c.id::text, c.session_id::text, c.challenge_sha256, c.expires_at, c.consumed_at, c.created_at
		from auth_sessions s
		join device_challenges c on c.session_id = s.id
		where s.id = $1
		for update of s, c`, sessionID), tx)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrChallengeNotFound
	}
	if err != nil {
		return fmt.Errorf("lock challenge: %w", err)
	}
	if err := fn(locked); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit locked challenge transaction: %w", err)
	}
	committed = true
	return nil
}

func scanPendingSession(row pgx.Row) (*domain.PendingSession, error) {
	var pending domain.PendingSession
	err := row.Scan(
		&pending.Session.ID,
		&pending.Session.UserID,
		&pending.Session.LicenseID,
		&pending.Session.Status,
		&pending.Session.ExpiresAt,
		&pending.Session.CreatedAt,
		&pending.Session.UpdatedAt,
		&pending.Challenge.ID,
		&pending.Challenge.SessionID,
		&pending.Challenge.ChallengeSHA256,
		&pending.Challenge.ExpiresAt,
		&pending.Challenge.ConsumedAt,
		&pending.Challenge.CreatedAt,
	)
	return &pending, err
}

func scanLockedChallenge(row pgx.Row, tx pgx.Tx) (*LockedChallenge, error) {
	pending, err := scanPendingSession(row)
	if err != nil {
		return nil, err
	}
	return &LockedChallenge{Session: pending.Session, Challenge: pending.Challenge, tx: tx}, nil
}

package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/starloader/backend/internal/domain"
)

const adminAccountColumns = `id::text, email, password_hash, status, created_at, updated_at`

const adminSessionColumns = `id::text, admin_account_id::text, token_sha256, ip_address, user_agent, expires_at, created_at, revoked_at`

const auditLogColumns = `id::text, coalesce(admin_account_id::text, ''), actor_email, action, resource_type, resource_id, ip_sha256, user_agent, metadata::text, created_at`

func (s *Store) CreateAdminAccount(ctx context.Context, input domain.NewAdminAccount) (*domain.AdminAccount, error) {
	row := s.db.QueryRow(ctx, `
		insert into admin_accounts (email, password_hash)
		values ($1, $2)
		returning `+adminAccountColumns, normalizeEmail(input.Email), input.PasswordHash)
	account, err := scanAdminAccount(row)
	if err != nil {
		return nil, fmt.Errorf("create admin account: %w", err)
	}
	return account, nil
}

func (s *Store) FindAdminAccountByEmail(ctx context.Context, email string) (*domain.AdminAccount, error) {
	account, err := scanAdminAccount(s.db.QueryRow(ctx,
		`select `+adminAccountColumns+` from admin_accounts where email = $1`, normalizeEmail(email)))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrAdminNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find admin account by email: %w", err)
	}
	return account, nil
}

func (s *Store) CreateAdminSession(ctx context.Context, input domain.NewAdminSession) (*domain.AdminSession, error) {
	row := s.db.QueryRow(ctx, `
		insert into admin_sessions (admin_account_id, token_sha256, ip_address, user_agent, expires_at)
		values ($1, $2, $3, $4, $5)
		returning `+adminSessionColumns,
		input.AdminAccountID, input.TokenSHA256, input.IPAddress, input.UserAgent, input.ExpiresAt)
	session, err := scanAdminSession(row)
	if err != nil {
		return nil, fmt.Errorf("create admin session: %w", err)
	}
	return session, nil
}

// LoadActiveAdminSession returns the session and its account only while the
// session is unrevoked and unexpired and the account is still active.
func (s *Store) LoadActiveAdminSession(ctx context.Context, tokenSHA256 []byte) (*domain.AdminSession, *domain.AdminAccount, error) {
	row := s.db.QueryRow(ctx, `
		select
			s.id::text, s.admin_account_id::text, s.token_sha256, s.ip_address, s.user_agent,
			s.expires_at, s.created_at, s.revoked_at,
			a.id::text, a.email, a.password_hash, a.status, a.created_at, a.updated_at
		from admin_sessions s
		join admin_accounts a on a.id = s.admin_account_id
		where s.token_sha256 = $1
			and s.revoked_at is null
			and s.expires_at > now()
			and a.status = 'active'`, tokenSHA256)
	var session domain.AdminSession
	var account domain.AdminAccount
	err := row.Scan(
		&session.ID, &session.AdminAccountID, &session.TokenSHA256, &session.IPAddress, &session.UserAgent,
		&session.ExpiresAt, &session.CreatedAt, &session.RevokedAt,
		&account.ID, &account.Email, &account.PasswordHash, &account.Status, &account.CreatedAt, &account.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, domain.ErrAdminSessionNotFound
	}
	if err != nil {
		return nil, nil, fmt.Errorf("load active admin session: %w", err)
	}
	return &session, &account, nil
}

func (s *Store) RevokeAdminSession(ctx context.Context, sessionID string) error {
	if err := s.db.QueryRow(ctx, `
		update admin_sessions
		set revoked_at = now()
		where id = $1 and revoked_at is null
		returning id`, sessionID).Scan(new(string)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("revoke admin session: %w", err)
	}
	return nil
}

// AppendAuditLog writes one immutable audit record. An empty AdminAccountID
// is stored as NULL so failed logins can still carry the attempted email.
func (s *Store) AppendAuditLog(ctx context.Context, input domain.NewAuditLog) error {
	var metadata any
	if len(input.Metadata) > 0 {
		metadata = string(input.Metadata)
	}
	err := s.db.QueryRow(ctx, `
		insert into audit_logs (admin_account_id, actor_email, action, resource_type, resource_id, ip_sha256, user_agent, metadata)
		values (nullif($1, '')::uuid, $2, $3, $4, $5, $6, $7, coalesce($8::jsonb, '{}'::jsonb))
		returning id`,
		input.AdminAccountID, input.ActorEmail, input.Action, input.ResourceType, input.ResourceID,
		input.IPSHA256, input.UserAgent, metadata).Scan(new(string))
	if err != nil {
		return fmt.Errorf("append audit log: %w", err)
	}
	return nil
}

func (s *Store) ListAuditLogs(ctx context.Context, offset, limit int) ([]domain.AuditLog, int64, error) {
	var total int64
	if err := s.db.QueryRow(ctx, `select count(*) from audit_logs`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count audit logs: %w", err)
	}
	rows, err := s.db.Query(ctx, `
		select `+auditLogColumns+`
		from audit_logs
		order by created_at desc, id desc
		limit $1 offset $2`, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list audit logs: %w", err)
	}
	defer rows.Close()
	logs := make([]domain.AuditLog, 0, limit)
	for rows.Next() {
		auditLog, err := scanAuditLog(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("scan audit log: %w", err)
		}
		logs = append(logs, *auditLog)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("list audit logs: %w", err)
	}
	return logs, total, nil
}

func scanAdminAccount(row pgx.Row) (*domain.AdminAccount, error) {
	var account domain.AdminAccount
	err := row.Scan(&account.ID, &account.Email, &account.PasswordHash, &account.Status, &account.CreatedAt, &account.UpdatedAt)
	return &account, err
}

func scanAdminSession(row pgx.Row) (*domain.AdminSession, error) {
	var session domain.AdminSession
	err := row.Scan(
		&session.ID, &session.AdminAccountID, &session.TokenSHA256, &session.IPAddress, &session.UserAgent,
		&session.ExpiresAt, &session.CreatedAt, &session.RevokedAt,
	)
	return &session, err
}

func scanAuditLog(row pgx.Row) (*domain.AuditLog, error) {
	var auditLog domain.AuditLog
	var metadata string
	err := row.Scan(
		&auditLog.ID, &auditLog.AdminAccountID, &auditLog.ActorEmail, &auditLog.Action,
		&auditLog.ResourceType, &auditLog.ResourceID, &auditLog.IPSHA256, &auditLog.UserAgent,
		&metadata, &auditLog.CreatedAt,
	)
	if err != nil {
		return nil, err
	}
	auditLog.Metadata = []byte(metadata)
	return &auditLog, nil
}

package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/starloader/backend/internal/domain"
)

// adminAccountColumns selects the account joined with its role so every scan
// carries the RBAC permission set.
const adminAccountColumns = `a.id::text, a.email, a.password_hash, a.status,
	r.id::text, r.name, coalesce(r.permissions, '{}'), coalesce(a.totp_secret, ''), a.mfa_enrolled,
	a.created_at, a.updated_at`

const adminAccountTables = `from admin_accounts a join roles r on r.id = a.role_id`

// adminAccountReturningColumns mirrors adminAccountColumns for INSERT ...
// RETURNING, where the target table cannot carry the "a" alias.
const adminAccountReturningColumns = `created.id::text, created.email, created.password_hash, created.status,
	r.id::text, r.name, coalesce(r.permissions, '{}'), coalesce(created.totp_secret, ''), created.mfa_enrolled,
	created.created_at, created.updated_at`

const adminSessionColumns = `id::text, admin_account_id::text, token_sha256, ip_address, user_agent, expires_at, created_at, revoked_at`

const auditLogColumns = `id::text, coalesce(admin_account_id::text, ''), actor_email, action, resource_type, resource_id, ip_sha256, user_agent, metadata::text, created_at`

func (s *Store) CreateAdminAccount(ctx context.Context, input domain.NewAdminAccount) (*domain.AdminAccount, error) {
	roleName := input.RoleName
	if roleName == "" {
		roleName = domain.RoleOwner
	}
	row := s.db.QueryRow(ctx, `
		with created as (
			insert into admin_accounts (email, password_hash, role_id)
			values ($1, $2, (select id from roles where name = $3))
			returning *
		)
		select `+adminAccountReturningColumns+`
		from created
		join roles r on r.id = created.role_id`, normalizeEmail(input.Email), input.PasswordHash, roleName)
	account, err := scanAdminAccount(row)
	if err != nil {
		var pgErr *pgconn.PgError
		switch {
		case errors.As(err, &pgErr) && pgErr.ConstraintName == "admin_accounts_email_unique":
			return nil, domain.ErrAdminAlreadyExists
		case errors.As(err, &pgErr) && pgErr.Code == "23502" && pgErr.ColumnName == "role_id":
			return nil, domain.ErrRoleNotFound
		case errors.Is(err, pgx.ErrNoRows):
			return nil, domain.ErrRoleNotFound
		}
		return nil, fmt.Errorf("create admin account: %w", err)
	}
	return account, nil
}

func (s *Store) FindAdminAccountByEmail(ctx context.Context, email string) (*domain.AdminAccount, error) {
	account, err := scanAdminAccount(s.db.QueryRow(ctx,
		`select `+adminAccountColumns+` `+adminAccountTables+` where a.email = $1`, normalizeEmail(email)))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrAdminNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find admin account by email: %w", err)
	}
	return account, nil
}

func (s *Store) FindAdminAccountByID(ctx context.Context, adminID string) (*domain.AdminAccount, error) {
	account, err := scanAdminAccount(s.db.QueryRow(ctx,
		`select `+adminAccountColumns+` `+adminAccountTables+` where a.id = $1::uuid`, adminID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrAdminNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find admin account by id: %w", err)
	}
	return account, nil
}

func (s *Store) ListAdminAccounts(ctx context.Context) ([]domain.AdminAccount, error) {
	rows, err := s.db.Query(ctx, `
		select `+adminAccountColumns+`
		`+adminAccountTables+`
		order by a.created_at asc, a.id asc`)
	if err != nil {
		return nil, fmt.Errorf("list admin accounts: %w", err)
	}
	defer rows.Close()
	accounts := make([]domain.AdminAccount, 0)
	for rows.Next() {
		account, err := scanAdminAccount(rows)
		if err != nil {
			return nil, fmt.Errorf("scan admin account: %w", err)
		}
		accounts = append(accounts, *account)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list admin accounts: %w", err)
	}
	return accounts, nil
}

// UpdateAdminAccountStatusAndRole changes status and/or role in one guarded
// statement. Empty role name leaves the role untouched.
func (s *Store) UpdateAdminAccountStatusAndRole(ctx context.Context, adminID string, status domain.AdminAccountStatus, roleName string) error {
	var err error
	if roleName == "" {
		err = s.db.QueryRow(ctx, `
			update admin_accounts
			set status = $2, updated_at = now()
			where id = $1::uuid
			returning id`, adminID, string(status)).Scan(new(string))
	} else {
		err = s.db.QueryRow(ctx, `
			update admin_accounts
			set status = $2,
				role_id = (select id from roles where name = $3),
				updated_at = now()
			where id = $1::uuid
			returning id`, adminID, string(status), roleName).Scan(new(string))
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrAdminNotFound
	}
	if err != nil {
		return fmt.Errorf("update admin account: %w", err)
	}
	return nil
}

// ListRoles returns every RBAC role with its permission set; used to validate
// role assignments and to render the role picker in the console.
func (s *Store) ListRoles(ctx context.Context) ([]domain.Role, error) {
	rows, err := s.db.Query(ctx, `
		select id::text, name, description, permissions, built_in
		from roles
		order by created_at asc, id asc`)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	defer rows.Close()
	roles := make([]domain.Role, 0)
	for rows.Next() {
		var role domain.Role
		if err := rows.Scan(&role.ID, &role.Name, &role.Description, &role.Permissions, &role.BuiltIn); err != nil {
			return nil, fmt.Errorf("scan role: %w", err)
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	return roles, nil
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
			a.id::text, a.email, a.password_hash, a.status,
			r.id::text, r.name, coalesce(r.permissions, '{}'), coalesce(a.totp_secret, ''), a.mfa_enrolled,
			a.created_at, a.updated_at
		from admin_sessions s
		join admin_accounts a on a.id = s.admin_account_id
		join roles r on r.id = a.role_id
		where s.token_sha256 = $1
			and s.revoked_at is null
			and s.expires_at > now()
			and a.status = 'active'`, tokenSHA256)
	var session domain.AdminSession
	var account domain.AdminAccount
	err := row.Scan(
		&session.ID, &session.AdminAccountID, &session.TokenSHA256, &session.IPAddress, &session.UserAgent,
		&session.ExpiresAt, &session.CreatedAt, &session.RevokedAt,
		&account.ID, &account.Email, &account.PasswordHash, &account.Status,
		&account.RoleID, &account.RoleName, &account.Permissions, &account.TOTPSecret, &account.MFAEnrolled,
		&account.CreatedAt, &account.UpdatedAt,
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

// RevokeAllAdminSessions drops every active session of one account, used when
// the account is disabled or its MFA is turned off.
func (s *Store) RevokeAllAdminSessions(ctx context.Context, adminID string) error {
	err := s.db.QueryRow(ctx, `
		update admin_sessions
		set revoked_at = now()
		where admin_account_id = $1::uuid and revoked_at is null
		returning id`, adminID).Scan(new(string))
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("revoke all admin sessions: %w", err)
	}
	return nil
}

// --- TOTP enrollment ---

// StartAdminTOTPEnrollment stores a pending secret; mfa_enrolled stays false
// until the code is confirmed.
func (s *Store) StartAdminTOTPEnrollment(ctx context.Context, adminID, secret string) error {
	if err := s.db.QueryRow(ctx, `
		update admin_accounts
		set totp_secret = $2, updated_at = now()
		where id = $1::uuid
		returning id`, adminID, secret).Scan(new(string)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrAdminNotFound
		}
		return fmt.Errorf("start totp enrollment: %w", err)
	}
	return nil
}

// ConfirmAdminTOTPEnrollment flips mfa_enrolled once a valid code proves the
// secret was registered in an authenticator app.
func (s *Store) ConfirmAdminTOTPEnrollment(ctx context.Context, adminID string) error {
	if err := s.db.QueryRow(ctx, `
		update admin_accounts
		set mfa_enrolled = true, updated_at = now()
		where id = $1::uuid and totp_secret is not null
		returning id`, adminID).Scan(new(string)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrAdminNotFound
		}
		return fmt.Errorf("confirm totp enrollment: %w", err)
	}
	return nil
}

// DisableAdminMFA clears the secret and enrollment flag.
func (s *Store) DisableAdminMFA(ctx context.Context, adminID string) error {
	if err := s.db.QueryRow(ctx, `
		update admin_accounts
		set totp_secret = null, mfa_enrolled = false, updated_at = now()
		where id = $1::uuid
		returning id`, adminID).Scan(new(string)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrAdminNotFound
		}
		return fmt.Errorf("disable admin mfa: %w", err)
	}
	return nil
}

// --- Recovery codes ---

// ReplaceAdminRecoveryCodes stores the SHA-256 digests of freshly generated
// codes, discarding any previous batch.
func (s *Store) ReplaceAdminRecoveryCodes(ctx context.Context, adminID string, codeHashes [][]byte) error {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin recovery code replacement: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := tx.QueryRow(ctx, `delete from admin_recovery_codes where admin_account_id = $1::uuid returning id`, adminID).Scan(new(string)); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("delete old recovery codes: %w", err)
	}
	for _, digest := range codeHashes {
		if _, err := tx.Exec(ctx, `
			insert into admin_recovery_codes (admin_account_id, code_sha256)
			values ($1::uuid, $2)`, adminID, digest); err != nil {
			return fmt.Errorf("insert recovery code: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit recovery codes: %w", err)
	}
	return nil
}

// ConsumeAdminRecoveryCode marks one unused code as used. Codes are looked up
// by digest so plaintext never reaches the database.
func (s *Store) ConsumeAdminRecoveryCode(ctx context.Context, adminID string, codeSHA256 []byte) error {
	if err := s.db.QueryRow(ctx, `
		update admin_recovery_codes
		set used_at = now()
		where admin_account_id = $1::uuid and code_sha256 = $2 and used_at is null
		returning id`, adminID, codeSHA256).Scan(new(string)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrAdminRecoveryCodeNotFound
		}
		return fmt.Errorf("consume recovery code: %w", err)
	}
	return nil
}

// --- MFA challenges ---

func (s *Store) CreateAdminMFAChallenge(ctx context.Context, input domain.NewAdminMFAChallenge) (*domain.AdminMFAChallenge, error) {
	row := s.db.QueryRow(ctx, `
		insert into admin_mfa_challenges (admin_account_id, token_sha256, ip_address, user_agent, expires_at)
		values ($1, $2, $3, $4, $5)
		returning id::text, admin_account_id::text, token_sha256, expires_at, created_at`,
		input.AdminAccountID, input.TokenSHA256, input.IPAddress, input.UserAgent, input.ExpiresAt)
	var challenge domain.AdminMFAChallenge
	if err := row.Scan(&challenge.ID, &challenge.AdminAccountID, &challenge.TokenSHA256, &challenge.ExpiresAt, &challenge.CreatedAt); err != nil {
		return nil, fmt.Errorf("create admin mfa challenge: %w", err)
	}
	return &challenge, nil
}

// ConsumeAdminMFAChallenge loads a still-valid challenge and deletes it so it
// can never be replayed.
func (s *Store) ConsumeAdminMFAChallenge(ctx context.Context, tokenSHA256 []byte) (*domain.AdminMFAChallenge, error) {
	row := s.db.QueryRow(ctx, `
		delete from admin_mfa_challenges
		where id = (
			select id from admin_mfa_challenges
			where token_sha256 = $1 and expires_at > now()
			limit 1
		)
		returning id::text, admin_account_id::text, token_sha256, expires_at, created_at`, tokenSHA256)
	var challenge domain.AdminMFAChallenge
	err := row.Scan(&challenge.ID, &challenge.AdminAccountID, &challenge.TokenSHA256, &challenge.ExpiresAt, &challenge.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrAdminMFAChallengeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("consume admin mfa challenge: %w", err)
	}
	return &challenge, nil
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

// --- Security events ---

func (s *Store) AppendSecurityEvent(ctx context.Context, input domain.NewSecurityEvent) error {
	var metadata any
	if len(input.Metadata) > 0 {
		metadata = string(input.Metadata)
	}
	err := s.db.QueryRow(ctx, `
		insert into security_events (kind, severity, admin_account_id, actor_email, ip_sha256, user_agent, metadata)
		values ($1, $2, nullif($3, '')::uuid, $4, $5, $6, coalesce($7::jsonb, '{}'::jsonb))
		returning id`,
		input.Kind, input.Severity, input.AdminAccountID, input.ActorEmail,
		input.IPSHA256, input.UserAgent, metadata).Scan(new(string))
	if err != nil {
		return fmt.Errorf("append security event: %w", err)
	}
	return nil
}

func (s *Store) ListSecurityEvents(ctx context.Context, offset, limit int) ([]domain.SecurityEvent, int64, error) {
	var total int64
	if err := s.db.QueryRow(ctx, `select count(*) from security_events`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count security events: %w", err)
	}
	rows, err := s.db.Query(ctx, `
		select id::text, kind, severity, coalesce(admin_account_id::text, ''), actor_email, ip_sha256, user_agent, metadata::text, created_at
		from security_events
		order by created_at desc, id desc
		limit $1 offset $2`, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list security events: %w", err)
	}
	defer rows.Close()
	events := make([]domain.SecurityEvent, 0, limit)
	for rows.Next() {
		var event domain.SecurityEvent
		var metadata string
		if err := rows.Scan(&event.ID, &event.Kind, &event.Severity, &event.AdminAccountID, &event.ActorEmail,
			&event.IPSHA256, &event.UserAgent, &metadata, &event.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("scan security event: %w", err)
		}
		event.Metadata = []byte(metadata)
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("list security events: %w", err)
	}
	return events, total, nil
}

func scanAdminAccount(row pgx.Row) (*domain.AdminAccount, error) {
	var account domain.AdminAccount
	err := row.Scan(
		&account.ID, &account.Email, &account.PasswordHash, &account.Status,
		&account.RoleID, &account.RoleName, &account.Permissions, &account.TOTPSecret, &account.MFAEnrolled,
		&account.CreatedAt, &account.UpdatedAt,
	)
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

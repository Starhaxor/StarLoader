package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/starloader/backend/internal/domain"
)

// Console queries serve the admin dashboard. Every query is parameterized and
// read views never expose password hashes, HMACs or raw hardware identifiers.

func (s *Store) ConsoleOverview(ctx context.Context) (*domain.ConsoleOverview, error) {
	overview := &domain.ConsoleOverview{}
	err := s.db.QueryRow(ctx, `
		select
			(select count(*) from users),
			(select count(*) from licenses where status = 'active' and expires_at > now()),
			(select count(*) from devices where status = 'active'),
			(select count(*) from auth_sessions where status = 'verified' and expires_at > now())`).
		Scan(&overview.TotalUsers, &overview.ActiveLicenses, &overview.ActiveDevices, &overview.ActiveSessions)
	if err != nil {
		return nil, fmt.Errorf("console overview: %w", err)
	}
	recent, _, err := s.ListAuditLogs(ctx, 0, 8)
	if err != nil {
		return nil, err
	}
	overview.RecentAudit = recent
	return overview, nil
}

// ConsoleDailyStats returns a per-day activity series (licenses created,
// devices registered, sessions created, audit events and admin logins) for
// the trailing days window. Days without events are included with zeroes.
func (s *Store) ConsoleDailyStats(ctx context.Context, days int) ([]domain.DailyStat, error) {
	if days < 1 || days > 90 {
		days = 14
	}
	countByDay := func(query string, args ...any) (map[string]int64, error) {
		rows, err := s.db.Query(ctx, query, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		counts := make(map[string]int64)
		for rows.Next() {
			var day string
			var count int64
			if err := rows.Scan(&day, &count); err != nil {
				return nil, err
			}
			counts[day] = count
		}
		return counts, rows.Err()
	}
	window := fmt.Sprintf("created_at >= now() - interval '%d days'", days)
	licenses, err := countByDay(`select to_char(created_at at time zone 'UTC', 'YYYY-MM-DD'), count(*) from licenses where ` + window + ` group by 1`)
	if err != nil {
		return nil, fmt.Errorf("daily licenses: %w", err)
	}
	devices, err := countByDay(`select to_char(created_at at time zone 'UTC', 'YYYY-MM-DD'), count(*) from devices where ` + window + ` group by 1`)
	if err != nil {
		return nil, fmt.Errorf("daily devices: %w", err)
	}
	sessions, err := countByDay(`select to_char(created_at at time zone 'UTC', 'YYYY-MM-DD'), count(*) from auth_sessions where ` + window + ` group by 1`)
	if err != nil {
		return nil, fmt.Errorf("daily sessions: %w", err)
	}
	audit, err := countByDay(`select to_char(created_at at time zone 'UTC', 'YYYY-MM-DD'), count(*) from audit_logs where ` + window + ` group by 1`)
	if err != nil {
		return nil, fmt.Errorf("daily audit: %w", err)
	}
	logins, err := countByDay(`select to_char(created_at at time zone 'UTC', 'YYYY-MM-DD'), count(*) from audit_logs where action = 'ADMIN_LOGIN' and ` + window + ` group by 1`)
	if err != nil {
		return nil, fmt.Errorf("daily logins: %w", err)
	}

	start := time.Now().UTC().Truncate(24 * time.Hour).AddDate(0, 0, -(days - 1))
	stats := make([]domain.DailyStat, 0, days)
	for i := 0; i < days; i++ {
		day := start.AddDate(0, 0, i).Format("2006-01-02")
		stats = append(stats, domain.DailyStat{
			Day:               day,
			LicensesCreated:   licenses[day],
			DevicesRegistered: devices[day],
			SessionsCreated:   sessions[day],
			AuditEvents:       audit[day],
			AdminLogins:       logins[day],
		})
	}
	return stats, nil
}

func (s *Store) ListConsoleUsers(ctx context.Context, offset, limit int, search string) ([]domain.ConsoleUser, int64, error) {
	search = strings.ToLower(strings.TrimSpace(search))
	var total int64
	countQuery := `select count(*) from users`
	countArgs := []any{}
	if search != "" {
		countQuery = `select count(*) from users where position($1 in email) > 0`
		countArgs = []any{search}
	}
	if err := s.db.QueryRow(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count console users: %w", err)
	}
	rows, err := s.db.Query(ctx, `
		with filtered as (
			select id
			from users
			where ($3 = '' or position($3 in email) > 0)
			order by created_at desc, id desc
			limit $2 offset $1
		)
		select u.id::text, u.email, u.status, u.created_at,
			(select count(*)::integer from licenses l where l.user_id = u.id),
			(select count(*)::integer from devices d where d.user_id = u.id),
			(select count(*)::integer from auth_sessions ss
				where ss.user_id = u.id and ss.status = 'verified' and ss.expires_at > now()),
			(select max(ss.created_at) from auth_sessions ss where ss.user_id = u.id)
		from filtered f
		join users u on u.id = f.id
		order by u.created_at desc, u.id desc`, offset, limit, search)
	if err != nil {
		return nil, 0, fmt.Errorf("list console users: %w", err)
	}
	defer rows.Close()
	users := make([]domain.ConsoleUser, 0, limit)
	for rows.Next() {
		var user domain.ConsoleUser
		if err := rows.Scan(&user.ID, &user.Email, &user.Status, &user.CreatedAt,
			&user.LicenseCount, &user.DeviceCount, &user.ActiveSessionCount, &user.LastLoginAt); err != nil {
			return nil, 0, fmt.Errorf("scan console user: %w", err)
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("list console users: %w", err)
	}
	return users, total, nil
}

func (s *Store) ConsoleUserDetail(ctx context.Context, userID string) (*domain.ConsoleUserDetail, error) {
	row := s.db.QueryRow(ctx, `
		select u.id::text, u.email, u.status, u.created_at,
			(select count(*)::integer from licenses l where l.user_id = u.id),
			(select count(*)::integer from devices d where d.user_id = u.id),
			(select count(*)::integer from auth_sessions ss
				where ss.user_id = u.id and ss.status = 'verified' and ss.expires_at > now()),
			(select max(ss.created_at) from auth_sessions ss where ss.user_id = u.id)
		from users u
		where u.id = $1::uuid`, userID)
	var user domain.ConsoleUser
	err := row.Scan(&user.ID, &user.Email, &user.Status, &user.CreatedAt,
		&user.LicenseCount, &user.DeviceCount, &user.ActiveSessionCount, &user.LastLoginAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("find console user: %w", err)
	}
	detail := &domain.ConsoleUserDetail{User: user}
	if detail.Licenses, err = s.listConsoleLicenses(ctx, "where l.user_id = $1", userID); err != nil {
		return nil, err
	}
	if detail.Devices, err = s.listConsoleDevices(ctx, "where d.user_id = $1", userID); err != nil {
		return nil, err
	}
	if detail.Sessions, err = s.listConsoleSessions(ctx, "where ss.user_id = $1", userID); err != nil {
		return nil, err
	}
	return detail, nil
}

func (s *Store) SetUserStatus(ctx context.Context, userID string, status domain.UserStatus) error {
	err := s.db.QueryRow(ctx, `
		update users
		set status = $2, updated_at = now()
		where id = $1::uuid
		returning id`, userID, string(status)).Scan(new(string))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrUserNotFound
		}
		return fmt.Errorf("set user status: %w", err)
	}
	return nil
}

func (s *Store) ListConsoleLicenses(ctx context.Context, offset, limit int) ([]domain.ConsoleLicense, int64, error) {
	var total int64
	if err := s.db.QueryRow(ctx, `select count(*) from licenses`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count console licenses: %w", err)
	}
	licenses, err := s.listConsoleLicenses(ctx, "order by l.created_at desc, l.id desc limit $1 offset $2", limit, offset)
	if err != nil {
		return nil, 0, err
	}
	return licenses, total, nil
}

func (s *Store) listConsoleLicenses(ctx context.Context, tail string, args ...any) ([]domain.ConsoleLicense, error) {
	rows, err := s.db.Query(ctx, `
		select l.id::text, l.user_id::text, u.email, l.product, l.status, l.max_devices, l.expires_at, l.created_at
		from licenses l
		join users u on u.id = l.user_id
		`+tail, args...)
	if err != nil {
		return nil, fmt.Errorf("list console licenses: %w", err)
	}
	defer rows.Close()
	licenses := make([]domain.ConsoleLicense, 0)
	for rows.Next() {
		var license domain.ConsoleLicense
		if err := rows.Scan(&license.ID, &license.UserID, &license.UserEmail, &license.Product,
			&license.Status, &license.MaxDevices, &license.ExpiresAt, &license.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan console license: %w", err)
		}
		licenses = append(licenses, license)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list console licenses: %w", err)
	}
	return licenses, nil
}

func (s *Store) FindLicenseByID(ctx context.Context, licenseID string) (*domain.License, error) {
	license, err := scanLicense(s.db.QueryRow(ctx,
		`select `+licenseColumns+` from licenses where id = $1::uuid`, licenseID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrLicenseNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find license by id: %w", err)
	}
	return license, nil
}

// AdminUpdateLicense extends expiry and adjusts the device limit. Revoked
// licenses cannot be modified; a renewed license returns to active status.
func (s *Store) AdminUpdateLicense(ctx context.Context, licenseID string, expiresAt time.Time, maxDevices int) error {
	err := s.db.QueryRow(ctx, `
		update licenses
		set expires_at = $2, max_devices = $3, status = 'active', updated_at = now()
		where id = $1::uuid and status <> 'revoked'
		returning id`, licenseID, expiresAt, maxDevices).Scan(new(string))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrLicenseNotFound
		}
		return fmt.Errorf("update license: %w", err)
	}
	return nil
}

func (s *Store) AdminRevokeLicense(ctx context.Context, licenseID string) error {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin license revocation: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	tag, err := tx.Exec(ctx, `
		update licenses
		set status = 'revoked', updated_at = now()
		where id = $1::uuid and status <> 'revoked'`, licenseID)
	if err != nil {
		return fmt.Errorf("revoke license: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return domain.ErrLicenseNotFound
	}
	if _, err := tx.Exec(ctx, `
		update auth_sessions
		set status = 'expired', updated_at = now()
		where license_id = $1::uuid and status in ('pending', 'verified')`, licenseID); err != nil {
		return fmt.Errorf("expire revoked license sessions: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit license revocation: %w", err)
	}
	return nil
}

func (s *Store) ListConsoleDevices(ctx context.Context, offset, limit int) ([]domain.ConsoleDevice, int64, error) {
	var total int64
	if err := s.db.QueryRow(ctx, `select count(*) from devices`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count console devices: %w", err)
	}
	devices, err := s.listConsoleDevices(ctx, "order by d.last_seen_at desc, d.id desc limit $1 offset $2", limit, offset)
	if err != nil {
		return nil, 0, err
	}
	return devices, total, nil
}

func (s *Store) listConsoleDevices(ctx context.Context, tail string, args ...any) ([]domain.ConsoleDevice, error) {
	rows, err := s.db.Query(ctx, `
		select d.id::text, d.user_id::text, u.email, d.license_id::text,
			octet_length(d.tpm_public_key) > 0,
			d.smbios_uuid_hmac is not null,
			d.motherboard_serial_hmac is not null,
			d.bios_serial_hmac is not null,
			d.system_disk_serial_hmac is not null,
			d.machine_guid_hmac is not null,
			d.status, d.created_at, d.last_seen_at
		from devices d
		join users u on u.id = d.user_id
		`+tail, args...)
	if err != nil {
		return nil, fmt.Errorf("list console devices: %w", err)
	}
	defer rows.Close()
	devices := make([]domain.ConsoleDevice, 0)
	for rows.Next() {
		var device domain.ConsoleDevice
		if err := rows.Scan(&device.ID, &device.UserID, &device.UserEmail, &device.LicenseID,
			&device.TPMRegistered, &device.HasSMBIOSUUID, &device.HasMotherboardSerial,
			&device.HasBIOSSerial, &device.HasSystemDiskSerial, &device.HasMachineGUID,
			&device.Status, &device.CreatedAt, &device.LastSeenAt); err != nil {
			return nil, fmt.Errorf("scan console device: %w", err)
		}
		devices = append(devices, device)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list console devices: %w", err)
	}
	return devices, nil
}

// FindConsoleDeviceByID returns the redacted device view plus the TPM public
// key fingerprint and the license product. No raw hardware identifier leaves
// the database.
func (s *Store) FindConsoleDeviceByID(ctx context.Context, deviceID string) (*domain.ConsoleDeviceDetail, error) {
	row := s.db.QueryRow(ctx, `
		select d.id::text, d.user_id::text, u.email, d.license_id::text,
			octet_length(d.tpm_public_key) > 0,
			d.smbios_uuid_hmac is not null,
			d.motherboard_serial_hmac is not null,
			d.bios_serial_hmac is not null,
			d.system_disk_serial_hmac is not null,
			d.machine_guid_hmac is not null,
			d.status, d.created_at, d.last_seen_at,
			l.product, encode(d.tpm_public_key_sha256, 'hex')
		from devices d
		join users u on u.id = d.user_id
		join licenses l on l.id = d.license_id
		where d.id = $1::uuid`, deviceID)
	var detail domain.ConsoleDeviceDetail
	err := row.Scan(&detail.Device.ID, &detail.Device.UserID, &detail.Device.UserEmail, &detail.Device.LicenseID,
		&detail.Device.TPMRegistered, &detail.Device.HasSMBIOSUUID, &detail.Device.HasMotherboardSerial,
		&detail.Device.HasBIOSSerial, &detail.Device.HasSystemDiskSerial, &detail.Device.HasMachineGUID,
		&detail.Device.Status, &detail.Device.CreatedAt, &detail.Device.LastSeenAt,
		&detail.Product, &detail.TPMFingerprint)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, domain.ErrDeviceNotFound
		}
		return nil, fmt.Errorf("find console device: %w", err)
	}
	return &detail, nil
}

// AdminResetDevice removes the hardware registration entirely so the user can
// register a fresh device; pending sessions bound to the license stay intact.
func (s *Store) AdminResetDevice(ctx context.Context, deviceID string) error {
	err := s.db.QueryRow(ctx, `
		delete from devices
		where id = $1::uuid
		returning id`, deviceID).Scan(new(string))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrDeviceNotFound
		}
		return fmt.Errorf("reset device: %w", err)
	}
	return nil
}

// RevokeUserSessions expires every pending or verified auth session of the
// user and reports how many were revoked.
func (s *Store) RevokeUserSessions(ctx context.Context, userID string) (int64, error) {
	var exists bool
	if err := s.db.QueryRow(ctx, `select exists(select 1 from users where id = $1::uuid)`, userID).Scan(&exists); err != nil {
		return 0, fmt.Errorf("check user for session revocation: %w", err)
	}
	if !exists {
		return 0, domain.ErrUserNotFound
	}
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, fmt.Errorf("begin user session revocation: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	tag, err := tx.Exec(ctx, `
		update auth_sessions
		set status = 'expired', updated_at = now()
		where user_id = $1::uuid and status in ('pending', 'verified')`, userID)
	if err != nil {
		return 0, fmt.Errorf("revoke user sessions: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit user session revocation: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (s *Store) AdminRevokeDevice(ctx context.Context, deviceID string) error {
	err := s.db.QueryRow(ctx, `
		update devices
		set status = 'revoked', updated_at = now()
		where id = $1::uuid and status = 'active'
		returning id`, deviceID).Scan(new(string))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrDeviceNotFound
		}
		return fmt.Errorf("revoke device: %w", err)
	}
	return nil
}

func (s *Store) ListConsoleSessions(ctx context.Context, offset, limit int) ([]domain.ConsoleSession, int64, error) {
	var total int64
	if err := s.db.QueryRow(ctx, `select count(*) from auth_sessions`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count console sessions: %w", err)
	}
	sessions, err := s.listConsoleSessions(ctx, "order by ss.created_at desc, ss.id desc limit $1 offset $2", limit, offset)
	if err != nil {
		return nil, 0, err
	}
	return sessions, total, nil
}

func (s *Store) listConsoleSessions(ctx context.Context, tail string, args ...any) ([]domain.ConsoleSession, error) {
	rows, err := s.db.Query(ctx, `
		select ss.id::text, ss.user_id::text, u.email, ss.license_id::text, ss.status, ss.expires_at, ss.created_at
		from auth_sessions ss
		join users u on u.id = ss.user_id
		`+tail, args...)
	if err != nil {
		return nil, fmt.Errorf("list console sessions: %w", err)
	}
	defer rows.Close()
	sessions := make([]domain.ConsoleSession, 0)
	for rows.Next() {
		var session domain.ConsoleSession
		if err := rows.Scan(&session.ID, &session.UserID, &session.UserEmail, &session.LicenseID,
			&session.Status, &session.ExpiresAt, &session.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan console session: %w", err)
		}
		sessions = append(sessions, session)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list console sessions: %w", err)
	}
	return sessions, nil
}

func (s *Store) AdminRevokeAuthSession(ctx context.Context, sessionID string) error {
	err := s.db.QueryRow(ctx, `
		update auth_sessions
		set status = 'expired', updated_at = now()
		where id = $1::uuid and status in ('pending', 'verified')
		returning id`, sessionID).Scan(new(string))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.ErrAuthSessionNotFound
		}
		return fmt.Errorf("revoke auth session: %w", err)
	}
	return nil
}

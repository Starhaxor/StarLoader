package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/starloader/backend/internal/domain"
)

const deviceColumns = `
	id::text, user_id::text, license_id::text, tpm_public_key, tpm_public_key_sha256,
	coalesce(smbios_uuid_hmac, ''), coalesce(motherboard_serial_hmac, ''),
	coalesce(bios_serial_hmac, ''), coalesce(system_disk_serial_hmac, ''),
	coalesce(machine_guid_hmac, ''), fingerprint_hmac, status,
	created_at, updated_at, last_seen_at`

// Device persistence is intentionally transaction-scoped: HMAC-only lookup
// and mutation methods belong on LockedChallenge so activation cannot escape
// the challenge transaction.

func (locked *LockedChallenge) PendingSession() domain.AuthSession {
	return locked.Session
}

func (locked *LockedChallenge) PendingChallenge() domain.DeviceChallenge {
	return locked.Challenge
}

func (locked *LockedChallenge) LockLicense(ctx context.Context) (*domain.License, error) {
	license, err := scanLicense(locked.tx.QueryRow(ctx, `
		select `+licenseColumns+`
		from licenses
		where id = $1 and user_id = $2
		for update`, locked.licenseID, locked.userID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrLicenseNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("lock verification license: %w", err)
	}
	return license, nil
}

func (locked *LockedChallenge) ListDevices(ctx context.Context) ([]domain.Device, error) {
	rows, err := locked.tx.Query(ctx, `
		select `+deviceColumns+`
		from devices
		where license_id = $1 and user_id = $2
		order by created_at, id
		for update`, locked.licenseID, locked.userID)
	if err != nil {
		return nil, fmt.Errorf("list verification devices: %w", err)
	}
	defer rows.Close()
	devices := make([]domain.Device, 0)
	for rows.Next() {
		device, err := scanDevice(rows)
		if err != nil {
			return nil, fmt.Errorf("scan verification device: %w", err)
		}
		devices = append(devices, *device)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list verification devices: %w", err)
	}
	return devices, nil
}

func (locked *LockedChallenge) CreateDevice(ctx context.Context, input domain.NewDevice) (*domain.Device, error) {
	device, err := scanDevice(locked.tx.QueryRow(ctx, `
		insert into devices (
			user_id, license_id, tpm_public_key, tpm_public_key_sha256,
			smbios_uuid_hmac, motherboard_serial_hmac, bios_serial_hmac,
			system_disk_serial_hmac, machine_guid_hmac, fingerprint_hmac,
			created_at, updated_at, last_seen_at
		) values (
			$1, $2, $3, $4, nullif($5, ''), nullif($6, ''), nullif($7, ''),
			nullif($8, ''), nullif($9, ''), $10, $11, $11, $11
		)
		returning `+deviceColumns,
		locked.userID, locked.licenseID, input.TPMPublicKey, input.TPMPublicKeySHA256,
		input.SMBIOSUUIDHMAC, input.MotherboardSerialHMAC, input.BIOSSerialHMAC,
		input.SystemDiskSerialHMAC, input.MachineGuidHMAC, input.FingerprintHMAC, input.SeenAt))
	if err != nil {
		return nil, fmt.Errorf("create verification device: %w", err)
	}
	return device, nil
}

func (locked *LockedChallenge) UpdateDevice(ctx context.Context, input domain.UpdateDevice) error {
	tag, err := locked.tx.Exec(ctx, `
		update devices
		set smbios_uuid_hmac = nullif($2, ''),
			motherboard_serial_hmac = nullif($3, ''),
			bios_serial_hmac = nullif($4, ''),
			system_disk_serial_hmac = nullif($5, ''),
			machine_guid_hmac = nullif($6, ''),
			fingerprint_hmac = $7,
			updated_at = $8,
			last_seen_at = $8
		where id = $1 and license_id = $9 and user_id = $10 and status = 'active'`,
		input.ID, input.SMBIOSUUIDHMAC, input.MotherboardSerialHMAC, input.BIOSSerialHMAC,
		input.SystemDiskSerialHMAC, input.MachineGuidHMAC, input.FingerprintHMAC,
		input.SeenAt, locked.licenseID, locked.userID)
	if err != nil {
		return fmt.Errorf("update verification device: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("update verification device: active device not found")
	}
	return nil
}

func (locked *LockedChallenge) MarkSessionVerified(ctx context.Context, now time.Time) error {
	tag, err := locked.tx.Exec(ctx, `
		update auth_sessions
		set status = 'verified', updated_at = $2
		where id = $1 and status = 'pending'`, locked.sessionID, now)
	if err != nil {
		return fmt.Errorf("mark verification session: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return errors.New("mark verification session: pending session not found")
	}
	return nil
}

func scanDevice(row pgx.Row) (*domain.Device, error) {
	var device domain.Device
	err := row.Scan(
		&device.ID, &device.UserID, &device.LicenseID, &device.TPMPublicKey, &device.TPMPublicKeySHA256,
		&device.SMBIOSUUIDHMAC, &device.MotherboardSerialHMAC, &device.BIOSSerialHMAC,
		&device.SystemDiskSerialHMAC, &device.MachineGuidHMAC, &device.FingerprintHMAC,
		&device.Status, &device.CreatedAt, &device.UpdatedAt, &device.LastSeenAt,
	)
	return &device, err
}

package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/starloader/backend/internal/domain"
)

// LoadProfile returns only safe account, license, and device data bound to all verified claim IDs.
func (s *Store) LoadProfile(ctx context.Context, userID, licenseID, deviceID string) (*domain.UserProfile, error) {
	var profile domain.UserProfile
	err := s.db.QueryRow(ctx, `
		select u.email, u.status, l.product, l.status, l.expires_at, l.max_devices, d.id::text, d.status
		from users u
		join licenses l on l.id = $2 and l.user_id = u.id
		join devices d on d.id = $3 and d.license_id = l.id and d.user_id = u.id
		where u.id = $1`, userID, licenseID, deviceID,
	).Scan(
		&profile.Email,
		&profile.AccountStatus,
		&profile.Product,
		&profile.LicenseStatus,
		&profile.LicenseExpiresAt,
		&profile.MaxDevices,
		&profile.DeviceID,
		&profile.DeviceStatus,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrProfileNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load profile: %w", err)
	}
	return &profile, nil
}

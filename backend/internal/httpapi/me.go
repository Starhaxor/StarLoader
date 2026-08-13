package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/starloader/backend/internal/domain"
)

// ProfileRepository loads the safe profile tuple selected by verified session claims.
type ProfileRepository interface {
	LoadProfile(context.Context, string, string, string) (*domain.UserProfile, error)
}

type meResponse struct {
	OK               bool                 `json:"ok"`
	Email            string               `json:"email"`
	AccountStatus    domain.UserStatus    `json:"account_status"`
	Product          string               `json:"product"`
	LicenseStatus    domain.LicenseStatus `json:"license_status"`
	LicenseExpiresAt string               `json:"license_expires_at"`
	MaxDevices       int                  `json:"max_devices"`
	DeviceID         string               `json:"device_id"`
	DeviceStatus     domain.DeviceStatus  `json:"device_status"`
	SessionExpiresAt string               `json:"session_expires_at"`
}

func (router *Router) handleMe(writer http.ResponseWriter, request *http.Request) {
	claims, ok := SessionClaimsFromContext(request.Context())
	if !ok {
		writeInvalidSessionToken(writer, request)
		return
	}
	if router.profile == nil {
		writeError(writer, request, http.StatusInternalServerError, "SERVER_ERROR", "internal server error")
		return
	}

	profile, err := router.profile.LoadProfile(request.Context(), claims.Subject, claims.LicenseID, claims.DeviceID)
	if errors.Is(err, domain.ErrProfileNotFound) {
		writeInvalidSessionToken(writer, request)
		return
	}
	if err != nil || profile == nil {
		writeError(writer, request, http.StatusInternalServerError, "SERVER_ERROR", "internal server error")
		return
	}
	if profile.DeviceID != claims.DeviceID || profile.Product != claims.Product || profile.AccountStatus != domain.UserStatusActive {
		writeInvalidSessionToken(writer, request)
		return
	}

	switch profile.LicenseStatus {
	case domain.LicenseStatusRevoked:
		writeError(writer, request, http.StatusForbidden, "LICENSE_REVOKED", "license revoked")
		return
	case domain.LicenseStatusExpired:
		writeError(writer, request, http.StatusForbidden, "LICENSE_EXPIRED", "license expired")
		return
	case domain.LicenseStatusActive:
		if !profile.LicenseExpiresAt.After(router.now().UTC()) {
			writeError(writer, request, http.StatusForbidden, "LICENSE_EXPIRED", "license expired")
			return
		}
	default:
		writeInvalidSessionToken(writer, request)
		return
	}

	switch profile.DeviceStatus {
	case domain.DeviceStatusRevoked:
		writeError(writer, request, http.StatusForbidden, "DEVICE_REVOKED", "device revoked")
		return
	case domain.DeviceStatusActive:
	default:
		writeInvalidSessionToken(writer, request)
		return
	}

	writeJSON(writer, http.StatusOK, meResponse{
		OK: true, Email: profile.Email, AccountStatus: profile.AccountStatus,
		Product: profile.Product, LicenseStatus: profile.LicenseStatus,
		LicenseExpiresAt: profile.LicenseExpiresAt.UTC().Format(time.RFC3339), MaxDevices: profile.MaxDevices,
		DeviceID: profile.DeviceID, DeviceStatus: profile.DeviceStatus,
		SessionExpiresAt: claims.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

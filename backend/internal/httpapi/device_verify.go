package httpapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/starloader/backend/internal/domain"
	"github.com/starloader/backend/internal/service"
)

const maxDeviceSessionIDBytes = 128

type deviceVerifyRequestBody struct {
	SessionID          string                   `json:"session_id"`
	Challenge          string                   `json:"challenge"`
	ChallengeSignature string                   `json:"challenge_signature"`
	TPMPublicKey       string                   `json:"tpm_public_key"`
	Hardware           deviceVerifyHardwareBody `json:"hardware"`
}

type deviceVerifyHardwareBody struct {
	SMBIOSUUID        string `json:"smbios_uuid"`
	MotherboardSerial string `json:"motherboard_serial"`
	BIOSSerial        string `json:"bios_serial"`
	SystemDiskSerial  string `json:"system_disk_serial"`
	MachineGuid       string `json:"machine_guid"`
	Fingerprint       string `json:"fingerprint"`
}

type deviceVerifyResponse struct {
	OK             bool   `json:"ok"`
	Token          string `json:"token"`
	TokenExpiresAt string `json:"token_expires_at"`
	LicenseID      string `json:"license_id"`
	DeviceID       string `json:"device_id"`
}

func (router *Router) handleDeviceVerify(writer http.ResponseWriter, request *http.Request) {
	ctx, cancel := context.WithTimeout(request.Context(), router.deviceVerifyTimeout)
	defer cancel()
	request = request.WithContext(ctx)
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(writer, request, http.StatusUnsupportedMediaType, "INVALID_REQUEST", "invalid request")
		return
	}
	body, err := decodeDeviceVerifyRequest(writer, request)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeError(writer, request, http.StatusRequestEntityTooLarge, "INVALID_REQUEST", "invalid request")
			return
		}
		writeError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
		return
	}
	if !validDeviceVerifyBody(body) {
		writeError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
		return
	}
	if !router.sessionLimiter.allow(strings.TrimSpace(body.SessionID)) {
		writeError(writer, request, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests")
		return
	}
	if router.deviceVerification == nil {
		writeError(writer, request, http.StatusInternalServerError, "SERVER_ERROR", "internal server error")
		return
	}
	verified, err := router.deviceVerification.Verify(request.Context(), service.VerifyInput{
		SessionID: body.SessionID, Challenge: body.Challenge,
		ChallengeSignature: body.ChallengeSignature, TPMPublicKey: body.TPMPublicKey,
		Hardware: service.HardwareSignals{
			SMBIOSUUID: body.Hardware.SMBIOSUUID, MotherboardSerial: body.Hardware.MotherboardSerial,
			BIOSSerial: body.Hardware.BIOSSerial, SystemDiskSerial: body.Hardware.SystemDiskSerial,
			MachineGuid: body.Hardware.MachineGuid, Fingerprint: body.Hardware.Fingerprint,
		},
	})
	if err != nil {
		router.writeDeviceVerifyError(writer, request, err)
		return
	}
	writeJSON(writer, http.StatusOK, deviceVerifyResponse{
		OK: true, Token: verified.Token, TokenExpiresAt: verified.ExpiresAt.UTC().Format(time.RFC3339),
		LicenseID: verified.LicenseID, DeviceID: verified.DeviceID,
	})
}

func decodeDeviceVerifyRequest(writer http.ResponseWriter, request *http.Request) (deviceVerifyRequestBody, error) {
	request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var body deviceVerifyRequestBody
	if err := decoder.Decode(&body); err != nil {
		return deviceVerifyRequestBody{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return deviceVerifyRequestBody{}, errors.New("multiple JSON values")
		}
		return deviceVerifyRequestBody{}, err
	}
	return body, nil
}

func validDeviceVerifyBody(body deviceVerifyRequestBody) bool {
	sessionID := strings.TrimSpace(body.SessionID)
	return sessionID == body.SessionID && len(sessionID) <= maxDeviceSessionIDBytes && validCanonicalUUID(sessionID) && body.Challenge != "" && body.ChallengeSignature != "" &&
		body.TPMPublicKey != "" && strings.TrimSpace(body.Hardware.Fingerprint) != ""
}

func validCanonicalUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' || value != strings.ToLower(value) {
		return false
	}
	compact := strings.NewReplacer("-", "").Replace(value)
	if len(compact) != 32 {
		return false
	}
	_, err := hex.DecodeString(compact)
	return err == nil
}

func (router *Router) writeDeviceVerifyError(writer http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, service.ErrInvalidVerifyRequest), errors.Is(err, domain.ErrChallengeNotFound):
		writeError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
	case errors.Is(err, service.ErrChallengeExpired):
		writeError(writer, request, http.StatusGone, "CHALLENGE_EXPIRED", "challenge expired")
	case errors.Is(err, domain.ErrChallengeConsumed):
		writeError(writer, request, http.StatusConflict, "CHALLENGE_CONSUMED", "challenge already consumed")
	case errors.Is(err, service.ErrInvalidDeviceSignature):
		writeError(writer, request, http.StatusUnauthorized, "INVALID_DEVICE_SIGNATURE", "invalid device signature")
	case errors.Is(err, service.ErrDeviceLimitReached):
		writeError(writer, request, http.StatusForbidden, "DEVICE_LIMIT_REACHED", "device limit reached")
	case errors.Is(err, service.ErrDeviceRevoked):
		writeError(writer, request, http.StatusForbidden, "DEVICE_REVOKED", "device revoked")
	case errors.Is(err, service.ErrLicenseExpired):
		writeError(writer, request, http.StatusForbidden, "LICENSE_EXPIRED", "license expired")
	case errors.Is(err, service.ErrLicenseRevoked):
		writeError(writer, request, http.StatusForbidden, "LICENSE_REVOKED", "license revoked")
	case errors.Is(err, service.ErrInvalidCredentials):
		writeError(writer, request, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid credentials")
	default:
		writeError(writer, request, http.StatusInternalServerError, "SERVER_ERROR", "internal server error")
	}
}

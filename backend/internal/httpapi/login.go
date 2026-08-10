package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/starloader/backend/internal/service"
)

const maxRequestBodyBytes = 64 * 1024

type loginRequestBody struct {
	Email             string `json:"email"`
	Password          string `json:"password"`
	LicenseKey        string `json:"license_key"`
	DeviceFingerprint string `json:"device_fingerprint"`
}

type loginResponse struct {
	OK                 bool   `json:"ok"`
	SessionID          string `json:"session_id"`
	Challenge          string `json:"challenge"`
	ChallengeExpiresAt string `json:"challenge_expires_at"`
}

func (router *Router) handleLogin(writer http.ResponseWriter, request *http.Request) {
	if !router.loginLimiter.allow(clientIP(request, router.trustedProxies)) {
		writeError(writer, request, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests")
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), router.loginTimeout)
	defer cancel()
	request = request.WithContext(ctx)
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(writer, request, http.StatusUnsupportedMediaType, "INVALID_REQUEST", "invalid request")
		return
	}

	body, err := decodeLoginRequest(writer, request)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeError(writer, request, http.StatusRequestEntityTooLarge, "INVALID_REQUEST", "invalid request")
			return
		}
		writeError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
		return
	}
	if strings.TrimSpace(body.Email) == "" || body.Password == "" || strings.TrimSpace(body.LicenseKey) == "" || strings.TrimSpace(body.DeviceFingerprint) == "" {
		writeError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
		return
	}
	if router.login == nil {
		writeError(writer, request, http.StatusInternalServerError, "SERVER_ERROR", "internal server error")
		return
	}

	pending, err := router.login.Login(request.Context(), service.LoginInput{
		Email:             body.Email,
		Password:          body.Password,
		LicenseKey:        body.LicenseKey,
		DeviceFingerprint: body.DeviceFingerprint,
	})
	if err != nil {
		router.writeLoginError(writer, request, err)
		return
	}
	writeJSON(writer, http.StatusOK, loginResponse{
		OK:                 true,
		SessionID:          pending.SessionID,
		Challenge:          base64.StdEncoding.EncodeToString(pending.Challenge),
		ChallengeExpiresAt: pending.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func decodeLoginRequest(writer http.ResponseWriter, request *http.Request) (loginRequestBody, error) {
	request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var body loginRequestBody
	if err := decoder.Decode(&body); err != nil {
		return loginRequestBody{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return loginRequestBody{}, errors.New("multiple JSON values")
		}
		return loginRequestBody{}, err
	}
	return body, nil
}

func (router *Router) writeLoginError(writer http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, service.ErrInvalidCredentials):
		writeError(writer, request, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid credentials")
	case errors.Is(err, service.ErrLicenseNotFound):
		writeError(writer, request, http.StatusNotFound, "LICENSE_NOT_FOUND", "license not found")
	case errors.Is(err, service.ErrLicenseExpired):
		writeError(writer, request, http.StatusForbidden, "LICENSE_EXPIRED", "license expired")
	case errors.Is(err, service.ErrLicenseRevoked):
		writeError(writer, request, http.StatusForbidden, "LICENSE_REVOKED", "license revoked")
	default:
		writeError(writer, request, http.StatusInternalServerError, "SERVER_ERROR", "internal server error")
	}
}

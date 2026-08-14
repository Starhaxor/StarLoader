package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/starloader/backend/internal/domain"
	"github.com/starloader/backend/internal/service/adminauth"
)

const maxAdminUserAgentLength = 200

type adminLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (router *Router) handleAdminLogin(writer http.ResponseWriter, request *http.Request) {
	ipAddress := clientIP(request, router.trustedProxies)
	if !router.adminLimiter.allow(ipAddress + "|admin-login") {
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
	body, err := decodeAdminLoginRequest(writer, request)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			writeError(writer, request, http.StatusRequestEntityTooLarge, "INVALID_REQUEST", "invalid request")
			return
		}
		writeError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
		return
	}
	if strings.TrimSpace(body.Email) == "" || body.Password == "" {
		writeError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
		return
	}

	tokenValue, account, err := router.admin.Auth.Login(ctx, body.Email, body.Password, ipAddress, request.UserAgent())
	if errors.Is(err, adminauth.ErrInvalidCredentials) {
		writeError(writer, request, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid credentials")
		return
	}
	if err != nil {
		writeError(writer, request, http.StatusInternalServerError, "SERVER_ERROR", "internal server error")
		return
	}

	router.setAdminCookies(writer, tokenValue)
	writeJSON(writer, http.StatusOK, struct {
		OK        bool   `json:"ok"`
		Email     string `json:"email"`
		ExpiresAt string `json:"expires_at"`
	}{
		OK:        true,
		Email:     account.Email,
		ExpiresAt: router.now().Add(router.admin.SessionTTL).UTC().Format(time.RFC3339),
	})
}

func (router *Router) handleAdminLogout(writer http.ResponseWriter, request *http.Request, session *domain.AdminSession, sessionToken string) {
	if err := router.admin.Auth.Logout(request.Context(), sessionToken); err != nil {
		writeError(writer, request, http.StatusInternalServerError, "SERVER_ERROR", "internal server error")
		return
	}
	clearAdminCookies(writer, router.admin.CookieSecure)
	writeJSON(writer, http.StatusOK, struct {
		OK bool `json:"ok"`
	}{OK: true})
}

func (router *Router) handleAdminMe(writer http.ResponseWriter, request *http.Request, account *domain.AdminAccount) {
	writeJSON(writer, http.StatusOK, struct {
		OK     bool   `json:"ok"`
		ID     string `json:"id"`
		Email  string `json:"email"`
		Status string `json:"status"`
	}{OK: true, ID: account.ID, Email: account.Email, Status: string(account.Status)})
}

func (router *Router) setAdminCookies(writer http.ResponseWriter, sessionToken string) {
	maxAge := int(router.admin.SessionTTL.Seconds())
	http.SetCookie(writer, &http.Cookie{
		Name:     adminSessionCookieName,
		Value:    sessionToken,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   router.admin.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(writer, &http.Cookie{
		Name:     adminCSRFCookieName,
		Value:    router.adminCSRFToken(sessionToken),
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   router.admin.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearAdminCookies(writer http.ResponseWriter, secure bool) {
	http.SetCookie(writer, &http.Cookie{
		Name:     adminSessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(writer, &http.Cookie{
		Name:     adminCSRFCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func decodeAdminLoginRequest(writer http.ResponseWriter, request *http.Request) (adminLoginRequest, error) {
	request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var body adminLoginRequest
	if err := decoder.Decode(&body); err != nil {
		return adminLoginRequest{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return adminLoginRequest{}, errors.New("multiple JSON values")
		}
		return adminLoginRequest{}, err
	}
	return body, nil
}

func hashClientIP(request *http.Request, trustedProxies []netip.Prefix) string {
	ipAddress := clientIP(request, trustedProxies)
	if ipAddress == "" || ipAddress == "unknown" {
		return ""
	}
	digest := sha256.Sum256([]byte(ipAddress))
	return hex.EncodeToString(digest[:])
}

func truncateAdminUserAgent(userAgent string) string {
	userAgent = strings.TrimSpace(userAgent)
	if len(userAgent) > maxAdminUserAgentLength {
		return userAgent[:maxAdminUserAgentLength]
	}
	return userAgent
}

func jsonMarshal(value any) (json.RawMessage, error) {
	return json.Marshal(value)
}

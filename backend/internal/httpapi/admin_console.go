package httpapi

import (
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/starloader/backend/internal/domain"
	"github.com/starloader/backend/internal/security"
)

const (
	defaultAdminPageSize     = 20
	maxAdminPageSize         = 100
	minEndUserPasswordLength = 10
	minAdminPasswordLength   = 12
)

func parseAdminPagination(request *http.Request) (page, pageSize, offset int) {
	page = atoiOrDefault(request.URL.Query().Get("page"), 1)
	if page < 1 {
		page = 1
	}
	pageSize = atoiOrDefault(request.URL.Query().Get("page_size"), defaultAdminPageSize)
	if pageSize < 1 {
		pageSize = 1
	}
	if pageSize > maxAdminPageSize {
		pageSize = maxAdminPageSize
	}
	return page, pageSize, (page - 1) * pageSize
}

func atoiOrDefault(value string, fallback int) int {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return fallback
	}
	return parsed
}

type adminPageResponse struct {
	OK       bool  `json:"ok"`
	Items    any   `json:"items"`
	Total    int64 `json:"total"`
	Page     int   `json:"page"`
	PageSize int   `json:"page_size"`
}

func decodeAdminJSONBody(writer http.ResponseWriter, request *http.Request, target any) error {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("invalid content type")
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339)
}

func formatOptionalTime(value *time.Time) *string {
	if value == nil {
		return nil
	}
	formatted := value.UTC().Format(time.RFC3339)
	return &formatted
}

func (router *Router) handleAdminOverview(writer http.ResponseWriter, request *http.Request, account *domain.AdminAccount) {
	overview, err := router.admin.Console.ConsoleOverview(request.Context())
	if err != nil {
		router.writeConsoleError(writer, request, err)
		return
	}
	writeJSON(writer, http.StatusOK, struct {
		OK             bool             `json:"ok"`
		TotalUsers     int64            `json:"total_users"`
		ActiveLicenses int64            `json:"active_licenses"`
		ActiveDevices  int64            `json:"active_devices"`
		ActiveSessions int64            `json:"active_sessions"`
		RecentAudit    []auditEntryJSON `json:"recent_audit"`
	}{
		OK:             true,
		TotalUsers:     overview.TotalUsers,
		ActiveLicenses: overview.ActiveLicenses,
		ActiveDevices:  overview.ActiveDevices,
		ActiveSessions: overview.ActiveSessions,
		RecentAudit:    mapAuditEntries(overview.RecentAudit),
	})
}

type dailyStatJSON struct {
	Day               string `json:"day"`
	LicensesCreated   int64  `json:"licenses_created"`
	DevicesRegistered int64  `json:"devices_registered"`
	SessionsCreated   int64  `json:"sessions_created"`
	AuditEvents       int64  `json:"audit_events"`
	AdminLogins       int64  `json:"admin_logins"`
}

func mapDailyStats(stats []domain.DailyStat) []dailyStatJSON {
	items := make([]dailyStatJSON, 0, len(stats))
	for _, stat := range stats {
		items = append(items, dailyStatJSON{
			Day:               stat.Day,
			LicensesCreated:   stat.LicensesCreated,
			DevicesRegistered: stat.DevicesRegistered,
			SessionsCreated:   stat.SessionsCreated,
			AuditEvents:       stat.AuditEvents,
			AdminLogins:       stat.AdminLogins,
		})
	}
	return items
}

// handleAdminOverviewStats returns the trailing 14-day activity series for
// the dashboard charts.
func (router *Router) handleAdminOverviewStats(writer http.ResponseWriter, request *http.Request) {
	days := atoiOrDefault(request.URL.Query().Get("days"), 14)
	stats, err := router.admin.Console.ConsoleDailyStats(request.Context(), days)
	if err != nil {
		router.writeConsoleError(writer, request, err)
		return
	}
	writeJSON(writer, http.StatusOK, struct {
		OK   bool            `json:"ok"`
		Days []dailyStatJSON `json:"days"`
	}{
		OK:   true,
		Days: mapDailyStats(stats),
	})
}

// Users

type consoleUserJSON struct {
	ID                 string  `json:"id"`
	Email              string  `json:"email"`
	Status             string  `json:"status"`
	LicenseCount       int     `json:"license_count"`
	DeviceCount        int     `json:"device_count"`
	ActiveSessionCount int     `json:"active_session_count"`
	LastLoginAt        *string `json:"last_login_at"`
	CreatedAt          string  `json:"created_at"`
}

func mapConsoleUser(user domain.ConsoleUser) consoleUserJSON {
	return consoleUserJSON{
		ID:                 user.ID,
		Email:              user.Email,
		Status:             string(user.Status),
		LicenseCount:       user.LicenseCount,
		DeviceCount:        user.DeviceCount,
		ActiveSessionCount: user.ActiveSessionCount,
		LastLoginAt:        formatOptionalTime(user.LastLoginAt),
		CreatedAt:          formatTime(user.CreatedAt),
	}
}

func (router *Router) routeAdminUsers(writer http.ResponseWriter, request *http.Request, account *domain.AdminAccount, segments []string) {
	switch {
	case len(segments) == 1 && request.Method == http.MethodGet:
		if !router.requirePermission(writer, request, account, domain.PermUsersRead) {
			return
		}
		router.handleAdminUserList(writer, request)
	case len(segments) == 1 && request.Method == http.MethodPost:
		if !router.requirePermission(writer, request, account, domain.PermUsersWrite) {
			return
		}
		router.handleAdminUserCreate(writer, request, account)
	case len(segments) == 2 && request.Method == http.MethodGet:
		if !router.requirePermission(writer, request, account, domain.PermUsersRead) {
			return
		}
		router.handleAdminUserDetail(writer, request, segments[1])
	case len(segments) == 2 && request.Method == http.MethodPatch:
		if !router.requirePermission(writer, request, account, domain.PermUsersWrite) {
			return
		}
		router.handleAdminUserStatus(writer, request, account, segments[1])
	case len(segments) == 4 && segments[2] == "sessions" && segments[3] == "revoke" && request.Method == http.MethodPost:
		if !router.requirePermission(writer, request, account, domain.PermSessionsWrite) {
			return
		}
		router.handleAdminUserSessionsRevoke(writer, request, account, segments[1])
	case len(segments) == 3 && segments[2] == "promote" && request.Method == http.MethodPost:
		if !router.requirePermission(writer, request, account, domain.PermAdminsWrite) {
			return
		}
		router.handleAdminUserPromote(writer, request, account, segments[1])
	case len(segments) == 3 && segments[2] == "password" && request.Method == http.MethodPost:
		if !router.requirePermission(writer, request, account, domain.PermUsersWrite) {
			return
		}
		router.handleAdminUserPasswordReset(writer, request, account, segments[1])
	default:
		writeError(writer, request, http.StatusNotFound, "INVALID_REQUEST", "not found")
	}
}

// handleAdminUserCreate provisions an end-user account. The password is
// hashed with Argon2id; only the hash is persisted.
func (router *Router) handleAdminUserCreate(writer http.ResponseWriter, request *http.Request, account *domain.AdminAccount) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeAdminJSONBody(writer, request, &body); err != nil {
		writeError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
		return
	}
	email := strings.ToLower(strings.TrimSpace(body.Email))
	if email == "" || !strings.Contains(email, "@") || len(email) > 254 {
		writeError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", "a valid email is required")
		return
	}
	if len(body.Password) < minEndUserPasswordLength {
		writeError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", "password must be at least 10 characters")
		return
	}
	hash, err := security.HashPassword(body.Password)
	if err != nil {
		writeError(writer, request, http.StatusInternalServerError, "SERVER_ERROR", "internal server error")
		return
	}
	user, err := router.admin.Console.CreateUser(request.Context(), domain.NewUser{Email: email, PasswordHash: hash})
	if err != nil {
		router.writeConsoleError(writer, request, err)
		return
	}
	router.auditAdmin(request, account, "USER_CREATED", "user", user.ID, map[string]string{"email": user.Email})
	writeJSON(writer, http.StatusOK, struct {
		OK   bool            `json:"ok"`
		User consoleUserJSON `json:"user"`
	}{
		OK: true,
		User: consoleUserJSON{
			ID: user.ID, Email: user.Email, Status: string(user.Status), CreatedAt: formatTime(user.CreatedAt),
		},
	})
}

func (router *Router) handleAdminUserList(writer http.ResponseWriter, request *http.Request) {
	page, pageSize, offset := parseAdminPagination(request)
	users, total, err := router.admin.Console.ListConsoleUsers(request.Context(), offset, pageSize, request.URL.Query().Get("search"))
	if err != nil {
		router.writeConsoleError(writer, request, err)
		return
	}
	items := make([]consoleUserJSON, 0, len(users))
	for _, user := range users {
		items = append(items, mapConsoleUser(user))
	}
	writeJSON(writer, http.StatusOK, adminPageResponse{OK: true, Items: items, Total: total, Page: page, PageSize: pageSize})
}

func (router *Router) handleAdminUserDetail(writer http.ResponseWriter, request *http.Request, userID string) {
	if !uuidPattern.MatchString(userID) {
		writeError(writer, request, http.StatusNotFound, "USER_NOT_FOUND", "user not found")
		return
	}
	detail, err := router.admin.Console.ConsoleUserDetail(request.Context(), userID)
	if err != nil {
		router.writeConsoleError(writer, request, err)
		return
	}
	writeJSON(writer, http.StatusOK, struct {
		OK       bool                 `json:"ok"`
		User     consoleUserJSON      `json:"user"`
		Licenses []consoleLicenseJSON `json:"licenses"`
		Devices  []consoleDeviceJSON  `json:"devices"`
		Sessions []consoleSessionJSON `json:"sessions"`
	}{
		OK:       true,
		User:     mapConsoleUser(detail.User),
		Licenses: mapConsoleLicenses(detail.Licenses),
		Devices:  mapConsoleDevices(detail.Devices),
		Sessions: mapConsoleSessions(detail.Sessions),
	})
}

func (router *Router) handleAdminUserStatus(writer http.ResponseWriter, request *http.Request, account *domain.AdminAccount, userID string) {
	if !uuidPattern.MatchString(userID) {
		writeError(writer, request, http.StatusNotFound, "USER_NOT_FOUND", "user not found")
		return
	}
	var body struct {
		Status string `json:"status"`
	}
	if err := decodeAdminJSONBody(writer, request, &body); err != nil {
		writeError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
		return
	}
	if body.Status != string(domain.UserStatusActive) && body.Status != string(domain.UserStatusDisabled) {
		writeError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", "status must be active or disabled")
		return
	}
	if err := router.admin.Console.SetUserStatus(request.Context(), userID, domain.UserStatus(body.Status)); err != nil {
		router.writeConsoleError(writer, request, err)
		return
	}
	router.auditAdmin(request, account, "USER_STATUS_CHANGED", "user", userID, map[string]string{"status": body.Status})
	writeJSON(writer, http.StatusOK, struct {
		OK bool `json:"ok"`
	}{OK: true})
}

// handleAdminUserPromote turns an existing end-user into a dashboard admin,
// reusing the user's existing Argon2id password hash — no new password is
// introduced. The role defaults to viewer when omitted.
func (router *Router) handleAdminUserPromote(writer http.ResponseWriter, request *http.Request, account *domain.AdminAccount, userID string) {
	if !uuidPattern.MatchString(userID) {
		writeError(writer, request, http.StatusNotFound, "USER_NOT_FOUND", "user not found")
		return
	}
	var body struct {
		Role string `json:"role"`
	}
	if err := decodeAdminJSONBody(writer, request, &body); err != nil {
		writeError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
		return
	}
	role := strings.ToLower(strings.TrimSpace(body.Role))
	if role == "" {
		role = domain.RoleViewer
	}
	created, err := router.admin.Console.PromoteUserToAdmin(request.Context(), userID, role)
	if err != nil {
		router.writeConsoleError(writer, request, err)
		return
	}
	router.auditAdmin(request, account, "ADMIN_PROMOTED", "admin_account", created.ID, map[string]string{"email": created.Email, "role": role})
	writeJSON(writer, http.StatusOK, struct {
		OK    bool             `json:"ok"`
		Admin adminAccountJSON `json:"admin"`
	}{OK: true, Admin: mapAdminAccount(*created)})
}

// handleAdminUserPasswordReset sets a new password for an end-user. When the
// request body omits a password, a strong random one is generated and returned
// exactly once so the admin can hand it to the user over a trusted channel.
func (router *Router) handleAdminUserPasswordReset(writer http.ResponseWriter, request *http.Request, account *domain.AdminAccount, userID string) {
	if !uuidPattern.MatchString(userID) {
		writeError(writer, request, http.StatusNotFound, "USER_NOT_FOUND", "user not found")
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeAdminJSONBody(writer, request, &body); err != nil {
		writeError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
		return
	}
	password := body.Password
	if password == "" {
		generated, err := generateTemporaryPassword()
		if err != nil {
			writeError(writer, request, http.StatusInternalServerError, "SERVER_ERROR", "internal server error")
			return
		}
		password = generated
	} else if len(password) < minEndUserPasswordLength {
		writeError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", "password must be at least 10 characters")
		return
	}
	hash, err := security.HashPassword(password)
	if err != nil {
		writeError(writer, request, http.StatusInternalServerError, "SERVER_ERROR", "internal server error")
		return
	}
	if err := router.admin.Console.SetUserPassword(request.Context(), userID, hash); err != nil {
		router.writeConsoleError(writer, request, err)
		return
	}
	router.auditAdmin(request, account, "USER_PASSWORD_RESET", "user", userID, nil)
	writeJSON(writer, http.StatusOK, struct {
		OK           bool   `json:"ok"`
		PasswordSet  bool   `json:"password_set"`
		TempPassword string `json:"temp_password,omitempty"`
	}{
		OK:           true,
		PasswordSet:  body.Password != "",
		TempPassword: password,
	})
}

// generateTemporaryPassword returns a 16-character password from a
// cryptographically secure alphabet that avoids visually ambiguous characters.
func generateTemporaryPassword() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*"
	const length = 16
	bytes := make([]byte, length)
	if _, err := cryptorand.Read(bytes); err != nil {
		return "", err
	}
	for index := range bytes {
		bytes[index] = alphabet[int(bytes[index])%len(alphabet)]
	}
	return string(bytes), nil
}

// handleAdminUserSessionsRevoke expires every pending or verified auth
// session of a single user.
func (router *Router) handleAdminUserSessionsRevoke(writer http.ResponseWriter, request *http.Request, account *domain.AdminAccount, userID string) {
	if !uuidPattern.MatchString(userID) {
		writeError(writer, request, http.StatusNotFound, "USER_NOT_FOUND", "user not found")
		return
	}
	revoked, err := router.admin.Console.RevokeUserSessions(request.Context(), userID)
	if err != nil {
		router.writeConsoleError(writer, request, err)
		return
	}
	router.auditAdmin(request, account, "USER_SESSIONS_REVOKED", "user", userID, map[string]int64{"revoked": revoked})
	writeJSON(writer, http.StatusOK, struct {
		OK      bool  `json:"ok"`
		Revoked int64 `json:"revoked"`
	}{OK: true, Revoked: revoked})
}

// Licenses

type consoleLicenseJSON struct {
	ID         string `json:"id"`
	UserID     string `json:"user_id"`
	UserEmail  string `json:"user_email"`
	Product    string `json:"product"`
	Status     string `json:"status"`
	MaxDevices int    `json:"max_devices"`
	ExpiresAt  string `json:"expires_at"`
	CreatedAt  string `json:"created_at"`
}

func mapConsoleLicenses(licenses []domain.ConsoleLicense) []consoleLicenseJSON {
	items := make([]consoleLicenseJSON, 0, len(licenses))
	for _, license := range licenses {
		items = append(items, consoleLicenseJSON{
			ID:         license.ID,
			UserID:     license.UserID,
			UserEmail:  license.UserEmail,
			Product:    license.Product,
			Status:     string(license.Status),
			MaxDevices: license.MaxDevices,
			ExpiresAt:  formatTime(license.ExpiresAt),
			CreatedAt:  formatTime(license.CreatedAt),
		})
	}
	return items
}

func (router *Router) routeAdminLicenses(writer http.ResponseWriter, request *http.Request, account *domain.AdminAccount, segments []string) {
	switch {
	case len(segments) == 1 && request.Method == http.MethodGet:
		if !router.requirePermission(writer, request, account, domain.PermLicensesRead) {
			return
		}
		router.handleAdminLicenseList(writer, request)
	case len(segments) == 1 && request.Method == http.MethodPost:
		if !router.requirePermission(writer, request, account, domain.PermLicensesWrite) {
			return
		}
		router.handleAdminLicenseCreate(writer, request, account)
	case len(segments) == 2 && request.Method == http.MethodPatch:
		if !router.requirePermission(writer, request, account, domain.PermLicensesWrite) {
			return
		}
		router.handleAdminLicenseUpdate(writer, request, account, segments[1])
	case len(segments) == 3 && segments[2] == "revoke" && request.Method == http.MethodPost:
		if !router.requirePermission(writer, request, account, domain.PermLicensesWrite) {
			return
		}
		router.handleAdminLicenseRevoke(writer, request, account, segments[1])
	default:
		writeError(writer, request, http.StatusNotFound, "INVALID_REQUEST", "not found")
	}
}

func (router *Router) handleAdminLicenseList(writer http.ResponseWriter, request *http.Request) {
	page, pageSize, offset := parseAdminPagination(request)
	licenses, total, err := router.admin.Console.ListConsoleLicenses(request.Context(), offset, pageSize)
	if err != nil {
		router.writeConsoleError(writer, request, err)
		return
	}
	writeJSON(writer, http.StatusOK, adminPageResponse{OK: true, Items: mapConsoleLicenses(licenses), Total: total, Page: page, PageSize: pageSize})
}

func (router *Router) handleAdminLicenseCreate(writer http.ResponseWriter, request *http.Request, account *domain.AdminAccount) {
	var body struct {
		UserEmail  string `json:"user_email"`
		Days       int    `json:"days"`
		MaxDevices int    `json:"max_devices"`
	}
	if err := decodeAdminJSONBody(writer, request, &body); err != nil {
		writeError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
		return
	}
	if strings.TrimSpace(body.UserEmail) == "" || body.Days < 1 || body.Days > 3650 || body.MaxDevices < 1 || body.MaxDevices > 10000 {
		writeError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", "user_email, days (1-3650) and max_devices (1-10000) are required")
		return
	}
	user, err := router.admin.Console.FindUserByEmail(request.Context(), body.UserEmail)
	if err != nil {
		router.writeConsoleError(writer, request, err)
		return
	}
	plain, normalized, err := security.GenerateLicense(cryptorand.Reader)
	if err != nil {
		writeError(writer, request, http.StatusInternalServerError, "SERVER_ERROR", "internal server error")
		return
	}
	license, err := router.admin.Console.CreateLicense(request.Context(), domain.NewLicense{
		LicenseHMAC: security.HMACHex(router.admin.LicenseHMACKey, normalized),
		UserID:      user.ID,
		Product:     router.admin.Product,
		MaxDevices:  body.MaxDevices,
		ExpiresAt:   router.now().UTC().AddDate(0, 0, body.Days),
	})
	if err != nil {
		router.writeConsoleError(writer, request, err)
		return
	}
	router.auditAdmin(request, account, "LICENSE_CREATED", "license", license.ID, map[string]string{"user_email": user.Email})
	writeJSON(writer, http.StatusOK, struct {
		OK      bool               `json:"ok"`
		License consoleLicenseJSON `json:"license"`
		Key     string             `json:"key"`
	}{
		OK: true,
		License: consoleLicenseJSON{
			ID: license.ID, UserID: license.UserID, UserEmail: user.Email, Product: license.Product,
			Status: string(license.Status), MaxDevices: license.MaxDevices,
			ExpiresAt: formatTime(license.ExpiresAt), CreatedAt: formatTime(license.CreatedAt),
		},
		Key: plain,
	})
}

func (router *Router) handleAdminLicenseUpdate(writer http.ResponseWriter, request *http.Request, account *domain.AdminAccount, licenseID string) {
	if !uuidPattern.MatchString(licenseID) {
		writeError(writer, request, http.StatusNotFound, "LICENSE_NOT_FOUND", "license not found")
		return
	}
	var body struct {
		ExtendDays int `json:"extend_days"`
		MaxDevices int `json:"max_devices"`
	}
	if err := decodeAdminJSONBody(writer, request, &body); err != nil {
		writeError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
		return
	}
	if body.ExtendDays == 0 && body.MaxDevices == 0 {
		writeError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", "extend_days or max_devices is required")
		return
	}
	if body.ExtendDays < 0 || body.ExtendDays > 3650 || body.MaxDevices < 0 || body.MaxDevices > 10000 {
		writeError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", "invalid extend_days or max_devices")
		return
	}
	license, err := router.admin.Console.FindLicenseByID(request.Context(), licenseID)
	if err != nil {
		router.writeConsoleError(writer, request, err)
		return
	}
	if license.Status == domain.LicenseStatusRevoked {
		writeError(writer, request, http.StatusConflict, "LICENSE_REVOKED", "revoked licenses cannot be modified")
		return
	}
	expiresAt := license.ExpiresAt.AddDate(0, 0, body.ExtendDays)
	if !expiresAt.After(router.now()) {
		expiresAt = router.now().AddDate(0, 0, body.ExtendDays)
	}
	maxDevices := body.MaxDevices
	if maxDevices == 0 {
		maxDevices = license.MaxDevices
	}
	if err := router.admin.Console.AdminUpdateLicense(request.Context(), licenseID, expiresAt, maxDevices); err != nil {
		router.writeConsoleError(writer, request, err)
		return
	}
	router.auditAdmin(request, account, "LICENSE_UPDATED", "license", licenseID, map[string]int{
		"extend_days": body.ExtendDays, "max_devices": maxDevices,
	})
	writeJSON(writer, http.StatusOK, struct {
		OK bool `json:"ok"`
	}{OK: true})
}

func (router *Router) handleAdminLicenseRevoke(writer http.ResponseWriter, request *http.Request, account *domain.AdminAccount, licenseID string) {
	if !uuidPattern.MatchString(licenseID) {
		writeError(writer, request, http.StatusNotFound, "LICENSE_NOT_FOUND", "license not found")
		return
	}
	if err := router.admin.Console.AdminRevokeLicense(request.Context(), licenseID); err != nil {
		router.writeConsoleError(writer, request, err)
		return
	}
	router.auditAdmin(request, account, "LICENSE_REVOKED", "license", licenseID, nil)
	writeJSON(writer, http.StatusOK, struct {
		OK bool `json:"ok"`
	}{OK: true})
}

// Devices

type consoleDeviceJSON struct {
	ID                   string `json:"id"`
	UserID               string `json:"user_id"`
	UserEmail            string `json:"user_email"`
	LicenseID            string `json:"license_id"`
	TPMRegistered        bool   `json:"tpm_registered"`
	HasSMBIOSUUID        bool   `json:"has_smbios_uuid"`
	HasMotherboardSerial bool   `json:"has_motherboard_serial"`
	HasBIOSSerial        bool   `json:"has_bios_serial"`
	HasSystemDiskSerial  bool   `json:"has_system_disk_serial"`
	HasMachineGUID       bool   `json:"has_machine_guid"`
	Status               string `json:"status"`
	CreatedAt            string `json:"created_at"`
	LastSeenAt           string `json:"last_seen_at"`
}

func mapConsoleDevice(device domain.ConsoleDevice) consoleDeviceJSON {
	return consoleDeviceJSON{
		ID:                   device.ID,
		UserID:               device.UserID,
		UserEmail:            device.UserEmail,
		LicenseID:            device.LicenseID,
		TPMRegistered:        device.TPMRegistered,
		HasSMBIOSUUID:        device.HasSMBIOSUUID,
		HasMotherboardSerial: device.HasMotherboardSerial,
		HasBIOSSerial:        device.HasBIOSSerial,
		HasSystemDiskSerial:  device.HasSystemDiskSerial,
		HasMachineGUID:       device.HasMachineGUID,
		Status:               string(device.Status),
		CreatedAt:            formatTime(device.CreatedAt),
		LastSeenAt:           formatTime(device.LastSeenAt),
	}
}

func mapConsoleDevices(devices []domain.ConsoleDevice) []consoleDeviceJSON {
	items := make([]consoleDeviceJSON, 0, len(devices))
	for _, device := range devices {
		items = append(items, mapConsoleDevice(device))
	}
	return items
}

func (router *Router) routeAdminDevices(writer http.ResponseWriter, request *http.Request, account *domain.AdminAccount, segments []string) {
	switch {
	case len(segments) == 1 && request.Method == http.MethodGet:
		if !router.requirePermission(writer, request, account, domain.PermDevicesRead) {
			return
		}
		router.handleAdminDeviceList(writer, request)
	case len(segments) == 2 && request.Method == http.MethodGet:
		if !router.requirePermission(writer, request, account, domain.PermDevicesRead) {
			return
		}
		router.handleAdminDeviceDetail(writer, request, segments[1])
	case len(segments) == 3 && segments[2] == "revoke" && request.Method == http.MethodPost:
		if !router.requirePermission(writer, request, account, domain.PermDevicesWrite) {
			return
		}
		router.handleAdminDeviceRevoke(writer, request, account, segments[1])
	case len(segments) == 3 && segments[2] == "reset" && request.Method == http.MethodPost:
		if !router.requirePermission(writer, request, account, domain.PermDevicesWrite) {
			return
		}
		router.handleAdminDeviceReset(writer, request, account, segments[1])
	default:
		writeError(writer, request, http.StatusNotFound, "INVALID_REQUEST", "not found")
	}
}

func (router *Router) handleAdminDeviceList(writer http.ResponseWriter, request *http.Request) {
	page, pageSize, offset := parseAdminPagination(request)
	devices, total, err := router.admin.Console.ListConsoleDevices(request.Context(), offset, pageSize)
	if err != nil {
		router.writeConsoleError(writer, request, err)
		return
	}
	writeJSON(writer, http.StatusOK, adminPageResponse{OK: true, Items: mapConsoleDevices(devices), Total: total, Page: page, PageSize: pageSize})
}

func (router *Router) handleAdminDeviceRevoke(writer http.ResponseWriter, request *http.Request, account *domain.AdminAccount, deviceID string) {
	if !uuidPattern.MatchString(deviceID) {
		writeError(writer, request, http.StatusNotFound, "DEVICE_NOT_FOUND", "device not found")
		return
	}
	if err := router.admin.Console.AdminRevokeDevice(request.Context(), deviceID); err != nil {
		router.writeConsoleError(writer, request, err)
		return
	}
	router.auditAdmin(request, account, "DEVICE_REVOKED", "device", deviceID, nil)
	writeJSON(writer, http.StatusOK, struct {
		OK bool `json:"ok"`
	}{OK: true})
}

// handleAdminDeviceDetail returns the redacted device view with HWID
// component presence and the TPM public key fingerprint. Raw hardware
// identifiers and HMACs never leave the database.
func (router *Router) handleAdminDeviceDetail(writer http.ResponseWriter, request *http.Request, deviceID string) {
	if !uuidPattern.MatchString(deviceID) {
		writeError(writer, request, http.StatusNotFound, "DEVICE_NOT_FOUND", "device not found")
		return
	}
	detail, err := router.admin.Console.FindConsoleDeviceByID(request.Context(), deviceID)
	if err != nil {
		router.writeConsoleError(writer, request, err)
		return
	}
	writeJSON(writer, http.StatusOK, struct {
		OK             bool              `json:"ok"`
		Device         consoleDeviceJSON `json:"device"`
		Product        string            `json:"product"`
		TPMFingerprint string            `json:"tpm_fingerprint"`
	}{
		OK:             true,
		Device:         mapConsoleDevice(detail.Device),
		Product:        detail.Product,
		TPMFingerprint: detail.TPMFingerprint,
	})
}

// handleAdminDeviceReset removes the hardware registration so the user can
// register a fresh device on the same license.
func (router *Router) handleAdminDeviceReset(writer http.ResponseWriter, request *http.Request, account *domain.AdminAccount, deviceID string) {
	if !uuidPattern.MatchString(deviceID) {
		writeError(writer, request, http.StatusNotFound, "DEVICE_NOT_FOUND", "device not found")
		return
	}
	if err := router.admin.Console.AdminResetDevice(request.Context(), deviceID); err != nil {
		router.writeConsoleError(writer, request, err)
		return
	}
	router.auditAdmin(request, account, "DEVICE_RESET", "device", deviceID, nil)
	writeJSON(writer, http.StatusOK, struct {
		OK bool `json:"ok"`
	}{OK: true})
}

// Sessions

type consoleSessionJSON struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	UserEmail string `json:"user_email"`
	LicenseID string `json:"license_id"`
	Status    string `json:"status"`
	ExpiresAt string `json:"expires_at"`
	CreatedAt string `json:"created_at"`
}

func mapConsoleSessions(sessions []domain.ConsoleSession) []consoleSessionJSON {
	items := make([]consoleSessionJSON, 0, len(sessions))
	for _, session := range sessions {
		items = append(items, consoleSessionJSON{
			ID:        session.ID,
			UserID:    session.UserID,
			UserEmail: session.UserEmail,
			LicenseID: session.LicenseID,
			Status:    string(session.Status),
			ExpiresAt: formatTime(session.ExpiresAt),
			CreatedAt: formatTime(session.CreatedAt),
		})
	}
	return items
}

func (router *Router) routeAdminSessions(writer http.ResponseWriter, request *http.Request, account *domain.AdminAccount, segments []string) {
	switch {
	case len(segments) == 1 && request.Method == http.MethodGet:
		if !router.requirePermission(writer, request, account, domain.PermSessionsRead) {
			return
		}
		router.handleAdminSessionList(writer, request)
	case len(segments) == 3 && segments[2] == "revoke" && request.Method == http.MethodPost:
		if !router.requirePermission(writer, request, account, domain.PermSessionsWrite) {
			return
		}
		router.handleAdminSessionRevoke(writer, request, account, segments[1])
	default:
		writeError(writer, request, http.StatusNotFound, "INVALID_REQUEST", "not found")
	}
}

func (router *Router) handleAdminSessionList(writer http.ResponseWriter, request *http.Request) {
	page, pageSize, offset := parseAdminPagination(request)
	sessions, total, err := router.admin.Console.ListConsoleSessions(request.Context(), offset, pageSize)
	if err != nil {
		router.writeConsoleError(writer, request, err)
		return
	}
	writeJSON(writer, http.StatusOK, adminPageResponse{OK: true, Items: mapConsoleSessions(sessions), Total: total, Page: page, PageSize: pageSize})
}

func (router *Router) handleAdminSessionRevoke(writer http.ResponseWriter, request *http.Request, account *domain.AdminAccount, sessionID string) {
	if !uuidPattern.MatchString(sessionID) {
		writeError(writer, request, http.StatusNotFound, "SESSION_NOT_FOUND", "session not found")
		return
	}
	if err := router.admin.Console.AdminRevokeAuthSession(request.Context(), sessionID); err != nil {
		router.writeConsoleError(writer, request, err)
		return
	}
	router.auditAdmin(request, account, "SESSION_REVOKED", "session", sessionID, nil)
	writeJSON(writer, http.StatusOK, struct {
		OK bool `json:"ok"`
	}{OK: true})
}

// Audit logs

type auditEntryJSON struct {
	ID             string          `json:"id"`
	AdminAccountID string          `json:"admin_account_id"`
	ActorEmail     string          `json:"actor_email"`
	Action         string          `json:"action"`
	ResourceType   string          `json:"resource_type"`
	ResourceID     string          `json:"resource_id"`
	UserAgent      string          `json:"user_agent"`
	Metadata       json.RawMessage `json:"metadata"`
	CreatedAt      string          `json:"created_at"`
}

func mapAuditEntries(logs []domain.AuditLog) []auditEntryJSON {
	items := make([]auditEntryJSON, 0, len(logs))
	for _, entry := range logs {
		metadata := entry.Metadata
		if len(metadata) == 0 {
			metadata = json.RawMessage("{}")
		}
		items = append(items, auditEntryJSON{
			ID:             entry.ID,
			AdminAccountID: entry.AdminAccountID,
			ActorEmail:     entry.ActorEmail,
			Action:         entry.Action,
			ResourceType:   entry.ResourceType,
			ResourceID:     entry.ResourceID,
			UserAgent:      entry.UserAgent,
			Metadata:       metadata,
			CreatedAt:      formatTime(entry.CreatedAt),
		})
	}
	return items
}

func (router *Router) handleAdminAuditLogs(writer http.ResponseWriter, request *http.Request) {
	page, pageSize, offset := parseAdminPagination(request)
	logs, total, err := router.admin.Console.ListAuditLogs(request.Context(), offset, pageSize)
	if err != nil {
		router.writeConsoleError(writer, request, err)
		return
	}
	writeJSON(writer, http.StatusOK, adminPageResponse{OK: true, Items: mapAuditEntries(logs), Total: total, Page: page, PageSize: pageSize})
}

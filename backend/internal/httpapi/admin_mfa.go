package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/starloader/backend/internal/domain"
	"github.com/starloader/backend/internal/service/adminauth"
)

// --- TOTP enrollment ---

func (router *Router) handleAdminMFAEnrollStart(writer http.ResponseWriter, request *http.Request, account *domain.AdminAccount) {
	secret, provisioningURI, err := router.admin.Auth.StartMFAEnrollment(request.Context(), account, router.adminMFAIssuer())
	if errors.Is(err, adminauth.ErrMFAAlreadyEnrolled) {
		writeError(writer, request, http.StatusConflict, "MFA_ALREADY_ENROLLED", "mfa already enrolled")
		return
	}
	if err != nil {
		writeError(writer, request, http.StatusInternalServerError, "SERVER_ERROR", "internal server error")
		return
	}
	writeJSON(writer, http.StatusOK, struct {
		OK             bool   `json:"ok"`
		Secret         string `json:"secret"`
		ProvisioningURI string `json:"provisioning_uri"`
	}{OK: true, Secret: secret, ProvisioningURI: provisioningURI})
}

func (router *Router) handleAdminMFAEnrollConfirm(writer http.ResponseWriter, request *http.Request, account *domain.AdminAccount) {
	var body struct {
		Code string `json:"code"`
	}
	if err := decodeAdminJSONBody(writer, request, &body); err != nil {
		writeError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
		return
	}
	if strings.TrimSpace(body.Code) == "" {
		writeError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", "code is required")
		return
	}
	ipAddress := clientIP(request, router.trustedProxies)
	recoveryCodes, err := router.admin.Auth.ConfirmMFAEnrollment(request.Context(), account, body.Code, ipAddress, request.UserAgent())
	switch {
	case errors.Is(err, adminauth.ErrInvalidMFACode):
		writeError(writer, request, http.StatusBadRequest, "INVALID_MFA_CODE", "invalid mfa code")
		return
	case errors.Is(err, adminauth.ErrMFANotEnrolled):
		writeError(writer, request, http.StatusBadRequest, "MFA_ENROLLMENT_NOT_STARTED", "start mfa enrollment first")
		return
	case errors.Is(err, adminauth.ErrMFAAlreadyEnrolled):
		writeError(writer, request, http.StatusConflict, "MFA_ALREADY_ENROLLED", "mfa already enrolled")
		return
	case err != nil:
		writeError(writer, request, http.StatusInternalServerError, "SERVER_ERROR", "internal server error")
		return
	}
	router.recordSecurityEvent(request, account, "ADMIN_MFA_ENROLLED", "info", nil)
	writeJSON(writer, http.StatusOK, struct {
		OK            bool     `json:"ok"`
		RecoveryCodes []string `json:"recovery_codes"`
	}{OK: true, RecoveryCodes: recoveryCodes})
}

// handleAdminMFADisable turns MFA off for the caller after password
// re-verification. Every session of the account is revoked, so the response
// also clears the cookies.
func (router *Router) handleAdminMFADisable(writer http.ResponseWriter, request *http.Request, account *domain.AdminAccount) {
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeAdminJSONBody(writer, request, &body); err != nil {
		writeError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
		return
	}
	if body.Password == "" {
		writeError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", "password is required")
		return
	}
	ipAddress := clientIP(request, router.trustedProxies)
	if err := router.admin.Auth.DisableMFA(request.Context(), account, body.Password, ipAddress, request.UserAgent()); err != nil {
		if errors.Is(err, adminauth.ErrInvalidCredentials) {
			writeError(writer, request, http.StatusUnauthorized, "INVALID_PASSWORD", "password verification failed")
			return
		}
		writeError(writer, request, http.StatusInternalServerError, "SERVER_ERROR", "internal server error")
		return
	}
	router.recordSecurityEvent(request, account, "ADMIN_MFA_DISABLED", "warning", nil)
	clearAdminCookies(writer, router.admin.CookieSecure)
	writeJSON(writer, http.StatusOK, struct {
		OK bool `json:"ok"`
	}{OK: true})
}

// --- Admin account management ---

type adminAccountJSON struct {
	ID          string   `json:"id"`
	Email       string   `json:"email"`
	Status      string   `json:"status"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	MFAEnrolled bool     `json:"mfa_enrolled"`
	CreatedAt   string   `json:"created_at"`
}

func mapAdminAccount(account domain.AdminAccount) adminAccountJSON {
	return adminAccountJSON{
		ID:          account.ID,
		Email:       account.Email,
		Status:      string(account.Status),
		Role:        account.RoleName,
		Permissions: account.Permissions,
		MFAEnrolled: account.MFAEnrolled,
		CreatedAt:   formatTime(account.CreatedAt),
	}
}

func (router *Router) routeAdminAccounts(writer http.ResponseWriter, request *http.Request, account *domain.AdminAccount, segments []string) {
	switch {
	case len(segments) == 1 && request.Method == http.MethodGet:
		if !router.requirePermission(writer, request, account, domain.PermAdminsRead) {
			return
		}
		router.handleAdminAccountList(writer, request)
	case len(segments) == 2 && request.Method == http.MethodPatch:
		if !router.requirePermission(writer, request, account, domain.PermAdminsWrite) {
			return
		}
		router.handleAdminAccountUpdate(writer, request, account, segments[1])
	default:
		writeError(writer, request, http.StatusNotFound, "INVALID_REQUEST", "not found")
	}
}

func (router *Router) handleAdminAccountList(writer http.ResponseWriter, request *http.Request) {
	accounts, err := router.admin.Console.ListAdminAccounts(request.Context())
	if err != nil {
		router.writeConsoleError(writer, request, err)
		return
	}
	items := make([]adminAccountJSON, 0, len(accounts))
	for _, admin := range accounts {
		items = append(items, mapAdminAccount(admin))
	}
	writeJSON(writer, http.StatusOK, struct {
		OK    bool             `json:"ok"`
		Items []adminAccountJSON `json:"items"`
		Total int              `json:"total"`
	}{OK: true, Items: items, Total: len(items)})
}

// handleAdminAccountUpdate changes the status and/or role of another admin.
// Self-modification is rejected: the acting admin manages their own MFA via
// the /mfa endpoints and cannot lock themselves out or escalate themselves.
func (router *Router) handleAdminAccountUpdate(writer http.ResponseWriter, request *http.Request, actor *domain.AdminAccount, adminID string) {
	if !uuidPattern.MatchString(adminID) {
		writeError(writer, request, http.StatusNotFound, "ADMIN_NOT_FOUND", "admin not found")
		return
	}
	if adminID == actor.ID {
		writeError(writer, request, http.StatusBadRequest, "ADMIN_SELF_MODIFICATION", "you cannot modify your own account")
		return
	}
	var body struct {
		Status string `json:"status"`
		Role   string `json:"role"`
	}
	if err := decodeAdminJSONBody(writer, request, &body); err != nil {
		writeError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", "invalid request")
		return
	}
	status := strings.TrimSpace(body.Status)
	roleName := strings.ToLower(strings.TrimSpace(body.Role))
	if status == "" && roleName == "" {
		writeError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", "status or role is required")
		return
	}
	if status != "" && status != string(domain.AdminStatusActive) && status != string(domain.AdminStatusDisabled) {
		writeError(writer, request, http.StatusBadRequest, "INVALID_REQUEST", "status must be active or disabled")
		return
	}
	if status == "" {
		status = string(domain.AdminStatusActive)
	}
	if roleName != "" {
		roles, err := router.admin.Console.ListRoles(request.Context())
		if err != nil {
			router.writeConsoleError(writer, request, err)
			return
		}
		found := false
		for _, role := range roles {
			if role.Name == roleName {
				found = true
				break
			}
		}
		if !found {
			writeError(writer, request, http.StatusBadRequest, "ROLE_NOT_FOUND", "unknown role")
			return
		}
	}
	target, err := router.admin.Console.FindAdminAccountByID(request.Context(), adminID)
	if err != nil {
		router.writeConsoleError(writer, request, err)
		return
	}
	if status == "" {
		status = string(target.Status)
	}
	if status == string(domain.AdminStatusDisabled) {
		router.recordSecurityEvent(request, actor, "ADMIN_ACCOUNT_DISABLED", "warning", map[string]string{"target_admin_id": adminID})
	}
	if err := router.admin.Console.UpdateAdminAccountStatusAndRole(request.Context(), adminID, domain.AdminAccountStatus(status), roleName); err != nil {
		router.writeConsoleError(writer, request, err)
		return
	}
	router.auditAdmin(request, actor, "ADMIN_ACCOUNT_UPDATED", "admin_account", adminID, map[string]string{
		"status": status, "role": roleName,
	})
	writeJSON(writer, http.StatusOK, struct {
		OK bool `json:"ok"`
	}{OK: true})
}

// --- Roles ---

type roleJSON struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	BuiltIn     bool     `json:"built_in"`
}

func (router *Router) handleAdminRoles(writer http.ResponseWriter, request *http.Request) {
	roles, err := router.admin.Console.ListRoles(request.Context())
	if err != nil {
		router.writeConsoleError(writer, request, err)
		return
	}
	items := make([]roleJSON, 0, len(roles))
	for _, role := range roles {
		items = append(items, roleJSON{
			ID:          role.ID,
			Name:        role.Name,
			Description: role.Description,
			Permissions: role.Permissions,
			BuiltIn:     role.BuiltIn,
		})
	}
	writeJSON(writer, http.StatusOK, struct {
		OK    bool       `json:"ok"`
		Items []roleJSON `json:"items"`
		Total int        `json:"total"`
	}{OK: true, Items: items, Total: len(items)})
}

// --- Security events ---

type securityEventJSON struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`
	Severity       string `json:"severity"`
	AdminAccountID string `json:"admin_account_id"`
	ActorEmail     string `json:"actor_email"`
	UserAgent      string `json:"user_agent"`
	CreatedAt      string `json:"created_at"`
}

func (router *Router) handleAdminSecurityEvents(writer http.ResponseWriter, request *http.Request) {
	page, pageSize, offset := parseAdminPagination(request)
	events, total, err := router.admin.Console.ListSecurityEvents(request.Context(), offset, pageSize)
	if err != nil {
		router.writeConsoleError(writer, request, err)
		return
	}
	items := make([]securityEventJSON, 0, len(events))
	for _, event := range events {
		items = append(items, securityEventJSON{
			ID:             event.ID,
			Kind:           event.Kind,
			Severity:       event.Severity,
			AdminAccountID: event.AdminAccountID,
			ActorEmail:     event.ActorEmail,
			UserAgent:      event.UserAgent,
			CreatedAt:      formatTime(event.CreatedAt),
		})
	}
	writeJSON(writer, http.StatusOK, adminPageResponse{OK: true, Items: items, Total: total, Page: page, PageSize: pageSize})
}

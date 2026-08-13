# Authenticated User Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a secure `/v1/me` profile endpoint, an authenticated compact Qt dashboard, memory-only sign-out, and genuinely icon-free custom dark title bars for all license-client windows.

**Architecture:** The Go API verifies Bearer session tokens, derives identity exclusively from signed claims, and reloads current user/license/device state before returning a safe profile. The Qt client loads that profile only after TPM/device authentication succeeds, then transitions from login to a single-card dashboard. A shared frameless Qt title-bar component replaces native Windows chrome instead of substituting a transparent icon.

**Tech Stack:** Go 1.24, PostgreSQL 17/pgx, Qt 6 Widgets/C++20, Qt Network, OpenSSL Ed25519, CMake/Ninja, Qt Test.

**Spec:** `docs/superpowers/specs/2026-08-13-user-dashboard-authenticated-profile-design.md`

## Global Constraints

- Session tokens remain memory-only and must never be logged or persisted.
- `/v1/me` selects identity only from verified token claims; request-supplied IDs are forbidden.
- Never return password hashes, license plaintext, HMAC values, TPM material, or raw hardware serials.
- Login, HWID, and dashboard windows use the same icon-free frameless dark title bar.
- Dashboard has `Sign out` only; no Launch action exists.
- Preserve the existing loopback-only HTTP development switch and all TPM/device proof checks.
- Work around existing unrelated local changes; stage only files belonging to each task.

---

## File Structure

- `backend/internal/security/token.go`: expose verified session claims through the existing strict Ed25519 verifier.
- `backend/internal/httpapi/auth.go`: parse Bearer credentials, verify tokens, and attach claims to request context.
- `backend/internal/httpapi/me.go`: `/v1/me` handler and safe response mapping.
- `backend/internal/store/profile.go`: load and bind current user/license/device records.
- `backend/internal/domain/models.go`: safe profile domain model.
- `backend/internal/httpapi/router.go`: register authenticated profile dependencies and route.
- `backend/cmd/server/main.go`: construct token verifier/profile store and inject them into the router.
- `license-client/src/api/ApiClient.{h,cpp}`: authenticated profile request and response parsing.
- `license-client/src/auth/AuthManager.{h,cpp}`: expose authenticated session data and clear it on sign-out/profile failure.
- `license-client/src/ui/WindowTitleBar.{h,cpp}`: shared draggable icon-free title bar.
- `license-client/src/ui/UserDashboard.{h,cpp}` and `license-client/ui/UserDashboard.ui`: compact single-card panel.
- `license-client/src/ui/LoginWindow.{h,cpp}` and UI files: profile loading, dashboard transition, sign-out, frameless chrome.
- `license-client/src/ui/HwidDialog.cpp` and UI: use shared custom chrome.
- `shared/theme/AdwaitaDark.qss`: title-bar and dashboard selectors.

---

### Task 1: Backend Bearer Authentication and Profile Store

**Files:**
- Create: `backend/internal/httpapi/auth.go`
- Create: `backend/internal/httpapi/auth_test.go`
- Create: `backend/internal/store/profile.go`
- Modify: `backend/internal/domain/models.go`
- Test: `backend/tests/integration/store_test.go`

**Interfaces:**
- Consumes: `security.TokenVerifier.Verify(token string) (security.SessionClaims, error)`.
- Produces: `httpapi.BearerVerifier`, `httpapi.RequireSession(...)`, `store.Store.LoadProfile(ctx, userID, licenseID, deviceID string)`, and `domain.UserProfile`.

- [ ] **Step 1: Write failing Bearer parsing tests**

Add table-driven tests proving that missing headers, wrong schemes, blank tokens, extra fields, and invalid tokens return `401`, while `Authorization: Bearer signed-token` places exact claims in the downstream request context. Use a fake verifier whose `Verify` records only the received token and returns literal claims.

- [ ] **Step 2: Run the focused auth tests**

Run:

```powershell
docker run --rm -v "${PWD}:/workspace" -w /workspace/backend golang:1.24 go test ./internal/httpapi -run TestRequireSession -count=1 -v
```

Expected: FAIL because `RequireSession` and `BearerVerifier` do not exist.

- [ ] **Step 3: Implement strict Bearer middleware**

Define:

```go
type BearerVerifier interface {
    Verify(string) (security.SessionClaims, error)
}

func RequireSession(verifier BearerVerifier, next http.Handler) http.Handler
func SessionClaimsFromContext(context.Context) (security.SessionClaims, bool)
```

Accept exactly two whitespace-separated authorization fields and a case-insensitive `Bearer` scheme. Map every verification failure to the same safe `401 INVALID_SESSION_TOKEN` response. Store verified claims in a private context-key type.

- [ ] **Step 4: Run auth tests to green**

Run the Step 2 command. Expected: PASS.

- [ ] **Step 5: Write failing profile-store integration tests**

Extend the existing PostgreSQL fixture tests to assert:

```go
profile, err := repository.LoadProfile(ctx, user.ID, license.ID, device.ID)
```

returns email, account status, product, license status/expiry/max devices, device ID/status; incorrect user-license-device combinations return `domain.ErrProfileNotFound`.

- [ ] **Step 6: Implement the bound profile query**

Add:

```go
type UserProfile struct {
    Email string
    AccountStatus UserStatus
    Product string
    LicenseStatus LicenseStatus
    LicenseExpiresAt time.Time
    MaxDevices int
    DeviceID string
    DeviceStatus DeviceStatus
}
```

Use one SQL join across `users`, `licenses`, and `devices`, constrained by all three claimed IDs and ownership foreign keys. Select only safe fields.

- [ ] **Step 7: Run store integration tests**

Run the project’s PostgreSQL integration test command from `scripts/test-all.ps1` or an equivalent isolated PostgreSQL container. Expected: new profile cases PASS.

- [ ] **Step 8: Commit Task 1**

```powershell
git add backend/internal/httpapi/auth.go backend/internal/httpapi/auth_test.go backend/internal/store/profile.go backend/internal/domain/models.go backend/tests/integration/store_test.go
git commit -m "feat: authenticate profile requests"
```

---

### Task 2: `GET /v1/me` Endpoint

**Files:**
- Create: `backend/internal/httpapi/me.go`
- Create: `backend/internal/httpapi/me_test.go`
- Modify: `backend/internal/httpapi/router.go`
- Modify: `backend/cmd/server/main.go`
- Modify: `server-contract/API.md`

**Interfaces:**
- Consumes: verified `security.SessionClaims` and `LoadProfile(ctx, userID, licenseID, deviceID)`.
- Produces: authenticated `GET /v1/me` JSON response.

- [ ] **Step 1: Write failing handler tests**

Test a literal successful response with these JSON keys:

```json
{
  "ok": true,
  "email": "test2@test.com",
  "account_status": "active",
  "product": "StarLoader",
  "license_status": "active",
  "license_expires_at": "2026-09-12T17:42:56Z",
  "max_devices": 1,
  "device_id": "019ffc3f-0396-7266-b82c-35371486cc4e",
  "device_status": "active",
  "session_expires_at": "2026-08-13T18:50:15Z"
}
```

Also assert disabled users, expired/revoked licenses, revoked devices, mismatched records, and repository errors map to safe codes without sensitive fields.

- [ ] **Step 2: Run focused handler tests**

```powershell
docker run --rm -v "${PWD}:/workspace" -w /workspace/backend golang:1.24 go test ./internal/httpapi -run 'TestMe|TestRouterMe' -count=1 -v
```

Expected: FAIL because the handler/route do not exist.

- [ ] **Step 3: Implement handler and route**

Define a narrow `ProfileRepository` interface in `me.go`. Reject non-active account, license, or device state even if the token is valid. Use the token expiry for `session_expires_at`; never trust client time or request data for identity.

Register only `GET /v1/me`; other methods return `405`. Wrap the route with `RequireSession`.

- [ ] **Step 4: Wire production dependencies**

In `main.go`, derive the public key from the already parsed private key, create `security.NewTokenVerifier`, and inject it plus the store into the router. Do not parse or log the private key twice.

- [ ] **Step 5: Update the API contract**

Document the Bearer header, exact response, safe error codes, and forbidden secret/raw fields.

- [ ] **Step 6: Run backend unit tests**

```powershell
docker run --rm -v "${PWD}:/workspace" -w /workspace/backend golang:1.24 go test ./... -count=1
docker run --rm -v "${PWD}:/workspace" -w /workspace/backend golang:1.24 go vet ./...
```

Expected: PASS.

- [ ] **Step 7: Commit Task 2**

```powershell
git add backend/internal/httpapi/me.go backend/internal/httpapi/me_test.go backend/internal/httpapi/router.go backend/cmd/server/main.go server-contract/API.md
git commit -m "feat: expose authenticated profile"
```

---

### Task 3: Qt Profile API and Session Lifecycle

**Files:**
- Modify: `license-client/src/api/ApiClient.h`
- Modify: `license-client/src/api/ApiClient.cpp`
- Modify: `license-client/tests/ApiClientTest.cpp`
- Modify: `license-client/src/auth/AuthManager.h`
- Modify: `license-client/src/auth/AuthManager.cpp`
- Modify: `license-client/tests/AuthManagerTest.cpp`

**Interfaces:**
- Produces: `UserProfileResponse`, `IApiClient::loadProfile(QString token)`, `profileLoaded`, `profileFailed`, `AuthManager::userProfile()`, and `AuthManager::signOut()`.
- Consumes: verified in-memory session token from existing device verification.

- [ ] **Step 1: Write failing API tests**

Assert `/v1/me` uses GET, carries exactly `Authorization: Bearer <token>`, sends no body, parses every required field, rejects missing fields, and never includes the token in an emitted error message.

- [ ] **Step 2: Run API tests red**

```powershell
& 'C:\Qt\Tools\CMake_64\bin\cmake.exe' --build --preset qt-mingw-build --target ApiClientTest
& 'C:\Qt\Tools\CMake_64\bin\ctest.exe' --test-dir build -R '^ApiClientTest$' --output-on-failure
```

Expected: compile/test failure because profile interfaces do not exist.

- [ ] **Step 3: Implement profile transport**

Add a dedicated authenticated GET path rather than overloading `postJson`. Validate ISO timestamps with `QDateTime::fromString(..., Qt::ISODate)` and require non-empty identity/status fields plus positive `maxDevices`.

- [ ] **Step 4: Write failing AuthManager lifecycle tests**

Test this sequence:

```text
deviceVerified -> token verified -> loadProfile(token) -> profileLoaded -> authenticated
```

and failure sequence:

```text
profileFailed -> token empty -> state Failed
```

Test `signOut()` clears token, profile, hardware/session identifiers, increments the attempt generation, and transitions to Idle.

- [ ] **Step 5: Implement AuthManager lifecycle**

Do not emit `authenticated` immediately from `handleDeviceVerified`. Store the verified token, transition to a profile-loading state, request `/v1/me`, then emit only after profile validation. Add `signOut()` as the sole public session-clear operation.

- [ ] **Step 6: Run Qt API/auth tests**

Build and run `ApiClientTest` and `AuthManagerTest`. Expected: PASS.

- [ ] **Step 7: Commit Task 3**

```powershell
git add license-client/src/api/ApiClient.h license-client/src/api/ApiClient.cpp license-client/tests/ApiClientTest.cpp license-client/src/auth/AuthManager.h license-client/src/auth/AuthManager.cpp license-client/tests/AuthManagerTest.cpp
git commit -m "feat: load authenticated user profile"
```

---

### Task 4: Reusable Icon-Free Custom Title Bar

**Files:**
- Create: `license-client/src/ui/WindowTitleBar.h`
- Create: `license-client/src/ui/WindowTitleBar.cpp`
- Create: `license-client/tests/WindowTitleBarTest.cpp`
- Modify: `license-client/CMakeLists.txt`
- Modify: `license-client/src/ui/LoginWindow.cpp`
- Modify: `license-client/src/ui/HwidDialog.cpp`
- Modify: `shared/theme/ThemeManager.h`
- Modify: `shared/theme/ThemeManager.cpp`
- Modify: `shared/theme/AdwaitaDark.qss`

**Interfaces:**
- Produces: `WindowTitleBar(QWidget *window, QString title, bool canMinimize, QWidget *parent)`.
- Removes: transparent native-icon workaround from `ThemeManager::applyWindowTheme`.

- [ ] **Step 1: Write failing title-bar tests**

Assert the host window has `Qt::FramelessWindowHint`, the component contains no icon label, exposes a title plus accessible close/minimize tool buttons, close closes the host, minimize changes host state, and mouse movement drags the host from a known starting point.

- [ ] **Step 2: Run title-bar test red**

Build/run `WindowTitleBarTest`. Expected: failure because component is missing.

- [ ] **Step 3: Implement minimal reusable component**

Use a compact `QHBoxLayout`, text-only title, `QToolButton` controls, and `QMouseEvent::globalPosition()` drag delta. Do not draw or assign any icon, including transparent icons. Set the frameless flag before the native window is shown.

- [ ] **Step 4: Integrate login and HWID windows**

Insert the title bar as the first layout item. Login supports minimize/close; HWID supports close only. Remove DWM icon substitution, `setWindowIcon`, and native caption manipulation that is no longer used.

- [ ] **Step 5: Style and test both forms**

Add scoped selectors for `#windowTitleBar`, title text, and control hover/pressed states. Update existing UI tests to assert frameless flags and no icon widget/slot.

- [ ] **Step 6: Run title/theme/form tests**

Run `WindowTitleBarTest`, `ThemeManagerTest`, `LoginWindowUiTest`, and `HwidDialogTest`. Expected: PASS.

- [ ] **Step 7: Commit Task 4**

```powershell
git add license-client/src/ui/WindowTitleBar.h license-client/src/ui/WindowTitleBar.cpp license-client/tests/WindowTitleBarTest.cpp license-client/CMakeLists.txt license-client/src/ui/LoginWindow.cpp license-client/src/ui/HwidDialog.cpp shared/theme/ThemeManager.h shared/theme/ThemeManager.cpp shared/theme/AdwaitaDark.qss
git commit -m "feat: add icon-free window chrome"
```

---

### Task 5: Compact User Dashboard and Window Transition

**Files:**
- Create: `license-client/ui/UserDashboard.ui`
- Create: `license-client/src/ui/UserDashboard.h`
- Create: `license-client/src/ui/UserDashboard.cpp`
- Create: `license-client/tests/UserDashboardTest.cpp`
- Modify: `license-client/src/ui/LoginWindow.h`
- Modify: `license-client/src/ui/LoginWindow.cpp`
- Modify: `license-client/CMakeLists.txt`
- Modify: `shared/theme/AdwaitaDark.qss`

**Interfaces:**
- Consumes: `AuthManager::userProfile()`, `deviceDisplayId()`, and `signOut()`.
- Produces: `UserDashboard::signOutRequested()` and compact single-card presentation.

- [ ] **Step 1: Write failing dashboard presentation tests**

Construct a literal profile and assert visible email, statuses, product, formatted license expiry, max devices, shortened device ID, HWID, and session expiry. Assert no Launch control and no sensitive property names/text.

- [ ] **Step 2: Run dashboard test red**

Build/run `UserDashboardTest`. Expected: failure because dashboard files do not exist.

- [ ] **Step 3: Implement the approved single-card dashboard**

Use the italic StarLoader brand, one active-status indicator, aligned label/value rows, and one `Sign out` button. Keep the window fixed-size and use `WindowTitleBar`.

- [ ] **Step 4: Write failing transition tests**

Assert successful profile authentication hides login and shows exactly one dashboard. Assert Sign out destroys/hides dashboard, clears email/password, calls `AuthManager::signOut`, and shows login. Assert dashboard close exits without resurrecting login.

- [ ] **Step 5: Implement LoginWindow orchestration**

Connect `authenticated` to a method that creates the dashboard from the already validated profile. Own it with `QPointer<UserDashboard>` or parent ownership and prevent duplicate panels. Connect sign-out before showing.

- [ ] **Step 6: Style and run UI tests**

Add dashboard-specific QSS without changing global input/button behavior. Run `UserDashboardTest`, `LoginWindowUiTest`, and `HwidDialogTest`. Expected: PASS.

- [ ] **Step 7: Commit Task 5**

```powershell
git add license-client/ui/UserDashboard.ui license-client/src/ui/UserDashboard.h license-client/src/ui/UserDashboard.cpp license-client/tests/UserDashboardTest.cpp license-client/src/ui/LoginWindow.h license-client/src/ui/LoginWindow.cpp license-client/CMakeLists.txt shared/theme/AdwaitaDark.qss
git commit -m "feat: show authenticated user dashboard"
```

---

### Task 6: End-to-End Verification and Documentation

**Files:**
- Modify: `README.md`
- Modify: `scripts/test-all.ps1` only if new test targets are not automatically covered.

**Interfaces:**
- Consumes: all prior tasks.
- Produces: verified local startup/dashboard instructions.

- [ ] **Step 1: Extend black-box coverage**

After the existing login/device verification flow obtains a token, call `/v1/me` and assert the profile is bound to the same license/device IDs. Add invalid and expired token cases.

- [ ] **Step 2: Run complete backend verification**

Run Go race tests, integration tests, black-box tests, and `go vet` through `scripts/test-all.ps1` or equivalent commands. Expected: zero failures.

- [ ] **Step 3: Run complete Qt verification**

Configure, build all targets twice if UIC-generated dependencies require the existing second incremental pass, then run:

```powershell
& 'C:\Qt\Tools\CMake_64\bin\ctest.exe' --test-dir build --output-on-failure
```

Expected: all tests PASS.

- [ ] **Step 4: Perform local live-flow verification**

With PostgreSQL and API running, log in using a test account, confirm `/v1/me` succeeds, dashboard fields match PostgreSQL safe fields, Sign out returns to login, and all three windows have no icon slot.

- [ ] **Step 5: Update README**

Document the authenticated dashboard, `/v1/me`, sign-out behavior, and runtime DLL `PATH` requirements for non-deployed local builds.

- [ ] **Step 6: Final diff and secret checks**

```powershell
git diff --check
git status --short
git check-ignore -v backend/.env
```

Inspect staged content for tokens, passwords, private keys, and local `.env` data.

- [ ] **Step 7: Commit Task 6**

```powershell
git add README.md scripts/test-all.ps1 backend/tests/blackbox/smoke_test.go
git commit -m "test: verify authenticated dashboard flow"
```

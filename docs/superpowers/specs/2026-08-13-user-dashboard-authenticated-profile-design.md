# StarLoader Authenticated User Dashboard Design

## Goal

Add a compact authenticated user dashboard to the Qt license client and replace the native Windows title bars on the login, HWID, and dashboard windows with consistent icon-free dark title bars.

The dashboard opens only after the complete password, TPM challenge, device verification, and session-token verification flow succeeds. It shows current server-authoritative account, license, device, and session information without exposing secrets or raw hardware identifiers.

## Scope

This change includes:

- a bearer-authenticated `GET /v1/me` backend endpoint;
- server-side token validation and identity binding for the endpoint;
- a compact Qt user dashboard using the approved single-card layout;
- login-to-dashboard and dashboard-to-login transitions;
- sign-out with in-memory token destruction;
- reusable custom dark title bars for the login, HWID, and dashboard windows;
- automated Go and Qt coverage for the new behavior.

This change does not include:

- persistent sessions or refresh tokens;
- a launch target or Launch button;
- editing account, license, or device data;
- an administrative panel;
- displaying password hashes, HMAC values, TPM key material, or raw hardware serials.

## Backend Architecture

### Authentication

The backend will add bearer-token authentication shared by protected endpoints. It will:

1. Require an `Authorization: Bearer <token>` header.
2. Verify the compact Ed25519 JWS with the configured public key and existing issuer, audience, product, lifetime, and claim policy.
3. Derive the user, license, and device identifiers only from verified token claims.
4. Reject malformed, expired, incorrectly signed, or policy-incompatible tokens with `401`.

The request must not accept user, license, or device identifiers from query parameters or request bodies.

### `GET /v1/me`

After token verification, the endpoint loads the claimed user, license, and device in a single repository operation or a transactionally consistent query. It confirms:

- the user exists and is active;
- the license belongs to the user and matches the configured product;
- the license is active and unexpired;
- the device belongs to the user and license and is active.

Any mismatch is denied rather than partially returned. Revoked or inactive state uses safe public error codes and never leaks internal database details.

The successful response contains:

- email and account status;
- product, license status, license expiry, and maximum device count;
- device ID and device status;
- session expiry derived from the verified token.

Raw license keys, password hashes, HMAC-protected values, TPM public keys, hardware serial numbers, and database-only security fields are never returned.

## Qt Client Architecture

### API and session flow

After `AuthManager` verifies the device response token, the client retains the token only in memory and requests `/v1/me`. The dashboard is not shown until this profile request succeeds.

If profile loading fails:

- the token is cleared;
- the authenticated state is abandoned;
- the login window remains or becomes visible;
- a safe, actionable connection or session message is shown.

On success, the login window is hidden and one dashboard window is created. Sign out clears the token and profile model, destroys the dashboard, clears the login fields, and shows the login window again.

### Dashboard content

The approved single compact card displays:

- signed-in email;
- account status;
- StarLoader product;
- license status;
- license expiry date;
- maximum device count;
- device status;
- shortened device ID;
- locally calculated display HWID;
- session expiry or remaining session time.

The only panel action is `Sign out`. There is no Launch button until a concrete launch target exists.

### Window chrome

The login, HWID, and dashboard windows will use a shared Qt custom title-bar component with `Qt::FramelessWindowHint`. This removes the native icon slot rather than inserting a transparent icon.

The title bar provides:

- the window title;
- minimize where appropriate;
- close;
- pointer dragging from the title region;
- keyboard-accessible controls with accessible names;
- the same Adwaita-derived dark palette as the form body.

The windows remain fixed-size and compact, so maximize and double-click maximize behavior are omitted. Closing the dashboard exits the application; signing out returns to login. Closing the HWID dialog closes only that dialog.

## Error Handling

- Missing or malformed bearer credentials: `401` with a safe authentication code.
- Expired or invalid token: `401`.
- Token identity no longer matching active database records: deny access with the appropriate safe account, license, or device code.
- Database or internal failures: `500 SERVER_ERROR` without internal details.
- Client network failure during profile load: clear the token and show a retry-oriented message on login.
- Profile response missing required fields: treat as malformed, clear the token, and do not show the panel.

## Testing

### Go

- Bearer parsing and rejection cases.
- Signature, expiry, issuer, audience, and product enforcement.
- `/v1/me` happy path.
- User, license, and device ownership binding.
- Disabled user, expired/revoked license, and revoked device behavior.
- Response schema excludes secret and raw hardware fields.
- Repository and HTTP error mapping.

### Qt

- Profile response parsing and required-field validation.
- Authorization header construction without token logging.
- Dashboard field presentation.
- Login remains hidden only after successful profile loading.
- Failed profile loading clears the session and returns to login.
- Sign out clears credentials/session state and returns to login.
- Login, HWID, and dashboard title bars have no native icon slot and expose working close/minimize behavior.
- Existing login, TPM, HWID, token, and theme tests remain green.

## Security Properties

- The token remains memory-only.
- `/v1/me` trusts only verified token claims for identity selection.
- Current database state is checked on every profile load.
- No secret, credential hash, license plaintext, protected hardware value, or TPM material reaches the dashboard.
- Sign out destroys client-held authenticated state.
- Custom window chrome changes presentation only and does not weaken transport, token, TPM, or database controls.

# StarLoader

**TPM-backed login, licensing, and device binding for Windows desktop applications.**

StarLoader is a C++ reference implementation for building an authenticated Windows loader or client. Use its Qt interface as a starting point, or adapt the authentication layer to an ImGui frontend for your own licensed software, private utilities, and authorized modding or testing tools.

A copied HWID is not proof of device possession. StarLoader combines hardware matching with a TPM-held key, signed server challenges, and short-lived proof-bound sessions.

[Quick start](#quick-start) · [Integration](#integration) · [StarLoader + KeyStar](#starloader--keystar)

## Screenshots

<p align="center">
  <img src="login_screenshoot.png" width="240" alt="StarLoader login form"/>
  <img src="user_detail_screenshoot.png" width="330" alt="Authenticated account, license, and device dashboard"/>
</p>
<p align="center">
  <img src="hwid_obtainer_tool_screenshoot.png" width="520" alt="Local HWID and TPM diagnostic tool"/>
</p>

## Stack

| Component | Technology | Role |
|---|---|---|
| `license-client/` | C++20, Qt 6, OpenSSL | Login UI, API client, token verification, and session state |
| `shared/` | Windows CNG / TPM 2.0 | Device key, hardware collection, and fingerprinting |
| `hwid-obtainer/` | Qt / C++ | Local hardware and TPM diagnostics; no API calls |
| `backend/` | Go 1.26.6, PostgreSQL | Bundled reference API for authentication, licensing, and device verification |
| [KeyStar](https://github.com/Starhaxor/KeyStar) | Go, PostgreSQL, Next.js | Separate multi-application authorization platform and administration console |

The included desktop applications use Qt. ImGui integration requires adapting the client code; this repository does not ship an ImGui frontend or a standalone UI-independent SDK.

## Architecture

```text
Qt client / custom ImGui frontend
  → account login
  → single-use server challenge
  → TPM P-256 signature + device signals
  → server checks license, device policy, and proof
  → Ed25519 access token (600 seconds)
  → DPoP-authenticated /v1/me
  → authenticated application UI
```

The client verifies the token and retrieves the authenticated profile before opening the dashboard. The backend owns authorization decisions, license status, device limits, and revocation. UI state alone must never authorize a protected server operation.

## Security model

- **Device proof:** a non-exportable TPM P-256 key signs a short-lived, single-use challenge. Hardware signals support matching; they are not secrets or proof by themselves.
- **Hardware privacy:** the reference backend HMAC-protects individual hardware signals and license keys; passwords use Argon2id.
- **Bound sessions:** Ed25519 tokens expire after exactly 600 seconds. The client checks the signing key and application, product, license, device, and session bindings.
- **Request proof:** protected requests carry `Authorization: DPoP <token>` and a TPM-signed `DPoP` header. The matching server must enforce key/token/URI binding and reject replay.
- **Client trust:** tokens stay in process memory and are cleared on expiry, profile failure, or sign-out. Endpoint, public-key ring, and trust policy are configured at build time.
- **Transport:** production requires normal HTTPS certificate validation plus two distinct SPKI pins for the configured host.

There is no bearer-session fallback, refresh flow, offline lease, or remote TPM attestation in this client. TPM possession does not establish that the operating system is uncompromised. TPM resets can require an authorized device recovery process.

## StarLoader + KeyStar

[KeyStar](https://github.com/Starhaxor/KeyStar) provides the backend and authorization service; StarLoader provides the Windows client and device-proof flow. KeyStar manages applications, users, products, licenses, device policies, and administrative operations.

1. Deploy KeyStar and its migrations, then create an application, product, user, and valid license.
2. Create a **publishable** client credential and confirm exactly one active application signing key.
3. Configure StarLoader with the same application/product IDs, publishable key, signing public-key ring, API origin, and TLS pins. KeyStar's `PUBLIC_SCHEME` and `PUBLIC_HOST` must match that public origin.
4. Follow KeyStar's activation order to enable the application's **`proof_bound`** profile, then verify login, device proof, `/v1/me`, expiry, revocation, and replay rejection.

KeyStar's default `legacy` bearer/refresh profile is incompatible with this StarLoader client. Keep `ks_sk_*` management credentials and private signing keys on trusted servers; distribute only the publishable credential and public verification material.

See [KeyStar's proof-bound setup](https://github.com/Starhaxor/KeyStar/blob/main/docs/PROOF_BOUND_APPLICATIONS.md) and the [StarLoader release guide](docs/STARLOADER_PROTECTED_RELEASE.md). Repository support for the protocol does not establish that a particular deployment has passed native TPM smoke tests.

## Quick start

### 1. Prepare the environment

Use Windows 10/11 with TPM 2.0 enabled, Qt 6.11.1 MinGW, MinGW 13.1, Ninja, and CMake with preset-schema v6 support. The client requires a matching MinGW build of **OpenSSL 3.5.8 or newer**; presets look in `build-deps/openssl-install`.

```powershell
git clone https://github.com/Starhaxor/StarLoader.git
cd StarLoader
```

Set up the KeyStar application as described above using its [backend quick start](https://github.com/Starhaxor/KeyStar#quick-start). Have a licensed test account and the deployment's public configuration ready.

### 2. Configure and build the client

Replace every placeholder below with values from that same deployment. Supply a real current pin and a distinct staged rotation pin.

```powershell
cmake --preset qt-mingw `
  -DSTARLOADER_API_URL="https://<keystar-host>" `
  -DSTARLOADER_TLS_PINNED_HOST="<keystar-host>" `
  -DSTARLOADER_TLS_SPKI_PINS="sha256/<current-pin>,sha256/<staged-pin>" `
  -DSTARLOADER_ED25519_KEY_RING="<kid>=<base64-public-key>" `
  -DSTARLOADER_APPLICATION_ID="<application-uuid>" `
  -DSTARLOADER_PRODUCT_ID="<product-uuid>" `
  -DSTARLOADER_PUBLISHABLE_KEY="<publishable-key>"
cmake --build --preset qt-mingw-build
```

For local fixture development, `qt-mingw-local` permits only `http://127.0.0.1:8080`. It forces the checked-in fixture application ID, publishable key, and signing public key through [CMakeLists.txt](CMakeLists.txt); it is not a generic configuration for any new KeyStar instance. Set `STARLOADER_PRODUCT_ID` to the fixture's licensed product UUID before configuring.

### 3. Run

For an unbundled build, add the matching runtime DLL directories to the current PowerShell session:

```powershell
$env:Path = "$PWD\build-deps\openssl-install\bin;C:\Qt\Tools\mingw1310_64\bin;C:\Qt\6.11.1\mingw_64\bin;$env:Path"
& .\build\license-client\LicenseClient.exe
```

Sign in with the licensed account while the API is running. Use `build\hwid-obtainer\HwidObtainer.exe` to inspect local hardware and TPM proof diagnostics.

The bundled `backend/` is a separate reference-service option. Its configuration and protocol are in [.env.example](.env.example) and [server-contract/API.md](server-contract/API.md); the local PostgreSQL service is defined in [deploy/compose.yaml](deploy/compose.yaml).

## Integration

For a Qt application, start with [AuthManager](license-client/src/auth/AuthManager.h), [ApiClient](license-client/src/api/ApiClient.h), and the verification code in [license-client/src/security](license-client/src/security). Connect your UI to authentication state and sign-out/expiry events.

For an ImGui application, place an adapter between your rendering loop and those authentication components. They currently depend on Qt, so retain the necessary Qt runtime/event handling or port that layer deliberately. Preserve TPM signing, token validation, DPoP generation, TLS policy, and session cleanup when changing the frontend.

Enable licensed functionality after the verified profile is loaded, and enforce authorization again on the server for protected operations. This integration is intended for applications and tools you own or are authorized to develop and operate.

## Verification and reference

Run the repository's full verification entry point with Docker Desktop and the native toolchain available:

```powershell
.\scripts\test-all.ps1
```

It covers the Go/PostgreSQL tests, Go vet, Qt/CTest, secret scanning, and whitespace checks. A live KeyStar/TPM flow requires a separately configured matching fixture.

- [HTTP API contract](server-contract/API.md)
- [Production configuration and release validation](docs/STARLOADER_PROTECTED_RELEASE.md)
- [KeyStar application integration](https://github.com/Starhaxor/KeyStar#application-integration)

## License

No open-source license is declared in this repository. Public source availability does not grant redistribution rights.

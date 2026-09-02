# StarLoader Proof-Bound Client Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the StarLoader desktop client enforce 600-second, TPM proof-bound, memory-only sessions with full password-plus-TPM reauthentication on launch and expiry, and add selective VMProtect release markers.

**Architecture:** A strict token verifier returns verified bindings and expiry, a dedicated DPoP builder converts the existing TPM CNG public blob into a P-256 JWK and signs request-bound proofs, and `ApiClient` exposes only a proof-required protected-request path. `AuthManager` owns expiry and secret clearing. VMProtect integration is isolated behind StarLoader macros and is inert in ordinary builds.

**Tech Stack:** C++20, Qt 6 Core/Network/Concurrent/Test, OpenSSL Ed25519 verification, Windows CNG/TPM, CMake/CTest, VMProtect SDK markers in protected releases.

**Spec:** `docs/superpowers/specs/2026-09-01-starloader-proof-bound-client-design.md`

## Global Constraints

- Preserve unrelated modified and untracked files.
- Access tokens, passwords, proofs, and TPM private material are never logged or persisted.
- Access-token lifetime is exactly 600 seconds; no refresh, offline lease, silent login, or bearer-only protected request exists.
- Production protected requests use `Authorization: DPoP <token>` plus exactly one TPM-signed `DPoP` header.
- Proof `htu` is an absolute normalized HTTPS URI without query or fragment; local numeric loopback HTTP remains test/development-only.
- Production activation remains fail-closed until KeyStar supports the matching token/proof contract; never add a bearer fallback.
- VMProtect markers are no-ops outside explicitly protected release builds and never wrap Qt loops, transport, OpenSSL/CNG calls, exception blocks, or unbounded parsing.

---

### Task 1: Verify the 600-Second Application-Bound Token Profile

**Files:**
- Modify: `license-client/src/security/SessionTokenVerifier.h`
- Modify: `license-client/src/security/SessionTokenVerifier.cpp`
- Modify: `license-client/tests/SessionTokenVerifierTest.cpp`
- Modify: `license-client/src/config/ClientSecurityConfig.h.in`
- Modify: `license-client/CMakeLists.txt`
- Modify: `CMakeLists.txt`
- Modify: `CMakePresets.json`

**Interfaces:**
- Produces: `VerifiedSession { bool valid; QString error; QDateTime expiresAt; QString sessionId; QString tokenId; QString deviceKeyThumbprint; }`.
- Produces: `SessionTokenVerifier(QHash<QString,QByteArray> keys, QString issuer, QString audience, QString applicationID, QString productID, QString product)`.
- Produces: `SessionTokenVerifier::fromConfiguredKeyRing(...)` parsing exact `kid=<standard-base64>[,kid=<standard-base64>]` entries.

```cpp
struct VerifiedSession {
    bool valid = false;
    QString error;
    QDateTime expiresAt;
    QString sessionId;
    QString tokenId;
    QString deviceKeyThumbprint;
};
```

- [x] Write tests whose tokens contain `kid`, `app`, `product_id`, `sid`, `jti`, `nbf`, and `cnf.jkt`; assert a valid 600-second token returns every verified binding.
- [x] Add table-driven rejection tests for unknown `kid`, missing/duplicate critical fields, wrong app/product/device/license, malformed thumbprint, `nbf` outside skew, and lifetimes 599/601/3600.
- [x] Run `cmake --build --preset qt-mingw-local --target SessionTokenVerifierTest && ctest --preset qt-mingw-local -R SessionTokenVerifierTest --output-on-failure`; verify RED because the new profile is unsupported.
- [x] Implement strict header/key selection and claim validation. Reject unknown/extra JOSE members and non-canonical encodings. Return only sanitized `Invalid session token.` failures.
- [x] Add `STARLOADER_ED25519_KEY_RING` compile-time validation; require at least one unique `kid`, canonical standard Base64, and 32-byte decoded keys without embedding a usable production example.
- [x] Re-run the focused test and commit `feat(auth): verify proof-bound StarLoader tokens`.

### Task 2: Build TPM P-256 JWK and DPoP Proofs

**Files:**
- Create: `license-client/src/security/DeviceProof.h`
- Create: `license-client/src/security/DeviceProof.cpp`
- Create: `license-client/tests/DeviceProofTest.cpp`
- Modify: `license-client/CMakeLists.txt`

**Interfaces:**
- Produces: `IDeviceProofSigner::sign(QByteArrayView input, QByteArray *signature, QByteArray *publicBlob, QString *error)` and `TpmProofSigner` backed by `TpmIdentity`.
- Produces: `DeviceProofBuilder::build(const QString &method, const QUrl &url, const QString &accessToken, const QString &expectedThumbprint) -> ProofResult`.
- Produces: `ProofResult { bool valid; QString compactJws; QString jwkThumbprint; QString error; }`.

```cpp
class IDeviceProofSigner {
public:
    virtual ~IDeviceProofSigner() = default;
    virtual bool sign(QByteArrayView input, QByteArray *signature,
                      QByteArray *publicBlob, QString *error) = 0;
};
struct ProofResult {
    bool valid = false;
    QString compactJws;
    QString jwkThumbprint;
    QString error;
};
```

- [x] Write deterministic tests with injected clock, 16-byte random source, and signer. Assert exact `typ`, `alg`, JWK X/Y, `jti`, uppercase `htm`, canonical `htu`, `iat`, `ath`, and 64-byte signature encoding.
- [x] Add rejection cases for wrong CNG magic/length, non-HTTPS production URL, query/fragment retention, non-64-byte signature, empty token, and token/JWK thumbprint mismatch.
- [x] Run the focused target and verify RED because `DeviceProofBuilder` does not exist.
- [x] Implement strict CNG blob parsing, RFC 7638 canonical thumbprint, canonical compact JSON/JWS, and SHA-256 `ath`. Clear temporary signing input after use.
- [x] Make `TpmDeviceSigner` implement the new signer interface using the existing non-exportable TPM key; do not change CNG key policy.
- [x] Run focused tests and commit `feat(security): create TPM-bound DPoP proofs`.

### Task 3: Make Protected Requests Proof-Required

**Files:**
- Modify: `license-client/src/api/ApiClient.h`
- Modify: `license-client/src/api/ApiClient.cpp`
- Modify: `license-client/tests/ApiClientTest.cpp`

**Interfaces:**
- Consumes: `DeviceProofBuilder::build` from Task 2.
- Replaces: `loadProfile(const QString &token, quint64 generation)` with `loadProfile(const ProtectedSession &session, quint64 generation)`.
- Produces: `ProtectedSession { QString accessToken; QString deviceKeyThumbprint; QDateTime expiresAt; }`.

```cpp
struct ProtectedSession {
    QString accessToken;
    QString deviceKeyThumbprint;
    QDateTime expiresAt;
};
// Captured request must contain exactly:
// Authorization: DPoP <accessToken>
// DPoP: <compact ES256 proof>
```

- [x] Write a loopback transport test that captures `/v1/me` and proves it carries exactly one `Authorization: DPoP <token>` and one matching `DPoP` proof.
- [x] Add tests proving no socket request is sent when proof construction fails, token is expired, URL is noncanonical, or the proof thumbprint mismatches.
- [x] Verify focused RED; current code sends bearer-only.
- [x] Inject a proof builder into `ApiClient`, centralize protected request creation, and remove the bearer-only profile path. Sanitize all proof/token failures.
- [x] Keep login/device endpoints publishable-credential authenticated and unchanged.
- [x] Run `ApiClientTest` and commit `feat(api): require TPM proof on protected requests`.

### Task 4: Expire Sessions into Full Reauthentication

**Files:**
- Modify: `license-client/src/auth/AuthManager.h`
- Modify: `license-client/src/auth/AuthManager.cpp`
- Modify: `license-client/src/api/ApiClient.h`
- Modify: `license-client/src/api/ApiClient.cpp`
- Modify: `license-client/src/ui/LoginWindow.cpp`
- Modify: `license-client/tests/AuthManagerTest.cpp`
- Modify: `license-client/tests/LoginWindowUiTest.cpp`
- Modify: `license-client/tests/UserDashboardTest.cpp`

**Interfaces:**
- Consumes: verified expiry and `cnf.jkt` from Task 1 and `ProtectedSession` from Task 3.
- Produces: single-shot expiry timer and `reauthenticationRequired(QString reason)` signal.

```cpp
QSignalSpy reauth(&manager, &AuthManager::reauthenticationRequired);
clock.advance(std::chrono::seconds(600));
QCOMPARE(reauth.count(), 1);
QCOMPARE(manager.state(), AuthState::LoggedOut);
QVERIFY(manager.sessionToken().isEmpty());
QCOMPARE(api.loginCount, 1); // no automatic login or refresh
```

- [x] Add tests with an injectable timer/clock proving expiry cancels protected work, overwrites token state, clears profile/device/session state, emits reauthentication, and never calls login/device/refresh automatically.
- [x] Add tests proving the password buffer is overwritten/cleared immediately after login serialization and is absent from failure/status strings.
- [x] Add UI tests proving launch always shows credentials and expiry closes the dashboard and restores the credential form with a safe reason.
- [x] Verify focused RED.
- [x] Implement the timer from verified `exp`, make all auth/proof failures call one memory-clearing path, and keep email only as ordinary UI state.
- [x] Run auth/UI tests and commit `feat(auth): require full reauthentication on expiry`.

### Task 5: Pin the Production KeyStar SPKI

**Files:**
- Create: `license-client/src/security/TlsPinPolicy.h`
- Create: `license-client/src/security/TlsPinPolicy.cpp`
- Create: `license-client/tests/TlsPinPolicyTest.cpp`
- Modify: `license-client/src/api/ApiClient.h`
- Modify: `license-client/src/api/ApiClient.cpp`
- Modify: `license-client/src/config/ClientSecurityConfig.h.in`
- Modify: `license-client/CMakeLists.txt`
- Modify: `CMakeLists.txt`
- Modify: `CMakePresets.json`

**Interfaces:**
- Produces: `TlsPinPolicy(QString expectedHost, QList<QByteArray> sha256Pins, bool localDevelopment)`.
- Produces: `TlsPinPolicy::verify(const QUrl &requestUrl, const QSslCertificate &peer) -> bool`.

```cpp
TlsPinPolicy policy(QStringLiteral("api.example.test"),
                    {currentPinSha256, stagedNextPinSha256}, false);
QVERIFY(policy.verify(QUrl(QStringLiteral("https://api.example.test/v1/me")), currentCertificate));
QVERIFY(!policy.verify(QUrl(QStringLiteral("https://redirect.example.test/v1/me")), currentCertificate));
```

- [x] Add policy tests with generated X.509 fixtures proving current and staged-next SPKI pins pass, while wrong host/key, empty certificate, malformed pin, redirect host, and a third pin fail.
- [x] Verify focused RED because `TlsPinPolicy` does not exist.
- [x] Implement SPKI extraction with OpenSSL `d2i_X509`, `X509_get_X509_PUBKEY`, and `i2d_X509_PUBKEY`, then SHA-256 compare without disabling normal Qt TLS validation.
- [x] Require exact compile-time syntax `sha256/<standard-base64>,sha256/<standard-base64>` for production; require two distinct 32-byte pins. Local-development presets carry no pins and allow only numeric loopback HTTP.
- [x] Connect `QNetworkAccessManager::encrypted` and `sslErrors`; abort on missing/mismatched pins or any TLS error, and reject redirects whose host differs from the configured host.
- [x] Run `TlsPinPolicyTest` and `ApiClientTest`; commit `feat(tls): pin KeyStar production SPKI`.

### Task 6: Add Selective VMProtect Marker Abstraction

**Files:**
- Create: `license-client/src/security/ProtectionMarkers.h`
- Create: `license-client/tests/ProtectionMarkersTest.cpp`
- Modify: `license-client/CMakeLists.txt`
- Modify: `CMakePresets.json`
- Modify: `license-client/src/security/SessionTokenVerifier.cpp`
- Modify: `license-client/src/security/DeviceProof.cpp`
- Modify: `license-client/src/auth/AuthManager.cpp`

**Interfaces:**
- Produces: `STARLOADER_VM_BEGIN(name)`, `STARLOADER_VM_END()`, `STARLOADER_MUTATE_BEGIN(name)`, `STARLOADER_MUTATE_END()`.

```cpp
#if defined(STARLOADER_PROTECTED_RELEASE)
#include <VMProtectSDK.h>
#define STARLOADER_VM_BEGIN(name) VMProtectBeginVirtualization(name)
#define STARLOADER_VM_END() VMProtectEnd()
#else
#define STARLOADER_VM_BEGIN(name) do { (void)sizeof(name); } while (false)
#define STARLOADER_VM_END() do {} while (false)
#endif
```

- [x] Add compile tests proving ordinary/test builds require no VMProtect SDK and every macro is a valid no-op statement pair.
- [x] Add a configure-negative test proving `STARLOADER_PROTECTED_RELEASE=ON` fails when the VMProtect SDK/project path is absent.
- [x] Verify RED before the marker header/options exist.
- [x] Implement no-op macros by default and VMProtect SDK mappings only under `STARLOADER_PROTECTED_RELEASE`.
- [x] Mark only token claim-policy decision, DPoP field/binding decision, and verified-profile-to-authenticated transition. Keep parsing, crypto, network, and Qt loops outside regions.
- [x] Run configure/build tests and commit `feat(release): add selective VMProtect markers`.

### Task 7: Verification and Activation Boundary

**Files:**
- Modify: `README.md`
- Create: `docs/STARLOADER_PROTECTED_RELEASE.md`
- Modify: `docs/superpowers/plans/2026-09-01-starloader-proof-bound-client.md`

**Interfaces:**
- Consumes all previous tasks.
- Produces documented client/KeyStar activation boundary and release ordering.

- [x] Document that the build is proof-ready but production activation requires KeyStar token-profile/DPoP support; no bearer fallback exists.
- [x] Document exact no-secret key-ring syntax, VMProtect SDK/project inputs, protected smoke tests, malware scanning, then Authenticode SHA-256 plus RFC 3161 timestamp.
- [x] Run `cmake --preset qt-mingw-local`, build all targets, and `ctest --preset qt-mingw-local --output-on-failure` (19/19 passed on 2026-09-02).
- [x] Run the native live-flow test against a matching proof-enabled KeyStar fixture when available; otherwise record the explicit dependency without weakening unit/API coverage. The fixture was unavailable: `STARLOADER_NATIVE_LIVE_EMAIL`, `STARLOADER_NATIVE_LIVE_PASSWORD`, and `STARLOADER_NATIVE_LIVE_MAX_DEVICES` were unset, so `NativeLiveFlowTest` skipped its live proof flow.
- [x] Run `git diff --check` and a reproducible literal-secret scan for access tokens, passwords, private keys, and proof bodies. The checked-in scanner includes authored source/configuration/docs/scripts/tests (including CMake presets) and excludes only build/generated/vendor/Git/nested-worktree paths; no prohibited literal was found.
- [x] Commit `fix(docs): align protected release instructions`.

# Login, HWID Obtainer and Go Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build two Windows Qt 6 applications backed by a Go/PostgreSQL licensing API with TPM-bound, single-use challenge verification.

**Architecture:** A C++20 `DeviceIdentityShared` library owns Windows hardware and TPM operations and is linked by independent `HwidObtainer` and `LicenseClient` executables. A single Go binary exposes the HTTP API and admin commands, with application services separated from PostgreSQL repositories so cryptography and policy remain unit-testable.

**Tech Stack:** Qt 6.11 Widgets/Core/Network/Concurrent/Test, C++20, Windows CNG and Win32 APIs, CMake/Ninja/MinGW, Go, `chi/v5`, `pgx/v5`, `golang-jwt/jwt/v5`, `x/crypto`, PostgreSQL 17, Docker Compose.

## Global Constraints

- Clients target Windows 10/11, Qt 6 Widgets, and C++20.
- Production authentication fails closed when TPM 2.0 is unavailable; there is no software-key fallback.
- Local PostgreSQL is started with Docker Compose.
- Production API traffic is HTTPS-only; local development may use HTTP.
- Passwords use Argon2id; license keys and hardware fields use separate HMAC-SHA256 secrets.
- Application tokens are Ed25519-signed and expire after one hour.
- Challenges contain 32 random bytes, expire after two minutes, and are single-use.
- Device matching weights are TPM 50, SMBIOS UUID 20, motherboard 15, BIOS 5, system disk 5, MachineGuid 5; the acceptance threshold is 70.
- Request IDs and every server-generated database primary key use canonical UUIDv7; database constraints reject other UUID versions.
- Never log passwords, full license keys, tokens, complete TPM public keys, or raw hardware serial values.
- Preserve the user's current uncommitted Qt UI work while moving it into the new repository layout.

---

## File Map

- `CMakeLists.txt`: top-level Qt/C++ build and test registration.
- `shared/`: focused hardware, SMBIOS, fingerprint, TPM, and JSON model units.
- `shared/tests/`: QtTest unit tests for pure identity logic and Windows TPM integration.
- `hwid-obtainer/`: independent diagnostic UI and executable.
- `license-client/`: API client, auth state machine, token verifier, login UI, and executable.
- `backend/cmd/server/`: HTTP server and admin command entry point.
- `backend/internal/config/`: environment validation.
- `backend/internal/security/`: Argon2id, HMAC, random license/challenge, ECDSA verification, Ed25519 tokens.
- `backend/internal/domain/`: shared domain values, statuses, errors, device scoring.
- `backend/internal/store/`: PostgreSQL repositories and transaction boundary.
- `backend/internal/service/`: login and device-verification use cases.
- `backend/internal/httpapi/`: JSON transport, middleware, handlers, and error mapping.
- `backend/migrations/`: versioned PostgreSQL schema.
- `backend/tests/integration/`: real-PostgreSQL API tests.
- `deploy/compose.yaml`: local PostgreSQL.
- `server-contract/API.md`: exact request, response, and error contract.
- `.env.example`, `README.md`: safe configuration and operator workflow.

---

### Task 1: Establish the Monorepo Build and Preserve the Existing UI

**Files:**
- Modify: `.gitignore`
- Modify: `CMakeLists.txt`
- Move: `main.cpp` -> `license-client/src/main.cpp`
- Move: `mainwindow.h` -> `license-client/src/ui/LoginWindow.h`
- Move: `mainwindow.cpp` -> `license-client/src/ui/LoginWindow.cpp`
- Move: `mainwindow.ui` -> `license-client/ui/LoginWindow.ui`
- Move: `hwiddialog.h` -> `license-client/src/ui/HwidDialog.h`
- Move: `hwiddialog.cpp` -> `license-client/src/ui/HwidDialog.cpp`
- Move: `hwiddialog.ui` -> `license-client/ui/HwidDialog.ui`
- Create: `shared/CMakeLists.txt`
- Create: `shared/DeviceIdentity.cpp`
- Create: `shared/tests/CMakeLists.txt`
- Create: `shared/tests/BuildSmokeTest.cpp`
- Create: `license-client/CMakeLists.txt`
- Create: `hwid-obtainer/CMakeLists.txt`
- Create: `hwid-obtainer/src/main.cpp`
- Create: `hwid-obtainer/src/MainWindow.h`
- Create: `hwid-obtainer/src/MainWindow.cpp`

**Interfaces:**
- Produces: CMake targets `DeviceIdentityShared`, `SharedTests`, `HwidObtainer`, and `LicenseClient`.
- Produces: `int main(int argc, char **argv)` for both GUI executables.

- [ ] **Step 1: Add the build smoke test before the library exists**

```cpp
#include <QtTest>

class BuildSmokeTest final : public QObject {
    Q_OBJECT
private slots:
    void qtRuntimeIsAvailable() { QVERIFY(QCoreApplication::instance() != nullptr); }
};

QTEST_MAIN(BuildSmokeTest)
#include "BuildSmokeTest.moc"
```

- [ ] **Step 2: Configure and confirm the missing target fails**

Run:

```powershell
& 'C:\Qt\Tools\CMake_64\bin\cmake.exe' -S . -B build -G Ninja -DCMAKE_PREFIX_PATH=C:\Qt\6.11.1\mingw_64
```

Expected: configuration fails because the new subdirectories/targets do not exist yet.

- [ ] **Step 3: Create the minimal target graph and move the existing files with history-preserving `git mv`**

The root `CMakeLists.txt` must set C++20, enable `AUTOMOC/AUTOUIC`, find Qt `Core`, `Widgets`, `Network`, `Concurrent`, and `Test`, call `enable_testing()`, and add the three subdirectories. `shared/CMakeLists.txt` initially creates an empty interface-compatible static library from a minimal `DeviceIdentity.cpp`; later tasks replace that stub with focused sources.

- [ ] **Step 4: Repair includes/class names after the move and build all targets**

Run:

```powershell
& 'C:\Qt\Tools\CMake_64\bin\cmake.exe' --build build
& 'C:\Qt\Tools\CMake_64\bin\ctest.exe' --test-dir build --output-on-failure
```

Expected: both executables build and `BuildSmokeTest` passes.

- [ ] **Step 5: Commit only the preserved UI and build skeleton**

```powershell
git add .gitignore CMakeLists.txt shared hwid-obtainer license-client docs/qt_cpp_hwid_login_license_system.md
git commit -m "build: split Qt applications and shared library"
```

---

### Task 2: Implement Normalization, Identity Model, and Fingerprint

**Files:**
- Create: `shared/hardware/HardwareIdentity.h`
- Create: `shared/security/HardwareNormalization.h`
- Create: `shared/security/HardwareNormalization.cpp`
- Create: `shared/security/Fingerprint.h`
- Create: `shared/security/Fingerprint.cpp`
- Create: `shared/tests/FingerprintTest.cpp`
- Modify: `shared/CMakeLists.txt`
- Modify: `shared/tests/CMakeLists.txt`

**Interfaces:**
- Produces: `QString normalizeHardwareValue(QString value)`.
- Produces: `QString Fingerprint::generate(const HardwareIdentity &identity)`.
- Produces: `QString HardwareIdentity::displayId() const` using the first 12 fingerprint characters formatted `XXXXXX-XXXXXX`.

- [ ] **Step 1: Write failing normalization and deterministic fingerprint tests**

```cpp
void FingerprintTest::normalizesHardwareValues()
{
    QCOMPARE(normalizeHardwareValue(" {ab-c 12} "), QString("ABC12"));
}

void FingerprintTest::usesEveryFieldInStableOrder()
{
    HardwareIdentity hw{"uuid", "board", "bios", "disk", "guid", "x64", "host", "tpm", {}};
    const auto first = Fingerprint::generate(hw);
    hw.machineGuid = "different";
    QVERIFY(first != Fingerprint::generate(hw));
    QCOMPARE(first.size(), 64);
}
```

- [ ] **Step 2: Run and verify RED**

```powershell
& 'C:\Qt\Tools\CMake_64\bin\cmake.exe' --build build --target SharedTests
& 'C:\Qt\Tools\CMake_64\bin\ctest.exe' --test-dir build -R FingerprintTest --output-on-failure
```

Expected: compilation fails because the identity and fingerprint APIs do not exist.

- [ ] **Step 3: Implement the minimal pure functions**

`Fingerprint::generate` appends the six normalized security fields in this exact order, appends `|` after each value, and returns uppercase SHA-256 hex. It assigns the result to callers; it does not mutate the passed model.

- [ ] **Step 4: Run the focused and complete C++ test suites**

Use the commands from Step 2, then run all CTest tests. Expected: PASS.

- [ ] **Step 5: Commit**

```powershell
git add shared
git commit -m "feat: add deterministic hardware fingerprints"
```

---

### Task 3: Parse SMBIOS and Collect Windows Hardware Signals

**Files:**
- Create: `shared/hardware/RegistryReader.h`
- Create: `shared/hardware/RegistryReader.cpp`
- Create: `shared/hardware/SmbiosParser.h`
- Create: `shared/hardware/SmbiosParser.cpp`
- Create: `shared/hardware/SmbiosReader.h`
- Create: `shared/hardware/SmbiosReader.cpp`
- Create: `shared/hardware/DiskReader.h`
- Create: `shared/hardware/DiskReader.cpp`
- Create: `shared/hardware/HardwareCollector.h`
- Create: `shared/hardware/HardwareCollector.cpp`
- Create: `shared/tests/SmbiosParserTest.cpp`
- Create: `shared/tests/HardwareCollectorTest.cpp`
- Modify: `shared/CMakeLists.txt`
- Modify: `shared/tests/CMakeLists.txt`

**Interfaces:**
- Produces: `SmbiosInfo SmbiosParser::parse(QByteArrayView rawTable)`.
- Produces: `SmbiosInfo SmbiosReader::read()`.
- Produces: `QString RegistryReader::machineGuid()`.
- Produces: `QString DiskReader::systemDiskSerial()` resolving the physical disk behind `%SystemDrive%`.
- Produces: `HardwareIdentity HardwareCollector::collect()`.

- [ ] **Step 1: Write a failing SMBIOS fixture test**

Construct a byte array containing Type 0, Type 1, Type 2, and Type 127 records with double-NUL string terminators. Assert BIOS serial, RFC 4122-formatted system UUID, and motherboard serial. Add truncated-record and missing-string-index cases that return empty fields without reading out of bounds.

```cpp
void SmbiosParserTest::rejectsTruncatedFormattedSection()
{
    const QByteArray malformed = QByteArray::fromHex("010801000000");
    const auto result = SmbiosParser::parse(malformed);
    QVERIFY(result.systemUuid.isEmpty());
}
```

- [ ] **Step 2: Run and verify RED**

Expected: `SmbiosParser` is missing.

- [ ] **Step 3: Implement the bounds-checked parser and Windows readers**

`SmbiosReader` obtains `RSMB` data through `GetSystemFirmwareTable`. `RegistryReader` uses the 64-bit registry view for `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`. `DiskReader` maps the Windows system volume to its disk extent before querying `IOCTL_STORAGE_QUERY_PROPERTY`; it must not assume `PhysicalDrive0`.

- [ ] **Step 4: Add an injected collector test**

Use an `IHardwareSource` boundary so the unit test can provide known SMBIOS/disk/registry values and assert that `HardwareCollector` fills architecture and hostname without requiring administrator rights.

- [ ] **Step 5: Run all C++ tests and commit**

```powershell
& 'C:\Qt\Tools\CMake_64\bin\ctest.exe' --test-dir build --output-on-failure
git add shared
git commit -m "feat: collect Windows hardware identity signals"
```

---

### Task 4: Add TPM-Backed Device Identity and Local Verification

**Files:**
- Create: `shared/security/TpmIdentity.h`
- Create: `shared/security/TpmIdentity.cpp`
- Create: `shared/security/EcdsaSignature.h`
- Create: `shared/security/EcdsaSignature.cpp`
- Create: `shared/tests/TpmIdentityTest.cpp`
- Modify: `shared/hardware/HardwareCollector.cpp`
- Modify: `shared/CMakeLists.txt`
- Modify: `shared/tests/CMakeLists.txt`

**Interfaces:**
- Produces: `bool TpmIdentity::isAvailable()`.
- Produces: `bool TpmIdentity::ensureKey(QString *error)` using `StarLoader.DeviceIdentity.v1`.
- Produces: `QByteArray TpmIdentity::publicKeyBlob()` in Windows `BCRYPT_ECCPUBLIC_BLOB` form.
- Produces: `QString TpmIdentity::publicKeySha256()`.
- Produces: `QByteArray TpmIdentity::signChallenge(QByteArrayView challenge, QString *error)`.
- Produces: `bool EcdsaSignature::verifyCngP256(QByteArrayView publicBlob, QByteArrayView challenge, QByteArrayView signature)`.

- [ ] **Step 1: Write the required three TPM tests**

```cpp
void TpmIdentityTest::signatureBindsChallenge()
{
    if (!TpmIdentity::isAvailable()) QSKIP("TPM 2.0 unavailable on test host");
    QString error;
    QVERIFY2(TpmIdentity::ensureKey(&error), qPrintable(error));
    const QByteArray challenge(32, '\x2a');
    const auto publicKey = TpmIdentity::publicKeyBlob();
    const auto signature = TpmIdentity::signChallenge(challenge, &error);
    QVERIFY(EcdsaSignature::verifyCngP256(publicKey, challenge, signature));
    QVERIFY(!EcdsaSignature::verifyCngP256(publicKey, challenge + "x", signature));
    QByteArray changed = signature; changed[0] ^= 1;
    QVERIFY(!EcdsaSignature::verifyCngP256(publicKey, challenge, changed));
}
```

- [ ] **Step 2: Run and verify RED**

Expected: TPM and verifier APIs are missing.

- [ ] **Step 3: Implement RAII CNG handles and fail-closed signing**

Open `MS_PLATFORM_CRYPTO_PROVIDER`, create/open an ECDSA P-256 persisted key, export only the public blob, hash the challenge with SHA-256, and call `NCryptSignHash`. Every handle is released on all paths. Empty challenge, unavailable TPM, key failure, or empty signature returns a failure with a non-secret error.

- [ ] **Step 4: Run tests on the Windows host**

Expected: all three local verification assertions pass when TPM is available; only the TPM integration case is explicitly skipped otherwise.

- [ ] **Step 5: Commit**

```powershell
git add shared
git commit -m "feat: add TPM-backed challenge signing"
```

---

### Task 5: Build the Independent HWID Obtainer

**Files:**
- Create: `shared/hardware/HardwareJson.h`
- Create: `shared/hardware/HardwareJson.cpp`
- Create: `shared/tests/HardwareJsonTest.cpp`
- Create: `hwid-obtainer/ui/MainWindow.ui`
- Modify: `hwid-obtainer/src/MainWindow.h`
- Modify: `hwid-obtainer/src/MainWindow.cpp`
- Modify: `hwid-obtainer/CMakeLists.txt`

**Interfaces:**
- Consumes: `HardwareCollector::collect`, `Fingerprint::generate`, and TPM APIs.
- Produces: `QJsonObject HardwareJson::toJson(const HardwareIdentity &identity)` with the seven documented snake_case keys.

- [ ] **Step 1: Write the failing JSON schema test**

```cpp
const auto json = HardwareJson::toJson(identity);
QCOMPARE(json.keys(), QStringList({"bios_serial", "fingerprint", "machine_guid", "motherboard_serial", "smbios_uuid", "system_disk_serial", "tpm_public_key_hash"}));
```

- [ ] **Step 2: Run RED, then implement only the serializer**

Expected RED: `HardwareJson` is missing. Expected GREEN: exact key list and values pass.

- [ ] **Step 3: Implement the non-blocking diagnostic window**

Use `QtConcurrent::run` plus `QFutureWatcher<HardwareIdentity>`. The UI contains read-only fields for all documented signals, per-field status, and `Refresh`, `Copy HWID`, `Export JSON`, and `TPM Test` buttons. Export uses `QSaveFile`; the TPM test signs 32 bytes from `QRandomGenerator::system()` and runs the valid/modified challenge/modified signature checks.

- [ ] **Step 4: Build and manually launch the tool**

```powershell
& 'C:\Qt\Tools\CMake_64\bin\cmake.exe' --build build --target HwidObtainer
& '.\build\hwid-obtainer\HwidObtainer.exe'
```

Verify the UI remains responsive, signals are visible, copy/export work, and the TPM test reports all checks.

- [ ] **Step 5: Commit**

```powershell
git add shared hwid-obtainer
git commit -m "feat: add standalone HWID diagnostic tool"
```

---

### Task 6: Bootstrap the Go Service, Security Primitives, and Admin Commands

**Files:**
- Create: `backend/go.mod`
- Create: `backend/cmd/server/main.go`
- Create: `backend/internal/config/config.go`
- Create: `backend/internal/config/config_test.go`
- Create: `backend/internal/security/password.go`
- Create: `backend/internal/security/password_test.go`
- Create: `backend/internal/security/hmac.go`
- Create: `backend/internal/security/hmac_test.go`
- Create: `backend/internal/security/license.go`
- Create: `backend/internal/security/license_test.go`
- Create: `backend/internal/admin/commands.go`
- Create: `deploy/compose.yaml`
- Create: `.env.example`

**Interfaces:**
- Produces: `config.Load() (Config, error)` requiring database URL, license HMAC key, hardware HMAC key, Ed25519 key, issuer, audience, and product.
- Produces: `security.HashPassword(string) (string, error)` and `VerifyPassword(encoded, password string) (bool, error)`.
- Produces: `security.HMACHex(secret []byte, normalized string) string`.
- Produces: `security.NormalizeLicense(string) string` and `GenerateLicense(io.Reader) (plain, normalized string, err error)`.

- [ ] **Step 1: Write failing table-driven security tests**

```go
func TestNormalizeLicense(t *testing.T) {
    if got := NormalizeLicense(" abcd-ef12 "); got != "ABCDEF12" { t.Fatalf("got %q", got) }
}

func TestPasswordRoundTrip(t *testing.T) {
    encoded, err := HashPassword("correct horse battery staple")
    if err != nil { t.Fatal(err) }
    ok, err := VerifyPassword(encoded, "correct horse battery staple")
    if err != nil || !ok { t.Fatalf("ok=%v err=%v", ok, err) }
}
```

- [ ] **Step 2: Run tests in the official Go container and verify RED**

```powershell
docker run --rm -v "${PWD}:/src" -w /src/backend golang:1.24 go test ./internal/security ./internal/config
```

Expected: missing package/functions.

- [ ] **Step 3: Implement minimal primitives and strict configuration**

Use Argon2id parameters `memory=64*1024 KiB`, `iterations=3`, `parallelism=2`, `saltLength=16`, `keyLength=32`; encode all parameters with the hash. Compare derived hashes with `subtle.ConstantTimeCompare`. License generation reads 16 random bytes and formats uppercase groups of eight hex characters.

- [ ] **Step 4: Add admin command parsing with injected service interfaces**

`create-user --email <email>` reads the password twice from a terminal without echo. `create-license --user <email> --product <product> --days <positive integer> --max-devices <positive integer>` prints the plaintext license exactly once after repository success. Unit tests inject fake repositories and a deterministic random reader.

- [ ] **Step 5: Run all Go tests and commit**

```powershell
docker run --rm -v "${PWD}:/src" -w /src/backend golang:1.24 go test ./...
git add backend deploy .env.example
git commit -m "feat: bootstrap secure Go license service"
```

---

### Task 7: Create PostgreSQL Migrations and Repositories

**Files:**
- Create: `backend/migrations/000001_initial.up.sql`
- Create: `backend/migrations/000001_initial.down.sql`
- Create: `backend/internal/domain/models.go`
- Create: `backend/internal/domain/errors.go`
- Create: `backend/internal/store/postgres.go`
- Create: `backend/internal/store/migrations.go`
- Create: `backend/internal/store/users.go`
- Create: `backend/internal/store/licenses.go`
- Create: `backend/internal/store/auth_sessions.go`
- Create: `backend/internal/store/devices.go`
- Create: `backend/tests/integration/store_test.go`

**Interfaces:**
- Produces: repository methods `CreateUser`, `FindUserByEmail`, `CreateLicense`, `FindLicenseByHMAC`, `CreatePendingSession`, and `WithLockedChallenge`.
- Produces: transaction callback `WithLockedChallenge(ctx, sessionID, fn) error` using `SELECT ... FOR UPDATE`.

- [ ] **Step 1: Start PostgreSQL and write a failing migration/repository test**

```powershell
docker compose -f deploy/compose.yaml up -d --wait
docker run --rm --network host -v "${PWD}:/src" -w /src/backend -e TEST_DATABASE_URL="postgres://starloader:starloader@host.docker.internal:5432/starloader_test?sslmode=disable" golang:1.24 go test ./tests/integration -run TestUserAndLicenseRoundTrip -v
```

The test resets the public schema, runs embedded migrations, creates a user/license, and reads them back. Expected RED: migrations/repository are missing.

- [ ] **Step 2: Implement schema constraints and indexes**

Use `gen_random_uuid()`, constrained user/license/device/session status columns, unique normalized email and license HMAC, positive `max_devices`, foreign keys, and indexes on license/device/session lookup fields. Store challenge SHA-256 only.

- [ ] **Step 3: Implement pgx repositories with explicit row mapping**

No repository method accepts plaintext passwords, license keys, or raw hardware serials. Convert `pgx.ErrNoRows` into typed domain not-found errors. Roll back every failed transaction path.

- [ ] **Step 4: Verify migration down/up and repository concurrency**

Add a test with two transactions attempting to consume the same challenge; assert exactly one succeeds.

- [ ] **Step 5: Run integration tests and commit**

```powershell
docker run --rm --network host -v "${PWD}:/src" -w /src/backend -e TEST_DATABASE_URL="postgres://starloader:starloader@host.docker.internal:5432/starloader_test?sslmode=disable" golang:1.24 go test ./tests/integration -v
git add backend/migrations backend/internal/domain backend/internal/store backend/tests/integration
git commit -m "feat: add PostgreSQL license repositories"
```

---

### Task 8: Implement Login, Request IDs, JSON Validation, and Rate Limits

**Files:**
- Create: `backend/internal/service/login.go`
- Create: `backend/internal/service/login_test.go`
- Create: `backend/internal/httpapi/router.go`
- Create: `backend/internal/httpapi/respond.go`
- Create: `backend/internal/httpapi/middleware.go`
- Create: `backend/internal/httpapi/login.go`
- Create: `backend/internal/httpapi/login_test.go`
- Modify: `backend/cmd/server/main.go`

**Interfaces:**
- Produces: `LoginService.Login(ctx, LoginInput) (PendingChallenge, error)`.
- Produces: `POST /v1/auth/login` and `GET /healthz`.
- Produces: every response with `X-Request-ID`; error JSON includes the same `request_id`.

- [ ] **Step 1: Write failing service tests for every login policy branch**

Test valid login, wrong password, inactive user, unknown/expired/revoked license, user/license mismatch, wrong product, and random-source failure. Assert all credential-related failures exposed to HTTP map to `INVALID_CREDENTIALS` or the documented license code without leaking database facts.

- [ ] **Step 2: Write failing handler contract tests**

```go
func TestLoginRejectsUnknownJSONField(t *testing.T) {
    req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{"email":"a@b.c","password":"x","license_key":"K","device_fingerprint":"F","extra":true}`))
    rr := httptest.NewRecorder()
    router.ServeHTTP(rr, req)
    if rr.Code != http.StatusBadRequest { t.Fatalf("status=%d", rr.Code) }
}
```

- [ ] **Step 3: Implement login and HTTP middleware**

Limit bodies to 64 KiB, reject unknown/multiple JSON values, normalize email/license, generate a 32-byte challenge, store only SHA-256, and return base64 challenge plus RFC3339 expiry. Request IDs use UUIDv7 where available. Panic recovery logs request ID only and returns `SERVER_ERROR`.

- [ ] **Step 4: Implement in-memory bounded rate limiting**

Apply 5 attempts/minute/IP to login. Periodically evict expired buckets so attacker-controlled keys cannot grow memory without bound. Honor direct `RemoteAddr`; accept proxy headers only when explicitly configured with trusted proxies.

- [ ] **Step 5: Run tests and commit**

```powershell
docker run --rm -v "${PWD}:/src" -w /src/backend golang:1.24 go test ./internal/service ./internal/httpapi
git add backend
git commit -m "feat: add login challenge API"
```

---

### Task 9: Implement Device Verification, Scoring, Activation, and Signed Tokens

**Files:**
- Create: `backend/internal/domain/device_score.go`
- Create: `backend/internal/domain/device_score_test.go`
- Create: `backend/internal/security/device_signature.go`
- Create: `backend/internal/security/device_signature_test.go`
- Create: `backend/internal/security/token.go`
- Create: `backend/internal/security/token_test.go`
- Create: `backend/internal/service/device_verify.go`
- Create: `backend/internal/service/device_verify_test.go`
- Create: `backend/internal/httpapi/device_verify.go`
- Create: `backend/internal/httpapi/device_verify_test.go`
- Modify: `backend/internal/httpapi/router.go`
- Modify: `backend/tests/integration/store_test.go`

**Interfaces:**
- Produces: `domain.ScoreDevice(stored, presented DeviceSignals) int`.
- Produces: `security.VerifyCNGP256(publicBlob, challenge, signature []byte) error`.
- Produces: `TokenIssuer.Issue(SessionClaims) (string, error)` and `TokenVerifier.Verify(string) (SessionClaims, error)`.
- Produces: `DeviceService.Verify(ctx, VerifyInput) (VerifiedSession, error)`.
- Produces: `POST /v1/device/verify`.

- [ ] **Step 1: Write failing device score boundary tests**

```go
func TestScoreThresholdRequiresSeventy(t *testing.T) {
    got := ScoreDevice(DeviceSignals{TPM:"t", SMBIOS:"s"}, DeviceSignals{TPM:"t", SMBIOS:"s"})
    if got != 70 { t.Fatalf("score=%d", got) }
}
```

Also test TPM-only=50, all fields=100, and empty values never matching each other.

- [ ] **Step 2: Write failing CNG ECDSA and Ed25519 token tests**

Construct a CNG `BCRYPT_ECCPUBLIC_BLOB` fixture from a generated P-256 key, verify the raw `r||s` signature over SHA-256(challenge), and reject wrong challenge/signature/blob magic. Token tests assert issuer, audience, product, license, device, and expiration validation.

- [ ] **Step 3: Implement transaction-safe device verification**

Decode bounded base64 fields; lock pending session/challenge; reject expired or consumed challenges; verify the challenge hash and ECDSA proof; HMAC each normalized hardware field; match active devices by score; enforce `max_devices`; create/update the device; mark challenge consumed; mark session verified; commit; then issue the one-hour token. A failed signature never consumes the challenge; a successful proof consumes it exactly once.

- [ ] **Step 4: Add integration tests for the acceptance matrix**

Cover first activation, repeat login, score 69 rejection/new-device limit, score 70 acceptance, invalid signature, expiry, replay, revoked device, and concurrent verification. Assert no raw hardware values occur in database columns or captured logs.

- [ ] **Step 5: Run all Go tests and commit**

```powershell
docker run --rm --network host -v "${PWD}:/src" -w /src/backend -e TEST_DATABASE_URL="postgres://starloader:starloader@host.docker.internal:5432/starloader_test?sslmode=disable" golang:1.24 go test ./...
git add backend
git commit -m "feat: verify TPM devices and issue sessions"
```

---

### Task 10: Integrate the Qt Login Client with the Go API

**Files:**
- Create: `license-client/src/api/ApiClient.h`
- Create: `license-client/src/api/ApiClient.cpp`
- Create: `license-client/src/auth/AuthState.h`
- Create: `license-client/src/auth/AuthManager.h`
- Create: `license-client/src/auth/AuthManager.cpp`
- Create: `license-client/src/security/SessionTokenVerifier.h`
- Create: `license-client/src/security/SessionTokenVerifier.cpp`
- Create: `license-client/tests/ApiClientTest.cpp`
- Create: `license-client/tests/AuthManagerTest.cpp`
- Create: `license-client/tests/SessionTokenVerifierTest.cpp`
- Modify: `license-client/src/ui/LoginWindow.h`
- Modify: `license-client/src/ui/LoginWindow.cpp`
- Modify: `license-client/ui/LoginWindow.ui`
- Modify: `license-client/CMakeLists.txt`

**Interfaces:**
- Produces: `ApiClient::login(LoginRequest)` and `ApiClient::verifyDevice(DeviceVerifyRequest)` with typed result signals.
- Produces: `AuthManager::login(email, password, licenseKey)` and states `LoggedOut`, `CollectingDevice`, `Authenticating`, `WaitingForDeviceChallenge`, `VerifyingDevice`, `Authenticated`, `Failed`.
- Produces: `SessionTokenVerifier::verify(token, expectedDevice, expectedLicense) -> VerificationResult`.

- [ ] **Step 1: Write failing HTTP contract tests with a local fake server**

Use `QTcpServer` to capture requests. Assert exact endpoint, `Content-Type`, `X-Request-ID`, JSON keys, 15-second timeout, HTTP status handling, malformed JSON handling, and structured error parsing. Assert logs/signals never expose password or license.

- [ ] **Step 2: Run RED and implement `ApiClient`**

Use one `QNetworkAccessManager`, asynchronous replies, bounded response parsing, HTTPS-only guard unless `STARLOADER_ALLOW_HTTP_LOCAL=1` and host is loopback, and typed `ApiError { code, message, requestId }`.

- [ ] **Step 3: Write failing auth state tests**

Inject `IHardwareCollector`, `IDeviceSigner`, and `IApiClient`. Assert the exact happy-path state sequence and failure at TPM absence, login failure, invalid challenge base64, signing failure, device rejection, and invalid token. Production code never transitions to `Authenticated` before token verification.

- [ ] **Step 4: Implement AuthManager and token verification**

Decode the server's Ed25519 public key at startup, verify signature and all required claims, and compare expected product/device/license. Keep the token only in memory in this first version.

- [ ] **Step 5: Update the login UI**

Replace username with email, add license key, masked device display ID, status text, and retry behavior. Disable all form inputs during asynchronous work. Map structured codes to safe Turkish messages and display request ID separately for support.

- [ ] **Step 6: Build, run tests, and commit**

```powershell
& 'C:\Qt\Tools\CMake_64\bin\cmake.exe' --build build
& 'C:\Qt\Tools\CMake_64\bin\ctest.exe' --test-dir build --output-on-failure
git add license-client
git commit -m "feat: integrate Qt TPM login flow"
```

---

### Task 11: Publish the Contract, Operator Workflow, and End-to-End Verification

**Files:**
- Create: `server-contract/API.md`
- Create: `README.md`
- Create: `scripts/test-all.ps1`
- Modify: `.env.example`
- Modify: `deploy/compose.yaml`
- Modify: `backend/cmd/server/main.go`

**Interfaces:**
- Produces: one documented setup path for database, migrations, admin user/license creation, server start, Qt build, and real-TPM login.
- Produces: `scripts/test-all.ps1` returning nonzero if any Go, C++, or integration test fails.

- [ ] **Step 1: Write a failing black-box API smoke test**

Start PostgreSQL and the server in a disposable configuration, call `/healthz`, create user/license through admin commands, perform login, sign the returned challenge with an ephemeral test P-256 key encoded as CNG blob, verify the device, verify the returned Ed25519 token, then replay the challenge and assert `CHALLENGE_CONSUMED`.

- [ ] **Step 2: Run the smoke test and verify RED**

Expected: the orchestration script/API contract is not yet complete.

- [ ] **Step 3: Complete operator documentation and safe examples**

Document key generation, environment variables, Docker lifecycle, migration/admin commands, API examples with fake values, Qt build commands using the discovered Qt 6.11.1 paths, production HTTPS requirement, TPM prerequisite, and reset implications. Do not put functional secrets in `.env.example`.

- [ ] **Step 4: Run the complete automated verification**

```powershell
.\scripts\test-all.ps1
git diff --check
git status --short
```

Expected: all Go unit/integration tests and C++ tests pass, both GUI executables build, no whitespace errors exist, and only intended files are changed.

- [ ] **Step 5: Run the real Windows acceptance test**

Create a user and license, launch the backend and `LicenseClient`, authenticate with the current machine's TPM, verify the database contains one active device, log in again without increasing activation count, then confirm `HwidObtainer` reports valid challenge, modified-challenge rejection, and modified-signature rejection.

- [ ] **Step 6: Commit documentation and verification tooling**

```powershell
git add README.md .env.example deploy server-contract scripts backend/cmd/server/main.go
git commit -m "docs: add secure setup and verification workflow"
```

---

## Plan Self-Review

- Every design requirement maps to a task: shared hardware identity (Tasks 2-4), separate Qt tools (Tasks 1, 5, 10), Go/PostgreSQL and admin commands (Tasks 6-9), security and API contract (Tasks 8-10), and end-to-end verification (Task 11).
- All cross-task interfaces use the same names and data direction.
- Production TPM failure remains fail-closed; the ephemeral key in Task 11 is test-only and never compiled into production clients.
- Redis, refresh tokens, offline grace, certificate pinning, and admin web UI remain out of scope.
- The host currently has Qt 6.11.1, CMake, Ninja, and MinGW under `C:\Qt`; Go is not on `PATH`, so Go build/test commands use the official Go Docker image.

# E-posta/Parola Girişi, Tema ve HWID Diyaloğu Uygulama Planı

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** License Client girişini e-posta/parola ile sınırlandırmak, backend'in kullanıcıya ait tek ürün lisansını seçmesini sağlamak, temayı güvenilir biçimde yüklemek ve giriş ekranından aynı hash'lenmiş HWID'yi gösteren diyaloğu açmak.

**Architecture:** Login API lisans anahtarını istemciden almayacak; Go servisi authenticated kullanıcı ve configured product üzerinden unique lisansı bulacak. Mevcut TPM challenge ve otomatik cihaz oluşturma akışı korunacak. Qt tarafında statik resource açıkça başlatılacak, `AuthManager` lisanssız sözleşmeye geçirilecek ve `HwidDialog` login ile aynı `IHardwareCollector` üzerinden final fingerprint'i asenkron gösterecek.

**Tech Stack:** C++20, Qt 6 Widgets/Concurrent/Test, CMake/Ninja, Go, PostgreSQL, pgx, versioned SQL migrations.

**Spec:** `docs/superpowers/specs/2026-08-12-email-password-login-theme-hwid-design.md`

## Global Constraints

- Login ekranında görünür giriş alanları yalnızca e-posta ve paroladır.
- Bir kullanıcı bir ürün için yalnızca bir lisansa sahip olabilir; `(user_id, product)` veritabanında unique olmalıdır.
- Login request içinde `license_key` bulunmaz ve eski alan unknown JSON field olarak reddedilir.
- `/v1/device/verify` cihaz eşleştirme, ilk cihaz oluşturma, limit ve revoke davranışları değiştirilmez.
- HWID diyaloğu yalnızca login sırasında kullanılan `HardwareIdentity::finalFingerprint` değerini gösterir; ham donanım alanlarını göstermez.
- Tema global QSS olarak uygulanır; UI dosyalarına yeni büyük inline stylesheet eklenmez.
- Parola, açık lisans anahtarı, token, TPM private key ve ham donanım değerleri loglanmaz.
- Her üretim değişikliği test önce kırmızı, sonra yeşil olacak biçimde yapılır.

---

### Task 1: Statik tema kaynağını güvenilir biçimde başlat

**Files:**
- Modify: `shared/theme/ThemeManager.cpp`
- Create: `shared/tests/ThemeManagerTest.cpp`
- Modify: `shared/tests/CMakeLists.txt`

**Interfaces:**
- Consumes: `:/theme/AdwaitaDark.qss` resource path.
- Produces: `ThemeManager::themeStyleSheet() -> QString` her executable içinde boş olmayan QSS; `ThemeManager::applyTheme()` global `QApplication` stylesheet'ini ayarlar.

- [ ] **Step 1: Resource ve apply davranışı için başarısız Qt testi yaz**

```cpp
#include "theme/ThemeManager.h"

#include <QApplication>
#include <QtTest>

class ThemeManagerTest final : public QObject
{
    Q_OBJECT
private slots:
    void loadsEmbeddedAdwaitaTheme();
    void appliesThemeToApplication();
};

void ThemeManagerTest::loadsEmbeddedAdwaitaTheme()
{
    const QString theme = ThemeManager::themeStyleSheet();
    QVERIFY(!theme.isEmpty());
    QVERIFY(theme.contains(QStringLiteral("QFrame#loginCard")));
    QVERIFY(theme.contains(QStringLiteral("QLabel#hwidLink")));
}

void ThemeManagerTest::appliesThemeToApplication()
{
    qApp->setStyleSheet(QString());
    ThemeManager::applyTheme();
    QCOMPARE(qApp->styleSheet(), ThemeManager::themeStyleSheet());
}

QTEST_MAIN(ThemeManagerTest)
#include "ThemeManagerTest.moc"
```

`shared/tests/CMakeLists.txt` içine `ThemeManagerTest` executable'ı, `DeviceIdentityShared`, `Qt6::Widgets` ve `Qt6::Test` linkleri, `add_test` ve Qt DLL PATH ayarı eklenir.

- [ ] **Step 2: Testin resource link edilmediği için kırmızı olduğunu doğrula**

Run:

```powershell
& 'C:\Qt\Tools\CMake_64\bin\cmake.exe' --build build --target ThemeManagerTest
& 'C:\Qt\Tools\CMake_64\bin\ctest.exe' --test-dir build -R '^ThemeManagerTest$' --output-on-failure
```

Expected: `loadsEmbeddedAdwaitaTheme` boş stylesheet nedeniyle FAIL.

- [ ] **Step 3: Resource'u açıkça başlat ve yükleme hatasını görünür yap**

`shared/theme/ThemeManager.cpp` içinde global scope'ta tek-seferlik initializer kullan:

```cpp
#include <QDebug>

static void initializeThemeResources()
{
    static const bool initialized = [] {
        Q_INIT_RESOURCE(theme);
        return true;
    }();
    Q_UNUSED(initialized);
}

QString ThemeManager::themeStyleSheet()
{
    initializeThemeResources();
    QFile file(QStringLiteral(":/theme/AdwaitaDark.qss"));
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qWarning() << "StarLoader theme resource could not be opened";
        return {};
    }
    return QString::fromUtf8(file.readAll());
}
```

`applyTheme()` QSS'i bir kez almalı, boşsa uygulamamalı, doluysa `app->setStyleSheet(theme)` çağırmalıdır.

- [ ] **Step 4: Tema testini ve mevcut CTest paketini yeşil doğrula**

```powershell
& 'C:\Qt\Tools\CMake_64\bin\cmake.exe' --build build --target ThemeManagerTest
& 'C:\Qt\Tools\CMake_64\bin\ctest.exe' --test-dir build -R '^ThemeManagerTest$' --output-on-failure
& 'C:\Qt\Tools\CMake_64\bin\ctest.exe' --test-dir build --output-on-failure
```

Expected: Tema testi PASS; mevcut Qt testlerinde regression yok.

- [ ] **Step 5: Tema düzeltmesini commit et**

```powershell
git add shared/theme/ThemeManager.cpp shared/tests/ThemeManagerTest.cpp shared/tests/CMakeLists.txt
git commit -m "fix: initialize embedded Qt theme resource"
```

---

### Task 2: Kullanıcı+ürün başına tek lisansı migration ve store katmanında uygula

**Files:**
- Create: `backend/migrations/000002_single_license_per_product.up.sql`
- Create: `backend/migrations/000002_single_license_per_product.down.sql`
- Modify: `backend/internal/store/migrations.go`
- Modify: `backend/internal/store/licenses.go`
- Modify: `backend/internal/domain/errors.go`
- Modify: `backend/tests/integration/store_test.go`

**Interfaces:**
- Produces: `Store.FindLicenseByUserAndProduct(ctx context.Context, userID, product string) (*domain.License, error)`.
- Produces: `domain.ErrLicenseAlreadyExists` duplicate kullanıcı+ürün lisansını temsil eder.
- Preserves: `Store.FindLicenseByHMAC` admin/recovery uyumluluğu için kalır; login artık kullanmaz.

- [ ] **Step 1: Store lookup, unique constraint ve migration ledger için başarısız integration testleri yaz**

`TestUserAndLicenseRoundTrip` lookup doğrulamasını kullanıcı+ürüne çevir:

```go
foundLicense, err := repository.FindLicenseByUserAndProduct(ctx, createdUser.ID, "StarLoader")
if err != nil {
    t.Fatalf("FindLicenseByUserAndProduct() error = %v", err)
}
if foundLicense.ID != createdLicense.ID {
    t.Fatalf("license ID = %q, want %q", foundLicense.ID, createdLicense.ID)
}
```

Aynı kullanıcı ve ürün için ikinci lisansı oluşturmayı deneyen test `errors.Is(err, domain.ErrLicenseAlreadyExists)` beklemeli. Migration idempotency testinde `schema_migrations` tablosunda version 1 ve 2 için toplam iki satır beklenmeli. Ayrı bir test, version 1 uygulanmış bir şemaya version 2'nin eklenebildiğini doğrulamalı.

- [ ] **Step 2: Integration testlerini çalıştır ve yeni API/migration olmadığı için kırmızı doğrula**

```powershell
Set-Location backend
go test ./tests/integration -run 'TestUserAndLicenseRoundTrip|TestSingleLicensePerUserProduct|TestMigration' -count=1
Set-Location ..
```

Expected: `FindLicenseByUserAndProduct`, version 2 migration veya duplicate error eksikliği nedeniyle FAIL/compile failure.

- [ ] **Step 3: Version 2 SQL migration'larını ekle**

`000002_single_license_per_product.up.sql`:

```sql
alter table licenses
    add constraint licenses_user_product_unique unique (user_id, product);
```

`000002_single_license_per_product.down.sql`:

```sql
alter table licenses
    drop constraint if exists licenses_user_product_unique;
```

Constraint mevcut duplicate veriyi otomatik seçmeden migration'ı reddetmelidir.

- [ ] **Step 4: Migration runner'ı sıralı migration listesine geçir**

`backend/internal/store/migrations.go` içinde:

```go
type migration struct {
    version int64
    up      string
    down    string
}

var versionedMigrations = []migration{
    {version: 1, up: "000001_initial.up.sql", down: "000001_initial.down.sql"},
    {version: 2, up: "000002_single_license_per_product.up.sql", down: "000002_single_license_per_product.down.sql"},
}
```

`MigrateUp` listeyi artan sırayla, `MigrateDown` azalan sırayla `executeVersionedMigration` üzerinden çalıştırmalı. Her version kendi ledger satırını idempotent biçimde yönetmeye devam etmelidir.

- [ ] **Step 5: Typed duplicate error ve kullanıcı+ürün lookup'ını uygula**

`backend/internal/domain/errors.go` içine:

```go
var ErrLicenseAlreadyExists = errors.New("license already exists for user and product")
```

Gerekli `errors` import'unu ekle. `CreateLicense`, `*pgconn.PgError` içindeki `ConstraintName == "licenses_user_product_unique"` durumunu bu domain error'a çevirmeli. `licenses.go` lookup:

```go
func (s *Store) FindLicenseByUserAndProduct(ctx context.Context, userID, product string) (*domain.License, error) {
    license, err := scanLicense(s.db.QueryRow(ctx,
        `select `+licenseColumns+` from licenses where user_id = $1 and product = $2`,
        userID, product))
    if errors.Is(err, pgx.ErrNoRows) {
        return nil, domain.ErrLicenseNotFound
    }
    if err != nil {
        return nil, fmt.Errorf("find license by user and product: %w", err)
    }
    return license, nil
}
```

- [ ] **Step 6: Store ve migration testlerini yeşil doğrula**

```powershell
Set-Location backend
gofmt -w internal/domain/errors.go internal/store/licenses.go internal/store/migrations.go tests/integration/store_test.go
go test ./tests/integration -run 'TestUserAndLicenseRoundTrip|TestSingleLicensePerUserProduct|TestMigration' -count=1
Set-Location ..
```

Expected: İlgili integration testleri PASS.

- [ ] **Step 7: Tek-lisans persistence değişikliğini commit et**

```powershell
git add backend/migrations backend/internal/domain/errors.go backend/internal/store/migrations.go backend/internal/store/licenses.go backend/tests/integration/store_test.go
git commit -m "feat: enforce one product license per user"
```

---

### Task 3: Backend login sözleşmesinden lisans anahtarını kaldır

**Files:**
- Modify: `backend/internal/httpapi/login.go`
- Modify: `backend/internal/httpapi/login_test.go`
- Modify: `backend/internal/service/login.go`
- Modify: `backend/internal/service/login_test.go`
- Modify: `backend/cmd/server/main.go`
- Modify: `backend/cmd/server/main_test.go`
- Modify: `backend/tests/blackbox/smoke_test.go`
- Modify: `backend/internal/admin/commands_test.go`
- Modify: `server-contract/API.md`

**Interfaces:**
- Produces: `service.LoginInput{Email, Password, DeviceFingerprint}`.
- Produces: `NewLoginService(repository LoginRepository, product string) *LoginService`.
- Consumes: `LoginRepository.FindLicenseByUserAndProduct(context.Context, userID, product string)` from Task 2.
- HTTP request keys are exactly `email`, `password`, `device_fingerprint`.

- [ ] **Step 1: HTTP contract testlerini lisanssız request için kırmızıya çevir**

`validLoginJSON`:

```go
const validLoginJSON = `{"email":"a@b.c","password":"x","device_fingerprint":"F"}`
```

Başarılı test `login.input` içinde email/password/fingerprint beklemeli. Yeni test eski alanı reddetmeli:

```go
func TestLoginRejectsLegacyLicenseKeyField(t *testing.T) {
    router := NewRouter(RouterConfig{Login: &fakeLoginService{}})
    req := loginRequest(`{"email":"a@b.c","password":"x","device_fingerprint":"F","license_key":"K"}`)
    rr := httptest.NewRecorder()
    router.ServeHTTP(rr, req)
    assertErrorResponse(t, rr, http.StatusBadRequest, "INVALID_REQUEST")
}
```

Required-field tablosundan lisans boşluğu senaryosunu kaldır; email, password ve fingerprint boşluklarını koru.

- [ ] **Step 2: Service testlerini kullanıcı+ürün lookup için kırmızıya çevir**

`fakeLoginRepository` alanları `foundLicenseUserID` ve `foundLicenseProduct` olmalı. Repository metodu:

```go
func (repository *fakeLoginRepository) FindLicenseByUserAndProduct(_ context.Context, userID, product string) (*domain.License, error) {
    repository.foundLicenseUserID = userID
    repository.foundLicenseProduct = product
    return repository.license, repository.licenseErr
}
```

Başarılı test lookup değerlerinin `user-1` ve `StarLoader` olduğunu doğrulamalı. `validLoginInput()` artık license key taşımamalı.

- [ ] **Step 3: Backend birim testlerini çalıştır ve eski contract nedeniyle kırmızı doğrula**

```powershell
Set-Location backend
go test ./internal/httpapi ./internal/service ./cmd/server -count=1
Set-Location ..
```

Expected: Eski `LicenseKey`, `FindLicenseByHMAC` ve constructor imzaları nedeniyle FAIL/compile failure.

- [ ] **Step 4: HTTP taşıma ve login servisini yeni sözleşmeye geçir**

`loginRequestBody`:

```go
type loginRequestBody struct {
    Email             string `json:"email"`
    Password          string `json:"password"`
    DeviceFingerprint string `json:"device_fingerprint"`
}
```

Validation yalnızca bu üç alanı zorunlu tutmalı. `service.LoginInput` lisans anahtarını kaldırmalı. `LoginRepository` ve servis constructor'ı:

```go
type LoginRepository interface {
    FindUserByEmail(context.Context, string) (*domain.User, error)
    FindLicenseByUserAndProduct(context.Context, string, string) (*domain.License, error)
    CreatePendingSession(context.Context, domain.NewPendingSession) (*domain.PendingSession, error)
}

func NewLoginService(repository LoginRepository, product string) *LoginService
```

Parola doğrulandıktan sonra:

```go
license, err := service.repository.FindLicenseByUserAndProduct(ctx, user.ID, service.product)
```

Mevcut lisans status/expiry/user/product savunma kontrolleri ve hata eşlemeleri korunmalı. `licenseHMACKey` state'i ve login servisindeki `security.NormalizeLicense/HMACHex` kullanımı kaldırılmalı.

- [ ] **Step 5: Server wiring, cancellation ve blackbox request'lerini güncelle**

`backend/cmd/server/main.go`:

```go
loginService := service.NewLoginService(repository, configuration.Product)
```

`main_test.go` cancellation request'i ve blackbox smoke login body üç alanı kullanmalı. Smoke ortamı lisans provisioning için lisans bilgisini kullanabilir, ancak login payload'ına eklememelidir.

Admin duplicate testinde repository `domain.ErrLicenseAlreadyExists` döndürdüğünde plaintext lisansın stdout'a yazılmadığı ve hata metninin `license already exists for user and product` içerdiği doğrulanmalı.

- [ ] **Step 6: API dokümanını yeni exact JSON sözleşmesine geçir**

`server-contract/API.md` login örneğinden `license_key` satırını kaldır. Metin, lisansın doğrulanmış kullanıcı ve configured product üzerinden bulunduğunu, kullanıcı+ürün başına tek lisans olduğunu belirtmeli. Hata kodları değişmeden kalmalı.

- [ ] **Step 7: Backend testlerini yeşil doğrula**

```powershell
Set-Location backend
gofmt -w internal/httpapi/login.go internal/httpapi/login_test.go internal/service/login.go internal/service/login_test.go cmd/server/main.go cmd/server/main_test.go tests/blackbox/smoke_test.go internal/admin/commands_test.go
go test ./internal/httpapi ./internal/service ./internal/admin ./cmd/server -count=1
go test ./... -count=1
Set-Location ..
```

Expected: Go birim paketleri ve erişilebilir integration/blackbox dışı paketler PASS; test ortam değişkeni isteyen paketler açık skip raporlar.

- [ ] **Step 8: Backend login sözleşmesini commit et**

```powershell
git add backend/internal/httpapi backend/internal/service backend/internal/admin/commands_test.go backend/cmd/server backend/tests/blackbox/smoke_test.go server-contract/API.md
git commit -m "feat: resolve user license during login"
```

---

### Task 4: Qt API ve AuthManager'ı e-posta/parola sözleşmesine geçir

**Files:**
- Modify: `license-client/src/api/ApiClient.h`
- Modify: `license-client/src/api/ApiClient.cpp`
- Modify: `license-client/tests/ApiClientTest.cpp`
- Modify: `license-client/src/auth/AuthManager.h`
- Modify: `license-client/src/auth/AuthManager.cpp`
- Modify: `license-client/tests/AuthManagerTest.cpp`

**Interfaces:**
- Produces: `LoginRequest { QString email; QString password; QString deviceFingerprint; }`.
- Produces: `AuthManager::login(const QString &email, const QString &password)`.
- Preserves: fingerprint collection before network, TPM challenge signing and verified token flow.

- [ ] **Step 1: ApiClient exact-body testini lisanssız sözleşme için kırmızı yaz**

Test çağrısı:

```cpp
client.login({QStringLiteral("person@example.com"),
              QStringLiteral("secret-password"),
              QStringLiteral("fingerprint")});
```

Request assertion'ları:

```cpp
QVERIFY(request.contains("\"email\":\"person@example.com\""));
QVERIFY(request.contains("\"password\":\"secret-password\""));
QVERIFY(request.contains("\"device_fingerprint\":\"fingerprint\""));
QVERIFY(!request.contains("license_key"));
```

Diğer test fixture initializer'larından lisans argümanını kaldır.

- [ ] **Step 2: AuthManager testlerini iki-parametre login için kırmızıya çevir**

Tüm çağrıları `manager.login(email, password)` yap. Başarılı akışta:

```cpp
QCOMPARE(api.lastLogin.email, QStringLiteral("person@example.com"));
QCOMPARE(api.lastLogin.deviceFingerprint, QStringLiteral("ABCDEF1234567890"));
```

Busy-state ve retry testlerinin davranışı aynı kalmalı.

- [ ] **Step 3: C++ hedeflerini çalıştır ve eski imzalar nedeniyle kırmızı doğrula**

```powershell
& 'C:\Qt\Tools\CMake_64\bin\cmake.exe' --build build --target ApiClientTest AuthManagerTest
& 'C:\Qt\Tools\CMake_64\bin\ctest.exe' --test-dir build -R '^(ApiClientTest|AuthManagerTest)$' --output-on-failure
```

Expected: Struct initializer ve `AuthManager::login` imza uyuşmazlıkları nedeniyle compile failure.

- [ ] **Step 4: ApiClient JSON modelini sadeleştir**

`ApiClient.h`:

```cpp
struct LoginRequest
{
    QString email;
    QString password;
    QString deviceFingerprint;
};
```

`ApiClient.cpp` login body:

```cpp
postJson(QStringLiteral("/v1/auth/login"), {
    {QStringLiteral("email"), request.email},
    {QStringLiteral("password"), request.password},
    {QStringLiteral("device_fingerprint"), request.deviceFingerprint},
}, false);
```

- [ ] **Step 5: AuthManager pending credential state'inden lisansı kaldır**

`AuthManager.h`:

```cpp
void login(const QString &email, const QString &password);
struct PendingLogin { QString email; QString password; };
```

`completeCollection()` şu request'i üretmeli:

```cpp
apiClient_.login({pendingLogin_.email, pendingLogin_.password, hardware_.finalFingerprint});
pendingLogin_.password.clear();
```

Lisans alanı temizleme satırı ve tüm license parameter kullanımları kaldırılmalı.

- [ ] **Step 6: ApiClient ve AuthManager testlerini yeşil doğrula**

```powershell
& 'C:\Qt\Tools\CMake_64\bin\cmake.exe' --build build --target ApiClientTest AuthManagerTest
& 'C:\Qt\Tools\CMake_64\bin\ctest.exe' --test-dir build -R '^(ApiClientTest|AuthManagerTest)$' --output-on-failure
```

Expected: İki test executable'ı PASS.

- [ ] **Step 7: Qt login contract değişikliğini commit et**

```powershell
git add license-client/src/api license-client/src/auth license-client/tests/ApiClientTest.cpp license-client/tests/AuthManagerTest.cpp
git commit -m "feat: remove license key from Qt login contract"
```

---

### Task 5: HWID diyaloğunu gerçek final fingerprint ile asenkron çalıştır

**Files:**
- Modify: `license-client/src/ui/HwidDialog.h`
- Modify: `license-client/src/ui/HwidDialog.cpp`
- Modify: `license-client/ui/HwidDialog.ui`
- Create: `license-client/tests/HwidDialogTest.cpp`
- Modify: `license-client/CMakeLists.txt`

**Interfaces:**
- Produces: `HwidDialog(IHardwareCollector &hardwareCollector, QWidget *parent = nullptr)`.
- Consumes: `IHardwareCollector::collect(HardwareIdentity *, QString *)`.
- Displays: yalnızca `HardwareIdentity::finalFingerprint`.

- [ ] **Step 1: Başarı, hata ve clipboard davranışı için başarısız Qt testi yaz**

Test içinde fake collector:

```cpp
class FakeHardwareCollector final : public IHardwareCollector
{
public:
    bool succeeds = true;
    HardwareIdentity identity;

    bool collect(HardwareIdentity *output, QString *error) override
    {
        if (!succeeds) {
            *error = QStringLiteral("raw collector detail");
            return false;
        }
        *output = identity;
        return true;
    }
};
```

Başarı testi `finalFingerprint = "ABCDEF0123456789"` verir, `hwidLineEdit` metnini bekler, diğer ham identity alanlarının hiçbirinin dialog text'inde bulunmadığını doğrular ve `copyButton` click sonrası clipboard'ı kontrol eder. Hata testi `copyButton` disabled, güvenli status mesajı görünür ve `raw collector detail` görünmez bekler.

- [ ] **Step 2: HwidDialogTest hedefini CMake'e ekle ve kırmızı doğrula**

Target kaynakları `src/ui/HwidDialog.cpp`, `src/ui/HwidDialog.h`, `ui/HwidDialog.ui`, `tests/HwidDialogTest.cpp` olmalı; `DeviceIdentityShared`, `Qt6::Widgets`, `Qt6::Concurrent`, `Qt6::Test` linklenmeli. Include path `license-client/src`, `AUTOUIC_SEARCH_PATHS` ise `license-client/ui` olmalı.

```powershell
& 'C:\Qt\Tools\CMake_64\bin\cmake.exe' --build build --target HwidDialogTest
& 'C:\Qt\Tools\CMake_64\bin\ctest.exe' --test-dir build -R '^HwidDialogTest$' --output-on-failure
```

Expected: Yeni collector constructor ve async davranış eksikliği nedeniyle FAIL/compile failure.

- [ ] **Step 3: HwidDialog UI başlangıç durumunu düzelt**

`enabled=false` property kaldırılmalı. `hwidLineEdit` read-only kalmalı ve başlangıçta boş olmalı. `copyButton` başlangıçta disabled olmalı. `descriptionLabel` başlangıçta `HWID hesaplanıyor…` göstermeli; object name değişmemeli ki QSS selector'ı çalışsın.

- [ ] **Step 4: Asenkron collector akışını uygula**

`HwidDialog` private result/watch state'i:

```cpp
struct CollectionResult
{
    bool success = false;
    QString fingerprint;
};

IHardwareCollector &hardwareCollector_;
QFutureWatcher<CollectionResult> collectionWatcher_;
void collectionFinished();
```

Constructor watcher `finished` signal'ini bağlamalı ve `QtConcurrent::run` içinde collector'ı çağırmalıdır. Worker raw error'ı UI'a taşımamalı; yalnızca success ve fingerprint dönmelidir. `collectionFinished()` başarıda line edit'i doldurup copy'yi açmalı, başarısızlıkta `HWID hesaplanamadı.` metnini göstermelidir. Destructor `cancel()` ve `waitForFinished()` ile worker'ın dialog/collector yaşam süresini aşmasını engellemelidir.

Mevcut `QSysInfo::machineUniqueId()`, salt ve `QCryptographicHash` tabanlı `createHwidCode()` tamamen kaldırılmalıdır.

- [ ] **Step 5: HWID dialog testini yeşil doğrula**

```powershell
& 'C:\Qt\Tools\CMake_64\bin\cmake.exe' --build build --target HwidDialogTest
& 'C:\Qt\Tools\CMake_64\bin\ctest.exe' --test-dir build -R '^HwidDialogTest$' --output-on-failure
```

Expected: Başarı, hata ve clipboard testleri PASS.

- [ ] **Step 6: HWID dialog değişikliğini commit et**

```powershell
git add license-client/src/ui/HwidDialog.h license-client/src/ui/HwidDialog.cpp license-client/ui/HwidDialog.ui license-client/tests/HwidDialogTest.cpp license-client/CMakeLists.txt
git commit -m "feat: show login fingerprint in HWID dialog"
```

---

### Task 6: Login UI'ı sadeleştir ve HWID bağlantısını bağla

**Files:**
- Modify: `license-client/ui/LoginWindow.ui`
- Modify: `license-client/src/ui/LoginWindow.cpp`
- Modify: `license-client/src/ui/LoginWindow.h`
- Create: `license-client/tests/LoginWindowUiTest.cpp`
- Modify: `license-client/CMakeLists.txt`
- Modify: `shared/theme/AdwaitaDark.qss` yalnızca mevcut `QLabel#hwidLink` selector'ı görsel olarak yetersizse.

**Interfaces:**
- Consumes: `AuthManager::login(email, password)` from Task 4.
- Consumes: `HwidDialog(IHardwareCollector &, QWidget *)` from Task 5.
- Produces: `QLabel#hwidLink` with internal `hwid` link.

- [ ] **Step 1: UI yapısı için başarısız Qt testi yaz**

`LoginWindowUiTest.cpp`, production LoginWindow constructor'ını ve gerçek TPM/network dependency'lerini kullanmadan generated UI'ı kurmalı:

```cpp
#include "ui_LoginWindow.h"

#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QPushButton>
#include <QtTest>

class LoginWindowUiTest final : public QObject
{
    Q_OBJECT
private slots:
    void exposesOnlyEmailAndPasswordInputs();
};

void LoginWindowUiTest::exposesOnlyEmailAndPasswordInputs()
{
    QMainWindow window;
    Ui::LoginWindow ui;
    ui.setupUi(&window);

    QVERIFY(window.findChild<QLineEdit *>(QStringLiteral("emailLineEdit")));
    QVERIFY(window.findChild<QLineEdit *>(QStringLiteral("passwordLineEdit")));
    QVERIFY(!window.findChild<QLineEdit *>(QStringLiteral("licenseKeyLineEdit")));
    QVERIFY(!window.findChild<QLineEdit *>(QStringLiteral("deviceIdLineEdit")));
    QVERIFY(window.findChild<QPushButton *>(QStringLiteral("loginButton")));
    QLabel *hwidLink = window.findChild<QLabel *>(QStringLiteral("hwidLink"));
    QVERIFY(hwidLink);
    QVERIFY(hwidLink->text().contains(QStringLiteral("href=\"hwid\"")));
}

QTEST_MAIN(LoginWindowUiTest)
#include "LoginWindowUiTest.moc"
```

- [ ] **Step 2: LoginWindowUiTest CMake hedefini ekle ve kırmızı doğrula**

Target `ui/LoginWindow.ui` ve test kaynağını içermeli, `Qt6::Widgets`/`Qt6::Test` linklemeli ve `AUTOUIC_SEARCH_PATHS` ayarlamalı.

```powershell
& 'C:\Qt\Tools\CMake_64\bin\cmake.exe' --build build --target LoginWindowUiTest
& 'C:\Qt\Tools\CMake_64\bin\ctest.exe' --test-dir build -R '^LoginWindowUiTest$' --output-on-failure
```

Expected: Eski license/device alanları bulunduğu ve `hwidLink` olmadığı için FAIL.

- [ ] **Step 3: LoginWindow.ui alanlarını ve tab sırasını sadeleştir**

`licenseKeyLineEdit` ve `deviceIdLineEdit` item'larını kaldır. Kartın altına şu davranışı veren QLabel ekle:

```xml
<widget class="QLabel" name="hwidLink">
 <property name="text">
  <string>&lt;a href=&quot;hwid&quot;&gt;HWID'yi görüntüle&lt;/a&gt;</string>
 </property>
 <property name="textFormat"><enum>Qt::TextFormat::RichText</enum></property>
 <property name="textInteractionFlags"><set>Qt::TextInteractionFlag::LinksAccessibleByKeyboard|Qt::TextInteractionFlag::LinksAccessibleByMouse</set></property>
 <property name="openExternalLinks"><bool>false</bool></property>
 <property name="alignment"><set>Qt::AlignmentFlag::AlignCenter</set></property>
</widget>
```

Tabstop listesi email, password, loginButton sırasını korumalı; QLabel link klavye erişimi kendi interaction flags'iyle sağlanmalıdır. Pencere sabit boyutu, tüm öğeler DPI ölçeğinde sınırlar içindeyse korunabilir.

- [ ] **Step 4: LoginWindow event bağlantılarını güncelle**

Constructor:

```cpp
connect(ui->hwidLink, &QLabel::linkActivated,
        this, &LoginWindow::openHwidDialog);
```

`startLogin()`:

```cpp
authManager_->login(ui->emailLineEdit->text(), ui->passwordLineEdit->text());
```

`applyState()` license/device widget erişimlerini kaldırmalı ve busy iken `hwidLink` dahil etkileşimleri kapatmalıdır. `openHwidDialog()` busy state'te geri dönmeli; diğer durumda:

```cpp
HwidDialog dialog(*hardwareCollector_, this);
dialog.exec();
```

Başka bir HWID algoritması veya ayrı `hwid-obtainer` process'i başlatılmamalıdır.

- [ ] **Step 5: UI testi, LicenseClient derlemesi ve ilgili Qt testlerini yeşil doğrula**

```powershell
& 'C:\Qt\Tools\CMake_64\bin\cmake.exe' --build build --target LoginWindowUiTest LicenseClient
& 'C:\Qt\Tools\CMake_64\bin\ctest.exe' --test-dir build -R '^(LoginWindowUiTest|HwidDialogTest|ThemeManagerTest|ApiClientTest|AuthManagerTest)$' --output-on-failure
```

Expected: UI structure ve ilgili testler PASS, LicenseClient linklenir.

- [ ] **Step 6: Login UI değişikliğini commit et**

```powershell
git add license-client/ui/LoginWindow.ui license-client/src/ui/LoginWindow.cpp license-client/src/ui/LoginWindow.h license-client/tests/LoginWindowUiTest.cpp license-client/CMakeLists.txt shared/theme/AdwaitaDark.qss
git commit -m "feat: simplify login form and link HWID dialog"
```

`shared/theme/AdwaitaDark.qss` değişmediyse staging komutundan çıkarılmalıdır.

---

### Task 7: Tam regresyon ve görsel kabul doğrulaması

**Files:**
- Modify only if verification exposes a defect in files already listed above.

**Interfaces:**
- Verifies all spec completion criteria; yeni interface üretmez.

- [ ] **Step 1: Fresh Qt configure/build ve tüm CTest paketini çalıştır**

```powershell
& 'C:\Qt\Tools\CMake_64\bin\cmake.exe' --preset qt-mingw
& 'C:\Qt\Tools\CMake_64\bin\cmake.exe' --build --preset qt-mingw-build
& 'C:\Qt\Tools\CMake_64\bin\ctest.exe' --test-dir build --output-on-failure
```

Expected: Build exit 0; tüm CTest testleri PASS.

- [ ] **Step 2: Tüm Go testlerini çalıştır**

```powershell
Set-Location backend
go test ./... -count=1
Set-Location ..
```

PostgreSQL test ortamı yapılandırılmışsa:

```powershell
Set-Location backend
go test ./tests/integration -count=1
Set-Location ..
```

Expected: Unit testler PASS; integration testleri PostgreSQL varsa PASS, yoksa mevcut skip sözleşmesi açıkça raporlanır.

- [ ] **Step 3: Login penceresini gerçek Qt runtime ile görsel olarak doğrula**

Qt ve OpenSSL DLL dizinlerini PATH'e ekleyip `build/license-client/LicenseClient.exe` çalıştır. Şunları doğrula:

- Adwaita Dark tema ve `loginCard` stili görünür.
- Yalnızca e-posta ve parola giriş alanları vardır.
- Lisans ve cihaz kimliği alanları yoktur.
- `HWID'yi görüntüle` bağlantısı görünür ve tıklanabilir.
- Diyalog global temayı miras alır, yalnızca final fingerprint'i gösterir ve kopyalama çalışır.
- %100 ve %150 DPI'da tüm öğeler pencere sınırları içindedir.

- [ ] **Step 4: Değişiklik kapsamı ve whitespace kontrolünü çalıştır**

```powershell
git diff --check
git status --short
git log --oneline -7
```

Expected: Whitespace hatası yok; yalnızca plan kapsamındaki dosyalar değişmiş; her görev ayrı commit.

Doğrulama bir hata gösterirse tamamlanma iddiasında bulunmadan ilgili görevin kırmızı-yeşil test döngüsüne dönülür; yalnızca tüm doğrulamalar yeniden başarılı olduğunda bu görev tamamlanır.

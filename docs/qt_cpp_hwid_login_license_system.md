# Qt C++ HWID + Login/Lisans Sistemi

Bu doküman iki ayrı Windows uygulaması geliştirmek için hazırlanmıştır:

1. **HWID Obtainer**
2. **Login + HWID Lisans Client**

Hedef teknoloji:

- Windows 10/11
- Qt 6 Widgets
- C++20 veya C++23
- CMake
- Windows CNG / TPM 2.0
- REST API
- PostgreSQL
- HTTPS

> Önemli: İstemci tarafında çalışan hiçbir lisans sistemi mutlak şekilde kırılamaz. Ama TPM tabanlı cihaz kimliği, çoklu donanım parmak izi, challenge-response ve sunucu tarafı doğrulama birlikte kullanıldığında bypass maliyeti ciddi şekilde yükselir.

---

# 1. Genel Mimari

```text
                    ┌──────────────────────┐
                    │     License Server   │
                    │                      │
                    │ Auth                 │
                    │ License Validation   │
                    │ Device Registry      │
                    │ TPM Verification     │
                    │ Signed Sessions      │
                    └──────────┬───────────┘
                               │ HTTPS
             ┌─────────────────┴─────────────────┐
             │                                   │
             ▼                                   ▼
┌─────────────────────────┐        ┌──────────────────────────┐
│ HWID Obtainer           │        │ Login / License Client   │
│                         │        │                          │
│ SMBIOS UUID             │        │ Login                    │
│ Motherboard Serial      │        │ License Validation       │
│ BIOS Serial             │        │ Device Verification      │
│ Disk Serial             │        │ TPM Challenge            │
│ MachineGuid             │        │ Signed Session           │
│ TPM Public Key          │        │                          │
│ Final Fingerprint       │        │                          │
└─────────────────────────┘        └──────────────────────────┘
```

---

# 2. Güvenlik Modeli

Tek bir HWID değerine güvenme.

Önerilen cihaz sinyalleri:

```text
TPM Public Key
SMBIOS System UUID
Motherboard Serial
BIOS Serial
System Disk Serial
Windows MachineGuid
```

Bu bilgiler normalize edilir.

Sonra:

```text
SHA-256(
    SMBIOS_UUID |
    MOTHERBOARD |
    BIOS |
    DISK |
    MACHINE_GUID |
    TPM_PUBLIC_KEY_HASH
)
```

ile final fingerprint üretilebilir.

Ancak sunucu tarafında yalnızca final fingerprint karşılaştırmak yerine her alan ayrı değerlendirilmelidir.

---

# 3. Repository Yapısı

```text
qt-license-system/
│
├── shared/
│   ├── hardware/
│   │   ├── HardwareIdentity.h
│   │   ├── HardwareIdentity.cpp
│   │   ├── RegistryReader.h
│   │   ├── RegistryReader.cpp
│   │   ├── SmbiosReader.h
│   │   ├── SmbiosReader.cpp
│   │   ├── DiskReader.h
│   │   └── DiskReader.cpp
│   │
│   ├── security/
│   │   ├── TpmIdentity.h
│   │   ├── TpmIdentity.cpp
│   │   ├── Fingerprint.h
│   │   ├── Fingerprint.cpp
│   │   ├── SecureStorage.h
│   │   └── SecureStorage.cpp
│   │
│   └── CMakeLists.txt
│
├── hwid-obtainer/
│   ├── CMakeLists.txt
│   ├── src/
│   │   ├── main.cpp
│   │   ├── MainWindow.h
│   │   └── MainWindow.cpp
│   └── ui/
│       └── MainWindow.ui
│
├── license-client/
│   ├── CMakeLists.txt
│   ├── src/
│   │   ├── main.cpp
│   │   ├── auth/
│   │   │   ├── AuthManager.h
│   │   │   └── AuthManager.cpp
│   │   ├── api/
│   │   │   ├── ApiClient.h
│   │   │   └── ApiClient.cpp
│   │   ├── license/
│   │   │   ├── LicenseManager.h
│   │   │   └── LicenseManager.cpp
│   │   └── ui/
│   │       ├── LoginWindow.h
│   │       ├── LoginWindow.cpp
│   │       ├── DashboardWindow.h
│   │       └── DashboardWindow.cpp
│   └── ui/
│       ├── LoginWindow.ui
│       └── DashboardWindow.ui
│
└── server-contract/
    ├── API.md
    └── schema.sql
```

---

# 4. Shared CMake

```cmake
cmake_minimum_required(VERSION 3.24)

project(DeviceIdentityShared LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Qt6 REQUIRED COMPONENTS Core Network)

add_library(DeviceIdentityShared STATIC
    hardware/HardwareIdentity.cpp
    hardware/RegistryReader.cpp
    hardware/SmbiosReader.cpp
    hardware/DiskReader.cpp

    security/TpmIdentity.cpp
    security/Fingerprint.cpp
    security/SecureStorage.cpp
)

target_include_directories(DeviceIdentityShared PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(DeviceIdentityShared PUBLIC
    Qt6::Core
    Qt6::Network
    ncrypt
    bcrypt
    advapi32
    crypt32
)
```

---

# 5. HardwareIdentity

`HardwareIdentity.h`

```cpp
#pragma once

#include <QString>

struct HardwareIdentity
{
    QString smbiosUuid;
    QString motherboardSerial;
    QString biosSerial;
    QString systemDiskSerial;
    QString machineGuid;

    QString cpuArchitecture;
    QString hostName;

    QString tpmPublicKeyHash;

    QString finalFingerprint;
};
```

---

# 6. MachineGuid

`RegistryReader.h`

```cpp
#pragma once

#include <QString>

class RegistryReader
{
public:
    static QString machineGuid();
};
```

`RegistryReader.cpp`

```cpp
#include "RegistryReader.h"

#include <QSettings>

QString RegistryReader::machineGuid()
{
    QSettings registry(
        R"(HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography)",
        QSettings::NativeFormat
    );

    return registry.value("MachineGuid").toString();
}
```

MachineGuid yardımcı sinyaldir.

Tek başına HWID olarak kullanılmamalıdır.

---

# 7. Hardware Normalization

```cpp
QString normalizeHardwareValue(QString value)
{
    value = value.trimmed().toUpper();

    value.remove(' ');
    value.remove('-');
    value.remove('{');
    value.remove('}');

    return value;
}
```

Her uygulamanın aynı normalization algoritmasını kullanması gerekir.

---

# 8. SMBIOS Reader

Windows raw SMBIOS:

```cpp
GetSystemFirmwareTable()
```

ile alınabilir.

`SmbiosReader.h`

```cpp
#pragma once

#include <QString>

struct SmbiosInfo
{
    QString systemUuid;
    QString motherboardSerial;
    QString biosSerial;
};

class SmbiosReader
{
public:
    static SmbiosInfo read();
};
```

Temel reader:

```cpp
#include "SmbiosReader.h"

#include <Windows.h>
#include <vector>

SmbiosInfo SmbiosReader::read()
{
    SmbiosInfo result;

    const DWORD provider = 'BMSR';

    const DWORD size =
        GetSystemFirmwareTable(
            provider,
            0,
            nullptr,
            0
        );

    if (size == 0)
        return result;

    std::vector<unsigned char> buffer(size);

    const DWORD written =
        GetSystemFirmwareTable(
            provider,
            0,
            buffer.data(),
            size
        );

    if (written != size)
        return result;

    // Raw SMBIOS structures burada parse edilir.
    //
    // Type 0 -> BIOS Information
    // Type 1 -> System Information
    // Type 2 -> Baseboard Information
    //
    // Type 1 içerisinden System UUID
    // Type 2 içerisinden Board Serial
    // Type 0 içerisinden BIOS bilgileri

    return result;
}
```

SMBIOS parser'ı ayrıca yaz:

```text
SmbiosParser
 ├── parseType0()
 ├── parseType1()
 ├── parseType2()
 └── readSmbiosString()
```

---

# 9. Disk Serial

`DiskReader.h`

```cpp
#pragma once

#include <QString>

class DiskReader
{
public:
    static QString systemDiskSerial();
};
```

Fiziksel disk için:

```cpp
CreateFileW(
    L"\\\\.\\PhysicalDrive0",
    ...
);
```

ardından:

```cpp
DeviceIoControl(
    handle,
    IOCTL_STORAGE_QUERY_PROPERTY,
    ...
);
```

kullanılır.

`STORAGE_DEVICE_DESCRIPTOR::SerialNumberOffset` içinden disk serial alınır.

> Production sürümünde doğrudan `PhysicalDrive0` varsayma. Windows'un kurulu olduğu logical volume'ün bağlı olduğu fiziksel diski belirle.

---

# 10. TPM Identity

`TpmIdentity.h`

```cpp
#pragma once

#include <QByteArray>
#include <QString>

class TpmIdentity
{
public:
    static bool isAvailable();

    static bool keyExists();
    static bool createKey();

    static QByteArray publicKey();

    static QByteArray signChallenge(
        const QByteArray& challenge
    );

    static QString publicKeySha256();

private:
    static constexpr const wchar_t* KeyName =
        L"MyCompany.MyProduct.DeviceIdentity.v1";
};
```

---

# 11. TPM Availability

```cpp
#include <Windows.h>
#include <ncrypt.h>

bool TpmIdentity::isAvailable()
{
    NCRYPT_PROV_HANDLE provider = 0;

    const SECURITY_STATUS status =
        NCryptOpenStorageProvider(
            &provider,
            MS_PLATFORM_CRYPTO_PROVIDER,
            0
        );

    if (status != ERROR_SUCCESS)
        return false;

    NCryptFreeObject(provider);

    return true;
}
```

---

# 12. TPM Key Oluşturma

```cpp
bool TpmIdentity::createKey()
{
    NCRYPT_PROV_HANDLE provider = 0;
    NCRYPT_KEY_HANDLE key = 0;

    SECURITY_STATUS status =
        NCryptOpenStorageProvider(
            &provider,
            MS_PLATFORM_CRYPTO_PROVIDER,
            0
        );

    if (status != ERROR_SUCCESS)
        return false;

    status =
        NCryptCreatePersistedKey(
            provider,
            &key,
            NCRYPT_ECDSA_P256_ALGORITHM,
            KeyName,
            0,
            0
        );

    if (status != ERROR_SUCCESS)
    {
        NCryptFreeObject(provider);
        return false;
    }

    status =
        NCryptFinalizeKey(
            key,
            0
        );

    NCryptFreeObject(key);
    NCryptFreeObject(provider);

    return status == ERROR_SUCCESS;
}
```

Burada private key TPM-backed provider içerisinde tutulur.

---

# 13. TPM Key Exists

```cpp
bool TpmIdentity::keyExists()
{
    NCRYPT_PROV_HANDLE provider = 0;
    NCRYPT_KEY_HANDLE key = 0;

    if (NCryptOpenStorageProvider(
            &provider,
            MS_PLATFORM_CRYPTO_PROVIDER,
            0) != ERROR_SUCCESS)
    {
        return false;
    }

    const SECURITY_STATUS status =
        NCryptOpenKey(
            provider,
            &key,
            KeyName,
            0,
            0
        );

    if (status == ERROR_SUCCESS)
        NCryptFreeObject(key);

    NCryptFreeObject(provider);

    return status == ERROR_SUCCESS;
}
```

---

# 14. TPM Public Key Export

```cpp
QByteArray TpmIdentity::publicKey()
{
    NCRYPT_PROV_HANDLE provider = 0;
    NCRYPT_KEY_HANDLE key = 0;

    if (NCryptOpenStorageProvider(
            &provider,
            MS_PLATFORM_CRYPTO_PROVIDER,
            0) != ERROR_SUCCESS)
    {
        return {};
    }

    if (NCryptOpenKey(
            provider,
            &key,
            KeyName,
            0,
            0) != ERROR_SUCCESS)
    {
        NCryptFreeObject(provider);
        return {};
    }

    DWORD size = 0;

    SECURITY_STATUS status =
        NCryptExportKey(
            key,
            0,
            BCRYPT_ECCPUBLIC_BLOB,
            nullptr,
            nullptr,
            0,
            &size,
            0
        );

    if (status != ERROR_SUCCESS)
    {
        NCryptFreeObject(key);
        NCryptFreeObject(provider);
        return {};
    }

    QByteArray blob(
        static_cast<int>(size),
        Qt::Uninitialized
    );

    status =
        NCryptExportKey(
            key,
            0,
            BCRYPT_ECCPUBLIC_BLOB,
            nullptr,
            reinterpret_cast<PBYTE>(blob.data()),
            size,
            &size,
            0
        );

    NCryptFreeObject(key);
    NCryptFreeObject(provider);

    if (status != ERROR_SUCCESS)
        return {};

    blob.resize(static_cast<int>(size));

    return blob;
}
```

---

# 15. TPM Public Key Hash

```cpp
QString TpmIdentity::publicKeySha256()
{
    const QByteArray key =
        publicKey();

    if (key.isEmpty())
        return {};

    return QCryptographicHash::hash(
        key,
        QCryptographicHash::Sha256
    ).toHex().toUpper();
}
```

---

# 16. Challenge Signing

Sunucu 32 random byte challenge üretir.

```cpp
QByteArray TpmIdentity::signChallenge(
    const QByteArray& challenge)
{
    NCRYPT_PROV_HANDLE provider = 0;
    NCRYPT_KEY_HANDLE key = 0;

    if (NCryptOpenStorageProvider(
            &provider,
            MS_PLATFORM_CRYPTO_PROVIDER,
            0) != ERROR_SUCCESS)
    {
        return {};
    }

    if (NCryptOpenKey(
            provider,
            &key,
            KeyName,
            0,
            0) != ERROR_SUCCESS)
    {
        NCryptFreeObject(provider);
        return {};
    }

    const QByteArray digest =
        QCryptographicHash::hash(
            challenge,
            QCryptographicHash::Sha256
        );

    DWORD signatureSize = 0;

    SECURITY_STATUS status =
        NCryptSignHash(
            key,
            nullptr,
            reinterpret_cast<PBYTE>(
                const_cast<char*>(digest.data())
            ),
            static_cast<DWORD>(digest.size()),
            nullptr,
            0,
            &signatureSize,
            0
        );

    if (status != ERROR_SUCCESS)
    {
        NCryptFreeObject(key);
        NCryptFreeObject(provider);
        return {};
    }

    QByteArray signature(
        static_cast<int>(signatureSize),
        Qt::Uninitialized
    );

    status =
        NCryptSignHash(
            key,
            nullptr,
            reinterpret_cast<PBYTE>(
                const_cast<char*>(digest.data())
            ),
            static_cast<DWORD>(digest.size()),
            reinterpret_cast<PBYTE>(
                signature.data()
            ),
            signatureSize,
            &signatureSize,
            0
        );

    NCryptFreeObject(key);
    NCryptFreeObject(provider);

    if (status != ERROR_SUCCESS)
        return {};

    signature.resize(
        static_cast<int>(signatureSize)
    );

    return signature;
}
```

---

# 17. Fingerprint Generator

`Fingerprint.h`

```cpp
#pragma once

#include "../hardware/HardwareIdentity.h"

#include <QString>

class Fingerprint
{
public:
    static QString generate(
        const HardwareIdentity& hw
    );
};
```

`Fingerprint.cpp`

```cpp
#include "Fingerprint.h"

#include <QCryptographicHash>

namespace
{
QString normalize(QString value)
{
    return value
        .trimmed()
        .toUpper()
        .remove(' ')
        .remove('-')
        .remove('{')
        .remove('}');
}
}

QString Fingerprint::generate(
    const HardwareIdentity& hw)
{
    QByteArray input;

    auto append =
        [&](const QString& value)
        {
            input +=
                normalize(value).toUtf8();

            input += '|';
        };

    append(hw.smbiosUuid);
    append(hw.motherboardSerial);
    append(hw.biosSerial);
    append(hw.systemDiskSerial);
    append(hw.machineGuid);
    append(hw.tpmPublicKeyHash);

    return QCryptographicHash::hash(
        input,
        QCryptographicHash::Sha256
    ).toHex().toUpper();
}
```

---

# 18. Hardware Collector

```cpp
HardwareIdentity collectHardwareIdentity()
{
    HardwareIdentity hw;

    const SmbiosInfo smbios =
        SmbiosReader::read();

    hw.smbiosUuid =
        smbios.systemUuid;

    hw.motherboardSerial =
        smbios.motherboardSerial;

    hw.biosSerial =
        smbios.biosSerial;

    hw.systemDiskSerial =
        DiskReader::systemDiskSerial();

    hw.machineGuid =
        RegistryReader::machineGuid();

    hw.cpuArchitecture =
        QSysInfo::currentCpuArchitecture();

    hw.hostName =
        QSysInfo::machineHostName();

    if (!TpmIdentity::keyExists())
        TpmIdentity::createKey();

    hw.tpmPublicKeyHash =
        TpmIdentity::publicKeySha256();

    hw.finalFingerprint =
        Fingerprint::generate(hw);

    return hw;
}
```

---

# 19. HWID Obtainer UI

```text
┌─────────────────────────────────────────────────┐
│              Device Identity Tool               │
├─────────────────────────────────────────────────┤
│ SMBIOS UUID                                     │
│ [.............................................] │
│                                                 │
│ Motherboard Serial                              │
│ [.............................................] │
│                                                 │
│ BIOS Serial                                     │
│ [.............................................] │
│                                                 │
│ System Disk Serial                              │
│ [.............................................] │
│                                                 │
│ MachineGuid                                     │
│ [.............................................] │
│                                                 │
│ TPM Public Key Hash                             │
│ [.............................................] │
│                                                 │
│ Final Fingerprint                               │
│ [.............................................] │
│                                                 │
│ [ Refresh ] [ Copy HWID ] [ Export JSON ]       │
└─────────────────────────────────────────────────┘
```

---

# 20. HWID Obtainer MainWindow

```cpp
void MainWindow::refreshHardware()
{
    const HardwareIdentity hw =
        collectHardwareIdentity();

    ui->smbiosUuidEdit
        ->setText(hw.smbiosUuid);

    ui->motherboardEdit
        ->setText(hw.motherboardSerial);

    ui->biosEdit
        ->setText(hw.biosSerial);

    ui->diskEdit
        ->setText(hw.systemDiskSerial);

    ui->machineGuidEdit
        ->setText(hw.machineGuid);

    ui->tpmEdit
        ->setText(hw.tpmPublicKeyHash);

    ui->fingerprintEdit
        ->setText(hw.finalFingerprint);
}
```

Copy HWID:

```cpp
QGuiApplication::clipboard()->setText(
    ui->fingerprintEdit->text()
);
```

---

# 21. JSON Export

```json
{
  "smbios_uuid": "...",
  "motherboard_serial": "...",
  "bios_serial": "...",
  "system_disk_serial": "...",
  "machine_guid": "...",
  "tpm_public_key_hash": "...",
  "fingerprint": "..."
}
```

Bu uygulama debug ve destek amaçlı kullanılabilir.

---

# 22. Login Client Akışı

```text
Application Start
        |
        v
Collect Hardware Identity
        |
        v
Ensure TPM Key
        |
        v
Login Form
        |
        v
POST /auth/login
        |
        v
Credential Validation
        |
        v
Server Challenge
        |
        v
TPM Sign Challenge
        |
        v
POST /device/verify
        |
        v
Device Score + License Check
        |
        v
Signed Session Token
        |
        v
Application Unlocked
```

---

# 23. Login UI

```text
┌──────────────────────────────────────┐
│             Product Login            │
├──────────────────────────────────────┤
│ Email                                │
│ [..................................] │
│                                      │
│ Password                             │
│ [..................................] │
│                                      │
│ License Key                          │
│ [..................................] │
│                                      │
│ [              Login             ]   │
│                                      │
│ Device: 8F34A1-33BC12                │
│ Status: Not authenticated            │
└──────────────────────────────────────┘
```

---

# 24. ApiClient

`ApiClient.h`

```cpp
#pragma once

#include <QObject>
#include <QNetworkAccessManager>
#include <QJsonObject>

class ApiClient : public QObject
{
    Q_OBJECT

public:
    explicit ApiClient(QObject* parent = nullptr);

    void login(
        const QString& email,
        const QString& password,
        const QString& licenseKey,
        const QString& fingerprint
    );

    void verifyDevice(
        const QString& sessionId,
        const QByteArray& signature,
        const QByteArray& tpmPublicKey,
        const QJsonObject& deviceInfo
    );

signals:
    void loginSucceeded(
        const QJsonObject& response
    );

    void loginFailed(
        const QString& error
    );

    void deviceVerified(
        const QJsonObject& response
    );

    void deviceVerificationFailed(
        const QString& error
    );

private:
    QNetworkAccessManager m_network;

    QString m_baseUrl =
        "https://api.example.com/v1";
};
```

---

# 25. Login Request

```http
POST /v1/auth/login
Content-Type: application/json
```

```json
{
  "email": "user@example.com",
  "password": "password",
  "license_key": "AAAA-BBBB-CCCC-DDDD",
  "device_fingerprint": "..."
}
```

Sunucu response:

```json
{
  "ok": true,
  "session_id": "efad3...",
  "challenge": "BASE64_RANDOM_BYTES",
  "challenge_expires_at": "2026-08-09T15:25:30+03:00"
}
```

Challenge:

- random olmalı
- tek kullanımlık olmalı
- kısa ömürlü olmalı
- en az 32 random byte tercih edilebilir

---

# 26. Qt Login POST

```cpp
void ApiClient::login(
    const QString& email,
    const QString& password,
    const QString& licenseKey,
    const QString& fingerprint)
{
    QNetworkRequest request(
        QUrl(m_baseUrl + "/auth/login")
    );

    request.setHeader(
        QNetworkRequest::ContentTypeHeader,
        "application/json"
    );

    QJsonObject body;

    body["email"] =
        email;

    body["password"] =
        password;

    body["license_key"] =
        licenseKey;

    body["device_fingerprint"] =
        fingerprint;

    const QByteArray payload =
        QJsonDocument(body).toJson(
            QJsonDocument::Compact
        );

    QNetworkReply* reply =
        m_network.post(
            request,
            payload
        );

    connect(
        reply,
        &QNetworkReply::finished,
        this,
        [this, reply]()
        {
            const QByteArray data =
                reply->readAll();

            if (reply->error() !=
                QNetworkReply::NoError)
            {
                emit loginFailed(
                    reply->errorString()
                );

                reply->deleteLater();

                return;
            }

            const QJsonDocument doc =
                QJsonDocument::fromJson(data);

            if (!doc.isObject())
            {
                emit loginFailed(
                    "Invalid server response"
                );

                reply->deleteLater();

                return;
            }

            emit loginSucceeded(
                doc.object()
            );

            reply->deleteLater();
        }
    );
}
```

Production sürümünde ayrıca:

- timeout
- HTTP status kontrolü
- JSON validation
- structured error codes
- network failure handling

ekle.

---

# 27. TPM Challenge İşleme

```cpp
const QByteArray challenge =
    QByteArray::fromBase64(
        response["challenge"]
            .toString()
            .toUtf8()
    );

const QByteArray signature =
    TpmIdentity::signChallenge(
        challenge
    );
```

Sonra server'a:

```json
{
  "session_id": "...",
  "challenge_signature": "...",
  "tpm_public_key": "...",

  "hardware": {
    "smbios_uuid": "...",
    "motherboard_serial": "...",
    "bios_serial": "...",
    "disk_serial": "...",
    "machine_guid": "...",
    "fingerprint": "..."
  }
}
```

gönder.

---

# 28. İlk Device Activation

Sunucuda bu lisansa bağlı cihaz yoksa:

```text
license valid
AND
activation_count < max_devices
AND
challenge signature valid
```

ise cihaz kaydı oluştur.

Kaydedilebilecek bilgiler:

```text
device_id
user_id
license_id

tpm_public_key
tpm_public_key_hash

smbios_uuid_hash
motherboard_serial_hash
bios_serial_hash
disk_serial_hash
machine_guid_hash

fingerprint

created_at
last_seen_at
status
```

---

# 29. Device Matching Score

Örnek:

```text
TPM Public Key        50
SMBIOS UUID           20
Motherboard Serial    15
BIOS Serial            5
Disk Serial            5
MachineGuid            5
-------------------------
Total                 100
```

Pseudo-code:

```cpp
int score = 0;

if (tpmMatches)
    score += 50;

if (smbiosMatches)
    score += 20;

if (motherboardMatches)
    score += 15;

if (biosMatches)
    score += 5;

if (diskMatches)
    score += 5;

if (machineGuidMatches)
    score += 5;

const bool sameDevice =
    score >= 70;
```

Bu ağırlıklar örnektir.

Gerçek cihazlarda test edilerek ayarlanmalıdır.

---

# 30. Neden TPM En Önemli Sinyal?

Şunlar değişebilir:

```text
SSD
Windows installation
MachineGuid
BIOS version
```

TPM-backed key ise aynı cihazda kaldığı sürece daha güçlü bir cihaz kanıtıdır.

TPM reset veya motherboard değişimi yeni cihaz prosedürü gerektirebilir.

---

# 31. PostgreSQL Schema

```sql
create table users (
    id uuid primary key,

    email text unique not null,

    password_hash text not null,

    status text not null
        default 'active',

    created_at timestamptz not null
        default now()
);
```

Licenses:

```sql
create table licenses (
    id uuid primary key,

    license_key_hash text
        unique not null,

    user_id uuid
        references users(id),

    product_id text not null,

    status text not null
        default 'active',

    max_devices integer not null
        default 1,

    expires_at timestamptz,

    created_at timestamptz not null
        default now()
);
```

Devices:

```sql
create table devices (
    id uuid primary key,

    user_id uuid not null
        references users(id),

    license_id uuid not null
        references licenses(id),

    tpm_public_key bytea not null,

    tpm_public_key_hash text not null,

    smbios_uuid_hash text,
    motherboard_serial_hash text,
    bios_serial_hash text,
    disk_serial_hash text,
    machine_guid_hash text,

    fingerprint text not null,

    status text not null
        default 'active',

    created_at timestamptz not null
        default now(),

    last_seen_at timestamptz not null
        default now()
);

create index idx_devices_license
    on devices(license_id);

create index idx_devices_tpm_hash
    on devices(tpm_public_key_hash);
```

---

# 32. Challenge Table

```sql
create table device_challenges (
    id uuid primary key,

    session_id uuid not null,

    challenge_hash text not null,

    expires_at timestamptz not null,

    consumed_at timestamptz,

    created_at timestamptz not null
        default now()
);
```

Challenge kullanım sonrası:

```text
consumed_at = now()
```

yap.

Aynı challenge ikinci kez kabul edilmemeli.

---

# 33. Login Session Akışı

```text
Credentials verified
        |
        v
Pending Device Verification
        |
        v
TPM Challenge Valid
        |
        v
License Valid
        |
        v
Device Valid
        |
        v
Session Token Issued
```

---

# 34. Signed License Session

Sunucu kısa ömürlü signed token üretsin.

Örnek payload:

```json
{
  "sub": "USER_UUID",
  "license_id": "LICENSE_UUID",
  "device_id": "DEVICE_UUID",
  "product": "MY_PRODUCT",

  "features": [
    "base",
    "premium"
  ],

  "iat": 1786280000,
  "exp": 1786283600
}
```

İmza algoritması olarak örneğin:

```text
Ed25519
```

kullanılabilir.

Server'da:

```text
PRIVATE KEY
```

bulunur.

Client'ta yalnızca:

```text
PUBLIC KEY
```

bulunur.

Private signing key istemci binary'sine gömülmemelidir.

---

# 35. Token Verification

İstemci token üzerinde şunları kontrol etsin:

```text
signature
expiration
issuer
audience
product
device_id
license_id
```

Token doğrulanmadan ana uygulama açılmamalıdır.

---

# 36. Offline Grace Period

İstenirse:

```text
online session: 4 saat
offline grace: 24 saat
```

gibi kısa bir sistem kullanılabilir.

Ama offline kullanım:

```text
security ↓
```

demektir.

Daha yüksek güvenlik için düzenli server validation tercih edilir.

---

# 37. Secure Local Storage

Şunları plaintext dosyaya yazma:

```text
access token
refresh token
session secret
license secret
```

Windows için:

```text
DPAPI
```

kullan.

API:

```cpp
CryptProtectData()
CryptUnprotectData()
```

---

# 38. SecureStorage

```cpp
#pragma once

#include <QByteArray>
#include <QString>

class SecureStorage
{
public:
    static bool save(
        const QString& key,
        const QByteArray& data
    );

    static QByteArray load(
        const QString& key
    );

    static bool remove(
        const QString& key
    );
};
```

---

# 39. Password Güvenliği

Client tarafında kendi password protocol'ünü icat etme.

Şifre:

```text
HTTPS
```

üzerinden server'a gönderilir.

Server tarafında:

```text
Argon2id
```

gibi modern password hashing kullanılabilir.

Database'de:

```text
plaintext password
```

saklanmamalıdır.

---

# 40. License Key Storage

Database'de plaintext license key yerine:

```text
HMAC-SHA256(
    server_secret,
    license_key
)
```

saklamak iyi bir yaklaşımdır.

Login sırasında gönderilen license key normalize edilip aynı HMAC hesaplanır.

---

# 41. Hardware Hashing

Ham seri numaralarını server'da saklamak yerine:

```text
HMAC-SHA256(
    hardware_pepper,
    normalized_hardware_value
)
```

saklanabilir.

Bu özellikle:

- motherboard serial
- disk serial
- MachineGuid
- SMBIOS UUID

gibi değerlerin doğrudan database'de görünmesini engeller.

---

# 42. API Endpoint Tasarımı

```text
POST /v1/auth/login

POST /v1/device/register
POST /v1/device/challenge
POST /v1/device/verify

POST /v1/license/validate

POST /v1/session/refresh
POST /v1/session/logout
```

Admin:

```text
GET    /v1/admin/users
GET    /v1/admin/licenses
GET    /v1/admin/devices

POST   /v1/admin/licenses

PATCH  /v1/admin/licenses/:id

POST   /v1/admin/devices/:id/revoke
POST   /v1/admin/devices/:id/reset
```

---

# 43. Login Endpoint

```text
POST /auth/login

1. rate limit
2. find user
3. verify password
4. check user status
5. find license
6. verify license
7. check expiry
8. create temporary auth session
9. generate challenge
10. return session + challenge
```

---

# 44. Device Verify Endpoint

```text
POST /device/verify

1. resolve session
2. resolve challenge
3. check challenge expiry
4. check challenge consumed
5. resolve public key
6. verify ECDSA signature
7. normalize hardware fields
8. HMAC hardware values
9. compare registered devices
10. calculate device score
11. check activation count
12. register/update device
13. consume challenge
14. create signed application session
```

---

# 45. Replay Protection

Challenge:

```text
cryptographically secure random
+
single use
+
short expiration
```

olmalıdır.

Her login için yeni challenge oluştur.

Örneğin:

```text
32 random bytes
```

---

# 46. Rate Limiting

Başlangıç için örnek:

```text
/auth/login
5 attempts / minute / IP

/device/verify
10 attempts / minute / session
```

Gerçek production değerleri kullanıcı davranışına göre ayarlanmalıdır.

---

# 47. Activation Limit

Örneğin:

```text
max_devices = 1
```

ise:

```text
0 active device
=> activate

1 matching device
=> allow

1 different device
=> reject/reset required
```

Response:

```json
{
  "ok": false,
  "code": "DEVICE_LIMIT_REACHED",
  "message": "This license is already active on another device."
}
```

---

# 48. Device Reset

Admin panelde:

```text
Reset Device
```

bulunmalı.

Kullanıcı:

- anakart değiştirdiğinde
- TPM resetlediğinde
- eski bilgisayarını sattığında

eski activation kaldırılabilir.

---

# 49. Device Status

```text
pending
active
revoked
blocked
```

---

# 50. License Status

```text
active
expired
suspended
revoked
```

---

# 51. Auth State Machine

`bool loggedIn` yerine:

```cpp
enum class AuthState
{
    LoggedOut,

    Authenticating,

    WaitingForDeviceChallenge,

    VerifyingDevice,

    Authenticated,

    Failed
};
```

kullan.

---

# 52. AuthManager

```cpp
class AuthManager : public QObject
{
    Q_OBJECT

public:
    explicit AuthManager(
        QObject* parent = nullptr
    );

    void login(
        const QString& email,
        const QString& password,
        const QString& licenseKey
    );

    void logout();

    bool isAuthenticated() const;

signals:
    void stateChanged(
        AuthState state
    );

    void authenticated();

    void authenticationFailed(
        const QString& reason
    );

private:
    ApiClient* m_api = nullptr;

    HardwareIdentity m_hardware;

    QString m_sessionId;
    QString m_accessToken;

    AuthState m_state =
        AuthState::LoggedOut;
};
```

---

# 53. AuthManager Flow

```text
AuthManager::login()
        |
        ├── collectHardwareIdentity()
        |
        ├── ensure TPM key
        |
        ├── ApiClient::login()
        |
        ├── receive challenge
        |
        ├── TPM sign
        |
        ├── ApiClient::verifyDevice()
        |
        ├── verify signed token
        |
        └── Authenticated
```

---

# 54. TLS

Tüm API trafiği:

```text
HTTPS
```

olmalıdır.

Production'da plain HTTP fallback yapma.

---

# 55. Certificate Pinning

Ekstra güvenlik katmanı olarak certificate/public-key pinning kullanılabilir.

Ancak:

```text
certificate rotation
```

yönetimini zorlaştırır.

İlk production sürümünde:

```text
HTTPS
+
signed application token
+
TPM challenge-response
```

önceliklidir.

---

# 56. Error Codes

Server:

```text
INVALID_CREDENTIALS
LICENSE_NOT_FOUND
LICENSE_EXPIRED
LICENSE_REVOKED
DEVICE_LIMIT_REACHED
DEVICE_REVOKED
CHALLENGE_EXPIRED
INVALID_DEVICE_SIGNATURE
SERVER_ERROR
```

gibi structured hata kodları dönsün.

Qt UI bu kodlara göre kullanıcı mesajı gösterir.

---

# 57. Logging

Client loglarında şunları yazma:

```text
password
full license key
access token
refresh token
full hardware serial numbers
```

Bunun yerine:

```text
timestamp
request_id
error_code
endpoint
masked device id
```

tut.

---

# 58. Request ID

Her API request için:

```text
X-Request-ID
```

oluştur.

UUIDv7 kullanılabilir.

Bu server-client log korelasyonunu kolaylaştırır.

---

# 59. Device Display ID

Kullanıcıya full fingerprint göstermek yerine kısa ID gösterebilirsin.

Örneğin:

```text
Full:
8D1261246F8A19E6...

UI:
8D1261-246F8A
```

Bu sadece display içindir.

Server full fingerprint kullanır.

---

# 60. Anti-Tamper Gerçeği

Şu tek başına yeterli değildir:

```cpp
if (licenseValid)
{
    startProgram();
}
```

Çünkü binary patchlenebilir.

Daha iyi model:

```text
authentication
+
TPM device proof
+
server license validation
+
short-lived signed session
+
server-dependent features
```

---

# 61. Server-Dependent Features

Mümkünse uygulamanın önemli parçalarının bir bölümü server doğrulamasına bağlı olsun:

```text
premium API
cloud storage
remote config
premium asset download
entitlement API
account data
```

Tamamen offline çalışan programda tüm güvenlik istemci tarafında kaldığı için protection daha zordur.

---

# 62. Code Signing

Release binary:

```text
Authenticode
```

ile imzalanabilir.

Faydaları:

```text
publisher verification
SmartScreen reputation
binary integrity
```

Ancak code signing:

```text
anti-crack sistemi değildir.
```

---

# 63. Threading

Donanım sorguları UI thread'i uzun süre bloklamamalı.

Kullan:

```text
QtConcurrent
```

veya worker:

```text
QThread
```

Network işlemleri:

```text
QNetworkAccessManager
```

ile async yapılmalı.

---

# 64. HWID Obtainer Geliştirme Sırası

```text
1. Qt Widgets project
2. UI
3. MachineGuid
4. SMBIOS raw reader
5. SMBIOS parser
6. System UUID
7. Motherboard serial
8. BIOS information
9. Physical system disk serial
10. Normalization
11. Fingerprint
12. JSON export
13. TPM availability
14. TPM persisted key
15. Public key export
16. Public key hash
17. Challenge signing
18. Local signature verification test
```

---

# 65. TPM Local Tests

Şu testleri yaz:

```text
challenge = random

sign(challenge)
verify(challenge, signature)
=> TRUE
```

Modified challenge:

```text
verify(challenge + "x", signature)
=> FALSE
```

Modified signature:

```text
verify(challenge, modified_signature)
=> FALSE
```

Bu üç test geçmeden server entegrasyonuna geçme.

---

# 66. Login Client Geliştirme Sırası

```text
1. Login UI
2. ApiClient
3. AuthManager
4. Fake login API
5. Challenge response
6. TPM signing
7. Device verify API
8. Activation logic
9. Device scoring
10. Signed session
11. Token verification
12. SecureStorage
13. Session refresh
14. Logout
15. Error handling
```

---

# 67. Backend Geliştirme Sırası

```text
1. PostgreSQL schema
2. User model
3. Password hashing
4. License model
5. Device model
6. Login endpoint
7. Challenge creation
8. ECDSA verification
9. Device registration
10. Device matching
11. Activation limit
12. Signed token
13. Refresh session
14. Revoke/reset
15. Rate limiting
16. Logging
17. Admin API
```

---

# 68. Gerçek Cihaz Test Senaryoları

Aşağıdaki durumları mutlaka test et.

## Normal restart

Beklenen:

```text
same device
```

## SSD değişimi

Beklenen:

```text
same device
```

TPM + motherboard + SMBIOS hala eşleşiyorsa.

## Windows reinstall

MachineGuid değişebilir.

Beklenen:

```text
same device
```

TPM identity kaldıysa.

## BIOS update

Beklenen:

```text
same device
```

## TPM reset

TPM persisted key kaybolabilir.

Beklenen:

```text
manual/device recovery flow
```

## Motherboard replacement

TPM + motherboard büyük ihtimalle değişir.

Beklenen:

```text
new device
```

## License dosyasını başka PC'ye kopyalama

Beklenen:

```text
challenge verification fail
or
new device activation required
```

---

# 69. Privacy

HWID sistemi geliştirirken kullanıcıya cihaz bilgilerinin lisans güvenliği için kullanıldığını belirt.

Server'da mümkün olduğunca:

```text
raw hardware identifiers
```

yerine:

```text
keyed hash / HMAC
```

sakla.

---

# 70. Önerilen Minimum Production Mimari

```text
Qt 6 Client
     |
     | HTTPS
     v
Reverse Proxy
     |
     v
License API
     |
     ├── PostgreSQL
     ├── Redis optional
     └── Signing Key
```

Redis zorunlu değildir.

Şunlar için yararlı olabilir:

```text
rate limit
short-lived challenge
temporary auth session
```

---

# 71. Final Güvenlik Katmanları

Production sistem:

```text
Layer 1
User/password authentication

Layer 2
License validation

Layer 3
Hardware fingerprint

Layer 4
TPM-backed device key

Layer 5
Challenge-response

Layer 6
Device matching score

Layer 7
Activation limit

Layer 8
Short-lived signed session

Layer 9
HTTPS

Layer 10
Secure local token storage

Layer 11
Server-side entitlements

Layer 12
Code signing / optional anti-tamper
```

---

# 72. Yapılmaması Gerekenler

```text
Sadece MachineGuid kullanma.

Sadece disk serial kullanma.

Sadece SHA256(HWID) güvenli sanma.

Server private key'i client'a koyma.

Plaintext password saklama.

Plaintext refresh token dosyaya yazma.

Challenge'ı tekrar kullanılabilir yapma.

Sonsuz süreli license token verme.

Tüm authorization mantığını client'a bırakma.

Client'tan gelen "licenseValid": true gibi değerlere güvenme.
```

---

# 73. İlk Hedef

Öncelikle aşağıdaki sonucu veren HWID Obtainer tamamlanmalı:

```text
SMBIOS UUID          OK
Motherboard Serial   OK
BIOS Serial          OK
System Disk Serial   OK
MachineGuid          OK
TPM Available        OK
TPM Key              OK
TPM Public Key       OK
Fingerprint          OK
Challenge Sign       OK
Local Verify         OK
```

Bundan sonra aynı `shared` kütüphanesi Login Client'a bağlanmalıdır.

---

# 74. Son Hedef Akış

```text
USER
 |
 v
LOGIN
 |
 v
PASSWORD VERIFIED
 |
 v
LICENSE VERIFIED
 |
 v
SERVER CHALLENGE
 |
 v
TPM SIGNATURE
 |
 v
DEVICE VERIFIED
 |
 v
HARDWARE SCORE
 |
 v
ACTIVATION CHECK
 |
 v
SIGNED SESSION TOKEN
 |
 v
APPLICATION START
```

Bu mimari iki uygulamanın da aynı cihaz kimliği altyapısını kullanmasını sağlar ve klasik tek-string HWID sistemlerinden çok daha güçlü bir temel oluşturur.

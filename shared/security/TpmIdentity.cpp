#include "TpmIdentity.h"

#include <QCryptographicHash>

#include <cstring>
#include <limits>
#include <utility>

namespace {

void clearError(QString *error)
{
    if (error)
        error->clear();
}

void setError(QString *error, QString message)
{
    if (error)
        *error = std::move(message);
}

} // namespace

#ifdef Q_OS_WIN
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>

namespace {

constexpr wchar_t KeyName[] = L"StarLoader.DeviceIdentity.v1";
constexpr qsizetype P256CoordinateSize = 32;
constexpr qsizetype P256PublicBlobSize = sizeof(BCRYPT_ECCKEY_BLOB) + P256CoordinateSize * 2;

template<typename Handle>
class NCryptHandle final
{
public:
    NCryptHandle() = default;
    NCryptHandle(const NCryptHandle &) = delete;
    NCryptHandle &operator=(const NCryptHandle &) = delete;

    ~NCryptHandle()
    {
        if (handle_)
            NCryptFreeObject(handle_);
    }

    Handle *put() { return &handle_; }
    Handle get() const { return handle_; }

private:
    Handle handle_ = 0;
};

using ProviderHandle = NCryptHandle<NCRYPT_PROV_HANDLE>;
using KeyHandle = NCryptHandle<NCRYPT_KEY_HANDLE>;

QString cngFailure(QStringView operation, SECURITY_STATUS status)
{
    return QStringLiteral("%1 failed (CNG status 0x%2).")
        .arg(operation)
        .arg(static_cast<quint32>(status), 8, 16, QLatin1Char('0'));
}

SECURITY_STATUS openProvider(ProviderHandle &provider)
{
    return NCryptOpenStorageProvider(provider.put(), MS_PLATFORM_CRYPTO_PROVIDER, 0);
}

SECURITY_STATUS openKey(NCRYPT_PROV_HANDLE provider, KeyHandle &key)
{
    return NCryptOpenKey(provider, key.put(), KeyName, 0, 0);
}

QByteArray exportPublicKey(NCRYPT_KEY_HANDLE key)
{
    DWORD size = 0;
    SECURITY_STATUS status = NCryptExportKey(
        key, 0, BCRYPT_ECCPUBLIC_BLOB, nullptr, nullptr, 0, &size, 0);
    if (status != ERROR_SUCCESS || size == 0
        || size > static_cast<DWORD>(std::numeric_limits<int>::max())) {
        return {};
    }

    QByteArray blob(static_cast<qsizetype>(size), Qt::Uninitialized);
    status = NCryptExportKey(
        key,
        0,
        BCRYPT_ECCPUBLIC_BLOB,
        nullptr,
        reinterpret_cast<PBYTE>(blob.data()),
        size,
        &size,
        0);
    if (status != ERROR_SUCCESS)
        return {};

    blob.resize(static_cast<qsizetype>(size));
    return blob;
}

bool isP256PublicBlob(QByteArrayView blob)
{
    if (blob.size() != P256PublicBlobSize)
        return false;

    BCRYPT_ECCKEY_BLOB header{};
    std::memcpy(&header, blob.data(), sizeof(header));
    return header.dwMagic == BCRYPT_ECDSA_PUBLIC_P256_MAGIC
        && header.cbKey == P256CoordinateSize;
}

bool validateP256Key(NCRYPT_KEY_HANDLE key)
{
    return isP256PublicBlob(exportPublicKey(key));
}

} // namespace
#endif

bool TpmIdentity::isAvailable()
{
#ifdef Q_OS_WIN
    ProviderHandle provider;
    return openProvider(provider) == ERROR_SUCCESS;
#else
    return false;
#endif
}

bool TpmIdentity::ensureKey(QString *error)
{
    clearError(error);
#ifdef Q_OS_WIN
    ProviderHandle provider;
    SECURITY_STATUS status = openProvider(provider);
    if (status != ERROR_SUCCESS) {
        setError(error, cngFailure(QStringLiteral("Opening the TPM platform provider"), status));
        return false;
    }

    KeyHandle key;
    status = openKey(provider.get(), key);
    if (status == ERROR_SUCCESS) {
        if (!validateP256Key(key.get())) {
            setError(error, QStringLiteral("The persisted TPM identity key is not ECDSA P-256."));
            return false;
        }
        return true;
    }
    if (status != NTE_BAD_KEYSET) {
        setError(error, cngFailure(QStringLiteral("Opening the persisted TPM identity key"), status));
        return false;
    }

    status = NCryptCreatePersistedKey(
        provider.get(), key.put(), NCRYPT_ECDSA_P256_ALGORITHM, KeyName, 0, 0);
    if (status != ERROR_SUCCESS) {
        setError(error, cngFailure(QStringLiteral("Creating the TPM identity key"), status));
        return false;
    }

    DWORD exportPolicy = 0;
    status = NCryptSetProperty(
        key.get(),
        NCRYPT_EXPORT_POLICY_PROPERTY,
        reinterpret_cast<PBYTE>(&exportPolicy),
        sizeof(exportPolicy),
        0);
    if (status != ERROR_SUCCESS) {
        setError(error, cngFailure(QStringLiteral("Disabling TPM private-key export"), status));
        return false;
    }

    DWORD usage = NCRYPT_ALLOW_SIGNING_FLAG;
    status = NCryptSetProperty(
        key.get(),
        NCRYPT_KEY_USAGE_PROPERTY,
        reinterpret_cast<PBYTE>(&usage),
        sizeof(usage),
        0);
    if (status != ERROR_SUCCESS) {
        setError(error, cngFailure(QStringLiteral("Restricting TPM key usage"), status));
        return false;
    }

    status = NCryptFinalizeKey(key.get(), 0);
    if (status != ERROR_SUCCESS) {
        setError(error, cngFailure(QStringLiteral("Finalizing the TPM identity key"), status));
        return false;
    }
    if (!validateP256Key(key.get())) {
        setError(error, QStringLiteral("The new TPM identity key is not ECDSA P-256."));
        return false;
    }
    return true;
#else
    setError(error, QStringLiteral("TPM identity is available only on Windows."));
    return false;
#endif
}

QByteArray TpmIdentity::publicKeyBlob()
{
#ifdef Q_OS_WIN
    ProviderHandle provider;
    if (openProvider(provider) != ERROR_SUCCESS)
        return {};

    KeyHandle key;
    if (openKey(provider.get(), key) != ERROR_SUCCESS)
        return {};

    const QByteArray blob = exportPublicKey(key.get());
    return isP256PublicBlob(blob) ? blob : QByteArray();
#else
    return {};
#endif
}

QString TpmIdentity::publicKeySha256()
{
    const QByteArray publicKey = publicKeyBlob();
    if (publicKey.isEmpty())
        return {};

    return QString::fromLatin1(
        QCryptographicHash::hash(publicKey, QCryptographicHash::Sha256).toHex().toUpper());
}

QByteArray TpmIdentity::signChallenge(QByteArrayView challenge, QString *error)
{
    clearError(error);
    if (challenge.isEmpty()) {
        setError(error, QStringLiteral("The challenge must not be empty."));
        return {};
    }

#ifdef Q_OS_WIN
    ProviderHandle provider;
    SECURITY_STATUS status = openProvider(provider);
    if (status != ERROR_SUCCESS) {
        setError(error, cngFailure(QStringLiteral("Opening the TPM platform provider"), status));
        return {};
    }

    KeyHandle key;
    status = openKey(provider.get(), key);
    if (status != ERROR_SUCCESS) {
        setError(error, cngFailure(QStringLiteral("Opening the persisted TPM identity key"), status));
        return {};
    }
    if (!validateP256Key(key.get())) {
        setError(error, QStringLiteral("The persisted TPM identity key is not ECDSA P-256."));
        return {};
    }

    const QByteArray digest = QCryptographicHash::hash(challenge, QCryptographicHash::Sha256);
    DWORD signatureSize = 0;
    status = NCryptSignHash(
        key.get(),
        nullptr,
        reinterpret_cast<PBYTE>(const_cast<char *>(digest.constData())),
        static_cast<DWORD>(digest.size()),
        nullptr,
        0,
        &signatureSize,
        0);
    if (status != ERROR_SUCCESS || signatureSize == 0
        || signatureSize > static_cast<DWORD>(std::numeric_limits<int>::max())) {
        setError(error, status == ERROR_SUCCESS
                ? QStringLiteral("The TPM returned an empty signature.")
                : cngFailure(QStringLiteral("Signing the challenge with the TPM"), status));
        return {};
    }

    QByteArray signature(static_cast<qsizetype>(signatureSize), Qt::Uninitialized);
    status = NCryptSignHash(
        key.get(),
        nullptr,
        reinterpret_cast<PBYTE>(const_cast<char *>(digest.constData())),
        static_cast<DWORD>(digest.size()),
        reinterpret_cast<PBYTE>(signature.data()),
        signatureSize,
        &signatureSize,
        0);
    if (status != ERROR_SUCCESS || signatureSize == 0) {
        setError(error, status == ERROR_SUCCESS
                ? QStringLiteral("The TPM returned an empty signature.")
                : cngFailure(QStringLiteral("Signing the challenge with the TPM"), status));
        return {};
    }

    signature.resize(static_cast<qsizetype>(signatureSize));
    return signature;
#else
    setError(error, QStringLiteral("TPM identity is available only on Windows."));
    return {};
#endif
}

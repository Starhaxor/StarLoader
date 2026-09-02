#include "TpmIdentity.h"
#include "TpmKeyLifecycle.h"

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
        reset();
    }

    Handle *put()
    {
        reset();
        return &handle_;
    }
    Handle get() const { return handle_; }
    Handle release() { return std::exchange(handle_, 0); }

    void reset()
    {
        if (handle_)
            NCryptFreeObject(std::exchange(handle_, 0));
    }

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

SECURITY_STATUS openPersistedKey(NCRYPT_PROV_HANDLE provider, KeyHandle &key)
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
    DWORD exportPolicy = 0;
    DWORD exportPolicySize = sizeof(exportPolicy);
    const bool exportPolicyPresent = NCryptGetProperty(
        key, NCRYPT_EXPORT_POLICY_PROPERTY, reinterpret_cast<PBYTE>(&exportPolicy),
        sizeof(exportPolicy), &exportPolicySize, 0) == ERROR_SUCCESS
        && exportPolicySize == sizeof(exportPolicy);

    DWORD keyUsage = 0;
    DWORD keyUsageSize = sizeof(keyUsage);
    const bool keyUsagePresent = NCryptGetProperty(
        key, NCRYPT_KEY_USAGE_PROPERTY, reinterpret_cast<PBYTE>(&keyUsage),
        sizeof(keyUsage), &keyUsageSize, 0) == ERROR_SUCCESS
        && keyUsageSize == sizeof(keyUsage);

    return isP256PublicBlob(exportPublicKey(key))
        && TpmIdentityDetail::isSigningOnlyNonExportablePolicy(
            {exportPolicyPresent, exportPolicy, keyUsagePresent, keyUsage});
}

class CngKeyLifecycle final : public TpmIdentityDetail::KeyLifecycle
{
public:
    explicit CngKeyLifecycle(NCRYPT_PROV_HANDLE provider)
        : provider_(provider)
    {
    }

    TpmIdentityDetail::KeyOperationResult openKey() override
    {
        operation_ = QStringLiteral("Opening the persisted TPM identity key");
        status_ = openPersistedKey(provider_, key_);
        if (status_ == ERROR_SUCCESS)
            return TpmIdentityDetail::KeyOperationResult::Success;
        if (status_ == NTE_BAD_KEYSET)
            return TpmIdentityDetail::KeyOperationResult::NotFound;
        return TpmIdentityDetail::KeyOperationResult::Failure;
    }

    TpmIdentityDetail::KeyOperationResult createKey() override
    {
        operation_ = QStringLiteral("Creating the TPM identity key");
        status_ = NCryptCreatePersistedKey(
            provider_, key_.put(), NCRYPT_ECDSA_P256_ALGORITHM, KeyName, 0, 0);
        if (status_ == ERROR_SUCCESS)
            return TpmIdentityDetail::KeyOperationResult::Success;
        if (status_ == NTE_EXISTS)
            return TpmIdentityDetail::KeyOperationResult::AlreadyExists;
        return TpmIdentityDetail::KeyOperationResult::Failure;
    }

    bool configureCreatedKey() override
    {
        DWORD exportPolicy = 0;
        operation_ = QStringLiteral("Disabling TPM private-key export");
        status_ = NCryptSetProperty(
            key_.get(),
            NCRYPT_EXPORT_POLICY_PROPERTY,
            reinterpret_cast<PBYTE>(&exportPolicy),
            sizeof(exportPolicy),
            0);
        if (status_ != ERROR_SUCCESS)
            return false;

        DWORD usage = NCRYPT_ALLOW_SIGNING_FLAG;
        operation_ = QStringLiteral("Restricting TPM key usage");
        status_ = NCryptSetProperty(
            key_.get(),
            NCRYPT_KEY_USAGE_PROPERTY,
            reinterpret_cast<PBYTE>(&usage),
            sizeof(usage),
            0);
        return status_ == ERROR_SUCCESS;
    }

    bool finalizeCreatedKey() override
    {
        operation_ = QStringLiteral("Finalizing the TPM identity key");
        status_ = NCryptFinalizeKey(key_.get(), 0);
        return status_ == ERROR_SUCCESS;
    }

    bool validateKey() override
    {
        operation_ = QStringLiteral("Validating the TPM identity key");
        return validateP256Key(key_.get());
    }

    void deleteCreatedKey() override
    {
        const NCRYPT_KEY_HANDLE handle = key_.release();
        if (!handle)
            return;

        if (NCryptDeleteKey(handle, 0) != ERROR_SUCCESS)
            NCryptFreeObject(handle);
    }

    SECURITY_STATUS status() const { return status_; }
    QString operation() const { return operation_; }

private:
    NCRYPT_PROV_HANDLE provider_;
    KeyHandle key_;
    SECURITY_STATUS status_ = ERROR_SUCCESS;
    QString operation_;
};

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

    CngKeyLifecycle lifecycle(provider.get());
    const TpmIdentityDetail::EnsureKeyResult result =
        TpmIdentityDetail::ensureKeyLifecycle(lifecycle);
    if (result == TpmIdentityDetail::EnsureKeyResult::Success)
        return true;
    if (result == TpmIdentityDetail::EnsureKeyResult::ValidationFailed) {
        setError(error, QStringLiteral("The TPM identity key does not satisfy the required security policy."));
        return false;
    }
    setError(error, cngFailure(lifecycle.operation(), lifecycle.status()));
    return false;
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
    if (openPersistedKey(provider.get(), key) != ERROR_SUCCESS)
        return {};

    if (!validateP256Key(key.get()))
        return {};
    return exportPublicKey(key.get());
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
    status = openPersistedKey(provider.get(), key);
    if (status != ERROR_SUCCESS) {
        setError(error, cngFailure(QStringLiteral("Opening the persisted TPM identity key"), status));
        return {};
    }
    if (!validateP256Key(key.get())) {
        setError(error, QStringLiteral("The TPM identity key does not satisfy the required security policy."));
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

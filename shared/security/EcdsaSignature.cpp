#include "EcdsaSignature.h"

#include <QCryptographicHash>

#include <cstring>
#include <limits>

#ifdef Q_OS_WIN
#include <windows.h>
#include <bcrypt.h>

namespace {

class BCryptAlgorithmHandle final
{
public:
    BCryptAlgorithmHandle() = default;
    BCryptAlgorithmHandle(const BCryptAlgorithmHandle &) = delete;
    BCryptAlgorithmHandle &operator=(const BCryptAlgorithmHandle &) = delete;

    ~BCryptAlgorithmHandle()
    {
        if (handle_)
            BCryptCloseAlgorithmProvider(handle_, 0);
    }

    BCRYPT_ALG_HANDLE *put() { return &handle_; }
    BCRYPT_ALG_HANDLE get() const { return handle_; }

private:
    BCRYPT_ALG_HANDLE handle_ = nullptr;
};

class BCryptKeyHandle final
{
public:
    BCryptKeyHandle() = default;
    BCryptKeyHandle(const BCryptKeyHandle &) = delete;
    BCryptKeyHandle &operator=(const BCryptKeyHandle &) = delete;

    ~BCryptKeyHandle()
    {
        if (handle_)
            BCryptDestroyKey(handle_);
    }

    BCRYPT_KEY_HANDLE *put() { return &handle_; }
    BCRYPT_KEY_HANDLE get() const { return handle_; }

private:
    BCRYPT_KEY_HANDLE handle_ = nullptr;
};

constexpr qsizetype P256CoordinateSize = 32;
constexpr qsizetype P256SignatureSize = P256CoordinateSize * 2;
constexpr qsizetype P256PublicBlobSize = sizeof(BCRYPT_ECCKEY_BLOB) + P256CoordinateSize * 2;

bool fitsUlong(QByteArrayView value)
{
    return value.size() >= 0
        && static_cast<quint64>(value.size()) <= std::numeric_limits<ULONG>::max();
}

} // namespace
#endif

bool EcdsaSignature::verifyCngP256(
    QByteArrayView publicBlob,
    QByteArrayView challenge,
    QByteArrayView signature)
{
#ifdef Q_OS_WIN
    if (challenge.isEmpty()
        || publicBlob.size() != P256PublicBlobSize
        || signature.size() != P256SignatureSize
        || !fitsUlong(publicBlob)
        || !fitsUlong(signature)) {
        return false;
    }

    BCRYPT_ECCKEY_BLOB header{};
    std::memcpy(&header, publicBlob.data(), sizeof(header));
    if (header.dwMagic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC
        || header.cbKey != P256CoordinateSize) {
        return false;
    }

    BCryptAlgorithmHandle algorithm;
    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
            algorithm.put(), BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0))) {
        return false;
    }

    BCryptKeyHandle key;
    if (!BCRYPT_SUCCESS(BCryptImportKeyPair(
            algorithm.get(),
            nullptr,
            BCRYPT_ECCPUBLIC_BLOB,
            key.put(),
            reinterpret_cast<PUCHAR>(const_cast<char *>(publicBlob.data())),
            static_cast<ULONG>(publicBlob.size()),
            0))) {
        return false;
    }

    const QByteArray digest = QCryptographicHash::hash(challenge, QCryptographicHash::Sha256);
    return BCRYPT_SUCCESS(BCryptVerifySignature(
        key.get(),
        nullptr,
        reinterpret_cast<PUCHAR>(const_cast<char *>(digest.constData())),
        static_cast<ULONG>(digest.size()),
        reinterpret_cast<PUCHAR>(const_cast<char *>(signature.data())),
        static_cast<ULONG>(signature.size()),
        0));
#else
    Q_UNUSED(publicBlob);
    Q_UNUSED(challenge);
    Q_UNUSED(signature);
    return false;
#endif
}

#include "SessionTokenVerifier.h"

#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QTimeZone>

#include <openssl/evp.h>

SessionTokenVerifier::SessionTokenVerifier(QByteArray publicKey, QString issuer, QString audience, QString product)
    : publicKey_(std::move(publicKey)), issuer_(std::move(issuer)), audience_(std::move(audience)), product_(std::move(product)) {}

// Client clocks can lag behind the issuing server (NTP drift, VM/host clock
// differences). A freshly issued token must not be rejected as "from the
// future" because of a few seconds of skew; the expiry check still bounds the
// token lifetime, so a bounded iat leeway does not weaken replay protection.
// Tokens issued up to maxClockSkewSeconds ahead of the local clock
// (inclusive) are accepted.
constexpr qint64 maxClockSkewSeconds = 60;

SessionTokenVerifier SessionTokenVerifier::fromBase64(const QString &encodedPublicKey, QString issuer, QString audience, QString product)
{
    const QByteArray input = encodedPublicKey.trimmed().toUtf8();
    const QByteArray key = QByteArray::fromBase64(input);
    return SessionTokenVerifier(key.toBase64() == input ? key : QByteArray(), std::move(issuer), std::move(audience), std::move(product));
}

bool SessionTokenVerifier::isConfigured() const { return publicKey_.size() == 32 && !issuer_.trimmed().isEmpty() && !audience_.trimmed().isEmpty() && !product_.trimmed().isEmpty(); }

VerificationResult SessionTokenVerifier::verify(const QString &token, const QString &expectedDevice, const QString &expectedLicense) const
{
    const QList<QByteArray> parts = token.toUtf8().split('.');
    if (!isConfigured() || parts.size() != 3 || token.size() > 16 * 1024 || expectedDevice.isEmpty() || expectedLicense.isEmpty()) return {false, QStringLiteral("Invalid session token."), {}};
    const auto decode = [](const QByteArray &part) { const QByteArray raw = QByteArray::fromBase64(part, QByteArray::Base64UrlEncoding); return raw.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals) == part ? raw : QByteArray(); };
    const QByteArray headerBytes = decode(parts[0]), payloadBytes = decode(parts[1]), signature = decode(parts[2]);
    const QJsonDocument header = QJsonDocument::fromJson(headerBytes), payload = QJsonDocument::fromJson(payloadBytes);
    if (!header.isObject() || !payload.isObject() || signature.size() != 64) return {false, QStringLiteral("Invalid session token."), {}};
    const QJsonObject jose = header.object();
    if (jose.size() != 2 || !jose.contains(QStringLiteral("alg")) || !jose.contains(QStringLiteral("typ")) || jose.value(QStringLiteral("alg")).toString() != QStringLiteral("EdDSA") || jose.value(QStringLiteral("typ")).toString() != QStringLiteral("JWT") || !verifySignature(parts[0] + '.' + parts[1], signature)) return {false, QStringLiteral("Invalid session token."), {}};
    const QJsonObject claims = payload.object();
    const qint64 iat = claims.value(QStringLiteral("iat")).toInteger(-1), exp = claims.value(QStringLiteral("exp")).toInteger(-1), now = QDateTime::currentSecsSinceEpoch();
    const QJsonValue features = claims.value(QStringLiteral("features"));
    if (!features.isArray()) return {false, QStringLiteral("Invalid session token."), {}};
    for (const QJsonValue &feature : features.toArray()) if (!feature.isString()) return {false, QStringLiteral("Invalid session token."), {}};
    if (claims.value(QStringLiteral("iss")).toString() != issuer_ || claims.value(QStringLiteral("aud")).toString() != audience_ || claims.value(QStringLiteral("product")).toString() != product_ || claims.value(QStringLiteral("device_id")).toString() != expectedDevice || claims.value(QStringLiteral("license_id")).toString() != expectedLicense || claims.value(QStringLiteral("sub")).toString().isEmpty() || iat < 0 || exp <= now || iat > now + maxClockSkewSeconds || exp - iat != 3600) return {false, QStringLiteral("Invalid session token."), {}};
    return {true, {}, QDateTime::fromSecsSinceEpoch(exp, QTimeZone::UTC)};
}

bool SessionTokenVerifier::verifySignature(const QByteArray &message, const QByteArray &signature) const
{
    EVP_PKEY *publicKey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr,
        reinterpret_cast<const unsigned char *>(publicKey_.constData()), publicKey_.size());
    if (publicKey == nullptr) return false;
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    const bool valid = context != nullptr &&
        EVP_DigestVerifyInit(context, nullptr, nullptr, nullptr, publicKey) == 1 &&
        EVP_DigestVerify(context,
            reinterpret_cast<const unsigned char *>(signature.constData()), signature.size(),
            reinterpret_cast<const unsigned char *>(message.constData()), message.size()) == 1;
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(publicKey);
    return valid;
}

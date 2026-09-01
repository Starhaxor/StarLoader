#include "SessionTokenVerifier.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSet>
#include <QTimeZone>

#include <cmath>
#include <limits>

#include <openssl/evp.h>

namespace {
constexpr qint64 kMaxClockSkewSeconds = 60;
constexpr qint64 kRequiredLifetimeSeconds = 600;
constexpr qsizetype kMaximumTokenBytes = 16 * 1024;

VerifiedSession invalidSession()
{
    return {false, QStringLiteral("Invalid session token."), {}, {}, {}, {}};
}

void skipWhitespace(const QByteArray &json, qsizetype *position)
{
    while (*position < json.size() && (json.at(*position) == ' ' || json.at(*position) == '\n' || json.at(*position) == '\r' || json.at(*position) == '\t')) ++*position;
}

bool consumeString(const QByteArray &json, qsizetype *position, QString *value)
{
    if (*position >= json.size() || json.at(*position) != '"') return false;
    const qsizetype begin = *position;
    ++*position;
    while (*position < json.size()) {
        const char current = json.at(*position);
        if (current == '"') {
            ++*position;
            const QJsonDocument parsed = QJsonDocument::fromJson('[' + json.mid(begin, *position - begin) + ']');
            if (!parsed.isArray() || parsed.array().size() != 1 || !parsed.array().at(0).isString()) return false;
            *value = parsed.array().at(0).toString();
            return true;
        }
        if (current == '\\') {
            ++*position;
            if (*position >= json.size()) return false;
        } else if (static_cast<unsigned char>(current) < 0x20) {
            return false;
        }
        ++*position;
    }
    return false;
}

bool scanJsonValue(const QByteArray &json, qsizetype *position, int depth)
{
    if (depth > 64) return false;
    skipWhitespace(json, position);
    if (*position >= json.size()) return false;
    if (json.at(*position) == '{') {
        ++*position;
        skipWhitespace(json, position);
        QSet<QString> members;
        if (*position < json.size() && json.at(*position) == '}') { ++*position; return true; }
        while (*position < json.size()) {
            QString member;
            if (!consumeString(json, position, &member) || members.contains(member)) return false;
            members.insert(member);
            skipWhitespace(json, position);
            if (*position >= json.size() || json.at(*position) != ':') return false;
            ++*position;
            if (!scanJsonValue(json, position, depth + 1)) return false;
            skipWhitespace(json, position);
            if (*position >= json.size()) return false;
            if (json.at(*position) == '}') { ++*position; return true; }
            if (json.at(*position) != ',') return false;
            ++*position;
            skipWhitespace(json, position);
        }
        return false;
    }
    if (json.at(*position) == '[') {
        ++*position;
        skipWhitespace(json, position);
        if (*position < json.size() && json.at(*position) == ']') { ++*position; return true; }
        while (*position < json.size()) {
            if (!scanJsonValue(json, position, depth + 1)) return false;
            skipWhitespace(json, position);
            if (*position >= json.size()) return false;
            if (json.at(*position) == ']') { ++*position; return true; }
            if (json.at(*position) != ',') return false;
            ++*position;
            skipWhitespace(json, position);
        }
        return false;
    }
    if (json.at(*position) == '"') {
        QString ignored;
        return consumeString(json, position, &ignored);
    }
    const qsizetype begin = *position;
    while (*position < json.size() && json.at(*position) != ',' && json.at(*position) != '}' && json.at(*position) != ']' && json.at(*position) != ' ' && json.at(*position) != '\n' && json.at(*position) != '\r' && json.at(*position) != '\t') ++*position;
    return *position > begin;
}

bool hasUniqueJsonMembers(const QByteArray &json)
{
    qsizetype position = 0;
    if (!scanJsonValue(json, &position, 0)) return false;
    skipWhitespace(json, &position);
    return position == json.size();
}

bool decodeCanonicalBase64Url(const QByteArray &encoded, QByteArray *decoded)
{
    if (encoded.isEmpty() || encoded.contains('=') || encoded.contains('+') || encoded.contains('/')) return false;
    const QByteArray value = QByteArray::fromBase64(encoded, QByteArray::Base64UrlEncoding);
    if (value.isEmpty() || value.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals) != encoded) return false;
    *decoded = value;
    return true;
}

bool decodeCanonicalStandardBase64Key(const QString &encoded, QByteArray *decoded)
{
    const QByteArray input = encoded.toLatin1();
    if (input.size() != 44 || input.at(43) != '=') return false;
    const QByteArray value = QByteArray::fromBase64(input);
    if (value.size() != 32 || value.toBase64() != input) return false;
    *decoded = value;
    return true;
}

bool validKeyId(const QString &keyId)
{
    if (keyId.isEmpty()) return false;
    for (const QChar character : keyId) {
        const ushort value = character.unicode();
        if (!((value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') || value == '.' || value == '_' || value == '-')) return false;
    }
    return true;
}

bool validStringClaim(const QJsonObject &claims, const QString &name, QString *value)
{
    const QJsonValue claim = claims.value(name);
    if (!claims.contains(name) || !claim.isString() || claim.toString().isEmpty()) return false;
    *value = claim.toString();
    return true;
}

bool validIntegerClaim(const QJsonObject &claims, const QString &name, qint64 *value)
{
    const QJsonValue claim = claims.value(name);
    if (!claims.contains(name) || !claim.isDouble()) return false;
    const double number = claim.toDouble();
    if (!std::isfinite(number) || number < 0 || number > static_cast<double>(std::numeric_limits<qint64>::max()) || std::floor(number) != number) return false;
    const qint64 integer = static_cast<qint64>(number);
    if (static_cast<double>(integer) != number) return false;
    *value = integer;
    return true;
}
} // namespace

SessionTokenVerifier::SessionTokenVerifier(QHash<QString, QByteArray> keys, QString issuer, QString audience, QString applicationID, QString productID, QString product)
    : keys_(std::move(keys)), issuer_(std::move(issuer)), audience_(std::move(audience)), applicationID_(std::move(applicationID)), productID_(std::move(productID)), product_(std::move(product)) {}

SessionTokenVerifier SessionTokenVerifier::fromConfiguredKeyRing(const QString &encodedKeys, QString issuer, QString audience, QString applicationID, QString productID, QString product)
{
    QHash<QString, QByteArray> keys;
    const QStringList entries = encodedKeys.split(',', Qt::KeepEmptyParts);
    for (const QString &entry : entries) {
        const qsizetype separator = entry.indexOf('=');
        if (separator <= 0 || separator + 1 >= entry.size()) return SessionTokenVerifier({}, {}, {}, {}, {}, {});
        const QString kid = entry.left(separator);
        QByteArray publicKey;
        if (!validKeyId(kid) || keys.contains(kid) || !decodeCanonicalStandardBase64Key(entry.mid(separator + 1), &publicKey)) return SessionTokenVerifier({}, {}, {}, {}, {}, {});
        keys.insert(kid, publicKey);
    }
    return SessionTokenVerifier(std::move(keys), std::move(issuer), std::move(audience), std::move(applicationID), std::move(productID), std::move(product));
}

bool SessionTokenVerifier::isConfigured() const
{
    if (keys_.isEmpty() || issuer_.trimmed().isEmpty() || audience_.trimmed().isEmpty() || applicationID_.trimmed().isEmpty() || productID_.trimmed().isEmpty() || product_.trimmed().isEmpty()) return false;
    for (auto it = keys_.cbegin(); it != keys_.cend(); ++it) if (!validKeyId(it.key()) || it.value().size() != 32) return false;
    return true;
}

VerifiedSession SessionTokenVerifier::verify(const QString &token, const QString &expectedDevice, const QString &expectedLicense) const
{
    const QByteArray tokenBytes = token.toUtf8();
    const QList<QByteArray> parts = tokenBytes.split('.');
    if (!isConfigured() || tokenBytes.size() > kMaximumTokenBytes || parts.size() != 3 || expectedDevice.isEmpty() || expectedLicense.isEmpty()) return invalidSession();
    QByteArray headerBytes, payloadBytes, signature;
    if (!decodeCanonicalBase64Url(parts.at(0), &headerBytes) || !decodeCanonicalBase64Url(parts.at(1), &payloadBytes) || !decodeCanonicalBase64Url(parts.at(2), &signature) || signature.size() != 64 || !hasUniqueJsonMembers(headerBytes) || !hasUniqueJsonMembers(payloadBytes)) return invalidSession();
    const QJsonDocument headerDocument = QJsonDocument::fromJson(headerBytes);
    const QJsonDocument payloadDocument = QJsonDocument::fromJson(payloadBytes);
    if (!headerDocument.isObject() || !payloadDocument.isObject()) return invalidSession();
    const QJsonObject header = headerDocument.object();
    if (header.size() != 3 || !header.contains(QStringLiteral("alg")) || !header.contains(QStringLiteral("typ")) || !header.contains(QStringLiteral("kid")) || !header.value(QStringLiteral("alg")).isString() || !header.value(QStringLiteral("typ")).isString() || !header.value(QStringLiteral("kid")).isString() || header.value(QStringLiteral("alg")).toString() != QStringLiteral("EdDSA") || header.value(QStringLiteral("typ")).toString() != QStringLiteral("JWT")) return invalidSession();
    const auto key = keys_.constFind(header.value(QStringLiteral("kid")).toString());
    if (key == keys_.cend() || !verifySignature(key.value(), parts.at(0) + '.' + parts.at(1), signature)) return invalidSession();

    const QJsonObject claims = payloadDocument.object();
    QString subject, issuer, audience, applicationID, productID, product, license, device, sessionID, tokenID;
    qint64 issuedAt = 0, notBefore = 0, expiresAt = 0;
    if (!validStringClaim(claims, QStringLiteral("iss"), &issuer) || !validStringClaim(claims, QStringLiteral("aud"), &audience) || !validStringClaim(claims, QStringLiteral("sub"), &subject) || !validStringClaim(claims, QStringLiteral("app"), &applicationID) || !validStringClaim(claims, QStringLiteral("product_id"), &productID) || !validStringClaim(claims, QStringLiteral("product"), &product) || !validStringClaim(claims, QStringLiteral("license_id"), &license) || !validStringClaim(claims, QStringLiteral("device_id"), &device) || !validStringClaim(claims, QStringLiteral("sid"), &sessionID) || !validStringClaim(claims, QStringLiteral("jti"), &tokenID) || !validIntegerClaim(claims, QStringLiteral("iat"), &issuedAt) || !validIntegerClaim(claims, QStringLiteral("nbf"), &notBefore) || !validIntegerClaim(claims, QStringLiteral("exp"), &expiresAt)) return invalidSession();
    const QJsonValue features = claims.value(QStringLiteral("features"));
    const QJsonValue confirmation = claims.value(QStringLiteral("cnf"));
    if (!features.isArray() || !confirmation.isObject()) return invalidSession();
    for (const QJsonValue &feature : features.toArray()) if (!feature.isString()) return invalidSession();
    const QJsonObject confirmationObject = confirmation.toObject();
    QString thumbprint;
    QByteArray thumbprintBytes;
    if (!validStringClaim(confirmationObject, QStringLiteral("jkt"), &thumbprint) || !decodeCanonicalBase64Url(thumbprint.toLatin1(), &thumbprintBytes) || thumbprintBytes.size() != 32) return invalidSession();

    const qint64 now = QDateTime::currentSecsSinceEpoch();
    if (issuer != issuer_ || audience != audience_ || applicationID != applicationID_ || productID != productID_ || product != product_ || license != expectedLicense || device != expectedDevice || issuedAt > now + kMaxClockSkewSeconds || notBefore > now + kMaxClockSkewSeconds || expiresAt <= now || expiresAt <= issuedAt || expiresAt - issuedAt != kRequiredLifetimeSeconds || notBefore > expiresAt) return invalidSession();
    return {true, {}, QDateTime::fromSecsSinceEpoch(expiresAt, QTimeZone::UTC), sessionID, tokenID, thumbprint};
}

bool SessionTokenVerifier::verifySignature(const QByteArray &publicKeyBytes, const QByteArray &message, const QByteArray &signature) const
{
    EVP_PKEY *publicKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char *>(publicKeyBytes.constData()), publicKeyBytes.size());
    if (publicKey == nullptr) return false;
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    const bool valid = context != nullptr && EVP_DigestVerifyInit(context, nullptr, nullptr, nullptr, publicKey) == 1 && EVP_DigestVerify(context, reinterpret_cast<const unsigned char *>(signature.constData()), signature.size(), reinterpret_cast<const unsigned char *>(message.constData()), message.size()) == 1;
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(publicKey);
    return valid;
}

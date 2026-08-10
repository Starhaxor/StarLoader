#include "security/SessionTokenVerifier.h"

#include <QJsonDocument>
#include <QtTest>

#include <openssl/evp.h>

namespace {
QByteArray testPrivateKey() { return QByteArray(32, '\x05'); }

QByteArray testPublicKey()
{
    const QByteArray privateKey = testPrivateKey();
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char *>(privateKey.constData()), privateKey.size());
    QByteArray publicKey(32, Qt::Uninitialized); size_t publicKeySize = static_cast<size_t>(publicKey.size());
    if (key == nullptr || EVP_PKEY_get_raw_public_key(key, reinterpret_cast<unsigned char *>(publicKey.data()), &publicKeySize) != 1 || publicKeySize != 32) publicKey.clear();
    EVP_PKEY_free(key); return publicKey;
}

QString signedToken(const QJsonObject &claims, QJsonObject header = {{QStringLiteral("alg"), QStringLiteral("EdDSA")}, {QStringLiteral("typ"), QStringLiteral("JWT")}})
{
    const QByteArray encodedHeader = QJsonDocument(header).toJson(QJsonDocument::Compact).toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    const QByteArray payload = QJsonDocument(claims).toJson(QJsonDocument::Compact).toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    const QByteArray message = encodedHeader + '.' + payload, privateKey = testPrivateKey();
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char *>(privateKey.constData()), privateKey.size());
    EVP_MD_CTX *context = EVP_MD_CTX_new(); size_t size = 0;
    if (key == nullptr || context == nullptr || EVP_DigestSignInit(context, nullptr, nullptr, nullptr, key) != 1 || EVP_DigestSign(context, nullptr, &size, reinterpret_cast<const unsigned char *>(message.constData()), message.size()) != 1) { EVP_MD_CTX_free(context); EVP_PKEY_free(key); return {}; }
    QByteArray signature(static_cast<qsizetype>(size), Qt::Uninitialized);
    if (EVP_DigestSign(context, reinterpret_cast<unsigned char *>(signature.data()), &size, reinterpret_cast<const unsigned char *>(message.constData()), message.size()) != 1) signature.clear();
    EVP_MD_CTX_free(context); EVP_PKEY_free(key);
    return QString::fromUtf8(message + '.' + signature.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}

QJsonObject validClaims()
{
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    return {{QStringLiteral("sub"), QStringLiteral("user-1")}, {QStringLiteral("license_id"), QStringLiteral("license-1")}, {QStringLiteral("device_id"), QStringLiteral("device-1")}, {QStringLiteral("product"), QStringLiteral("StarLoader")}, {QStringLiteral("features"), QJsonArray{}}, {QStringLiteral("iss"), QStringLiteral("starloader")}, {QStringLiteral("aud"), QStringLiteral("starloader-client")}, {QStringLiteral("iat"), now}, {QStringLiteral("exp"), now + 3600}};
}
} // namespace

class SessionTokenVerifierTest final : public QObject
{
    Q_OBJECT
private slots:
    void acceptsKnownValidEd25519Token();
    void rejectsTamperedPayloadAndSignature();
    void rejectsMalformedToken();
    void rejectsInvalidPublicKeyAtStartup();
    void rejectsMissingOrMalformedFeatures();
    void rejectsUnknownJoseHeadersAndCriticalHeaders();
};

void SessionTokenVerifierTest::acceptsKnownValidEd25519Token()
{
    SessionTokenVerifier verifier(testPublicKey(), QStringLiteral("starloader"), QStringLiteral("starloader-client"), QStringLiteral("StarLoader"));
    const VerificationResult result = verifier.verify(signedToken(validClaims()), QStringLiteral("device-1"), QStringLiteral("license-1"));
    QVERIFY(result.valid);
    QVERIFY(result.expiresAt.isValid());
}

void SessionTokenVerifierTest::rejectsTamperedPayloadAndSignature()
{
    SessionTokenVerifier verifier(testPublicKey(), QStringLiteral("starloader"), QStringLiteral("starloader-client"), QStringLiteral("StarLoader"));
    const QString token = signedToken(validClaims());
    QString payloadTampered = token; payloadTampered[payloadTampered.indexOf('.') + 2] = payloadTampered[payloadTampered.indexOf('.') + 2] == 'A' ? 'B' : 'A';
    QVERIFY(!verifier.verify(payloadTampered, QStringLiteral("device-1"), QStringLiteral("license-1")).valid);
    QString signatureTampered = token; signatureTampered[signatureTampered.lastIndexOf('.') + 1] = signatureTampered[signatureTampered.lastIndexOf('.') + 1] == 'A' ? 'B' : 'A';
    QVERIFY(!verifier.verify(signatureTampered, QStringLiteral("device-1"), QStringLiteral("license-1")).valid);
}

void SessionTokenVerifierTest::rejectsMalformedToken()
{
    SessionTokenVerifier verifier(testPublicKey(), QStringLiteral("starloader"), QStringLiteral("starloader-client"), QStringLiteral("StarLoader"));
    QVERIFY(!verifier.verify(QStringLiteral("not.a.token"), QStringLiteral("device"), QStringLiteral("license")).valid);
}

void SessionTokenVerifierTest::rejectsInvalidPublicKeyAtStartup()
{
    SessionTokenVerifier verifier(QByteArrayLiteral("bad"), QStringLiteral("starloader"), QStringLiteral("starloader-client"), QStringLiteral("StarLoader"));
    QVERIFY(!verifier.isConfigured());
}

void SessionTokenVerifierTest::rejectsMissingOrMalformedFeatures()
{
    SessionTokenVerifier verifier(testPublicKey(), QStringLiteral("starloader"), QStringLiteral("starloader-client"), QStringLiteral("StarLoader"));
    QJsonObject missing = validClaims(); missing.remove(QStringLiteral("features"));
    QVERIFY(!verifier.verify(signedToken(missing), QStringLiteral("device-1"), QStringLiteral("license-1")).valid);
    QJsonObject scalar = validClaims(); scalar[QStringLiteral("features")] = QStringLiteral("feature");
    QVERIFY(!verifier.verify(signedToken(scalar), QStringLiteral("device-1"), QStringLiteral("license-1")).valid);
    QJsonObject nonString = validClaims(); nonString[QStringLiteral("features")] = QJsonArray{QStringLiteral("feature"), 3};
    QVERIFY(!verifier.verify(signedToken(nonString), QStringLiteral("device-1"), QStringLiteral("license-1")).valid);
}

void SessionTokenVerifierTest::rejectsUnknownJoseHeadersAndCriticalHeaders()
{
    SessionTokenVerifier verifier(testPublicKey(), QStringLiteral("starloader"), QStringLiteral("starloader-client"), QStringLiteral("StarLoader"));
    QVERIFY(!verifier.verify(signedToken(validClaims(), {{QStringLiteral("alg"), QStringLiteral("EdDSA")}, {QStringLiteral("typ"), QStringLiteral("JWT")}, {QStringLiteral("kid"), QStringLiteral("unexpected")}}), QStringLiteral("device-1"), QStringLiteral("license-1")).valid);
    QVERIFY(!verifier.verify(signedToken(validClaims(), {{QStringLiteral("alg"), QStringLiteral("EdDSA")}, {QStringLiteral("typ"), QStringLiteral("JWT")}, {QStringLiteral("crit"), QJsonArray{QStringLiteral("exp")}}}), QStringLiteral("device-1"), QStringLiteral("license-1")).valid);
}

QTEST_MAIN(SessionTokenVerifierTest)
#include "SessionTokenVerifierTest.moc"

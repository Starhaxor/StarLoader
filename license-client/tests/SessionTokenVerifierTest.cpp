#include "security/SessionTokenVerifier.h"

#include <QJsonDocument>
#include <QJsonArray>
#include <QtTest>

#include <openssl/evp.h>

namespace {
const QString kIssuer = QStringLiteral("keystar");
const QString kAudience = QStringLiteral("keystar-clients");
const QString kApplicationId = QStringLiteral("app-1");
const QString kProductId = QStringLiteral("product-1");
const QString kProduct = QStringLiteral("StarLoader");
const QString kKid = QStringLiteral("test-kid");
const QString kDevice = QStringLiteral("device-1");
const QString kLicense = QStringLiteral("license-1");
const QString kJkt = QStringLiteral("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

QByteArray testPrivateKey() { return QByteArray(32, '\x05'); }

QByteArray testPublicKey()
{
    const QByteArray privateKey = testPrivateKey();
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char *>(privateKey.constData()), privateKey.size());
    QByteArray publicKey(32, Qt::Uninitialized); size_t publicKeySize = static_cast<size_t>(publicKey.size());
    if (key == nullptr || EVP_PKEY_get_raw_public_key(key, reinterpret_cast<unsigned char *>(publicKey.data()), &publicKeySize) != 1 || publicKeySize != 32) publicKey.clear();
    EVP_PKEY_free(key); return publicKey;
}

QHash<QString, QByteArray> testKeyRing() { return {{kKid, testPublicKey()}}; }

SessionTokenVerifier verifier()
{
    return SessionTokenVerifier(testKeyRing(), kIssuer, kAudience, kApplicationId, kProductId, kProduct);
}

QJsonObject validHeader(QString kid = kKid)
{
    return {{QStringLiteral("alg"), QStringLiteral("EdDSA")}, {QStringLiteral("typ"), QStringLiteral("JWT")}, {QStringLiteral("kid"), std::move(kid)}};
}

QJsonObject validClaims(qint64 lifetimeSeconds = 600, qint64 iatOffsetSeconds = 0, qint64 nbfOffsetSeconds = 0)
{
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    const qint64 iat = now + iatOffsetSeconds;
    return {
        {QStringLiteral("iss"), kIssuer}, {QStringLiteral("aud"), kAudience},
        {QStringLiteral("sub"), QStringLiteral("user-1")}, {QStringLiteral("app"), kApplicationId},
        {QStringLiteral("product_id"), kProductId}, {QStringLiteral("product"), kProduct},
        {QStringLiteral("license_id"), kLicense}, {QStringLiteral("device_id"), kDevice},
        {QStringLiteral("sid"), QStringLiteral("session-1")}, {QStringLiteral("jti"), QStringLiteral("token-1")},
        {QStringLiteral("iat"), iat}, {QStringLiteral("nbf"), iat + nbfOffsetSeconds}, {QStringLiteral("exp"), iat + lifetimeSeconds},
        {QStringLiteral("features"), QJsonArray{}}, {QStringLiteral("cnf"), QJsonObject{{QStringLiteral("jkt"), kJkt}}},
    };
}

QString signedEncoded(const QByteArray &encodedHeader, const QByteArray &encodedPayload)
{
    const QByteArray message = encodedHeader + '.' + encodedPayload;
    const QByteArray privateKey = testPrivateKey();
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char *>(privateKey.constData()), privateKey.size());
    EVP_MD_CTX *context = EVP_MD_CTX_new(); size_t size = 0;
    if (key == nullptr || context == nullptr || EVP_DigestSignInit(context, nullptr, nullptr, nullptr, key) != 1 || EVP_DigestSign(context, nullptr, &size, reinterpret_cast<const unsigned char *>(message.constData()), message.size()) != 1) { EVP_MD_CTX_free(context); EVP_PKEY_free(key); return {}; }
    QByteArray signature(static_cast<qsizetype>(size), Qt::Uninitialized);
    if (EVP_DigestSign(context, reinterpret_cast<unsigned char *>(signature.data()), &size, reinterpret_cast<const unsigned char *>(message.constData()), message.size()) != 1) signature.clear();
    EVP_MD_CTX_free(context); EVP_PKEY_free(key);
    return QString::fromUtf8(message + '.' + signature.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}

QString signedToken(const QJsonObject &claims, const QJsonObject &header = validHeader())
{
    return signedEncoded(QJsonDocument(header).toJson(QJsonDocument::Compact).toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals),
                         QJsonDocument(claims).toJson(QJsonDocument::Compact).toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}

QString signedRawToken(const QByteArray &header, const QByteArray &payload)
{
    return signedEncoded(header.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals), payload.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}

void verifyRejected(const VerifiedSession &result)
{
    QVERIFY(!result.valid);
    QCOMPARE(result.error, QStringLiteral("Invalid session token."));
    QVERIFY(!result.expiresAt.isValid());
    QVERIFY(result.sessionId.isEmpty());
    QVERIFY(result.tokenId.isEmpty());
    QVERIFY(result.deviceKeyThumbprint.isEmpty());
}
} // namespace

class SessionTokenVerifierTest final : public QObject
{
    Q_OBJECT
private slots:
    void acceptsExact600SecondApplicationBoundToken();
    void rejectsInvalidBindings_data();
    void rejectsInvalidBindings();
    void rejectsDuplicateJsonMembers();
    void rejectsNonCanonicalBase64Url();
    void rejectsInvalidConfiguredKeyRing();
};

void SessionTokenVerifierTest::acceptsExact600SecondApplicationBoundToken()
{
    const QJsonObject claims = validClaims();
    const VerifiedSession result = verifier().verify(signedToken(claims), kDevice, kLicense);
    QVERIFY(result.valid);
    QVERIFY(result.error.isEmpty());
    QCOMPARE(result.expiresAt, QDateTime::fromSecsSinceEpoch(claims.value(QStringLiteral("exp")).toInteger(), QTimeZone::UTC));
    QCOMPARE(result.sessionId, QStringLiteral("session-1"));
    QCOMPARE(result.tokenId, QStringLiteral("token-1"));
    QCOMPARE(result.deviceKeyThumbprint, kJkt);
}

void SessionTokenVerifierTest::rejectsInvalidBindings_data()
{
    QTest::addColumn<QString>("mutation");
    QTest::newRow("unknown-kid") << QStringLiteral("unknown-kid");
    QTest::newRow("extra-jose-member") << QStringLiteral("extra-jose-member");
    QTest::newRow("missing-issuer") << QStringLiteral("missing-issuer");
    QTest::newRow("missing-audience") << QStringLiteral("missing-audience");
    QTest::newRow("missing-subject") << QStringLiteral("missing-subject");
    QTest::newRow("missing-app") << QStringLiteral("missing-app");
    QTest::newRow("missing-product-id") << QStringLiteral("missing-product-id");
    QTest::newRow("missing-product") << QStringLiteral("missing-product");
    QTest::newRow("missing-license") << QStringLiteral("missing-license");
    QTest::newRow("missing-device") << QStringLiteral("missing-device");
    QTest::newRow("missing-sid") << QStringLiteral("missing-sid");
    QTest::newRow("missing-jti") << QStringLiteral("missing-jti");
    QTest::newRow("missing-iat") << QStringLiteral("missing-iat");
    QTest::newRow("missing-nbf") << QStringLiteral("missing-nbf");
    QTest::newRow("missing-exp") << QStringLiteral("missing-exp");
    QTest::newRow("missing-features") << QStringLiteral("missing-features");
    QTest::newRow("missing-cnf") << QStringLiteral("missing-cnf");
    QTest::newRow("missing-cnf-jkt") << QStringLiteral("missing-cnf-jkt");
    QTest::newRow("wrong-app") << QStringLiteral("wrong-app");
    QTest::newRow("wrong-product-id") << QStringLiteral("wrong-product-id");
    QTest::newRow("wrong-product") << QStringLiteral("wrong-product");
    QTest::newRow("wrong-device") << QStringLiteral("wrong-device");
    QTest::newRow("wrong-license") << QStringLiteral("wrong-license");
    QTest::newRow("malformed-jkt") << QStringLiteral("malformed-jkt");
    QTest::newRow("nbf-outside-skew") << QStringLiteral("nbf-outside-skew");
    QTest::newRow("lifetime-599") << QStringLiteral("lifetime-599");
    QTest::newRow("lifetime-601") << QStringLiteral("lifetime-601");
    QTest::newRow("lifetime-3600") << QStringLiteral("lifetime-3600");
}

void SessionTokenVerifierTest::rejectsInvalidBindings()
{
    QFETCH(QString, mutation);
    QJsonObject claims = validClaims();
    QJsonObject header = validHeader();
    QString expectedDevice = kDevice;
    QString expectedLicense = kLicense;
    if (mutation == QStringLiteral("unknown-kid")) header = validHeader(QStringLiteral("unknown"));
    else if (mutation == QStringLiteral("extra-jose-member")) header.insert(QStringLiteral("crit"), QJsonArray{QStringLiteral("exp")});
    else if (mutation == QStringLiteral("missing-issuer")) claims.remove(QStringLiteral("iss"));
    else if (mutation == QStringLiteral("missing-audience")) claims.remove(QStringLiteral("aud"));
    else if (mutation == QStringLiteral("missing-subject")) claims.remove(QStringLiteral("sub"));
    else if (mutation == QStringLiteral("missing-app")) claims.remove(QStringLiteral("app"));
    else if (mutation == QStringLiteral("missing-product-id")) claims.remove(QStringLiteral("product_id"));
    else if (mutation == QStringLiteral("missing-product")) claims.remove(QStringLiteral("product"));
    else if (mutation == QStringLiteral("missing-license")) claims.remove(QStringLiteral("license_id"));
    else if (mutation == QStringLiteral("missing-device")) claims.remove(QStringLiteral("device_id"));
    else if (mutation == QStringLiteral("missing-sid")) claims.remove(QStringLiteral("sid"));
    else if (mutation == QStringLiteral("missing-jti")) claims.remove(QStringLiteral("jti"));
    else if (mutation == QStringLiteral("missing-iat")) claims.remove(QStringLiteral("iat"));
    else if (mutation == QStringLiteral("missing-nbf")) claims.remove(QStringLiteral("nbf"));
    else if (mutation == QStringLiteral("missing-exp")) claims.remove(QStringLiteral("exp"));
    else if (mutation == QStringLiteral("missing-features")) claims.remove(QStringLiteral("features"));
    else if (mutation == QStringLiteral("missing-cnf")) claims.remove(QStringLiteral("cnf"));
    else if (mutation == QStringLiteral("missing-cnf-jkt")) claims.insert(QStringLiteral("cnf"), QJsonObject{});
    else if (mutation == QStringLiteral("wrong-app")) claims.insert(QStringLiteral("app"), QStringLiteral("other-app"));
    else if (mutation == QStringLiteral("wrong-product-id")) claims.insert(QStringLiteral("product_id"), QStringLiteral("other-product"));
    else if (mutation == QStringLiteral("wrong-product")) claims.insert(QStringLiteral("product"), QStringLiteral("Other"));
    else if (mutation == QStringLiteral("wrong-device")) expectedDevice = QStringLiteral("other-device");
    else if (mutation == QStringLiteral("wrong-license")) expectedLicense = QStringLiteral("other-license");
    else if (mutation == QStringLiteral("malformed-jkt")) claims.insert(QStringLiteral("cnf"), QJsonObject{{QStringLiteral("jkt"), QStringLiteral("not-a-thumbprint")}});
    else if (mutation == QStringLiteral("nbf-outside-skew")) claims.insert(QStringLiteral("nbf"), QDateTime::currentSecsSinceEpoch() + 61);
    else if (mutation == QStringLiteral("lifetime-599")) claims = validClaims(599);
    else if (mutation == QStringLiteral("lifetime-601")) claims = validClaims(601);
    else if (mutation == QStringLiteral("lifetime-3600")) claims = validClaims(3600);
    else QFAIL("unhandled test case");
    verifyRejected(verifier().verify(signedToken(claims, header), expectedDevice, expectedLicense));
}

void SessionTokenVerifierTest::rejectsDuplicateJsonMembers()
{
    const QByteArray duplicateHeader = R"({"alg":"EdDSA","typ":"JWT","kid":"test-kid","kid":"test-kid"})";
    verifyRejected(verifier().verify(signedRawToken(duplicateHeader, QJsonDocument(validClaims()).toJson(QJsonDocument::Compact)), kDevice, kLicense));

    const QByteArray validPayload = QJsonDocument(validClaims()).toJson(QJsonDocument::Compact);
    const QByteArray duplicatePayload = validPayload.left(validPayload.size() - 1) + R"(,"sid":"other-session"})";
    verifyRejected(verifier().verify(signedRawToken(QJsonDocument(validHeader()).toJson(QJsonDocument::Compact), duplicatePayload), kDevice, kLicense));
}

void SessionTokenVerifierTest::rejectsNonCanonicalBase64Url()
{
    const QByteArray header = QJsonDocument(validHeader()).toJson(QJsonDocument::Compact);
    QByteArray encodedHeader = header.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    QVERIFY(encodedHeader.size() % 4 != 0);
    const QByteArray alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const int lastIndex = alphabet.indexOf(encodedHeader.back());
    QVERIFY(lastIndex >= 0);
    encodedHeader[encodedHeader.size() - 1] = alphabet.at(lastIndex ^ 1);
    const QByteArray encodedPayload = QJsonDocument(validClaims()).toJson(QJsonDocument::Compact).toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    verifyRejected(verifier().verify(signedEncoded(encodedHeader, encodedPayload), kDevice, kLicense));
}

void SessionTokenVerifierTest::rejectsInvalidConfiguredKeyRing()
{
    const QString goodKey = QString::fromLatin1(testPublicKey().toBase64());
    QVERIFY(SessionTokenVerifier::fromConfiguredKeyRing(QStringLiteral("test-kid=%1").arg(goodKey), kIssuer, kAudience, kApplicationId, kProductId, kProduct).isConfigured());
    QVERIFY(!SessionTokenVerifier::fromConfiguredKeyRing(QStringLiteral("test-kid=not-base64"), kIssuer, kAudience, kApplicationId, kProductId, kProduct).isConfigured());
    QString nonCanonicalKey = goodKey;
    const QByteArray standardAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const int finalCharacterIndex = standardAlphabet.indexOf(nonCanonicalKey.at(42).toLatin1());
    QVERIFY(finalCharacterIndex >= 0);
    nonCanonicalKey[42] = QChar::fromLatin1(standardAlphabet.at(finalCharacterIndex ^ 1));
    QVERIFY(!SessionTokenVerifier::fromConfiguredKeyRing(QStringLiteral("test-kid=%1").arg(nonCanonicalKey), kIssuer, kAudience, kApplicationId, kProductId, kProduct).isConfigured());
    QVERIFY(!SessionTokenVerifier::fromConfiguredKeyRing(QStringLiteral("first=%1,first=%1").arg(goodKey), kIssuer, kAudience, kApplicationId, kProductId, kProduct).isConfigured());
}

QTEST_MAIN(SessionTokenVerifierTest)
#include "SessionTokenVerifierTest.moc"

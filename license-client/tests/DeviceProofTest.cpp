#include "security/DeviceProof.h"
#include "ClientSecurityConfig.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QtTest>

#include <type_traits>

namespace {
constexpr quint32 kEcdsaP256PublicMagic = 0x31534345;
const QString kAccessToken = QStringLiteral("e30.e30.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

static_assert(!std::is_constructible_v<DeviceProofBuilder,
                                       IDeviceProofSigner &,
                                       DeviceProofBuilder::Clock,
                                       DeviceProofBuilder::RandomSource,
                                       bool>,
              "Local HTTP policy must not be runtime-enableable");

void appendLittleEndian32(QByteArray *output, quint32 value)
{
    for (int shift = 0; shift < 32; shift += 8)
        output->append(static_cast<char>((value >> shift) & 0xff));
}

QByteArray validPublicBlob()
{
    QByteArray blob;
    appendLittleEndian32(&blob, kEcdsaP256PublicMagic);
    appendLittleEndian32(&blob, 32);
    for (int value = 0; value < 64; ++value)
        blob.append(static_cast<char>(value));
    return blob;
}

QByteArray fixedSignature(qsizetype size = 64)
{
    QByteArray signature;
    for (qsizetype value = 0; value < size; ++value)
        signature.append(static_cast<char>(0x40 + value));
    return signature;
}

QByteArray decodeBase64Url(const QByteArray &encoded)
{
    return QByteArray::fromBase64(encoded, QByteArray::Base64UrlEncoding | QByteArray::AbortOnBase64DecodingErrors);
}

class FakeProofSigner final : public IDeviceProofSigner
{
public:
    QByteArray blob = validPublicBlob();
    QByteArray blobReturnedBySign;
    QByteArray signature = fixedSignature();
    QByteArray signedInput;
    int signCalls = 0;
    bool publicKeySucceeds = true;
    bool signingSucceeds = true;

    bool publicKeyBlob(QByteArray *publicBlob, QString *error) override
    {
        if (!publicKeySucceeds) {
            if (error)
                *error = QStringLiteral("fixture failure containing secret material");
            return false;
        }
        *publicBlob = blob;
        return true;
    }

    bool sign(QByteArrayView input, QByteArray *resultSignature,
              QByteArray *publicBlob, QString *error) override
    {
        ++signCalls;
        signedInput = QByteArray(input.data(), input.size());
        if (!signingSucceeds) {
            if (error)
                *error = QStringLiteral("fixture failure containing secret material");
            return false;
        }
        *resultSignature = signature;
        *publicBlob = blobReturnedBySign.isNull() ? blob : blobReturnedBySign;
        return true;
    }
};

DeviceProofBuilder builder(FakeProofSigner &signer,
                           DeviceProofBuilder::RandomSource randomSource = [] {
                               return QByteArray::fromHex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
                           })
{
    return DeviceProofBuilder(
        signer,
        [] { return qint64{1700000000}; },
        std::move(randomSource));
}

void verifyRejected(const ProofResult &result)
{
    QVERIFY(!result.valid);
    QVERIFY(result.compactJws.isEmpty());
    QVERIFY(result.jwkThumbprint.isEmpty());
    QCOMPARE(result.error, QStringLiteral("Device proof could not be created."));
}
} // namespace

class DeviceProofTest final : public QObject
{
    Q_OBJECT
private slots:
    void buildsExactRequestBoundProof();
    void rejectsMalformedPublicBlob_data();
    void rejectsMalformedPublicBlob();
    void rejectsUnsafeProductionUrl();
    void appliesCompileTimeHttpPolicy();
    void rejectsEmptyTokenAndThumbprintMismatch();
    void rejectsInvalidSignatureAndKeySwap();
    void rejectsMalformedAccessTokens_data();
    void rejectsMalformedAccessTokens();
    void rejectsInvalidMethodAndRandomLength();
    void sanitizesSignerFailures();
};

void DeviceProofTest::buildsExactRequestBoundProof()
{
    FakeProofSigner signer;
    const QString expectedThumbprint = QStringLiteral("0r62zgBj277RicA3LnaBKQ5_9RCDIomrlbpWjO0QTG0");
    const ProofResult result = builder(signer).build(
        QStringLiteral("get"),
        QUrl(QStringLiteral("https://Example.TEST:443/a/../v1/me?ignored=yes#fragment")),
        kAccessToken,
        expectedThumbprint);

    QVERIFY(result.valid);
    QVERIFY(result.error.isEmpty());
    QCOMPARE(result.jwkThumbprint, expectedThumbprint);

    const QList<QByteArray> segments = result.compactJws.toLatin1().split('.');
    QCOMPARE(segments.size(), 3);
    const QJsonObject header = QJsonDocument::fromJson(decodeBase64Url(segments.at(0))).object();
    QCOMPARE(header.size(), 3);
    QCOMPARE(header.value(QStringLiteral("typ")).toString(), QStringLiteral("dpop+jwt"));
    QCOMPARE(header.value(QStringLiteral("alg")).toString(), QStringLiteral("ES256"));
    const QJsonObject jwk = header.value(QStringLiteral("jwk")).toObject();
    QCOMPARE(jwk.size(), 4);
    QCOMPARE(jwk.value(QStringLiteral("kty")).toString(), QStringLiteral("EC"));
    QCOMPARE(jwk.value(QStringLiteral("crv")).toString(), QStringLiteral("P-256"));
    QCOMPARE(jwk.value(QStringLiteral("x")).toString(), QStringLiteral("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"));
    QCOMPARE(jwk.value(QStringLiteral("y")).toString(), QStringLiteral("ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8"));

    const QJsonObject payload = QJsonDocument::fromJson(decodeBase64Url(segments.at(1))).object();
    QCOMPARE(payload.size(), 5);
    QCOMPARE(payload.value(QStringLiteral("jti")).toString(), QStringLiteral("oKGio6SlpqeoqaqrrK2urw"));
    QCOMPARE(payload.value(QStringLiteral("htm")).toString(), QStringLiteral("GET"));
    QCOMPARE(payload.value(QStringLiteral("htu")).toString(), QStringLiteral("https://example.test/v1/me"));
    QCOMPARE(payload.value(QStringLiteral("iat")).toInteger(), qint64{1700000000});
    QCOMPARE(payload.value(QStringLiteral("ath")).toString(), QStringLiteral("ZAI9tnKiCz84fzrVLX3pmluoafSEOV452lfXYMvPszA"));
    QCOMPARE(decodeBase64Url(segments.at(2)), fixedSignature());
    QCOMPARE(signer.signedInput, segments.at(0) + '.' + segments.at(1));
    QCOMPARE(signer.signCalls, 1);
}

void DeviceProofTest::rejectsMalformedPublicBlob_data()
{
    QTest::addColumn<QByteArray>("blob");
    QByteArray wrongMagic = validPublicBlob();
    wrongMagic[0] = '\0';
    QTest::newRow("wrong-magic") << wrongMagic;
    QTest::newRow("short") << validPublicBlob().left(71);
    QTest::newRow("long") << (validPublicBlob() + QByteArray(1, '\0'));
    QByteArray wrongCoordinateSize = validPublicBlob();
    wrongCoordinateSize[4] = 31;
    QTest::newRow("wrong-coordinate-size") << wrongCoordinateSize;
}

void DeviceProofTest::rejectsMalformedPublicBlob()
{
    QFETCH(QByteArray, blob);
    FakeProofSigner signer;
    signer.blob = blob;
    verifyRejected(builder(signer).build(QStringLiteral("GET"), QUrl(QStringLiteral("https://api.example.test/v1/me")),
                                         kAccessToken, QStringLiteral("0r62zgBj277RicA3LnaBKQ5_9RCDIomrlbpWjO0QTG0")));
    QCOMPARE(signer.signCalls, 0);
}

void DeviceProofTest::rejectsUnsafeProductionUrl()
{
    FakeProofSigner signer;
    verifyRejected(builder(signer).build(QStringLiteral("GET"), QUrl(QStringLiteral("https://user@example.test/v1/me")),
                                         kAccessToken, QStringLiteral("0r62zgBj277RicA3LnaBKQ5_9RCDIomrlbpWjO0QTG0")));
    verifyRejected(builder(signer).build(QStringLiteral("GET"), QUrl(QStringLiteral("ftp://example.test/v1/me")),
                                         kAccessToken, QStringLiteral("0r62zgBj277RicA3LnaBKQ5_9RCDIomrlbpWjO0QTG0")));
}

void DeviceProofTest::appliesCompileTimeHttpPolicy()
{
    FakeProofSigner signer;
    const ProofResult loopback = builder(signer).build(
        QStringLiteral("GET"), QUrl(QStringLiteral("http://127.0.0.1:8080/v1/me")),
        kAccessToken, QStringLiteral("0r62zgBj277RicA3LnaBKQ5_9RCDIomrlbpWjO0QTG0"));
#if STARLOADER_LOCAL_DEVELOPMENT
    QVERIFY(loopback.valid);
#else
    verifyRejected(loopback);
#endif
    verifyRejected(builder(signer).build(QStringLiteral("GET"), QUrl(QStringLiteral("http://localhost:8080/v1/me")),
                                          kAccessToken, QStringLiteral("0r62zgBj277RicA3LnaBKQ5_9RCDIomrlbpWjO0QTG0")));
    verifyRejected(builder(signer).build(QStringLiteral("GET"), QUrl(QStringLiteral("http://192.0.2.1:8080/v1/me")),
                                          kAccessToken, QStringLiteral("0r62zgBj277RicA3LnaBKQ5_9RCDIomrlbpWjO0QTG0")));
}

void DeviceProofTest::rejectsEmptyTokenAndThumbprintMismatch()
{
    FakeProofSigner signer;
    verifyRejected(builder(signer).build(QStringLiteral("GET"), QUrl(QStringLiteral("https://api.example.test/v1/me")),
                                         QString(), QStringLiteral("0r62zgBj277RicA3LnaBKQ5_9RCDIomrlbpWjO0QTG0")));
    verifyRejected(builder(signer).build(QStringLiteral("GET"), QUrl(QStringLiteral("https://api.example.test/v1/me")),
                                         kAccessToken, QStringLiteral("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")));
    QCOMPARE(signer.signCalls, 0);
}

void DeviceProofTest::rejectsInvalidSignatureAndKeySwap()
{
    FakeProofSigner shortSignature;
    shortSignature.signature = fixedSignature(63);
    verifyRejected(builder(shortSignature).build(QStringLiteral("GET"), QUrl(QStringLiteral("https://api.example.test/v1/me")),
                                                 kAccessToken, QStringLiteral("0r62zgBj277RicA3LnaBKQ5_9RCDIomrlbpWjO0QTG0")));

    FakeProofSigner swappedKey;
    swappedKey.blobReturnedBySign = swappedKey.blob;
    swappedKey.blobReturnedBySign[8] = static_cast<char>(0xff);
    verifyRejected(builder(swappedKey).build(QStringLiteral("GET"), QUrl(QStringLiteral("https://api.example.test/v1/me")),
                                             kAccessToken, QStringLiteral("0r62zgBj277RicA3LnaBKQ5_9RCDIomrlbpWjO0QTG0")));
}

void DeviceProofTest::rejectsMalformedAccessTokens_data()
{
    QTest::addColumn<QString>("token");
    QTest::newRow("non-ascii") << QStringLiteral("e30.e3é.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    QString nulToken = kAccessToken;
    nulToken[1] = QChar(u'\0');
    QTest::newRow("nul") << nulToken;
    QTest::newRow("control") << QStringLiteral("e30.e3\n.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    QTest::newRow("one-segment") << QStringLiteral("e30");
    QTest::newRow("empty-segment") << QStringLiteral("e30..AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    QTest::newRow("four-segments") << (kAccessToken + QStringLiteral(".extra"));
    QTest::newRow("standard-base64-padding") << QStringLiteral("e30=.e30.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    QTest::newRow("noncanonical-pad-bits") << QStringLiteral("AB.e30.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    QTest::newRow("short-signature") << QStringLiteral("e30.e30.AA");
}

void DeviceProofTest::rejectsMalformedAccessTokens()
{
    QFETCH(QString, token);
    FakeProofSigner signer;
    verifyRejected(builder(signer).build(QStringLiteral("GET"), QUrl(QStringLiteral("https://api.example.test/v1/me")),
                                         token, QStringLiteral("0r62zgBj277RicA3LnaBKQ5_9RCDIomrlbpWjO0QTG0")));
    QCOMPARE(signer.signCalls, 0);
}

void DeviceProofTest::rejectsInvalidMethodAndRandomLength()
{
    FakeProofSigner signer;
    verifyRejected(builder(signer).build(QStringLiteral("GET\r\nX-Evil"), QUrl(QStringLiteral("https://api.example.test/v1/me")),
                                         kAccessToken, QStringLiteral("0r62zgBj277RicA3LnaBKQ5_9RCDIomrlbpWjO0QTG0")));
    verifyRejected(builder(signer, [] { return QByteArray(15, '\x5a'); }).build(
        QStringLiteral("GET"), QUrl(QStringLiteral("https://api.example.test/v1/me")),
        kAccessToken, QStringLiteral("0r62zgBj277RicA3LnaBKQ5_9RCDIomrlbpWjO0QTG0")));
}

void DeviceProofTest::sanitizesSignerFailures()
{
    FakeProofSigner publicKeyFailure;
    publicKeyFailure.publicKeySucceeds = false;
    verifyRejected(builder(publicKeyFailure).build(
        QStringLiteral("GET"), QUrl(QStringLiteral("https://api.example.test/v1/me")),
        kAccessToken, QStringLiteral("0r62zgBj277RicA3LnaBKQ5_9RCDIomrlbpWjO0QTG0")));

    FakeProofSigner signingFailure;
    signingFailure.signingSucceeds = false;
    verifyRejected(builder(signingFailure).build(
        QStringLiteral("GET"), QUrl(QStringLiteral("https://api.example.test/v1/me")),
        kAccessToken, QStringLiteral("0r62zgBj277RicA3LnaBKQ5_9RCDIomrlbpWjO0QTG0")));
}

QTEST_MAIN(DeviceProofTest)
#include "DeviceProofTest.moc"

#include "auth/AuthManager.h"
#include "security/Fingerprint.h"

#include <QJsonDocument>
#include <QtTest>

#include <openssl/evp.h>

namespace {
class FakeApiClient final : public IApiClient
{
public:
    using IApiClient::IApiClient;
    LoginRequest lastLogin;
    DeviceVerifyRequest lastVerify;
    int loginCount = 0;
    void login(const LoginRequest &request) override { lastLogin = request; ++loginCount; }
    void verifyDevice(const DeviceVerifyRequest &request) override { lastVerify = request; }
    void completeLogin(const LoginResponse &response) { emit loginSucceeded(response); }
    void rejectLogin(const ApiError &error) { emit loginFailed(error); }
    void completeVerify(const DeviceVerifyResponse &response) { emit deviceVerified(response); }
    void rejectVerify(const ApiError &error) { emit deviceVerificationFailed(error); }
};

class FakeHardwareCollector final : public IHardwareCollector
{
public:
    bool succeeds = true;
    bool collect(HardwareIdentity *identity, QString *error) override {
        if (!succeeds) { *error = QStringLiteral("missing TPM"); return false; }
        *identity = {QStringLiteral("smbios"), QStringLiteral("board"), QStringLiteral("bios"), QStringLiteral("disk"), QStringLiteral("machine"), {}, {}, {}, QStringLiteral("ABCDEF1234567890")};
        return true;
    }
};

class FakeDeviceSigner final : public IDeviceSigner
{
public:
    bool succeeds = true;
    bool sign(const QByteArray &challenge, QByteArray *signature, QByteArray *publicKey, QString *error) override {
        if (!succeeds) { *error = QStringLiteral("signing failed"); return false; }
        if (challenge != QByteArrayLiteral("challenge")) return false;
        *signature = QByteArrayLiteral("signature"); *publicKey = QByteArrayLiteral("public-key"); return true;
    }
};

QString tokenFor(const QJsonObject &claims)
{
    const QByteArray header = QJsonDocument(QJsonObject{{QStringLiteral("alg"), QStringLiteral("EdDSA")}, {QStringLiteral("typ"), QStringLiteral("JWT")}}).toJson(QJsonDocument::Compact).toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    const QByteArray payload = QJsonDocument(claims).toJson(QJsonDocument::Compact).toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    const QByteArray message = header + '.' + payload;
    const QByteArray privateKey(32, '\x02');
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char *>(privateKey.constData()), privateKey.size());
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    size_t signatureSize = 0;
    const bool initialized = key != nullptr && context != nullptr && EVP_DigestSignInit(context, nullptr, nullptr, nullptr, key) == 1;
    if (!initialized || EVP_DigestSign(context, nullptr, &signatureSize, reinterpret_cast<const unsigned char *>(message.constData()), message.size()) != 1) { EVP_MD_CTX_free(context); EVP_PKEY_free(key); return {}; }
    QByteArray signature(static_cast<qsizetype>(signatureSize), Qt::Uninitialized);
    if (EVP_DigestSign(context, reinterpret_cast<unsigned char *>(signature.data()), &signatureSize, reinterpret_cast<const unsigned char *>(message.constData()), message.size()) != 1) { EVP_MD_CTX_free(context); EVP_PKEY_free(key); return {}; }
    EVP_MD_CTX_free(context); EVP_PKEY_free(key);
    return QString::fromUtf8(message + '.' + signature.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}

SessionTokenVerifier verifier()
{
    const QByteArray privateKey(32, '\x02');
    EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char *>(privateKey.constData()), privateKey.size());
    QByteArray publicKey(32, Qt::Uninitialized); size_t publicKeySize = static_cast<size_t>(publicKey.size());
    const bool extracted = key != nullptr && EVP_PKEY_get_raw_public_key(key, reinterpret_cast<unsigned char *>(publicKey.data()), &publicKeySize) == 1 && publicKeySize == 32;
    EVP_PKEY_free(key); if (!extracted) return SessionTokenVerifier(QByteArray(), QStringLiteral("starloader"), QStringLiteral("starloader-client"), QStringLiteral("StarLoader"));
    return SessionTokenVerifier(publicKey, QStringLiteral("starloader"), QStringLiteral("starloader-client"), QStringLiteral("StarLoader"));
}

LoginResponse challengeResponse() { return {QStringLiteral("0198940d-7cec-7000-8000-000000000001"), QStringLiteral("Y2hhbGxlbmdl"), {}, QStringLiteral("request-1")}; }
DeviceVerifyResponse verifiedResponse(QString token = {}) { return {token, {}, QStringLiteral("license-1"), QStringLiteral("device-1"), QStringLiteral("request-2")}; }
QJsonObject validClaims() { const qint64 now = QDateTime::currentSecsSinceEpoch(); return {{QStringLiteral("sub"), QStringLiteral("user-1")}, {QStringLiteral("license_id"), QStringLiteral("license-1")}, {QStringLiteral("device_id"), QStringLiteral("device-1")}, {QStringLiteral("product"), QStringLiteral("StarLoader")}, {QStringLiteral("features"), QJsonArray{}}, {QStringLiteral("iss"), QStringLiteral("starloader")}, {QStringLiteral("aud"), QStringLiteral("starloader-client")}, {QStringLiteral("iat"), now}, {QStringLiteral("exp"), now + 3600}}; }
} // namespace

class AuthManagerTest final : public QObject
{
    Q_OBJECT
private slots:
    void reachesAuthenticatedOnlyAfterVerifiedDeviceToken();
    void failsBeforeNetworkWhenTpmIsUnavailable();
    void failsForLoginChallengeSigningAndDeviceErrors();
    void failsForInvalidTokenWithoutAuthenticatedState();
    void systemCollectorGeneratesFingerprintBeforeAuthentication();
};

void AuthManagerTest::reachesAuthenticatedOnlyAfterVerifiedDeviceToken()
{
    FakeApiClient api; FakeHardwareCollector collector; FakeDeviceSigner signer;
    AuthManager manager(api, collector, signer, verifier());
    QSignalSpy states(&manager, &AuthManager::stateChanged);
    manager.login(QStringLiteral("person@example.com"), QStringLiteral("password"), QStringLiteral("license-key"));
    QTRY_COMPARE(api.loginCount, 1);
    QCOMPARE(api.lastLogin.deviceFingerprint, QStringLiteral("ABCDEF1234567890"));
    api.completeLogin(challengeResponse());
    QCOMPARE(api.lastVerify.challenge, QStringLiteral("Y2hhbGxlbmdl"));
    QCOMPARE(api.lastVerify.challengeSignature, QStringLiteral("c2lnbmF0dXJl"));
    api.completeVerify(verifiedResponse(tokenFor(validClaims())));
    QCOMPARE(manager.state(), AuthState::Authenticated);
    QCOMPARE(states.size(), 5);
    QCOMPARE(states.at(0).at(0).value<AuthState>(), AuthState::CollectingDevice);
    QCOMPARE(states.at(1).at(0).value<AuthState>(), AuthState::Authenticating);
    QCOMPARE(states.at(2).at(0).value<AuthState>(), AuthState::WaitingForDeviceChallenge);
    QCOMPARE(states.at(3).at(0).value<AuthState>(), AuthState::VerifyingDevice);
    QCOMPARE(states.at(4).at(0).value<AuthState>(), AuthState::Authenticated);
}

void AuthManagerTest::failsBeforeNetworkWhenTpmIsUnavailable()
{
    FakeApiClient api; FakeHardwareCollector collector; FakeDeviceSigner signer; collector.succeeds = false;
    AuthManager manager(api, collector, signer, verifier());
    manager.login(QStringLiteral("a@b.c"), QStringLiteral("p"), QStringLiteral("l"));
    QTRY_COMPARE(manager.state(), AuthState::Failed);
    QCOMPARE(api.loginCount, 0);
    QCOMPARE(manager.state(), AuthState::Failed);
}

void AuthManagerTest::failsForLoginChallengeSigningAndDeviceErrors()
{
    FakeApiClient api; FakeHardwareCollector collector; FakeDeviceSigner signer;
    AuthManager manager(api, collector, signer, verifier());
    manager.login(QStringLiteral("a@b.c"), QStringLiteral("p"), QStringLiteral("l"));
    QTRY_COMPARE(api.loginCount, 1);
    api.rejectLogin({QStringLiteral("INVALID_CREDENTIALS"), {}, {}});
    QCOMPARE(manager.state(), AuthState::Failed);
    manager.login(QStringLiteral("a@b.c"), QStringLiteral("p"), QStringLiteral("l"));
    QTRY_COMPARE(api.loginCount, 2);
    api.completeLogin({QStringLiteral("session"), QStringLiteral("bad-base64"), {}, {}});
    QCOMPARE(manager.state(), AuthState::Failed);
    manager.login(QStringLiteral("a@b.c"), QStringLiteral("p"), QStringLiteral("l"));
    QTRY_COMPARE(api.loginCount, 3);
    signer.succeeds = false; api.completeLogin(challengeResponse());
    QCOMPARE(manager.state(), AuthState::Failed);
    signer.succeeds = true; manager.login(QStringLiteral("a@b.c"), QStringLiteral("p"), QStringLiteral("l")); QTRY_COMPARE(api.loginCount, 4);
    api.completeLogin(challengeResponse()); api.rejectVerify({QStringLiteral("DEVICE_REVOKED"), {}, {}});
    QCOMPARE(manager.state(), AuthState::Failed);
}

void AuthManagerTest::failsForInvalidTokenWithoutAuthenticatedState()
{
    FakeApiClient api; FakeHardwareCollector collector; FakeDeviceSigner signer;
    AuthManager manager(api, collector, signer, verifier()); QSignalSpy states(&manager, &AuthManager::stateChanged);
    manager.login(QStringLiteral("a@b.c"), QStringLiteral("p"), QStringLiteral("l")); QTRY_COMPARE(api.loginCount, 1); api.completeLogin(challengeResponse());
    QJsonObject claims = validClaims(); claims[QStringLiteral("device_id")] = QStringLiteral("other-device");
    api.completeVerify(verifiedResponse(tokenFor(claims)));
    QCOMPARE(manager.state(), AuthState::Failed);
    for (const QList<QVariant> &entry : states) QVERIFY(entry.at(0).value<AuthState>() != AuthState::Authenticated);
}

void AuthManagerTest::systemCollectorGeneratesFingerprintBeforeAuthentication()
{
    const HardwareIdentity raw{QStringLiteral("uuid"), QStringLiteral("board"), QStringLiteral("bios"), QStringLiteral("disk"), QStringLiteral("guid"), {}, {}, QStringLiteral("tpm"), {}};
    SystemHardwareCollector collector({
        [] { return true; },
        [](QString *) { return true; },
        [raw] { return raw; },
    });
    HardwareIdentity identity;
    QString error;
    QVERIFY2(collector.collect(&identity, &error), qPrintable(error));
    QCOMPARE(identity.finalFingerprint, Fingerprint::generate(raw));
}

QTEST_MAIN(AuthManagerTest)
#include "AuthManagerTest.moc"

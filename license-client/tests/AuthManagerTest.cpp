#include "auth/AuthManager.h"
#include "security/Fingerprint.h"

#include <QJsonDocument>
#include <QElapsedTimer>
#include <QSemaphore>
#include <QThread>
#include <QtTest>

#include <thread>

#include <openssl/evp.h>

namespace {
class FakeApiClient final : public IApiClient
{
public:
    using IApiClient::IApiClient;
    LoginRequest lastLogin;
    DeviceVerifyRequest lastVerify;
    QString lastProfileToken;
    quint64 lastLoginGeneration = 0;
    quint64 lastVerifyGeneration = 0;
    quint64 lastProfileGeneration = 0;
    int loginCount = 0;
    int verifyCount = 0;
    int profileCount = 0;
    int cancelProfileCount = 0;
    void login(const LoginRequest &request, quint64 generation) override { lastLogin = request; lastLoginGeneration = generation; ++loginCount; }
    void verifyDevice(const DeviceVerifyRequest &request, quint64 generation) override { lastVerify = request; lastVerifyGeneration = generation; ++verifyCount; }
    void loadProfile(const QString &token, quint64 generation) override { lastProfileToken = token; lastProfileGeneration = generation; ++profileCount; }
    void cancelProfile() override { ++cancelProfileCount; }
    void completeLogin(const LoginResponse &response) { completeLogin(response, lastLoginGeneration); }
    void completeLogin(const LoginResponse &response, quint64 generation) { emit loginSucceeded(response, generation); }
    void rejectLogin(const ApiError &error) { rejectLogin(error, lastLoginGeneration); }
    void rejectLogin(const ApiError &error, quint64 generation) { emit loginFailed(error, generation); }
    void completeVerify(const DeviceVerifyResponse &response) { completeVerify(response, lastVerifyGeneration); }
    void completeVerify(const DeviceVerifyResponse &response, quint64 generation) { emit deviceVerified(response, generation); }
    void rejectVerify(const ApiError &error) { rejectVerify(error, lastVerifyGeneration); }
    void rejectVerify(const ApiError &error, quint64 generation) { emit deviceVerificationFailed(error, generation); }
    void completeProfile(const UserProfileResponse &response, quint64 generation) { emit profileLoaded(response, generation); }
    void rejectProfile(const ApiError &error, quint64 generation) { emit profileFailed(error, generation); }
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

class BlockingDeviceSigner final : public IDeviceSigner
{
public:
    QSemaphore entered;
    QSemaphore release;
    bool sign(const QByteArray &challenge, QByteArray *signature, QByteArray *publicKey, QString *) override {
        if (challenge != QByteArrayLiteral("challenge")) return false;
        entered.release();
        release.acquire();
        *signature = QByteArrayLiteral("signature");
        *publicKey = QByteArrayLiteral("public-key");
        return true;
    }
};

QString tokenFor(const QJsonObject &claims)
{
    const QByteArray header = QJsonDocument(QJsonObject{{QStringLiteral("alg"), QStringLiteral("EdDSA")}, {QStringLiteral("typ"), QStringLiteral("JWT")}, {QStringLiteral("kid"), QStringLiteral("test-kid")}}).toJson(QJsonDocument::Compact).toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
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
    EVP_PKEY_free(key); if (!extracted) return SessionTokenVerifier({}, QStringLiteral("starloader"), QStringLiteral("starloader-client"), QStringLiteral("app-1"), QStringLiteral("product-1"), QStringLiteral("StarLoader"));
    return SessionTokenVerifier({{QStringLiteral("test-kid"), publicKey}}, QStringLiteral("starloader"), QStringLiteral("starloader-client"), QStringLiteral("app-1"), QStringLiteral("product-1"), QStringLiteral("StarLoader"));
}

LoginResponse challengeResponse() { return {QStringLiteral("0198940d-7cec-7000-8000-000000000001"), QStringLiteral("Y2hhbGxlbmdl"), {}, QStringLiteral("request-1")}; }
DeviceVerifyResponse verifiedResponse(QString token = {}) { return {token, {}, QStringLiteral("license-1"), QStringLiteral("device-1"), QStringLiteral("request-2")}; }
QJsonObject validClaims() { const qint64 now = QDateTime::currentSecsSinceEpoch(); return {{QStringLiteral("sub"), QStringLiteral("user-1")}, {QStringLiteral("app"), QStringLiteral("app-1")}, {QStringLiteral("product_id"), QStringLiteral("product-1")}, {QStringLiteral("license_id"), QStringLiteral("license-1")}, {QStringLiteral("device_id"), QStringLiteral("device-1")}, {QStringLiteral("product"), QStringLiteral("StarLoader")}, {QStringLiteral("sid"), QStringLiteral("session-1")}, {QStringLiteral("jti"), QStringLiteral("token-1")}, {QStringLiteral("features"), QJsonArray{}}, {QStringLiteral("cnf"), QJsonObject{{QStringLiteral("jkt"), QStringLiteral("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")}}}, {QStringLiteral("iss"), QStringLiteral("starloader")}, {QStringLiteral("aud"), QStringLiteral("starloader-client")}, {QStringLiteral("iat"), now}, {QStringLiteral("nbf"), now}, {QStringLiteral("exp"), now + 600}}; }
UserProfileResponse validProfile()
{
    return {
        QStringLiteral("test2@test.com"), QStringLiteral("active"), QStringLiteral("StarLoader"), QStringLiteral("active"),
        QDateTime::fromString(QStringLiteral("2026-09-12T17:42:56Z"), Qt::ISODate), 1,
        QStringLiteral("device-1"), QStringLiteral("active"),
        QDateTime::fromString(QStringLiteral("2026-08-13T18:50:15Z"), Qt::ISODate), QStringLiteral("request-3"),
    };
}
} // namespace

class AuthManagerTest final : public QObject
{
    Q_OBJECT
private slots:
    void reachesAuthenticatedOnlyAfterVerifiedDeviceToken();
    void profileFailureClearsAuthenticatedSession();
    void signOutClearsSessionAndIgnoresStaleProfileCompletion();
    void staleProfileAndLoginCallbacksCannotCrossAttempts();
    void staleLoginAndDeviceCallbacksCannotCrossAttempts();
    void failsBeforeNetworkWhenTpmIsUnavailable();
    void failsForLoginChallengeSigningAndDeviceErrors();
    void failsForInvalidTokenWithoutAuthenticatedState();
    void systemCollectorGeneratesFingerprintBeforeAuthentication();
    void signsDeviceChallengeWithoutBlockingManagerThread();
    void destructionWaitsForInFlightSigning();
};

void AuthManagerTest::reachesAuthenticatedOnlyAfterVerifiedDeviceToken()
{
    FakeApiClient api; FakeHardwareCollector collector; FakeDeviceSigner signer;
    AuthManager manager(api, collector, signer, verifier());
    QSignalSpy states(&manager, &AuthManager::stateChanged);
    QSignalSpy authenticated(&manager, &AuthManager::authenticated);
    manager.login(QStringLiteral("person@example.com"), QStringLiteral("password"));
    QTRY_COMPARE(api.loginCount, 1);
    QCOMPARE(api.lastLogin.email, QStringLiteral("person@example.com"));
    QCOMPARE(api.lastLogin.deviceFingerprint, QStringLiteral("ABCDEF1234567890"));
    api.completeLogin(challengeResponse());
    QTRY_COMPARE(api.verifyCount, 1);
    QCOMPARE(api.lastVerify.challenge, QStringLiteral("Y2hhbGxlbmdl"));
    QCOMPARE(api.lastVerify.challengeSignature, QStringLiteral("c2lnbmF0dXJl"));
    const QString token = tokenFor(validClaims());
    api.completeVerify(verifiedResponse(token));
    QCOMPARE(api.profileCount, 1);
    QCOMPARE(api.lastProfileToken, token);
    const quint64 profileGeneration = api.lastProfileGeneration;
    QVERIFY(manager.state() != AuthState::Authenticated);
    QCOMPARE(authenticated.size(), 0);
    api.completeLogin(challengeResponse());
    QCOMPARE(manager.state(), AuthState::Authenticating);
    QCOMPARE(api.verifyCount, 1);
    api.completeProfile(validProfile(), profileGeneration);
    QCOMPARE(manager.state(), AuthState::Authenticated);
    QCOMPARE(authenticated.size(), 1);
    QCOMPARE(manager.userProfile().email, QStringLiteral("test2@test.com"));
    QCOMPARE(states.size(), 6);
    QCOMPARE(states.at(0).at(0).value<AuthState>(), AuthState::CollectingDevice);
    QCOMPARE(states.at(1).at(0).value<AuthState>(), AuthState::Authenticating);
    QCOMPARE(states.at(2).at(0).value<AuthState>(), AuthState::WaitingForDeviceChallenge);
    QCOMPARE(states.at(3).at(0).value<AuthState>(), AuthState::VerifyingDevice);
    QCOMPARE(states.at(4).at(0).value<AuthState>(), AuthState::Authenticating);
    QCOMPARE(states.at(5).at(0).value<AuthState>(), AuthState::Authenticated);
}

void AuthManagerTest::profileFailureClearsAuthenticatedSession()
{
    FakeApiClient api; FakeHardwareCollector collector; FakeDeviceSigner signer;
    AuthManager manager(api, collector, signer, verifier());
    QSignalSpy authenticated(&manager, &AuthManager::authenticated);
    manager.login(QStringLiteral("a@b.c"), QStringLiteral("p"));
    QTRY_COMPARE(api.loginCount, 1);
    api.completeLogin(challengeResponse());
    QTRY_COMPARE(api.verifyCount, 1);
    const QString token = tokenFor(validClaims());
    api.completeVerify(verifiedResponse(token));
    QCOMPARE(api.profileCount, 1);
    const quint64 profileGeneration = api.lastProfileGeneration;
    QVERIFY(!manager.sessionToken().isEmpty());
    QSignalSpy failed(&manager, &AuthManager::failed);

    api.rejectProfile({token, QStringLiteral("rejected %1").arg(token), token}, profileGeneration);

    QCOMPARE(manager.state(), AuthState::Failed);
    QVERIFY(manager.sessionToken().isEmpty());
    QVERIFY(manager.userProfile().email.isEmpty());
    QCOMPARE(authenticated.size(), 0);
    QCOMPARE(failed.size(), 1);
    const ApiError safeError = failed.at(0).at(0).value<ApiError>();
    QVERIFY(!safeError.code.contains(token));
    QVERIFY(!safeError.message.contains(token));
    QVERIFY(!safeError.requestId.contains(token));
}

void AuthManagerTest::signOutClearsSessionAndIgnoresStaleProfileCompletion()
{
    FakeApiClient api; FakeHardwareCollector collector; FakeDeviceSigner signer;
    AuthManager manager(api, collector, signer, verifier());
    QSignalSpy authenticated(&manager, &AuthManager::authenticated);
    manager.login(QStringLiteral("a@b.c"), QStringLiteral("p"));
    QTRY_COMPARE(api.loginCount, 1);
    api.completeLogin(challengeResponse());
    QTRY_COMPARE(api.verifyCount, 1);
    api.completeVerify(verifiedResponse(tokenFor(validClaims())));
    QCOMPARE(api.profileCount, 1);
    api.completeProfile(validProfile(), api.lastProfileGeneration);
    QCOMPARE(manager.state(), AuthState::Authenticated);
    QVERIFY(!manager.userProfile().email.isEmpty());
    QCOMPARE(authenticated.size(), 1);

    manager.signOut();

    QCOMPARE(manager.state(), AuthState::LoggedOut);
    QVERIFY(manager.sessionToken().isEmpty());
    QVERIFY(manager.userProfile().email.isEmpty());
    QVERIFY(manager.deviceDisplayId().isEmpty());
    QVERIFY(!manager.collectionWatcher_.future().isValid());
    QVERIFY(!manager.signingWatcher_.future().isValid());
    api.completeProfile(validProfile(), api.lastProfileGeneration);
    QCOMPARE(manager.state(), AuthState::LoggedOut);
    QCOMPARE(authenticated.size(), 1);
}

void AuthManagerTest::staleProfileAndLoginCallbacksCannotCrossAttempts()
{
    FakeApiClient api; FakeHardwareCollector collector; FakeDeviceSigner signer;
    AuthManager manager(api, collector, signer, verifier());
    QSignalSpy authenticated(&manager, &AuthManager::authenticated);

    manager.login(QStringLiteral("first@example.com"), QStringLiteral("p"));
    QTRY_COMPARE(api.loginCount, 1);
    api.completeLogin(challengeResponse());
    QTRY_COMPARE(api.verifyCount, 1);
    api.completeVerify(verifiedResponse(tokenFor(validClaims())));
    QCOMPARE(api.profileCount, 1);
    const quint64 oldGeneration = api.lastProfileGeneration;
    manager.signOut();
    QCOMPARE(api.cancelProfileCount, 1);

    manager.login(QStringLiteral("second@example.com"), QStringLiteral("p"));
    QTRY_COMPARE(api.loginCount, 2);
    api.completeLogin(challengeResponse());
    QTRY_COMPARE(api.verifyCount, 2);
    api.completeVerify(verifiedResponse(tokenFor(validClaims())));
    QCOMPARE(api.profileCount, 2);
    const quint64 currentGeneration = api.lastProfileGeneration;
    QVERIFY(currentGeneration != oldGeneration);

    UserProfileResponse oldProfile = validProfile();
    oldProfile.email = QStringLiteral("first@example.com");
    api.completeProfile(oldProfile, oldGeneration);
    api.completeLogin(challengeResponse());
    QCOMPARE(manager.state(), AuthState::Authenticating);
    QVERIFY(manager.userProfile().email.isEmpty());
    QCOMPARE(api.verifyCount, 2);
    QCOMPARE(authenticated.size(), 0);

    UserProfileResponse currentProfile = validProfile();
    currentProfile.email = QStringLiteral("second@example.com");
    api.completeProfile(currentProfile, currentGeneration);
    QCOMPARE(manager.state(), AuthState::Authenticated);
    QCOMPARE(manager.userProfile().email, QStringLiteral("second@example.com"));
    QCOMPARE(authenticated.size(), 1);
}

void AuthManagerTest::staleLoginAndDeviceCallbacksCannotCrossAttempts()
{
    FakeApiClient api; FakeHardwareCollector collector; FakeDeviceSigner signer;
    AuthManager manager(api, collector, signer, verifier());
    QSignalSpy authenticated(&manager, &AuthManager::authenticated);

    manager.login(QStringLiteral("first@example.com"), QStringLiteral("p"));
    QTRY_COMPARE(api.loginCount, 1);
    const quint64 staleLoginGeneration = api.lastLoginGeneration;
    manager.signOut();

    manager.login(QStringLiteral("second@example.com"), QStringLiteral("p"));
    QTRY_COMPARE(api.loginCount, 2);
    const quint64 secondGeneration = api.lastLoginGeneration;
    QVERIFY(secondGeneration != staleLoginGeneration);
    api.rejectLogin({QStringLiteral("INVALID_CREDENTIALS"), {}, {}}, staleLoginGeneration);
    api.completeLogin(challengeResponse(), staleLoginGeneration);
    QCOMPARE(manager.state(), AuthState::Authenticating);
    QCOMPARE(api.verifyCount, 0);

    api.completeLogin(challengeResponse(), secondGeneration);
    QTRY_COMPARE(api.verifyCount, 1);
    const quint64 staleDeviceGeneration = api.lastVerifyGeneration;
    manager.signOut();

    manager.login(QStringLiteral("third@example.com"), QStringLiteral("p"));
    QTRY_COMPARE(api.loginCount, 3);
    api.completeLogin(challengeResponse(), api.lastLoginGeneration);
    QTRY_COMPARE(api.verifyCount, 2);
    const quint64 currentGeneration = api.lastVerifyGeneration;
    QVERIFY(currentGeneration != staleDeviceGeneration);
    api.rejectVerify({QStringLiteral("DEVICE_REVOKED"), {}, {}}, staleDeviceGeneration);
    api.completeVerify(verifiedResponse(tokenFor(validClaims())), staleDeviceGeneration);
    QCOMPARE(manager.state(), AuthState::VerifyingDevice);
    QCOMPARE(api.profileCount, 0);
    QCOMPARE(authenticated.size(), 0);

    api.completeVerify(verifiedResponse(tokenFor(validClaims())), currentGeneration);
    QCOMPARE(api.profileCount, 1);
    QCOMPARE(api.lastProfileGeneration, currentGeneration);
    api.completeProfile(validProfile(), currentGeneration);
    QCOMPARE(manager.state(), AuthState::Authenticated);
    QCOMPARE(authenticated.size(), 1);
}

void AuthManagerTest::failsBeforeNetworkWhenTpmIsUnavailable()
{
    FakeApiClient api; FakeHardwareCollector collector; FakeDeviceSigner signer; collector.succeeds = false;
    AuthManager manager(api, collector, signer, verifier());
    manager.login(QStringLiteral("a@b.c"), QStringLiteral("p"));
    QTRY_COMPARE(manager.state(), AuthState::Failed);
    QCOMPARE(api.loginCount, 0);
    QCOMPARE(manager.state(), AuthState::Failed);
}

void AuthManagerTest::failsForLoginChallengeSigningAndDeviceErrors()
{
    FakeApiClient api; FakeHardwareCollector collector; FakeDeviceSigner signer;
    AuthManager manager(api, collector, signer, verifier());
    manager.login(QStringLiteral("a@b.c"), QStringLiteral("p"));
    QTRY_COMPARE(api.loginCount, 1);
    api.rejectLogin({QStringLiteral("INVALID_CREDENTIALS"), {}, {}});
    QCOMPARE(manager.state(), AuthState::Failed);
    manager.login(QStringLiteral("a@b.c"), QStringLiteral("p"));
    QTRY_COMPARE(api.loginCount, 2);
    api.completeLogin({QStringLiteral("session"), QStringLiteral("bad-base64"), {}, {}});
    QCOMPARE(manager.state(), AuthState::Failed);
    manager.login(QStringLiteral("a@b.c"), QStringLiteral("p"));
    QTRY_COMPARE(api.loginCount, 3);
    signer.succeeds = false; api.completeLogin(challengeResponse());
    QTRY_COMPARE(manager.state(), AuthState::Failed);
    signer.succeeds = true; manager.login(QStringLiteral("a@b.c"), QStringLiteral("p")); QTRY_COMPARE(api.loginCount, 4);
    api.completeLogin(challengeResponse()); QTRY_COMPARE(api.verifyCount, 1); api.rejectVerify({QStringLiteral("DEVICE_REVOKED"), {}, {}});
    QCOMPARE(manager.state(), AuthState::Failed);
}

void AuthManagerTest::failsForInvalidTokenWithoutAuthenticatedState()
{
    FakeApiClient api; FakeHardwareCollector collector; FakeDeviceSigner signer;
    AuthManager manager(api, collector, signer, verifier()); QSignalSpy states(&manager, &AuthManager::stateChanged);
    manager.login(QStringLiteral("a@b.c"), QStringLiteral("p")); QTRY_COMPARE(api.loginCount, 1); api.completeLogin(challengeResponse()); QTRY_COMPARE(api.verifyCount, 1);
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

void AuthManagerTest::signsDeviceChallengeWithoutBlockingManagerThread()
{
    FakeApiClient api; FakeHardwareCollector collector; BlockingDeviceSigner signer;
    AuthManager manager(api, collector, signer, verifier());
    manager.login(QStringLiteral("a@b.c"), QStringLiteral("p"));
    QTRY_COMPARE(api.loginCount, 1);

    std::thread releaser([&signer] { QThread::msleep(200); signer.release.release(); });
    QElapsedTimer elapsed; elapsed.start();
    api.completeLogin(challengeResponse());
    const qint64 deliveryMilliseconds = elapsed.elapsed();
    releaser.join();

    QVERIFY2(deliveryMilliseconds < 100, qPrintable(QStringLiteral("challenge delivery blocked for %1 ms").arg(deliveryMilliseconds)));
    QCOMPARE(manager.state(), AuthState::VerifyingDevice);
    manager.login(QStringLiteral("other@b.c"), QStringLiteral("other"));
    QCOMPARE(api.loginCount, 1);
    QTRY_COMPARE(api.verifyCount, 1);
}

void AuthManagerTest::destructionWaitsForInFlightSigning()
{
    FakeApiClient api; FakeHardwareCollector collector; BlockingDeviceSigner signer;
    auto manager = std::make_unique<AuthManager>(api, collector, signer, verifier());
    manager->login(QStringLiteral("a@b.c"), QStringLiteral("p"));
    QTRY_COMPARE(api.loginCount, 1);
    api.completeLogin(challengeResponse());
    QVERIFY(signer.entered.tryAcquire(1, 1000));

    std::thread releaser([&signer] { QThread::msleep(200); signer.release.release(); });
    QElapsedTimer elapsed; elapsed.start();
    manager.reset();
    const qint64 destructionMilliseconds = elapsed.elapsed();
    releaser.join();

    QVERIFY2(destructionMilliseconds >= 150, qPrintable(QStringLiteral("destruction returned before signer completion after %1 ms").arg(destructionMilliseconds)));
}

QTEST_MAIN(AuthManagerTest)
#include "AuthManagerTest.moc"

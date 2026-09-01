#include "AuthManager.h"

#include "hardware/HardwareCollector.h"
#include "security/Fingerprint.h"
#include "security/ProtectionMarkers.h"
#include "security/TpmIdentity.h"

#include <QtConcurrent/QtConcurrentRun>
#include <QRegularExpression>
#include <QSet>
#include <QTimer>
#include <limits>

namespace {
bool strictBase64(const QString &encoded, QByteArray *decoded)
{
    const QByteArray source = encoded.toUtf8();
    const QByteArray value = QByteArray::fromBase64(source);
    if (value.isEmpty() || value.toBase64() != source) return false;
    *decoded = value;
    return true;
}

void secureClear(QString &value)
{
    if (!value.isEmpty()) {
        value.detach();
        value.fill(QChar());
    }
    value.clear();
    value.squeeze();
}

void secureClear(QByteArray &value)
{
    if (!value.isEmpty()) {
        value.detach();
        value.fill('\0');
    }
    value.clear();
    value.squeeze();
}

class QtSessionExpiryTimer final : public ISessionExpiryTimer
{
public:
    QtSessionExpiryTimer()
    {
        timer_.setSingleShot(true);
        QObject::connect(&timer_, &QTimer::timeout, [this] {
            const auto callback = std::move(callback_);
            callback_ = {};
            if (callback) callback();
        });
    }

    void schedule(qint64 delayMs, std::function<void()> expiryCallback) override
    {
        cancel();
        callback_ = std::move(expiryCallback);
        timer_.start(static_cast<int>(qBound(qint64(0), delayMs,
                                             qint64(std::numeric_limits<int>::max()))));
    }

    void cancel() override
    {
        timer_.stop();
        callback_ = {};
    }

private:
    QTimer timer_;
    std::function<void()> callback_;
};
}

SystemHardwareCollector::SystemHardwareCollector()
    : SystemHardwareCollector({
        [] { return TpmIdentity::isAvailable(); },
        [](QString *error) { return TpmIdentity::ensureKey(error); },
        [] { return HardwareCollector().collect(); },
    }) {}

SystemHardwareCollector::SystemHardwareCollector(SystemHardwareDependencies dependencies)
    : dependencies_(std::move(dependencies)) {}

bool SystemHardwareCollector::collect(HardwareIdentity *identity, QString *error)
{
    if (!dependencies_.isTpmAvailable || !dependencies_.ensureTpmKey || !dependencies_.collectHardware) { *error = QStringLiteral("Device collector is unavailable."); return false; }
    if (!dependencies_.isTpmAvailable()) { *error = QStringLiteral("TPM is unavailable."); return false; }
    if (!dependencies_.ensureTpmKey(error)) return false;
    *identity = dependencies_.collectHardware();
    identity->finalFingerprint = Fingerprint::generate(*identity);
    if (identity->finalFingerprint.trimmed().isEmpty()) { *error = QStringLiteral("Device identity is unavailable."); return false; }
    return true;
}

bool TpmDeviceSigner::sign(const QByteArray &challenge, QByteArray *signature, QByteArray *publicKey, QString *error)
{
    return sign(QByteArrayView(challenge), signature, publicKey, error);
}

bool TpmDeviceSigner::publicKeyBlob(QByteArray *publicBlob, QString *error)
{
    if (!publicBlob)
        return false;
    if (error)
        error->clear();
    *publicBlob = TpmIdentity::publicKeyBlob();
    if (!publicBlob->isEmpty())
        return true;
    if (error)
        *error = QStringLiteral("The TPM public key is unavailable.");
    return false;
}

bool TpmDeviceSigner::sign(QByteArrayView input, QByteArray *signature, QByteArray *publicBlob, QString *error)
{
    if (!signature || !publicBlob || input.isEmpty() || !publicKeyBlob(publicBlob, error))
        return false;
    *signature = TpmIdentity::signChallenge(input, error);
    return !signature->isEmpty();
}

AuthManager::AuthManager(IApiClient &apiClient, IHardwareCollector &hardwareCollector, IDeviceSigner &deviceSigner, SessionTokenVerifier verifier, QObject *parent)
    : AuthManager(apiClient, hardwareCollector, deviceSigner, std::move(verifier),
                  [] { return QDateTime::currentSecsSinceEpoch(); },
                  std::make_unique<QtSessionExpiryTimer>(), parent)
{}

AuthManager::AuthManager(IApiClient &apiClient, IHardwareCollector &hardwareCollector, IDeviceSigner &deviceSigner,
                         SessionTokenVerifier verifier, Clock clock,
                         std::unique_ptr<ISessionExpiryTimer> expiryTimer, QObject *parent)
    : QObject(parent), apiClient_(apiClient), hardwareCollector_(hardwareCollector), deviceSigner_(deviceSigner),
      verifier_(std::move(verifier)), clock_(clock ? std::move(clock) : Clock([] { return QDateTime::currentSecsSinceEpoch(); })),
      expiryTimer_(expiryTimer ? std::move(expiryTimer) : std::make_unique<QtSessionExpiryTimer>())
{
    qRegisterMetaType<AuthState>();
    connect(&apiClient_, &IApiClient::loginSucceeded, this, &AuthManager::handleLoginSucceeded);
    connect(&apiClient_, &IApiClient::loginFailed, this, &AuthManager::handleLoginFailed);
    connect(&apiClient_, &IApiClient::deviceVerified, this, &AuthManager::handleDeviceVerified);
    connect(&apiClient_, &IApiClient::deviceVerificationFailed, this, &AuthManager::handleDeviceVerificationFailed);
    connect(&apiClient_, &IApiClient::profileLoaded, this, &AuthManager::handleProfileLoaded);
    connect(&apiClient_, &IApiClient::profileFailed, this, &AuthManager::handleProfileFailed);
    connect(&collectionWatcher_, &QFutureWatcher<CollectionResult>::finished, this, &AuthManager::completeCollection);
    connect(&signingWatcher_, &QFutureWatcher<SigningResult>::finished, this, &AuthManager::completeSigning);
}

AuthManager::~AuthManager() { cancelAndWait(); apiClient_.cancelProfile(); clearSession(); }

AuthState AuthManager::state() const { return state_; }
QString AuthManager::sessionToken() const { return sessionToken_; }
const UserProfileResponse &AuthManager::userProfile() const { return userProfile_; }
QString AuthManager::deviceDisplayId() const { return hardware_.finalFingerprint.isEmpty() ? QString() : hardware_.displayId(); }

void AuthManager::transition(AuthState state, const QString &status)
{
    state_ = state;
    emitTransitionSignals(status);
}

void AuthManager::emitTransitionSignals(const QString &status)
{
    emit stateChanged(state_);
    emit statusChanged(status);
}

void AuthManager::fail(const ApiError &error)
{
    ApiError safeError = error;
    const QStringList secrets{sessionToken_, pendingLogin_.password};
    for (const QString &secret : secrets) {
        if (secret.isEmpty()) continue;
        if (safeError.code.contains(secret)) safeError.code = QStringLiteral("AUTHENTICATION_FAILED");
        if (safeError.message.contains(secret)) safeError.message = QStringLiteral("Authentication failed.");
        if (safeError.requestId.contains(secret)) safeError.requestId.clear();
    }
    static const QSet<QString> allowedCodes{
        QStringLiteral("INVALID_CREDENTIALS"), QStringLiteral("LICENSE_EXPIRED"),
        QStringLiteral("LICENSE_REVOKED"), QStringLiteral("DEVICE_LIMIT_REACHED"),
        QStringLiteral("DEVICE_REVOKED"), QStringLiteral("RATE_LIMITED"),
        QStringLiteral("TPM_UNAVAILABLE"), QStringLiteral("TOKEN_VERIFIER_UNAVAILABLE"),
        QStringLiteral("INVALID_CHALLENGE"), QStringLiteral("DEVICE_SIGNING_FAILED"),
        QStringLiteral("INVALID_SESSION_TOKEN"), QStringLiteral("INVALID_SESSION"),
        QStringLiteral("SESSION_EXPIRED"), QStringLiteral("DEVICE_PROOF_FAILED"),
        QStringLiteral("NETWORK_ERROR"), QStringLiteral("INSECURE_TRANSPORT"),
        QStringLiteral("TIMEOUT"), QStringLiteral("RESPONSE_TOO_LARGE"),
        QStringLiteral("MALFORMED_RESPONSE"), QStringLiteral("REQUEST_IN_PROGRESS"),
    };
    if (!allowedCodes.contains(safeError.code)) safeError.code = QStringLiteral("AUTHENTICATION_FAILED");
    safeError.message = QStringLiteral("Authentication failed.");
    static const QRegularExpression safeRequestId(QStringLiteral(
        "^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"));
    if (!safeRequestId.match(safeError.requestId).hasMatch()) safeError.requestId.clear();
    expiryTimer_->cancel();
    if (profileLoading_) apiClient_.cancelProfile();
    ++attempt_;
    clearSession();
    transition(AuthState::Failed, QStringLiteral("Authentication failed."));
    emit failed(safeError);
}

void AuthManager::clearSession()
{
    secureClear(pendingLogin_.password);
    pendingLogin_.email.clear();
    hardware_ = {};
    secureClear(sessionId_);
    secureClear(challenge_);
    secureClear(sessionToken_);
    userProfile_ = {};
    profileLoading_ = false;
    expiresAt_ = {};
}

void AuthManager::login(const QString &email, const QString &password)
{
    if (state_ != AuthState::LoggedOut && state_ != AuthState::Failed) return;
    expiryTimer_->cancel();
    clearSession();
    pendingLogin_ = {email, password};
    const quint64 attempt = ++attempt_;
    transition(AuthState::CollectingDevice, QStringLiteral("Collecting device identity."));
    IHardwareCollector *collector = &hardwareCollector_;
    collectionWatcher_.setFuture(QtConcurrent::run([collector, attempt] {
        CollectionResult result; result.attempt = attempt;
        result.success = collector->collect(&result.identity, &result.error);
        return result;
    }));
}

void AuthManager::signOut()
{
    cancelAndWait();
    expiryTimer_->cancel();
    apiClient_.cancelProfile();
    clearSession();
    transition(AuthState::LoggedOut, QStringLiteral("Signed out."));
}

void AuthManager::cancelAndWait()
{
    ++attempt_;
    collectionWatcher_.cancel();
    collectionWatcher_.waitForFinished();
    signingWatcher_.cancel();
    signingWatcher_.waitForFinished();
    collectionWatcher_.setFuture(QFuture<CollectionResult>());
    signingWatcher_.setFuture(QFuture<SigningResult>());
}

void AuthManager::completeCollection()
{
    const QFuture<CollectionResult> future = collectionWatcher_.future();
    if (!future.isValid()) return;
    const CollectionResult result = future.result();
    collectionWatcher_.setFuture(QFuture<CollectionResult>());
    if (result.attempt != attempt_ || state_ != AuthState::CollectingDevice) return;
    if (!result.success) { fail({QStringLiteral("TPM_UNAVAILABLE"), QStringLiteral("Device security is unavailable."), {}}); return; }
    hardware_ = result.identity;
    if (!verifier_.isConfigured()) { fail({QStringLiteral("TOKEN_VERIFIER_UNAVAILABLE"), QStringLiteral("Client security configuration is unavailable."), {}}); return; }
    transition(AuthState::Authenticating, QStringLiteral("Authenticating."));
    apiClient_.login({pendingLogin_.email, pendingLogin_.password, hardware_.finalFingerprint}, attempt_);
    secureClear(pendingLogin_.password);
}

void AuthManager::handleLoginSucceeded(const LoginResponse &response, quint64 generation)
{
    if (generation != attempt_ || state_ != AuthState::Authenticating || profileLoading_) return;
    transition(AuthState::WaitingForDeviceChallenge, QStringLiteral("Verifying device challenge."));
    if (!strictBase64(response.challenge, &challenge_)) { fail({QStringLiteral("INVALID_CHALLENGE"), QStringLiteral("Server challenge is invalid."), response.requestId}); return; }
    sessionId_ = response.sessionId;
    transition(AuthState::VerifyingDevice, QStringLiteral("Signing device challenge."));
    IDeviceSigner *signer = &deviceSigner_;
    const QByteArray challenge = challenge_;
    const quint64 attempt = attempt_;
    const QString encodedChallenge = response.challenge;
    const QString requestId = response.requestId;
    signingWatcher_.setFuture(QtConcurrent::run([signer, challenge, attempt, encodedChallenge, requestId] {
        SigningResult result;
        result.attempt = attempt;
        result.encodedChallenge = encodedChallenge;
        result.requestId = requestId;
        result.success = signer->sign(challenge, &result.signature, &result.publicKey, &result.error);
        return result;
    }));
}

void AuthManager::completeSigning()
{
    const QFuture<SigningResult> future = signingWatcher_.future();
    if (!future.isValid()) return;
    const SigningResult result = future.result();
    signingWatcher_.setFuture(QFuture<SigningResult>());
    if (result.attempt != attempt_ || state_ != AuthState::VerifyingDevice) return;
    if (!result.success) { fail({QStringLiteral("DEVICE_SIGNING_FAILED"), QStringLiteral("Device proof could not be created."), result.requestId}); return; }
    apiClient_.verifyDevice({sessionId_, result.encodedChallenge, QString::fromUtf8(result.signature.toBase64()), QString::fromUtf8(result.publicKey.toBase64()), {hardware_.smbiosUuid, hardware_.motherboardSerial, hardware_.biosSerial, hardware_.systemDiskSerial, hardware_.machineGuid, hardware_.finalFingerprint}}, attempt_);
}

void AuthManager::handleLoginFailed(const ApiError &error, quint64 generation) { if (generation == attempt_ && state_ == AuthState::Authenticating && !profileLoading_) fail(error); }

void AuthManager::handleDeviceVerified(const DeviceVerifyResponse &response, quint64 generation)
{
    if (generation != attempt_ || state_ != AuthState::VerifyingDevice) return;
    const VerifiedSession verified = verifier_.verify(response.token, response.deviceId, response.licenseId);
    if (!verified.valid) { fail({QStringLiteral("INVALID_SESSION_TOKEN"), QStringLiteral("Server session token is invalid."), response.requestId}); return; }
    sessionToken_ = response.token;
    expiresAt_ = verified.expiresAt;
    if (expiresAt_.toSecsSinceEpoch() <= clock_()) {
        requireReauthentication(generation);
        return;
    }
    scheduleExpiry(expiresAt_, generation);
    userProfile_ = {};
    profileLoading_ = true;
    transition(AuthState::Authenticating, QStringLiteral("Loading profile."));
    apiClient_.loadProfile({sessionToken_, verified.deviceKeyThumbprint, verified.expiresAt}, attempt_);
}

void AuthManager::handleDeviceVerificationFailed(const ApiError &error, quint64 generation) { if (generation == attempt_ && state_ == AuthState::VerifyingDevice) fail(error); }

void AuthManager::handleProfileLoaded(const UserProfileResponse &response, quint64 generation)
{
    if (generation != attempt_ || state_ != AuthState::Authenticating || !profileLoading_ || sessionToken_.isEmpty()) return;
    if (!expiresAt_.isValid() || expiresAt_.toSecsSinceEpoch() <= clock_()) {
        requireReauthentication(generation);
        return;
    }
    STARLOADER_VM_BEGIN("starloader.auth.verified-profile-transition.v1");
    userProfile_ = response;
    profileLoading_ = false;
    state_ = AuthState::Authenticated;
    STARLOADER_VM_END();
    emitTransitionSignals(QStringLiteral("Authenticated."));
    emit authenticated();
}

void AuthManager::scheduleExpiry(const QDateTime &expiresAt, quint64 generation)
{
    const qint64 delayMs = qMax<qint64>(0, (expiresAt.toSecsSinceEpoch() - clock_()) * 1000);
    expiryTimer_->schedule(delayMs, [this, generation] { requireReauthentication(generation); });
}

void AuthManager::requireReauthentication(quint64 generation)
{
    if (generation != attempt_ || sessionToken_.isEmpty()) return;
    expiryTimer_->cancel();
    apiClient_.cancelProfile();
    ++attempt_;
    clearSession();
    const QString reason = QStringLiteral("Session expired. Sign in again.");
    transition(AuthState::LoggedOut, reason);
    emit reauthenticationRequired(reason);
}

void AuthManager::handleProfileFailed(const ApiError &error, quint64 generation)
{
    if (generation == attempt_ && state_ == AuthState::Authenticating && profileLoading_) fail(error);
}

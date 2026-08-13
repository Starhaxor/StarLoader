#include "AuthManager.h"

#include "hardware/HardwareCollector.h"
#include "security/Fingerprint.h"
#include "security/TpmIdentity.h"

#include <QtConcurrent/QtConcurrentRun>

namespace {
bool strictBase64(const QString &encoded, QByteArray *decoded)
{
    const QByteArray source = encoded.toUtf8();
    const QByteArray value = QByteArray::fromBase64(source);
    if (value.isEmpty() || value.toBase64() != source) return false;
    *decoded = value;
    return true;
}
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
    *publicKey = TpmIdentity::publicKeyBlob();
    *signature = TpmIdentity::signChallenge(challenge, error);
    return !publicKey->isEmpty() && !signature->isEmpty();
}

AuthManager::AuthManager(IApiClient &apiClient, IHardwareCollector &hardwareCollector, IDeviceSigner &deviceSigner, SessionTokenVerifier verifier, QObject *parent)
    : QObject(parent), apiClient_(apiClient), hardwareCollector_(hardwareCollector), deviceSigner_(deviceSigner), verifier_(std::move(verifier))
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
    emit stateChanged(state_);
    emit statusChanged(status);
}

void AuthManager::fail(const ApiError &error)
{
    ApiError safeError = error;
    if (!sessionToken_.isEmpty()) {
        if (safeError.code.contains(sessionToken_)) safeError.code = QStringLiteral("INVALID_SESSION_TOKEN");
        if (safeError.message.contains(sessionToken_)) safeError.message = QStringLiteral("Authentication failed.");
        if (safeError.requestId.contains(sessionToken_)) safeError.requestId.clear();
    }
    clearSession();
    transition(AuthState::Failed, QStringLiteral("Authentication failed."));
    emit failed(safeError);
}

void AuthManager::clearSession()
{
    pendingLogin_ = {};
    hardware_ = {};
    sessionId_.clear();
    challenge_.clear();
    sessionToken_.clear();
    userProfile_ = {};
    profileLoading_ = false;
}

void AuthManager::login(const QString &email, const QString &password)
{
    if (state_ != AuthState::LoggedOut && state_ != AuthState::Failed) return;
    sessionToken_.clear();
    userProfile_ = {};
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
    pendingLogin_.password.clear();
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
    const VerificationResult verified = verifier_.verify(response.token, response.deviceId, response.licenseId);
    if (!verified.valid) { fail({QStringLiteral("INVALID_SESSION_TOKEN"), QStringLiteral("Server session token is invalid."), response.requestId}); return; }
    sessionToken_ = response.token;
    userProfile_ = {};
    profileLoading_ = true;
    transition(AuthState::Authenticating, QStringLiteral("Loading profile."));
    apiClient_.loadProfile(sessionToken_, attempt_);
}

void AuthManager::handleDeviceVerificationFailed(const ApiError &error, quint64 generation) { if (generation == attempt_ && state_ == AuthState::VerifyingDevice) fail(error); }

void AuthManager::handleProfileLoaded(const UserProfileResponse &response, quint64 generation)
{
    if (generation != attempt_ || state_ != AuthState::Authenticating || !profileLoading_ || sessionToken_.isEmpty()) return;
    userProfile_ = response;
    profileLoading_ = false;
    transition(AuthState::Authenticated, QStringLiteral("Authenticated."));
    emit authenticated();
}

void AuthManager::handleProfileFailed(const ApiError &error, quint64 generation)
{
    if (generation == attempt_ && state_ == AuthState::Authenticating && profileLoading_) fail(error);
}

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
    connect(&collectionWatcher_, &QFutureWatcher<CollectionResult>::finished, this, &AuthManager::completeCollection);
}

AuthManager::~AuthManager() { cancelAndWait(); }

AuthState AuthManager::state() const { return state_; }
QString AuthManager::sessionToken() const { return sessionToken_; }
QString AuthManager::deviceDisplayId() const { return hardware_.displayId(); }

void AuthManager::transition(AuthState state, const QString &status)
{
    state_ = state;
    emit stateChanged(state_);
    emit statusChanged(status);
}

void AuthManager::fail(const ApiError &error)
{
    sessionToken_.clear();
    transition(AuthState::Failed, QStringLiteral("Authentication failed."));
    emit failed(error);
}

void AuthManager::login(const QString &email, const QString &password, const QString &licenseKey)
{
    if (state_ == AuthState::CollectingDevice || state_ == AuthState::Authenticating || state_ == AuthState::WaitingForDeviceChallenge || state_ == AuthState::VerifyingDevice) return;
    sessionToken_.clear();
    pendingLogin_ = {email, password, licenseKey};
    const quint64 attempt = ++attempt_;
    transition(AuthState::CollectingDevice, QStringLiteral("Collecting device identity."));
    IHardwareCollector *collector = &hardwareCollector_;
    collectionWatcher_.setFuture(QtConcurrent::run([collector, attempt] {
        CollectionResult result; result.attempt = attempt;
        result.success = collector->collect(&result.identity, &result.error);
        return result;
    }));
}

void AuthManager::cancelAndWait()
{
    ++attempt_;
    collectionWatcher_.cancel();
    collectionWatcher_.waitForFinished();
}

void AuthManager::completeCollection()
{
    const CollectionResult result = collectionWatcher_.result();
    if (result.attempt != attempt_ || state_ != AuthState::CollectingDevice) return;
    if (!result.success) { fail({QStringLiteral("TPM_UNAVAILABLE"), QStringLiteral("Device security is unavailable."), {}}); return; }
    hardware_ = result.identity;
    if (!verifier_.isConfigured()) { fail({QStringLiteral("TOKEN_VERIFIER_UNAVAILABLE"), QStringLiteral("Client security configuration is unavailable."), {}}); return; }
    transition(AuthState::Authenticating, QStringLiteral("Authenticating."));
    apiClient_.login({pendingLogin_.email, pendingLogin_.password, pendingLogin_.licenseKey, hardware_.finalFingerprint});
    pendingLogin_.password.clear();
    pendingLogin_.licenseKey.clear();
}

void AuthManager::handleLoginSucceeded(const LoginResponse &response)
{
    if (state_ != AuthState::Authenticating) return;
    transition(AuthState::WaitingForDeviceChallenge, QStringLiteral("Verifying device challenge."));
    if (!strictBase64(response.challenge, &challenge_)) { fail({QStringLiteral("INVALID_CHALLENGE"), QStringLiteral("Server challenge is invalid."), response.requestId}); return; }
    sessionId_ = response.sessionId;
    QByteArray signature, publicKey;
    QString signerError;
    transition(AuthState::VerifyingDevice, QStringLiteral("Signing device challenge."));
    if (!deviceSigner_.sign(challenge_, &signature, &publicKey, &signerError)) { fail({QStringLiteral("DEVICE_SIGNING_FAILED"), QStringLiteral("Device proof could not be created."), response.requestId}); return; }
    apiClient_.verifyDevice({sessionId_, response.challenge, QString::fromUtf8(signature.toBase64()), QString::fromUtf8(publicKey.toBase64()), {hardware_.smbiosUuid, hardware_.motherboardSerial, hardware_.biosSerial, hardware_.systemDiskSerial, hardware_.machineGuid, hardware_.finalFingerprint}});
}

void AuthManager::handleLoginFailed(const ApiError &error) { if (state_ == AuthState::Authenticating) fail(error); }

void AuthManager::handleDeviceVerified(const DeviceVerifyResponse &response)
{
    if (state_ != AuthState::VerifyingDevice) return;
    const VerificationResult verified = verifier_.verify(response.token, response.deviceId, response.licenseId);
    if (!verified.valid) { fail({QStringLiteral("INVALID_SESSION_TOKEN"), QStringLiteral("Server session token is invalid."), response.requestId}); return; }
    sessionToken_ = response.token;
    transition(AuthState::Authenticated, QStringLiteral("Authenticated."));
    emit authenticated();
}

void AuthManager::handleDeviceVerificationFailed(const ApiError &error) { if (state_ == AuthState::VerifyingDevice) fail(error); }

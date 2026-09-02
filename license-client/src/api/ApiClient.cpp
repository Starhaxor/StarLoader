#include "ApiClient.h"
#include "ClientSecurityConfig.h"

#include <QJsonDocument>
#include <QJsonParseError>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRegularExpression>
#include <QSet>
#include <QSslConfiguration>
#include <QSslError>
#include <QTimer>
#include <QUuid>

namespace {
constexpr qsizetype MaxResponseBytes = 64 * 1024;

QList<QByteArray> configuredTlsPins()
{
    const QByteArray configured(STARLOADER_TLS_SPKI_PINS);
    return configured.isEmpty() ? QList<QByteArray>{} : configured.split(',');
}

ApiError transportSecurityError(QNetworkReply *reply, const QString &requestId)
{
    const QString code = reply->property("starloader.transportSecurityError").toString();
    if (code == QStringLiteral("TLS_REDIRECT_REJECTED")) {
        return {code, QStringLiteral("The server redirect was rejected."), requestId};
    }
    return {QStringLiteral("TLS_VALIDATION_FAILED"),
            QStringLiteral("The secure connection could not be verified."), requestId};
}

ApiError errorForReply(QNetworkReply *reply, const QByteArray &body, const QString &fallbackRequestId)
{
    ApiError error{QStringLiteral("NETWORK_ERROR"), QStringLiteral("Network request failed."), fallbackRequestId};
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(body, &parseError);
    if (parseError.error == QJsonParseError::NoError && document.isObject()) {
        const QJsonObject json = document.object();
        const QString code = json.value(QStringLiteral("code")).toString();
        const QString message = json.value(QStringLiteral("message")).toString();
        const QString requestId = json.value(QStringLiteral("request_id")).toString();
        if (!code.isEmpty()) error.code = code;
        if (!message.isEmpty()) error.message = message;
        if (!requestId.isEmpty()) error.requestId = requestId;
    }
    const QByteArray headerRequestId = reply->rawHeader("X-Request-ID");
    if (error.requestId.isEmpty() && !headerRequestId.isEmpty()) error.requestId = QString::fromUtf8(headerRequestId);
    if (error.code == QStringLiteral("NETWORK_ERROR")) {
        // Never surface the endpoint URL: Qt's errorString() embeds the full
        // request URL, which must stay hidden from users. Report the HTTP
        // status when available and otherwise a generic connectivity message.
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (status >= 400) {
            error.message = QStringLiteral("Server returned an error (HTTP %1).").arg(status);
        } else {
            error.message = QStringLiteral("Could not reach the server. Check your connection and try again.");
        }
    }
    return error;
}

ApiError withoutSecret(ApiError error, const QString &secret)
{
    if (secret.isEmpty()) return error;
    if (error.code.contains(secret)) error.code = QStringLiteral("INVALID_SESSION_TOKEN");
    if (error.message.contains(secret)) error.message = QStringLiteral("Profile request failed.");
    if (error.requestId.contains(secret)) error.requestId.clear();
    return error;
}

ApiError sanitizedLoginError(ApiError error)
{
    static const QSet<QString> allowedCodes{
        QStringLiteral("INVALID_CREDENTIALS"), QStringLiteral("LICENSE_EXPIRED"),
        QStringLiteral("LICENSE_REVOKED"), QStringLiteral("DEVICE_LIMIT_REACHED"),
        QStringLiteral("DEVICE_REVOKED"), QStringLiteral("RATE_LIMITED"),
        QStringLiteral("NETWORK_ERROR"), QStringLiteral("INSECURE_TRANSPORT"),
        QStringLiteral("TLS_VALIDATION_FAILED"), QStringLiteral("TLS_REDIRECT_REJECTED"),
        QStringLiteral("TIMEOUT"), QStringLiteral("RESPONSE_TOO_LARGE"),
        QStringLiteral("MALFORMED_RESPONSE"), QStringLiteral("REQUEST_IN_PROGRESS"),
    };
    if (!allowedCodes.contains(error.code)) error.code = QStringLiteral("AUTHENTICATION_FAILED");
    if (error.code != QStringLiteral("NETWORK_ERROR") && error.code != QStringLiteral("TIMEOUT"))
        error.message = QStringLiteral("Authentication failed.");
    static const QRegularExpression safeRequestId(QStringLiteral(
        "^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"));
    if (!safeRequestId.match(error.requestId).hasMatch()) error.requestId.clear();
    return error;
}
} // namespace

ApiClient::ApiClient(QUrl baseUrl, int timeoutMs, QObject *parent)
    : IApiClient(parent), baseUrl_(std::move(baseUrl)),
      tlsPinPolicy_(QStringLiteral(STARLOADER_TLS_PINNED_HOST), configuredTlsPins(),
                    STARLOADER_LOCAL_DEVELOPMENT == 1),
      timeoutMs_(qBound(1, timeoutMs, RequestTimeoutMs)),
      proofBuilder_(std::make_shared<DeviceProofBuilder>(defaultProofSigner_)),
      clock_([] { return QDateTime::currentMSecsSinceEpoch(); })
{
    initializeNetworkSecurity();
    qRegisterMetaType<LoginResponse>();
    qRegisterMetaType<DeviceVerifyResponse>();
    qRegisterMetaType<UserProfileResponse>();
    qRegisterMetaType<ApiError>();
}

ApiClient::ApiClient(QUrl baseUrl, std::shared_ptr<IDeviceProofBuilder> proofBuilder, Clock clock,
                     int timeoutMs, QObject *parent)
    : IApiClient(parent), baseUrl_(std::move(baseUrl)),
      tlsPinPolicy_(QStringLiteral(STARLOADER_TLS_PINNED_HOST), configuredTlsPins(),
                    STARLOADER_LOCAL_DEVELOPMENT == 1),
      timeoutMs_(qBound(1, timeoutMs, RequestTimeoutMs)),
      proofBuilder_(std::move(proofBuilder)),
      clock_(clock ? std::move(clock) : Clock([] { return QDateTime::currentMSecsSinceEpoch(); }))
{
    initializeNetworkSecurity();
    qRegisterMetaType<LoginResponse>();
    qRegisterMetaType<DeviceVerifyResponse>();
    qRegisterMetaType<UserProfileResponse>();
    qRegisterMetaType<ApiError>();
}

bool ApiClient::isAllowedTransport() const
{
    return tlsPinPolicy_.isValid() && tlsPinPolicy_.permitsRequestUrl(baseUrl_);
}

void ApiClient::initializeNetworkSecurity()
{
    connect(&network_, &QNetworkAccessManager::sslErrors, this,
            [this](QNetworkReply *reply, const QList<QSslError> &) {
        if (!reply) return;
        reply->setProperty("starloader.transportSecurityError", QStringLiteral("TLS_VALIDATION_FAILED"));
        reply->abort();
    });
    connect(&network_, &QNetworkAccessManager::encrypted, this, [this](QNetworkReply *reply) {
        if (!reply || tlsPinPolicy_.verify(reply->url(), reply->sslConfiguration().peerCertificate())) return;
        reply->setProperty("starloader.transportSecurityError", QStringLiteral("TLS_VALIDATION_FAILED"));
        reply->abort();
    });
}

void ApiClient::configureReplySecurity(QNetworkReply *reply)
{
    if (!reply) return;
    connect(reply, &QNetworkReply::redirected, reply, [this, reply](const QUrl &redirectUrl) {
        const QUrl target = reply->url().resolved(redirectUrl);
        if (tlsPinPolicy_.permitsRequestUrl(target)) {
            reply->redirectAllowed();
            return;
        }
        reply->setProperty("starloader.transportSecurityError", QStringLiteral("TLS_REDIRECT_REJECTED"));
        reply->abort();
    });
}

QString ApiClient::newRequestId() const
{
    return QUuid::createUuidV7().toString(QUuid::WithoutBraces);
}

void ApiClient::login(const LoginRequest &request, quint64 generation)
{
    postJson(QStringLiteral("/v1/auth/login"), {
        {QStringLiteral("email"), request.email}, {QStringLiteral("password"), request.password},
        {QStringLiteral("device_fingerprint"), request.deviceFingerprint},
    }, false, generation);
}

void ApiClient::verifyDevice(const DeviceVerifyRequest &request, quint64 generation)
{
    const HardwareSignals &hardware = request.hardware;
    postJson(QStringLiteral("/v1/device/verify"), {
        {QStringLiteral("session_id"), request.sessionId}, {QStringLiteral("challenge"), request.challenge},
        {QStringLiteral("challenge_signature"), request.challengeSignature}, {QStringLiteral("tpm_public_key"), request.tpmPublicKey},
        {QStringLiteral("hardware"), QJsonObject{{QStringLiteral("smbios_uuid"), hardware.smbiosUuid}, {QStringLiteral("motherboard_serial"), hardware.motherboardSerial}, {QStringLiteral("bios_serial"), hardware.biosSerial}, {QStringLiteral("system_disk_serial"), hardware.systemDiskSerial}, {QStringLiteral("machine_guid"), hardware.machineGuid}, {QStringLiteral("fingerprint"), hardware.fingerprint}}},
    }, true, generation);
}

bool ApiClient::buildProtectedRequest(const QString &path, const QString &method,
                                      const ProtectedSession &session, const QString &requestId,
                                      QNetworkRequest *request, ApiError *error)
{
    const auto reject = [requestId, error](const QString &code, const QString &message) {
        if (error) *error = {code, message, requestId};
        return false;
    };
    if (!request || !proofBuilder_ || session.accessToken.isEmpty()
        || session.deviceKeyThumbprint.isEmpty() || !session.expiresAt.isValid()) {
        return reject(QStringLiteral("INVALID_SESSION"), QStringLiteral("A valid session is required."));
    }
    if (session.expiresAt.toMSecsSinceEpoch() <= clock_()) {
        return reject(QStringLiteral("SESSION_EXPIRED"), QStringLiteral("The session has expired. Sign in again."));
    }

    const QUrl requestUrl = baseUrl_.resolved(QUrl(path));
    const ProofResult proof = proofBuilder_->build(method, requestUrl, session.accessToken,
                                                    session.deviceKeyThumbprint);
    if (!proof.valid || proof.compactJws.isEmpty()
        || proof.jwkThumbprint != session.deviceKeyThumbprint) {
        return reject(QStringLiteral("DEVICE_PROOF_FAILED"), QStringLiteral("Device proof could not be created."));
    }
    if (session.expiresAt.toMSecsSinceEpoch() <= clock_()) {
        return reject(QStringLiteral("SESSION_EXPIRED"), QStringLiteral("The session has expired. Sign in again."));
    }

    *request = QNetworkRequest(requestUrl);
    request->setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                          QNetworkRequest::UserVerifiedRedirectPolicy);
    request->setRawHeader("Authorization", QByteArrayLiteral("DPoP ") + session.accessToken.toLatin1());
    request->setRawHeader("DPoP", proof.compactJws.toLatin1());
    request->setRawHeader("X-Request-ID", requestId.toUtf8());
    return true;
}

void ApiClient::setBodyCleanupObserverForTesting(BodyCleanupObserver observer)
{
    bodyCleanupObserver_ = std::move(observer);
}

void ApiClient::loadProfile(const ProtectedSession &session, quint64 generation)
{
    const QString requestId = newRequestId();
    const auto fail = [this, generation](const ApiError &error) { emit profileFailed(error, generation); };
    if (!isAllowedTransport()) { fail({QStringLiteral("INSECURE_TRANSPORT"), QStringLiteral("Secure transport is required."), requestId}); return; }
    if (requestActive_) { fail({QStringLiteral("REQUEST_IN_PROGRESS"), QStringLiteral("A request is already in progress."), requestId}); return; }
    QNetworkRequest networkRequest;
    ApiError preparationError;
    if (!buildProtectedRequest(QStringLiteral("/v1/me"), QStringLiteral("GET"), session,
                               requestId, &networkRequest, &preparationError)) {
        fail(preparationError);
        return;
    }
    if (session.expiresAt.toMSecsSinceEpoch() <= clock_()) {
        fail({QStringLiteral("SESSION_EXPIRED"), QStringLiteral("The session has expired. Sign in again."), requestId});
        return;
    }

    requestActive_ = true;
    QNetworkReply *reply = network_.get(networkRequest);
    configureReplySecurity(reply);
    const QString compactProof = QString::fromLatin1(networkRequest.rawHeader("DPoP"));
    profileReply_ = reply;
    reply->setReadBufferSize(MaxResponseBytes);
    auto *timer = new QTimer(reply);
    timer->setSingleShot(true);
    connect(timer, &QTimer::timeout, reply, [reply] { reply->setProperty("starloader.timeout", true); reply->abort(); });
    timer->start(timeoutMs_);
    connect(reply, &QNetworkReply::finished, this, [this, reply, requestId, token = session.accessToken,
                                                    compactProof, generation] {
        if (reply->property("starloader.cancelled").toBool()) {
            reply->deleteLater();
            return;
        }
        if (profileReply_ == reply) profileReply_.clear();
        requestActive_ = false;
        const QByteArray body = reply->isOpen() ? reply->readAll() : QByteArray{};
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (body.size() > MaxResponseBytes || reply->error() != QNetworkReply::NoError || status < 200 || status >= 300) {
            ApiError error = !reply->property("starloader.transportSecurityError").toString().isEmpty()
                ? transportSecurityError(reply, requestId)
                : reply->property("starloader.timeout").toBool()
                ? ApiError{QStringLiteral("TIMEOUT"), QStringLiteral("Network request timed out."), requestId}
                : errorForReply(reply, body, requestId);
            if (body.size() > MaxResponseBytes) error = {QStringLiteral("RESPONSE_TOO_LARGE"), QStringLiteral("Server response is too large."), requestId};
            emit profileFailed(withoutSecret(withoutSecret(error, token), compactProof), generation);
            reply->deleteLater();
            return;
        }

        QJsonParseError parseError;
        const QJsonDocument document = QJsonDocument::fromJson(body, &parseError);
        const QJsonObject json = document.object();
        const QDateTime licenseExpiresAt = QDateTime::fromString(json.value(QStringLiteral("license_expires_at")).toString(), Qt::ISODate);
        const QDateTime sessionExpiresAt = QDateTime::fromString(json.value(QStringLiteral("session_expires_at")).toString(), Qt::ISODate);
        UserProfileResponse response{
            json.value(QStringLiteral("email")).toString(),
            json.value(QStringLiteral("account_status")).toString(),
            json.value(QStringLiteral("product")).toString(),
            json.value(QStringLiteral("license_status")).toString(),
            licenseExpiresAt,
            json.value(QStringLiteral("max_devices")).toInt(),
            json.value(QStringLiteral("device_id")).toString(),
            json.value(QStringLiteral("device_status")).toString(),
            sessionExpiresAt,
            QString::fromUtf8(reply->rawHeader("X-Request-ID")),
        };
        const bool malformed = parseError.error != QJsonParseError::NoError || !document.isObject()
            || !json.value(QStringLiteral("ok")).toBool()
            || response.email.trimmed().isEmpty() || response.accountStatus.trimmed().isEmpty() || response.product.trimmed().isEmpty()
            || response.licenseStatus.trimmed().isEmpty() || !response.licenseExpiresAt.isValid() || response.maxDevices <= 0
            || response.deviceId.trimmed().isEmpty() || response.deviceStatus.trimmed().isEmpty() || !response.sessionExpiresAt.isValid();
        if (malformed) emit profileFailed({QStringLiteral("MALFORMED_RESPONSE"), QStringLiteral("Server response is invalid."), requestId}, generation);
        else emit profileLoaded(response, generation);
        reply->deleteLater();
    });
}

void ApiClient::cancelProfile()
{
    if (profileReply_.isNull()) return;
    QNetworkReply *reply = profileReply_.data();
    profileReply_.clear();
    reply->setProperty("starloader.cancelled", true);
    requestActive_ = false;
    reply->abort();
}

void ApiClient::postJson(const QString &path, const QJsonObject &body, bool deviceRequest, quint64 generation)
{
    const QString requestId = newRequestId();
    const auto fail = [this, deviceRequest, generation](const ApiError &error) {
        if (deviceRequest) emit deviceVerificationFailed(error, generation); else emit loginFailed(error, generation);
    };
    if (!isAllowedTransport()) { fail({QStringLiteral("INSECURE_TRANSPORT"), QStringLiteral("Secure transport is required."), requestId}); return; }
    if (requestActive_) { fail({QStringLiteral("REQUEST_IN_PROGRESS"), QStringLiteral("A request is already in progress."), requestId}); return; }
    requestActive_ = true;
    QNetworkRequest networkRequest(baseUrl_.resolved(QUrl(path)));
    networkRequest.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                                QNetworkRequest::UserVerifiedRedirectPolicy);
    networkRequest.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    networkRequest.setRawHeader("X-KeyStar-App", QByteArrayLiteral(STARLOADER_APPLICATION_ID));
    networkRequest.setRawHeader("Authorization", QByteArrayLiteral("Bearer ") + QByteArrayLiteral(STARLOADER_PUBLISHABLE_KEY));
    networkRequest.setRawHeader("X-Request-ID", requestId.toUtf8());
    QByteArray requestBody = QJsonDocument(body).toJson(QJsonDocument::Compact);
    QNetworkReply *reply = network_.post(networkRequest, requestBody);
    configureReplySecurity(reply);
    requestBody.detach();
    requestBody.fill('\0');
    if (bodyCleanupObserver_) bodyCleanupObserver_(QByteArrayView(requestBody));
    requestBody.clear();
    requestBody.squeeze();
    reply->setReadBufferSize(MaxResponseBytes);
    auto *timer = new QTimer(reply);
    timer->setSingleShot(true);
    connect(timer, &QTimer::timeout, reply, [reply] { reply->setProperty("starloader.timeout", true); reply->abort(); });
    timer->start(timeoutMs_);
    connect(reply, &QNetworkReply::finished, this, [this, reply, deviceRequest, requestId, generation] {
        requestActive_ = false;
        const QByteArray body = reply->isOpen() ? reply->readAll() : QByteArray{};
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (body.size() > MaxResponseBytes || reply->error() != QNetworkReply::NoError || status < 200 || status >= 300) {
            ApiError error = !reply->property("starloader.transportSecurityError").toString().isEmpty()
                ? transportSecurityError(reply, requestId)
                : reply->property("starloader.timeout").toBool()
                ? ApiError{QStringLiteral("TIMEOUT"), QStringLiteral("Network request timed out."), requestId}
                : errorForReply(reply, body, requestId);
            if (body.size() > MaxResponseBytes) error = {QStringLiteral("RESPONSE_TOO_LARGE"), QStringLiteral("Server response is too large."), requestId};
            if (deviceRequest) emit deviceVerificationFailed(error, generation);
            else emit loginFailed(sanitizedLoginError(error), generation);
            reply->deleteLater(); return;
        }
        QJsonParseError parseError;
        const QJsonDocument document = QJsonDocument::fromJson(body, &parseError);
        const QJsonObject json = document.object();
        if (parseError.error != QJsonParseError::NoError || !document.isObject() || !json.value(QStringLiteral("ok")).toBool()) {
            const ApiError error{QStringLiteral("MALFORMED_RESPONSE"), QStringLiteral("Server response is invalid."), requestId};
            if (deviceRequest) emit deviceVerificationFailed(error, generation); else emit loginFailed(error, generation);
            reply->deleteLater(); return;
        }
        const QString serverRequestId = QString::fromUtf8(reply->rawHeader("X-Request-ID"));
        if (deviceRequest) {
            DeviceVerifyResponse response{json.value(QStringLiteral("token")).toString(), json.value(QStringLiteral("token_expires_at")).toString(), json.value(QStringLiteral("license_id")).toString(), json.value(QStringLiteral("device_id")).toString(), serverRequestId};
            if (response.token.isEmpty() || response.licenseId.isEmpty() || response.deviceId.isEmpty()) emit deviceVerificationFailed({QStringLiteral("MALFORMED_RESPONSE"), QStringLiteral("Server response is invalid."), requestId}, generation); else emit deviceVerified(response, generation);
        } else {
            LoginResponse response{json.value(QStringLiteral("session_id")).toString(), json.value(QStringLiteral("challenge")).toString(), json.value(QStringLiteral("challenge_expires_at")).toString(), serverRequestId};
            if (response.sessionId.isEmpty() || response.challenge.isEmpty()) emit loginFailed({QStringLiteral("MALFORMED_RESPONSE"), QStringLiteral("Server response is invalid."), requestId}, generation); else emit loginSucceeded(response, generation);
        }
        reply->deleteLater();
    });
}

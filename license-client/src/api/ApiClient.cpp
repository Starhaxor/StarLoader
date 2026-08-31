#include "ApiClient.h"
#include "ClientSecurityConfig.h"

#include <QHostAddress>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QTimer>
#include <QUuid>

namespace {
constexpr qsizetype MaxResponseBytes = 64 * 1024;

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

bool loopbackHost(const QString &host)
{
    QHostAddress address;
    return address.setAddress(host) && address.isLoopback();
}

ApiError withoutSecret(ApiError error, const QString &secret)
{
    if (secret.isEmpty()) return error;
    if (error.code.contains(secret)) error.code = QStringLiteral("INVALID_SESSION_TOKEN");
    if (error.message.contains(secret)) error.message = QStringLiteral("Profile request failed.");
    if (error.requestId.contains(secret)) error.requestId.clear();
    return error;
}
} // namespace

ApiClient::ApiClient(QUrl baseUrl, int timeoutMs, QObject *parent)
    : IApiClient(parent), baseUrl_(std::move(baseUrl)), timeoutMs_(qBound(1, timeoutMs, RequestTimeoutMs))
{
    qRegisterMetaType<LoginResponse>();
    qRegisterMetaType<DeviceVerifyResponse>();
    qRegisterMetaType<UserProfileResponse>();
    qRegisterMetaType<ApiError>();
}

bool ApiClient::isAllowedTransport() const
{
    if (baseUrl_.scheme().compare(QStringLiteral("https"), Qt::CaseInsensitive) == 0) return true;
    const bool localDevelopment = STARLOADER_LOCAL_DEVELOPMENT == 1 ||
        qEnvironmentVariableIntValue("STARLOADER_ALLOW_HTTP_LOCAL") == 1;
    return baseUrl_.scheme().compare(QStringLiteral("http"), Qt::CaseInsensitive) == 0 &&
        localDevelopment && loopbackHost(baseUrl_.host());
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

void ApiClient::loadProfile(const QString &token, quint64 generation)
{
    const QString requestId = newRequestId();
    const auto fail = [this, generation](const ApiError &error) { emit profileFailed(error, generation); };
    if (!isAllowedTransport()) { fail({QStringLiteral("INSECURE_TRANSPORT"), QStringLiteral("Secure transport is required."), requestId}); return; }
    if (requestActive_) { fail({QStringLiteral("REQUEST_IN_PROGRESS"), QStringLiteral("A request is already in progress."), requestId}); return; }
    if (token.isEmpty()) { fail({QStringLiteral("INVALID_SESSION_TOKEN"), QStringLiteral("A valid session is required."), requestId}); return; }

    requestActive_ = true;
    QNetworkRequest networkRequest(baseUrl_.resolved(QUrl(QStringLiteral("/v1/me"))));
    networkRequest.setRawHeader("Authorization", QByteArrayLiteral("Bearer ") + token.toUtf8());
    networkRequest.setRawHeader("X-Request-ID", requestId.toUtf8());
    QNetworkReply *reply = network_.get(networkRequest);
    profileReply_ = reply;
    reply->setReadBufferSize(MaxResponseBytes);
    auto *timer = new QTimer(reply);
    timer->setSingleShot(true);
    connect(timer, &QTimer::timeout, reply, [reply] { reply->setProperty("starloader.timeout", true); reply->abort(); });
    timer->start(timeoutMs_);
    connect(reply, &QNetworkReply::finished, this, [this, reply, requestId, token, generation] {
        if (reply->property("starloader.cancelled").toBool()) {
            reply->deleteLater();
            return;
        }
        if (profileReply_ == reply) profileReply_.clear();
        requestActive_ = false;
        const QByteArray body = reply->readAll();
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (body.size() > MaxResponseBytes || reply->error() != QNetworkReply::NoError || status < 200 || status >= 300) {
            ApiError error = reply->property("starloader.timeout").toBool()
                ? ApiError{QStringLiteral("TIMEOUT"), QStringLiteral("Network request timed out."), requestId}
                : errorForReply(reply, body, requestId);
            if (body.size() > MaxResponseBytes) error = {QStringLiteral("RESPONSE_TOO_LARGE"), QStringLiteral("Server response is too large."), requestId};
            emit profileFailed(withoutSecret(error, token), generation);
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
    networkRequest.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/json"));
    networkRequest.setRawHeader("X-KeyStar-App", QByteArrayLiteral(STARLOADER_APPLICATION_ID));
    networkRequest.setRawHeader("Authorization", QByteArrayLiteral("Bearer ") + QByteArrayLiteral(STARLOADER_PUBLISHABLE_KEY));
    networkRequest.setRawHeader("X-Request-ID", requestId.toUtf8());
    QNetworkReply *reply = network_.post(networkRequest, QJsonDocument(body).toJson(QJsonDocument::Compact));
    reply->setReadBufferSize(MaxResponseBytes);
    auto *timer = new QTimer(reply);
    timer->setSingleShot(true);
    connect(timer, &QTimer::timeout, reply, [reply] { reply->setProperty("starloader.timeout", true); reply->abort(); });
    timer->start(timeoutMs_);
    connect(reply, &QNetworkReply::finished, this, [this, reply, deviceRequest, requestId, generation] {
        requestActive_ = false;
        const QByteArray body = reply->readAll();
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        if (body.size() > MaxResponseBytes || reply->error() != QNetworkReply::NoError || status < 200 || status >= 300) {
            ApiError error = reply->property("starloader.timeout").toBool()
                ? ApiError{QStringLiteral("TIMEOUT"), QStringLiteral("Network request timed out."), requestId}
                : errorForReply(reply, body, requestId);
            if (body.size() > MaxResponseBytes) error = {QStringLiteral("RESPONSE_TOO_LARGE"), QStringLiteral("Server response is too large."), requestId};
            if (deviceRequest) emit deviceVerificationFailed(error, generation); else emit loginFailed(error, generation);
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

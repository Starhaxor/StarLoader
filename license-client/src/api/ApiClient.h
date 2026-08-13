#pragma once

#include <QJsonObject>
#include <QDateTime>
#include <QNetworkAccessManager>
#include <QObject>
#include <QPointer>
#include <QUrl>

struct HardwareSignals
{
    QString smbiosUuid;
    QString motherboardSerial;
    QString biosSerial;
    QString systemDiskSerial;
    QString machineGuid;
    QString fingerprint;
};

struct LoginRequest { QString email; QString password; QString deviceFingerprint; };
struct LoginResponse { QString sessionId; QString challenge; QString challengeExpiresAt; QString requestId; };
struct DeviceVerifyRequest { QString sessionId; QString challenge; QString challengeSignature; QString tpmPublicKey; HardwareSignals hardware; };
struct DeviceVerifyResponse { QString token; QString tokenExpiresAt; QString licenseId; QString deviceId; QString requestId; };
struct UserProfileResponse
{
    QString email;
    QString accountStatus;
    QString product;
    QString licenseStatus;
    QDateTime licenseExpiresAt;
    int maxDevices = 0;
    QString deviceId;
    QString deviceStatus;
    QDateTime sessionExpiresAt;
    QString requestId;
};
struct ApiError { QString code; QString message; QString requestId; };

Q_DECLARE_METATYPE(LoginResponse)
Q_DECLARE_METATYPE(DeviceVerifyResponse)
Q_DECLARE_METATYPE(UserProfileResponse)
Q_DECLARE_METATYPE(ApiError)

class IApiClient : public QObject
{
    Q_OBJECT
public:
    using QObject::QObject;
    ~IApiClient() override = default;
    virtual void login(const LoginRequest &request, quint64 generation = 0) = 0;
    virtual void verifyDevice(const DeviceVerifyRequest &request, quint64 generation = 0) = 0;
    virtual void loadProfile(const QString &token, quint64 generation = 0) = 0;
    virtual void cancelProfile() = 0;
signals:
    void loginSucceeded(const LoginResponse &response, quint64 generation);
    void loginFailed(const ApiError &error, quint64 generation);
    void deviceVerified(const DeviceVerifyResponse &response, quint64 generation);
    void deviceVerificationFailed(const ApiError &error, quint64 generation);
    void profileLoaded(const UserProfileResponse &response, quint64 generation);
    void profileFailed(const ApiError &error, quint64 generation);
};

class ApiClient final : public IApiClient
{
    Q_OBJECT
public:
    static constexpr int RequestTimeoutMs = 15'000;
    explicit ApiClient(QUrl baseUrl, int timeoutMs = RequestTimeoutMs, QObject *parent = nullptr);
    void login(const LoginRequest &request, quint64 generation = 0) override;
    void verifyDevice(const DeviceVerifyRequest &request, quint64 generation = 0) override;
    void loadProfile(const QString &token, quint64 generation = 0) override;
    void cancelProfile() override;

private:
    QUrl baseUrl_;
    QNetworkAccessManager network_;
    int timeoutMs_;
    bool requestActive_ = false;
    QPointer<QNetworkReply> profileReply_;
    bool isAllowedTransport() const;
    void postJson(const QString &path, const QJsonObject &body, bool deviceRequest, quint64 generation);
    QString newRequestId() const;
};

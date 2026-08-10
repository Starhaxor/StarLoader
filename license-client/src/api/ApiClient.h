#pragma once

#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QObject>
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

struct LoginRequest { QString email; QString password; QString licenseKey; QString deviceFingerprint; };
struct LoginResponse { QString sessionId; QString challenge; QString challengeExpiresAt; QString requestId; };
struct DeviceVerifyRequest { QString sessionId; QString challenge; QString challengeSignature; QString tpmPublicKey; HardwareSignals hardware; };
struct DeviceVerifyResponse { QString token; QString tokenExpiresAt; QString licenseId; QString deviceId; QString requestId; };
struct ApiError { QString code; QString message; QString requestId; };

Q_DECLARE_METATYPE(LoginResponse)
Q_DECLARE_METATYPE(DeviceVerifyResponse)
Q_DECLARE_METATYPE(ApiError)

class IApiClient : public QObject
{
    Q_OBJECT
public:
    using QObject::QObject;
    ~IApiClient() override = default;
    virtual void login(const LoginRequest &request) = 0;
    virtual void verifyDevice(const DeviceVerifyRequest &request) = 0;
signals:
    void loginSucceeded(const LoginResponse &response);
    void loginFailed(const ApiError &error);
    void deviceVerified(const DeviceVerifyResponse &response);
    void deviceVerificationFailed(const ApiError &error);
};

class ApiClient final : public IApiClient
{
    Q_OBJECT
public:
    static constexpr int RequestTimeoutMs = 15'000;
    explicit ApiClient(QUrl baseUrl, QObject *parent = nullptr);
    void login(const LoginRequest &request) override;
    void verifyDevice(const DeviceVerifyRequest &request) override;

private:
    QUrl baseUrl_;
    QNetworkAccessManager network_;
    bool requestActive_ = false;
    bool isAllowedTransport() const;
    void postJson(const QString &path, const QJsonObject &body, bool deviceRequest);
    QString newRequestId() const;
};

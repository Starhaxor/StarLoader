#pragma once

#include "api/ApiClient.h"
#include "auth/AuthState.h"
#include "security/SessionTokenVerifier.h"

#include "hardware/HardwareIdentity.h"

class IHardwareCollector
{
public:
    virtual ~IHardwareCollector() = default;
    virtual bool collect(HardwareIdentity *identity, QString *error) = 0;
};

class IDeviceSigner
{
public:
    virtual ~IDeviceSigner() = default;
    virtual bool sign(const QByteArray &challenge, QByteArray *signature, QByteArray *publicKey, QString *error) = 0;
};

class SystemHardwareCollector final : public IHardwareCollector
{
public:
    bool collect(HardwareIdentity *identity, QString *error) override;
};

class TpmDeviceSigner final : public IDeviceSigner
{
public:
    bool sign(const QByteArray &challenge, QByteArray *signature, QByteArray *publicKey, QString *error) override;
};

class AuthManager final : public QObject
{
    Q_OBJECT
public:
    AuthManager(IApiClient &apiClient, IHardwareCollector &hardwareCollector, IDeviceSigner &deviceSigner, SessionTokenVerifier verifier, QObject *parent = nullptr);
    AuthState state() const;
    QString sessionToken() const;
    QString deviceDisplayId() const;
    void login(const QString &email, const QString &password, const QString &licenseKey);

signals:
    void stateChanged(AuthState state);
    void statusChanged(const QString &status);
    void failed(const ApiError &error);
    void authenticated();

private slots:
    void handleLoginSucceeded(const LoginResponse &response);
    void handleLoginFailed(const ApiError &error);
    void handleDeviceVerified(const DeviceVerifyResponse &response);
    void handleDeviceVerificationFailed(const ApiError &error);

private:
    IApiClient &apiClient_;
    IHardwareCollector &hardwareCollector_;
    IDeviceSigner &deviceSigner_;
    SessionTokenVerifier verifier_;
    AuthState state_ = AuthState::LoggedOut;
    HardwareIdentity hardware_;
    QString sessionId_;
    QByteArray challenge_;
    QString sessionToken_;
    void transition(AuthState state, const QString &status);
    void fail(const ApiError &error);
};

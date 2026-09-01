#pragma once

#include "api/ApiClient.h"
#include "auth/AuthState.h"
#include "security/SessionTokenVerifier.h"
#include "security/DeviceProof.h"

#include "hardware/HardwareIdentity.h"

#include <QFutureWatcher>
#include <functional>

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

struct SystemHardwareDependencies
{
    std::function<bool()> isTpmAvailable;
    std::function<bool(QString *)> ensureTpmKey;
    std::function<HardwareIdentity()> collectHardware;
};

class SystemHardwareCollector final : public IHardwareCollector
{
public:
    SystemHardwareCollector();
    explicit SystemHardwareCollector(SystemHardwareDependencies dependencies);
    bool collect(HardwareIdentity *identity, QString *error) override;
private:
    SystemHardwareDependencies dependencies_;
};

class TpmDeviceSigner final : public IDeviceSigner, public IDeviceProofSigner
{
public:
    bool sign(const QByteArray &challenge, QByteArray *signature, QByteArray *publicKey, QString *error) override;
    bool publicKeyBlob(QByteArray *publicBlob, QString *error) override;
    bool sign(QByteArrayView input, QByteArray *signature, QByteArray *publicBlob, QString *error) override;
};

class AuthManager final : public QObject
{
    Q_OBJECT
public:
    AuthManager(IApiClient &apiClient, IHardwareCollector &hardwareCollector, IDeviceSigner &deviceSigner, SessionTokenVerifier verifier, QObject *parent = nullptr);
    ~AuthManager() override;
    AuthState state() const;
    QString sessionToken() const;
    const UserProfileResponse &userProfile() const;
    QString deviceDisplayId() const;
    void login(const QString &email, const QString &password);
    void signOut();
    void cancelAndWait();

signals:
    void stateChanged(AuthState state);
    void statusChanged(const QString &status);
    void failed(const ApiError &error);
    void authenticated();

private slots:
    void handleLoginSucceeded(const LoginResponse &response, quint64 generation);
    void handleLoginFailed(const ApiError &error, quint64 generation);
    void handleDeviceVerified(const DeviceVerifyResponse &response, quint64 generation);
    void handleDeviceVerificationFailed(const ApiError &error, quint64 generation);
    void handleProfileLoaded(const UserProfileResponse &response, quint64 generation);
    void handleProfileFailed(const ApiError &error, quint64 generation);

private:
    friend class AuthManagerTest;
    IApiClient &apiClient_;
    IHardwareCollector &hardwareCollector_;
    IDeviceSigner &deviceSigner_;
    SessionTokenVerifier verifier_;
    AuthState state_ = AuthState::LoggedOut;
    HardwareIdentity hardware_;
    QString sessionId_;
    QByteArray challenge_;
    QString sessionToken_;
    UserProfileResponse userProfile_;
    bool profileLoading_ = false;
    struct CollectionResult { quint64 attempt = 0; bool success = false; HardwareIdentity identity; QString error; };
    struct SigningResult { quint64 attempt = 0; bool success = false; QByteArray signature; QByteArray publicKey; QString encodedChallenge; QString requestId; QString error; };
    struct PendingLogin { QString email; QString password; };
    QFutureWatcher<CollectionResult> collectionWatcher_;
    QFutureWatcher<SigningResult> signingWatcher_;
    PendingLogin pendingLogin_;
    quint64 attempt_ = 0;
    void transition(AuthState state, const QString &status);
    void fail(const ApiError &error);
    void clearSession();
    void completeCollection();
    void completeSigning();
};

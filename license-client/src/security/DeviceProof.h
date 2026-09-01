#pragma once

#include <QByteArray>
#include <QByteArrayView>
#include <QString>
#include <QUrl>

#include <functional>

class IDeviceProofSigner
{
public:
    virtual ~IDeviceProofSigner() = default;
    virtual bool publicKeyBlob(QByteArray *publicBlob, QString *error) = 0;
    virtual bool sign(QByteArrayView input, QByteArray *signature,
                      QByteArray *publicBlob, QString *error) = 0;
};

class TpmProofSigner : public IDeviceProofSigner
{
public:
    bool publicKeyBlob(QByteArray *publicBlob, QString *error) override;
    bool sign(QByteArrayView input, QByteArray *signature,
              QByteArray *publicBlob, QString *error) override;
};

struct ProofResult
{
    bool valid = false;
    QString compactJws;
    QString jwkThumbprint;
    QString error;
};

class IDeviceProofBuilder
{
public:
    virtual ~IDeviceProofBuilder() = default;
    virtual ProofResult build(const QString &method, const QUrl &url,
                              const QString &accessToken,
                              const QString &expectedThumbprint) const = 0;
};

class DeviceProofBuilder final : public IDeviceProofBuilder
{
public:
    using Clock = std::function<qint64()>;
    using RandomSource = std::function<QByteArray()>;

    explicit DeviceProofBuilder(IDeviceProofSigner &signer,
                                Clock clock = {},
                                RandomSource randomSource = {});

    ProofResult build(const QString &method, const QUrl &url,
                      const QString &accessToken,
                      const QString &expectedThumbprint) const override;

private:
    IDeviceProofSigner &signer_;
    Clock clock_;
    RandomSource randomSource_;
};

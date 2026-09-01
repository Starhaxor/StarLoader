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

class DeviceProofBuilder
{
public:
    using Clock = std::function<qint64()>;
    using RandomSource = std::function<QByteArray()>;

    explicit DeviceProofBuilder(IDeviceProofSigner &signer,
                                Clock clock = {},
                                RandomSource randomSource = {},
                                bool localDevelopment = false);

    ProofResult build(const QString &method, const QUrl &url,
                      const QString &accessToken,
                      const QString &expectedThumbprint) const;

private:
    IDeviceProofSigner &signer_;
    Clock clock_;
    RandomSource randomSource_;
    bool localDevelopment_ = false;
};

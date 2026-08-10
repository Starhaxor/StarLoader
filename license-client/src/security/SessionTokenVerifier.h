#pragma once

#include <QByteArray>
#include <QDateTime>
#include <QString>

struct VerificationResult { bool valid = false; QString error; QDateTime expiresAt; };

class SessionTokenVerifier
{
public:
    SessionTokenVerifier(QByteArray publicKey, QString issuer, QString audience, QString product);
    static SessionTokenVerifier fromBase64(const QString &encodedPublicKey, QString issuer, QString audience, QString product);
    bool isConfigured() const;
    VerificationResult verify(const QString &token, const QString &expectedDevice, const QString &expectedLicense) const;

private:
    QByteArray publicKey_;
    QString issuer_;
    QString audience_;
    QString product_;
    bool verifySignature(const QByteArray &message, const QByteArray &signature) const;
};

#pragma once

#include <QByteArray>
#include <QDateTime>
#include <QHash>
#include <QString>

struct VerifiedSession {
    bool valid = false;
    QString error;
    QDateTime expiresAt;
    QString sessionId;
    QString tokenId;
    QString deviceKeyThumbprint;
};

class SessionTokenVerifier
{
public:
    SessionTokenVerifier(QHash<QString, QByteArray> keys, QString issuer, QString audience, QString applicationID, QString productID, QString product);
    static SessionTokenVerifier fromConfiguredKeyRing(const QString &encodedKeys, QString issuer, QString audience, QString applicationID, QString productID, QString product);
    bool isConfigured() const;
    VerifiedSession verify(const QString &token, const QString &expectedDevice, const QString &expectedLicense) const;

private:
    QHash<QString, QByteArray> keys_;
    QString issuer_;
    QString audience_;
    QString applicationID_;
    QString productID_;
    QString product_;
    bool verifySignature(const QByteArray &publicKey, const QByteArray &message, const QByteArray &signature) const;
};

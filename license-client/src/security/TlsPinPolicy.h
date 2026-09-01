#pragma once

#include <QByteArray>
#include <QList>
#include <QString>
#include <QUrl>

class QSslCertificate;

class TlsPinPolicy final
{
public:
    TlsPinPolicy(QString expectedHost, QList<QByteArray> sha256Pins, bool localDevelopment);

    bool isValid() const;
    bool verify(const QUrl &requestUrl, const QSslCertificate &peer) const;
    bool permitsRequestUrl(const QUrl &requestUrl) const;

private:
    QString expectedHost_;
    QList<QByteArray> pinDigests_;
    bool localDevelopment_ = false;
    bool valid_ = false;
};

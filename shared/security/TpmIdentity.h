#pragma once

#include <QByteArray>
#include <QByteArrayView>
#include <QString>

class TpmIdentity
{
public:
    static bool isAvailable();
    static bool ensureKey(QString *error);
    static QByteArray publicKeyBlob();
    static QString publicKeySha256();
    static QByteArray signChallenge(QByteArrayView challenge, QString *error);
};

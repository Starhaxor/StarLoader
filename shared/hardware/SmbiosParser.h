#pragma once

#include <QByteArrayView>
#include <QString>

struct SmbiosInfo
{
    QString systemUuid;
    QString motherboardSerial;
    QString biosSerial;
};

class SmbiosParser
{
public:
    static SmbiosInfo parse(QByteArrayView rawTable);
};

#pragma once

#include <QList>
#include <QString>

class IDiskSerialSource
{
public:
    virtual ~IDiskSerialSource() = default;
    virtual QString serialNumber(quint32 diskNumber) = 0;
};

class DiskReader
{
public:
    static QString systemDiskSerial();
    static QString serialSignal(QList<quint32> diskNumbers,
                                IDiskSerialSource &source);
};

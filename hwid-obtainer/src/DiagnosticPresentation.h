#pragma once

#include <QString>

class DiagnosticPresentation
{
public:
    struct Signal
    {
        QString value;
        QString status;
    };

    struct StatusState
    {
        QString collection;
        QString tpmTest;
    };

    static Signal signalFor(const QString &value);
    static StatusState withCollectionStatus(StatusState status, const QString &message);
    static StatusState withTpmTestStatus(StatusState status, const QString &message);
};

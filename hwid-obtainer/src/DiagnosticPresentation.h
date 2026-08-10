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

    static Signal signalFor(const QString &value);
};

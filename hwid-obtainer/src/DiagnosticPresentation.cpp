#include "DiagnosticPresentation.h"

DiagnosticPresentation::Signal DiagnosticPresentation::signalFor(const QString &value)
{
    if (value.trimmed().isEmpty())
        return {QStringLiteral("<unavailable>"), QStringLiteral("Missing")};

    return {value, QStringLiteral("Available")};
}

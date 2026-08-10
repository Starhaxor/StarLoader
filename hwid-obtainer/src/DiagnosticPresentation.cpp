#include "DiagnosticPresentation.h"

DiagnosticPresentation::Signal DiagnosticPresentation::signalFor(const QString &value)
{
    if (value.trimmed().isEmpty())
        return {QStringLiteral("<unavailable>"), QStringLiteral("Missing")};

    return {value, QStringLiteral("Available")};
}

DiagnosticPresentation::StatusState DiagnosticPresentation::withCollectionStatus(
    StatusState status,
    const QString &message)
{
    status.collection = message;
    return status;
}

DiagnosticPresentation::StatusState DiagnosticPresentation::withTpmTestStatus(
    StatusState status,
    const QString &message)
{
    status.tpmTest = message;
    return status;
}

#include "DiagnosticPresentation.h"

#include <QtTest>

class DiagnosticPresentationTest final : public QObject
{
    Q_OBJECT

private slots:
    void presentsEmptySignalAsMissing();
    void presentsNonEmptySignalAsAvailable();
};

void DiagnosticPresentationTest::presentsEmptySignalAsMissing()
{
    const DiagnosticPresentation::Signal signal = DiagnosticPresentation::signalFor(QStringLiteral("   "));

    QCOMPARE(signal.value, QStringLiteral("<unavailable>"));
    QCOMPARE(signal.status, QStringLiteral("Missing"));
}

void DiagnosticPresentationTest::presentsNonEmptySignalAsAvailable()
{
    const DiagnosticPresentation::Signal signal = DiagnosticPresentation::signalFor(QStringLiteral(" TPM hash "));

    QCOMPARE(signal.value, QStringLiteral(" TPM hash "));
    QCOMPARE(signal.status, QStringLiteral("Available"));
}

QTEST_MAIN(DiagnosticPresentationTest)
#include "DiagnosticPresentationTest.moc"

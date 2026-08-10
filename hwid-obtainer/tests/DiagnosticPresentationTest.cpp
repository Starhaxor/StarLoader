#include "DiagnosticPresentation.h"

#include <QtTest>

class DiagnosticPresentationTest final : public QObject
{
    Q_OBJECT

private slots:
    void presentsEmptySignalAsMissing();
    void presentsNonEmptySignalAsAvailable();
    void preservesTpmResultWhenCollectionStatusChanges();
    void preservesCollectionStatusWhenTpmStatusChanges();
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

void DiagnosticPresentationTest::preservesTpmResultWhenCollectionStatusChanges()
{
    DiagnosticPresentation::StatusState status{
        QStringLiteral("Collecting hardware signals."),
        QStringLiteral("TPM test: valid signature PASS."),
    };

    status = DiagnosticPresentation::withCollectionStatus(
        status, QStringLiteral("Hardware collection complete."));

    QCOMPARE(status.collection, QStringLiteral("Hardware collection complete."));
    QCOMPARE(status.tpmTest, QStringLiteral("TPM test: valid signature PASS."));
}

void DiagnosticPresentationTest::preservesCollectionStatusWhenTpmStatusChanges()
{
    DiagnosticPresentation::StatusState status{
        QStringLiteral("Hardware collection complete."),
        QStringLiteral("TPM test not run."),
    };

    status = DiagnosticPresentation::withTpmTestStatus(
        status, QStringLiteral("TPM test: valid signature PASS."));

    QCOMPARE(status.collection, QStringLiteral("Hardware collection complete."));
    QCOMPARE(status.tpmTest, QStringLiteral("TPM test: valid signature PASS."));
}

QTEST_MAIN(DiagnosticPresentationTest)
#include "DiagnosticPresentationTest.moc"

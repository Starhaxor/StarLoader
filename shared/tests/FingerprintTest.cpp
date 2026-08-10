#include "hardware/HardwareIdentity.h"
#include "security/Fingerprint.h"
#include "security/HardwareNormalization.h"

#include <QCryptographicHash>
#include <QtTest>

class FingerprintTest final : public QObject {
    Q_OBJECT

private slots:
    void qtRuntimeIsAvailable();
    void normalizesHardwareValues();
    void usesEveryFieldInStableOrder();
    void displayIdFormatsFirstTwelveFingerprintCharacters();
};

void FingerprintTest::qtRuntimeIsAvailable()
{
    QVERIFY(QCoreApplication::instance() != nullptr);
}

void FingerprintTest::normalizesHardwareValues()
{
    QCOMPARE(normalizeHardwareValue(" {ab-c 12} "), QString("ABC12"));
}

void FingerprintTest::usesEveryFieldInStableOrder()
{
    HardwareIdentity hw{"uuid", "board", "bios", "disk", "guid", "x64", "host", "tpm", {}};
    const auto first = Fingerprint::generate(hw);
    hw.machineGuid = "different";
    QVERIFY(first != Fingerprint::generate(hw));
    QCOMPARE(first.size(), 64);

    const QByteArray expectedInput("UUID|BOARD|BIOS|DISK|GUID|TPM|");
    const QString expected = QCryptographicHash::hash(
        expectedInput, QCryptographicHash::Sha256).toHex().toUpper();
    hw.machineGuid = "guid";
    QCOMPARE(Fingerprint::generate(hw), expected);
}

void FingerprintTest::displayIdFormatsFirstTwelveFingerprintCharacters()
{
    HardwareIdentity hw{"uuid", "board", "bios", "disk", "guid", "x64", "host", "tpm", "ABCDEF1234567890"};
    QCOMPARE(hw.displayId(), QString("ABCDEF-123456"));
}

QTEST_MAIN(FingerprintTest)
#include "FingerprintTest.moc"

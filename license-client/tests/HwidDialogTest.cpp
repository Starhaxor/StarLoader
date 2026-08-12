#include "auth/AuthManager.h"
#include "ui/HwidDialog.h"

#include <QApplication>
#include <QClipboard>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTest>

class FakeHardwareCollector final : public IHardwareCollector
{
public:
    bool succeeds = true;
    HardwareIdentity identity;

    bool collect(HardwareIdentity *output, QString *error) override
    {
        if (!succeeds) {
            *error = QStringLiteral("raw collector detail");
            return false;
        }

        *output = identity;
        return true;
    }
};

class HwidDialogTest final : public QObject
{
    Q_OBJECT

private slots:
    void showsOnlyFinalFingerprintAndCopiesIt();
    void showsSafeErrorWhenCollectionFails();
};

void HwidDialogTest::showsOnlyFinalFingerprintAndCopiesIt()
{
    FakeHardwareCollector collector;
    collector.identity.finalFingerprint = QStringLiteral("ABCDEF0123456789");
    collector.identity.smbiosUuid = QStringLiteral("raw-smbios-uuid");
    collector.identity.motherboardSerial = QStringLiteral("raw-motherboard-serial");
    collector.identity.biosSerial = QStringLiteral("raw-bios-serial");
    collector.identity.systemDiskSerial = QStringLiteral("raw-disk-serial");
    collector.identity.machineGuid = QStringLiteral("raw-machine-guid");
    collector.identity.cpuArchitecture = QStringLiteral("raw-cpu-architecture");
    collector.identity.hostName = QStringLiteral("raw-host-name");
    collector.identity.tpmPublicKeyHash = QStringLiteral("raw-tpm-public-key-hash");

    HwidDialog dialog(collector);
    dialog.show();

    auto *hwidLineEdit = dialog.findChild<QLineEdit *>(QStringLiteral("hwidLineEdit"));
    auto *copyButton = dialog.findChild<QPushButton *>(QStringLiteral("copyButton"));
    QVERIFY(hwidLineEdit);
    QVERIFY(copyButton);

    QTRY_COMPARE(hwidLineEdit->text(), collector.identity.finalFingerprint);
    QVERIFY(copyButton->isEnabled());

    QString visibleText;
    for (const QLabel *label : dialog.findChildren<QLabel *>())
        visibleText += label->text();
    visibleText += hwidLineEdit->text();

    QVERIFY(!visibleText.contains(collector.identity.smbiosUuid));
    QVERIFY(!visibleText.contains(collector.identity.motherboardSerial));
    QVERIFY(!visibleText.contains(collector.identity.biosSerial));
    QVERIFY(!visibleText.contains(collector.identity.systemDiskSerial));
    QVERIFY(!visibleText.contains(collector.identity.machineGuid));
    QVERIFY(!visibleText.contains(collector.identity.cpuArchitecture));
    QVERIFY(!visibleText.contains(collector.identity.hostName));
    QVERIFY(!visibleText.contains(collector.identity.tpmPublicKeyHash));

    QTest::mouseClick(copyButton, Qt::LeftButton);
    QTRY_COMPARE(QApplication::clipboard()->text(), collector.identity.finalFingerprint);
}

void HwidDialogTest::showsSafeErrorWhenCollectionFails()
{
    FakeHardwareCollector collector;
    collector.succeeds = false;

    HwidDialog dialog(collector);
    dialog.show();

    auto *copyButton = dialog.findChild<QPushButton *>(QStringLiteral("copyButton"));
    auto *descriptionLabel = dialog.findChild<QLabel *>(QStringLiteral("descriptionLabel"));
    QVERIFY(copyButton);
    QVERIFY(descriptionLabel);

    QTRY_COMPARE(descriptionLabel->text(), QStringLiteral("Device ID could not be calculated."));
    QVERIFY(!copyButton->isEnabled());
    QVERIFY(!descriptionLabel->text().contains(QStringLiteral("raw collector detail")));
}

QTEST_MAIN(HwidDialogTest)

#include "HwidDialogTest.moc"

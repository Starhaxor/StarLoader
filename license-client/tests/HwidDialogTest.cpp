#include "auth/AuthManager.h"
#include "ui/HwidDialog.h"

#include <QApplication>
#include <QClipboard>
#include <QLabel>
#include <QLineEdit>
#include <QTest>
#include <QToolButton>

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
    void usesCompactHorizontalLayout();
    void usesCloseOnlyIconFreeCustomWindowChrome();
    void showsOnlyFinalFingerprintAndCopiesIt();
    void showsSafeErrorWhenCollectionFails();
};

void HwidDialogTest::usesCompactHorizontalLayout()
{
    FakeHardwareCollector collector;
    HwidDialog dialog(collector);

    auto *copyButton = dialog.findChild<QToolButton *>(QStringLiteral("copyButton"));
    QVERIFY(copyButton);
    QCOMPARE(dialog.windowTitle(), QStringLiteral("HWID Obtainer Tool"));
    QVERIFY(dialog.width() <= 420);
    QVERIFY(dialog.height() <= 120);
    QVERIFY(!dialog.findChild<QLabel *>(QStringLiteral("titleLabel")));
    auto *descriptionLabel = dialog.findChild<QLabel *>(QStringLiteral("descriptionLabel"));
    QVERIFY(descriptionLabel);
    auto *hwidLineEdit = dialog.findChild<QLineEdit *>(QStringLiteral("hwidLineEdit"));
    QVERIFY(hwidLineEdit);

    // Same palette as the login form, embedded inline (theme-independent).
    QVERIFY(dialog.styleSheet().contains(QStringLiteral("#0B1117")));
    QVERIFY(descriptionLabel->styleSheet().contains(QStringLiteral("#9AAAB2")));
    QVERIFY(hwidLineEdit->styleSheet().contains(QStringLiteral("#111A22")));
    QVERIFY(hwidLineEdit->styleSheet().contains(QStringLiteral("#2AB8C6")));
    QVERIFY(copyButton->styleSheet().contains(QStringLiteral("#1B2732")));

    QVERIFY(copyButton->width() <= 36);
    QVERIFY(copyButton->text().isEmpty());
    QVERIFY(!copyButton->icon().isNull());
    QVERIFY(!dialog.findChild<QWidget *>(QStringLiteral("closeButton")));
}

void HwidDialogTest::usesCloseOnlyIconFreeCustomWindowChrome()
{
    FakeHardwareCollector collector;
    HwidDialog dialog(collector);

    QVERIFY(dialog.windowFlags().testFlag(Qt::FramelessWindowHint));
    QVERIFY(dialog.windowIcon().isNull());
    auto *titleBar = dialog.findChild<QWidget *>(QStringLiteral("windowTitleBar"));
    QVERIFY(titleBar);
    QVERIFY(titleBar->findChild<QLabel *>(QStringLiteral("windowTitleText")));
    QVERIFY(!titleBar->findChild<QLabel *>(QStringLiteral("windowIcon")));
    QVERIFY(!titleBar->findChild<QToolButton *>(QStringLiteral("windowMinimizeButton")));

    auto *closeButton = titleBar->findChild<QToolButton *>(QStringLiteral("windowCloseButton"));
    QVERIFY(closeButton);
    QVERIFY(closeButton->icon().isNull());
    QCOMPARE(closeButton->accessibleName(), QStringLiteral("Close window"));
}

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
    auto *copyButton = dialog.findChild<QToolButton *>(QStringLiteral("copyButton"));
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

    auto *copyButton = dialog.findChild<QToolButton *>(QStringLiteral("copyButton"));
    auto *descriptionLabel = dialog.findChild<QLabel *>(QStringLiteral("descriptionLabel"));
    QVERIFY(copyButton);
    QVERIFY(descriptionLabel);

    QTRY_COMPARE(descriptionLabel->text(), QStringLiteral("Device ID could not be calculated."));
    QVERIFY(!copyButton->isEnabled());
    QVERIFY(!descriptionLabel->text().contains(QStringLiteral("raw collector detail")));
}

QTEST_MAIN(HwidDialogTest)

#include "HwidDialogTest.moc"

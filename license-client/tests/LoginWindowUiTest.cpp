#include "ui_LoginWindow.h"

#include <QLabel>
#include <QLineEdit>
#include <QMainWindow>
#include <QPushButton>
#include <QtTest>

class LoginWindowUiTest final : public QObject
{
    Q_OBJECT

private slots:
    void usesCompactBrandedLayout();
    void exposesOnlyEmailAndPasswordInputs();
};

void LoginWindowUiTest::usesCompactBrandedLayout()
{
    QMainWindow window;
    Ui::LoginWindow ui;
    ui.setupUi(&window);

    QLabel *title = window.findChild<QLabel *>(QStringLiteral("titleLabel"));
    QVERIFY(title);
    QCOMPARE(window.windowTitle(), QStringLiteral("StarLoader"));
    QCOMPARE(title->text(), QStringLiteral("StarLoader"));
    QVERIFY(title->font().italic());
    QVERIFY(window.width() <= 340);
    QVERIFY(window.height() <= 400);
    QVERIFY(!window.findChild<QLabel *>(QStringLiteral("logoLabel")));
}

void LoginWindowUiTest::exposesOnlyEmailAndPasswordInputs()
{
    QMainWindow window;
    Ui::LoginWindow ui;
    ui.setupUi(&window);

    QVERIFY(window.findChild<QLineEdit *>(QStringLiteral("emailLineEdit")));
    QVERIFY(window.findChild<QLineEdit *>(QStringLiteral("passwordLineEdit")));
    QVERIFY(!window.findChild<QLineEdit *>(QStringLiteral("licenseKeyLineEdit")));
    QVERIFY(!window.findChild<QLineEdit *>(QStringLiteral("deviceIdLineEdit")));
    QVERIFY(!window.findChild<QLabel *>(QStringLiteral("requestIdLabel")));
    QVERIFY(window.findChild<QPushButton *>(QStringLiteral("loginButton")));
    QLabel *hwidLink = window.findChild<QLabel *>(QStringLiteral("hwidLink"));
    QVERIFY(hwidLink);
    QVERIFY(hwidLink->text().contains(QStringLiteral("href=\"hwid\"")));
    QVERIFY(hwidLink->text().contains(QStringLiteral("View HWID")));
}

QTEST_MAIN(LoginWindowUiTest)

#include "LoginWindowUiTest.moc"

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
    void exposesOnlyEmailAndPasswordInputs();
};

void LoginWindowUiTest::exposesOnlyEmailAndPasswordInputs()
{
    QMainWindow window;
    Ui::LoginWindow ui;
    ui.setupUi(&window);

    QVERIFY(window.findChild<QLineEdit *>(QStringLiteral("emailLineEdit")));
    QVERIFY(window.findChild<QLineEdit *>(QStringLiteral("passwordLineEdit")));
    QVERIFY(!window.findChild<QLineEdit *>(QStringLiteral("licenseKeyLineEdit")));
    QVERIFY(!window.findChild<QLineEdit *>(QStringLiteral("deviceIdLineEdit")));
    QVERIFY(window.findChild<QPushButton *>(QStringLiteral("loginButton")));
    QLabel *hwidLink = window.findChild<QLabel *>(QStringLiteral("hwidLink"));
    QVERIFY(hwidLink);
    QVERIFY(hwidLink->text().contains(QStringLiteral("href=\"hwid\"")));
}

QTEST_MAIN(LoginWindowUiTest)

#include "LoginWindowUiTest.moc"

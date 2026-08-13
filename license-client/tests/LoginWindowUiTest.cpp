#include "ui/LoginWindow.h"

#include "api/ApiClient.h"

#include <QApplication>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QToolButton>
#include <QtTest>

class LoginWindowUiTest final : public QObject
{
    Q_OBJECT

private slots:
    void usesCompactBrandedLayout();
    void exposesOnlyEmailAndPasswordInputs();
    void usesIconFreeCustomWindowChrome();
    void failureOpensMessageBoxWithErrorCode();
};

void LoginWindowUiTest::usesCompactBrandedLayout()
{
    LoginWindow window;

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
    LoginWindow window;

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

void LoginWindowUiTest::usesIconFreeCustomWindowChrome()
{
    LoginWindow window;

    QVERIFY(window.windowFlags().testFlag(Qt::FramelessWindowHint));
    QVERIFY(window.windowIcon().isNull());
    auto *titleBar = window.findChild<QWidget *>(QStringLiteral("windowTitleBar"));
    QVERIFY(titleBar);
    QVERIFY(titleBar->findChild<QLabel *>(QStringLiteral("windowTitleText")));
    QVERIFY(!titleBar->findChild<QLabel *>(QStringLiteral("windowIcon")));

    auto *minimizeButton = titleBar->findChild<QToolButton *>(QStringLiteral("windowMinimizeButton"));
    auto *closeButton = titleBar->findChild<QToolButton *>(QStringLiteral("windowCloseButton"));
    QVERIFY(minimizeButton);
    QVERIFY(closeButton);
    QVERIFY(minimizeButton->icon().isNull());
    QVERIFY(closeButton->icon().isNull());
    QCOMPARE(minimizeButton->accessibleName(), QStringLiteral("Minimize window"));
    QCOMPARE(closeButton->accessibleName(), QStringLiteral("Close window"));
}

void LoginWindowUiTest::failureOpensMessageBoxWithErrorCode()
{
    qRegisterMetaType<ApiError>("ApiError");

    LoginWindow window;
    window.show();

    ApiError error;
    error.code = QStringLiteral("INVALID_SESSION_TOKEN");
    error.message = QStringLiteral("Session token is invalid.");

    QVERIFY(QMetaObject::invokeMethod(&window, "showFailure", Qt::DirectConnection, Q_ARG(ApiError, error)));
    QTest::qWait(50);

    // Inline status feedback is kept alongside the message box.
    QLabel *statusLabel = window.findChild<QLabel *>(QStringLiteral("statusLabel"));
    QVERIFY(statusLabel);
    QVERIFY(!statusLabel->text().isEmpty());

    QMessageBox *box = nullptr;
    const QWidgetList topLevel = QApplication::topLevelWidgets();
    for (QWidget *widget : topLevel) {
        if (auto *candidate = qobject_cast<QMessageBox *>(widget)) {
            if (candidate->isVisible()) { box = candidate; break; }
        }
    }
    QVERIFY(box);
    QCOMPARE(box->windowTitle(), QStringLiteral("Sign-in failed"));
    QVERIFY(box->informativeText().contains(QStringLiteral("INVALID_SESSION_TOKEN")));

    box->close();
    QTest::qWait(20);
}

QTEST_MAIN(LoginWindowUiTest)

#include "LoginWindowUiTest.moc"

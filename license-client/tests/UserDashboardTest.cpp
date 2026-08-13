#include "api/ApiClient.h"
#include "auth/AuthManager.h"
#include "auth/AuthState.h"
#include "ui/LoginWindow.h"
#include "ui/UserDashboard.h"

#include <QAbstractButton>
#include <QApplication>
#include <QFrame>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QPushButton>
#include <QRegularExpression>
#include <QSignalSpy>
#include <QToolButton>
#include <QtTest>

class UserDashboardTest final : public QObject
{
    Q_OBJECT

private slots:
    void presentsSafeProfileInCompactSingleCard();
    void usesIconFreeChromeAndOnePanelAction();
    void requestsSignOutFromItsOnlyAction();
    void validatedAuthenticationShowsExactlyOneDashboard();
    void signOutClearsCredentialsAndReturnsToLogin();
    void closingDashboardDoesNotResurrectLogin();
};

namespace {

UserProfileResponse literalProfile()
{
    return {
        QStringLiteral("test2@test.com"),
        QStringLiteral("active"),
        QStringLiteral("StarLoader"),
        QStringLiteral("active"),
        QDateTime::fromString(QStringLiteral("2026-09-12T17:42:56Z"), Qt::ISODate),
        1,
        QStringLiteral("019ffc3f-0396-7266-b82c-35371486cc4e"),
        QStringLiteral("active"),
        QDateTime::fromString(QStringLiteral("2026-08-13T18:50:15Z"), Qt::ISODate),
        QStringLiteral("profile-request")
    };
}

QList<UserDashboard *> openDashboards()
{
    QList<UserDashboard *> dashboards;
    for (QWidget *widget : QApplication::topLevelWidgets()) {
        if (auto *dashboard = qobject_cast<UserDashboard *>(widget)) {
            dashboards.append(dashboard);
        }
    }
    return dashboards;
}

AuthManager *authenticatedManager(LoginWindow &login)
{
    auto *manager = login.findChild<AuthManager *>();
    if (manager != nullptr) {
        QMetaObject::invokeMethod(manager, "authenticated", Qt::DirectConnection);
        QCoreApplication::processEvents();
    }
    return manager;
}

} // namespace

void UserDashboardTest::presentsSafeProfileInCompactSingleCard()
{
    UserDashboard dashboard(literalProfile(), QStringLiteral("ABCDEF-123456"));
    dashboard.show();
    QCoreApplication::processEvents();

    const auto cards = dashboard.findChildren<QFrame *>(QRegularExpression(QStringLiteral(".*Card$")));
    QCOMPARE(cards.size(), 1);
    QCOMPARE(cards.constFirst()->objectName(), QStringLiteral("dashboardCard"));

    const QStringList requiredLabels = {
        QStringLiteral("dashboardBrandLabel"),
        QStringLiteral("activeStatusIndicator"),
        QStringLiteral("emailValue"),
        QStringLiteral("accountStatusValue"),
        QStringLiteral("productValue"),
        QStringLiteral("licenseStatusValue"),
        QStringLiteral("licenseExpiryValue"),
        QStringLiteral("maxDevicesValue"),
        QStringLiteral("deviceStatusValue"),
        QStringLiteral("deviceIdValue"),
        QStringLiteral("hwidValue"),
        QStringLiteral("sessionExpiryValue")
    };
    for (const QString &objectName : requiredLabels) {
        auto *label = dashboard.findChild<QLabel *>(objectName);
        QVERIFY2(label, qPrintable(QStringLiteral("Missing dashboard label: %1").arg(objectName)));
        QVERIFY2(label->isVisible(), qPrintable(QStringLiteral("Hidden dashboard label: %1").arg(objectName)));
    }

    const auto labelText = [&dashboard](const char *objectName) {
        return dashboard.findChild<QLabel *>(QString::fromLatin1(objectName))->text();
    };

    auto *brand = dashboard.findChild<QLabel *>(QStringLiteral("dashboardBrandLabel"));
    QVERIFY(brand);
    QCOMPARE(brand->text(), QStringLiteral("StarLoader"));
    QVERIFY(brand->font().italic());

    auto *activeIndicator = dashboard.findChild<QLabel *>(QStringLiteral("activeStatusIndicator"));
    QVERIFY(activeIndicator);
    QCOMPARE(activeIndicator->text(), QStringLiteral("Active"));
    QCOMPARE(activeIndicator->property("state").toString(), QStringLiteral("success"));

    int successIndicators = 0;
    for (const auto *label : dashboard.findChildren<QLabel *>()) {
        if (label->property("state").toString() == QStringLiteral("success")) {
            ++successIndicators;
        }
    }
    QCOMPARE(successIndicators, 1);

    QCOMPARE(labelText("emailValue"), QStringLiteral("test2@test.com"));
    QCOMPARE(labelText("accountStatusValue"), QStringLiteral("Active"));
    QCOMPARE(labelText("productValue"), QStringLiteral("StarLoader"));
    QCOMPARE(labelText("licenseStatusValue"), QStringLiteral("Active"));
    QCOMPARE(labelText("licenseExpiryValue"), QStringLiteral("12 Sep 2026"));
    QCOMPARE(labelText("maxDevicesValue"), QStringLiteral("1"));
    QCOMPARE(labelText("deviceStatusValue"), QStringLiteral("Active"));
    QCOMPARE(labelText("deviceIdValue"), QStringLiteral("019ffc3f\u20261486cc4e"));
    QCOMPARE(labelText("hwidValue"), QStringLiteral("ABCDEF-123456"));
    QCOMPARE(labelText("sessionExpiryValue"), QStringLiteral("13 Aug 2026, 18:50 UTC"));

    QCOMPARE(dashboard.minimumSize(), dashboard.maximumSize());
    QVERIFY(dashboard.width() <= 520);
    QVERIFY(dashboard.height() <= 620);
}

void UserDashboardTest::usesIconFreeChromeAndOnePanelAction()
{
    UserDashboard dashboard(literalProfile(), QStringLiteral("ABCDEF-123456"));

    QVERIFY(dashboard.windowFlags().testFlag(Qt::FramelessWindowHint));
    QVERIFY(dashboard.windowIcon().isNull());

    auto *titleBar = dashboard.findChild<QWidget *>(QStringLiteral("windowTitleBar"));
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

    auto *card = dashboard.findChild<QFrame *>(QStringLiteral("dashboardCard"));
    QVERIFY(card);
    const auto panelActions = card->findChildren<QPushButton *>();
    QCOMPARE(panelActions.size(), 1);
    QCOMPARE(panelActions.constFirst()->objectName(), QStringLiteral("signOutButton"));
    QCOMPARE(panelActions.constFirst()->text(), QStringLiteral("Sign out"));

    const QStringList forbiddenTerms = {
        QStringLiteral("launch"),
        QStringLiteral("password"),
        QStringLiteral("license key"),
        QStringLiteral("license_key"),
        QStringLiteral("hmac"),
        QStringLiteral("tpm public"),
        QStringLiteral("serial number"),
        QStringLiteral("session token")
    };
    const auto widgets = dashboard.findChildren<QWidget *>();
    for (const QWidget *widget : widgets) {
        QString presented = widget->objectName();
        if (const auto *label = qobject_cast<const QLabel *>(widget)) {
            presented += QLatin1Char(' ') + label->text();
        } else if (const auto *button = qobject_cast<const QAbstractButton *>(widget)) {
            presented += QLatin1Char(' ') + button->text();
        }
        presented = presented.toLower();
        for (const QString &term : forbiddenTerms) {
            QVERIFY2(!presented.contains(term), qPrintable(QStringLiteral("Unsafe dashboard term '%1' in '%2'").arg(term, presented)));
        }
    }
}

void UserDashboardTest::requestsSignOutFromItsOnlyAction()
{
    UserDashboard dashboard(literalProfile(), QStringLiteral("ABCDEF-123456"));
    QSignalSpy signOutSpy(&dashboard, &UserDashboard::signOutRequested);

    auto *signOutButton = dashboard.findChild<QPushButton *>(QStringLiteral("signOutButton"));
    QVERIFY(signOutButton);
    QTest::mouseClick(signOutButton, Qt::LeftButton);

    QCOMPARE(signOutSpy.count(), 1);
}

void UserDashboardTest::validatedAuthenticationShowsExactlyOneDashboard()
{
    LoginWindow login;
    login.show();
    QCoreApplication::processEvents();

    AuthManager *manager = authenticatedManager(login);
    QVERIFY(manager);
    QVERIFY(!login.isVisible());

    const auto firstDashboards = openDashboards();
    QCOMPARE(firstDashboards.size(), 1);
    QVERIFY(firstDashboards.constFirst()->isVisible());
    QPointer<UserDashboard> firstDashboard = firstDashboards.constFirst();

    QMetaObject::invokeMethod(manager, "authenticated", Qt::DirectConnection);
    QCoreApplication::processEvents();
    const auto secondDashboards = openDashboards();
    QCOMPARE(secondDashboards.size(), 1);
    QCOMPARE(secondDashboards.constFirst(), firstDashboard.data());

    login.show();
    delete firstDashboard.data();
}

void UserDashboardTest::signOutClearsCredentialsAndReturnsToLogin()
{
    LoginWindow login;
    auto *email = login.findChild<QLineEdit *>(QStringLiteral("emailLineEdit"));
    auto *password = login.findChild<QLineEdit *>(QStringLiteral("passwordLineEdit"));
    QVERIFY(email);
    QVERIFY(password);
    email->setText(QStringLiteral("test2@test.com"));
    password->setText(QStringLiteral("correct horse battery staple"));
    login.show();

    AuthManager *manager = authenticatedManager(login);
    QVERIFY(manager);
    QSignalSpy stateSpy(manager, &AuthManager::stateChanged);
    QSignalSpy statusSpy(manager, &AuthManager::statusChanged);

    const auto dashboards = openDashboards();
    QCOMPARE(dashboards.size(), 1);
    QPointer<UserDashboard> dashboard = dashboards.constFirst();
    auto *signOutButton = dashboard->findChild<QPushButton *>(QStringLiteral("signOutButton"));
    QVERIFY(signOutButton);
    QTest::mouseClick(signOutButton, Qt::LeftButton);

    QTRY_VERIFY(dashboard.isNull());
    QCOMPARE(manager->state(), AuthState::LoggedOut);
    QVERIFY(!stateSpy.isEmpty());
    QCOMPARE(qvariant_cast<AuthState>(stateSpy.constLast().constFirst()), AuthState::LoggedOut);
    QVERIFY(!statusSpy.isEmpty());
    QCOMPARE(statusSpy.constLast().constFirst().toString(), QStringLiteral("Signed out."));
    QVERIFY(manager->sessionToken().isEmpty());
    QVERIFY(manager->userProfile().email.isEmpty());
    QVERIFY(manager->deviceDisplayId().isEmpty());
    QVERIFY(email->text().isEmpty());
    QVERIFY(password->text().isEmpty());
    QVERIFY(login.isVisible());
    QCOMPARE(openDashboards().size(), 0);
}

void UserDashboardTest::closingDashboardDoesNotResurrectLogin()
{
    LoginWindow login;
    login.show();
    QCoreApplication::processEvents();
    QVERIFY(authenticatedManager(login));

    const auto dashboards = openDashboards();
    QCOMPARE(dashboards.size(), 1);
    QPointer<UserDashboard> dashboard = dashboards.constFirst();
    QVERIFY(QApplication::quitOnLastWindowClosed());
    QVERIFY(dashboard->testAttribute(Qt::WA_QuitOnClose));

    dashboard->close();
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);

    QVERIFY(dashboard.isNull());
    QVERIFY(!login.isVisible());
    QCOMPARE(openDashboards().size(), 0);
}

QTEST_MAIN(UserDashboardTest)

#include "UserDashboardTest.moc"

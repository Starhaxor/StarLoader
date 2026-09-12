#include "api/ApiClient.h"
#include "auth/AuthManager.h"
#include "auth/AuthState.h"
#include "ui/LoginWindow.h"
#include "ui/UserDashboard.h"

#include <QAbstractButton>
#include <QApplication>
#include <QClipboard>
#include <QDebug>
#include <QEvent>
#include <QFrame>
#include <QFontDatabase>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QProcess>
#include <QProcessEnvironment>
#include <QPushButton>
#include <QRegularExpression>
#include <QSignalSpy>
#include <QTextStream>
#include <QToolButton>
#include <QTimer>
#include <QtTest>

class UserDashboardTest final : public QObject
{
    Q_OBJECT

private slots:
    void offersOnlyExecutableSelectionForFixedPayload();
    void successfulLoadClosesDashboard();
    void showsOnlyAccountAndLicenseSummary();
    void usesIconFreeChromeAndAccountAndGameActions();
    void requestsSignOutFromItsOnlyAction();
    void validatedAuthenticationShowsExactlyOneDashboard();
    void signOutClearsCredentialsAndReturnsToLogin();
    void expiryClosesDashboardAndRestoresCredentials();
    void closingDashboardDoesNotResurrectLogin();
    void closingDashboardExitsRealApplicationLoop();
};

namespace {

constexpr auto DashboardCloseHelperArgument = "--dashboard-close-helper";

class LoginShowCounter final : public QObject
{
public:
    explicit LoginShowCounter(LoginWindow &login) : login_(&login) {}

    int showCount() const { return showCount_; }

protected:
    bool eventFilter(QObject *watched, QEvent *event) override
    {
        if (watched == login_ && event->type() == QEvent::Show) {
            ++showCount_;
        }
        return QObject::eventFilter(watched, event);
    }

private:
    LoginWindow *login_;
    int showCount_ = 0;
};

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

int runDashboardCloseHelper(int argc, char **argv)
{
    QApplication application(argc, argv);
    application.setApplicationName(QStringLiteral("StarLoader dashboard close helper"));
    application.setAttribute(Qt::AA_Use96Dpi, true);

    LoginWindow login;
    LoginShowCounter loginShows(login);
    login.installEventFilter(&loginShows);
    login.show();

    bool watchdogExpired = false;
    QTimer watchdog;
    watchdog.setSingleShot(true);
    QObject::connect(&watchdog, &QTimer::timeout, &application, [&] {
        watchdogExpired = true;
        application.exit(70);
    });
    watchdog.start(3'000);

    QTimer::singleShot(0, &application, [&] {
        AuthManager *manager = login.findChild<AuthManager *>();
        if (manager == nullptr
            || !QMetaObject::invokeMethod(manager, "authenticated", Qt::DirectConnection)) {
            application.exit(71);
            return;
        }

        const auto dashboards = openDashboards();
        const bool dashboardVisible = dashboards.size() == 1
                                      && dashboards.constFirst()->isVisible();
        if (!dashboardVisible || login.isVisible() || loginShows.showCount() != 1) {
            application.exit(72);
            return;
        }

        QPointer<UserDashboard> dashboard = dashboards.constFirst();
        QTimer::singleShot(0, dashboard.data(), [dashboard] {
            if (dashboard != nullptr) {
                dashboard->close();
            }
        });
    });

    const int eventLoopResult = application.exec();
    watchdog.stop();

    if (watchdogExpired || eventLoopResult != 0 || login.isVisible()
        || loginShows.showCount() != 1 || !openDashboards().isEmpty()) {
        qCritical().noquote()
            << QStringLiteral("DASHBOARD_CLOSE_HELPER_FAILED result=%1 watchdog=%2 login_visible=%3 show_count=%4 dashboards=%5")
                   .arg(eventLoopResult)
                   .arg(watchdogExpired)
                   .arg(login.isVisible())
                   .arg(loginShows.showCount())
                   .arg(openDashboards().size());
        return eventLoopResult == 0 ? 73 : eventLoopResult;
    }

    QTextStream output(stdout);
    output << "DASHBOARD_CLOSE_HELPER_OK dashboard_visible=1 show_count="
           << loginShows.showCount() << Qt::endl;
    return 0;
}

} // namespace

void UserDashboardTest::offersOnlyExecutableSelectionForFixedPayload()
{
    const QString screenshot = qEnvironmentVariable("STARLOADER_DASHBOARD_SCREENSHOT");
    if (!screenshot.isEmpty()) QFontDatabase::addApplicationFont(QStringLiteral("C:/Windows/Fonts/segoeui.ttf"));
    UserDashboard dashboard(literalProfile(), QStringLiteral("TEST-HWID"));
    auto *button = dashboard.findChild<QPushButton *>(QStringLiteral("selectGameButton"));
    QVERIFY2(button, "Authenticated dashboard must offer game EXE selection");
    QVERIFY(!dashboard.findChild<QPushButton *>(QStringLiteral("selectDllButton")));
    if (!screenshot.isEmpty()) {
        dashboard.show();
        QCoreApplication::processEvents();
        QVERIFY(dashboard.grab().save(screenshot));
    }
}

void UserDashboardTest::successfulLoadClosesDashboard()
{
    QPointer<UserDashboard> dashboard = new UserDashboard(literalProfile(), QStringLiteral("TEST-HWID"));
    dashboard->show();
    auto *panel = dashboard->findChild<QWidget *>(QStringLiteral("launchPanel"));
    QVERIFY(panel);
    // Exercise the dashboard's real completion connection without executing a DLL.
    QVERIFY(QMetaObject::invokeMethod(panel, "completed", Qt::DirectConnection));
    QTRY_VERIFY(dashboard.isNull());
}

void UserDashboardTest::showsOnlyAccountAndLicenseSummary()
{
    UserDashboard dashboard(literalProfile(), QStringLiteral("ABCDEF-123456"));
    dashboard.show();
    QCoreApplication::processEvents();
    auto *email = dashboard.findChild<QLabel *>(QStringLiteral("emailValue"));
    auto *license = dashboard.findChild<QLabel *>(QStringLiteral("activeStatusIndicator"));
    auto *expiry = dashboard.findChild<QLabel *>(QStringLiteral("licenseExpiryValue"));
    QVERIFY(email && email->isVisible());
    QVERIFY(license && license->isVisible());
    QVERIFY(expiry && expiry->isVisible());
    QCOMPARE(email->text(), QStringLiteral("test2@test.com"));
    QVERIFY(license->text().contains(QStringLiteral("Active")));
    QVERIFY(expiry->text().contains(QStringLiteral("12 Sep 2026")));
    QVERIFY(dashboard.width() <= 600);
    QVERIFY(dashboard.height() <= 400);
    for (const auto *label : dashboard.findChildren<QLabel *>()) {
        QVERIFY(!label->text().contains(QStringLiteral("ABCDEF-123456")));
        QVERIFY(!label->text().contains(QStringLiteral("019ffc3f")));
        QVERIFY(!label->text().contains(QStringLiteral("18:50")));
    }
    for (const QString &name : {QStringLiteral("deviceIdValue"), QStringLiteral("hwidValue"),
                                QStringLiteral("maxDevicesValue"), QStringLiteral("sessionExpiryValue")})
        QVERIFY(!dashboard.findChild<QLabel *>(name));
}
void UserDashboardTest::usesIconFreeChromeAndAccountAndGameActions()
{
    UserDashboard dashboard(literalProfile(), QStringLiteral("ABCDEF-123456"));
    QVERIFY(dashboard.windowFlags().testFlag(Qt::FramelessWindowHint));
    QVERIFY(dashboard.windowIcon().isNull());
    QVERIFY(dashboard.findChild<QWidget *>(QStringLiteral("windowTitleBar")));
    QVERIFY(dashboard.findChild<QToolButton *>(QStringLiteral("windowCloseButton")));
    QVERIFY(dashboard.findChild<QToolButton *>(QStringLiteral("windowMinimizeButton")));
    auto *signOut = dashboard.findChild<QPushButton *>(QStringLiteral("signOutButton"));
    QVERIFY(signOut);
    QVERIFY(dashboard.findChild<QPushButton *>(QStringLiteral("selectGameButton")));
    QVERIFY(!dashboard.findChild<QPushButton *>(QStringLiteral("selectDllButton")));
    const QStringList forbidden = {QStringLiteral("session token"), QStringLiteral("hmac"), QStringLiteral("license key")};
    for (const auto *label : dashboard.findChildren<QLabel *>())
        for (const auto &term : forbidden) QVERIFY(!label->text().contains(term, Qt::CaseInsensitive));
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

void UserDashboardTest::expiryClosesDashboardAndRestoresCredentials()
{
    LoginWindow login;
    auto *email = login.findChild<QLineEdit *>(QStringLiteral("emailLineEdit"));
    auto *password = login.findChild<QLineEdit *>(QStringLiteral("passwordLineEdit"));
    auto *subtitle = login.findChild<QLabel *>(QStringLiteral("subtitleLabel"));
    QVERIFY(email);
    QVERIFY(password);
    QVERIFY(subtitle);
    email->setText(QStringLiteral("person@example.com"));
    password->setText(QStringLiteral("not-retained"));
    login.show();
    AuthManager *manager = authenticatedManager(login);
    QVERIFY(manager);
    QCOMPARE(openDashboards().size(), 1);

    const QString reason = QStringLiteral("Session expired. Sign in again.");
    QVERIFY(QMetaObject::invokeMethod(manager, "reauthenticationRequired", Qt::DirectConnection,
                                      Q_ARG(QString, reason)));
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);

    QVERIFY(login.isVisible());
    QCOMPARE(openDashboards().size(), 0);
    QCOMPARE(email->text(), QStringLiteral("person@example.com"));
    QVERIFY(password->text().isEmpty());
    QCOMPARE(subtitle->text(), reason);
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

void UserDashboardTest::closingDashboardExitsRealApplicationLoop()
{
    QProcess helper;
    QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
    environment.insert(QStringLiteral("QT_QPA_PLATFORM"), QStringLiteral("offscreen"));
    helper.setProcessEnvironment(environment);
    helper.setProgram(QCoreApplication::applicationFilePath());
    helper.setArguments({QString::fromLatin1(DashboardCloseHelperArgument)});
    helper.start();

    QVERIFY2(helper.waitForStarted(2'000), qPrintable(helper.errorString()));
    if (!helper.waitForFinished(5'000)) {
        helper.kill();
        helper.waitForFinished(2'000);
        QFAIL("Authenticated dashboard close did not exit QApplication::exec() within 5 seconds");
    }

    const QByteArray output = helper.readAllStandardOutput() + helper.readAllStandardError();
    QCOMPARE(helper.exitStatus(), QProcess::NormalExit);
    QCOMPARE(helper.exitCode(), 0);
    QVERIFY2(output.contains("DASHBOARD_CLOSE_HELPER_OK dashboard_visible=1 show_count=1"),
             output.constData());
}

int main(int argc, char **argv)
{
    for (int index = 1; index < argc; ++index) {
        if (QByteArrayView(argv[index]) == DashboardCloseHelperArgument) {
            return runDashboardCloseHelper(argc, argv);
        }
    }

    QApplication application(argc, argv);
    application.setAttribute(Qt::AA_Use96Dpi, true);
    UserDashboardTest test;
    return QTest::qExec(&test, argc, argv);
}

#include "UserDashboardTest.moc"

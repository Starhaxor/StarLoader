#include "auth/AuthManager.h"
#include "ui/HwidDialog.h"
#include "ui/LoginWindow.h"
#include "ui/UserDashboard.h"

#include <QApplication>
#include <QElapsedTimer>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTest>

#include <cstdlib>
#include <functional>

namespace {

class DiagnosticCollector final : public IHardwareCollector
{
public:
    bool collect(HardwareIdentity *identity, QString *) override
    {
        identity->finalFingerprint = QStringLiteral("native-live-diagnostic");
        return true;
    }
};

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

void requireIconFreeChrome(QWidget &window)
{
    QVERIFY(window.windowFlags().testFlag(Qt::FramelessWindowHint));
    QVERIFY(window.windowIcon().isNull());
    auto *titleBar = window.findChild<QWidget *>(QStringLiteral("windowTitleBar"));
    QVERIFY(titleBar);
    QVERIFY(!titleBar->findChild<QLabel *>(QStringLiteral("windowIcon")));
}

bool waitUntil(const std::function<bool()> &condition, int timeoutMs)
{
    QElapsedTimer timer;
    timer.start();
    while (!condition() && timer.elapsed() < timeoutMs) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
        QTest::qWait(10);
    }
    return condition();
}

} // namespace

class NativeLiveFlowTest final : public QObject
{
    Q_OBJECT

private slots:
    void productionClientCompletesAuthenticatedDashboardAndSignOutFlow();
};

void NativeLiveFlowTest::productionClientCompletesAuthenticatedDashboardAndSignOutFlow()
{
    const QString email = qEnvironmentVariable("STARLOADER_NATIVE_LIVE_EMAIL");
    const QString password = qEnvironmentVariable("STARLOADER_NATIVE_LIVE_PASSWORD");
    const QString expectedMaxDevices = qEnvironmentVariable("STARLOADER_NATIVE_LIVE_MAX_DEVICES");
    if (email.isEmpty() || password.isEmpty() || expectedMaxDevices.isEmpty()) {
        QSKIP("native production live-flow environment is not configured");
    }

    DiagnosticCollector diagnosticCollector;
    HwidDialog diagnostic(diagnosticCollector);
    diagnostic.show();
    QCoreApplication::processEvents();
    requireIconFreeChrome(diagnostic);
    diagnostic.close();

    LoginWindow login;
    login.show();
    QCoreApplication::processEvents();
    requireIconFreeChrome(login);

    auto *emailInput = login.findChild<QLineEdit *>(QStringLiteral("emailLineEdit"));
    auto *passwordInput = login.findChild<QLineEdit *>(QStringLiteral("passwordLineEdit"));
    auto *loginButton = login.findChild<QPushButton *>(QStringLiteral("loginButton"));
    QVERIFY(emailInput);
    QVERIFY(passwordInput);
    QVERIFY(loginButton);
    emailInput->setText(email);
    passwordInput->setText(password);
    QTest::mouseClick(loginButton, Qt::LeftButton);

    if (!waitUntil([] { return openDashboards().size() == 1; }, 30000)) {
        const auto *status = login.findChild<QLabel *>(QStringLiteral("statusLabel"));
        qCritical().noquote() << "NATIVE_LIVE_FLOW_FAILED stage=authentication status="
                              << (status == nullptr ? QStringLiteral("missing") : status->text());
        std::_Exit(80);
    }
    UserDashboard *dashboard = openDashboards().constFirst();
    QVERIFY(dashboard->isVisible());
    QVERIFY(!login.isVisible());
    requireIconFreeChrome(*dashboard);

    const auto value = [dashboard](const char *objectName) {
        auto *label = dashboard->findChild<QLabel *>(QString::fromLatin1(objectName));
        return label == nullptr ? QString() : label->text();
    };
    QCOMPARE(value("emailValue"), email);
    QCOMPARE(value("accountStatusValue"), QStringLiteral("Active"));
    QCOMPARE(value("productValue"), QStringLiteral("StarLoader"));
    QCOMPARE(value("licenseStatusValue"), QStringLiteral("Active"));
    QCOMPARE(value("maxDevicesValue"), expectedMaxDevices);
    QCOMPARE(value("deviceStatusValue"), QStringLiteral("Active"));
    QVERIFY(!value("licenseExpiryValue").isEmpty() && value("licenseExpiryValue") != QStringLiteral("\u2014"));
    QVERIFY(value("deviceIdValue").contains(QStringLiteral("\u2026")));
    QVERIFY(!value("hwidValue").isEmpty() && value("hwidValue") != QStringLiteral("\u2014"));
    QVERIFY(!value("sessionExpiryValue").isEmpty() && value("sessionExpiryValue") != QStringLiteral("\u2014"));

    auto *signOutButton = dashboard->findChild<QPushButton *>(QStringLiteral("signOutButton"));
    QVERIFY(signOutButton);
    QTest::mouseClick(signOutButton, Qt::LeftButton);

    if (!waitUntil([] { return openDashboards().isEmpty(); }, 5000)) {
        qCritical() << "NATIVE_LIVE_FLOW_FAILED stage=sign_out";
        std::_Exit(81);
    }
    QVERIFY(login.isVisible());
    QVERIFY(emailInput->text().isEmpty());
    QVERIFY(passwordInput->text().isEmpty());
    qInfo() << "NATIVE_LIVE_FLOW_OK dashboard_visible=1 profile_safe=1 signed_out=1 icon_free=3";
    std::_Exit(0);
}

QTEST_MAIN(NativeLiveFlowTest)

#include "NativeLiveFlowTest.moc"

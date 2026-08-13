#include "LoginWindow.h"
#include "ui_LoginWindow.h"
#include "HwidDialog.h"
#include "UserDashboard.h"
#include "WindowTitleBar.h"
#include "api/ApiClient.h"
#include "auth/AuthManager.h"
#include "ClientSecurityConfig.h"

#include <QPushButton>
#include <QLabel>
#include <QStyle>
#include <QUrl>

LoginWindow::LoginWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::LoginWindow)
{
    ui->setupUi(this);
    ui->loginButton->setProperty("suggested", true);
    ui->loginCard->setAutoFillBackground(true);
    ui->pageLayout->insertWidget(0, new WindowTitleBar(this, windowTitle(), true, ui->centralwidget));
    setFixedSize(size());

    apiClient_ = new ApiClient(QUrl(qEnvironmentVariable("STARLOADER_API_URL", "https://api.starloader.example")), ApiClient::RequestTimeoutMs, this);
    hardwareCollector_ = std::make_unique<SystemHardwareCollector>();
    deviceSigner_ = std::make_unique<TpmDeviceSigner>();
    const SessionTokenVerifier verifier = SessionTokenVerifier::fromBase64(
        QString::fromLatin1(STARLOADER_ED25519_PUBLIC_KEY_BASE64),
        QStringLiteral("starloader"), QStringLiteral("starloader-client"), QStringLiteral("StarLoader"));
    authManager_ = new AuthManager(*apiClient_, *hardwareCollector_, *deviceSigner_, verifier, this);

    connect(ui->loginButton, &QPushButton::clicked, this, &LoginWindow::startLogin);
    connect(ui->hwidLink, &QLabel::linkActivated, this, &LoginWindow::openHwidDialog);
    connect(authManager_, &AuthManager::stateChanged, this, &LoginWindow::applyState);
    connect(authManager_, &AuthManager::statusChanged, ui->statusLabel, &QLabel::setText);
    connect(authManager_, &AuthManager::failed, this, &LoginWindow::showFailure);
    connect(authManager_, &AuthManager::authenticated, this, &LoginWindow::showDashboard);
}

LoginWindow::~LoginWindow()
{
    if (dashboard_ != nullptr) { dashboard_->hide(); delete dashboard_.data(); }
    if (authManager_ != nullptr) { authManager_->cancelAndWait(); delete authManager_; authManager_ = nullptr; }
    delete ui;
}

void LoginWindow::openHwidDialog()
{
    if (!ui->hwidLink->isEnabled()) return;

    HwidDialog dialog(*hardwareCollector_, this);
    dialog.exec();
}

void LoginWindow::startLogin()
{
    ui->statusLabel->setProperty("state", QVariant());
    ui->statusLabel->style()->unpolish(ui->statusLabel);
    ui->statusLabel->style()->polish(ui->statusLabel);
    authManager_->login(ui->emailLineEdit->text(), ui->passwordLineEdit->text());
}

void LoginWindow::showDashboard()
{
    if (dashboard_ == nullptr) {
        dashboard_ = new UserDashboard(authManager_->userProfile(),
                                       authManager_->deviceDisplayId());
        connect(dashboard_, &UserDashboard::signOutRequested,
                this, &LoginWindow::signOut);
    }

    hide();
    dashboard_->show();
}

void LoginWindow::signOut()
{
    UserDashboard *dashboard = dashboard_.data();
    if (dashboard != nullptr) {
        dashboard->hide();
    }

    authManager_->signOut();
    ui->emailLineEdit->clear();
    ui->passwordLineEdit->clear();
    show();

    if (dashboard != nullptr) {
        dashboard->deleteLater();
    }
}

void LoginWindow::applyState(AuthState state)
{
    const bool busy = state == AuthState::CollectingDevice || state == AuthState::Authenticating || state == AuthState::WaitingForDeviceChallenge || state == AuthState::VerifyingDevice;
    ui->emailLineEdit->setEnabled(!busy);
    ui->passwordLineEdit->setEnabled(!busy);
    ui->loginButton->setEnabled(!busy);
    ui->hwidLink->setEnabled(!busy);
}

QString LoginWindow::safeMessage(const ApiError &error)
{
    if (error.code == QStringLiteral("INVALID_CREDENTIALS")) return QStringLiteral("Email address or password is incorrect.");
    if (error.code == QStringLiteral("LICENSE_EXPIRED")) return QStringLiteral("Your license has expired.");
    if (error.code == QStringLiteral("LICENSE_REVOKED")) return QStringLiteral("Your license has been revoked.");
    if (error.code == QStringLiteral("DEVICE_LIMIT_REACHED")) return QStringLiteral("The device limit has been reached.");
    if (error.code == QStringLiteral("DEVICE_REVOKED")) return QStringLiteral("This device has been revoked.");
    if (error.code == QStringLiteral("RATE_LIMITED")) return QStringLiteral("Too many attempts. Please wait and try again.");
    if (error.code == QStringLiteral("TPM_UNAVAILABLE")) return QStringLiteral("Device security hardware is unavailable.");
    return QStringLiteral("Sign-in could not be completed. Please try again.");
}

void LoginWindow::showFailure(const ApiError &error)
{
    ui->statusLabel->setProperty("state", "error");
    ui->statusLabel->style()->unpolish(ui->statusLabel);
    ui->statusLabel->style()->polish(ui->statusLabel);
    ui->statusLabel->setText(safeMessage(error));
}

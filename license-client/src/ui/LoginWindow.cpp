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
#include <QEvent>
#include <QMessageBox>
#include <QPalette>
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

    // The API URL is baked in at build time exclusively from
    // STARLOADER_API_URL (configured via CMakePresets.json). There is no
    // runtime override: the client must never talk to an unexpected endpoint.
    apiClient_ = new ApiClient(QUrl(QString::fromUtf8(STARLOADER_API_URL)), ApiClient::RequestTimeoutMs, this);
    hardwareCollector_ = std::make_unique<SystemHardwareCollector>();
    deviceSigner_ = std::make_unique<TpmDeviceSigner>();
    const SessionTokenVerifier verifier = SessionTokenVerifier::fromConfiguredKeyRing(
        QString::fromLatin1(STARLOADER_ED25519_KEY_RING),
        QStringLiteral("keystar"), QStringLiteral("keystar-clients"), QString::fromLatin1(STARLOADER_APPLICATION_ID),
        QString::fromLatin1(STARLOADER_PRODUCT_ID), QStringLiteral("StarLoader"));
    authManager_ = new AuthManager(*apiClient_, *hardwareCollector_, *deviceSigner_, verifier, this);

    connect(ui->loginButton, &QPushButton::clicked, this, &LoginWindow::startLogin);
    connect(ui->hwidLink, &QLabel::linkActivated, this, &LoginWindow::openHwidDialog);

    // Dim link by default; brighten + underline on hover (rich-text anchors
    // ignore stylesheets/palettes, so the color lives in the HTML itself).
    ui->hwidLink->setMouseTracking(true);
    ui->hwidLink->installEventFilter(this);

    QPalette inputPalette = ui->emailLineEdit->palette();
    inputPalette.setColor(QPalette::PlaceholderText, QColor(QStringLiteral("#71818A")));
    ui->emailLineEdit->setPalette(inputPalette);
    ui->passwordLineEdit->setPalette(inputPalette);
    connect(authManager_, &AuthManager::stateChanged, this, &LoginWindow::applyState);
    connect(authManager_, &AuthManager::failed, this, &LoginWindow::showFailure);
    connect(authManager_, &AuthManager::authenticated, this, &LoginWindow::showDashboard);
}

LoginWindow::~LoginWindow()
{
    if (dashboard_ != nullptr) { dashboard_->hide(); delete dashboard_.data(); }
    if (authManager_ != nullptr) { authManager_->cancelAndWait(); delete authManager_; authManager_ = nullptr; }
    delete ui;
}

bool LoginWindow::eventFilter(QObject *watched, QEvent *event)
{
    if (watched == ui->hwidLink) {
        if (event->type() == QEvent::Enter) {
            ui->hwidLink->setText(QStringLiteral("<a href=\"hwid\"><u><font color=\"#44C7D5\">View HWID</font></u></a>"));
            ui->hwidLink->setCursor(Qt::PointingHandCursor);
        } else if (event->type() == QEvent::Leave) {
            ui->hwidLink->setText(QStringLiteral("<a href=\"hwid\"><font color=\"#76949D\">View HWID</font></a>"));
            ui->hwidLink->unsetCursor();
        }
    }
    return QMainWindow::eventFilter(watched, event);
}

void LoginWindow::openHwidDialog()
{
    if (!ui->hwidLink->isEnabled()) return;

    HwidDialog dialog(*hardwareCollector_, this);
    dialog.exec();
}

void LoginWindow::startLogin()
{
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
    if (error.code == QStringLiteral("NETWORK_ERROR")) return error.message;
    if (error.code == QStringLiteral("INSECURE_TRANSPORT")) return QStringLiteral("A secure connection is required. The server must be reachable over HTTPS.");
    if (error.code == QStringLiteral("TIMEOUT")) return QStringLiteral("The request timed out. Please check your connection and try again.");
    return QStringLiteral("Sign-in could not be completed. Please try again.");
}

void LoginWindow::showFailure(const ApiError &error)
{
    showErrorDialog(error.code, safeMessage(error));
}

void LoginWindow::showErrorDialog(const QString &code, const QString &text)
{
    // Non-modal presentation: QMessageBox::exec() would block the event loop
    // and freeze offscreen UI tests, so the box is shown without modality and
    // tracked in errorDialog_ so callers/tests can locate and close it.
    if (errorDialog_ != nullptr) {
        errorDialog_->close();
        errorDialog_->deleteLater();
    }

    auto *box = new QMessageBox(QMessageBox::Critical, QStringLiteral("Sign-in failed"), QString(), QMessageBox::Ok, this);
    box->setText(QStringLiteral("<b>%1</b>").arg(text.toHtmlEscaped()));
    box->setInformativeText(QStringLiteral("Error code: %1").arg(code.toHtmlEscaped()));
    box->setAttribute(Qt::WA_DeleteOnClose);
    box->setWindowModality(Qt::NonModal);
    box->setWindowFlags(
    Qt::Dialog |
    Qt::CustomizeWindowHint |
    Qt::WindowTitleHint |
    Qt::WindowCloseButtonHint
);
    errorDialog_ = box;
    box->show();
}

#include "LoginWindow.h"
#include "ui_LoginWindow.h"
#include "HwidDialog.h"
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
    setFixedSize(size());

    apiClient_ = new ApiClient(QUrl(qEnvironmentVariable("STARLOADER_API_URL", "https://api.starloader.example")), ApiClient::RequestTimeoutMs, this);
    hardwareCollector_ = std::make_unique<SystemHardwareCollector>();
    deviceSigner_ = std::make_unique<TpmDeviceSigner>();
    const SessionTokenVerifier verifier = SessionTokenVerifier::fromBase64(
        QString::fromLatin1(STARLOADER_ED25519_PUBLIC_KEY_BASE64),
        QStringLiteral("starloader"), QStringLiteral("starloader-client"), QStringLiteral("StarLoader"));
    authManager_ = new AuthManager(*apiClient_, *hardwareCollector_, *deviceSigner_, verifier, this);

    connect(ui->loginButton, &QPushButton::clicked, this, &LoginWindow::startLogin);
    connect(authManager_, &AuthManager::stateChanged, this, &LoginWindow::applyState);
    connect(authManager_, &AuthManager::statusChanged, ui->statusLabel, &QLabel::setText);
    connect(authManager_, &AuthManager::failed, this, &LoginWindow::showFailure);
}

LoginWindow::~LoginWindow()
{
    if (authManager_ != nullptr) { authManager_->cancelAndWait(); delete authManager_; authManager_ = nullptr; }
    delete ui;
}

void LoginWindow::openHwidDialog()
{
    HwidDialog dialog(this);
    dialog.exec();
}

void LoginWindow::startLogin()
{
    ui->statusLabel->setProperty("state", QVariant());
    ui->statusLabel->style()->unpolish(ui->statusLabel);
    ui->statusLabel->style()->polish(ui->statusLabel);
    ui->requestIdLabel->clear();
    authManager_->login(ui->emailLineEdit->text(), ui->passwordLineEdit->text(), ui->licenseKeyLineEdit->text());
}

void LoginWindow::applyState(AuthState state)
{
    const bool busy = state == AuthState::CollectingDevice || state == AuthState::Authenticating || state == AuthState::WaitingForDeviceChallenge || state == AuthState::VerifyingDevice;
    ui->emailLineEdit->setEnabled(!busy);
    ui->passwordLineEdit->setEnabled(!busy);
    ui->licenseKeyLineEdit->setEnabled(!busy);
    ui->loginButton->setEnabled(!busy);
    if (!authManager_->deviceDisplayId().isEmpty()) ui->deviceIdLineEdit->setText(authManager_->deviceDisplayId());
}

QString LoginWindow::safeTurkishMessage(const ApiError &error)
{
    if (error.code == QStringLiteral("INVALID_CREDENTIALS")) return QStringLiteral("E-posta veya parola hatalı.");
    if (error.code == QStringLiteral("LICENSE_EXPIRED")) return QStringLiteral("Lisansın süresi dolmuş.");
    if (error.code == QStringLiteral("LICENSE_REVOKED")) return QStringLiteral("Lisans devre dışı bırakılmış.");
    if (error.code == QStringLiteral("DEVICE_LIMIT_REACHED")) return QStringLiteral("Cihaz sınırına ulaşıldı.");
    if (error.code == QStringLiteral("DEVICE_REVOKED")) return QStringLiteral("Bu cihaz devre dışı bırakılmış.");
    if (error.code == QStringLiteral("RATE_LIMITED")) return QStringLiteral("Çok fazla deneme yapıldı. Lütfen bekleyin.");
    if (error.code == QStringLiteral("TPM_UNAVAILABLE")) return QStringLiteral("TPM güvenlik donanımı kullanılamıyor.");
    return QStringLiteral("Giriş tamamlanamadı. Lütfen tekrar deneyin.");
}

void LoginWindow::showFailure(const ApiError &error)
{
    ui->statusLabel->setProperty("state", "error");
    ui->statusLabel->style()->unpolish(ui->statusLabel);
    ui->statusLabel->style()->polish(ui->statusLabel);
    ui->statusLabel->setText(safeTurkishMessage(error));
    ui->requestIdLabel->setText(error.requestId.isEmpty() ? QString() : QStringLiteral("Destek kodu: %1").arg(error.requestId));
}

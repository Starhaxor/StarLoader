#include "UserDashboard.h"
#include "ui_UserDashboard.h"
#include "WindowTitleBar.h"
#include "launcher/LaunchPanel.h"
#include <QHideEvent>
#include <QPushButton>
#include <QStyle>
#include <QTimer>

UserDashboard::UserDashboard(const UserProfileResponse &profile, const QString &displayHwid, QWidget *parent)
    : QMainWindow(parent), ui(new Ui::UserDashboard)
{
    Q_UNUSED(displayHwid)
    ui->setupUi(this);
    ui->pageLayout->insertWidget(0, new WindowTitleBar(this, windowTitle(), true, ui->centralwidget));
    ui->emailValue->setTextFormat(Qt::PlainText);
    ui->emailValue->setText(ui->emailValue->fontMetrics().elidedText(profile.email, Qt::ElideRight, 370));
    ui->emailValue->setToolTip(profile.email);
    ui->emailValue->setAccessibleName(profile.email);
    QString status = profile.licenseStatus.trimmed();
    if (status.isEmpty()) status = tr("Unavailable");
    else status[0] = status.at(0).toUpper();
    ui->activeStatusIndicator->setText(status);
    const bool active = profile.accountStatus == QLatin1String("active")
        && profile.licenseStatus == QLatin1String("active")
        && profile.deviceStatus == QLatin1String("active");
    ui->activeStatusIndicator->setProperty("state", active ? "success" : "error");
    ui->activeStatusIndicator->style()->unpolish(ui->activeStatusIndicator);
    ui->activeStatusIndicator->style()->polish(ui->activeStatusIndicator);
    ui->licenseExpiryValue->setText(profile.licenseExpiresAt.isValid()
        ? tr("Expires %1").arg(profile.licenseExpiresAt.toUTC().toString(QStringLiteral("dd MMM yyyy"))) : QString());
    QDateTime expiry = profile.sessionExpiresAt;
    if (profile.licenseExpiresAt.isValid() && profile.licenseExpiresAt < expiry) expiry = profile.licenseExpiresAt;
    launchPanel_ = new LaunchPanel(active ? expiry : QDateTime(), this);
    ui->contentLayout->insertWidget(1, launchPanel_);
    connect(ui->signOutButton, &QPushButton::clicked, this, &UserDashboard::signOutRequested);
    connect(launchPanel_, &LaunchPanel::completed, this, [this] {
        QTimer::singleShot(1500, this, &QWidget::close);
    });
    setAttribute(Qt::WA_DeleteOnClose);
    setFixedSize(560, 330);
}

UserDashboard::~UserDashboard()
{
    launchPanel_->stop();
    delete ui;
}
void UserDashboard::hideEvent(QHideEvent *event)
{
    if (launchPanel_ && !event->spontaneous()) launchPanel_->stop();
    QMainWindow::hideEvent(event);
}

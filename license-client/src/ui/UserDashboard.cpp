#include "UserDashboard.h"
#include "ui_UserDashboard.h"

#include "WindowTitleBar.h"

#include <QDateTime>
#include <QPushButton>

namespace {

QString displayStatus(QString status)
{
    status = status.trimmed();
    if (status.isEmpty()) {
        return QStringLiteral("\u2014");
    }
    status[0] = status.at(0).toUpper();
    return status;
}

QString shortenedDeviceId(const QString &deviceId)
{
    constexpr qsizetype visibleCharacters = 8;
    if (deviceId.size() <= visibleCharacters * 2) {
        return deviceId;
    }
    return deviceId.left(visibleCharacters)
           + QStringLiteral("\u2026")
           + deviceId.right(visibleCharacters);
}

QString formattedDate(const QDateTime &dateTime)
{
    return dateTime.isValid()
               ? dateTime.toUTC().toString(QStringLiteral("dd MMM yyyy"))
               : QStringLiteral("\u2014");
}

QString formattedDateTime(const QDateTime &dateTime)
{
    return dateTime.isValid()
               ? dateTime.toUTC().toString(QStringLiteral("dd MMM yyyy, HH:mm 'UTC'"))
               : QStringLiteral("\u2014");
}

} // namespace

UserDashboard::UserDashboard(const UserProfileResponse &profile,
                             const QString &displayHwid,
                             QWidget *parent)
    : QMainWindow(parent), ui(new Ui::UserDashboard)
{
    ui->setupUi(this);
    ui->dashboardCard->setAutoFillBackground(true);
    ui->pageLayout->insertWidget(0, new WindowTitleBar(this, windowTitle(), true, ui->centralwidget));

    ui->emailValue->setText(profile.email);
    ui->accountStatusValue->setText(displayStatus(profile.accountStatus));
    ui->productValue->setText(profile.product);
    ui->licenseStatusValue->setText(displayStatus(profile.licenseStatus));
    ui->licenseExpiryValue->setText(formattedDate(profile.licenseExpiresAt));
    ui->maxDevicesValue->setText(QString::number(profile.maxDevices));
    ui->deviceStatusValue->setText(displayStatus(profile.deviceStatus));
    ui->deviceIdValue->setText(shortenedDeviceId(profile.deviceId));
    ui->hwidValue->setText(displayHwid);
    ui->sessionExpiryValue->setText(formattedDateTime(profile.sessionExpiresAt));

    connect(ui->signOutButton, &QPushButton::clicked,
            this, &UserDashboard::signOutRequested);

    setAttribute(Qt::WA_DeleteOnClose);
    setFixedSize(size());
}

UserDashboard::~UserDashboard()
{
    delete ui;
}

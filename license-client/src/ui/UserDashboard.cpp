#include "UserDashboard.h"
#include "ui_UserDashboard.h"

#include "WindowTitleBar.h"

#include <QApplication>
#include <QClipboard>
#include <QDateTime>
#include <QPainter>
#include <QPushButton>
#include <QStyle>
#include <QTimer>
#include <QToolButton>

namespace {

const QColor kAccentColor(QStringLiteral("#44C7D5"));

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

QString normalizedStatus(const QString &status)
{
    return status.trimmed().toLower();
}

QString badgeState(const QString &licenseStatus)
{
    const QString status = normalizedStatus(licenseStatus);
    if (status == QLatin1String("expired") || status == QLatin1String("revoked")
        || status == QLatin1String("disabled") || status == QLatin1String("banned")) {
        return QStringLiteral("error");
    }
    if (status == QLatin1String("warning") || status == QLatin1String("trial")
        || status == QLatin1String("pending")) {
        return QStringLiteral("warning");
    }
    return QStringLiteral("success");
}

QString statusColor(const QString &value)
{
    const QString status = normalizedStatus(value);
    if (status == QLatin1String("active") || status == QLatin1String("connected")
        || status == QLatin1String("enabled")) {
        return QStringLiteral("#43D19E");
    }
    if (status == QLatin1String("expired") || status == QLatin1String("revoked")
        || status == QLatin1String("disabled") || status == QLatin1String("banned")) {
        return QStringLiteral("#FF647C");
    }
    if (status == QLatin1String("warning") || status == QLatin1String("trial")
        || status == QLatin1String("pending")) {
        return QStringLiteral("#F4B860");
    }
    return QString();
}

QIcon copyIcon(const QColor &color)
{
    QPixmap pixmap(16, 16);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.setPen(QPen(color, 1.5));
    painter.setBrush(Qt::NoBrush);
    painter.drawRoundedRect(QRectF(2.5, 4.5, 8, 9), 1.2, 1.2);
    painter.drawRoundedRect(QRectF(5.5, 1.5, 8, 9), 1.2, 1.2);
    return QIcon(pixmap);
}

QIcon copiedIcon(const QColor &color)
{
    QPixmap pixmap(16, 16);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.setPen(QPen(color, 1.8, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
    painter.drawPolyline(QPolygonF{QPointF(2.5, 8.5), QPointF(6.5, 12), QPointF(13.5, 4)});
    return QIcon(pixmap);
}

} // namespace

UserDashboard::UserDashboard(const UserProfileResponse &profile,
                             const QString &displayHwid,
                             QWidget *parent)
    : QMainWindow(parent), ui(new Ui::UserDashboard)
{
    ui->setupUi(this);
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

    ui->activeStatusIndicator->setText(
        QStringLiteral("\u25CF %1 License").arg(displayStatus(profile.licenseStatus)));
    const QString state = badgeState(profile.licenseStatus);
    ui->activeStatusIndicator->setProperty("state", state);
    ui->activeStatusIndicator->style()->unpolish(ui->activeStatusIndicator);
    ui->activeStatusIndicator->style()->polish(ui->activeStatusIndicator);

    const auto applyStatusColor = [](QLabel *label, const QString &value) {
        const QString color = statusColor(value);
        if (!color.isEmpty()) {
            label->setStyleSheet(QStringLiteral(
                "color: %1; font-size: 11px; font-weight: 600; background: transparent;")
                                     .arg(color));
        }
    };
    applyStatusColor(ui->licenseStatusValue, profile.licenseStatus);
    applyStatusColor(ui->deviceStatusValue, profile.deviceStatus);

    fullDeviceId_ = profile.deviceId;
    fullHwid_ = displayHwid;

    ui->copyDeviceIdButton->setIcon(copyIcon(kAccentColor));
    ui->copyDeviceIdButton->setIconSize(QSize(14, 14));
    ui->copyHwidButton->setIcon(copyIcon(kAccentColor));
    ui->copyHwidButton->setIconSize(QSize(14, 14));

    connect(ui->copyDeviceIdButton, &QToolButton::clicked,
            this, &UserDashboard::copyDeviceId);
    connect(ui->copyHwidButton, &QToolButton::clicked,
            this, &UserDashboard::copyHwid);
    connect(ui->signOutButton, &QPushButton::clicked,
            this, &UserDashboard::signOutRequested);

    setAttribute(Qt::WA_DeleteOnClose);
    setFixedSize(size());
}

UserDashboard::~UserDashboard()
{
    delete ui;
}

void UserDashboard::copyDeviceId()
{
    copyToClipboard(ui->copyDeviceIdButton, fullDeviceId_, QStringLiteral("Copy device ID"));
}

void UserDashboard::copyHwid()
{
    copyToClipboard(ui->copyHwidButton, fullHwid_, QStringLiteral("Copy HWID"));
}

void UserDashboard::copyToClipboard(QToolButton *button,
                                    const QString &value,
                                    const QString &restoreToolTip)
{
    QApplication::clipboard()->setText(value);
    button->setIcon(copiedIcon(kAccentColor));
    button->setToolTip(QStringLiteral("Copied"));
    button->setEnabled(false);

    QTimer::singleShot(1300, this, [button, restoreToolTip] {
        button->setIcon(copyIcon(kAccentColor));
        button->setToolTip(restoreToolTip);
        button->setEnabled(true);
    });
}

#pragma once

#include "api/ApiClient.h"

#include <QMainWindow>

QT_BEGIN_NAMESPACE
class QToolButton;
namespace Ui { class UserDashboard; }
QT_END_NAMESPACE

class UserDashboard final : public QMainWindow
{
    Q_OBJECT

public:
    explicit UserDashboard(const UserProfileResponse &profile,
                           const QString &displayHwid,
                           QWidget *parent = nullptr);
    ~UserDashboard() override;

signals:
    void signOutRequested();

private:
    void copyDeviceId();
    void copyHwid();
    void copyToClipboard(QToolButton *button,
                         const QString &value,
                         const QString &restoreToolTip);

    Ui::UserDashboard *ui;
    QString fullDeviceId_;
    QString fullHwid_;
};

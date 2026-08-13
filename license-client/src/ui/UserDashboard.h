#pragma once

#include "api/ApiClient.h"

#include <QMainWindow>

QT_BEGIN_NAMESPACE
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
    Ui::UserDashboard *ui;
};

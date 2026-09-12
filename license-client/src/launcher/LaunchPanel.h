#pragma once
#include <QDateTime>
#include <QWidget>
class LaunchController;
class LaunchPanel final : public QWidget {
    Q_OBJECT
public:
    explicit LaunchPanel(QDateTime expiry, QWidget *parent = nullptr);
    void stop();
signals:
    void completed();
private:
    LaunchController *controller_;
};

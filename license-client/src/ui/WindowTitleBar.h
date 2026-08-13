#pragma once

#include <QPoint>
#include <QString>
#include <QWidget>

class QMouseEvent;

class WindowTitleBar final : public QWidget
{
    Q_OBJECT

public:
    explicit WindowTitleBar(QWidget *window, QString title, bool canMinimize,
                            QWidget *parent = nullptr);

protected:
    void mousePressEvent(QMouseEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;
    void mouseReleaseEvent(QMouseEvent *event) override;

private:
    QWidget *window_;
    QPoint dragOffset_;
    bool dragging_ = false;
};

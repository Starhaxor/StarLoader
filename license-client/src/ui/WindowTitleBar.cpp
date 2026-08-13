#include "WindowTitleBar.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QMouseEvent>
#include <QToolButton>

#include <utility>

WindowTitleBar::WindowTitleBar(QWidget *window, QString title, bool canMinimize, QWidget *parent)
    : QWidget(parent), window_(window)
{
    setObjectName(QStringLiteral("windowTitleBar"));
    setFixedHeight(32);
    window_->setWindowFlag(Qt::FramelessWindowHint, true);

    auto *layout = new QHBoxLayout(this);
    layout->setContentsMargins(10, 0, 4, 0);
    layout->setSpacing(2);

    auto *titleLabel = new QLabel(std::move(title), this);
    titleLabel->setObjectName(QStringLiteral("windowTitleText"));
    titleLabel->setAttribute(Qt::WA_TransparentForMouseEvents);
    layout->addWidget(titleLabel, 1);

    if (canMinimize) {
        auto *minimizeButton = new QToolButton(this);
        minimizeButton->setObjectName(QStringLiteral("windowMinimizeButton"));
        minimizeButton->setText(QStringLiteral("\u2212"));
        minimizeButton->setAccessibleName(QStringLiteral("Minimize window"));
        minimizeButton->setToolTip(QStringLiteral("Minimize"));
        minimizeButton->setFocusPolicy(Qt::TabFocus);
        connect(minimizeButton, &QToolButton::clicked, window_, &QWidget::showMinimized);
        layout->addWidget(minimizeButton);
    }

    auto *closeButton = new QToolButton(this);
    closeButton->setObjectName(QStringLiteral("windowCloseButton"));
    closeButton->setText(QStringLiteral("\u00d7"));
    closeButton->setAccessibleName(QStringLiteral("Close window"));
    closeButton->setToolTip(QStringLiteral("Close"));
    closeButton->setFocusPolicy(Qt::TabFocus);
    connect(closeButton, &QToolButton::clicked, window_, &QWidget::close);
    layout->addWidget(closeButton);
}

void WindowTitleBar::mousePressEvent(QMouseEvent *event)
{
    if (event->button() == Qt::LeftButton) {
        dragging_ = true;
        dragOffset_ = event->globalPosition().toPoint() - window_->frameGeometry().topLeft();
        event->accept();
        return;
    }
    QWidget::mousePressEvent(event);
}

void WindowTitleBar::mouseMoveEvent(QMouseEvent *event)
{
    if (dragging_ && event->buttons().testFlag(Qt::LeftButton)) {
        window_->move(event->globalPosition().toPoint() - dragOffset_);
        event->accept();
        return;
    }
    QWidget::mouseMoveEvent(event);
}

void WindowTitleBar::mouseReleaseEvent(QMouseEvent *event)
{
    if (event->button() == Qt::LeftButton) {
        dragging_ = false;
        event->accept();
        return;
    }
    QWidget::mouseReleaseEvent(event);
}

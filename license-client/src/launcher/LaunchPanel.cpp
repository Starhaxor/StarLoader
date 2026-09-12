#include "LaunchPanel.h"
#include "NativeLaunch.h"
#include <QCoreApplication>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QVBoxLayout>

LaunchPanel::LaunchPanel(QDateTime expiry, QWidget *parent) : QWidget(parent)
{
    setObjectName(QStringLiteral("launchPanel"));
    setAttribute(Qt::WA_StyledBackground);
    setMinimumHeight(136);
    setStyleSheet(QStringLiteral(
        "QWidget#launchPanel { background:#111A23; border:1px solid #24333F; border-radius:12px; }"
        "QLabel { border:none; background:transparent; font-family:'Segoe UI'; }"
        "QLabel#gameNameLabel { color:#E8F0F3; font-size:17px; font-weight:600; }"
        "QLabel#launchStatusLabel { color:#8296A5; font-size:11px; }"
        "QLineEdit { color:#8296A5; background:transparent; padding:0; border:none; font-size:11px; font-family:'Segoe UI'; }"
        "QPushButton { font-family:'Segoe UI'; font-size:11px; font-weight:600; border:none; }"
        "QPushButton#selectGameButton { color:#05181D; background:#36BDCC; border-radius:7px; padding:10px 14px; }"
        "QPushButton#selectGameButton:hover { background:#65D3DF; }"
        "QPushButton#selectGameButton:disabled { background:#223340; color:#7A91A2; }"
        "QPushButton#stopWaitingButton { color:#B1C1CA; background:transparent; padding:5px 0 5px 10px; }"
        "QPushButton#stopWaitingButton:hover { color:#E8F0F3; }"
        "QProgressBar { border:none; background:#23303C; height:2px; }"
        "QProgressBar::chunk { background:#36BDCC; }"));
    auto *layout = new QVBoxLayout(this);
    layout->setContentsMargins(18,16,18,14); layout->setSpacing(12);
    auto *targetRow = new QHBoxLayout; targetRow->setSpacing(16);
    auto *targetText = new QVBoxLayout; targetText->setSpacing(5);
    auto *title = new QLabel(QStringLiteral("AssaultCube"), this);
    title->setObjectName(QStringLiteral("gameNameLabel")); targetText->addWidget(title);
    auto *path = new QLineEdit(this); path->setObjectName(QStringLiteral("gameExecutablePath"));
    path->setReadOnly(true); path->setFrame(false); path->setMinimumWidth(0);
    path->setPlaceholderText(tr("Choose your game executable"));
    targetText->addWidget(path);
    targetRow->addLayout(targetText, 1);
    auto *select = new QPushButton(tr("Choose EXE"), this);
    select->setObjectName(QStringLiteral("selectGameButton")); select->setCursor(Qt::PointingHandCursor);
    targetRow->addWidget(select);
    layout->addLayout(targetRow);
    auto *progress = new QProgressBar(this); progress->setTextVisible(false);
    progress->setFixedHeight(2); progress->setRange(0,1); progress->setValue(0);
    layout->addWidget(progress);
    auto *statusRow = new QHBoxLayout;
    auto *status = new QLabel(this); status->setObjectName(QStringLiteral("launchStatusLabel"));
    status->setTextFormat(Qt::PlainText); status->setWordWrap(true); status->setMinimumHeight(28);
    statusRow->addWidget(status, 1);
    auto *cancel = new QPushButton(tr("Cancel"), this);
    cancel->setObjectName(QStringLiteral("stopWaitingButton")); cancel->setCursor(Qt::PointingHandCursor);
    statusRow->addWidget(cancel);
    layout->addLayout(statusRow);
    controller_ = new LaunchController(QCoreApplication::applicationDirPath(), expiry, nativeLaunchServices(), this);
    const auto refresh = [this, select, cancel, status, progress] {
        const auto state = controller_->state();
        const bool busy = state == LaunchController::State::Waiting || state == LaunchController::State::Loading;
        select->setEnabled(state != LaunchController::State::Loading && state != LaunchController::State::Succeeded);
        cancel->setVisible(state == LaunchController::State::Waiting);
        progress->setRange(0, busy ? 0 : 1);
        if (!busy) progress->setValue(state == LaunchController::State::Succeeded ? 1 : 0);
        status->setText(controller_->message());
        status->setStyleSheet(state == LaunchController::State::Failed ? QStringLiteral("color:#F18C96;") : QStringLiteral("color:#8296A5;"));
    };
    connect(controller_, &LaunchController::changed, this, refresh);
    connect(controller_, &LaunchController::completed, this, &LaunchPanel::completed);
    connect(cancel, &QPushButton::clicked, controller_, &LaunchController::cancel);
    connect(select, &QPushButton::clicked, this, [this, path, select] {
        controller_->cancel();
        const QString file = QFileDialog::getOpenFileName(this, tr("Select the game executable"), path->text(), tr("Windows executables (*.exe)"));
        if (file.isEmpty()) return;
        const QString absolute = QFileInfo(file).canonicalFilePath();
        path->setText(absolute); path->setToolTip(absolute); path->setCursorPosition(0);
        select->setText(tr("Change"));
        controller_->start(absolute);
    });
    refresh();
}
void LaunchPanel::stop() { controller_->cancel(); }

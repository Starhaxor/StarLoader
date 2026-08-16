#include "HwidDialog.h"
#include "ui_HwidDialog.h"
#include "WindowTitleBar.h"

#include "auth/AuthManager.h"

#include <QApplication>
#include <QClipboard>
#include <QPainter>
#include <QTimer>
#include <QToolButton>
#include <QtConcurrentRun>

namespace {

const QColor kIconColor(QStringLiteral("#44C7D5"));

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

HwidDialog::HwidDialog(IHardwareCollector &hardwareCollector, QWidget *parent)
    : QDialog(parent), hardwareCollector_(hardwareCollector), ui(new Ui::HwidDialog)
{
    ui->setupUi(this);
    ui->dialogLayout->insertWidget(0, new WindowTitleBar(this, windowTitle(), false, this));
    setFixedSize(width(), ui->dialogLayout->sizeHint().height());
    ui->copyButton->setIcon(copyIcon(kIconColor));
    ui->copyButton->setIconSize(QSize(16, 16));

    connect(ui->copyButton, &QToolButton::clicked,
            this, &HwidDialog::copyCode);
    connect(&collectionWatcher_, &QFutureWatcher<CollectionResult>::finished,
            this, &HwidDialog::collectionFinished);

    collectionWatcher_.setFuture(QtConcurrent::run([collector = &hardwareCollector_] {
        HardwareIdentity identity;
        QString error;
        const bool collected = collector->collect(&identity, &error);
        return CollectionResult{collected && !identity.finalFingerprint.isEmpty(),
                                collected ? identity.finalFingerprint : QString()};
    }));
}

HwidDialog::~HwidDialog()
{
    collectionWatcher_.cancel();
    collectionWatcher_.waitForFinished();
    delete ui;
}

void HwidDialog::collectionFinished()
{
    const CollectionResult result = collectionWatcher_.result();
    if (!result.success) {
        ui->descriptionLabel->setText(QStringLiteral("Device ID could not be calculated."));
        return;
    }

    ui->hwidLineEdit->setText(result.fingerprint);
    ui->descriptionLabel->setText(QStringLiteral("This code is unique to your device. Only share it with support."));
    ui->copyButton->setEnabled(true);
}

void HwidDialog::copyCode()
{
    QApplication::clipboard()->setText(ui->hwidLineEdit->text());
    ui->copyButton->setIcon(copiedIcon(kIconColor));
    ui->copyButton->setToolTip(QStringLiteral("Copied"));
    ui->copyButton->setEnabled(false);

    QTimer::singleShot(1300, this, [this] {
        ui->copyButton->setIcon(copyIcon(kIconColor));
        ui->copyButton->setToolTip(QStringLiteral("Copy HWID"));
        ui->copyButton->setEnabled(true);
    });
}

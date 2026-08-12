#include "HwidDialog.h"
#include "ui_HwidDialog.h"

#include "auth/AuthManager.h"

#include <QApplication>
#include <QClipboard>
#include <QPushButton>
#include <QTimer>
#include <QtConcurrentRun>

HwidDialog::HwidDialog(IHardwareCollector &hardwareCollector, QWidget *parent)
    : QDialog(parent), hardwareCollector_(hardwareCollector), ui(new Ui::HwidDialog)
{
    ui->setupUi(this);
    setFixedSize(size());
    ui->copyButton->setProperty("suggested", true);

    connect(ui->copyButton, &QPushButton::clicked,
            this, &HwidDialog::copyCode);
    connect(ui->closeButton, &QPushButton::clicked,
            this, &QDialog::accept);
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
    ui->copyButton->setText(QStringLiteral("Copied"));
    ui->copyButton->setEnabled(false);

    QTimer::singleShot(1300, this, [this] {
        ui->copyButton->setText(QStringLiteral("Copy code"));
        ui->copyButton->setEnabled(true);
    });
}

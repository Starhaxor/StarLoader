#include "HwidDialog.h"
#include "ui_HwidDialog.h"

#include <QApplication>
#include <QClipboard>
#include <QCryptographicHash>
#include <QPushButton>
#include <QSysInfo>
#include <QTimer>

HwidDialog::HwidDialog(QWidget *parent)
    : QDialog(parent), ui(new Ui::HwidDialog)
{
    ui->setupUi(this);
    setFixedSize(size());
    ui->copyButton->setProperty("suggested", true);
    ui->hwidLineEdit->setText(createHwidCode());

    connect(ui->copyButton, &QPushButton::clicked,
            this, &HwidDialog::copyCode);
    connect(ui->closeButton, &QPushButton::clicked,
            this, &QDialog::accept);
}

HwidDialog::~HwidDialog()
{
    delete ui;
}

QString HwidDialog::createHwidCode()
{
    QByteArray machineId = QSysInfo::machineUniqueId();
    if (machineId.isEmpty())
        machineId = QSysInfo::machineHostName().toUtf8();

    const QByteArray saltedId = QByteArrayLiteral("ModernLogin-HWID-v1|") + machineId;
    const QByteArray digest = QCryptographicHash::hash(
                                  saltedId, QCryptographicHash::Sha256).toHex().toUpper();

    QString code = QString::fromLatin1(digest.left(32));
    for (int index = 4; index < code.size(); index += 5)
        code.insert(index, QLatin1Char('-'));
    return code;
}

void HwidDialog::copyCode()
{
    QApplication::clipboard()->setText(ui->hwidLineEdit->text());
    ui->copyButton->setText(QStringLiteral("Copied ✓"));
    ui->copyButton->setEnabled(false);

    QTimer::singleShot(1300, this, [this] {
        ui->copyButton->setText(QStringLiteral("Copy code"));
        ui->copyButton->setEnabled(true);
    });
}

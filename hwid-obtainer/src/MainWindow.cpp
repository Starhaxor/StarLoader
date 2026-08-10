#include "MainWindow.h"

#include "DiagnosticPresentation.h"
#include "hardware/HardwareCollector.h"
#include "hardware/HardwareJson.h"
#include "security/EcdsaSignature.h"
#include "security/Fingerprint.h"
#include "security/TpmIdentity.h"
#include "ui_MainWindow.h"

#include <QApplication>
#include <QClipboard>
#include <QFileDialog>
#include <QJsonDocument>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QRandomGenerator>
#include <QSaveFile>
#include <QtConcurrentRun>

#include <array>
#include <algorithm>
#include <exception>

namespace {

QByteArray randomChallenge()
{
    QByteArray challenge(32, Qt::Uninitialized);
    QRandomGenerator *random = QRandomGenerator::system();
    for (char &byte : challenge)
        byte = static_cast<char>(random->generate() & 0xffU);
    return challenge;
}

} // namespace

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui_(new Ui::MainWindow)
{
    ui_->setupUi(this);

    connect(ui_->refreshButton, &QPushButton::clicked, this, &MainWindow::refreshHardware);
    connect(ui_->copyHwidButton, &QPushButton::clicked, this, &MainWindow::copyHwid);
    connect(ui_->exportJsonButton, &QPushButton::clicked, this, &MainWindow::exportJson);
    connect(ui_->tpmTestButton, &QPushButton::clicked, this, &MainWindow::runTpmTest);
    connect(&collectionWatcher_, &QFutureWatcher<HardwareIdentity>::finished,
            this, &MainWindow::collectionFinished);
    connect(&tpmTestWatcher_, &QFutureWatcher<TpmTestResult>::finished,
            this, &MainWindow::tpmTestFinished);

    setCollectionStatus(ui_->operationStatusLabel->text());
    setTpmTestStatus(ui_->tpmTestStatusLabel->text());
    ui_->copyHwidButton->setEnabled(false);
    ui_->exportJsonButton->setEnabled(false);
    refreshHardware();
}

MainWindow::~MainWindow()
{
    delete ui_;
}

void MainWindow::refreshHardware()
{
    if (collectionWatcher_.isRunning())
        return;

    hasCollectedIdentity_ = false;
    ui_->refreshButton->setEnabled(false);
    ui_->copyHwidButton->setEnabled(false);
    ui_->exportJsonButton->setEnabled(false);
    setCollectionStatus(QStringLiteral("Collecting hardware signals…"));

    collectionWatcher_.setFuture(QtConcurrent::run([] {
        HardwareIdentity identity = HardwareCollector().collect();
        identity.finalFingerprint = Fingerprint::generate(identity);
        return identity;
    }));
}

void MainWindow::collectionFinished()
{
    ui_->refreshButton->setEnabled(true);

    try {
        identity_ = collectionWatcher_.result();
    } catch (const std::exception &) {
        setCollectionStatus(
            QStringLiteral("Hardware collection failed; no values are available."));
        return;
    }

    showIdentity(identity_);
    hasCollectedIdentity_ = true;
    ui_->copyHwidButton->setEnabled(!identity_.finalFingerprint.trimmed().isEmpty());
    ui_->exportJsonButton->setEnabled(true);
}

void MainWindow::copyHwid()
{
    if (!hasCollectedIdentity_ || identity_.finalFingerprint.trimmed().isEmpty()) {
        setCollectionStatus(QStringLiteral("No fingerprint is available to copy."));
        return;
    }

    QApplication::clipboard()->setText(identity_.finalFingerprint);
    setCollectionStatus(QStringLiteral("Fingerprint copied to the clipboard."));
}

void MainWindow::exportJson()
{
    if (!hasCollectedIdentity_) {
        setCollectionStatus(QStringLiteral("Collect hardware signals before exporting JSON."));
        return;
    }

    const QString fileName = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("Export hardware identity"),
        QStringLiteral("hardware-identity.json"),
        QStringLiteral("JSON files (*.json)"));
    if (fileName.isEmpty())
        return;

    QSaveFile file(fileName);
    if (!file.open(QIODevice::WriteOnly)) {
        setCollectionStatus(QStringLiteral("Could not open the selected export file."));
        return;
    }

    const QByteArray json = QJsonDocument(HardwareJson::toJson(identity_)).toJson(QJsonDocument::Indented);
    if (file.write(json) != json.size() || !file.commit()) {
        setCollectionStatus(QStringLiteral("JSON export failed; the existing file was not replaced."));
        return;
    }

    setCollectionStatus(QStringLiteral("Hardware identity exported successfully."));
}

void MainWindow::runTpmTest()
{
    if (tpmTestWatcher_.isRunning())
        return;

    ui_->tpmTestButton->setEnabled(false);
    setTpmTestStatus(QStringLiteral("Running TPM verification checks…"));
    tpmTestWatcher_.setFuture(QtConcurrent::run(&MainWindow::performTpmTest));
}

void MainWindow::tpmTestFinished()
{
    ui_->tpmTestButton->setEnabled(true);

    try {
        const TpmTestResult result = tpmTestWatcher_.result();
        setTpmTestStatus(result.summary);
    } catch (const std::exception &) {
        setTpmTestStatus(QStringLiteral("TPM test failed unexpectedly."));
    }
}

MainWindow::TpmTestResult MainWindow::performTpmTest()
{
    if (!TpmIdentity::isAvailable())
        return {QStringLiteral("TPM test: unavailable."), false};

    QString error;
    if (!TpmIdentity::ensureKey(&error))
        return {QStringLiteral("TPM test: key setup failed (%1).").arg(error), false};

    const QByteArray challenge = randomChallenge();
    const QByteArray publicKey = TpmIdentity::publicKeyBlob();
    const QByteArray signature = TpmIdentity::signChallenge(challenge, &error);
    if (publicKey.isEmpty() || signature.isEmpty()) {
        return {QStringLiteral("TPM test: signing failed (%1).").arg(error), false};
    }

    const bool validSignature = EcdsaSignature::verifyCngP256(publicKey, challenge, signature);

    QByteArray changedChallenge = challenge;
    changedChallenge[0] ^= 1;
    const bool modifiedChallengeRejected =
        !EcdsaSignature::verifyCngP256(publicKey, changedChallenge, signature);

    QByteArray changedSignature = signature;
    changedSignature[0] ^= 1;
    const bool modifiedSignatureRejected =
        !EcdsaSignature::verifyCngP256(publicKey, challenge, changedSignature);

    const bool passed = validSignature && modifiedChallengeRejected && modifiedSignatureRejected;
    return {
        QStringLiteral("TPM test — valid signature: %1; modified challenge rejected: %2; modified signature rejected: %3.")
            .arg(validSignature ? QStringLiteral("PASS") : QStringLiteral("FAIL"))
            .arg(modifiedChallengeRejected ? QStringLiteral("PASS") : QStringLiteral("FAIL"))
            .arg(modifiedSignatureRejected ? QStringLiteral("PASS") : QStringLiteral("FAIL")),
        passed,
    };
}

void MainWindow::showSignal(QLineEdit *field, QLabel *status, const QString &value)
{
    const DiagnosticPresentation::Signal presentation = DiagnosticPresentation::signalFor(value);
    field->setText(presentation.value);
    status->setText(presentation.status);
}

void MainWindow::showIdentity(const HardwareIdentity &identity)
{
    showSignal(ui_->smbiosUuidEdit, ui_->smbiosUuidStatusLabel, identity.smbiosUuid);
    showSignal(ui_->motherboardEdit, ui_->motherboardStatusLabel, identity.motherboardSerial);
    showSignal(ui_->biosEdit, ui_->biosStatusLabel, identity.biosSerial);
    showSignal(ui_->diskEdit, ui_->diskStatusLabel, identity.systemDiskSerial);
    showSignal(ui_->machineGuidEdit, ui_->machineGuidStatusLabel, identity.machineGuid);
    showSignal(ui_->tpmEdit, ui_->tpmStatusLabel, identity.tpmPublicKeyHash);
    showSignal(ui_->fingerprintEdit, ui_->fingerprintStatusLabel, identity.finalFingerprint);

    const std::array hardwareValues{
        identity.smbiosUuid,
        identity.motherboardSerial,
        identity.biosSerial,
        identity.systemDiskSerial,
        identity.machineGuid,
        identity.tpmPublicKeyHash,
        identity.finalFingerprint,
    };
    const int availableSignals = static_cast<int>(std::count_if(
        hardwareValues.cbegin(), hardwareValues.cend(),
        [](const QString &value) { return !value.trimmed().isEmpty(); }));
    setCollectionStatus(
        QStringLiteral("Hardware collection complete: %1 of 7 signals available.").arg(availableSignals));
}

void MainWindow::setCollectionStatus(const QString &message)
{
    statusState_ = DiagnosticPresentation::withCollectionStatus(statusState_, message);
    ui_->operationStatusLabel->setText(statusState_.collection);
}

void MainWindow::setTpmTestStatus(const QString &message)
{
    statusState_ = DiagnosticPresentation::withTpmTestStatus(statusState_, message);
    ui_->tpmTestStatusLabel->setText(statusState_.tpmTest);
}

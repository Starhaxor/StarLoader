#pragma once

#include "DiagnosticPresentation.h"
#include "hardware/HardwareIdentity.h"

#include <QMainWindow>
#include <QFutureWatcher>

class QLabel;
class QLineEdit;

namespace Ui {
class MainWindow;
}

class MainWindow final : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

private slots:
    void refreshHardware();
    void collectionFinished();
    void copyHwid();
    void exportJson();
    void runTpmTest();
    void tpmTestFinished();

private:
    struct TpmTestResult
    {
        QString summary;
        bool passed = false;
    };

    static TpmTestResult performTpmTest();
    void showSignal(QLineEdit *field, QLabel *status, const QString &value);
    void showIdentity(const HardwareIdentity &identity);
    void setCollectionStatus(const QString &message);
    void setTpmTestStatus(const QString &message);

    Ui::MainWindow *ui_;
    HardwareIdentity identity_;
    DiagnosticPresentation::StatusState statusState_;
    QFutureWatcher<HardwareIdentity> collectionWatcher_;
    QFutureWatcher<TpmTestResult> tpmTestWatcher_;
    bool hasCollectedIdentity_ = false;
};

#ifndef HWIDDIALOG_H
#define HWIDDIALOG_H

#include <QDialog>
#include <QFutureWatcher>

#include <QString>

namespace Ui { class HwidDialog; }
class IHardwareCollector;

class HwidDialog final : public QDialog
{
    Q_OBJECT

public:
    explicit HwidDialog(IHardwareCollector &hardwareCollector, QWidget *parent = nullptr);
    ~HwidDialog() override;

private:
    struct CollectionResult
    {
        bool success = false;
        QString fingerprint;
    };

    IHardwareCollector &hardwareCollector_;
    QFutureWatcher<CollectionResult> collectionWatcher_;
    Ui::HwidDialog *ui;
    void collectionFinished();
    void copyCode();
};

#endif


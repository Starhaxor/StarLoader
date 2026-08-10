#ifndef HWIDDIALOG_H
#define HWIDDIALOG_H

#include <QDialog>

namespace Ui { class HwidDialog; }

class HwidDialog final : public QDialog
{
    Q_OBJECT

public:
    explicit HwidDialog(QWidget *parent = nullptr);
    ~HwidDialog() override;

private:
    Ui::HwidDialog *ui;
    static QString createHwidCode();
    void copyCode();
};

#endif


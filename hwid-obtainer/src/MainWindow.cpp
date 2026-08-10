#include "MainWindow.h"

#include <QLabel>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle(QStringLiteral("HWID Obtainer"));
    setCentralWidget(new QLabel(QStringLiteral("HWID obtaining will be available soon."), this));
}

#include "MainWindow.h"

#include <QApplication>

int main(int argc, char **argv)
{
    QApplication application(argc, argv);
    application.setApplicationName(QStringLiteral("HWID Obtainer"));

    MainWindow window;
    window.show();
    return application.exec();
}

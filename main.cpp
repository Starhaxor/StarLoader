#include "mainwindow.h"

#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication application(argc, argv);
    application.setApplicationName(QStringLiteral("Modern Login"));

    MainWindow window;
    window.show();
    return application.exec();
}


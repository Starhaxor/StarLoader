#include "ui/LoginWindow.h"

#include <QApplication>

int main(int argc, char **argv)
{
    QApplication application(argc, argv);
    application.setApplicationName(QStringLiteral("StarLoader"));

    LoginWindow window;
    window.show();
    return application.exec();
}

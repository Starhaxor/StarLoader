#include "MainWindow.h"
#include "theme/ThemeManager.h"

#include <QApplication>

int main(int argc, char **argv)
{
    QApplication application(argc, argv);
    application.setApplicationName(QStringLiteral("HWID Obtainer Tool"));

    ThemeManager::applyTheme();

    MainWindow window;
    window.show();
    return application.exec();
}

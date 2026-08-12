#include "ui/LoginWindow.h"
#include "theme/ThemeManager.h"

#include <QApplication>

int main(int argc, char **argv)
{
    QApplication application(argc, argv);
    application.setApplicationName(QStringLiteral("Modern Login"));

    ThemeManager::applyTheme();

    LoginWindow window;
    window.show();
    return application.exec();
}

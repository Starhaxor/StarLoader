#include "ThemeManager.h"

#include <QApplication>
#include <QFile>

void ThemeManager::applyTheme()
{
    if (QApplication *app = qobject_cast<QApplication *>(QCoreApplication::instance())) {
        app->setStyleSheet(themeStyleSheet());
    }
}

QString ThemeManager::themeStyleSheet()
{
    QFile file(QStringLiteral(":/theme/AdwaitaDark.qss"));
    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return QString::fromUtf8(file.readAll());
    }
    return QString();
}

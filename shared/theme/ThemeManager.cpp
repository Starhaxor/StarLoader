#include "ThemeManager.h"

#include <QApplication>
#include <QDebug>
#include <QFile>

static void initializeThemeResources()
{
    static const bool initialized = [] {
        Q_INIT_RESOURCE(theme);
        return true;
    }();
    Q_UNUSED(initialized);
}

void ThemeManager::applyTheme()
{
    if (QApplication *app = qobject_cast<QApplication *>(QCoreApplication::instance())) {
        const QString theme = themeStyleSheet();
        if (!theme.isEmpty()) {
            app->setStyleSheet(theme);
        }
    }
}

QString ThemeManager::themeStyleSheet()
{
    initializeThemeResources();
    QFile file(QStringLiteral(":/theme/AdwaitaDark.qss"));
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qWarning() << "StarLoader theme resource could not be opened";
        return {};
    }
    return QString::fromUtf8(file.readAll());
}

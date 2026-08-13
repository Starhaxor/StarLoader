#include "ThemeManager.h"

#include <QApplication>
#include <QDebug>
#include <QFile>
#include <QIcon>
#include <QTimer>
#include <QWidget>

#ifdef Q_OS_WIN
#include <windows.h>
#include <dwmapi.h>
#endif

namespace {

#ifdef Q_OS_WIN
QIcon transparentWindowIcon()
{
    QPixmap pixmap(16, 16);
    pixmap.fill(Qt::transparent);
    return QIcon(pixmap);
}
#endif

void applyNativeWindowTheme(QWidget *window)
{
#ifdef Q_OS_WIN
    const HWND nativeWindow = reinterpret_cast<HWND>(window->winId());
    const BOOL darkMode = TRUE;
    const COLORREF captionColor = RGB(32, 32, 32);
    const COLORREF textColor = RGB(238, 238, 236);
    const COLORREF borderColor = RGB(53, 53, 53);

    if (FAILED(DwmSetWindowAttribute(nativeWindow, static_cast<DWMWINDOWATTRIBUTE>(20),
                                     &darkMode, sizeof(darkMode)))) {
        DwmSetWindowAttribute(nativeWindow, static_cast<DWMWINDOWATTRIBUTE>(19),
                              &darkMode, sizeof(darkMode));
    }
    DwmSetWindowAttribute(nativeWindow, static_cast<DWMWINDOWATTRIBUTE>(35),
                          &captionColor, sizeof(captionColor));
    DwmSetWindowAttribute(nativeWindow, static_cast<DWMWINDOWATTRIBUTE>(36),
                          &textColor, sizeof(textColor));
    DwmSetWindowAttribute(nativeWindow, static_cast<DWMWINDOWATTRIBUTE>(34),
                          &borderColor, sizeof(borderColor));

    const LONG_PTR extendedStyle = GetWindowLongPtrW(nativeWindow, GWL_EXSTYLE);
    SetWindowLongPtrW(nativeWindow, GWL_EXSTYLE, extendedStyle | WS_EX_DLGMODALFRAME);
    SetWindowPos(nativeWindow, nullptr, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
#else
    Q_UNUSED(window);
#endif
}

} // namespace

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

void ThemeManager::applyWindowTheme(QWidget *window)
{
    if (window == nullptr)
        return;

#ifdef Q_OS_WIN
    window->setWindowIcon(transparentWindowIcon());
#else
    window->setWindowIcon(QIcon());
#endif
    applyNativeWindowTheme(window);

    QTimer::singleShot(0, window, [window] {
#ifdef Q_OS_WIN
        window->setWindowIcon(transparentWindowIcon());
#else
        window->setWindowIcon(QIcon());
#endif
        applyNativeWindowTheme(window);
    });
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

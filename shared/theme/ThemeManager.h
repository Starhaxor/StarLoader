#pragma once

#include <QString>

class QWidget;

class ThemeManager
{
public:
    ThemeManager() = delete;

    static void applyTheme();
    static void applyWindowTheme(QWidget *window);
    static QString themeStyleSheet();
};

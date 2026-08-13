#pragma once

#include <QString>

class ThemeManager
{
public:
    ThemeManager() = delete;

    static void applyTheme();
    static QString themeStyleSheet();
};

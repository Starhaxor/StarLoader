#include "theme/ThemeManager.h"

#include <QApplication>
#include <QtTest>

class ThemeManagerTest final : public QObject
{
    Q_OBJECT
private slots:
    void loadsEmbeddedAdwaitaTheme();
    void appliesThemeToApplication();
    void stylesCustomWindowChrome();
};

void ThemeManagerTest::loadsEmbeddedAdwaitaTheme()
{
    const QString theme = ThemeManager::themeStyleSheet();
    QVERIFY(!theme.isEmpty());
    QVERIFY(theme.contains(QStringLiteral("QFrame#loginCard")));
    QVERIFY(theme.contains(QStringLiteral("QLabel#hwidLink")));
}

void ThemeManagerTest::appliesThemeToApplication()
{
    qApp->setStyleSheet(QString());
    ThemeManager::applyTheme();
    QCOMPARE(qApp->styleSheet(), ThemeManager::themeStyleSheet());
}

void ThemeManagerTest::stylesCustomWindowChrome()
{
    const QString theme = ThemeManager::themeStyleSheet();
    QVERIFY(theme.contains(QStringLiteral("#windowTitleBar")));
    QVERIFY(theme.contains(QStringLiteral("QLabel#windowTitleText")));
    QVERIFY(theme.contains(QStringLiteral("QToolButton#windowCloseButton")));
    QVERIFY(theme.contains(QStringLiteral("QToolButton#windowMinimizeButton")));
    QVERIFY(theme.contains(QStringLiteral("QToolButton#windowCloseButton:hover")));
    QVERIFY(theme.contains(QStringLiteral("QToolButton#windowMinimizeButton:pressed")));
}

QTEST_MAIN(ThemeManagerTest)
#include "ThemeManagerTest.moc"

#include "theme/ThemeManager.h"

#include <QApplication>
#include <QIcon>
#include <QPixmap>
#include <QWidget>
#include <QtTest>

class ThemeManagerTest final : public QObject
{
    Q_OBJECT
private slots:
    void loadsEmbeddedAdwaitaTheme();
    void appliesThemeToApplication();
    void appliesIconlessWindowTheme();
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

void ThemeManagerTest::appliesIconlessWindowTheme()
{
    QPixmap iconPixmap(4, 4);
    iconPixmap.fill(Qt::red);

    QWidget window;
    window.setWindowIcon(QIcon(iconPixmap));
    QVERIFY(!window.windowIcon().isNull());

    ThemeManager::applyWindowTheme(&window);
    window.show();
    QCoreApplication::processEvents();

#ifdef Q_OS_WIN
    QVERIFY(!window.windowIcon().isNull());
#else
    QVERIFY(window.windowIcon().isNull());
#endif
}

QTEST_MAIN(ThemeManagerTest)
#include "ThemeManagerTest.moc"

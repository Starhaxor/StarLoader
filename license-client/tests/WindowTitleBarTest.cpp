#include "ui/WindowTitleBar.h"

#include <QLabel>
#include <QMouseEvent>
#include <QTest>
#include <QToolButton>
#include <QWidget>

class WindowTitleBarTest final : public QObject
{
    Q_OBJECT

private slots:
    void exposesIconFreeAccessibleControls();
    void closeButtonClosesHostWindow();
    void minimizeButtonMinimizesHostWindow();
    void closeOnlyModeOmitsMinimizeButton();
    void draggingMovesHostWindow();
};

void WindowTitleBarTest::exposesIconFreeAccessibleControls()
{
    QWidget host;
    WindowTitleBar titleBar(&host, QStringLiteral("StarLoader"), true, &host);

    QVERIFY(host.windowFlags().testFlag(Qt::FramelessWindowHint));

    const QList<QLabel *> labels = titleBar.findChildren<QLabel *>();
    QCOMPARE(labels.size(), 1);
    QCOMPARE(labels.constFirst()->objectName(), QStringLiteral("windowTitleText"));
    QCOMPARE(labels.constFirst()->text(), QStringLiteral("StarLoader"));
    QVERIFY(!titleBar.findChild<QLabel *>(QStringLiteral("windowIcon")));

    auto *minimizeButton = titleBar.findChild<QToolButton *>(QStringLiteral("windowMinimizeButton"));
    auto *closeButton = titleBar.findChild<QToolButton *>(QStringLiteral("windowCloseButton"));
    QVERIFY(minimizeButton);
    QVERIFY(closeButton);
    QCOMPARE(minimizeButton->accessibleName(), QStringLiteral("Minimize window"));
    QCOMPARE(closeButton->accessibleName(), QStringLiteral("Close window"));
    QVERIFY(minimizeButton->icon().isNull());
    QVERIFY(closeButton->icon().isNull());
}

void WindowTitleBarTest::closeButtonClosesHostWindow()
{
    QWidget host;
    WindowTitleBar titleBar(&host, QStringLiteral("StarLoader"), true, &host);
    host.show();
    QVERIFY(host.isVisible());

    auto *closeButton = titleBar.findChild<QToolButton *>(QStringLiteral("windowCloseButton"));
    QVERIFY(closeButton);
    QTest::mouseClick(closeButton, Qt::LeftButton);

    QTRY_VERIFY(!host.isVisible());
}

void WindowTitleBarTest::minimizeButtonMinimizesHostWindow()
{
    QWidget host;
    WindowTitleBar titleBar(&host, QStringLiteral("StarLoader"), true, &host);
    host.show();

    auto *minimizeButton = titleBar.findChild<QToolButton *>(QStringLiteral("windowMinimizeButton"));
    QVERIFY(minimizeButton);
    QTest::mouseClick(minimizeButton, Qt::LeftButton);

    QTRY_VERIFY(host.windowState().testFlag(Qt::WindowMinimized));
}

void WindowTitleBarTest::closeOnlyModeOmitsMinimizeButton()
{
    QWidget host;
    WindowTitleBar titleBar(&host, QStringLiteral("HWID Obtainer Tool"), false, &host);

    QVERIFY(!titleBar.findChild<QToolButton *>(QStringLiteral("windowMinimizeButton")));
    QVERIFY(titleBar.findChild<QToolButton *>(QStringLiteral("windowCloseButton")));
}

void WindowTitleBarTest::draggingMovesHostWindow()
{
    QWidget host;
    WindowTitleBar titleBar(&host, QStringLiteral("StarLoader"), true, &host);
    titleBar.resize(280, 32);
    host.move(100, 100);
    host.show();
    QCoreApplication::processEvents();

    const QPoint start = host.pos();
    const QPointF pressLocal(40, 16);
    const QPointF pressGlobal = titleBar.mapToGlobal(pressLocal.toPoint());
    QMouseEvent pressEvent(QEvent::MouseButtonPress, pressLocal, pressGlobal,
                           Qt::LeftButton, Qt::LeftButton, Qt::NoModifier);
    QApplication::sendEvent(&titleBar, &pressEvent);

    const QPoint delta(35, 24);
    const QPointF moveGlobal = pressGlobal + QPointF(delta);
    QMouseEvent moveEvent(QEvent::MouseMove, pressLocal + QPointF(delta), moveGlobal,
                          Qt::NoButton, Qt::LeftButton, Qt::NoModifier);
    QApplication::sendEvent(&titleBar, &moveEvent);

    QMouseEvent releaseEvent(QEvent::MouseButtonRelease, pressLocal + QPointF(delta), moveGlobal,
                             Qt::LeftButton, Qt::NoButton, Qt::NoModifier);
    QApplication::sendEvent(&titleBar, &releaseEvent);

    QCOMPARE(host.pos(), start + delta);
}

QTEST_MAIN(WindowTitleBarTest)

#include "WindowTitleBarTest.moc"

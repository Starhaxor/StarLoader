#include <QtTest>

class BuildSmokeTest final : public QObject {
    Q_OBJECT
private slots:
    void qtRuntimeIsAvailable() { QVERIFY(QCoreApplication::instance() != nullptr); }
};

QTEST_MAIN(BuildSmokeTest)
#include "BuildSmokeTest.moc"

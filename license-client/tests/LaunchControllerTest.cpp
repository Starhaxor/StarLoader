#include "launcher/LaunchController.h"
#include "launcher/NativeLaunch.h"
#include "launcher/NativeCallResult.h"
#include <QDir>
#include <QFile>
#include <QSemaphore>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QtEndian>
#include <QtTest>

class LaunchControllerTest final : public QObject {
    Q_OBJECT
private slots:
    void validationFailureNeverStartsLoading();
    void waitsThenUsesOnlyBundledPayloadOnce();
    void failedLoadDoesNotCompleteOrRetrySameProcess();
    void cancelSuppressesLateSuccess();
    void expiredSessionCannotStart();
    void expiryStopsWaiting();
    void cancelledWaitNeverLoadsNewProcess();
    void nativeProcessLookupMatchesFullPath();
    void validatesMissingMalformedAndMismatchedFiles();
    void abnormalNativeCompletionNeverCompletes();
    void autoLaunchesGameWhenNotRunning();
    void skipsLaunchWhenGameAlreadyRunning();
};

namespace {
QDateTime expiry() { return QDateTime::currentDateTimeUtc().addSecs(60); }
LaunchServices services(std::atomic_int &loads, std::atomic_int &pid, bool success = true) {
    return {[](const QString &, const QString &) { return QString(); },
            [&pid](const QString &) { return TargetProcess{quint32(pid.load()), {}}; },
            [&loads, success](quint32, const QString &, const QString &) { ++loads; return LaunchResult{success, QStringLiteral("Load failed")}; }};
}
void writePe(const QString &path, quint16 architecture, bool dll) {
    QByteArray bytes(128, 0); bytes.replace(0, 2, "MZ");
    qToLittleEndian<quint32>(64, bytes.data() + 60);
    bytes.replace(64, 4, QByteArray("PE\0\0", 4));
    qToLittleEndian<quint16>(architecture, bytes.data() + 68);
    qToLittleEndian<quint16>(dll ? 0x2002 : 0x0002, bytes.data() + 86);
    QFile file(path); QVERIFY(file.open(QIODevice::WriteOnly)); QCOMPARE(file.write(bytes), bytes.size());
}
}

void LaunchControllerTest::validationFailureNeverStartsLoading() {
    std::atomic_int loads = 0, pid = 12; auto native = services(loads, pid);
    native.validate = [](const QString &, const QString &) { return QStringLiteral("Missing DLL"); };
    LaunchController controller(QDir::tempPath(), expiry(), native);
    controller.start(QStringLiteral("game.exe"));
    QCOMPARE(controller.state(), LaunchController::State::Failed);
    QCOMPARE(loads.load(), 0);
}
void LaunchControllerTest::abnormalNativeCompletionNeverCompletes() {
    QVERIFY(nativeInitializationConfirmed(WAIT_OBJECT_0, TRUE, true));
    for (const DWORD status : {DWORD(0), DWORD(0xC0000005), DWORD(0xC0000409), DWORD(STILL_ACTIVE)}) {
        std::atomic_int loads = 0, pid = 12; auto native = services(loads, pid);
        native.load = [status](quint32, const QString &, const QString &) {
            return LaunchResult{nativeInitializationConfirmed(WAIT_OBJECT_0, status, true), QStringLiteral("Abnormal completion")};
        };
        LaunchController controller(QDir::tempPath(), expiry(), native);
        QSignalSpy done(&controller, &LaunchController::completed);
        controller.start(QStringLiteral("game.exe"));
        QTRY_COMPARE(controller.state(), LaunchController::State::Failed);
        QCOMPARE(done.count(), 0);
    }
    QVERIFY(!nativeInitializationConfirmed(WAIT_TIMEOUT, TRUE, true));
    QVERIFY(!nativeInitializationConfirmed(WAIT_OBJECT_0, TRUE, false));
}
void LaunchControllerTest::waitsThenUsesOnlyBundledPayloadOnce() {
    QTemporaryDir folder; QVERIFY(folder.isValid());
    std::atomic_int loads = 0, pid = 0; auto native = services(loads, pid);
    QString loadedPayload, loadedExe; quint32 loadedPid = 0;
    native.load = [&](quint32 p, const QString &exe, const QString &dll) {
        loadedPid = p; loadedExe = exe; loadedPayload = dll; ++loads; return LaunchResult{true, {}};
    };
    LaunchController controller(folder.path(), expiry(), native); QSignalSpy done(&controller, &LaunchController::completed);
    controller.start(QStringLiteral("selected-game.exe"));
    QCOMPARE(controller.state(), LaunchController::State::Waiting); QCOMPARE(loads.load(), 0);
    pid.store(1234);
    QTRY_COMPARE(done.count(), 1);
    QCOMPARE(loadedPayload, folder.path() + QStringLiteral("/AssaultCubeMultiHack.dll"));
    QCOMPARE(loadedExe, QStringLiteral("selected-game.exe")); QCOMPARE(loadedPid, quint32(1234));
    controller.start(QStringLiteral("other.exe")); QTest::qWait(600);
    QCOMPARE(loads.load(), 1); QCOMPARE(done.count(), 1);
}
void LaunchControllerTest::failedLoadDoesNotCompleteOrRetrySameProcess() {
    std::atomic_int loads = 0, pid = 12;
    LaunchController controller(QDir::tempPath(), expiry(), services(loads, pid, false));
    QSignalSpy done(&controller, &LaunchController::completed);
    controller.start(QStringLiteral("game.exe"));
    QTRY_COMPARE(controller.state(), LaunchController::State::Failed);
    QCOMPARE(done.count(), 0);
    controller.start(QStringLiteral("game.exe"));
    QCOMPARE(controller.state(), LaunchController::State::Failed); QCOMPARE(loads.load(), 1);
}
void LaunchControllerTest::cancelSuppressesLateSuccess() {
    std::atomic_int loads = 0, pid = 12; auto native = services(loads, pid);
    auto gate = std::make_shared<QSemaphore>();
    native.load = [gate](quint32, const QString &, const QString &) { gate->tryAcquire(1, 2000); return LaunchResult{true, {}}; };
    LaunchController controller(QDir::tempPath(), expiry(), native); QSignalSpy done(&controller, &LaunchController::completed);
    controller.start(QStringLiteral("game.exe")); QCOMPARE(controller.state(), LaunchController::State::Loading);
    controller.cancel(); gate->release(); QTest::qWait(100);
    QCOMPARE(controller.state(), LaunchController::State::Cancelled); QCOMPARE(done.count(), 0);
}
void LaunchControllerTest::expiredSessionCannotStart() {
    std::atomic_int loads = 0, pid = 12;
    LaunchController controller(QDir::tempPath(), QDateTime::currentDateTimeUtc().addSecs(-1), services(loads, pid));
    controller.start(QStringLiteral("game.exe")); QCOMPARE(controller.state(), LaunchController::State::Failed); QCOMPARE(loads.load(), 0);
}
void LaunchControllerTest::expiryStopsWaiting() {
    std::atomic_int loads = 0, pid = 0;
    LaunchController controller(QDir::tempPath(), QDateTime::currentDateTimeUtc().addMSecs(100), services(loads, pid));
    controller.start(QStringLiteral("game.exe"));
    QTRY_COMPARE(controller.state(), LaunchController::State::Cancelled);
    pid.store(12); QTest::qWait(600); QCOMPARE(loads.load(), 0);
}
void LaunchControllerTest::cancelledWaitNeverLoadsNewProcess() {
    std::atomic_int loads = 0, pid = 0;
    LaunchController controller(QDir::tempPath(), expiry(), services(loads, pid));
    controller.start(QStringLiteral("game.exe")); controller.cancel();
    pid.store(12); QTest::qWait(600); QCOMPARE(loads.load(), 0);
}
void LaunchControllerTest::nativeProcessLookupMatchesFullPath() {
    const auto native = nativeLaunchServices();
    const auto own = native.find(QCoreApplication::applicationFilePath());
    QVERIFY2(own.error.isEmpty(), qPrintable(own.error));
    QCOMPARE(own.pid, quint32(QCoreApplication::applicationPid()));
    QTemporaryDir other; QVERIFY(other.isValid());
    const QString copy = other.filePath(QFileInfo(QCoreApplication::applicationFilePath()).fileName());
    QVERIFY(QFile::copy(QCoreApplication::applicationFilePath(), copy));
    const auto different = native.find(copy);
    QVERIFY2(different.error.isEmpty(), qPrintable(different.error));
    QCOMPARE(different.pid, quint32(0));
}
void LaunchControllerTest::validatesMissingMalformedAndMismatchedFiles() {
    QTemporaryDir folder; QVERIFY(folder.isValid());
    const QString exe = folder.filePath(QStringLiteral("game.exe"));
    const QString dll = folder.filePath(QStringLiteral("AssaultCubeMultiHack.dll"));
    QVERIFY(!validateLaunchFiles(exe, dll).isEmpty());
    QFile bad(dll); QVERIFY(bad.open(QIODevice::WriteOnly)); bad.write("invalid"); bad.close();
    QVERIFY(!validateLaunchFiles(exe, dll).isEmpty());
    writePe(exe, 0x14c, false); writePe(dll, 0x8664, true);
    QVERIFY(!validateLaunchFiles(exe, dll).isEmpty());
    writePe(dll, 0x14c, true); QVERIFY(validateLaunchFiles(exe, dll).isEmpty());
    writePe(dll, 0x14c, false); QVERIFY(!validateLaunchFiles(exe, dll).isEmpty());
}
void LaunchControllerTest::autoLaunchesGameWhenNotRunning() {
    std::atomic_int loads = 0, launches = 0, unusedPid = 0;
    std::atomic<quint32> runningPid = 0;
    auto native = services(loads, unusedPid);
    native.find = [&](const QString &) { return TargetProcess{runningPid.load(), {}}; };
    QString launchedExe;
    native.launch = [&](const QString &exe) {
        ++launches;
        launchedExe = exe;
        runningPid.store(5678);
        return TargetProcess{quint32(5678), {}};
    };
    quint32 loadedPid = 0;
    native.load = [&](quint32 p, const QString &, const QString &) {
        ++loads;
        loadedPid = p;
        return LaunchResult{true, {}};
    };
    LaunchController controller(QDir::tempPath(), expiry(), native);
    QSignalSpy done(&controller, &LaunchController::completed);
    controller.start(QStringLiteral("selected-game.exe"));
    QTRY_COMPARE(done.count(), 1);
    QCOMPARE(launches.load(), 1);
    QCOMPARE(loads.load(), 1);
    QCOMPARE(launchedExe, QStringLiteral("selected-game.exe"));
    QCOMPARE(loadedPid, quint32(5678));
    QCOMPARE(controller.succeededPid(), quint32(5678));
}
void LaunchControllerTest::skipsLaunchWhenGameAlreadyRunning() {
    std::atomic_int loads = 0, launches = 0, pid = 4321;
    auto native = services(loads, pid);
    native.launch = [&](const QString &) {
        ++launches;
        return TargetProcess{quint32(9999), {}};
    };
    LaunchController controller(QDir::tempPath(), expiry(), native);
    QSignalSpy done(&controller, &LaunchController::completed);
    controller.start(QStringLiteral("selected-game.exe"));
    QTRY_COMPARE(done.count(), 1);
    QCOMPARE(launches.load(), 0);
    QCOMPARE(loads.load(), 1);
    QCOMPARE(controller.succeededPid(), quint32(4321));
}
QTEST_GUILESS_MAIN(LaunchControllerTest)
#include "LaunchControllerTest.moc"

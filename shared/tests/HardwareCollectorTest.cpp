#include "hardware/HardwareCollector.h"

#include <QSysInfo>
#include <QtTest>

namespace {

class FakeHardwareSource final : public IHardwareSource
{
public:
    SmbiosInfo smbiosInfo() override
    {
        return {"fixture-uuid", "fixture-board", "fixture-bios"};
    }

    QString systemDiskSerial() override { return "fixture-disk"; }
    QString machineGuid() override { return "fixture-guid"; }
};

} // namespace

class HardwareCollectorTest final : public QObject
{
    Q_OBJECT

private slots:
    void collectsInjectedSignalsAndLocalSystemMetadata();
};

void HardwareCollectorTest::collectsInjectedSignalsAndLocalSystemMetadata()
{
    FakeHardwareSource source;
    HardwareCollector collector(source);

    const HardwareIdentity result = collector.collect();

    QCOMPARE(result.smbiosUuid, QString("fixture-uuid"));
    QCOMPARE(result.motherboardSerial, QString("fixture-board"));
    QCOMPARE(result.biosSerial, QString("fixture-bios"));
    QCOMPARE(result.systemDiskSerial, QString("fixture-disk"));
    QCOMPARE(result.machineGuid, QString("fixture-guid"));
    QCOMPARE(result.cpuArchitecture, QSysInfo::currentCpuArchitecture());
    QCOMPARE(result.hostName, QSysInfo::machineHostName());
    QVERIFY(result.tpmPublicKeyHash.isEmpty());
    QVERIFY(result.finalFingerprint.isEmpty());
}

QTEST_MAIN(HardwareCollectorTest)
#include "HardwareCollectorTest.moc"

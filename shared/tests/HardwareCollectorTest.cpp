#include "hardware/HardwareCollector.h"
#include "hardware/DiskReader.h"

#include <QHash>
#include <QSysInfo>
#include <QtTest>

namespace {

class FakeHardwareSource final : public IHardwareSource
{
public:
    SmbiosInfo smbiosInfo() override
    {
        return {"fixture-uuid", "fixture-board", "version-must-not-be-used"};
    }

    QString biosSerial() override { return "fixture-bios-serial"; }
    QString systemDiskSerial() override { return "fixture-disk"; }
    QString machineGuid() override { return "fixture-guid"; }
};

class FakeDiskSerialSource final : public IDiskSerialSource
{
public:
    QString serialNumber(quint32 diskNumber) override
    {
        requestedDiskNumbers.append(diskNumber);
        return serials.value(diskNumber);
    }

    QHash<quint32, QString> serials;
    QList<quint32> requestedDiskNumbers;
};

} // namespace

class HardwareCollectorTest final : public QObject
{
    Q_OBJECT

private slots:
    void collectsInjectedSignalsAndLocalSystemMetadata();
    void buildsStableSignalFromEveryUniqueBackingDisk();
};

void HardwareCollectorTest::collectsInjectedSignalsAndLocalSystemMetadata()
{
    FakeHardwareSource source;
    HardwareCollector collector(source);

    const HardwareIdentity result = collector.collect();

    QCOMPARE(result.smbiosUuid, QString("fixture-uuid"));
    QCOMPARE(result.motherboardSerial, QString("fixture-board"));
    QCOMPARE(result.biosSerial, QString("fixture-bios-serial"));
    QCOMPARE(result.systemDiskSerial, QString("fixture-disk"));
    QCOMPARE(result.machineGuid, QString("fixture-guid"));
    QCOMPARE(result.cpuArchitecture, QSysInfo::currentCpuArchitecture());
    QCOMPARE(result.hostName, QSysInfo::machineHostName());
    QVERIFY(result.tpmPublicKeyHash.isEmpty());
    QVERIFY(result.finalFingerprint.isEmpty());
}

void HardwareCollectorTest::buildsStableSignalFromEveryUniqueBackingDisk()
{
    FakeDiskSerialSource source;
    source.serials.insert(2, " {disk-a 1} ");
    source.serials.insert(7, "disk-b-2");
    source.serials.insert(9, "   ");

    const QString result = DiskReader::serialSignal({7, 2, 7, 9}, source);

    QCOMPARE(source.requestedDiskNumbers, QList<quint32>({2, 7, 9}));
    QCOMPARE(result, QString("DISKA1|DISKB2"));
}

QTEST_MAIN(HardwareCollectorTest)
#include "HardwareCollectorTest.moc"

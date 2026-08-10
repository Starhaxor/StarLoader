#include "hardware/HardwareIdentity.h"
#include "hardware/HardwareJson.h"

#include <QtTest>

class HardwareJsonTest final : public QObject
{
    Q_OBJECT

private slots:
    void usesDocumentedSnakeCaseKeysAndValues();
};

void HardwareJsonTest::usesDocumentedSnakeCaseKeysAndValues()
{
    const HardwareIdentity identity{
        "smbios", "motherboard", "bios", "disk", "machine-guid", "x64", "host", "tpm-hash", "fingerprint"};

    const QJsonObject json = HardwareJson::toJson(identity);

    QCOMPARE(
        json.keys(),
        QStringList({
            "bios_serial",
            "fingerprint",
            "machine_guid",
            "motherboard_serial",
            "smbios_uuid",
            "system_disk_serial",
            "tpm_public_key_hash",
        }));
    QCOMPARE(json.value("bios_serial").toString(), identity.biosSerial);
    QCOMPARE(json.value("fingerprint").toString(), identity.finalFingerprint);
    QCOMPARE(json.value("machine_guid").toString(), identity.machineGuid);
    QCOMPARE(json.value("motherboard_serial").toString(), identity.motherboardSerial);
    QCOMPARE(json.value("smbios_uuid").toString(), identity.smbiosUuid);
    QCOMPARE(json.value("system_disk_serial").toString(), identity.systemDiskSerial);
    QCOMPARE(json.value("tpm_public_key_hash").toString(), identity.tpmPublicKeyHash);
}

QTEST_MAIN(HardwareJsonTest)
#include "HardwareJsonTest.moc"

#include "HardwareJson.h"

QJsonObject HardwareJson::toJson(const HardwareIdentity &identity)
{
    return {
        {QStringLiteral("bios_serial"), identity.biosSerial},
        {QStringLiteral("fingerprint"), identity.finalFingerprint},
        {QStringLiteral("machine_guid"), identity.machineGuid},
        {QStringLiteral("motherboard_serial"), identity.motherboardSerial},
        {QStringLiteral("smbios_uuid"), identity.smbiosUuid},
        {QStringLiteral("system_disk_serial"), identity.systemDiskSerial},
        {QStringLiteral("tpm_public_key_hash"), identity.tpmPublicKeyHash},
    };
}

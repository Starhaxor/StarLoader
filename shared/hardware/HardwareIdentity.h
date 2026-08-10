#pragma once

#include <QString>

struct HardwareIdentity
{
    QString smbiosUuid;
    QString motherboardSerial;
    QString biosSerial;
    QString systemDiskSerial;
    QString machineGuid;
    QString cpuArchitecture;
    QString hostName;
    QString tpmPublicKeyHash;
    QString finalFingerprint;

    QString displayId() const
    {
        return finalFingerprint.left(6) + '-' + finalFingerprint.mid(6, 6);
    }
};

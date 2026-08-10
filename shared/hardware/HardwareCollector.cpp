#include "HardwareCollector.h"

#include "BiosReader.h"
#include "DiskReader.h"
#include "RegistryReader.h"
#include "SmbiosReader.h"
#include "security/TpmIdentity.h"

#include <QSysInfo>

namespace {

class WindowsHardwareSource final : public IHardwareSource
{
public:
    SmbiosInfo smbiosInfo() override { return SmbiosReader::read(); }
    QString biosSerial() override { return BiosReader::serialNumber(); }
    QString systemDiskSerial() override { return DiskReader::systemDiskSerial(); }
    QString machineGuid() override { return RegistryReader::machineGuid(); }
};

IHardwareSource &defaultHardwareSource()
{
    static WindowsHardwareSource source;
    return source;
}

} // namespace

HardwareCollector::HardwareCollector()
    : HardwareCollector(defaultHardwareSource())
{
}

HardwareCollector::HardwareCollector(IHardwareSource &source)
    : source_(&source)
{
}

HardwareIdentity HardwareCollector::collect()
{
    const SmbiosInfo smbios = source_->smbiosInfo();

    HardwareIdentity identity;
    identity.smbiosUuid = smbios.systemUuid;
    identity.motherboardSerial = smbios.motherboardSerial;
    identity.biosSerial = source_->biosSerial();
    identity.systemDiskSerial = source_->systemDiskSerial();
    identity.machineGuid = source_->machineGuid();
    identity.cpuArchitecture = QSysInfo::currentCpuArchitecture();
    identity.hostName = QSysInfo::machineHostName();
    if (source_ == &defaultHardwareSource()) {
        QString error;
        if (TpmIdentity::ensureKey(&error))
            identity.tpmPublicKeyHash = TpmIdentity::publicKeySha256();
    }
    return identity;
}

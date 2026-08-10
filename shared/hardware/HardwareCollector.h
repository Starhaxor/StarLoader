#pragma once

#include "HardwareIdentity.h"
#include "SmbiosParser.h"

#include <QString>

class IHardwareSource
{
public:
    virtual ~IHardwareSource() = default;

    virtual SmbiosInfo smbiosInfo() = 0;
    virtual QString biosSerial() = 0;
    virtual QString systemDiskSerial() = 0;
    virtual QString machineGuid() = 0;
};

class HardwareCollector
{
public:
    HardwareCollector();
    explicit HardwareCollector(IHardwareSource &source);

    HardwareIdentity collect();

private:
    IHardwareSource *source_;
};

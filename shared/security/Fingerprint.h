#pragma once

#include "hardware/HardwareIdentity.h"

#include <QString>

class Fingerprint
{
public:
    static QString generate(const HardwareIdentity &identity);
};

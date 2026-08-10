#pragma once

#include "HardwareIdentity.h"

#include <QJsonObject>

class HardwareJson
{
public:
    static QJsonObject toJson(const HardwareIdentity &identity);
};

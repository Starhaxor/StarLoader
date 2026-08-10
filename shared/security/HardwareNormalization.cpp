#include "HardwareNormalization.h"

QString normalizeHardwareValue(QString value)
{
    return value.trimmed()
        .toUpper()
        .remove(' ')
        .remove('-')
        .remove('{')
        .remove('}');
}

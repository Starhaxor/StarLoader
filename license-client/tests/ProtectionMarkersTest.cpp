#include "security/ProtectionMarkers.h"

namespace {
int compileStatementPairs(bool condition)
{
    int value = 0;
    if (condition)
        STARLOADER_VM_BEGIN("starloader.test.vm-pair.v1");
    else
        value = 1;
    STARLOADER_VM_END();

    if (condition)
        STARLOADER_MUTATE_BEGIN("starloader.test.mutate-pair.v1");
    else
        value = 2;
    STARLOADER_MUTATE_END();
    return value;
}
} // namespace

int main()
{
    return compileStatementPairs(true);
}

#pragma once
#include <windows.h>

// Conservatively accept an explicit TRUE, not exception/termination codes.
inline bool nativeInitializationConfirmed(DWORD waitResult, DWORD exitCode, bool targetAlive)
{
    return waitResult == WAIT_OBJECT_0 && exitCode == TRUE && targetAlive;
}

#include "RegistryReader.h"

#include <Windows.h>

#include <vector>

QString RegistryReader::machineGuid()
{
    HKEY key = nullptr;
    constexpr wchar_t registryPath[] = L"SOFTWARE\\Microsoft\\Cryptography";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      registryPath,
                      0,
                      KEY_READ | KEY_WOW64_64KEY,
                      &key) != ERROR_SUCCESS) {
        return {};
    }

    DWORD type = 0;
    DWORD byteCount = 0;
    const LSTATUS sizeStatus = RegQueryValueExW(key,
                                                L"MachineGuid",
                                                nullptr,
                                                &type,
                                                nullptr,
                                                &byteCount);
    if (sizeStatus != ERROR_SUCCESS
        || (type != REG_SZ && type != REG_EXPAND_SZ)
        || byteCount == 0) {
        RegCloseKey(key);
        return {};
    }

    std::vector<wchar_t> value(byteCount / sizeof(wchar_t) + 1, L'\0');
    const LSTATUS readStatus = RegQueryValueExW(
        key,
        L"MachineGuid",
        nullptr,
        &type,
        reinterpret_cast<BYTE *>(value.data()),
        &byteCount);
    RegCloseKey(key);

    if (readStatus != ERROR_SUCCESS) {
        return {};
    }

    return QString::fromWCharArray(value.data()).trimmed();
}

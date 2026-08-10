#include "SmbiosReader.h"

#include <Windows.h>

#include <cstddef>
#include <vector>

namespace {

#pragma pack(push, 1)
struct RawSmbiosData
{
    BYTE used20CallingMethod;
    BYTE majorVersion;
    BYTE minorVersion;
    BYTE dmiRevision;
    DWORD length;
    BYTE tableData[1];
};
#pragma pack(pop)

constexpr DWORD rawSmbiosProvider = 0x52534d42UL; // 'RSMB'

} // namespace

SmbiosInfo SmbiosReader::read()
{
    const DWORD required = GetSystemFirmwareTable(rawSmbiosProvider, 0, nullptr, 0);
    if (required < offsetof(RawSmbiosData, tableData)) {
        return {};
    }

    std::vector<BYTE> buffer(required);
    const DWORD written = GetSystemFirmwareTable(rawSmbiosProvider,
                                                  0,
                                                  buffer.data(),
                                                  required);
    if (written < offsetof(RawSmbiosData, tableData) || written > buffer.size()) {
        return {};
    }

    const auto *raw = reinterpret_cast<const RawSmbiosData *>(buffer.data());
    const qsizetype headerSize = offsetof(RawSmbiosData, tableData);
    if (raw->length > written - headerSize) {
        return {};
    }

    return SmbiosParser::parse(QByteArrayView(
        reinterpret_cast<const char *>(raw->tableData), raw->length));
}

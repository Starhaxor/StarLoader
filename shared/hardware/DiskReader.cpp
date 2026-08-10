#include "DiskReader.h"

#include "security/HardwareNormalization.h"

#include <Windows.h>
#include <winioctl.h>

#include <QStringList>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <limits>
#include <optional>
#include <string>
#include <vector>

namespace {

class Handle final
{
public:
    explicit Handle(HANDLE value = INVALID_HANDLE_VALUE) : value_(value) {}
    ~Handle()
    {
        if (value_ != INVALID_HANDLE_VALUE) {
            CloseHandle(value_);
        }
    }

    Handle(const Handle &) = delete;
    Handle &operator=(const Handle &) = delete;

    HANDLE get() const { return value_; }
    bool isValid() const { return value_ != INVALID_HANDLE_VALUE; }

private:
    HANDLE value_;
};

QString systemDriveDevicePath()
{
    const DWORD required = GetEnvironmentVariableW(L"SystemDrive", nullptr, 0);
    if (required == 0) {
        return {};
    }

    std::vector<wchar_t> drive(required, L'\0');
    if (GetEnvironmentVariableW(L"SystemDrive", drive.data(), required) == 0) {
        return {};
    }

    QString systemDrive = QString::fromWCharArray(drive.data()).trimmed();
    while (systemDrive.endsWith('\\') || systemDrive.endsWith('/')) {
        systemDrive.chop(1);
    }
    if (systemDrive.size() != 2
        || !systemDrive.front().isLetter()
        || systemDrive.back() != ':') {
        return {};
    }

    return QStringLiteral("\\\\.\\") + systemDrive;
}

std::optional<DWORD> checkedExtentBufferSize(DWORD extentCount)
{
    constexpr size_t headerSize = offsetof(VOLUME_DISK_EXTENTS, Extents);
    constexpr size_t maxDword = std::numeric_limits<DWORD>::max();
    if (extentCount == 0
        || extentCount > (maxDword - headerSize) / sizeof(DISK_EXTENT)) {
        return std::nullopt;
    }

    return static_cast<DWORD>(headerSize
                              + static_cast<size_t>(extentCount)
                                  * sizeof(DISK_EXTENT));
}

std::optional<QList<quint32>> systemDiskNumbers(HANDLE volume)
{
    std::vector<BYTE> buffer(sizeof(VOLUME_DISK_EXTENTS), 0);
    DWORD bytesReturned = 0;
    const BOOL initialResult = DeviceIoControl(
        volume,
        IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
        nullptr,
        0,
        buffer.data(),
        static_cast<DWORD>(buffer.size()),
        &bytesReturned,
        nullptr);
    const DWORD initialError = initialResult ? ERROR_SUCCESS : GetLastError();

    const auto *initialExtents =
        reinterpret_cast<const VOLUME_DISK_EXTENTS *>(buffer.data());
    auto requiredSize = checkedExtentBufferSize(initialExtents->NumberOfDiskExtents);
    if (initialResult) {
        if (!requiredSize || bytesReturned < *requiredSize) {
            return std::nullopt;
        }
    } else {
        if (initialError != ERROR_MORE_DATA
            || bytesReturned < sizeof(initialExtents->NumberOfDiskExtents)
            || !requiredSize
            || *requiredSize <= buffer.size()) {
            return std::nullopt;
        }

        buffer.assign(*requiredSize, 0);
        bytesReturned = 0;
        if (!DeviceIoControl(volume,
                             IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                             nullptr,
                             0,
                             buffer.data(),
                             static_cast<DWORD>(buffer.size()),
                             &bytesReturned,
                             nullptr)) {
            return std::nullopt;
        }
    }

    const auto *extents =
        reinterpret_cast<const VOLUME_DISK_EXTENTS *>(buffer.data());
    requiredSize = checkedExtentBufferSize(extents->NumberOfDiskExtents);
    if (!requiredSize
        || *requiredSize > buffer.size()
        || bytesReturned < *requiredSize) {
        return std::nullopt;
    }

    QList<quint32> diskNumbers;
    diskNumbers.reserve(extents->NumberOfDiskExtents);
    for (DWORD index = 0; index < extents->NumberOfDiskExtents; ++index) {
        diskNumbers.append(extents->Extents[index].DiskNumber);
    }
    return diskNumbers;
}

QString diskSerial(HANDLE disk)
{
    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;

    STORAGE_DESCRIPTOR_HEADER header{};
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(disk,
                         IOCTL_STORAGE_QUERY_PROPERTY,
                         &query,
                         sizeof(query),
                         &header,
                         sizeof(header),
                         &bytesReturned,
                         nullptr)
        || bytesReturned < sizeof(header)
        || header.Size < sizeof(STORAGE_DEVICE_DESCRIPTOR)
        || header.Size > 1024 * 1024) {
        return {};
    }

    std::vector<BYTE> descriptor(header.Size);
    if (!DeviceIoControl(disk,
                         IOCTL_STORAGE_QUERY_PROPERTY,
                         &query,
                         sizeof(query),
                         descriptor.data(),
                         static_cast<DWORD>(descriptor.size()),
                         &bytesReturned,
                         nullptr)
        || bytesReturned < sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
        return {};
    }

    const auto *device =
        reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR *>(descriptor.data());
    const size_t usableSize = std::min<size_t>(bytesReturned, descriptor.size());
    const size_t serialOffset = device->SerialNumberOffset;
    if (serialOffset == 0 || serialOffset >= usableSize) {
        return {};
    }

    const char *serialStart =
        reinterpret_cast<const char *>(descriptor.data() + serialOffset);
    const size_t serialCapacity = usableSize - serialOffset;
    const auto *serialEnd = static_cast<const char *>(
        std::memchr(serialStart, '\0', serialCapacity));
    if (serialEnd == nullptr) {
        return {};
    }

    return QString::fromLatin1(serialStart, serialEnd - serialStart).trimmed();
}

class WindowsDiskSerialSource final : public IDiskSerialSource
{
public:
    QString serialNumber(quint32 diskNumber) override
    {
        const QString diskPath =
            QStringLiteral("\\\\.\\PhysicalDrive%1").arg(diskNumber);
        const std::wstring nativeDiskPath = diskPath.toStdWString();
        const Handle disk(CreateFileW(nativeDiskPath.c_str(),
                                      0,
                                      FILE_SHARE_READ | FILE_SHARE_WRITE,
                                      nullptr,
                                      OPEN_EXISTING,
                                      0,
                                      nullptr));
        if (!disk.isValid()) {
            return {};
        }

        return diskSerial(disk.get());
    }
};

} // namespace

QString DiskReader::serialSignal(QList<quint32> diskNumbers,
                                 IDiskSerialSource &source)
{
    std::sort(diskNumbers.begin(), diskNumbers.end());
    diskNumbers.erase(std::unique(diskNumbers.begin(), diskNumbers.end()),
                      diskNumbers.end());

    QStringList serials;
    for (const quint32 diskNumber : diskNumbers) {
        const QString serial =
            normalizeHardwareValue(source.serialNumber(diskNumber));
        if (!serial.isEmpty()) {
            serials.append(serial);
        }
    }

    return serials.join('|');
}

QString DiskReader::systemDiskSerial()
{
    const QString volumePath = systemDriveDevicePath();
    if (volumePath.isEmpty()) {
        return {};
    }

    const std::wstring nativeVolumePath = volumePath.toStdWString();
    const Handle volume(CreateFileW(nativeVolumePath.c_str(),
                                    0,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                                    nullptr,
                                    OPEN_EXISTING,
                                    0,
                                    nullptr));
    if (!volume.isValid()) {
        return {};
    }

    const auto diskNumbers = systemDiskNumbers(volume.get());
    if (!diskNumbers) {
        return {};
    }

    WindowsDiskSerialSource source;
    return serialSignal(*diskNumbers, source);
}

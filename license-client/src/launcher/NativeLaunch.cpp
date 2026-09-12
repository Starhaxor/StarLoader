#include "NativeLaunch.h"
#include "StarInjectorManualMap.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QtEndian>
#include <tlhelp32.h>

namespace {
struct Handle {
    HANDLE value;
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
QString canonical(const QString &path) { return QDir::fromNativeSeparators(QFileInfo(path).canonicalFilePath()); }
QString imagePath(HANDLE process) {
    wchar_t buffer[32768]; DWORD length = 32768;
    return QueryFullProcessImageNameW(process, 0, buffer, &length)
        ? canonical(QString::fromWCharArray(buffer, length)) : QString();
}
bool samePath(const QString &a, const QString &b) {
    return !a.isEmpty() && !b.isEmpty() && a.compare(b, Qt::CaseInsensitive) == 0;
}
quint16 machine(const QString &path, bool dll) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) return 0;
    const QByteArray dos = file.read(64);
    if (dos.size() != 64 || dos.first(2) != "MZ") return 0;
    const quint32 offset = qFromLittleEndian<quint32>(dos.constData() + 60);
    if (offset < 64 || qint64(offset) + 24 > file.size() || !file.seek(offset)) return 0;
    const QByteArray pe = file.read(24);
    if (pe.size() != 24 || pe.first(4) != QByteArray("PE\0\0", 4)) return 0;
    const quint16 flags = qFromLittleEndian<quint16>(pe.constData() + 22);
    if (!(flags & IMAGE_FILE_EXECUTABLE_IMAGE) || bool(flags & IMAGE_FILE_DLL) != dll) return 0;
    const quint16 architecture = qFromLittleEndian<quint16>(pe.constData() + 4);
    return architecture == IMAGE_FILE_MACHINE_I386 || architecture == IMAGE_FILE_MACHINE_AMD64 ? architecture : 0;
}
TargetProcess findTarget(const QString &executable) {
    const QString expected = canonical(executable);
    if (expected.isEmpty()) return {0, QStringLiteral("The selected executable no longer exists.")};
    Handle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};
    if (snapshot.value == INVALID_HANDLE_VALUE) return {0, QStringLiteral("Could not inspect running applications.")};
    PROCESSENTRY32W entry{}; entry.dwSize = sizeof(entry);
    quint32 found = 0;
    if (Process32FirstW(snapshot.value, &entry)) do {
        if (QString::fromWCharArray(entry.szExeFile).compare(QFileInfo(expected).fileName(), Qt::CaseInsensitive) != 0) continue;
        Handle process{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID)};
        // An unrelated same-name process or a process exiting during enumeration
        // must not prevent discovering a later exact-path match.
        if (!process.value) continue;
        if (!samePath(imagePath(process.value), expected)) continue;
        if (found) return {0, QStringLiteral("Multiple copies of the selected game are running. Keep only one open.")};
        found = entry.th32ProcessID;
    } while (Process32NextW(snapshot.value, &entry));
    return {found, {}};
}
LaunchResult loadTarget(quint32 pid, const QString &executable, const QString &payload) {
    const QString error = validateLaunchFiles(executable, payload);
    if (!error.isEmpty()) return {false, error};
    Handle process{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid)};
    if (!process.value || !samePath(imagePath(process.value), canonical(executable))
        || WaitForSingleObject(process.value, 0) != WAIT_TIMEOUT)
        return {false, QStringLiteral("The selected game exited or changed before loading.")};
    BOOL wow64 = FALSE;
    SYSTEM_INFO system{}; GetNativeSystemInfo(&system);
    if (!IsWow64Process(process.value, &wow64)) return {false, QStringLiteral("Cannot determine game architecture.")};
    const bool target32 = wow64 || system.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL;
    if ((machine(payload, true) == IMAGE_FILE_MACHINE_I386) != target32)
        return {false, QStringLiteral("DLL architecture does not match the running game.")};
    InjectorEngine engine;
    SetLastError(ERROR_SUCCESS);
    if (!engine.injectManualMap(pid, payload, 5000))
        return {false, QStringLiteral("Loading failed (Windows error %1).").arg(GetLastError())};
    if (WaitForSingleObject(process.value, 0) != WAIT_TIMEOUT)
        return {false, QStringLiteral("The game exited during loading.")};
    return {true, {}};
}
}

QString validateLaunchFiles(const QString &executable, const QString &payload) {
    if (QFileInfo(executable).suffix().compare(QStringLiteral("exe"), Qt::CaseInsensitive) != 0)
        return QStringLiteral("Select a Windows game EXE.");
    if (!QFileInfo(payload).isFile()) return QStringLiteral("AssaultCubeMultiHack.dll is missing. Place it beside StarLoader.");
    const auto exeMachine = machine(executable, false), dllMachine = machine(payload, true);
    if (!exeMachine || !dllMachine) return QStringLiteral("The game or DLL is not a supported Windows executable.");
    if (exeMachine != dllMachine) return QStringLiteral("The game and DLL must both be x86 or both be x64.");
    return {};
}
LaunchServices nativeLaunchServices() { return {validateLaunchFiles, findTarget, loadTarget}; }

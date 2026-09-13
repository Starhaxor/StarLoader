#include "NativeLaunch.h"
#include "StarInjectorManualMap.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QtEndian>
#include <tlhelp32.h>
#include <vector>

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

namespace {
struct WindowSearch {
    DWORD pid = 0;
    bool found = false;
};
BOOL CALLBACK enumProcessWindows(HWND window, LPARAM param)
{
    auto *search = reinterpret_cast<WindowSearch *>(param);
    DWORD windowPid = 0;
    GetWindowThreadProcessId(window, &windowPid);
    if (windowPid != search->pid) return TRUE;
    if (GetWindow(window, GW_OWNER) != nullptr) return TRUE;
    if (!IsWindowVisible(window)) return TRUE;
    search->found = true;
    return FALSE;
}
} // namespace

bool processAlive(quint32 pid)
{
    if (pid == 0) return false;
    Handle process{OpenProcess(SYNCHRONIZE, FALSE, pid)};
    if (!process.value) return false;
    return WaitForSingleObject(process.value, 0) == WAIT_TIMEOUT;
}

bool processWindowOpen(quint32 pid)
{
    if (!processAlive(pid)) return false;
    WindowSearch search{};
    search.pid = pid;
    EnumWindows(enumProcessWindows, reinterpret_cast<LPARAM>(&search));
    return search.found;
}

TargetProcess launchGame(const QString &executable)
{
    const QString absolute = canonical(executable);
    if (absolute.isEmpty())
        return {0, QStringLiteral("The selected executable no longer exists.")};
    // Games like AssaultCube must start from the game root (parent of the
    // bin folder), not from the executable's own folder, or they cannot
    // find their data files.
    QDir directory(QFileInfo(absolute).absolutePath());
    if (directory.dirName().startsWith(QStringLiteral("bin"), Qt::CaseInsensitive))
        directory.cdUp();
    const QString workDirPath = directory.absolutePath();
    // AssaultCube keeps the player profile (settings, window mode, binds)
    // outside the install dir and only uses it when started with the same
    // arguments as its official launcher. Without them the game boots a
    // fresh default profile (fullscreen, default settings), which looks
    // like "my config was wiped". Keep in sync with assaultcube.bat.
    // TODO: move to per-game launch profiles once more games are supported.
    QString commandLine = QStringLiteral("\"%1\"").arg(absolute);
    if (QFileInfo(absolute).fileName().compare(QStringLiteral("ac_client.exe"), Qt::CaseInsensitive) == 0)
        commandLine += QStringLiteral(" \"--home=?MYDOCUMENTS?\\My Games\\AssaultCube\\v1.3\" --init");
    std::vector<wchar_t> command(commandLine.size() + 1, 0);
    commandLine.toWCharArray(command.data());
    std::vector<wchar_t> workDir(workDirPath.size() + 1, 0);
    workDirPath.toWCharArray(workDir.data());
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION info{};
    if (!CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, 0,
                        nullptr, workDir.data(), &startup, &info)) {
        const DWORD err = GetLastError();
        return {0, QStringLiteral("Could not start the game (Windows error %1).").arg(err)};
    }
    CloseHandle(info.hThread);
    CloseHandle(info.hProcess);
    return {info.dwProcessId, {}};
}

QString validateLaunchFiles(const QString &executable, const QString &payload) {
    if (QFileInfo(executable).suffix().compare(QStringLiteral("exe"), Qt::CaseInsensitive) != 0)
        return QStringLiteral("Select a Windows game EXE.");
    if (!QFileInfo(payload).isFile()) return QStringLiteral("Payload %1 is missing. Place it beside StarLoader.").arg(QFileInfo(payload).fileName());
    const auto exeMachine = machine(executable, false), dllMachine = machine(payload, true);
    if (!exeMachine || !dllMachine) return QStringLiteral("The game or DLL is not a supported Windows executable.");
    if (exeMachine != dllMachine) return QStringLiteral("The game and DLL must both be x86 or both be x64.");
    return {};
}
LaunchServices nativeLaunchServices() { return {validateLaunchFiles, findTarget, loadTarget, launchGame}; }

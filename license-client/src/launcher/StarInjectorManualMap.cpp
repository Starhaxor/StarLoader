// Adapted from the user's local StarInjector/injectorengine.cpp.
// Only manual mapping and its dependencies are included. No alternate injection methods.
#include "StarInjectorManualMap.h"
#include "NativeCallResult.h"
#include <tlhelp32.h>
#include <vector>
#include <algorithm>
#include <cstring>
#include <QtGlobal>
#include <QDebug>
#include <QFileInfo>
#include <QDir>

InjectorEngine::InjectorEngine() {}
InjectorEngine::~InjectorEngine() {}

void InjectorEngine::logMessage(const QString& message)
{
    Q_UNUSED(message)
}

std::string InjectorEngine::getLastErrorString(DWORD errorCode)
{
    return std::to_string(errorCode);
}

QString InjectorEngine::getProcessArchitecture(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) return QStringLiteral("Unknown");
    BOOL isWow64 = FALSE;
    // IsWow64Process: if true -> 32-bit process on 64-bit OS
    // if false -> either 32-bit on 32-bit OS or 64-bit on 64-bit OS
    if (!IsWow64Process(hProcess, &isWow64)) {
        CloseHandle(hProcess);
        return QStringLiteral("Unknown");
    }
    CloseHandle(hProcess);

    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    const bool osIs64 = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
                          si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64 ||
                          si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64);
    if (!osIs64) return QStringLiteral("x86");
    return isWow64 ? QStringLiteral("x86") : QStringLiteral("x64");
}

static bool isDllLoadedInProcess(DWORD pid, const QString &dllPath, bool targetIs32 = false)
{
    const QString dllName = QFileInfo(dllPath).fileName().toLower();
    const QString dllFull = QDir::toNativeSeparators(dllPath).toLower();
    DWORD flags = TH32CS_SNAPMODULE;
    if (targetIs32) flags |= TH32CS_SNAPMODULE32;
    HANDLE hSnap = CreateToolhelp32Snapshot(flags, pid);
    if (hSnap == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W me{}; me.dwSize = sizeof(me);
    bool found = false;
    if (Module32FirstW(hSnap, &me)) {
        do {
            QString modName = QString::fromWCharArray(me.szModule).toLower();
            QString modPath = QString::fromWCharArray(me.szExePath).toLower();
            if (modName == dllName || modPath == dllFull || modPath.endsWith(QLatin1Char('\\') + dllName)) {
                ULONGLONG addr = reinterpret_cast<ULONGLONG>(me.modBaseAddr);
                if (targetIs32 && addr >= 0x100000000ULL) continue;
                found = true; break;
            }
        } while (Module32NextW(hSnap, &me));
    }
    CloseHandle(hSnap);
    return found;
}

static bool waitForModuleLoad(DWORD pid, const QString &dllPath, DWORD timeoutMs, bool targetIs32 = false)
{
    const DWORD interval = 100;
    DWORD waited = 0;
    while (waited < timeoutMs) {
        if (isDllLoadedInProcess(pid, dllPath, targetIs32)) return true;
        Sleep(interval);
        waited += interval;
    }
    return isDllLoadedInProcess(pid, dllPath, targetIs32);
}

static ULONGLONG getRemoteModuleBase(DWORD pid, const QString &dllNameLower, bool targetIs32 = false)
{
    DWORD flags = TH32CS_SNAPMODULE;
    if (targetIs32) flags |= TH32CS_SNAPMODULE32;
    HANDLE hSnap = CreateToolhelp32Snapshot(flags, pid);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32W me{}; me.dwSize = sizeof(me);
    ULONGLONG base = 0;
    if (Module32FirstW(hSnap, &me)) {
        do {
            QString mod = QString::fromWCharArray(me.szModule).toLower();
            if (mod == dllNameLower) {
                ULONGLONG addr = reinterpret_cast<ULONGLONG>(me.modBaseAddr);
                // CRITICAL FIX: For 32-bit target, ignore 64-bit modules (>=4GB) from WoW64 snapshot
                if (targetIs32 && addr >= 0x100000000ULL) {
                    continue;
                }
                base = addr;
                break;
            }
        } while (Module32NextW(hSnap, &me));
    }
    CloseHandle(hSnap);
    return base;
}

static QString findSystemDllPath(const QString &dllName, bool targetIs32)
{
    // For 32-bit target on 64-bit OS, system32 is actually 64-bit, SysWOW64 is 32-bit
    // dllName is like "VCRUNTIME140D.dll"
    const QString nameLower = dllName.toLower();
    // Try SysWOW64 for 32-bit target
    if (targetIs32) {
        QString p1 = QStringLiteral("C:\\Windows\\SysWOW64\\") + dllName;
        if (GetFileAttributesW(reinterpret_cast<LPCWSTR>(p1.utf16())) != INVALID_FILE_ATTRIBUTES) return p1;
        QString p2 = QStringLiteral("C:\\Windows\\System32\\") + dllName;
        if (GetFileAttributesW(reinterpret_cast<LPCWSTR>(p2.utf16())) != INVALID_FILE_ATTRIBUTES) return p2;
    } else {
        QString p1 = QStringLiteral("C:\\Windows\\System32\\") + dllName;
        if (GetFileAttributesW(reinterpret_cast<LPCWSTR>(p1.utf16())) != INVALID_FILE_ATTRIBUTES) return p1;
    }
    // Fallback to SearchPath
    wchar_t buf[MAX_PATH] = {0};
    if (SearchPathW(nullptr, reinterpret_cast<LPCWSTR>(dllName.utf16()), nullptr, MAX_PATH, buf, nullptr)) {
        return QString::fromWCharArray(buf);
    }
    return dllName;
}

static DWORD getExportRVAFromFile(const QString &filePath, const char* funcName, WORD ordinal, bool isOrdinal);

// N-arg 32-bit call inside a WOW64 target via borrowed-thread hijack (defined below).
static bool call32ViaThreadHijack(HANDLE hProcess, DWORD pid, DWORD func32,
                                  const DWORD *args, int nArgs, DWORD timeoutMs,
                                  DWORD *outResult, const char *tag);

static ULONGLONG getRemoteLoadLibraryAddress(DWORD pid, bool targetIs32)
{
    ULONGLONG k32Base = getRemoteModuleBase(pid, QStringLiteral("kernel32.dll"), targetIs32);
    if (k32Base == 0) {
        qDebug() << "[LoadLibrary] kernel32 not found in target pid=" << pid;
        return 0;
    }
    QString k32Path = findSystemDllPath(QStringLiteral("kernel32.dll"), targetIs32);
    DWORD rva = getExportRVAFromFile(k32Path, "LoadLibraryW", 0, false);
    if (rva == 0) {
        // Try remote path from snapshot (filter 64-bit for 32-bit target)
        DWORD flags = TH32CS_SNAPMODULE;
        if (targetIs32) flags |= TH32CS_SNAPMODULE32;
        HANDLE hSnap = CreateToolhelp32Snapshot(flags, pid);
        if (hSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me{}; me.dwSize = sizeof(me);
            if (Module32FirstW(hSnap, &me)) do {
                if (QString::fromWCharArray(me.szModule).toLower() == QStringLiteral("kernel32.dll")) {
                    ULONGLONG addr = reinterpret_cast<ULONGLONG>(me.modBaseAddr);
                    if (targetIs32 && addr >= 0x100000000ULL) continue;
                    QString rp = QString::fromWCharArray(me.szExePath);
                    rva = getExportRVAFromFile(rp, "LoadLibraryW", 0, false);
                    if (rva) { k32Path = rp; break; }
                }
            } while (Module32NextW(hSnap, &me));
            CloseHandle(hSnap);
        }
        if (rva == 0) {
            qDebug() << "[LoadLibrary] LoadLibraryW RVA not found in" << k32Path;
            return 0;
        }
    }
    ULONGLONG addr = k32Base + rva;
    qDebug() << "[LoadLibrary] Remote LoadLibraryW for pid" << pid << (targetIs32 ? "x86" : "x64") << " base=0x" << Qt::hex << k32Base << " rva=0x" << rva << " addr=0x" << addr << Qt::dec;
    return addr;
}

static DWORD getExportRVAFromFile(const QString &filePath, const char* funcName, WORD ordinal, bool isOrdinal)
{
    HANDLE hFile = CreateFileW(reinterpret_cast<LPCWSTR>(filePath.utf16()), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return 0;
    HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMap) { CloseHandle(hFile); return 0; }
    BYTE* base = reinterpret_cast<BYTE*>(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
    if (!base) { CloseHandle(hMap); CloseHandle(hFile); return 0; }
    DWORD rva = 0;
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
        BYTE* ntBase = base + dos->e_lfanew;
        DWORD sig = *reinterpret_cast<DWORD*>(ntBase);
        if (sig == IMAGE_NT_SIGNATURE) {
            auto* fh = reinterpret_cast<PIMAGE_FILE_HEADER>(ntBase + sizeof(DWORD));
            BYTE* optBase = ntBase + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
            WORD magic = *reinterpret_cast<WORD*>(optBase);
            DWORD exportRVA = 0, exportSize = 0;
            if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
                auto* opt = reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(optBase);
                exportRVA = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                exportSize = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
                auto* opt = reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(optBase);
                exportRVA = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                exportSize = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            }
            if (exportRVA && exportSize) {
                // Need to map RVA to file offset via sections
                auto* sections = reinterpret_cast<PIMAGE_SECTION_HEADER>(optBase + fh->SizeOfOptionalHeader);
                auto rvaToOffset = [&](DWORD rva)->BYTE* {
                    for (WORD i=0;i<fh->NumberOfSections;++i) {
                        DWORD secVA = sections[i].VirtualAddress;
                        DWORD secSize = std::max(sections[i].Misc.VirtualSize, sections[i].SizeOfRawData);
                        if (rva >= secVA && rva < secVA + secSize) {
                            DWORD delta = rva - secVA;
                            return base + sections[i].PointerToRawData + delta;
                        }
                    }
                    return nullptr;
                };
                BYTE* expBase = rvaToOffset(exportRVA);
                if (expBase) {
                    auto* expDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(expBase);
                    DWORD numNames = expDir->NumberOfNames;
                    DWORD numFuncs = expDir->NumberOfFunctions;
                    DWORD addrNamesRVA = expDir->AddressOfNames;
                    DWORD addrFuncsRVA = expDir->AddressOfFunctions;
                    DWORD addrOrdinalsRVA = expDir->AddressOfNameOrdinals;
                    BYTE* namesTab = rvaToOffset(addrNamesRVA);
                    BYTE* funcsTab = rvaToOffset(addrFuncsRVA);
                    BYTE* ordsTab = rvaToOffset(addrOrdinalsRVA);
                    if (namesTab && funcsTab && ordsTab) {
                        if (isOrdinal) {
                            DWORD ordBase = expDir->Base;
                            if (ordinal >= ordBase && ordinal < ordBase + numFuncs) {
                                DWORD idx = ordinal - ordBase;
                                DWORD funcRVA = reinterpret_cast<DWORD*>(funcsTab)[idx];
                                rva = funcRVA;
                            }
                        } else {
                            for (DWORD i=0;i<numNames;++i) {
                                DWORD nameRVA = reinterpret_cast<DWORD*>(namesTab)[i];
                                BYTE* namePtr = rvaToOffset(nameRVA);
                                if (!namePtr) continue;
                                if (strcmp(reinterpret_cast<char*>(namePtr), funcName)==0) {
                                    WORD ordIdx = reinterpret_cast<WORD*>(ordsTab)[i];
                                    DWORD funcRVA = reinterpret_cast<DWORD*>(funcsTab)[ordIdx];
                                    rva = funcRVA;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    UnmapViewOfFile(base);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return rva;
}

static std::string getForwarderStringForRVA(const QString &filePath, DWORD rva)
{
    HANDLE hFile = CreateFileW(reinterpret_cast<LPCWSTR>(filePath.utf16()), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return {};
    HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMap) { CloseHandle(hFile); return {}; }
    BYTE* base = reinterpret_cast<BYTE*>(MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
    if (!base) { CloseHandle(hMap); CloseHandle(hFile); return {}; }
    std::string result;
    auto* dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
        BYTE* ntBase = base + dos->e_lfanew;
        DWORD sig = *reinterpret_cast<DWORD*>(ntBase);
        if (sig == IMAGE_NT_SIGNATURE) {
            auto* fh = reinterpret_cast<PIMAGE_FILE_HEADER>(ntBase + sizeof(DWORD));
            BYTE* optBase = ntBase + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
            WORD magic = *reinterpret_cast<WORD*>(optBase);
            DWORD exportRVA = 0, exportSize = 0;
            if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
                auto* opt = reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(optBase);
                exportRVA = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                exportSize = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
                auto* opt = reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(optBase);
                exportRVA = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                exportSize = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            }
            if (exportRVA && exportSize && rva >= exportRVA && rva < exportRVA + exportSize) {
                auto* sections = reinterpret_cast<PIMAGE_SECTION_HEADER>(optBase + fh->SizeOfOptionalHeader);
                auto rvaToOffset = [&](DWORD r)->BYTE* {
                    for (WORD i=0;i<fh->NumberOfSections;++i) {
                        DWORD secVA = sections[i].VirtualAddress;
                        DWORD secSize = std::max(sections[i].Misc.VirtualSize, sections[i].SizeOfRawData);
                        if (r >= secVA && r < secVA + secSize) {
                            return base + sections[i].PointerToRawData + (r - secVA);
                        }
                    }
                    return (BYTE*)nullptr;
                };
                BYTE* fwdPtr = rvaToOffset(rva);
                if (fwdPtr) result = reinterpret_cast<char*>(fwdPtr);
            }
        }
    }
    UnmapViewOfFile(base);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return result;
}

static QString apiSetToHost(const QString &apiSetLower)
{
    // Common api-ms -> host mapping for CRT and core
    if (apiSetLower.startsWith(QStringLiteral("api-ms-win-crt-"))) {
        return QStringLiteral("ucrtbase.dll");
    }
    if (apiSetLower == QStringLiteral("api-ms-win-core-winrt-string-l1-1-0.dll") ||
        apiSetLower == QStringLiteral("api-ms-win-core-winrt-l1-1-0.dll")) {
        return QStringLiteral("combase.dll");
    }
    if (apiSetLower.startsWith(QStringLiteral("api-ms-win-core-"))) {
        // Most api-ms-win-core -> kernel32/kernelbase/ntdll
        // Try kernel32 first, then kernelbase, then ntdll as fallback
        // For simplicity, try kernel32
        if (apiSetLower.contains(QStringLiteral("file")) || apiSetLower.contains(QStringLiteral("process")) || apiSetLower.contains(QStringLiteral("memory")) || apiSetLower.contains(QStringLiteral("handle")) || apiSetLower.contains(QStringLiteral("errorhandling")) || apiSetLower.contains(QStringLiteral("threadpool")) || apiSetLower.contains(QStringLiteral("profile")) || apiSetLower.contains(QStringLiteral("sysinfo")) || apiSetLower.contains(QStringLiteral("timezone")) || apiSetLower.contains(QStringLiteral("registry")) || apiSetLower.contains(QStringLiteral("enclave"))) {
            return QStringLiteral("kernel32.dll");
        }
        if (apiSetLower.contains(QStringLiteral("rtlsupport")) || apiSetLower.contains(QStringLiteral("fibers")) || apiSetLower.contains(QStringLiteral("interlocked")) || apiSetLower.contains(QStringLiteral("normalization")) || apiSetLower.contains(QStringLiteral("string")) || apiSetLower.contains(QStringLiteral("winnls"))) {
            return QStringLiteral("ntdll.dll");
        }
        return QStringLiteral("kernelbase.dll");
    }
    if (apiSetLower.startsWith(QStringLiteral("ext-ms-"))) {
        return QStringLiteral("kernel32.dll");
    }
    return QString();
}

static FARPROC getRemoteProcAddressFallback(HANDLE hTargetProc, DWORD pid, const char* dllName, const char* funcName, WORD ordinal, bool isOrdinal, bool targetIs32, int depth = 0)
{
    if (depth > 8) {
        qDebug() << "[ManualMap] Max recursion depth reached for" << dllName;
        return nullptr;
    }
    QString dllStr = QString::fromLatin1(dllName);
    QString dllLower = dllStr.toLower();
    // Handle API Set virtual DLLs: directly map to host without needing file
    if (dllLower.startsWith(QStringLiteral("api-ms-")) || dllLower.startsWith(QStringLiteral("ext-ms-"))) {
        QString host = apiSetToHost(dllLower);
        if (!host.isEmpty()) {
            qDebug() << "[ManualMap] API Set" << dllName << "-> host" << host << " for" << (isOrdinal ? QString::number(ordinal) : QString(funcName ? funcName : ""));
            // Recursively resolve via host DLL
            FARPROC hostAddr = getRemoteProcAddressFallback(hTargetProc, pid, host.toLatin1().constData(), funcName, ordinal, isOrdinal, targetIs32, depth + 1);
            if (hostAddr) return hostAddr;
            // Fall through to normal handling if host resolve fails
            qDebug() << "[ManualMap] API Set host resolve failed, trying file fallback";
        }
    }
    ULONGLONG remoteBase = getRemoteModuleBase(pid, dllLower, targetIs32);
    bool isApiSet = dllLower.startsWith(QStringLiteral("api-ms-")) || dllLower.startsWith(QStringLiteral("ext-ms-"));
    // If not loaded in target, try to load it remotely via remote LoadLibraryW (cross-arch safe)
    // For api-ms virtual DLLs, don't try LoadLibrary - they are not real files, resolve via forwarder instead
    if (remoteBase == 0) {
        if (isApiSet) {
            qDebug() << "[ManualMap] api-ms virtual DLL" << dllName << "not loaded in target pid=" << pid << "- will resolve forwarder via file";
            // Don't return, fall through to file forwarder handling below (remoteBase stays 0, but forwarder will redirect)
        } else {
            qDebug() << "[ManualMap] Remote module not found in target:" << dllName << " pid=" << pid << " -> attempting remote LoadLibrary";
            ULONGLONG k32Base = getRemoteModuleBase(pid, QStringLiteral("kernel32.dll"), targetIs32);
            if (k32Base == 0) {
                qDebug() << "[ManualMap] kernel32 not found in target, cannot remote load";
                return nullptr;
            }
            QString k32Path = findSystemDllPath(QStringLiteral("kernel32.dll"), targetIs32);
            DWORD loadLibRVA = getExportRVAFromFile(k32Path, "LoadLibraryW", 0, false);
            if (loadLibRVA == 0) {
                qDebug() << "[ManualMap] LoadLibraryW RVA not found in" << k32Path;
                return nullptr;
            }
            ULONGLONG loadLibAddr = k32Base + loadLibRVA;
            qDebug() << "[ManualMap] LoadLibraryW remote addr=0x" << Qt::hex << loadLibAddr
                     << " (k32=0x" << k32Base << " rva=0x" << loadLibRVA << ")" << Qt::dec;
            QString depPath = findSystemDllPath(dllStr, targetIs32);
            // Verify file exists
            if (GetFileAttributesW(reinterpret_cast<LPCWSTR>(depPath.utf16())) == INVALID_FILE_ATTRIBUTES) {
                depPath = dllStr; // fallback to just name, let target search
            }
            // Use existing hTargetProc instead of opening new (avoids extra ACCESS_DENIED for protected processes)
            if (!hTargetProc || hTargetProc == INVALID_HANDLE_VALUE) {
                qDebug() << "[ManualMap] Invalid target handle for remote load";
                return nullptr;
            }
            std::wstring wpath = depPath.toStdWString();
            SIZE_T sz = (wpath.size() + 1) * sizeof(wchar_t);
            LPVOID rem = VirtualAllocEx(hTargetProc, nullptr, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!rem) {
                DWORD err = GetLastError();
                qDebug() << "[ManualMap] VirtualAllocEx for remote LoadLibrary failed err=" << err;
                return nullptr;
            }
            if (!WriteProcessMemory(hTargetProc, rem, wpath.c_str(), sz, nullptr)) {
                DWORD err = GetLastError();
                qDebug() << "[ManualMap] WriteProcessMemory for remote LoadLibrary failed err=" << err;
                VirtualFreeEx(hTargetProc, rem, 0, MEM_RELEASE);
                return nullptr;
            }
            DWORD ec = 0;
            // A 64-bit injector's CreateRemoteThread into a WOW64 target starts
            // a 64-bit thread, which cannot run the 32-bit LoadLibraryW entry
            // correctly. Borrow a native 32-bit thread instead (1-arg call).
            if (targetIs32 && sizeof(void*) == 8) {
                const DWORD strArg = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(rem) & 0xFFFFFFFFULL);
                const DWORD libFunc = static_cast<DWORD>(loadLibAddr & 0xFFFFFFFFULL);
                DWORD libResult = 0;
                if (!call32ViaThreadHijack(hTargetProc, pid, libFunc, &strArg, 1,
                                           4000, &libResult, "LoadLibrary") ||
                    libResult == 0) {
                    qDebug() << "[ManualMap] Remote hijack LoadLibrary failed for" << dllName;
                    VirtualFreeEx(hTargetProc, rem, 0, MEM_RELEASE);
                    SetLastError(ERROR_MOD_NOT_FOUND);
                    return nullptr;
                }
                ec = libResult;
                VirtualFreeEx(hTargetProc, rem, 0, MEM_RELEASE);
            } else {
                HANDLE hTh = CreateRemoteThread(hTargetProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(static_cast<ULONG_PTR>(loadLibAddr)), rem, 0, nullptr);
                if (!hTh) {
                    DWORD err = GetLastError();
                    qDebug() << "[ManualMap] CreateRemoteThread for remote LoadLibrary failed err=" << err;
                    VirtualFreeEx(hTargetProc, rem, 0, MEM_RELEASE);
                    return nullptr;
                }
                if (WaitForSingleObject(hTh, 4000) != WAIT_OBJECT_0) {
                    CloseHandle(hTh);
                    SetLastError(ERROR_TIMEOUT);
                    // A running remote call may still reference rem; leave it allocated.
                    return nullptr;
                }
                if (!GetExitCodeThread(hTh, &ec)) {
                    CloseHandle(hTh);
                    return nullptr;
                }
                CloseHandle(hTh);
                VirtualFreeEx(hTargetProc, rem, 0, MEM_RELEASE);
                if (ec == 0) {
                    qDebug() << "[ManualMap] Remote LoadLibrary failed for" << dllName << " err=" << GetLastError();
                    return nullptr;
                }
            }
            qDebug() << "[ManualMap] Remote LoadLibrary succeeded for" << dllName << " hMod=0x" << Qt::hex << ec << Qt::dec;
            // Small delay and retry
            Sleep(200);
            remoteBase = getRemoteModuleBase(pid, dllLower, targetIs32);
            if (remoteBase == 0) {
                qDebug() << "[ManualMap] Still not found after remote load:" << dllName;
                return nullptr;
            }
        }
    }
    QString filePath = findSystemDllPath(dllStr, targetIs32);
    DWORD funcRVA = getExportRVAFromFile(filePath, funcName, ordinal, isOrdinal);
    if (funcRVA == 0) {
        // Try alternative file path (maybe loaded from different location)
        // Try to get remote module path via snapshot and parse that file (filter 64-bit for 32-bit target)
        DWORD flags = TH32CS_SNAPMODULE;
        if (targetIs32) flags |= TH32CS_SNAPMODULE32;
        HANDLE hSnap = CreateToolhelp32Snapshot(flags, pid);
        if (hSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me{}; me.dwSize = sizeof(me);
            if (Module32FirstW(hSnap, &me)) do {
                if (QString::fromWCharArray(me.szModule).toLower() == dllLower) {
                    ULONGLONG addr = reinterpret_cast<ULONGLONG>(me.modBaseAddr);
                    if (targetIs32 && addr >= 0x100000000ULL) continue;
                    QString remotePath = QString::fromWCharArray(me.szExePath);
                    funcRVA = getExportRVAFromFile(remotePath, funcName, ordinal, isOrdinal);
                    if (funcRVA) { filePath = remotePath; break; }
                }
            } while (Module32NextW(hSnap, &me));
            CloseHandle(hSnap);
        }
        if (funcRVA == 0) {
            qDebug() << "[ManualMap] Export RVA not found in file:" << filePath << " func:" << (isOrdinal ? QString::number(ordinal) : QString::fromLatin1(funcName ? funcName : ""));
            return nullptr;
        }
    }
    // Check for forwarded export (API Set like api-ms-win-crt-runtime-l1-1-0 -> ucrtbase)
    {
        std::string fwd = getForwarderStringForRVA(filePath, funcRVA);
        if (!fwd.empty()) {
            qDebug() << "[ManualMap] Forwarder detected" << dllName << (isOrdinal ? QString::number(ordinal) : QString(funcName ? funcName : "")) << "->" << QString::fromStdString(fwd);
            size_t dot = fwd.find('.');
            if (dot != std::string::npos) {
                std::string fwdDll = fwd.substr(0, dot);
                std::string fwdSym = fwd.substr(dot+1);
                if (fwdDll.find('.') == std::string::npos) fwdDll += ".dll";
                bool fwdIsOrd = !fwdSym.empty() && fwdSym[0] == '#';
                WORD fwdOrd = 0;
                std::string fwdNameStr;
                const char* fwdNameC = nullptr;
                if (fwdIsOrd) fwdOrd = static_cast<WORD>(atoi(fwdSym.c_str()+1));
                else { fwdNameStr = fwdSym; fwdNameC = fwdNameStr.c_str(); }
                // Prevent infinite loop
                QString fwdDllLower = QString::fromStdString(fwdDll).toLower();
                bool same = (fwdDllLower == dllLower) && ((fwdIsOrd && fwdOrd == ordinal) || (!fwdIsOrd && funcName && fwdSym == std::string(funcName)));
                if (!same) {
                    FARPROC fwdAddr = getRemoteProcAddressFallback(hTargetProc, pid, fwdDll.c_str(), fwdIsOrd ? nullptr : fwdNameC, fwdOrd, fwdIsOrd, targetIs32, depth + 1);
                    if (fwdAddr) return fwdAddr;
                    qDebug() << "[ManualMap] Forwarder resolve failed for" << QString::fromStdString(fwd);
                    return nullptr;
                }
            }
        }
    }
    ULONGLONG remoteAddr = remoteBase + funcRVA;
    qDebug() << "[ManualMap] Cross-arch fallback resolved" << dllName << (isOrdinal ? QString::number(ordinal) : QString::fromLatin1(funcName ? funcName : "")) << " remoteBase=0x" << Qt::hex << remoteBase << " rva=0x" << funcRVA << " addr=0x" << remoteAddr << Qt::dec;
    // For 32-bit target, truncate to 32-bit
    if (targetIs32) return reinterpret_cast<FARPROC>(static_cast<ULONG_PTR>(remoteAddr & 0xFFFFFFFFULL));
    return reinterpret_cast<FARPROC>(static_cast<ULONG_PTR>(remoteAddr));
}



// Executes one 32-bit __stdcall call func(args[0..nArgs)) inside a WOW64
// target by briefly borrowing one of its own 32-bit threads, without any
// code-segment switching:
//
//   1. Suspend a target thread and save its WOW64 context.
//   2. Point its Eip at a plain 32-bit shell (pushad, pushfd, push args in
//      reverse, mov eax, func, call eax, store result, popfd, popad,
//      restore Esp, ret to the saved Eip) with a fresh 32-bit stack.
//   3. Resume: the thread runs the call, writes the result flag, then flows
//      back into its original code as if nothing happened.
//   4. Poll the flag; on timeout restore the saved context.
//
// This is used when a 64-bit injector drives a 32-bit target, where a
// CreateRemoteThread-started (64-bit) thread would misdeliver 32-bit
// stdcall arguments (pushes land in 8-byte slots, so fdwReason arrives as
// garbage and DllMain silently no-ops while still exiting TRUE).
static bool call32ViaThreadHijack(HANDLE hProcess, DWORD pid, DWORD func32,
                                  const DWORD *args, int nArgs, DWORD timeoutMs,
                                  DWORD *outResult, const char *tag)
{
    // 1. Pick a target thread.
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return false;
    DWORD targetTid = 0;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(hSnap, &te)) do {
        if (te.th32OwnerProcessID == pid && te.th32ThreadID != GetCurrentThreadId()) {
            targetTid = te.th32ThreadID;
            break;
        }
    } while (Thread32Next(hSnap, &te));
    CloseHandle(hSnap);
    if (!targetTid) {
        qDebug() << "[ManualMap] Hijack" << tag << ": no thread found in pid=" << pid;
        return false;
    }
    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                                THREAD_SET_CONTEXT, FALSE, targetTid);
    if (!hThread) {
        qDebug() << "[ManualMap] Hijack" << tag << ": OpenThread failed err=" << GetLastError();
        return false;
    }

    // 2. Suspend and save the 32-bit context.
    if (SuspendThread(hThread) == (DWORD)-1) {
        qDebug() << "[ManualMap] Hijack" << tag << ": SuspendThread failed err=" << GetLastError();
        CloseHandle(hThread);
        return false;
    }
    WOW64_CONTEXT saved{};
    saved.ContextFlags = WOW64_CONTEXT_FULL;
    if (!Wow64GetThreadContext(hThread, &saved)) {
        qDebug() << "[ManualMap] Hijack" << tag << ": Wow64GetThreadContext failed err=" << GetLastError();
        ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }

    // 3. Allocate stack + shell (single RWX block keeps addresses < 4GB).
    // A full 1MB stack: deep callee chains (e.g. LoadLibrary with driver
    // init) must never run off the borrowed stack.
    // NOTE: the flag area must start AFTER the whole shell (~160 bytes).
    // It previously sat at +128 inside the shell: the first poll then read
    // shell code bytes as an instant bogus "result" while the call had not
    // run yet, and the block was freed from under the running thread.
    static const SIZE_T kStackSize = 1024 * 1024;
    static const SIZE_T kShellOff = kStackSize;
    static const SIZE_T kFlagOff = kStackSize + 512;
    static const SIZE_T kTotal = kStackSize + 1024;
    BYTE *remote = reinterpret_cast<BYTE*>(VirtualAllocEx(
        hProcess, nullptr, kTotal, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!remote) {
        WOW64_CONTEXT restore = saved;
        Wow64SetThreadContext(hThread, &restore);
        ResumeThread(hThread);
        CloseHandle(hThread);
        return false;
    }
    const DWORD remote32 = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(remote));
    const DWORD shell32 = remote32 + static_cast<DWORD>(kShellOff);
    const DWORD flag32 = remote32 + static_cast<DWORD>(kFlagOff);
    const DWORD stackTop = remote32 + static_cast<DWORD>(kStackSize - 16);
    // Shell: pushad; pushfd; capture TEB + point it at the borrowed stack;
    //        push args[n-1..0]; mov eax, func; call eax; mov [flag], eax;
    //        restore TEB; popfd; popad; mov esp, savedEsp; push savedEip;
    //        ret. Built byte-exact (no patch math to get wrong).
    // The TEB switch matters: on syscall return the kernel validates ESP
    // against the TEB stack limits (FAST_FAIL_INCORRECT_STACK otherwise),
    // which kills borrowed-thread calls that enter the kernel (LoadLibrary,
    // GDI, ...). Flag layout: +0 result, +4 origBase, +8 origLimit,
    // +12 origDealloc, +16 tebAddr.
    if (nArgs < 0 || nArgs > 8) return false;
    const DWORD tebFlag = flag32;
    const DWORD myBase = remote32 + static_cast<DWORD>(kTotal);
    const DWORD myLimit = remote32;
    std::vector<BYTE> shell;
    shell.reserve(96 + size_t(nArgs) * 5);
    auto pushU32 = [&shell](DWORD v) {
        shell.push_back(0x68);
        for (int i = 0; i < 4; ++i) shell.push_back(BYTE((v >> (8 * i)) & 0xFF));
    };
    auto movEaxU32 = [&shell](DWORD v) {
        shell.push_back(0xB8);
        for (int i = 0; i < 4; ++i) shell.push_back(BYTE((v >> (8 * i)) & 0xFF));
    };
    auto movEaxFs = [&shell](DWORD off) {
        shell.push_back(0x64); shell.push_back(0xA1);
        for (int i = 0; i < 4; ++i) shell.push_back(BYTE((off >> (8 * i)) & 0xFF));
    };
    auto movFsEax = [&shell](DWORD off) {
        shell.push_back(0x64); shell.push_back(0xA3);
        for (int i = 0; i < 4; ++i) shell.push_back(BYTE((off >> (8 * i)) & 0xFF));
    };
    auto movMemEax = [&shell](DWORD addr) {
        shell.push_back(0xA3);
        for (int i = 0; i < 4; ++i) shell.push_back(BYTE((addr >> (8 * i)) & 0xFF));
    };
    shell.push_back(0x60);                               // pushad
    shell.push_back(0x9C);                               // pushfd
    movEaxFs(0x18);                                      // eax = TEB (FS:[Self])
    movMemEax(tebFlag + 16);                             // save TEB address
    movEaxFs(0x04);                                      // eax = StackBase
    movMemEax(tebFlag + 4);                              // save orig base
    movEaxFs(0x08);                                      // eax = StackLimit
    movMemEax(tebFlag + 8);                              // save orig limit
    movEaxFs(0x0E0C);                                    // eax = DeallocationStack
    movMemEax(tebFlag + 12);                             // save orig dealloc
    movEaxU32(myBase);
    movFsEax(0x04);                                      // StackBase = borrowed top
    movEaxU32(myLimit);
    movFsEax(0x08);                                      // StackLimit = borrowed bottom
    movEaxU32(remote32);
    movFsEax(0x0E0C);                                    // DeallocationStack = block
    for (int i = nArgs - 1; i >= 0; --i) pushU32(args ? args[i] : 0);
    movEaxU32(func32);
    shell.push_back(0xFF); shell.push_back(0xD0);        // call eax
    movMemEax(flag32);                                   // [flag] = result
    movEaxU32(tebFlag + 4); shell.push_back(0x8B); shell.push_back(0x00);
    movFsEax(0x04);                                      // restore StackBase
    movEaxU32(tebFlag + 8); shell.push_back(0x8B); shell.push_back(0x00);
    movFsEax(0x08);                                      // restore StackLimit
    movEaxU32(tebFlag + 12); shell.push_back(0x8B); shell.push_back(0x00);
    movFsEax(0x0E0C);                                    // restore DeallocationStack
    shell.push_back(0x9D);                               // popfd
    shell.push_back(0x61);                               // popad
    shell.push_back(0xBC);                               // mov esp, savedEsp
    DWORD espV = saved.Esp;
    for (int i = 0; i < 4; ++i) shell.push_back(BYTE((espV >> (8 * i)) & 0xFF));
    shell.push_back(0x68);                               // push savedEip
    DWORD eipV = saved.Eip;
    for (int i = 0; i < 4; ++i) shell.push_back(BYTE((eipV >> (8 * i)) & 0xFF));
    shell.push_back(0xC3);                               // ret -> original code
    const DWORD pending = 0xFFFFFFFF;
    if (!WriteProcessMemory(hProcess, remote + kFlagOff, &pending, sizeof(pending), nullptr) ||
        !WriteProcessMemory(hProcess, remote + kShellOff, shell.data(), shell.size(), nullptr)) {
        WOW64_CONTEXT restore = saved;
        Wow64SetThreadContext(hThread, &restore);
        ResumeThread(hThread);
        VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
        CloseHandle(hThread);
        return false;
    }
    qDebug() << "[ManualMap] Hijack" << tag << "tid=" << targetTid
             << "shell=0x" << Qt::hex << shell32 << "flag=0x" << flag32 << Qt::dec;

    // 4. Divert, resume, poll.
    WOW64_CONTEXT divert = saved;
    divert.Eip = shell32;
    divert.Esp = stackTop;
    if (!Wow64SetThreadContext(hThread, &divert)) {
        ResumeThread(hThread);
        VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
        CloseHandle(hThread);
        return false;
    }
    ResumeThread(hThread);
    DWORD result = pending;
    const DWORD waitedStep = 50;
    DWORD waited = 0;
    while (waited < timeoutMs) {
        Sleep(waitedStep);
        waited += waitedStep;
        DWORD current = pending;
        SIZE_T done = 0;
        if (ReadProcessMemory(hProcess, remote + kFlagOff, &current, sizeof(current), &done) &&
            done == sizeof(current) && current != pending) {
            result = current;
            break;
        }
    }
    if (outResult) *outResult = result;
    qDebug() << "[ManualMap] Hijack" << tag << "result=0x" << Qt::hex << result << Qt::dec;
    VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);
    CloseHandle(hThread);
    if (result == pending) {
        // Timed out: try to put the borrowed thread back where it was,
        // including its TEB stack limits (the shell may have switched them
        // before hanging inside the call).
        HANDLE hReopen = OpenThread(THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT, FALSE, targetTid);
        if (hReopen) {
            SuspendThread(hReopen);
            DWORD tebAddr = 0;
            SIZE_T tebDone = 0;
            DWORD captured[3] = { 0, 0, 0 };
            SIZE_T capDone = 0;
            if (ReadProcessMemory(hProcess, remote + kFlagOff + 16, &tebAddr,
                                  sizeof(tebAddr), &tebDone) &&
                tebDone == sizeof(tebAddr) && tebAddr != 0 &&
                ReadProcessMemory(hProcess, remote + kFlagOff + 4, captured,
                                  sizeof(captured), &capDone) &&
                capDone == sizeof(captured) && captured[0] != 0) {
                const DWORD tebOff[3] = { 4, 8, 0x0E0C };
                for (int i = 0; i < 3; ++i) {
                    WriteProcessMemory(hProcess,
                        reinterpret_cast<BYTE*>(static_cast<ULONG_PTR>(tebAddr)) + tebOff[i],
                        &captured[i], sizeof(DWORD), nullptr);
                }
            }
            WOW64_CONTEXT restore = saved;
            Wow64SetThreadContext(hReopen, &restore);
            ResumeThread(hReopen);
            CloseHandle(hReopen);
        }
        return false;
    }
    return true;
}

bool InjectorEngine::injectManualMap(DWORD pid, const QString& dllPath, DWORD timeoutMs)
{
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | SYNCHRONIZE, FALSE, pid);
    if (!hProcess) {
        DWORD err = GetLastError();
        qDebug() << "[ManualMap] OpenProcess failed pid=" << pid << " err=" << err;
        return false;
    }

    // A 64-bit injector's CreateRemoteThread into a WOW64 target starts a
    // 64-bit thread. Raw 32-bit entry shellcode there silently misdelivers
    // arguments (fdwReason != DLL_PROCESS_ATTACH) while still exiting TRUE.
    // Detect that case once and route 32-bit calls through thread hijack.
    BOOL targetWow64 = FALSE;
    IsWow64Process(hProcess, &targetWow64);
    const bool needWow64Gate = (sizeof(void*) == 8) && (targetWow64 == TRUE);
    if (needWow64Gate)
        qDebug() << "[ManualMap] WOW64 cross-arch target: 32-bit calls will use Heaven's Gate";

    // 1. Dosyayi ac ve map et (dogru yontem: CreateFile + CreateFileMapping)
    HANDLE hFile = CreateFileW(reinterpret_cast<LPCWSTR>(dllPath.utf16()), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) { CloseHandle(hProcess); return false; }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart == 0) { CloseHandle(hFile); CloseHandle(hProcess); return false; }

    HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMapping) { CloseHandle(hFile); CloseHandle(hProcess); return false; }

    void* pFileView = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pFileView) { CloseHandle(hMapping); CloseHandle(hFile); CloseHandle(hProcess); return false; }

    auto cleanupFile = [&]() {
        UnmapViewOfFile(pFileView);
        CloseHandle(hMapping);
        CloseHandle(hFile);
    };

    auto* fileBase = reinterpret_cast<BYTE*>(pFileView);

    if (fileSize.QuadPart < sizeof(IMAGE_DOS_HEADER)) {
        cleanupFile();
        CloseHandle(hProcess);
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }

    auto* pDos = reinterpret_cast<PIMAGE_DOS_HEADER>(fileBase);

    if (pDos->e_magic != IMAGE_DOS_SIGNATURE ||
        pDos->e_lfanew <= 0 ||
        static_cast<ULONGLONG>(pDos->e_lfanew) + sizeof(DWORD) +
                sizeof(IMAGE_FILE_HEADER) + sizeof(WORD) >
            static_cast<ULONGLONG>(fileSize.QuadPart))
    {
        cleanupFile();
        CloseHandle(hProcess);
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return false;
    }

    BYTE* ntBase = fileBase + pDos->e_lfanew;

    DWORD signature = *reinterpret_cast<DWORD*>(ntBase);

    if (signature != IMAGE_NT_SIGNATURE) {
        cleanupFile();
        CloseHandle(hProcess);
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return false;
    }

    auto* fileHeader =
        reinterpret_cast<PIMAGE_FILE_HEADER>(
            ntBase + sizeof(DWORD));

    BYTE* optionalBase =
        ntBase +
        sizeof(DWORD) +
        sizeof(IMAGE_FILE_HEADER);

    WORD optionalMagic =
        *reinterpret_cast<WORD*>(optionalBase);

    const WORD machine = fileHeader->Machine;

    bool dllIs32 = false;
    bool dllIs64 = false;

    DWORD imageSize = 0;
    DWORD headersSize = 0;
    DWORD entryRVA = 0;

    ULONGLONG preferredBase = 0;

    DWORD relocRVA = 0;
    DWORD relocSize = 0;

    DWORD importRVA = 0;
    DWORD importSize = 0;

    DWORD tlsRVA = 0;
    DWORD tlsSize = 0;

    if (optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        if (fileHeader->SizeOfOptionalHeader <
            sizeof(IMAGE_OPTIONAL_HEADER32))
        {
            cleanupFile();
            CloseHandle(hProcess);
            SetLastError(ERROR_INVALID_DATA);
            return false;
        }

        auto* opt =
            reinterpret_cast<PIMAGE_OPTIONAL_HEADER32>(
                optionalBase);

        dllIs32 = true;

        imageSize    = opt->SizeOfImage;
        headersSize  = opt->SizeOfHeaders;
        entryRVA     = opt->AddressOfEntryPoint;
        preferredBase = opt->ImageBase;

        relocRVA =
            opt->DataDirectory[
                   IMAGE_DIRECTORY_ENTRY_BASERELOC
        ].VirtualAddress;

        relocSize =
            opt->DataDirectory[
                   IMAGE_DIRECTORY_ENTRY_BASERELOC
        ].Size;

        importRVA =
            opt->DataDirectory[
                   IMAGE_DIRECTORY_ENTRY_IMPORT
        ].VirtualAddress;

        importSize =
            opt->DataDirectory[
                   IMAGE_DIRECTORY_ENTRY_IMPORT
        ].Size;

        tlsRVA =
            opt->DataDirectory[
                   IMAGE_DIRECTORY_ENTRY_TLS
        ].VirtualAddress;

        tlsSize =
            opt->DataDirectory[
                   IMAGE_DIRECTORY_ENTRY_TLS
        ].Size;
    }
    else if (optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        if (fileHeader->SizeOfOptionalHeader <
            sizeof(IMAGE_OPTIONAL_HEADER64))
        {
            cleanupFile();
            CloseHandle(hProcess);
            SetLastError(ERROR_INVALID_DATA);
            return false;
        }

        auto* opt =
            reinterpret_cast<PIMAGE_OPTIONAL_HEADER64>(
                optionalBase);

        dllIs64 = true;

        imageSize    = opt->SizeOfImage;
        headersSize  = opt->SizeOfHeaders;
        entryRVA     = opt->AddressOfEntryPoint;
        preferredBase = opt->ImageBase;

        relocRVA =
            opt->DataDirectory[
                   IMAGE_DIRECTORY_ENTRY_BASERELOC
        ].VirtualAddress;

        relocSize =
            opt->DataDirectory[
                   IMAGE_DIRECTORY_ENTRY_BASERELOC
        ].Size;

        importRVA =
            opt->DataDirectory[
                   IMAGE_DIRECTORY_ENTRY_IMPORT
        ].VirtualAddress;

        importSize =
            opt->DataDirectory[
                   IMAGE_DIRECTORY_ENTRY_IMPORT
        ].Size;

        tlsRVA =
            opt->DataDirectory[
                   IMAGE_DIRECTORY_ENTRY_TLS
        ].VirtualAddress;

        tlsSize =
            opt->DataDirectory[
                   IMAGE_DIRECTORY_ENTRY_TLS
        ].Size;
    }
    else
    {
        cleanupFile();
        CloseHandle(hProcess);
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return false;
    }

    if ((dllIs32 && machine != IMAGE_FILE_MACHINE_I386) ||
        (dllIs64 &&
         machine != IMAGE_FILE_MACHINE_AMD64 &&
         machine != IMAGE_FILE_MACHINE_ARM64))
    {
        cleanupFile();
        CloseHandle(hProcess);
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return false;
    }

    if (imageSize == 0 ||
        headersSize == 0 ||
        headersSize > imageSize)
    {
        cleanupFile();
        CloseHandle(hProcess);
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }

    // Hedef mimari kontrolu
    QString targetArch = getProcessArchitecture(pid);

    if ((dllIs64 &&
         targetArch.compare(QStringLiteral("x86"),
                            Qt::CaseInsensitive) == 0) ||
        (dllIs32 &&
         targetArch.compare(QStringLiteral("x64"),
                            Qt::CaseInsensitive) == 0))
    {
        cleanupFile();
        CloseHandle(hProcess);
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return false;
    }

    // Section header PE32 ve PE32+ icin FileHeader +
    // SizeOfOptionalHeader sonrasindadir.
    auto* pSections =
        reinterpret_cast<PIMAGE_SECTION_HEADER>(
            optionalBase +
            fileHeader->SizeOfOptionalHeader);

    const WORD numSections =
        fileHeader->NumberOfSections;

    // Section tablosunun da dosya icinde oldugunu kontrol et.
    const ULONGLONG sectionTableEnd =
        static_cast<ULONGLONG>(
            reinterpret_cast<BYTE*>(pSections) - fileBase) +
        static_cast<ULONGLONG>(numSections) *
            sizeof(IMAGE_SECTION_HEADER);

    if (sectionTableEnd >
        static_cast<ULONGLONG>(fileSize.QuadPart))
    {
        cleanupFile();
        CloseHandle(hProcess);
        SetLastError(ERROR_INVALID_DATA);
        return false;
    }

    qDebug()
        << "PE type:"
        << (dllIs64 ? "PE32+" : "PE32")
        << "| Machine:"
        << QStringLiteral("0x%1").arg(machine, 4, 16, QLatin1Char('0'))
        << "| ImageBase:"
        << QStringLiteral("0x%1").arg(preferredBase, 0, 16)
        << "| SizeOfImage:"
        << QStringLiteral("0x%1").arg(imageSize, 0, 16)
        << "| Headers:"
        << QStringLiteral("0x%1").arg(headersSize, 0, 16)
        << "| Reloc RVA:"
        << QStringLiteral("0x%1").arg(relocRVA, 0, 16)
        << "| Reloc Size:"
        << QStringLiteral("0x%1").arg(relocSize, 0, 16)
        << "| Import RVA:"
        << QStringLiteral("0x%1").arg(importRVA, 0, 16)
        << "| Import Size:"
        << QStringLiteral("0x%1").arg(importSize, 0, 16);
    // 3. Lokal imaj buffer olustur (SizeOfImage kadar zeroed)
    std::vector<BYTE> localImage(imageSize, 0);
    // Headerlari kopyala
    memcpy(localImage.data(), pFileView, std::min<DWORD>(headersSize, static_cast<DWORD>(fileSize.QuadPart)));
    // Sectionlari kopyala: VirtualAddress -> raw data
    for (WORD i = 0; i < numSections; ++i) {
        const auto &sec = pSections[i];
        if (sec.SizeOfRawData == 0) continue;
        if (sec.PointerToRawData + sec.SizeOfRawData > static_cast<DWORD>(fileSize.QuadPart)) continue;
        if (sec.VirtualAddress + sec.SizeOfRawData > imageSize) continue;
        memcpy(localImage.data() + sec.VirtualAddress,
               reinterpret_cast<BYTE*>(pFileView) + sec.PointerToRawData,
               sec.SizeOfRawData);
    }

    // PE header pointer'i lokal imaj uzerinden yeniden almaya GEREK YOK.
    // HATA: PIMAGE_NT_HEADERS / IMAGE_FIRST_SECTION derleme mimarisine baglidir.
    // x64 derlenen injector x86 DLL icin OptionalHeader'i yanlis okur.
    // Zaten yukaridaki dogru parser relocRVA/relocSize/importRVA/importSize'i
    // cikardi; relocation ve import asagida direkt o degerlerle yapilir.
    // Section tablosu icin de fileBase offsetinden hesap yapilir.
    const SIZE_T sectionTableOffset = static_cast<SIZE_T>(reinterpret_cast<BYTE*>(pSections) - fileBase);
    auto *pLocalSections = reinterpret_cast<PIMAGE_SECTION_HEADER>(localImage.data() + sectionTableOffset);

    // 4. Hedef surecte bellek ayir (once preferred base dene, sonra hedefe yakin dene - MinHook far JMP icin)
    LPVOID pRemoteBase = VirtualAllocEx(hProcess, reinterpret_cast<LPVOID>(preferredBase), imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pRemoteBase) {
        DWORD err1 = GetLastError();
        qDebug() << "[ManualMap] VirtualAllocEx at preferred 0x" << Qt::hex << preferredBase << " failed err=" << err1 << Qt::dec << " trying near target";
        // MinHook far detour (2GB) icin hedef modullere yakin allocate dene
        bool isTarget32 = (targetArch.compare(QStringLiteral("x86"), Qt::CaseInsensitive) == 0);
        const char* nearMods[] = {"dxgi.dll", "d3d11.dll", "d3d9.dll", "opengl32.dll", "kernel32.dll", nullptr};
        for (int ni=0; nearMods[ni] && !pRemoteBase; ++ni) {
            ULONGLONG modBase = getRemoteModuleBase(pid, QString::fromLatin1(nearMods[ni]).toLower(), isTarget32);
            if (!modBase) continue;
            for (int attempt=0; attempt<4 && !pRemoteBase; ++attempt) {
                ULONGLONG tryAddr = modBase - (0x200000ULL * (attempt+1)) - (imageSize * attempt);
                // 2GB icinde kal
                if (tryAddr < 0x10000) continue;
                pRemoteBase = VirtualAllocEx(hProcess, reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(tryAddr)), imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if (pRemoteBase) qDebug() << "[ManualMap] Allocated near" << nearMods[ni] << "at 0x" << Qt::hex << reinterpret_cast<quintptr>(pRemoteBase) << Qt::dec;
            }
        }
        if (!pRemoteBase) {
            pRemoteBase = VirtualAllocEx(hProcess, nullptr, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        }
        if (!pRemoteBase) {
            DWORD err2 = GetLastError();
            qDebug() << "[ManualMap] VirtualAllocEx anywhere failed err=" << err2 << " size=0x" << Qt::hex << imageSize << Qt::dec;
            cleanupFile(); CloseHandle(hProcess);
            SetLastError(err2);
            return false;
        }
    } else {
        // Preferred allocate basarili ama hedefe cok uzaksa (MinHook 2GB) yakin yere tasimayi dene - ImGui icin
        bool isTarget32Far = (targetArch.compare(QStringLiteral("x86"), Qt::CaseInsensitive) == 0);
        // Sadece x64 hedefte far kontrolu yap (x64 MinHook JMP_REL 2GB siniri)
        if (!isTarget32Far) {
            ULONGLONG dxgiBase = getRemoteModuleBase(pid, QStringLiteral("dxgi.dll"), false);
            if (dxgiBase) {
                long long dist = (long long)reinterpret_cast<ULONG_PTR>(pRemoteBase) - (long long)dxgiBase;
                if (dist < -0x7fffffffLL || dist > 0x7fffffffLL) {
                    qDebug() << "[ManualMap] Preferred base far from dxgi (dist" << dist << ") trying near alloc";
                    LPVOID pNear = nullptr;
                    for (int a=0; a<4 && !pNear; ++a) {
                        ULONGLONG tryAddr = dxgiBase - 0x200000ULL * (a+1);
                        pNear = VirtualAllocEx(hProcess, reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(tryAddr)), imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                    }
                    if (pNear) {
                        // Eski allocation'i birak, yakin olani kullan (reloc tekrar hesaplanacak)
                        VirtualFreeEx(hProcess, pRemoteBase, 0, MEM_RELEASE);
                        pRemoteBase = pNear;
                        qDebug() << "[ManualMap] Re-allocated near dxgi at 0x" << Qt::hex << reinterpret_cast<quintptr>(pRemoteBase) << Qt::dec;
                    }
                }
            }
        }
    }
    qDebug() << "[ManualMap] Allocated remote base 0x" << Qt::hex << reinterpret_cast<quintptr>(pRemoteBase) << " delta=0x" << (qint64)((qint64)reinterpret_cast<quintptr>(pRemoteBase) - (qint64)preferredBase) << Qt::dec;

    const ULONGLONG remoteBaseAddr = reinterpret_cast<ULONGLONG>(pRemoteBase);
    const long long delta = static_cast<long long>(remoteBaseAddr - preferredBase);

    // 5. Relocation uygula (lokal imaj uzerinde) - ARCH INDEPENDENT
    // HATA DUZELTMESI: pLocalNt->OptionalHeader.DataDirectory kullanma!
    // Direct relocRVA / relocSize kullan (yukari dogru parse edildi).
    if (delta != 0) {
        if (relocSize > 0 && relocRVA != 0 && relocRVA < imageSize &&
            static_cast<ULONGLONG>(relocRVA) + relocSize <= imageSize) {
            auto *pReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(localImage.data() + relocRVA);
            DWORD processed = 0;
            while (processed < relocSize && reinterpret_cast<BYTE*>(pReloc) < localImage.data() + imageSize) {
                if (pReloc->SizeOfBlock == 0) break;
                if (pReloc->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;
                if (pReloc->VirtualAddress >= imageSize) break;
                if (processed + pReloc->SizeOfBlock > relocSize) break;
                DWORD count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* entries = reinterpret_cast<WORD*>(reinterpret_cast<BYTE*>(pReloc) + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD j = 0; j < count; ++j) {
                    WORD type = entries[j] >> 12;
                    WORD offset = entries[j] & 0xFFF;
                    if (pReloc->VirtualAddress + offset >= imageSize) continue;
                    BYTE* patchAddr = localImage.data() + pReloc->VirtualAddress + offset;
                    if (type == IMAGE_REL_BASED_HIGHLOW) {
                        if (patchAddr + sizeof(DWORD) > localImage.data() + imageSize) continue;
                        if (dllIs32) {
                            *reinterpret_cast<DWORD*>(patchAddr) += static_cast<DWORD>(delta);
                        } else {
                            // PE32+ icinde HIGHLOW olmamali ama tolerans icin destek
                            *reinterpret_cast<DWORD*>(patchAddr) += static_cast<DWORD>(delta);
                        }
                    } else if (type == IMAGE_REL_BASED_DIR64) {
                        if (patchAddr + sizeof(ULONGLONG) > localImage.data() + imageSize) continue;
                        *reinterpret_cast<ULONGLONG*>(patchAddr) += static_cast<ULONGLONG>(delta);
                    } else if (type == IMAGE_REL_BASED_ABSOLUTE) {
                        // padding - no patch
                    } else {
                        // Desteklenmeyen reloc tipi: sadece bilinenleri uygula
                    }
                }
                processed += pReloc->SizeOfBlock;
                pReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<BYTE*>(pReloc) + pReloc->SizeOfBlock);
            }
        } else {
            // Reloc yok ama base farkli -> fail (ASLR'li DLL'lerde reloc olmali)
            if (delta != 0) {
                VirtualFreeEx(hProcess, pRemoteBase, 0, MEM_RELEASE);
                cleanupFile(); CloseHandle(hProcess);
                SetLastError(ERROR_INVALID_DATA);
                return false;
            }
        }
    }

    // 6. Lokal imaji hedef surece yaz
    if (!WriteProcessMemory(hProcess, pRemoteBase, localImage.data(), imageSize, nullptr)) {
        DWORD err = GetLastError();
        qDebug() << "[ManualMap] WriteProcessMemory failed size=0x" << Qt::hex << imageSize << " err=" << err << Qt::dec;
        VirtualFreeEx(hProcess, pRemoteBase, 0, MEM_RELEASE);
        cleanupFile(); CloseHandle(hProcess);
        SetLastError(err);
        return false;
    } else {
        qDebug() << "[ManualMap] WriteProcessMemory OK size=0x" << Qt::hex << imageSize << Qt::dec;
    }

    // 7. Import cozumle - ARCH INDEPENDENT
    // HATA DUZELTMESI: PIMAGE_THUNK_DATA / IMAGE_ORDINAL_FLAG derleme mimarisine baglidir.
    // x86 DLL icin IMAGE_THUNK_DATA32 + IMAGE_ORDINAL_FLAG32, x64 icin _64 kullan.
    // Ayrica IAT stride: x86'da 4 byte, x64'te 8 byte.
    if (importSize > 0 && importRVA != 0 && importRVA < imageSize &&
        static_cast<ULONGLONG>(importRVA) + importSize <= imageSize) {
        auto *pImportDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(localImage.data() + importRVA);
        // Import descriptorlari hedef bellekte de guncel olmali (IAT yazilacak)
        // importSize icinde kac descriptor var hesapla
        size_t maxDescs = importSize / sizeof(IMAGE_IMPORT_DESCRIPTOR);
        for (size_t d = 0; d < maxDescs; ++d) {
            if (pImportDesc[d].Name == 0 && pImportDesc[d].FirstThunk == 0) break;
            auto &desc = pImportDesc[d];
            if (desc.Name == 0 || desc.Name >= imageSize) continue;
            if (desc.Name + 1 >= imageSize) continue;
            const char* dllName = reinterpret_cast<char*>(localImage.data() + desc.Name);
            // Guvenlik: dllName null-terminated mi?
            size_t maxNameLen = imageSize - desc.Name;
            if (strnlen(dllName, maxNameLen) == maxNameLen) continue;
            // DLL'i yukle - cross-arch (x64->x86) için local LoadLibrary YAPMA, remote resolver kullan
            HMODULE hMod = nullptr;
#ifdef _WIN64
            if (dllIs32) {
                // x86 DLL from x64 injector: don't use local 64-bit module, remote fallback will handle
                qDebug() << "[ManualMap] Cross-arch import DLL:" << dllName << " - skipping local LoadLibrary, using remote resolver";
                // Check if remote module exists (for logging), but don't fail if not - it will be loaded per-function
                ULONGLONG remoteChk = getRemoteModuleBase(pid, QString::fromLatin1(dllName).toLower(), true);
                if (remoteChk) qDebug() << "[ManualMap] Remote DLL already loaded base=0x" << Qt::hex << remoteChk << Qt::dec;
                else qDebug() << "[ManualMap] Remote DLL not yet loaded, will be loaded on demand";
                hMod = reinterpret_cast<HMODULE>(1); // dummy non-null to pass check, per-function will use remote
            } else
#endif
            {
                hMod = GetModuleHandleA(dllName);
                if (!hMod) hMod = LoadLibraryA(dllName);
                if (!hMod) {
                    DWORD err = GetLastError();
                    qDebug() << "[ManualMap] LoadLibrary failed for import DLL:" << dllName << " err=" << err;
                    QString dllLower = QString::fromLatin1(dllName).toLower();
                    if (dllLower.contains(QStringLiteral("vcruntime140d")) || dllLower.contains(QStringLiteral("ucrtbased")) || dllLower.contains(QStringLiteral("msvcp140d"))) {
                        qDebug() << "[ManualMap] HINT: This DLL imports DEBUG CRT (" << dllName << "). Release build kullanin: testdll1/Release/testdll1.dll";
                    }
                    VirtualFreeEx(hProcess, pRemoteBase, 0, MEM_RELEASE);
                    cleanupFile(); CloseHandle(hProcess);
                    SetLastError(err ? err : ERROR_MOD_NOT_FOUND);
                    return false;
                } else {
                    qDebug() << "[ManualMap] Resolved import DLL:" << dllName << " hMod=" << Qt::hex << reinterpret_cast<quintptr>(hMod);
                }
            }

            // Thunk'lar
            DWORD thunkRVA = desc.OriginalFirstThunk ? desc.OriginalFirstThunk : desc.FirstThunk;
            DWORD iatRVA = desc.FirstThunk;
            if (thunkRVA >= imageSize || iatRVA >= imageSize) continue;

            // IAT hedefte
            LPVOID pRemoteIAT = reinterpret_cast<BYTE*>(pRemoteBase) + iatRVA;

            if (dllIs32) {
                auto *pOrigThunk32 = reinterpret_cast<PIMAGE_THUNK_DATA32>(localImage.data() + thunkRVA);
                for (int idx = 0; pOrigThunk32[idx].u1.AddressOfData != 0; ++idx) {
                    // Bounds check: bir sonraki thunk IAT icinde mi?
                    if (iatRVA + idx * sizeof(DWORD) + sizeof(DWORD) > imageSize) break;
                    if (thunkRVA + idx * sizeof(IMAGE_THUNK_DATA32) + sizeof(IMAGE_THUNK_DATA32) > imageSize) break;
                    FARPROC funcAddr = nullptr;
                    const char* funcNameDbg = nullptr;
                    WORD ordinalDbg = 0;
                    bool isOrdinalDbg = false;
                    if (pOrigThunk32[idx].u1.Ordinal & IMAGE_ORDINAL_FLAG32) {
                        WORD ordinal = static_cast<WORD>(pOrigThunk32[idx].u1.Ordinal & 0xFFFF);
                        ordinalDbg = ordinal; isOrdinalDbg = true;
                    } else {
                        DWORD addrOfData = pOrigThunk32[idx].u1.AddressOfData;
                        if (addrOfData >= imageSize) continue;
                        if (addrOfData + sizeof(WORD) >= imageSize) continue;
                        auto *pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(localImage.data() + addrOfData);
                        size_t maxByName = imageSize - addrOfData - sizeof(WORD);
                        if (strnlen(pImportByName->Name, maxByName) == maxByName) continue;
                        funcNameDbg = pImportByName->Name;
                    }
#ifdef _WIN64
                    // Cross-arch: x64 injector -> x86 target must use remote resolver, local 64-bit GetProcAddress gives wrong truncated address or misses x86-only exports
                    if (dllIs32) {
                        funcAddr = getRemoteProcAddressFallback(hProcess, pid, dllName, funcNameDbg, ordinalDbg, isOrdinalDbg, true);
                        if (funcAddr) {
                            qDebug() << "[ManualMap] Cross-arch remote OK for" << dllName << (isOrdinalDbg ? QString::number(ordinalDbg) : QString(funcNameDbg ? funcNameDbg : "")) << "->" << Qt::hex << reinterpret_cast<quintptr>(funcAddr) << Qt::dec;
                        } else {
                            qDebug() << "[ManualMap] Cross-arch remote FAILED for" << dllName << (isOrdinalDbg ? QString::number(ordinalDbg) : QString(funcNameDbg ? funcNameDbg : "")) << " trying local";
                        }
                    }
                    if (!funcAddr) {
#endif
                        if (isOrdinalDbg) {
                            funcAddr = GetProcAddress(hMod, reinterpret_cast<LPCSTR>(static_cast<ULONG_PTR>(ordinalDbg)));
                        } else {
                            funcAddr = GetProcAddress(hMod, funcNameDbg);
                        }
#ifdef _WIN64
                    }
#endif
                    if (!funcAddr) {
                        DWORD err = GetLastError();
                        if (isOrdinalDbg) {
                            qDebug() << "[ManualMap] GetProcAddress FAILED (x86) DLL:" << dllName << " ordinal:" << ordinalDbg << " err=" << err;
                        } else {
                            qDebug() << "[ManualMap] GetProcAddress FAILED (x86) DLL:" << dllName << " func:" << (funcNameDbg ? funcNameDbg : "<unknown>") << " err=" << err;
                        }
#ifdef _WIN64
                        if (dllIs32 && !funcAddr) {
                            // Second try remote (for forwarder or if first remote failed due to not yet loaded)
                            FARPROC fallback2 = getRemoteProcAddressFallback(hProcess, pid, dllName, funcNameDbg, ordinalDbg, isOrdinalDbg, true);
                            if (fallback2) {
                                funcAddr = fallback2;
                                qDebug() << "[ManualMap] Second fallback SUCCESS addr=" << Qt::hex << reinterpret_cast<quintptr>(fallback2) << Qt::dec;
                            } else {
                                qDebug() << "[ManualMap] Both remote and local FAILED for" << dllName << (isOrdinalDbg ? QString::number(ordinalDbg) : QString(funcNameDbg ? funcNameDbg : ""));
                                SetLastError(err ? err : ERROR_PROC_NOT_FOUND);
                                VirtualFreeEx(hProcess, pRemoteBase, 0, MEM_RELEASE);
                                cleanupFile(); CloseHandle(hProcess);
                                return false;
                            }
                        } else if (!dllIs32) {
                            SetLastError(err ? err : ERROR_PROC_NOT_FOUND);
                            VirtualFreeEx(hProcess, pRemoteBase, 0, MEM_RELEASE);
                            cleanupFile(); CloseHandle(hProcess);
                            return false;
                        }
                        if (!funcAddr) {
                            SetLastError(err ? err : ERROR_PROC_NOT_FOUND);
                            VirtualFreeEx(hProcess, pRemoteBase, 0, MEM_RELEASE);
                            cleanupFile(); CloseHandle(hProcess);
                            return false;
                        }
#else
                        SetLastError(err ? err : ERROR_PROC_NOT_FOUND);
                        VirtualFreeEx(hProcess, pRemoteBase, 0, MEM_RELEASE);
                        cleanupFile(); CloseHandle(hProcess);
                        return false;
#endif
                    }
                    // Hedef IAT'a yaz - x86: 4 byte, stride 4
                    DWORD func32 = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(funcAddr) & 0xFFFFFFFF);
                    LPVOID pRemoteThunk = reinterpret_cast<BYTE*>(pRemoteIAT) + idx * sizeof(DWORD);
                    if (!WriteProcessMemory(hProcess, pRemoteThunk, &func32, sizeof(DWORD), nullptr)) {
                        VirtualFreeEx(hProcess, pRemoteBase, 0, MEM_RELEASE);
                        cleanupFile(); CloseHandle(hProcess);
                        return false;
                    }
                }
            } else {
                auto *pOrigThunk64 = reinterpret_cast<PIMAGE_THUNK_DATA64>(localImage.data() + thunkRVA);
                for (int idx = 0; pOrigThunk64[idx].u1.AddressOfData != 0; ++idx) {
                    if (iatRVA + idx * sizeof(ULONGLONG) + sizeof(ULONGLONG) > imageSize) break;
                    if (thunkRVA + idx * sizeof(IMAGE_THUNK_DATA64) + sizeof(IMAGE_THUNK_DATA64) > imageSize) break;
                    FARPROC funcAddr = nullptr;
                    const char* funcNameDbg64 = nullptr;
                    WORD ordinalDbg64 = 0;
                    bool isOrdinalDbg64 = false;
                    if (pOrigThunk64[idx].u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                        WORD ordinal = static_cast<WORD>(pOrigThunk64[idx].u1.Ordinal & 0xFFFF);
                        ordinalDbg64 = ordinal; isOrdinalDbg64 = true;
                        funcAddr = GetProcAddress(hMod, reinterpret_cast<LPCSTR>(static_cast<ULONG_PTR>(ordinal)));
                    } else {
                        ULONGLONG addrOfData = pOrigThunk64[idx].u1.AddressOfData;
                        if (addrOfData >= imageSize) continue;
                        if (addrOfData + sizeof(WORD) >= imageSize) continue;
                        auto *pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(localImage.data() + static_cast<SIZE_T>(addrOfData));
                        size_t maxByName = imageSize - static_cast<SIZE_T>(addrOfData) - sizeof(WORD);
                        if (strnlen(pImportByName->Name, maxByName) == maxByName) continue;
                        funcNameDbg64 = pImportByName->Name;
                        funcAddr = GetProcAddress(hMod, pImportByName->Name);
                    }
                    if (!funcAddr) {
                        DWORD err = GetLastError();
                        if (isOrdinalDbg64) {
                            qDebug() << "[ManualMap] GetProcAddress FAILED (x64) DLL:" << dllName << " ordinal:" << ordinalDbg64 << " err=" << err;
                        } else {
                            qDebug() << "[ManualMap] GetProcAddress FAILED (x64) DLL:" << dllName << " func:" << (funcNameDbg64 ? funcNameDbg64 : "<unknown>") << " err=" << err;
                        }
                        // x64 cross-arch not needed, but keep fallback for completeness (e.g., ARM64)
                        FARPROC fallback64 = nullptr;
                        if (dllIs64) {
#ifdef _WIN64
                            // Try remote fallback as well (target may have different base)
                            fallback64 = getRemoteProcAddressFallback(hProcess, pid, dllName, funcNameDbg64, ordinalDbg64, isOrdinalDbg64, false);
                            if (fallback64) {
                                funcAddr = fallback64;
                                qDebug() << "[ManualMap] Fallback SUCCESS (x64) addr=" << Qt::hex << reinterpret_cast<quintptr>(fallback64) << Qt::dec;
                            }
#endif
                        }
                        if (!funcAddr) {
                            SetLastError(err ? err : ERROR_PROC_NOT_FOUND);
                            VirtualFreeEx(hProcess, pRemoteBase, 0, MEM_RELEASE);
                            cleanupFile(); CloseHandle(hProcess);
                            return false;
                        }
                    }
                    // Hedef IAT'a yaz - x64: 8 byte, stride 8
                    ULONGLONG funcAddrVal = reinterpret_cast<ULONGLONG>(funcAddr);
                    LPVOID pRemoteThunk = reinterpret_cast<BYTE*>(pRemoteIAT) + idx * sizeof(ULONGLONG);
                    if (!WriteProcessMemory(hProcess, pRemoteThunk, &funcAddrVal, sizeof(ULONGLONG), nullptr)) {
                        VirtualFreeEx(hProcess, pRemoteBase, 0, MEM_RELEASE);
                        cleanupFile(); CloseHandle(hProcess);
                        return false;
                    }
                }
            }
        }
    }

    // 7b. TLS callbacks (if any) - must be called before DllMain, after imports
    if (tlsRVA != 0 && tlsSize != 0 && tlsRVA < imageSize) {
        qDebug() << "[ManualMap] TLS directory found RVA=0x" << Qt::hex << tlsRVA << " size=0x" << tlsSize << Qt::dec;
        // Note: TLS callbacks are stored as VA (ImageBase + RVA). After relocation, localImage's TLS dir has been patched to remoteBase.
        // To find the callbacks array in localImage, compute RVA = VA - remoteBase
        if (dllIs32) {
            if (tlsRVA + sizeof(IMAGE_TLS_DIRECTORY32) <= imageSize) {
                auto* tlsDir = reinterpret_cast<PIMAGE_TLS_DIRECTORY32>(localImage.data() + tlsRVA);
                DWORD callbacksVA32 = tlsDir->AddressOfCallBacks; // actually 32-bit VA truncated, but stored as DWORD
                ULONGLONG callbacksVA = callbacksVA32;
                if (callbacksVA != 0) {
                    // callbacksVA should be remoteBase + rva_of_array, so rva = VA - remoteBase
                    DWORD callbacksRVA = static_cast<DWORD>(callbacksVA - (remoteBaseAddr & 0xFFFFFFFFULL));
                    if (callbacksRVA < imageSize) {
                        DWORD* callbacks = reinterpret_cast<DWORD*>(localImage.data() + callbacksRVA);
                        // Also need to ensure the callbacks array itself is within image and was relocated
                        for (int ti = 0; ti < 16; ++ti) { // max 16 callbacks
                            DWORD cbVA32 = callbacks[ti];
                            if (cbVA32 == 0) break;
                            ULONGLONG cbVA = cbVA32;
                            // cbVA is remote VA, convert to remote address
                            LPVOID pCallback = reinterpret_cast<LPVOID>(static_cast<ULONG_PTR>(cbVA));
                            qDebug() << "[ManualMap] Calling TLS callback x86" << ti << " VA=0x" << Qt::hex << cbVA << Qt::dec;
                            // TLS callback: same as DllMain (HMODULE,1,0). From
                            // a 64-bit injector into a WOW64 target, borrow a
                            // native 32-bit thread instead of CreateRemoteThread.
                            if (needWow64Gate && dllIs32) {
                                DWORD tlsResult = 0xFFFFFFFF;
                                const DWORD tlsArgs[3] = {
                                    static_cast<DWORD>(remoteBaseAddr & 0xFFFFFFFF), 1, 0 };
                                if (!call32ViaThreadHijack(
                                        hProcess, pid,
                                        static_cast<DWORD>(cbVA & 0xFFFFFFFF),
                                        tlsArgs, 3,
                                        3000, &tlsResult, "TLS")) {
                                    qDebug() << "[ManualMap] TLS hijack failed, continuing";
                                    break;
                                }
                                qDebug() << "[ManualMap] TLS hijack result=0x" << Qt::hex << tlsResult << Qt::dec;
                                continue;
                            }
                            // Build shellcode for TLS callback: same as DllMain (HMODULE,1,0)
                            std::vector<BYTE> tlsShell = {
                                0x68, 0x00,0x00,0x00,0x00, // push 0
                                0x68, 0x01,0x00,0x00,0x00, // push 1
                                0x68, 0,0,0,0, // push dllBase
                                0xB8, 0,0,0,0, // mov eax, callback
                                0xFF, 0xD0, // call eax
                                0xC3 // ret
                            };
                            *reinterpret_cast<DWORD*>(&tlsShell[11]) = static_cast<DWORD>(remoteBaseAddr & 0xFFFFFFFF);
                            *reinterpret_cast<DWORD*>(&tlsShell[16]) = static_cast<DWORD>(cbVA & 0xFFFFFFFF);
                            LPVOID pTlsShell = VirtualAllocEx(hProcess, nullptr, tlsShell.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                            if (!pTlsShell) { qDebug() << "[ManualMap] TLS shell alloc failed"; break; }
                            if (!WriteProcessMemory(hProcess, pTlsShell, tlsShell.data(), tlsShell.size(), nullptr)) { VirtualFreeEx(hProcess, pTlsShell, 0, MEM_RELEASE); break; }
                            HANDLE hTlsTh = CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pTlsShell), nullptr, 0, nullptr);
                            if (!hTlsTh) { VirtualFreeEx(hProcess, pTlsShell, 0, MEM_RELEASE); break; }
                            if (WaitForSingleObject(hTlsTh, 3000) != WAIT_OBJECT_0) {
                                CloseHandle(hTlsTh);
                                cleanupFile(); CloseHandle(hProcess);
                                SetLastError(ERROR_TIMEOUT);
                                return false;
                            }
                            CloseHandle(hTlsTh);
                            VirtualFreeEx(hProcess, pTlsShell, 0, MEM_RELEASE);
                        }
                    } else {
                        qDebug() << "[ManualMap] TLS callbacks RVA out of range" << Qt::hex << callbacksRVA << Qt::dec;
                    }
                }
            }
        } else {
            if (tlsRVA + sizeof(IMAGE_TLS_DIRECTORY64) <= imageSize) {
                auto* tlsDir = reinterpret_cast<PIMAGE_TLS_DIRECTORY64>(localImage.data() + tlsRVA);
                ULONGLONG callbacksVA = tlsDir->AddressOfCallBacks;
                if (callbacksVA != 0) {
                    ULONGLONG callbacksRVA = callbacksVA - remoteBaseAddr;
                    if (callbacksRVA < imageSize) {
                        ULONGLONG* callbacks = reinterpret_cast<ULONGLONG*>(localImage.data() + static_cast<size_t>(callbacksRVA));
                        for (int ti=0; ti<16; ++ti) {
                            ULONGLONG cbVA = callbacks[ti];
                            if (cbVA == 0) break;
                            qDebug() << "[ManualMap] Calling TLS callback x64" << ti << " VA=0x" << Qt::hex << cbVA << Qt::dec;
                            std::vector<BYTE> tlsShell = {
                                0x48, 0xB9, 0,0,0,0,0,0,0,0, // mov rcx, dllBase
                                0x48, 0xBA, 0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // mov rdx,1
                                0x49, 0xB8, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // mov r8,0
                                0x48, 0xB8, 0,0,0,0,0,0,0,0, // mov rax, callback
                                0x48, 0x83, 0xEC, 0x28, // sub rsp,0x28
                                0xFF, 0xD0, // call rax
                                0x48, 0x83, 0xC4, 0x28, // add rsp,0x28
                                0xC3 // ret
                            };
                            *reinterpret_cast<ULONGLONG*>(&tlsShell[2]) = remoteBaseAddr;
                            *reinterpret_cast<ULONGLONG*>(&tlsShell[32]) = cbVA;
                            LPVOID pTlsShell = VirtualAllocEx(hProcess, nullptr, tlsShell.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                            if (!pTlsShell) break;
                            if (!WriteProcessMemory(hProcess, pTlsShell, tlsShell.data(), tlsShell.size(), nullptr)) { VirtualFreeEx(hProcess, pTlsShell, 0, MEM_RELEASE); break; }
                            HANDLE hTlsTh = CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pTlsShell), nullptr, 0, nullptr);
                            if (!hTlsTh) { VirtualFreeEx(hProcess, pTlsShell, 0, MEM_RELEASE); break; }
                            if (WaitForSingleObject(hTlsTh, 3000) != WAIT_OBJECT_0) {
                                CloseHandle(hTlsTh);
                                cleanupFile(); CloseHandle(hProcess);
                                SetLastError(ERROR_TIMEOUT);
                                return false;
                            }
                            CloseHandle(hTlsTh);
                            VirtualFreeEx(hProcess, pTlsShell, 0, MEM_RELEASE);
                        }
                    }
                }
            }
        }
    }

    // 8. Section korumalarini ayarla
    for (WORD i = 0; i < numSections; ++i) {
        const auto &sec = pLocalSections[i];
        if (sec.VirtualAddress >= imageSize) continue;
        DWORD protect = PAGE_NOACCESS;
        bool executable = (sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        bool readable   = (sec.Characteristics & IMAGE_SCN_MEM_READ) != 0;
        bool writable   = (sec.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        if (executable) {
            protect = writable ? PAGE_EXECUTE_READWRITE : (readable ? PAGE_EXECUTE_READ : PAGE_EXECUTE);
        } else {
            protect = writable ? PAGE_READWRITE : (readable ? PAGE_READONLY : PAGE_NOACCESS);
        }
        if (sec.Misc.VirtualSize == 0) continue;
        DWORD oldProtect;
        VirtualProtectEx(hProcess, reinterpret_cast<BYTE*>(pRemoteBase) + sec.VirtualAddress, sec.Misc.VirtualSize, protect, &oldProtect);
    }
    // Headerlari READONLY yap
    {
        DWORD old;
        VirtualProtectEx(hProcess, pRemoteBase, headersSize, PAGE_READONLY, &old);
    }

    // 9. Entry point (DllMain) cagir - shellcode ile dogru parametrelerle
    if (entryRVA != 0) {
        LPVOID pEntryPoint = reinterpret_cast<BYTE*>(pRemoteBase) + entryRVA;

        LPVOID pShellcode = nullptr;
        SIZE_T shellSize = 0;
        std::vector<BYTE> shell;

        if (dllIs64) {
            // x64: rcx=dllBase, rdx=1, r8=0, rax=entry, call rax
            shell = {
                0x48, 0xB9, 0,0,0,0,0,0,0,0, // mov rcx, dllBase
                0x48, 0xBA, 0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // mov rdx,1
                0x49, 0xB8, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // mov r8,0
                0x48, 0xB8, 0,0,0,0,0,0,0,0, // mov rax, entry
                0x48, 0x83, 0xEC, 0x28, // sub rsp,0x28
                0xFF, 0xD0, // call rax
                0x48, 0x83, 0xC4, 0x28, // add rsp,0x28
                0xC3 // ret
            };
            *reinterpret_cast<ULONGLONG*>(&shell[2]) = remoteBaseAddr;
            *reinterpret_cast<ULONGLONG*>(&shell[32]) = reinterpret_cast<ULONGLONG>(pEntryPoint);
            shellSize = shell.size();
        } else if (needWow64Gate) {
            // 64-bit injector into a WOW64 target (dllIs32 implied by the
            // architecture check above): borrow a native 32-bit thread so the
            // stdcall arguments arrive intact, then return with success.
            DWORD gateResult = 0xFFFFFFFF;
            const DWORD entry32 =
                static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(pEntryPoint) & 0xFFFFFFFF);
            const DWORD base32 = static_cast<DWORD>(remoteBaseAddr & 0xFFFFFFFF);
            const DWORD dllArgs[3] = { base32, 1, 0 };
            if (!call32ViaThreadHijack(hProcess, pid, entry32, dllArgs, 3, timeoutMs,
                                       &gateResult, "DllMain")) {
                qDebug() << "[ManualMap] DllMain hijack failed";
                cleanupFile(); CloseHandle(hProcess);
                SetLastError(ERROR_TIMEOUT);
                return false;
            }
            qDebug() << "[ManualMap] DllMain hijack result=0x" << Qt::hex << gateResult << Qt::dec;
            if (gateResult != TRUE) {
                cleanupFile(); CloseHandle(hProcess);
                SetLastError(ERROR_DLL_INIT_FAILED);
                return false;
            }
            cleanupFile();
            CloseHandle(hProcess);
            return true;
        } else {
            // x86: push 0, push 1, push dllBase, mov eax, entry, call eax, ret.
            // Same-architecture injector: the remote thread is 32-bit, so the
            // arguments land correctly.
            shell = {
                0x68, 0x00,0x00,0x00,0x00, // push 0
                0x68, 0x01,0x00,0x00,0x00, // push 1
                0x68, 0,0,0,0, // push dllBase
                0xB8, 0,0,0,0, // mov eax, entry
                0xFF, 0xD0, // call eax
                0xC3 // ret
            };
            *reinterpret_cast<DWORD*>(&shell[11]) = static_cast<DWORD>(remoteBaseAddr & 0xFFFFFFFF);
            *reinterpret_cast<DWORD*>(&shell[16]) = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(pEntryPoint) & 0xFFFFFFFF);
            shellSize = shell.size();
        }

        pShellcode = VirtualAllocEx(hProcess, nullptr, shellSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!pShellcode) {
            VirtualFreeEx(hProcess, pRemoteBase, 0, MEM_RELEASE);
            cleanupFile(); CloseHandle(hProcess);
            return false;
        }
        if (!WriteProcessMemory(hProcess, pShellcode, shell.data(), shellSize, nullptr)) {
            VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, pRemoteBase, 0, MEM_RELEASE);
            cleanupFile(); CloseHandle(hProcess);
            return false;
        }
        HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), nullptr, 0, nullptr);
        if (!hThread) {
            VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
            VirtualFreeEx(hProcess, pRemoteBase, 0, MEM_RELEASE);
            cleanupFile(); CloseHandle(hProcess);
            return false;
        }
        const DWORD waitResult = WaitForSingleObject(hThread, timeoutMs);
        DWORD exitCode = 0;
        const bool gotExit = GetExitCodeThread(hThread, &exitCode) != FALSE;
        qDebug() << "[ManualMap] DllMain thread wait=" << waitResult << " exit=" << Qt::hex << exitCode << Qt::dec << (needWow64Gate && dllIs32 ? " (heavens-gate)" : "");
        const bool initialized = gotExit
            && nativeInitializationConfirmed(waitResult, exitCode,
                                              WaitForSingleObject(hProcess, 0) == WAIT_TIMEOUT);
        CloseHandle(hThread);
        // Never free code while the remote thread may still be executing it.
        if (waitResult == WAIT_OBJECT_0)
            VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
        if (!initialized) {
            cleanupFile(); CloseHandle(hProcess);
            SetLastError(waitResult == WAIT_OBJECT_0 ? ERROR_DLL_INIT_FAILED : ERROR_TIMEOUT);
            return false;
        }
    }

    cleanupFile();
    CloseHandle(hProcess);
    return true;
}

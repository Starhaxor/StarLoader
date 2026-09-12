#pragma once
#include <QString>
#include <string>
#include <windows.h>
class InjectorEngine {
public:
    InjectorEngine();
    ~InjectorEngine();
    bool injectManualMap(DWORD pid, const QString &dllPath, DWORD timeoutMs = 5000);
    QString getProcessArchitecture(DWORD pid);
    std::string getLastErrorString(DWORD errorCode);
    void logMessage(const QString &message);
};

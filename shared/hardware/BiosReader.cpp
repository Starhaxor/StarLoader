#include "BiosReader.h"

#include <Windows.h>
#include <Wbemidl.h>
#include <OleAuto.h>

namespace {

template<typename T>
class ComPtr final
{
public:
    ComPtr() = default;
    ~ComPtr()
    {
        if (value_ != nullptr) {
            value_->Release();
        }
    }

    ComPtr(const ComPtr &) = delete;
    ComPtr &operator=(const ComPtr &) = delete;

    T *get() const { return value_; }
    T **put() { return &value_; }

private:
    T *value_ = nullptr;
};

class BString final
{
public:
    explicit BString(const wchar_t *value) : value_(SysAllocString(value)) {}
    ~BString() { SysFreeString(value_); }

    BString(const BString &) = delete;
    BString &operator=(const BString &) = delete;

    BSTR get() const { return value_; }
    bool isValid() const { return value_ != nullptr; }

private:
    BSTR value_;
};

class ComApartment final
{
public:
    ComApartment()
        : result_(CoInitializeEx(nullptr, COINIT_MULTITHREADED))
    {
    }

    ~ComApartment()
    {
        if (SUCCEEDED(result_)) {
            CoUninitialize();
        }
    }

    bool isAvailable() const
    {
        return SUCCEEDED(result_) || result_ == RPC_E_CHANGED_MODE;
    }

private:
    HRESULT result_;
};

} // namespace

QString BiosReader::serialNumber()
{
    const ComApartment apartment;
    if (!apartment.isAvailable()) {
        return {};
    }

    const HRESULT securityResult = CoInitializeSecurity(
        nullptr,
        -1,
        nullptr,
        nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_NONE,
        nullptr);
    if (FAILED(securityResult) && securityResult != RPC_E_TOO_LATE) {
        return {};
    }

    ComPtr<IWbemLocator> locator;
    if (FAILED(CoCreateInstance(CLSID_WbemLocator,
                                nullptr,
                                CLSCTX_INPROC_SERVER,
                                IID_IWbemLocator,
                                reinterpret_cast<void **>(locator.put())))) {
        return {};
    }

    const BString namespaceName(L"ROOT\\CIMV2");
    if (!namespaceName.isValid()) {
        return {};
    }

    ComPtr<IWbemServices> services;
    if (FAILED(locator.get()->ConnectServer(namespaceName.get(),
                                             nullptr,
                                             nullptr,
                                             nullptr,
                                             0,
                                             nullptr,
                                             nullptr,
                                             services.put()))) {
        return {};
    }

    if (FAILED(CoSetProxyBlanket(services.get(),
                                 RPC_C_AUTHN_WINNT,
                                 RPC_C_AUTHZ_NONE,
                                 nullptr,
                                 RPC_C_AUTHN_LEVEL_CALL,
                                 RPC_C_IMP_LEVEL_IMPERSONATE,
                                 nullptr,
                                 EOAC_NONE))) {
        return {};
    }

    const BString queryLanguage(L"WQL");
    const BString query(L"SELECT SerialNumber FROM Win32_BIOS");
    if (!queryLanguage.isValid() || !query.isValid()) {
        return {};
    }

    ComPtr<IEnumWbemClassObject> results;
    if (FAILED(services.get()->ExecQuery(
            queryLanguage.get(),
            query.get(),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            nullptr,
            results.put()))) {
        return {};
    }

    IWbemClassObject *row = nullptr;
    ULONG returned = 0;
    const HRESULT nextResult = results.get()->Next(5000, 1, &row, &returned);
    if (nextResult != WBEM_S_NO_ERROR || returned != 1 || row == nullptr) {
        if (row != nullptr) {
            row->Release();
        }
        return {};
    }

    VARIANT serial;
    VariantInit(&serial);
    const HRESULT readResult = row->Get(L"SerialNumber", 0, &serial, nullptr, nullptr);
    row->Release();

    QString value;
    if (SUCCEEDED(readResult) && serial.vt == VT_BSTR && serial.bstrVal != nullptr) {
        value = QString::fromWCharArray(serial.bstrVal, SysStringLen(serial.bstrVal))
                    .trimmed();
    }
    VariantClear(&serial);
    return value;
}

#pragma once

namespace TpmIdentityDetail {

enum class KeyOperationResult
{
    Success,
    NotFound,
    AlreadyExists,
    Failure
};

enum class EnsureKeyResult
{
    Success,
    OpenFailed,
    CreateFailed,
    ConfigureFailed,
    FinalizeFailed,
    ValidationFailed
};

class KeyLifecycle
{
public:
    virtual ~KeyLifecycle() = default;

    virtual KeyOperationResult openKey() = 0;
    virtual KeyOperationResult createKey() = 0;
    virtual bool configureCreatedKey() = 0;
    virtual bool finalizeCreatedKey() = 0;
    virtual bool validateKey() = 0;
    virtual void deleteCreatedKey() = 0;
};

EnsureKeyResult ensureKeyLifecycle(KeyLifecycle &lifecycle);

} // namespace TpmIdentityDetail

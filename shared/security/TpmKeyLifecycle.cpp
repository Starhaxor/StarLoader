#include "TpmKeyLifecycle.h"

namespace TpmIdentityDetail {

namespace {

class DeleteCreatedKeyOnFailure final
{
public:
    explicit DeleteCreatedKeyOnFailure(KeyLifecycle &lifecycle)
        : lifecycle_(&lifecycle)
    {
    }

    DeleteCreatedKeyOnFailure(const DeleteCreatedKeyOnFailure &) = delete;
    DeleteCreatedKeyOnFailure &operator=(const DeleteCreatedKeyOnFailure &) = delete;

    ~DeleteCreatedKeyOnFailure()
    {
        if (lifecycle_)
            lifecycle_->deleteCreatedKey();
    }

    void disarm() { lifecycle_ = nullptr; }

private:
    KeyLifecycle *lifecycle_;
};

} // namespace

EnsureKeyResult ensureKeyLifecycle(KeyLifecycle &lifecycle)
{
    const KeyOperationResult openResult = lifecycle.openKey();
    if (openResult == KeyOperationResult::Success) {
        return lifecycle.validateKey()
            ? EnsureKeyResult::Success
            : EnsureKeyResult::ValidationFailed;
    }
    if (openResult != KeyOperationResult::NotFound)
        return EnsureKeyResult::OpenFailed;

    const KeyOperationResult createResult = lifecycle.createKey();
    if (createResult == KeyOperationResult::AlreadyExists) {
        if (lifecycle.openKey() != KeyOperationResult::Success)
            return EnsureKeyResult::OpenFailed;
        return lifecycle.validateKey()
            ? EnsureKeyResult::Success
            : EnsureKeyResult::ValidationFailed;
    }
    if (createResult != KeyOperationResult::Success)
        return EnsureKeyResult::CreateFailed;

    DeleteCreatedKeyOnFailure rollback(lifecycle);
    if (!lifecycle.configureCreatedKey())
        return EnsureKeyResult::ConfigureFailed;
    if (!lifecycle.finalizeCreatedKey())
        return EnsureKeyResult::FinalizeFailed;
    if (!lifecycle.validateKey())
        return EnsureKeyResult::ValidationFailed;

    rollback.disarm();
    return EnsureKeyResult::Success;
}

} // namespace TpmIdentityDetail

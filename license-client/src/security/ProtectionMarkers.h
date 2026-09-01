#pragma once

// These markers are defense in depth for protected release coordination
// decisions. They do not provide cryptographic protection and are deliberately
// inactive outside a release built with the separately supplied VMProtect SDK.
#if defined(STARLOADER_PROTECTED_RELEASE)
#include <VMProtectSDK.h>

#define STARLOADER_VM_BEGIN(name) do { VMProtectBeginVirtualization(name); } while (false)
#define STARLOADER_VM_END() do { VMProtectEnd(); } while (false)
#define STARLOADER_MUTATE_BEGIN(name) do { VMProtectBeginMutation(name); } while (false)
#define STARLOADER_MUTATE_END() do { VMProtectEnd(); } while (false)
#else
#define STARLOADER_VM_BEGIN(name) do { (void)sizeof(name); } while (false)
#define STARLOADER_VM_END() do {} while (false)
#define STARLOADER_MUTATE_BEGIN(name) do { (void)sizeof(name); } while (false)
#define STARLOADER_MUTATE_END() do {} while (false)
#endif

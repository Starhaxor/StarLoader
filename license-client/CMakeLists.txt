if(STARLOADER_STATIC)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
if(STARLOADER_STATIC AND MINGW)
    target_link_libraries(OpenSSL::Crypto INTERFACE z)
endif()

# VMProtect is a release-only post-build protection dependency. Its SDK and
# project are supplied from a private release environment and are never stored
# in this repository. Development and test builds deliberately use inert
# markers and require none of these inputs.
option(STARLOADER_PROTECTED_RELEASE "Enable VMProtect markers for a protected release build" OFF)
set(STARLOADER_VMPROTECT_SDK_INCLUDE_DIR "" CACHE PATH "Directory containing VMProtectSDK.h for protected releases")
set(STARLOADER_VMPROTECT_SDK_LIBRARY "" CACHE FILEPATH "VMProtect SDK library for protected releases")
set(STARLOADER_VMPROTECT_PROJECT_FILE "" CACHE FILEPATH "VMProtect project file used by the release pipeline")
if(STARLOADER_PROTECTED_RELEASE)
    get_property(STARLOADER_VMPROTECT_MULTI_CONFIG GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
    if(STARLOADER_VMPROTECT_MULTI_CONFIG)
        set(CMAKE_CONFIGURATION_TYPES "Release" CACHE STRING "Configurations permitted for a protected release" FORCE)
    elseif(NOT CMAKE_BUILD_TYPE STREQUAL "Release")
        message(FATAL_ERROR "STARLOADER_PROTECTED_RELEASE=ON requires CMAKE_BUILD_TYPE=Release for a single-config generator")
    endif()
    foreach(STARLOADER_VMPROTECT_REQUIRED_INPUT IN ITEMS
            STARLOADER_VMPROTECT_SDK_INCLUDE_DIR
            STARLOADER_VMPROTECT_SDK_LIBRARY
            STARLOADER_VMPROTECT_PROJECT_FILE)
        if("${${STARLOADER_VMPROTECT_REQUIRED_INPUT}}" STREQUAL "" OR NOT EXISTS "${${STARLOADER_VMPROTECT_REQUIRED_INPUT}}")
            message(FATAL_ERROR "STARLOADER_PROTECTED_RELEASE=ON requires an existing ${STARLOADER_VMPROTECT_REQUIRED_INPUT}; VMProtect SDK and project inputs are release-environment only.")
        endif()
    endforeach()
    if(NOT IS_DIRECTORY "${STARLOADER_VMPROTECT_SDK_INCLUDE_DIR}" OR NOT EXISTS "${STARLOADER_VMPROTECT_SDK_INCLUDE_DIR}/VMProtectSDK.h")
        message(FATAL_ERROR "STARLOADER_VMPROTECT_SDK_INCLUDE_DIR must contain VMProtectSDK.h when STARLOADER_PROTECTED_RELEASE=ON")
    endif()
    if(IS_DIRECTORY "${STARLOADER_VMPROTECT_SDK_LIBRARY}")
        message(FATAL_ERROR "STARLOADER_VMPROTECT_SDK_LIBRARY must be a VMProtect SDK library file when STARLOADER_PROTECTED_RELEASE=ON")
    endif()
    if(IS_DIRECTORY "${STARLOADER_VMPROTECT_PROJECT_FILE}")
        message(FATAL_ERROR "STARLOADER_VMPROTECT_PROJECT_FILE must be a VMProtect project file when STARLOADER_PROTECTED_RELEASE=ON")
    endif()
endif()


set(STARLOADER_ED25519_KEY_RING "" CACHE STRING "Comma-separated kid=canonical-standard-base64 Ed25519 session-token public keys")
string(REPLACE "," ";" STARLOADER_ED25519_KEY_RING_ENTRIES "${STARLOADER_ED25519_KEY_RING}")
list(LENGTH STARLOADER_ED25519_KEY_RING_ENTRIES STARLOADER_ED25519_KEY_RING_COUNT)
if(STARLOADER_ED25519_KEY_RING_COUNT LESS 1)
    message(FATAL_ERROR "STARLOADER_ED25519_KEY_RING must contain at least one kid=canonical-standard-base64 32-byte public key")
endif()
set(STARLOADER_ED25519_KEY_RING_KIDS)
foreach(STARLOADER_ED25519_KEY_RING_ENTRY IN LISTS STARLOADER_ED25519_KEY_RING_ENTRIES)
    string(REGEX MATCH "^([A-Za-z0-9._-]+)=([A-Za-z0-9+/]+)=$" STARLOADER_ED25519_KEY_RING_MATCH "${STARLOADER_ED25519_KEY_RING_ENTRY}")
    if(NOT STARLOADER_ED25519_KEY_RING_MATCH)
        message(FATAL_ERROR "STARLOADER_ED25519_KEY_RING entries must use kid=canonical-standard-base64 syntax")
    endif()
    set(STARLOADER_ED25519_KEY_RING_KID "${CMAKE_MATCH_1}")
    set(STARLOADER_ED25519_KEY_RING_KEY "${CMAKE_MATCH_2}=")
    string(LENGTH "${STARLOADER_ED25519_KEY_RING_KEY}" STARLOADER_ED25519_KEY_RING_KEY_LENGTH)
    string(SUBSTRING "${STARLOADER_ED25519_KEY_RING_KEY}" 42 1 STARLOADER_ED25519_KEY_RING_LAST_CHARACTER)
    if(NOT STARLOADER_ED25519_KEY_RING_KEY_LENGTH EQUAL 44 OR NOT STARLOADER_ED25519_KEY_RING_LAST_CHARACTER MATCHES "^[AEIMQUYcgkosw048]$")
        message(FATAL_ERROR "STARLOADER_ED25519_KEY_RING keys must be canonical 32-byte standard-base64 values")
    endif()
    list(FIND STARLOADER_ED25519_KEY_RING_KIDS "${STARLOADER_ED25519_KEY_RING_KID}" STARLOADER_ED25519_KEY_RING_DUPLICATE)
    if(NOT STARLOADER_ED25519_KEY_RING_DUPLICATE EQUAL -1)
        message(FATAL_ERROR "STARLOADER_ED25519_KEY_RING kid values must be unique")
    endif()
    list(APPEND STARLOADER_ED25519_KEY_RING_KIDS "${STARLOADER_ED25519_KEY_RING_KID}")
endforeach()

# STARLOADER_API_URL comes exclusively from the qt-mingw preset in
# CMakePresets.json (or an explicit -D override). There is deliberately no
# placeholder default and no runtime environment override: a build without an
# explicit https:// URL must fail loudly instead of silently shipping a client
# that talks to the wrong endpoint.
option(STARLOADER_LOCAL_DEVELOPMENT "Allow a numeric loopback HTTP API URL in an explicitly local build" OFF)
set(STARLOADER_TLS_PINNED_HOST "" CACHE STRING "Exact KeyStar host protected by SPKI pinning")
set(STARLOADER_TLS_SPKI_PINS "" CACHE STRING "Exactly two comma-separated sha256/<canonical-standard-base64> SPKI pins")
if(STARLOADER_LOCAL_DEVELOPMENT)
    if(NOT STARLOADER_API_URL MATCHES "^http://127\\.0\\.0\\.1(:[0-9]+)?/?$")
        message(FATAL_ERROR "STARLOADER_LOCAL_DEVELOPMENT only permits http://127.0.0.1 with an optional port.")
    endif()
    if(NOT STARLOADER_TLS_PINNED_HOST STREQUAL "127.0.0.1" OR NOT STARLOADER_TLS_SPKI_PINS STREQUAL "")
        message(FATAL_ERROR "Local development requires STARLOADER_TLS_PINNED_HOST=127.0.0.1 and no TLS pins")
    endif()
elseif(NOT STARLOADER_API_URL MATCHES "^https://")
    message(FATAL_ERROR "STARLOADER_API_URL must be set to an https:// URL. Use the qt-mingw-local preset only for loopback development.")
endif()
if(NOT STARLOADER_LOCAL_DEVELOPMENT)
    if(STARLOADER_TLS_PINNED_HOST STREQUAL "" OR NOT STARLOADER_TLS_PINNED_HOST MATCHES "^[A-Za-z0-9.-]+$")
        message(FATAL_ERROR "STARLOADER_TLS_PINNED_HOST must be the exact production KeyStar DNS host")
    endif()
    string(REGEX MATCH "^https://([^/:?#]+)" STARLOADER_TLS_API_HOST_MATCH "${STARLOADER_API_URL}")
    if(NOT STARLOADER_TLS_API_HOST_MATCH)
        message(FATAL_ERROR "STARLOADER_API_URL must include the exact production KeyStar host")
    endif()
    string(TOLOWER "${CMAKE_MATCH_1}" STARLOADER_TLS_API_HOST)
    string(TOLOWER "${STARLOADER_TLS_PINNED_HOST}" STARLOADER_TLS_CONFIGURED_HOST)
    if(NOT STARLOADER_TLS_API_HOST STREQUAL STARLOADER_TLS_CONFIGURED_HOST)
        message(FATAL_ERROR "STARLOADER_API_URL host must match STARLOADER_TLS_PINNED_HOST exactly")
    endif()
    string(REPLACE "," ";" STARLOADER_TLS_SPKI_PIN_ENTRIES "${STARLOADER_TLS_SPKI_PINS}")
    list(LENGTH STARLOADER_TLS_SPKI_PIN_ENTRIES STARLOADER_TLS_SPKI_PIN_COUNT)
    if(NOT STARLOADER_TLS_SPKI_PIN_COUNT EQUAL 2)
        message(FATAL_ERROR "STARLOADER_TLS_SPKI_PINS must contain exactly two pins")
    endif()
    set(STARLOADER_TLS_SPKI_PIN_DIGESTS)
    foreach(STARLOADER_TLS_SPKI_PIN IN LISTS STARLOADER_TLS_SPKI_PIN_ENTRIES)
        string(REGEX MATCH "^sha256/([A-Za-z0-9+/]+)=$" STARLOADER_TLS_SPKI_PIN_MATCH "${STARLOADER_TLS_SPKI_PIN}")
        if(NOT STARLOADER_TLS_SPKI_PIN_MATCH)
            message(FATAL_ERROR "TLS pins must use sha256/<canonical-standard-base64> syntax")
        endif()
        set(STARLOADER_TLS_SPKI_PIN_DIGEST "${CMAKE_MATCH_1}=")
        string(LENGTH "${STARLOADER_TLS_SPKI_PIN_DIGEST}" STARLOADER_TLS_SPKI_PIN_LENGTH)
        if(STARLOADER_TLS_SPKI_PIN_LENGTH EQUAL 44)
            string(SUBSTRING "${STARLOADER_TLS_SPKI_PIN_DIGEST}" 42 1 STARLOADER_TLS_SPKI_PIN_LAST_CHARACTER)
        else()
            set(STARLOADER_TLS_SPKI_PIN_LAST_CHARACTER "")
        endif()
        if(NOT STARLOADER_TLS_SPKI_PIN_LENGTH EQUAL 44 OR NOT STARLOADER_TLS_SPKI_PIN_LAST_CHARACTER MATCHES "^[AEIMQUYcgkosw048]$")
            message(FATAL_ERROR "TLS pins must encode exactly 32 bytes using canonical standard Base64")
        endif()
        list(APPEND STARLOADER_TLS_SPKI_PIN_DIGESTS "${STARLOADER_TLS_SPKI_PIN_DIGEST}")
    endforeach()
    list(GET STARLOADER_TLS_SPKI_PIN_DIGESTS 0 STARLOADER_TLS_SPKI_PIN_CURRENT)
    list(GET STARLOADER_TLS_SPKI_PIN_DIGESTS 1 STARLOADER_TLS_SPKI_PIN_NEXT)
    if(STARLOADER_TLS_SPKI_PIN_CURRENT STREQUAL STARLOADER_TLS_SPKI_PIN_NEXT)
        message(FATAL_ERROR "Current and staged-next TLS pins must be distinct")
    endif()
endif()
set(STARLOADER_APPLICATION_ID "" CACHE STRING "KeyStar application UUID used by the StarLoader client")
string(LENGTH "${STARLOADER_APPLICATION_ID}" STARLOADER_APPLICATION_ID_LENGTH)
if(NOT STARLOADER_APPLICATION_ID_LENGTH EQUAL 36 OR NOT STARLOADER_APPLICATION_ID MATCHES "^[0-9a-f]+-[0-9a-f]+-[1-8][0-9a-f]+-[89ab][0-9a-f]+-[0-9a-f]+$")
    message(FATAL_ERROR "STARLOADER_APPLICATION_ID must be a canonical UUID. Configure it with the qt-mingw preset (CMakePresets.json) or -DSTARLOADER_APPLICATION_ID=<application-id>.")
endif()
set(STARLOADER_PRODUCT_ID "" CACHE STRING "KeyStar product identifier bound into StarLoader access tokens")
if(STARLOADER_PRODUCT_ID STREQUAL "" OR NOT STARLOADER_PRODUCT_ID MATCHES "^[A-Za-z0-9._-]+$")
    message(FATAL_ERROR "STARLOADER_PRODUCT_ID must be a non-empty product identifier")
endif()
set(STARLOADER_PUBLISHABLE_KEY "" CACHE STRING "KeyStar publishable API key used by the StarLoader client")
if(NOT STARLOADER_PUBLISHABLE_KEY MATCHES "^ks_pk_(live|test)_[A-Za-z0-9_-]+$")
    message(FATAL_ERROR "STARLOADER_PUBLISHABLE_KEY must be a KeyStar publishable key. Configure it with the qt-mingw preset (CMakePresets.json) or -DSTARLOADER_PUBLISHABLE_KEY=ks_pk_live_<key>.")
endif()
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/config/ClientSecurityConfig.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/ClientSecurityConfig.h"
    @ONLY)

if(WIN32)
    unset(OPENSSL_CRYPTO_RUNTIME CACHE)
    find_file(OPENSSL_CRYPTO_RUNTIME
        NAMES libcrypto-3-x64.dll libcrypto-1_1-x64.dll libcrypto-1_1.dll
        HINTS "${OPENSSL_ROOT_DIR}/bin"
        NO_DEFAULT_PATH)
    if(NOT OPENSSL_CRYPTO_RUNTIME)
        message(FATAL_ERROR "OpenSSL Crypto runtime DLL is required for Qt tests")
    endif()
    get_filename_component(OPENSSL_CRYPTO_RUNTIME_DIR "${OPENSSL_CRYPTO_RUNTIME}" DIRECTORY)
else()
    set(OPENSSL_CRYPTO_RUNTIME_DIR "$<TARGET_FILE_DIR:OpenSSL::Crypto>")
endif()

qt_add_executable(LicenseClient WIN32
    src/main.cpp
    src/api/ApiClient.cpp
    src/api/ApiClient.h
    src/auth/AuthManager.cpp
    src/auth/AuthManager.h
    src/auth/AuthState.h
    src/security/SessionTokenVerifier.cpp
    src/security/SessionTokenVerifier.h
    src/security/DeviceProof.cpp
    src/security/DeviceProof.h
    src/security/TlsPinPolicy.cpp
    src/security/TlsPinPolicy.h
    src/ui/LoginWindow.cpp
    src/ui/LoginWindow.h
    src/ui/WindowTitleBar.cpp
    src/ui/WindowTitleBar.h
    src/ui/UserDashboard.cpp
    src/ui/UserDashboard.h
    ui/UserDashboard.ui
    ui/LoginWindow.ui
    src/ui/HwidDialog.cpp
    src/ui/HwidDialog.h
    ui/HwidDialog.ui
)

qt_add_executable(ApiClientTest
    src/api/ApiClient.cpp
    src/api/ApiClient.h
    src/security/DeviceProof.cpp
    src/security/DeviceProof.h
    src/security/TlsPinPolicy.cpp
    src/security/TlsPinPolicy.h
    tests/ApiClientTest.cpp
)

qt_add_executable(AuthManagerTest
    src/api/ApiClient.cpp
    src/api/ApiClient.h
    src/security/DeviceProof.cpp
    src/security/DeviceProof.h
    src/security/TlsPinPolicy.cpp
    src/security/TlsPinPolicy.h
    src/auth/AuthManager.cpp
    src/auth/AuthManager.h
    src/auth/AuthState.h
    src/security/SessionTokenVerifier.cpp
    src/security/SessionTokenVerifier.h
    tests/AuthManagerTest.cpp
)

qt_add_executable(SessionTokenVerifierTest
    src/security/SessionTokenVerifier.cpp
    src/security/SessionTokenVerifier.h
    tests/SessionTokenVerifierTest.cpp
)

qt_add_executable(DeviceProofTest
    src/security/DeviceProof.cpp
    src/security/DeviceProof.h
    tests/DeviceProofTest.cpp
)

qt_add_executable(TlsPinPolicyTest
    src/security/TlsPinPolicy.cpp
    src/security/TlsPinPolicy.h
    tests/TlsPinPolicyTest.cpp
)

add_executable(ProtectionMarkersTest
    tests/ProtectionMarkersTest.cpp
)

qt_add_executable(HwidDialogTest
    src/ui/HwidDialog.cpp
    src/ui/HwidDialog.h
    src/ui/WindowTitleBar.cpp
    src/ui/WindowTitleBar.h
    ui/HwidDialog.ui
    tests/HwidDialogTest.cpp
)

qt_add_executable(LoginWindowUiTest
    src/api/ApiClient.cpp
    src/api/ApiClient.h
    src/security/DeviceProof.cpp
    src/security/DeviceProof.h
    src/security/TlsPinPolicy.cpp
    src/security/TlsPinPolicy.h
    src/auth/AuthManager.cpp
    src/auth/AuthManager.h
    src/auth/AuthState.h
    src/security/SessionTokenVerifier.cpp
    src/security/SessionTokenVerifier.h
    src/ui/LoginWindow.cpp
    src/ui/LoginWindow.h
    src/ui/HwidDialog.cpp
    src/ui/HwidDialog.h
    src/ui/WindowTitleBar.cpp
    src/ui/WindowTitleBar.h
    src/ui/UserDashboard.cpp
    src/ui/UserDashboard.h
    ui/LoginWindow.ui
    ui/HwidDialog.ui
    ui/UserDashboard.ui
    tests/LoginWindowUiTest.cpp
)

qt_add_executable(WindowTitleBarTest
    src/ui/WindowTitleBar.cpp
    src/ui/WindowTitleBar.h
    tests/WindowTitleBarTest.cpp
)

qt_add_executable(UserDashboardTest
    src/api/ApiClient.cpp
    src/api/ApiClient.h
    src/security/DeviceProof.cpp
    src/security/DeviceProof.h
    src/security/TlsPinPolicy.cpp
    src/security/TlsPinPolicy.h
    src/auth/AuthManager.cpp
    src/auth/AuthManager.h
    src/auth/AuthState.h
    src/security/SessionTokenVerifier.cpp
    src/security/SessionTokenVerifier.h
    src/ui/LoginWindow.cpp
    src/ui/LoginWindow.h
    src/ui/HwidDialog.cpp
    src/ui/HwidDialog.h
    src/ui/UserDashboard.cpp
    src/ui/UserDashboard.h
    src/ui/WindowTitleBar.cpp
    src/ui/WindowTitleBar.h
    ui/LoginWindow.ui
    ui/HwidDialog.ui
    ui/UserDashboard.ui
    tests/UserDashboardTest.cpp
)

qt_add_executable(NativeLiveFlowTest
    src/api/ApiClient.cpp
    src/api/ApiClient.h
    src/security/DeviceProof.cpp
    src/security/DeviceProof.h
    src/security/TlsPinPolicy.cpp
    src/security/TlsPinPolicy.h
    src/auth/AuthManager.cpp
    src/auth/AuthManager.h
    src/auth/AuthState.h
    src/security/SessionTokenVerifier.cpp
    src/security/SessionTokenVerifier.h
    src/ui/LoginWindow.cpp
    src/ui/LoginWindow.h
    src/ui/HwidDialog.cpp
    src/ui/HwidDialog.h
    src/ui/UserDashboard.cpp
    src/ui/UserDashboard.h
    src/ui/WindowTitleBar.cpp
    src/ui/WindowTitleBar.h
    ui/LoginWindow.ui
    ui/HwidDialog.ui
    ui/UserDashboard.ui
    tests/NativeLiveFlowTest.cpp
)

target_link_libraries(LicenseClient PRIVATE
    DeviceIdentityShared
    Qt6::Core
    Qt6::Widgets
    Qt6::Network
    Qt6::Concurrent
    OpenSSL::Crypto
)

if(STARLOADER_PROTECTED_RELEASE)
    target_compile_definitions(LicenseClient PRIVATE STARLOADER_PROTECTED_RELEASE=1)
    target_include_directories(LicenseClient PRIVATE "${STARLOADER_VMPROTECT_SDK_INCLUDE_DIR}")
    target_link_libraries(LicenseClient PRIVATE "${STARLOADER_VMPROTECT_SDK_LIBRARY}")
endif()


target_include_directories(LicenseClient PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}/generated
)

if(STARLOADER_STATIC)
    if(TARGET Qt6::QWindowsIntegrationPlugin)
        target_link_libraries(LicenseClient PRIVATE Qt6::QWindowsIntegrationPlugin)
    endif()
    message(STATUS "STARLOADER_STATIC=ON -> windeployqt atlaniyor (tek EXE)")
elseif(WIN32)
    get_target_property(QT_QMAKE_EXECUTABLE Qt6::qmake IMPORTED_LOCATION)
    get_filename_component(QT_RUNTIME_DIR "${QT_QMAKE_EXECUTABLE}" DIRECTORY)
    get_filename_component(QT_INSTALL_ROOT "${QT_RUNTIME_DIR}" DIRECTORY)
    set(QT_PLATFORM_PLUGIN_DIR "${QT_INSTALL_ROOT}/plugins/platforms")
    find_program(WINDEPLOYQT_EXECUTABLE
        NAMES windeployqt
        HINTS "${QT_RUNTIME_DIR}"
        REQUIRED)
    add_custom_command(TARGET LicenseClient POST_BUILD
        COMMAND "${WINDEPLOYQT_EXECUTABLE}"
            --no-translations
            --compiler-runtime
            --openssl-root "${OPENSSL_ROOT_DIR}"
            "$<TARGET_FILE:LicenseClient>"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
            "${OPENSSL_CRYPTO_RUNTIME}"
            "$<TARGET_FILE_DIR:LicenseClient>"
        COMMENT "Deploying the Qt, MinGW, and OpenSSL runtime beside LicenseClient"
        VERBATIM)
endif()

target_link_libraries(ApiClientTest PRIVATE DeviceIdentityShared Qt6::Core Qt6::Network Qt6::Test OpenSSL::Crypto)
target_link_libraries(AuthManagerTest PRIVATE DeviceIdentityShared Qt6::Core Qt6::Network Qt6::Concurrent Qt6::Test OpenSSL::Crypto)
target_link_libraries(SessionTokenVerifierTest PRIVATE Qt6::Core Qt6::Test OpenSSL::Crypto)
target_link_libraries(DeviceProofTest PRIVATE DeviceIdentityShared Qt6::Core Qt6::Network Qt6::Test)
target_link_libraries(TlsPinPolicyTest PRIVATE Qt6::Core Qt6::Network Qt6::Test OpenSSL::Crypto)
target_include_directories(ProtectionMarkersTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
if(STARLOADER_PROTECTED_RELEASE)
    target_compile_definitions(ProtectionMarkersTest PRIVATE STARLOADER_PROTECTED_RELEASE=1)
    target_include_directories(ProtectionMarkersTest PRIVATE "${STARLOADER_VMPROTECT_SDK_INCLUDE_DIR}")
    target_link_libraries(ProtectionMarkersTest PRIVATE "${STARLOADER_VMPROTECT_SDK_LIBRARY}")
endif()
target_link_libraries(HwidDialogTest PRIVATE DeviceIdentityShared Qt6::Widgets Qt6::Concurrent Qt6::Test)
target_link_libraries(LoginWindowUiTest PRIVATE DeviceIdentityShared Qt6::Widgets Qt6::Network Qt6::Concurrent Qt6::Test OpenSSL::Crypto)
target_link_libraries(WindowTitleBarTest PRIVATE Qt6::Widgets Qt6::Test)
target_link_libraries(UserDashboardTest PRIVATE DeviceIdentityShared Qt6::Widgets Qt6::Network Qt6::Concurrent Qt6::Test OpenSSL::Crypto)
target_link_libraries(NativeLiveFlowTest PRIVATE DeviceIdentityShared Qt6::Widgets Qt6::Network Qt6::Concurrent Qt6::Test OpenSSL::Crypto)

target_include_directories(ApiClientTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR}/generated)
target_include_directories(AuthManagerTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR}/generated ${CMAKE_SOURCE_DIR}/shared)
target_include_directories(SessionTokenVerifierTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(DeviceProofTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR}/generated)
target_include_directories(TlsPinPolicyTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(HwidDialogTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(LoginWindowUiTest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}/generated
)
target_include_directories(WindowTitleBarTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(UserDashboardTest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}/generated
)
target_include_directories(NativeLiveFlowTest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}/generated
)

add_test(NAME ApiClientTest COMMAND ApiClientTest)
add_test(NAME AuthManagerTest COMMAND AuthManagerTest)
add_test(NAME SessionTokenVerifierTest COMMAND SessionTokenVerifierTest)
add_test(NAME DeviceProofTest COMMAND DeviceProofTest)
add_test(NAME TlsPinPolicyTest COMMAND TlsPinPolicyTest)
add_test(NAME ProtectionMarkersTest COMMAND ProtectionMarkersTest)
add_test(NAME ProtectedReleaseConfigurationTest
    COMMAND "${CMAKE_COMMAND}"
        "-DSTARLOADER_CMAKE_COMMAND=${CMAKE_COMMAND}"
        "-DSTARLOADER_SOURCE_DIR=${CMAKE_SOURCE_DIR}"
        "-DSTARLOADER_TEST_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}/p"
        "-DSTARLOADER_CMAKE_GENERATOR=${CMAKE_GENERATOR}"
        "-DSTARLOADER_CMAKE_GENERATOR_PLATFORM=${CMAKE_GENERATOR_PLATFORM}"
        "-DSTARLOADER_CMAKE_GENERATOR_TOOLSET=${CMAKE_GENERATOR_TOOLSET}"
        "-DSTARLOADER_CMAKE_MAKE_PROGRAM=${CMAKE_MAKE_PROGRAM}"
        "-DSTARLOADER_CMAKE_C_COMPILER=${CMAKE_C_COMPILER}"
        "-DSTARLOADER_CMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
        "-DSTARLOADER_CMAKE_AR=${CMAKE_AR}"
        "-DSTARLOADER_CMAKE_RANLIB=${CMAKE_RANLIB}"
        "-DSTARLOADER_CMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}"
        "-DSTARLOADER_CMAKE_PREFIX_PATH=${CMAKE_PREFIX_PATH}"
        "-DSTARLOADER_QT6_DIR=${Qt6_DIR}"
        "-DSTARLOADER_OPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/VerifyProtectedReleaseConfiguration.cmake")
add_test(NAME HwidDialogTest COMMAND HwidDialogTest)
add_test(NAME LoginWindowUiTest COMMAND LoginWindowUiTest)
add_test(NAME WindowTitleBarTest COMMAND WindowTitleBarTest)
add_test(NAME UserDashboardTest COMMAND UserDashboardTest)
add_test(NAME NativeLiveFlowTest COMMAND NativeLiveFlowTest)
foreach(test_name IN ITEMS ApiClientTest AuthManagerTest SessionTokenVerifierTest DeviceProofTest TlsPinPolicyTest ProtectionMarkersTest HwidDialogTest LoginWindowUiTest WindowTitleBarTest UserDashboardTest NativeLiveFlowTest)
    set_tests_properties(${test_name} PROPERTIES
        ENVIRONMENT "PATH=$<TARGET_FILE_DIR:Qt6::Core>\\;${OPENSSL_CRYPTO_RUNTIME_DIR}\\;$ENV{PATH}")
    if(WIN32)
        set_property(TEST ${test_name} APPEND PROPERTY ENVIRONMENT
            "QT_QPA_PLATFORM_PLUGIN_PATH=${QT_PLATFORM_PLUGIN_DIR}")
    endif()
endforeach()
set_property(TEST HwidDialogTest APPEND PROPERTY ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
set_property(TEST LoginWindowUiTest APPEND PROPERTY ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
set_property(TEST WindowTitleBarTest APPEND PROPERTY ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
set_property(TEST UserDashboardTest APPEND PROPERTY ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
set_property(TEST NativeLiveFlowTest APPEND PROPERTY ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
set_tests_properties(NativeLiveFlowTest PROPERTIES TIMEOUT 90)

set_target_properties(LicenseClient PROPERTIES
    AUTOUIC_SEARCH_PATHS "${CMAKE_CURRENT_SOURCE_DIR}/ui"
)

set_target_properties(HwidDialogTest PROPERTIES
    AUTOUIC_SEARCH_PATHS "${CMAKE_CURRENT_SOURCE_DIR}/ui"
)

set_target_properties(LoginWindowUiTest PROPERTIES
    AUTOUIC_SEARCH_PATHS "${CMAKE_CURRENT_SOURCE_DIR}/ui"
)

set_target_properties(UserDashboardTest PROPERTIES
    AUTOUIC_SEARCH_PATHS "${CMAKE_CURRENT_SOURCE_DIR}/ui"
)

set_target_properties(NativeLiveFlowTest PROPERTIES
    AUTOUIC_SEARCH_PATHS "${CMAKE_CURRENT_SOURCE_DIR}/ui"
)

if(STARLOADER_STATIC)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
if(STARLOADER_STATIC AND MINGW)
    target_link_libraries(OpenSSL::Crypto INTERFACE z)
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
if(STARLOADER_LOCAL_DEVELOPMENT)
    if(NOT STARLOADER_API_URL MATCHES "^http://127\\.0\\.0\\.1(:[0-9]+)?/?$")
        message(FATAL_ERROR "STARLOADER_LOCAL_DEVELOPMENT only permits http://127.0.0.1 with an optional port.")
    endif()
elseif(NOT STARLOADER_API_URL MATCHES "^https://")
    message(FATAL_ERROR "STARLOADER_API_URL must be set to an https:// URL. Use the qt-mingw-local preset only for loopback development.")
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
    tests/ApiClientTest.cpp
)

qt_add_executable(AuthManagerTest
    src/api/ApiClient.cpp
    src/api/ApiClient.h
    src/security/DeviceProof.cpp
    src/security/DeviceProof.h
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

target_link_libraries(ApiClientTest PRIVATE DeviceIdentityShared Qt6::Core Qt6::Network Qt6::Test)
target_link_libraries(AuthManagerTest PRIVATE DeviceIdentityShared Qt6::Core Qt6::Network Qt6::Concurrent Qt6::Test OpenSSL::Crypto)
target_link_libraries(SessionTokenVerifierTest PRIVATE Qt6::Core Qt6::Test OpenSSL::Crypto)
target_link_libraries(DeviceProofTest PRIVATE DeviceIdentityShared Qt6::Core Qt6::Network Qt6::Test)
target_link_libraries(HwidDialogTest PRIVATE DeviceIdentityShared Qt6::Widgets Qt6::Concurrent Qt6::Test)
target_link_libraries(LoginWindowUiTest PRIVATE DeviceIdentityShared Qt6::Widgets Qt6::Network Qt6::Concurrent Qt6::Test OpenSSL::Crypto)
target_link_libraries(WindowTitleBarTest PRIVATE Qt6::Widgets Qt6::Test)
target_link_libraries(UserDashboardTest PRIVATE DeviceIdentityShared Qt6::Widgets Qt6::Network Qt6::Concurrent Qt6::Test OpenSSL::Crypto)
target_link_libraries(NativeLiveFlowTest PRIVATE DeviceIdentityShared Qt6::Widgets Qt6::Network Qt6::Concurrent Qt6::Test OpenSSL::Crypto)

target_include_directories(ApiClientTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR}/generated)
target_include_directories(AuthManagerTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR}/generated ${CMAKE_SOURCE_DIR}/shared)
target_include_directories(SessionTokenVerifierTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(DeviceProofTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR}/generated)
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
add_test(NAME HwidDialogTest COMMAND HwidDialogTest)
add_test(NAME LoginWindowUiTest COMMAND LoginWindowUiTest)
add_test(NAME WindowTitleBarTest COMMAND WindowTitleBarTest)
add_test(NAME UserDashboardTest COMMAND UserDashboardTest)
add_test(NAME NativeLiveFlowTest COMMAND NativeLiveFlowTest)
foreach(test_name IN ITEMS ApiClientTest AuthManagerTest SessionTokenVerifierTest DeviceProofTest HwidDialogTest LoginWindowUiTest WindowTitleBarTest UserDashboardTest NativeLiveFlowTest)
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

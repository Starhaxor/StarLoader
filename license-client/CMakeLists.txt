find_package(OpenSSL REQUIRED COMPONENTS Crypto)

set(STARLOADER_ED25519_PUBLIC_KEY "" CACHE STRING "Canonical standard-base64 Ed25519 session-token public key")
string(LENGTH "${STARLOADER_ED25519_PUBLIC_KEY}" STARLOADER_ED25519_PUBLIC_KEY_LENGTH)
if(NOT STARLOADER_ED25519_PUBLIC_KEY_LENGTH EQUAL 44 OR NOT STARLOADER_ED25519_PUBLIC_KEY MATCHES "^[A-Za-z0-9+/]+=$")
    message(FATAL_ERROR "STARLOADER_ED25519_PUBLIC_KEY must be a canonical 32-byte standard-base64 public key")
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
    src/ui/LoginWindow.cpp
    src/ui/LoginWindow.h
    src/ui/WindowTitleBar.cpp
    src/ui/WindowTitleBar.h
    ui/LoginWindow.ui
    src/ui/HwidDialog.cpp
    src/ui/HwidDialog.h
    ui/HwidDialog.ui
)

qt_add_executable(ApiClientTest
    src/api/ApiClient.cpp
    src/api/ApiClient.h
    tests/ApiClientTest.cpp
)

qt_add_executable(AuthManagerTest
    src/api/ApiClient.cpp
    src/api/ApiClient.h
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
    ui/LoginWindow.ui
    ui/HwidDialog.ui
    tests/LoginWindowUiTest.cpp
)

qt_add_executable(WindowTitleBarTest
    src/ui/WindowTitleBar.cpp
    src/ui/WindowTitleBar.h
    tests/WindowTitleBarTest.cpp
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

target_link_libraries(ApiClientTest PRIVATE Qt6::Core Qt6::Network Qt6::Test)
target_link_libraries(AuthManagerTest PRIVATE DeviceIdentityShared Qt6::Core Qt6::Network Qt6::Concurrent Qt6::Test OpenSSL::Crypto)
target_link_libraries(SessionTokenVerifierTest PRIVATE Qt6::Core Qt6::Test OpenSSL::Crypto)
target_link_libraries(HwidDialogTest PRIVATE DeviceIdentityShared Qt6::Widgets Qt6::Concurrent Qt6::Test)
target_link_libraries(LoginWindowUiTest PRIVATE DeviceIdentityShared Qt6::Widgets Qt6::Network Qt6::Concurrent Qt6::Test OpenSSL::Crypto)
target_link_libraries(WindowTitleBarTest PRIVATE Qt6::Widgets Qt6::Test)

target_include_directories(ApiClientTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(AuthManagerTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/shared)
target_include_directories(SessionTokenVerifierTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(HwidDialogTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(LoginWindowUiTest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}/generated
)
target_include_directories(WindowTitleBarTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_test(NAME ApiClientTest COMMAND ApiClientTest)
add_test(NAME AuthManagerTest COMMAND AuthManagerTest)
add_test(NAME SessionTokenVerifierTest COMMAND SessionTokenVerifierTest)
add_test(NAME HwidDialogTest COMMAND HwidDialogTest)
add_test(NAME LoginWindowUiTest COMMAND LoginWindowUiTest)
add_test(NAME WindowTitleBarTest COMMAND WindowTitleBarTest)
foreach(test_name IN ITEMS ApiClientTest AuthManagerTest SessionTokenVerifierTest HwidDialogTest LoginWindowUiTest WindowTitleBarTest)
    set_tests_properties(${test_name} PROPERTIES
        ENVIRONMENT "PATH=$<TARGET_FILE_DIR:Qt6::Core>\\;${OPENSSL_CRYPTO_RUNTIME_DIR}\\;$ENV{PATH}")
endforeach()
set_property(TEST HwidDialogTest APPEND PROPERTY ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
set_property(TEST LoginWindowUiTest APPEND PROPERTY ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
set_property(TEST WindowTitleBarTest APPEND PROPERTY ENVIRONMENT "QT_QPA_PLATFORM=offscreen")

set_target_properties(LicenseClient PROPERTIES
    AUTOUIC_SEARCH_PATHS "${CMAKE_CURRENT_SOURCE_DIR}/ui"
)

set_target_properties(HwidDialogTest PROPERTIES
    AUTOUIC_SEARCH_PATHS "${CMAKE_CURRENT_SOURCE_DIR}/ui"
)

set_target_properties(LoginWindowUiTest PROPERTIES
    AUTOUIC_SEARCH_PATHS "${CMAKE_CURRENT_SOURCE_DIR}/ui"
)

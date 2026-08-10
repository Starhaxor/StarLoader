find_package(OpenSSL REQUIRED COMPONENTS Crypto)

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
)

target_link_libraries(ApiClientTest PRIVATE Qt6::Core Qt6::Network Qt6::Test)
target_link_libraries(AuthManagerTest PRIVATE DeviceIdentityShared Qt6::Core Qt6::Network Qt6::Test OpenSSL::Crypto)
target_link_libraries(SessionTokenVerifierTest PRIVATE Qt6::Core Qt6::Test OpenSSL::Crypto)

target_include_directories(ApiClientTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_include_directories(AuthManagerTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/shared)
target_include_directories(SessionTokenVerifierTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_test(NAME ApiClientTest COMMAND ApiClientTest)
add_test(NAME AuthManagerTest COMMAND AuthManagerTest)
add_test(NAME SessionTokenVerifierTest COMMAND SessionTokenVerifierTest)
foreach(test_name IN ITEMS ApiClientTest AuthManagerTest SessionTokenVerifierTest)
    set_tests_properties(${test_name} PROPERTIES
        ENVIRONMENT "PATH=$<TARGET_FILE_DIR:Qt6::Core>\\;${OPENSSL_CRYPTO_RUNTIME_DIR}\\;$ENV{PATH}")
endforeach()

set_target_properties(LicenseClient PROPERTIES
    AUTOUIC_SEARCH_PATHS "${CMAKE_CURRENT_SOURCE_DIR}/ui"
)

function(parent_configure_arguments output)
    set(arguments)
    set(without_prefix_path FALSE)
    if(ARGC GREATER 1 AND "${ARGV1}" STREQUAL "WITHOUT_PREFIX_PATH")
        set(without_prefix_path TRUE)
    endif()
    if(NOT "${STARLOADER_CMAKE_GENERATOR}" STREQUAL "")
        list(APPEND arguments -G "${STARLOADER_CMAKE_GENERATOR}")
    endif()
    if(NOT "${STARLOADER_CMAKE_GENERATOR_PLATFORM}" STREQUAL "")
        list(APPEND arguments -A "${STARLOADER_CMAKE_GENERATOR_PLATFORM}")
    endif()
    if(NOT "${STARLOADER_CMAKE_GENERATOR_TOOLSET}" STREQUAL "")
        list(APPEND arguments -T "${STARLOADER_CMAKE_GENERATOR_TOOLSET}")
    endif()
    foreach(variable IN ITEMS
            CMAKE_MAKE_PROGRAM
            CMAKE_C_COMPILER
            CMAKE_CXX_COMPILER
            CMAKE_AR
            CMAKE_RANLIB
            CMAKE_TOOLCHAIN_FILE
            CMAKE_PREFIX_PATH
            OPENSSL_ROOT_DIR)
        if(without_prefix_path AND variable STREQUAL "CMAKE_PREFIX_PATH")
            continue()
        endif()
        set(value "${STARLOADER_${variable}}")
        if(NOT "${value}" STREQUAL "")
            list(APPEND arguments "-D${variable}=${value}")
        endif()
    endforeach()
    if(NOT "${STARLOADER_QT6_DIR}" STREQUAL "")
        list(APPEND arguments "-DQt6_DIR=${STARLOADER_QT6_DIR}")
    endif()
    set(${output} "${arguments}" PARENT_SCOPE)
endfunction()

function(configure_protected_with_qt6_dir_only binary_dir expected_message)
    parent_configure_arguments(configure_arguments WITHOUT_PREFIX_PATH)
    execute_process(
        COMMAND "${STARLOADER_CMAKE_COMMAND}"
            -S "${STARLOADER_SOURCE_DIR}"
            -B "${binary_dir}"
            ${configure_arguments}
            -DCMAKE_BUILD_TYPE=Release
            -DSTARLOADER_LOCAL_DEVELOPMENT=OFF
            -DSTARLOADER_API_URL=https://api.example.test
            -DSTARLOADER_TLS_PINNED_HOST=api.example.test
            -DSTARLOADER_TLS_SPKI_PINS=sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=,sha256/AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
            -DSTARLOADER_ED25519_KEY_RING=local-test=e/40nbaaIxXaqAopnL6j/M0w7WeF70Nk8uIij1nr5SQ=
            -DSTARLOADER_APPLICATION_ID=01a04caa-baa0-72ec-9b69-b4ba548bb3e5
            -DSTARLOADER_PRODUCT_ID=starloader
            -DSTARLOADER_PUBLISHABLE_KEY=ks_pk_test_3MQ61B26VW_l7Xh56LE9PuaGEAZz1YD0hsJoe_myOKLPWnPtS9dxbQ
            -DSTARLOADER_PROTECTED_RELEASE=ON
        RESULT_VARIABLE configure_result
        OUTPUT_VARIABLE configure_stdout
        ERROR_VARIABLE configure_stderr)
    if(configure_result EQUAL 0 OR NOT "${configure_stdout}${configure_stderr}" MATCHES "${expected_message}")
        message(FATAL_ERROR "Protected-release configuration with only Qt6_DIR did not reach: ${expected_message}")
    endif()
endfunction()

function(configure_protected binary_dir expected_message)
    parent_configure_arguments(configure_arguments)
    execute_process(
        COMMAND "${STARLOADER_CMAKE_COMMAND}"
            -S "${STARLOADER_SOURCE_DIR}"
            -B "${binary_dir}"
            ${configure_arguments}
            -DCMAKE_BUILD_TYPE=Release
            -DSTARLOADER_LOCAL_DEVELOPMENT=OFF
            -DSTARLOADER_API_URL=https://api.example.test
            -DSTARLOADER_TLS_PINNED_HOST=api.example.test
            -DSTARLOADER_TLS_SPKI_PINS=sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=,sha256/AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
            -DSTARLOADER_ED25519_KEY_RING=local-test=e/40nbaaIxXaqAopnL6j/M0w7WeF70Nk8uIij1nr5SQ=
            -DSTARLOADER_APPLICATION_ID=01a04caa-baa0-72ec-9b69-b4ba548bb3e5
            -DSTARLOADER_PRODUCT_ID=starloader
            -DSTARLOADER_PUBLISHABLE_KEY=ks_pk_test_3MQ61B26VW_l7Xh56LE9PuaGEAZz1YD0hsJoe_myOKLPWnPtS9dxbQ
            -DSTARLOADER_PROTECTED_RELEASE=ON
            ${ARGN}
        RESULT_VARIABLE configure_result
        OUTPUT_VARIABLE configure_stdout
        ERROR_VARIABLE configure_stderr)
    if(configure_result EQUAL 0)
        message(FATAL_ERROR "Protected-release configuration unexpectedly succeeded.")
    endif()
    if(NOT "${configure_stdout}${configure_stderr}" MATCHES "${expected_message}")
        message(FATAL_ERROR "Protected-release configuration failed without the expected diagnostic: ${expected_message}")
    endif()
endfunction()

function(configure_protected_debug binary_dir expected_message)
    parent_configure_arguments(configure_arguments)
    execute_process(
        COMMAND "${STARLOADER_CMAKE_COMMAND}"
            -S "${STARLOADER_SOURCE_DIR}"
            -B "${binary_dir}"
            ${configure_arguments}
            -DCMAKE_BUILD_TYPE=Debug
            -DSTARLOADER_LOCAL_DEVELOPMENT=OFF
            -DSTARLOADER_API_URL=https://api.example.test
            -DSTARLOADER_TLS_PINNED_HOST=api.example.test
            -DSTARLOADER_TLS_SPKI_PINS=sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=,sha256/AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
            -DSTARLOADER_ED25519_KEY_RING=local-test=e/40nbaaIxXaqAopnL6j/M0w7WeF70Nk8uIij1nr5SQ=
            -DSTARLOADER_APPLICATION_ID=01a04caa-baa0-72ec-9b69-b4ba548bb3e5
            -DSTARLOADER_PRODUCT_ID=starloader
            -DSTARLOADER_PUBLISHABLE_KEY=ks_pk_test_3MQ61B26VW_l7Xh56LE9PuaGEAZz1YD0hsJoe_myOKLPWnPtS9dxbQ
            -DSTARLOADER_PROTECTED_RELEASE=ON
        RESULT_VARIABLE configure_result
        OUTPUT_VARIABLE configure_stdout
        ERROR_VARIABLE configure_stderr)
    if(configure_result EQUAL 0 OR NOT "${configure_stdout}${configure_stderr}" MATCHES "${expected_message}")
        message(FATAL_ERROR "Protected-release Debug configuration was not rejected with: ${expected_message}")
    endif()
endfunction()

function(configure_protected_local binary_dir)
    parent_configure_arguments(configure_arguments)
    execute_process(
        COMMAND "${STARLOADER_CMAKE_COMMAND}" -S "${STARLOADER_SOURCE_DIR}" -B "${binary_dir}"
            ${configure_arguments}
            -DCMAKE_BUILD_TYPE=Release
            -DSTARLOADER_LOCAL_DEVELOPMENT=ON
            -DSTARLOADER_API_URL=http://127.0.0.1:8080
            -DSTARLOADER_TLS_PINNED_HOST=127.0.0.1
            -DSTARLOADER_TLS_SPKI_PINS=
            -DSTARLOADER_ED25519_KEY_RING=local-test=e/40nbaaIxXaqAopnL6j/M0w7WeF70Nk8uIij1nr5SQ=
            -DSTARLOADER_APPLICATION_ID=01a04caa-baa0-72ec-9b69-b4ba548bb3e5
            -DSTARLOADER_PRODUCT_ID=starloader
            -DSTARLOADER_PUBLISHABLE_KEY=ks_pk_test_3MQ61B26VW_l7Xh56LE9PuaGEAZz1YD0hsJoe_myOKLPWnPtS9dxbQ
            -DSTARLOADER_PROTECTED_RELEASE=ON
        RESULT_VARIABLE configure_result OUTPUT_VARIABLE configure_stdout ERROR_VARIABLE configure_stderr)
    if(configure_result EQUAL 0 OR NOT "${configure_stdout}${configure_stderr}" MATCHES "incompatible with[\r\n ]+STARLOADER_LOCAL_DEVELOPMENT")
        message(FATAL_ERROR "Protected release did not reject local-development mode.\n${configure_stdout}\n${configure_stderr}")
    endif()
endfunction()

file(REMOVE_RECURSE "${STARLOADER_TEST_BINARY_DIR}")
configure_protected_local("${STARLOADER_TEST_BINARY_DIR}/protected-local")
configure_protected_debug(
    "${STARLOADER_TEST_BINARY_DIR}/debug"
    "CMAKE_BUILD_TYPE=Release")
configure_protected(
    "${STARLOADER_TEST_BINARY_DIR}/missing-sdk"
    "STARLOADER_VMPROTECT_SDK_INCLUDE_DIR")
configure_protected_with_qt6_dir_only(
    "${STARLOADER_TEST_BINARY_DIR}/qt6-dir-only"
    "STARLOADER_VMPROTECT_SDK_INCLUDE_DIR")

set(fake_sdk_dir "${STARLOADER_TEST_BINARY_DIR}/fake-sdk")
set(fake_project "${STARLOADER_TEST_BINARY_DIR}/fake-project.vmp")
set(fake_library_source "${STARLOADER_TEST_BINARY_DIR}/fake-library-source")
set(fake_library_build "${STARLOADER_TEST_BINARY_DIR}/fake-library-build")
file(MAKE_DIRECTORY "${fake_sdk_dir}" "${fake_library_source}")
file(WRITE "${fake_sdk_dir}/VMProtectSDK.h" [=[
#pragma once
extern "C" {
void VMProtectBeginVirtualization(const char *name);
void VMProtectBeginMutation(const char *name);
void VMProtectEnd();
}
]=])
file(WRITE "${fake_project}" "test-only VMProtect project fixture\n")
file(WRITE "${fake_library_source}/CMakeLists.txt" [=[
cmake_minimum_required(VERSION 3.21)
project(VMProtectFixture LANGUAGES CXX)
add_library(vmprotect_fixture STATIC VMProtectSDK.cpp)
]=])
file(WRITE "${fake_library_source}/VMProtectSDK.cpp" [=[
#include "VMProtectSDK.h"
extern "C" void VMProtectBeginVirtualization(const char *) {}
extern "C" void VMProtectBeginMutation(const char *) {}
extern "C" void VMProtectEnd() {}
]=])
file(COPY "${fake_sdk_dir}/VMProtectSDK.h" DESTINATION "${fake_library_source}")

configure_protected(
    "${STARLOADER_TEST_BINARY_DIR}/missing-library"
    "STARLOADER_VMPROTECT_SDK_LIBRARY"
    "-DSTARLOADER_VMPROTECT_SDK_INCLUDE_DIR=${fake_sdk_dir}"
    "-DSTARLOADER_VMPROTECT_PROJECT_FILE=${fake_project}")
configure_protected(
    "${STARLOADER_TEST_BINARY_DIR}/nonexistent-library"
    "STARLOADER_VMPROTECT_SDK_LIBRARY"
    "-DSTARLOADER_VMPROTECT_SDK_INCLUDE_DIR=${fake_sdk_dir}"
    "-DSTARLOADER_VMPROTECT_SDK_LIBRARY=${STARLOADER_TEST_BINARY_DIR}/missing-vmprotect.lib"
    "-DSTARLOADER_VMPROTECT_PROJECT_FILE=${fake_project}")

parent_configure_arguments(fake_library_configure_arguments)
execute_process(
    COMMAND "${STARLOADER_CMAKE_COMMAND}"
        -S "${fake_library_source}"
        -B "${fake_library_build}"
        ${fake_library_configure_arguments}
        -DCMAKE_BUILD_TYPE=Release
    RESULT_VARIABLE fake_library_configure_result)
if(NOT fake_library_configure_result EQUAL 0)
    message(FATAL_ERROR "Could not configure the fake VMProtect library fixture.")
endif()
execute_process(
    COMMAND "${STARLOADER_CMAKE_COMMAND}" --build "${fake_library_build}" --config Release
    RESULT_VARIABLE fake_library_build_result)
if(NOT fake_library_build_result EQUAL 0)
    message(FATAL_ERROR "Could not build the fake VMProtect library fixture.")
endif()
file(GLOB_RECURSE fake_library_candidates
    "${fake_library_build}/vmprotect_fixture.lib"
    "${fake_library_build}/libvmprotect_fixture.a")
list(LENGTH fake_library_candidates fake_library_count)
if(NOT fake_library_count EQUAL 1)
    message(FATAL_ERROR "Fake VMProtect library fixture did not produce exactly one static library.")
endif()
list(GET fake_library_candidates 0 fake_library)

configure_protected(
    "${STARLOADER_TEST_BINARY_DIR}/missing-project"
    "STARLOADER_VMPROTECT_PROJECT_FILE"
    "-DSTARLOADER_VMPROTECT_SDK_INCLUDE_DIR=${fake_sdk_dir}"
    "-DSTARLOADER_VMPROTECT_SDK_LIBRARY=${fake_library}")

parent_configure_arguments(positive_configure_arguments)
execute_process(
    COMMAND "${STARLOADER_CMAKE_COMMAND}"
        -S "${STARLOADER_SOURCE_DIR}"
        -B "${STARLOADER_TEST_BINARY_DIR}/positive"
        ${positive_configure_arguments}
        -DCMAKE_BUILD_TYPE=Release
        -DSTARLOADER_LOCAL_DEVELOPMENT=OFF
        -DSTARLOADER_API_URL=https://api.example.test
        -DSTARLOADER_TLS_PINNED_HOST=api.example.test
        -DSTARLOADER_TLS_SPKI_PINS=sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=,sha256/AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
        -DSTARLOADER_ED25519_KEY_RING=local-test=e/40nbaaIxXaqAopnL6j/M0w7WeF70Nk8uIij1nr5SQ=
        -DSTARLOADER_APPLICATION_ID=01a04caa-baa0-72ec-9b69-b4ba548bb3e5
        -DSTARLOADER_PRODUCT_ID=starloader
        -DSTARLOADER_PUBLISHABLE_KEY=ks_pk_test_3MQ61B26VW_l7Xh56LE9PuaGEAZz1YD0hsJoe_myOKLPWnPtS9dxbQ
        -DSTARLOADER_PROTECTED_RELEASE=ON
        "-DSTARLOADER_VMPROTECT_SDK_INCLUDE_DIR=${fake_sdk_dir}"
        "-DSTARLOADER_VMPROTECT_SDK_LIBRARY=${fake_library}"
        "-DSTARLOADER_VMPROTECT_PROJECT_FILE=${fake_project}"
    RESULT_VARIABLE positive_configure_result)
if(NOT positive_configure_result EQUAL 0)
    message(FATAL_ERROR "Protected-release configuration with the fake VMProtect SDK failed.")
endif()
execute_process(
    COMMAND "${STARLOADER_CMAKE_COMMAND}" --build "${STARLOADER_TEST_BINARY_DIR}/positive" --target ProtectionMarkersTest --config Release
    RESULT_VARIABLE positive_build_result)
if(NOT positive_build_result EQUAL 0)
    message(FATAL_ERROR "Protected VMProtect marker compilation/link fixture failed.")
endif()

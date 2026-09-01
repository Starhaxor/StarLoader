function(configure_without_vmprotect_project binary_dir expected_message)
    execute_process(
        COMMAND "${STARLOADER_CMAKE_COMMAND}"
            -S "${STARLOADER_SOURCE_DIR}"
            -B "${binary_dir}"
            -G Ninja
            "-DCMAKE_PREFIX_PATH=${STARLOADER_CMAKE_PREFIX_PATH}"
            "-DOPENSSL_ROOT_DIR=${STARLOADER_OPENSSL_ROOT_DIR}"
            -DSTARLOADER_LOCAL_DEVELOPMENT=ON
            -DSTARLOADER_API_URL=http://127.0.0.1:8080
            -DSTARLOADER_TLS_PINNED_HOST=127.0.0.1
            -DSTARLOADER_TLS_SPKI_PINS=
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

file(REMOVE_RECURSE "${STARLOADER_TEST_BINARY_DIR}")
configure_without_vmprotect_project(
    "${STARLOADER_TEST_BINARY_DIR}/missing-sdk"
    "STARLOADER_VMPROTECT_SDK_INCLUDE_DIR")

set(fake_sdk_dir "${STARLOADER_TEST_BINARY_DIR}/fake-sdk")
set(fake_library "${STARLOADER_TEST_BINARY_DIR}/VMProtectSDK.lib")
file(MAKE_DIRECTORY "${fake_sdk_dir}")
file(WRITE "${fake_sdk_dir}/VMProtectSDK.h" "// Test-only configuration fixture.\n")
file(WRITE "${fake_library}" "test-only fixture")
configure_without_vmprotect_project(
    "${STARLOADER_TEST_BINARY_DIR}/missing-project"
    "STARLOADER_VMPROTECT_PROJECT_FILE"
    "-DSTARLOADER_VMPROTECT_SDK_INCLUDE_DIR=${fake_sdk_dir}"
    "-DSTARLOADER_VMPROTECT_SDK_LIBRARY=${fake_library}")

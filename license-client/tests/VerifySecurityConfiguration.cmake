function(configure_rejected name expected_message api_url host pins)
    set(binary_dir "${STARLOADER_TEST_BINARY_DIR}/${name}")
    file(REMOVE_RECURSE "${binary_dir}")
    set(arguments)
    if(NOT "${STARLOADER_CMAKE_GENERATOR}" STREQUAL "")
        list(APPEND arguments -G "${STARLOADER_CMAKE_GENERATOR}")
    endif()
    foreach(variable IN ITEMS CMAKE_MAKE_PROGRAM CMAKE_C_COMPILER CMAKE_CXX_COMPILER
            CMAKE_AR CMAKE_RANLIB CMAKE_TOOLCHAIN_FILE CMAKE_PREFIX_PATH OPENSSL_ROOT_DIR)
        if(NOT "${STARLOADER_${variable}}" STREQUAL "")
            list(APPEND arguments "-D${variable}=${STARLOADER_${variable}}")
        endif()
    endforeach()
    execute_process(
        COMMAND "${STARLOADER_CMAKE_COMMAND}" -S "${STARLOADER_SOURCE_DIR}" -B "${binary_dir}"
            ${arguments}
            -DCMAKE_BUILD_TYPE=Release
            -DSTARLOADER_LOCAL_DEVELOPMENT=OFF
            "-DSTARLOADER_API_URL=${api_url}"
            "-DSTARLOADER_TLS_PINNED_HOST=${host}"
            "-DSTARLOADER_TLS_SPKI_PINS=${pins}"
            -DSTARLOADER_ED25519_KEY_RING=local-test=e/40nbaaIxXaqAopnL6j/M0w7WeF70Nk8uIij1nr5SQ=
            -DSTARLOADER_APPLICATION_ID=01a04caa-baa0-72ec-9b69-b4ba548bb3e5
            -DSTARLOADER_PRODUCT_ID=starloader
            -DSTARLOADER_PUBLISHABLE_KEY=ks_pk_test_3MQ61B26VW_l7Xh56LE9PuaGEAZz1YD0hsJoe_myOKLPWnPtS9dxbQ
        RESULT_VARIABLE result OUTPUT_VARIABLE stdout ERROR_VARIABLE stderr)
    if(result EQUAL 0 OR NOT "${stdout}${stderr}" MATCHES "${expected_message}")
        message(FATAL_ERROR "${name} did not fail with expected diagnostic: ${expected_message}")
    endif()
endfunction()

set(pin_a "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
set(pin_b "sha256/AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=")
set(pin_c "sha256/AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=")
configure_rejected(missing-pins "exactly two pins" "https://api.example.test" "api.example.test" "")
configure_rejected(one-pin "exactly two pins" "https://api.example.test" "api.example.test" "${pin_a}")
configure_rejected(duplicate-pins "must be distinct" "https://api.example.test" "api.example.test" "${pin_a},${pin_a}")
configure_rejected(third-pin "exactly two pins" "https://api.example.test" "api.example.test" "${pin_a},${pin_b},${pin_c}")
configure_rejected(malformed-pin "canonical-standard-base64" "https://api.example.test" "api.example.test" "sha256/not-base64,${pin_b}")
configure_rejected(host-mismatch "host must match" "https://other.example.test" "api.example.test" "${pin_a},${pin_b}")

set(binary_dir "${STARLOADER_TEST_BINARY_DIR}/bundled-openssl")
file(REMOVE_RECURSE "${binary_dir}")

set(configure_arguments)
if(NOT "${STARLOADER_CMAKE_GENERATOR}" STREQUAL "")
    list(APPEND configure_arguments -G "${STARLOADER_CMAKE_GENERATOR}")
endif()
foreach(variable IN ITEMS
        CMAKE_MAKE_PROGRAM
        CMAKE_C_COMPILER
        CMAKE_CXX_COMPILER
        CMAKE_AR
        CMAKE_RANLIB
        CMAKE_TOOLCHAIN_FILE
        CMAKE_PREFIX_PATH)
    if(NOT "${STARLOADER_${variable}}" STREQUAL "")
        list(APPEND configure_arguments "-D${variable}=${STARLOADER_${variable}}")
    endif()
endforeach()

# Qt Creator configures a kit without project presets.  The bundled OpenSSL
# installation must therefore be discovered without OPENSSL_ROOT_DIR.
execute_process(
    COMMAND "${STARLOADER_CMAKE_COMMAND}"
        -S "${STARLOADER_SOURCE_DIR}"
        -B "${binary_dir}"
        ${configure_arguments}
        -DCMAKE_BUILD_TYPE=Debug
        -DSTARLOADER_PRODUCT_ID=security-verification
    RESULT_VARIABLE configure_result
    OUTPUT_VARIABLE configure_stdout
    ERROR_VARIABLE configure_stderr)

if(NOT configure_result EQUAL 0)
    message(FATAL_ERROR "A Qt Creator-style configuration without OPENSSL_ROOT_DIR must discover the bundled OpenSSL installation.\n${configure_stdout}\n${configure_stderr}")
endif()

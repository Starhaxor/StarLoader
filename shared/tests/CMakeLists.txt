qt_add_executable(SharedTests
    FingerprintTest.cpp
)

target_link_libraries(SharedTests PRIVATE
    DeviceIdentityShared
    Qt6::Core
    Qt6::Test
)

add_test(NAME FingerprintTest COMMAND SharedTests)

set_tests_properties(FingerprintTest PROPERTIES
    ENVIRONMENT "PATH=$<TARGET_FILE_DIR:Qt6::Core>\\;$ENV{PATH}"
)

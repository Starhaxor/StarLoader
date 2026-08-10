qt_add_executable(SharedTests
    FingerprintTest.cpp
)

qt_add_executable(SmbiosParserTest
    SmbiosParserTest.cpp
)

qt_add_executable(HardwareCollectorTest
    HardwareCollectorTest.cpp
)

qt_add_executable(TpmIdentityTest
    TpmIdentityTest.cpp
)

qt_add_executable(HardwareJsonTest
    HardwareJsonTest.cpp
)

target_link_libraries(SharedTests PRIVATE
    DeviceIdentityShared
    Qt6::Core
    Qt6::Test
)

target_link_libraries(SmbiosParserTest PRIVATE
    DeviceIdentityShared
    Qt6::Core
    Qt6::Test
)

target_link_libraries(HardwareCollectorTest PRIVATE
    DeviceIdentityShared
    Qt6::Core
    Qt6::Test
)

target_link_libraries(TpmIdentityTest PRIVATE
    DeviceIdentityShared
    Qt6::Core
    Qt6::Test
)

target_link_libraries(HardwareJsonTest PRIVATE
    DeviceIdentityShared
    Qt6::Core
    Qt6::Test
)

add_test(NAME FingerprintTest COMMAND SharedTests)
add_test(NAME SmbiosParserTest COMMAND SmbiosParserTest)
add_test(NAME HardwareCollectorTest COMMAND HardwareCollectorTest)
add_test(NAME TpmIdentityTest COMMAND TpmIdentityTest)
add_test(NAME HardwareJsonTest COMMAND HardwareJsonTest)

set_tests_properties(FingerprintTest PROPERTIES
    ENVIRONMENT "PATH=$<TARGET_FILE_DIR:Qt6::Core>\\;$ENV{PATH}"
)

set_tests_properties(SmbiosParserTest PROPERTIES
    ENVIRONMENT "PATH=$<TARGET_FILE_DIR:Qt6::Core>\\;$ENV{PATH}"
)

set_tests_properties(HardwareCollectorTest PROPERTIES
    ENVIRONMENT "PATH=$<TARGET_FILE_DIR:Qt6::Core>\\;$ENV{PATH}"
)

set_tests_properties(TpmIdentityTest PROPERTIES
    ENVIRONMENT "PATH=$<TARGET_FILE_DIR:Qt6::Core>\\;$ENV{PATH}"
)

set_tests_properties(HardwareJsonTest PROPERTIES
    ENVIRONMENT "PATH=$<TARGET_FILE_DIR:Qt6::Core>\\;$ENV{PATH}"
)

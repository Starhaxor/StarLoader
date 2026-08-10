qt_add_executable(SharedTests
    BuildSmokeTest.cpp
)

target_link_libraries(SharedTests PRIVATE
    Qt6::Core
    Qt6::Test
)

add_test(NAME SharedTests COMMAND SharedTests)

set_tests_properties(SharedTests PROPERTIES
    ENVIRONMENT "PATH=$<TARGET_FILE_DIR:Qt6::Core>\\;$ENV{PATH}"
)

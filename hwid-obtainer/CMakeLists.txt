qt_add_executable(HwidObtainer WIN32
    src/main.cpp
    src/DiagnosticPresentation.cpp
    src/DiagnosticPresentation.h
    src/MainWindow.cpp
    src/MainWindow.h
    ui/MainWindow.ui
)

set_target_properties(HwidObtainer PROPERTIES
    AUTOUIC_SEARCH_PATHS "${CMAKE_CURRENT_SOURCE_DIR}/ui"
)

target_link_libraries(HwidObtainer PRIVATE
    DeviceIdentityShared
    Qt6::Core
    Qt6::Widgets
    Qt6::Concurrent
)

if(STARLOADER_STATIC AND TARGET Qt6::QWindowsIntegrationPlugin)
    target_link_libraries(HwidObtainer PRIVATE Qt6::QWindowsIntegrationPlugin)
endif()

qt_add_executable(HwidObtainerPresentationTest
    src/DiagnosticPresentation.cpp
    src/DiagnosticPresentation.h
    tests/DiagnosticPresentationTest.cpp
)

target_link_libraries(HwidObtainerPresentationTest PRIVATE
    Qt6::Core
    Qt6::Test
)

target_include_directories(HwidObtainerPresentationTest PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

add_test(NAME HwidObtainerPresentationTest COMMAND HwidObtainerPresentationTest)
set_tests_properties(HwidObtainerPresentationTest PROPERTIES
    ENVIRONMENT "PATH=$<TARGET_FILE_DIR:Qt6::Core>\\;$ENV{PATH}"
)

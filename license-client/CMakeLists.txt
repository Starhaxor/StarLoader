qt_add_executable(LicenseClient WIN32
    src/main.cpp
    src/ui/LoginWindow.cpp
    src/ui/LoginWindow.h
    ui/LoginWindow.ui
    src/ui/HwidDialog.cpp
    src/ui/HwidDialog.h
    ui/HwidDialog.ui
)

target_link_libraries(LicenseClient PRIVATE
    DeviceIdentityShared
    Qt6::Core
    Qt6::Widgets
    Qt6::Network
    Qt6::Concurrent
)

set_target_properties(LicenseClient PROPERTIES
    AUTOUIC_SEARCH_PATHS "${CMAKE_CURRENT_SOURCE_DIR}/ui"
)

qt_add_executable(HwidObtainer WIN32
    src/main.cpp
    src/MainWindow.cpp
    src/MainWindow.h
)

target_link_libraries(HwidObtainer PRIVATE
    DeviceIdentityShared
    Qt6::Core
    Qt6::Widgets
)

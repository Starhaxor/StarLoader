add_library(DeviceIdentityShared STATIC
    DeviceIdentity.cpp
)

target_include_directories(DeviceIdentityShared PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(DeviceIdentityShared PUBLIC
    Qt6::Core
    Qt6::Network
)

add_subdirectory(tests)

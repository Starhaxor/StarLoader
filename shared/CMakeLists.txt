add_library(DeviceIdentityShared STATIC
    DeviceIdentity.cpp
    hardware/DiskReader.cpp
    hardware/HardwareCollector.cpp
    hardware/RegistryReader.cpp
    hardware/SmbiosParser.cpp
    hardware/SmbiosReader.cpp
    security/Fingerprint.cpp
    security/HardwareNormalization.cpp
)

target_include_directories(DeviceIdentityShared PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(DeviceIdentityShared PUBLIC
    Qt6::Core
    Qt6::Network
)

if(WIN32)
    target_link_libraries(DeviceIdentityShared PRIVATE Advapi32)
endif()

add_subdirectory(tests)

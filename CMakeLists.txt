cmake_minimum_required(VERSION 3.16)
project(LicenseSystem LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Network Concurrent Test)

enable_testing()

add_subdirectory(shared)
add_subdirectory(hwid-obtainer)
add_subdirectory(license-client)


cmake_minimum_required(VERSION 3.16)
project(ModernLogin LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Widgets)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Widgets)

add_executable(ModernLogin WIN32
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
    hwiddialog.cpp
    hwiddialog.h
    hwiddialog.ui
)

target_link_libraries(ModernLogin PRIVATE Qt${QT_VERSION_MAJOR}::Widgets)


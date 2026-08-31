cmake_minimum_required(VERSION 3.16)
project(LicenseSystem LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

# ── Ortak static ayarlar (StarInjector ile ayni dosya) ───────────────────────
if(EXISTS "C:/Qt/static-settings.cmake")
    include("C:/Qt/static-settings.cmake")
endif()
option(STARLOADER_STATIC "Statik Qt + statik MinGW runtime ile tek EXE" OFF)
if(CMAKE_PREFIX_PATH MATCHES "6-static")
    set(STARLOADER_STATIC ON)
endif()
if(STARLOADER_STATIC AND MINGW)
    add_link_options(-static -static-libgcc -static-libstdc++)
    message(STATUS "STARLOADER_STATIC=ON -> -static aktif")
endif()

# Qt Creator configures a kit with `cmake -S/-B` unless the project is opened
# through a CMake preset. Keep that default development path coherent and safe:
# when no API URL was supplied at all, use the numeric loopback KeyStar profile.
# Any explicit URL still has to satisfy the transport checks in license-client.
if(NOT DEFINED STARLOADER_API_URL OR STARLOADER_API_URL STREQUAL "")
    set(STARLOADER_LOCAL_DEVELOPMENT ON CACHE BOOL "Allow a numeric loopback HTTP API URL in an explicitly local build" FORCE)
    message(STATUS "STARLOADER_API_URL was not provided; using the local KeyStar development profile")
endif()

# A Qt Creator kit keeps CMake cache values across runs. Once the kit is a
# local-development build, refresh the complete profile together so stale
# production keys cannot be mixed with the local API and invalidate tokens.
if(STARLOADER_LOCAL_DEVELOPMENT)
    set(STARLOADER_API_URL "http://127.0.0.1:8080" CACHE STRING "KeyStar API base URL" FORCE)
    set(STARLOADER_APPLICATION_ID "01a04caa-baa0-72ec-9b69-b4ba548bb3e5" CACHE STRING "KeyStar application UUID used by the StarLoader client" FORCE)
    set(STARLOADER_PUBLISHABLE_KEY "ks_pk_test_3MQ61B26VW_l7Xh56LE9PuaGEAZz1YD0hsJoe_myOKLPWnPtS9dxbQ" CACHE STRING "KeyStar publishable API key used by the StarLoader client" FORCE)
    set(STARLOADER_ED25519_PUBLIC_KEY "e/40nbaaIxXaqAopnL6j/M0w7WeF70Nk8uIij1nr5SQ=" CACHE STRING "Canonical standard-base64 Ed25519 session-token public key" FORCE)
endif()

find_package(Qt6 REQUIRED COMPONENTS Core Widgets Network Concurrent Test)

enable_testing()

add_subdirectory(shared)
add_subdirectory(hwid-obtainer)
add_subdirectory(license-client)


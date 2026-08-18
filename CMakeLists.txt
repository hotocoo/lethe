cmake_minimum_required(VERSION 3.18)
project(lethe VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_WITH_SANDBOX "Enable renderer sandboxing" ON)
option(BUILD_HARDENED "Apply strict compiler hardening" ON)
option(USE_PREBUILT_CHROMIUM "Use prebuilt Chromium SDK" OFF)
option(USE_QT "Use Qt for UI (recommended)" OFF)
option(USE_GTK "Use GTK for UI (fallback)" ON)
option(BUILD_TESTS "Build test suite" ON)
option(BUILD_UI "Build the GUI application" ON)

if(APPLE)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "13.0")
    # Build for native architecture only (Homebrew libs may be single-arch).
    # Remove this line to build a universal binary if all deps support it.
endif()

if(BUILD_HARDENED)
    message(STATUS "[lethe] Building with hardened flags")
    add_compile_definitions(-D_FORTIFY_SOURCE=2)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -pipe -flto=auto -fstack-protector-strong -fvisibility=hidden -Wall -Wextra")
    endif()
endif()

add_compile_definitions(-DLETHE_VERSION="1.0.0")
add_compile_definitions(-DLETHE_MIN_TLS_VERSION=0x0304)
add_compile_definitions(-DLETHE_MAX_TLS_VERSION=0x0305)

# --- Find OpenSSL ---
# Prefer Homebrew on macOS.
if(APPLE)
    execute_process(COMMAND brew --prefix openssl@3
                    OUTPUT_VARIABLE OPENSSL_PREFIX
                    OUTPUT_STRIP_TRAILING_WHITESPACE
                    ERROR_QUIET)
    if(OPENSSL_PREFIX)
        set(OPENSSL_ROOT_DIR "${OPENSSL_PREFIX}" CACHE PATH "OpenSSL root")
        link_directories("${OPENSSL_PREFIX}/lib")
    endif()
endif()
find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

# --- Core library (no UI dependencies) ---
# This is the heart of Lethe: engine, network, VPN, security, LLM search,
# and the Aletheia bridge. It can be linked by the GUI app, tests, or the
# Aletheia OS integration.

file(GLOB_RECURSE SRC_CORE src/core/*.cc)
file(GLOB_RECURSE SRC_RENDERER src/renderer/*.cc)
file(GLOB_RECURSE SRC_BROWSER src/browser/*.cc)
file(GLOB_RECURSE SRC_SECURITY src/security/*.cc)
file(GLOB_RECURSE SRC_NETWORK src/network/*.cc)
file(GLOB_RECURSE SRC_LLM src/llm/*.cc)
file(GLOB_RECURSE SRC_ALETHEIA src/aletheia/*.cc)

add_library(lethe_core STATIC
    "${SRC_CORE}"
    "${SRC_RENDERER}"
    "${SRC_BROWSER}"
    "${SRC_SECURITY}"
    "${SRC_NETWORK}"
    "${SRC_LLM}"
    "${SRC_ALETHEIA}"
)

target_include_directories(lethe_core PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(lethe_core PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
)

if(BUILD_WITH_SANDBOX)
    target_compile_definitions(lethe_core PUBLIC -DLETHE_SANDBOXING)
endif()

# --- GUI application (optional) ---
if(BUILD_UI)
    if(USE_QT)
        find_package(Qt6 COMPONENTS Widgets Quick Controls2 QUIET)
        if(Qt6_FOUND)
            set(USE_QT6 TRUE)
            set(CMAKE_AUTOMOC ON)
            set(CMAKE_AUTORCC ON)
            set(CMAKE_AUTOUIC ON)
        endif()
    endif()

    if(NOT USE_QT6 AND USE_GTK)
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
            pkg_check_modules(GTK3 QUIET gtk+-3.0>=3.20)
            if(GTK3_FOUND)
                set(USE_GTK3 TRUE)
            endif()
        endif()
    endif()

    if(USE_QT6 OR USE_GTK3)
        message(STATUS "[lethe] Building GUI application")

        file(GLOB_RECURSE SRC_UI src/ui/*.cc)

        add_executable(lethe
            "browser/app/main.cc"
            "${SRC_UI}"
        )

        set_target_properties(lethe PROPERTIES
            MACOSX_BUNDLE TRUE
            MACOSX_BUNDLE_BUNDLE_NAME "Lethe"
            MACOSX_BUNDLE_IDENTIFIER "org.aletheia.lethe"
            WIN32_EXECUTABLE TRUE
        )

        target_include_directories(lethe PRIVATE
            ${CMAKE_SOURCE_DIR}/include
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/browser
        )

        target_link_libraries(lethe PRIVATE
            lethe_core
        )

        if(USE_QT6)
            target_compile_definitions(lethe PRIVATE -DUSE_QT6)
            target_link_libraries(lethe PRIVATE
                Qt6::Widgets
                Qt6::Quick
                Qt6::Controls2
            )
        endif()

        if(USE_GTK3)
            target_compile_definitions(lethe PRIVATE -DUSE_GTK3 -DHAVE_OPENSSL)
            target_link_libraries(lethe PRIVATE
                gtk-3
                gdk-3
                glib-2.0
                gio-2.0
            )
            target_include_directories(lethe PRIVATE ${GTK3_INCLUDE_DIRS})
        endif()

        if(APPLE)
            target_link_libraries(lethe PRIVATE
                "-framework Cocoa"
                "-framework AppKit"
                "-framework Foundation"
            )
        endif()

        install(TARGETS lethe DESTINATION bin)
    else()
        message(STATUS "[lethe] No UI framework found, skipping GUI application")
    endif()
endif()

# --- Tests ---
if(BUILD_TESTS)
    enable_testing()

    file(GLOB_RECURSE TEST_SOURCES tests/*.cc)

    add_executable(lethe_tests "${TEST_SOURCES}")
    target_include_directories(lethe_tests PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/tests
    )
    target_link_libraries(lethe_tests PRIVATE lethe_core)
    add_test(NAME LetheTests COMMAND lethe_tests)
endif()

if(UNIX)
    target_link_libraries(lethe_core PUBLIC pthread)
endif()

message(STATUS "[lethe] Build Configuration:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Sandbox: ${BUILD_WITH_SANDBOX}")
message(STATUS "  Hardened: ${BUILD_HARDENED}")
message(STATUS "  Tests: ${BUILD_TESTS}")
message(STATUS "  UI: ${BUILD_UI}")


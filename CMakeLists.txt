cmake_minimum_required(VERSION 3.18)
project(lethe VERSION 1.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_WITH_SANDBOX "Enable renderer sandboxing" ON)
option(BUILD_HARDENED "Apply strict compiler hardening" ON)
option(USE_PREBUILT_CHROMIUM "Use prebuilt Chromium SDK" OFF)
option(USE_QT "Use Qt for UI (recommended)" OFF)
option(USE_GTK "Use GTK for UI (fallback)" ON)
option(BUILD_TESTS "Build test suite" ON)
option(BUILD_UI "Build the GUI application" ON)
option(USE_FULLWEB "Embed the platform web engine for full-web mode" ON)

if(APPLE)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "13.0")
    # Build for native architecture only (Homebrew libs may be single-arch).
    # Remove this line to build a universal binary if all deps support it.
endif()

if(BUILD_HARDENED)
    message(STATUS "[lethe] Building with hardened flags")
    add_compile_definitions(-D_FORTIFY_SOURCE=2)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -pipe -fstack-protector-strong -fvisibility=hidden -Wall -Wextra")
        # Linux clang + LTO + static archives drops archive members at link
        # time (undefined refs to symbols the archive provably contains);
        # keep LTO on the GNU/Apple toolchains where it links reliably.
        if(CMAKE_CXX_COMPILER_ID MATCHES "GNU" OR APPLE)
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -flto=auto")
        endif()
    endif()
endif()

add_compile_definitions(-DLETHE_VERSION="1.1.0")
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

# OpenSSL is a hard requirement: expose it to all targets (core lib, tests,
# GUI) so TLS code paths are compiled and exercised.
add_compile_definitions(-DHAVE_OPENSSL)

# --- libseccomp (required on Linux for enforced sandboxing) ---
# src/security/sandbox.cc builds its default-deny filter through libseccomp.
# Fail loudly instead of silently shipping an unsandboxed browser.
if(UNIX AND NOT APPLE AND BUILD_WITH_SANDBOX)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(SECCOMP QUIET libseccomp)
    endif()
    if(NOT SECCOMP_FOUND)
        message(FATAL_ERROR
            "libseccomp development files are required on Linux for the "
            "enforced sandbox (BUILD_WITH_SANDBOX=ON). Install libseccomp-dev "
            "(Debian/Ubuntu) or libseccomp-devel (Fedora), or configure with "
            "-DBUILD_WITH_SANDBOX=OFF to build without sandboxing.")
    endif()
    message(STATUS "[lethe] libseccomp: ${SECCOMP_INCLUDE_DIRS} ${SECCOMP_LIBRARIES}")
endif()

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

if(SECCOMP_FOUND)
    target_include_directories(lethe_core PUBLIC ${SECCOMP_INCLUDE_DIRS})
    target_link_libraries(lethe_core PUBLIC ${SECCOMP_LIBRARIES})
endif()

if(BUILD_WITH_SANDBOX)
    target_compile_definitions(lethe_core PUBLIC -DLETHE_SANDBOXING)
endif()

# --- Reference VPN server (standalone, always built) ---
# A runnable UDP VPN server that the built-in VPN client connects to.
add_executable(lethe-vpn-server tools/vpn_server_main.cc)
target_link_libraries(lethe-vpn-server PRIVATE lethe_core)

# End-to-end VPN client (for verifying a running lethe-vpn-server).
add_executable(lethe-vpn-e2e-client tools/e2e_client.cc)

# Local throughput probe of the real HTTP stack (used by docs/COMPARISON.md).
add_executable(lethe-fetch-bench EXCLUDE_FROM_ALL tools/fetch_bench.cc)
target_link_libraries(lethe-fetch-bench PRIVATE lethe_core)
target_link_libraries(lethe-vpn-e2e-client PRIVATE lethe_core)

# Install the runnable network tools alongside the browser.
install(TARGETS lethe-vpn-server lethe-vpn-e2e-client DESTINATION bin)

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
            # IMPORTED_TARGET carries include dirs, library dirs, and libs,
            # so non-system installs (e.g. Homebrew) link correctly.
            pkg_check_modules(GTK3 QUIET IMPORTED_TARGET gtk+-3.0>=3.20)
            if(GTK3_FOUND)
                set(USE_GTK3 TRUE)
            endif()
        endif()
    endif()

    if(USE_QT6 OR USE_GTK3)
        message(STATUS "[lethe] Building GUI application")

        file(GLOB_RECURSE SRC_UI src/ui/*.cc)
# Backend-specific full-web sources are added by the USE_FULLWEB branch
# below; the generic glob must not leak them across platforms.
list(FILTER SRC_UI EXCLUDE REGEX "fullweb_gtk\.cc$")
list(FILTER SRC_UI EXCLUDE REGEX "fullweb_mac\.mm$")

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

        # --- Full-web mode: embed the platform web engine ---
        if(USE_FULLWEB)
            if(APPLE)
                message(STATUS "[lethe] full-web: APPLE branch (WKWebView)")
                enable_language(OBJCXX)
                find_library(WEBKIT_FRAMEWORK WebKit REQUIRED)
                target_sources(lethe PRIVATE src/ui/fullweb_mac.mm)
                set_source_files_properties(src/ui/fullweb_mac.mm
                    PROPERTIES LANGUAGE OBJCXX)
                target_compile_definitions(lethe PRIVATE HAVE_FULLWEB)
                target_link_libraries(lethe PRIVATE ${WEBKIT_FRAMEWORK})
            elseif(UNIX)
                find_package(PkgConfig QUIET)
                if(PkgConfig_FOUND)
                    pkg_check_modules(WEBKITGTK QUIET IMPORTED_TARGET webkit2gtk-4.1)
                    if(NOT WEBKITGTK_FOUND)
                        pkg_check_modules(WEBKITGTK QUIET IMPORTED_TARGET webkit2gtk-4.0)
                    endif()
                    if(WEBKITGTK_FOUND)
                        target_sources(lethe PRIVATE src/ui/fullweb_gtk.cc)
                        target_compile_definitions(lethe PRIVATE HAVE_FULLWEB)
                        target_link_libraries(lethe PRIVATE PkgConfig::WEBKITGTK)
                    else()
                        message(STATUS "[lethe] webkit2gtk not found - full-web mode disabled")
                    endif()
                endif()
            endif()
        endif()

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
                PkgConfig::GTK3
            )
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

# --- Windows: WebView2 full-web host (.exe) ---
# Built by the windows CI job (MSVC + WebView2 SDK via nuget). The POSIX
# core does not compile on Windows yet; this host enforces Lethe policy at
# the navigation layer and is honest about that in its header comment.
if(WIN32)
    add_executable(lethe-win WIN32 src/win/lethe_win.cpp)
    target_compile_definitions(lethe-win PRIVATE UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
    target_link_libraries(lethe-win PRIVATE user32 gdi32 shell32 shlwapi ws2_32 ole32 oleaut32 uuid)
    if(DEFINED WEBVIEW2_DIR AND EXISTS "${WEBVIEW2_DIR}/build/native/include/WebView2.h")
        target_include_directories(lethe-win PRIVATE "${WEBVIEW2_DIR}/build/native/include")
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            target_link_libraries(lethe-win PRIVATE "${WEBVIEW2_DIR}/build/native/x64/WebView2LoaderStatic.lib")
        else()
            target_link_libraries(lethe-win PRIVATE "${WEBVIEW2_DIR}/build/native/x86/WebView2LoaderStatic.lib")
        endif()
    else()
        message(STATUS "[lethe] WEBVIEW2_DIR not provided - lethe-win will not link WebView2")
    endif()
endif()

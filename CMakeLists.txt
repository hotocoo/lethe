cmake_minimum_required(VERSION 3.18)
project(lethe VERSION 1.3.3 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_WITH_SANDBOX "Enable renderer sandboxing" ON)
option(BUILD_HARDENED "Apply strict compiler hardening" ON)
option(USE_PREBUILT_CHROMIUM "Use prebuilt Chromium SDK" OFF)
option(BUILD_TESTS "Build test suite" ON)
if(WIN32)
    set(BUILD_TESTS OFF)
    set(BUILD_UI OFF)
    set(BUILD_WITH_SANDBOX OFF)
endif()
option(BUILD_UI "Build the GUI application" ON)
option(USE_FULLWEB "Embed the platform web engine for full-web mode" ON)
option(LETHE_WITH_CEF "Build the CEF (Chromium / Blink) shell alongside the WebKit one" OFF)

# Built-in tracker protection list -> embedded string constant. Edit
# browser/blocklist/trackers.txt; the binary picks it up on rebuild.
set(TRACKER_LIST_TXT "${CMAKE_SOURCE_DIR}/browser/blocklist/trackers.txt")
set(TRACKER_LIST_INC "${CMAKE_BINARY_DIR}/generated/security/tracker_blocklist_data.inc")
file(READ "${TRACKER_LIST_TXT}" TRACKER_LIST_CONTENT)
file(WRITE "${TRACKER_LIST_INC}.tmp"
    "// Generated from browser/blocklist/trackers.txt - do not edit.\n"
    "static const char kBuiltinTrackerBlocklistText[] = R\"LETHE_BL(\n${TRACKER_LIST_CONTENT})LETHE_BL\";\n")
configure_file("${TRACKER_LIST_INC}.tmp" "${TRACKER_LIST_INC}" COPYONLY)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${TRACKER_LIST_TXT}")

# ---------------------------------------------------------------------------
# Windows: ships ONLY the WebView2 full-web host (src/win/lethe_win.cpp).
# The POSIX core (sockets, Seatbelt/seccomp sandboxing) does not build there
# yet; early-return so no POSIX target is even configured.
# ---------------------------------------------------------------------------
if(WIN32)
    add_executable(lethe-win WIN32 src/win/lethe_win.cpp)
    target_compile_definitions(lethe-win PRIVATE
        UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
    target_include_directories(lethe-win PRIVATE ${CMAKE_BINARY_DIR}/generated)
    target_link_libraries(lethe-win PRIVATE
        user32 gdi32 shell32 shlwapi ws2_32 ole32 oleaut32 uuid comctl32)
    if(DEFINED WEBVIEW2_DIR AND EXISTS "${WEBVIEW2_DIR}/build/native/include/WebView2.h")
        target_include_directories(lethe-win PRIVATE
            "${WEBVIEW2_DIR}/build/native/include")
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            target_link_libraries(lethe-win PRIVATE
                "${WEBVIEW2_DIR}/build/native/x64/WebView2LoaderStatic.lib")
        else()
            target_link_libraries(lethe-win PRIVATE
                "${WEBVIEW2_DIR}/build/native/x86/WebView2LoaderStatic.lib")
        endif()
    else()
        message(FATAL_ERROR "WEBVIEW2_DIR must point at the extracted "
            "Microsoft.Web.WebView2 nuget package")
    endif()
    return()
endif()

if(APPLE)
    # WebKit transport enforcement is part of Lethe's security boundary.
    # WKWebsiteDataStore.proxyConfigurations is available from macOS 14;
    # shipping a macOS 13 fallback would silently reduce full-web traffic to
    # navigation-only policy enforcement. Require the API instead of
    # producing a browser whose subresources can bypass the policy proxy.
    set(CMAKE_OSX_DEPLOYMENT_TARGET "14.0")
    enable_language(OBJCXX)
    find_library(FOUNDATION_FRAMEWORK Foundation REQUIRED)
    find_library(METAL_FRAMEWORK Metal REQUIRED)
    find_library(METALFX_FRAMEWORK MetalFX REQUIRED)
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

add_compile_definitions(-DLETHE_VERSION="${PROJECT_VERSION}")
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
if(NOT WIN32)
    find_package(OpenSSL REQUIRED)
    find_package(ZLIB REQUIRED)
else()
    # Windows builds only the WebView2 host; the POSIX core is not compiled.
endif()

# OpenSSL is a hard requirement: expose it to all targets (core lib, tests,
# GUI) so TLS code paths are compiled and exercised.
if(NOT WIN32)
    add_compile_definitions(-DHAVE_OPENSSL)
endif()

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
file(GLOB_RECURSE SRC_PLUGINS src/plugins/*.cc)

add_library(lethe_core STATIC
    "${SRC_CORE}"
    "${SRC_RENDERER}"
    "${SRC_BROWSER}"
    "${SRC_SECURITY}"
    "${SRC_NETWORK}"
    "${SRC_LLM}"
    "${SRC_ALETHEIA}"
    "${SRC_PLUGINS}"
)

target_include_directories(lethe_core PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_BINARY_DIR}/generated
)

target_link_libraries(lethe_core PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
)

if(APPLE)
    target_sources(lethe_core PRIVATE src/renderer/media_upscaler.mm)
    target_link_libraries(lethe_core PUBLIC ${FOUNDATION_FRAMEWORK} ${METAL_FRAMEWORK} ${METALFX_FRAMEWORK})
endif()

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
if(BUILD_UI AND APPLE)
    # macOS: native AppKit shell around WKWebView. No GTK on this platform.
    message(STATUS "[lethe] Building GUI application (AppKit + WKWebView)")
    enable_language(OBJCXX)
    find_library(COCOA_FRAMEWORK Cocoa REQUIRED)
    find_library(WEBKIT_FRAMEWORK WebKit REQUIRED)
    find_library(NETWORK_FRAMEWORK Network REQUIRED)
    file(GLOB SRC_UI_MAC src/ui/mac/*.mm)
    add_executable(lethe MACOSX_BUNDLE browser/app/main_mac.mm browser/app/shell_bootstrap.cc ${SRC_UI_MAC})
    set_source_files_properties(browser/app/main_mac.mm ${SRC_UI_MAC}
        PROPERTIES LANGUAGE OBJCXX)
    target_compile_options(lethe PRIVATE -fobjc-arc)
    set_target_properties(lethe PROPERTIES
        MACOSX_BUNDLE TRUE
        MACOSX_BUNDLE_INFO_PLIST "${CMAKE_SOURCE_DIR}/browser/app/Info.plist.in"
        MACOSX_BUNDLE_BUNDLE_NAME "Lethe"
        MACOSX_BUNDLE_GUI_IDENTIFIER "org.aletheia.lethe"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
        MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
        MACOSX_BUNDLE_ICON_FILE "lethe.icns"
        OUTPUT_NAME "lethe"
    )
    # Bundle the app icon
    set_source_files_properties("${CMAKE_SOURCE_DIR}/browser/app/resources/lethe.icns"
        PROPERTIES MACOSX_PACKAGE_LOCATION "Resources")
    target_sources(lethe PRIVATE "${CMAKE_SOURCE_DIR}/browser/app/resources/lethe.icns")
    target_include_directories(lethe PRIVATE
        ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/browser)
    target_link_libraries(lethe PRIVATE lethe_core
        ${COCOA_FRAMEWORK} ${WEBKIT_FRAMEWORK} ${NETWORK_FRAMEWORK})
    install(TARGETS lethe BUNDLE DESTINATION .)

    if(LETHE_WITH_CEF)
        # CEF (Chromium / Blink) shell. Sibling app bundle to the WebKit
        # lethe.app. The build is gated on third_party/cef/ being populated
        # (the binary distribution from cefbuilds.com). When this option
        # is on, the configured tree compiles main_cef.mm and links against
        # the CEF framework in place.
        set(CEF_ROOT "${CMAKE_SOURCE_DIR}/third_party/cef" CACHE PATH
            "Path to the CEF binary distribution root (e.g. third_party/cef)")
        if(NOT EXISTS "${CEF_ROOT}/include/cef_version.h")
            message(FATAL_ERROR
                "LETHE_WITH_CEF=ON but ${CEF_ROOT}/include/cef_version.h is missing. "
                "Drop the CEF binary distribution (Chromium Embedded Framework.framework, "
                "include/, libcef_dll/) into third_party/cef/ and re-configure.")
        endif()
        message(STATUS "[lethe-cef] CEF root: ${CEF_ROOT}")
        # The CEF framework's Headers/ live inside the .framework bundle.
        # We use a SYMBOLIC include path so #include "include/cef_*.h" works
        # from C++ sources (CEF headers are authored with that prefix).
        add_executable(lethe-cef MACOSX_BUNDLE
            browser/app/main_cef.mm
            browser/app/cef_app_delegate.mm
            browser/app/cef_browser_client.mm
            browser/app/cef_chrome.mm
            browser/app/cef_automation.mm
            browser/app/cef_render_handler.mm
            browser/app/shell_bootstrap.cc
        )
        set_source_files_properties(
            browser/app/main_cef.mm
            browser/app/cef_app_delegate.mm
            browser/app/cef_browser_client.mm
            browser/app/cef_automation.mm
            browser/app/cef_render_handler.mm
            PROPERTIES LANGUAGE OBJCXX)
        target_compile_options(lethe-cef PRIVATE -fobjc-arc -Wno-deprecated-declarations)
        set_target_properties(lethe-cef PROPERTIES
            MACOSX_BUNDLE TRUE
            MACOSX_BUNDLE_INFO_PLIST "${CMAKE_SOURCE_DIR}/browser/app/Info.plist.in"
            MACOSX_BUNDLE_BUNDLE_NAME "Lethe (CEF)"
            MACOSX_BUNDLE_GUI_IDENTIFIER "org.aletheia.lethe.cef"
            MACOSX_BUNDLE_SHORT_VERSION_STRING "${PROJECT_VERSION}"
            MACOSX_BUNDLE_BUNDLE_VERSION "${PROJECT_VERSION}"
            OUTPUT_NAME "lethe-cef"
        )
        target_include_directories(lethe-cef PRIVATE
            ${CMAKE_SOURCE_DIR}/include
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/browser
            ${CEF_ROOT}                          # so "include/cef_*.h" works
            ${CEF_ROOT}/include
        )
        # libcef_dll is provided as a static lib via the CEF binary dist.
        # Some distros ship it at libcef_dll/libcef_dll.a; newer ones at
        # Release/libcef_dll.a. Try both.
        find_library(CEF_LIB NAMES cef HINTS "${CEF_ROOT}/Release")
        if(NOT CEF_LIB)
            find_library(CEF_LIB NAMES cef_dll HINTS "${CEF_ROOT}/libcef_dll")
        endif()
        if(NOT CEF_LIB)
            # Newer CEF builds ship a single dylib (Chromium Embedded Framework)
            # and no static lib. The framework itself is the link target.
            find_library(CEF_LIB
                NAMES "Chromium Embedded Framework"
                HINTS "${CEF_ROOT}/Release"
                NO_DEFAULT_PATH)
        endif()
        if(NOT CEF_LIB)
            message(FATAL_ERROR
                "Could not find a CEF library. Looked for libcef.dylib, "
                "libcef_dll.a, and Chromium Embedded Framework.framework "
                "under ${CEF_ROOT}.")
        endif()
        # The C++ wrapper glue: this is the static archive that resolves the
        # CefRefPtr / CefString / CefV8Value / CefBrowser symbols the headers
        # forward-declare. Built by the CEF binary dist under build/.
        find_library(CEF_WRAPPER_LIB
            NAMES libcef_dll_wrapper cef_dll_wrapper
            HINTS "${CEF_ROOT}/build/libcef_dll_wrapper"
                  "${CEF_ROOT}/libcef_dll"
            NO_DEFAULT_PATH)
        if(NOT CEF_WRAPPER_LIB)
            message(FATAL_ERROR
                "Could not find libcef_dll_wrapper.a. Build the CEF wrapper "
                "(cmake --build ${CEF_ROOT}/build --target libcef_dll_wrapper) "
                "or pass CEF_WRAPPER_LIB=... to this configure step.")
        endif()
        message(STATUS "[lethe-cef] CEF library:    ${CEF_LIB}")
        message(STATUS "[lethe-cef] CEF wrapper lib: ${CEF_WRAPPER_LIB}")
        target_link_libraries(lethe-cef PRIVATE
            lethe_core
            ${COCOA_FRAMEWORK} ${NETWORK_FRAMEWORK}
            "${CEF_LIB}"
            "${CEF_WRAPPER_LIB}")
        # The CEF framework's other dylibs (libEGL, libGLESv2, etc.) live in
        # Release/Chromium Embedded Framework.framework/Libraries/; rpath
        # gets them from the framework's standard @rpath.
        set_target_properties(lethe-cef PROPERTIES
            BUILD_RPATH "${CEF_ROOT}/Release/Chromium Embedded Framework.framework/Libraries")

        # ---- CEF Helper (subprocess binary) ----------------------------------
        # Chromium's multi-process model spawns one Helper per renderer / GPU
        # / network / utility process. The Helper is a tiny binary that just
        # calls CefExecuteProcess. We build it as a console executable (no
        # bundle) and copy it into the main .app's Frameworks/ as a sibling
        # .app via a post-build step.
        add_executable(lethe-cef-helper
            browser/app/lethe_cef_helper.mm
            browser/app/cef_render_handler.mm)
        set_source_files_properties(
            browser/app/lethe_cef_helper.mm
            browser/app/cef_render_handler.mm
            PROPERTIES LANGUAGE OBJCXX)
        target_compile_options(lethe-cef-helper PRIVATE
            -fobjc-arc -Wno-deprecated-declarations)
        target_link_options(lethe-cef-helper PRIVATE
            "-Wl,-undefined,dynamic_lookup")
        target_compile_definitions(lethe-cef-helper PRIVATE CEF_USE_SANDBOX)
        target_include_directories(lethe-cef-helper PRIVATE
            ${CMAKE_SOURCE_DIR}/browser
            ${CEF_ROOT} ${CEF_ROOT}/include)
        target_link_libraries(lethe-cef-helper PRIVATE
            "${CEF_WRAPPER_LIB}" ${COCOA_FRAMEWORK})
        set_target_properties(lethe-cef-helper PROPERTIES
            OUTPUT_NAME "lethe_cef_helper")

        # Post-build: copy the CEF framework + Helper .app into the bundle.
        # The browser process uses the framework in the main bundle; each CEF
        # helper bundle gets an APFS clone of the framework at the relative
        # location required by CefScopedLibraryLoader. Framework images are
        # process-local, so these per-helper copies do not duplicate classes
        # or allocators inside a single process.
        #
        # CEF 151 / Chromium 151 on macOS launches SOME child types from
        # Chrome-style per-type helper bundles derived from the subprocess
        # executable's basename, not from CefSettings.browser_subprocess_path:
        #   <basename> (Renderer).app / (GPU) / (Plugin) / (Alerts)
        # The renderer is the critical one - without its bundle the exec
        # fails silently and every navigation aborts with ERR_ABORTED (-3).
        # Each per-type bundle gets APFS clones of both the helper binary and
        # the CEF framework. A symlink to the shared framework looks attractive
        # here, but macOS code signing rejects symlink destinations inside an
        # app bundle (codesign --verify --deep reports "invalid destination for
        # symbolic link in bundle"). CEF's official helper loader also expects
        # the framework at this exact per-helper relative path. Cloning keeps
        # the normal bundle layout while avoiding a second physical copy on
        # APFS; each helper process loads its own framework image, so there is
        # no duplicate framework image inside a single process.
        set(LETHE_CEF_HELPER_SUFFIXES "Renderer" "GPU" "Plugin" "Alerts")
        add_custom_command(TARGET lethe-cef POST_BUILD
            # Remove artifacts from older incremental builds. The diagnostic
            # probe is no longer part of the shipping CEF bundle.
            COMMAND ${CMAKE_COMMAND} -E remove
                "$<TARGET_BUNDLE_DIR:lethe-cef>/Contents/MacOS/lethe-cef-probe"
            COMMAND ${CMAKE_COMMAND} -E make_directory
                "$<TARGET_BUNDLE_DIR:lethe-cef>/Contents/Frameworks"
            COMMAND ${CMAKE_COMMAND} -E copy_directory
                "${CEF_ROOT}/Release/Chromium Embedded Framework.framework"
                "$<TARGET_BUNDLE_DIR:lethe-cef>/Contents/Frameworks/Chromium Embedded Framework.framework"
            COMMAND ${CMAKE_COMMAND} -E make_directory
                "$<TARGET_BUNDLE_DIR:lethe-cef>/Contents/Frameworks/Lethe CEF Helper.app/Contents/MacOS"
            COMMAND ${CMAKE_COMMAND} -E copy
                "$<TARGET_FILE:lethe-cef-helper>"
                "$<TARGET_BUNDLE_DIR:lethe-cef>/Contents/Frameworks/Lethe CEF Helper.app/Contents/MacOS/lethe_cef_helper"
            COMMAND ${CMAKE_COMMAND} -E make_directory
                "$<TARGET_BUNDLE_DIR:lethe-cef>/Contents/Frameworks/Lethe CEF Helper.app/Contents/Frameworks"
            COMMAND ${CMAKE_COMMAND} -E copy
                "${CMAKE_SOURCE_DIR}/browser/app/Info_helper.plist.in"
                "$<TARGET_BUNDLE_DIR:lethe-cef>/Contents/Frameworks/Lethe CEF Helper.app/Contents/Info.plist"
            COMMAND ${CMAKE_COMMAND} -E echo
                "Bundled CEF framework + Helper into $<TARGET_BUNDLE_DIR:lethe-cef>"
            VERBATIM)

        # Per-type helper bundles (see comment above). Chromium derives the
        # per-type path by inserting the " (Type)" suffix into the subprocess
        # path; depending on the build that suffix lands on the BUNDLE stem,
        # the EXECUTABLE name, or both. Cover every spelling with a real,
        # independently signed bundle so no symlink remains inside the app.
        set(LETHE_CEF_HELPER_BUNDLES "")
        foreach(_suffix IN LISTS LETHE_CEF_HELPER_SUFFIXES)
            string(TOLOWER "${_suffix}" _suffix_lc)
            set(_exec "lethe_cef_helper (${_suffix})")
            set(_exec2 "Lethe CEF Helper (${_suffix})")
            set(_bundleName "${_exec}.app")
            set(_bundleName2 "${_exec2}.app")
            set(_plist "${CMAKE_CURRENT_BINARY_DIR}/Info_helper_${_suffix_lc}.plist")
            set(_bundlePath "$<TARGET_BUNDLE_DIR:lethe-cef>/Contents/Frameworks/${_bundleName}")
            set(_bundlePath2 "$<TARGET_BUNDLE_DIR:lethe-cef>/Contents/Frameworks/${_bundleName2}")
            list(APPEND LETHE_CEF_HELPER_BUNDLES "${_bundleName}" "${_bundleName2}")
            set(HELPER_EXEC "${_exec}")
            set(HELPER_ID "org.aletheia.lethe.cef.helper.${_suffix_lc}")
            set(HELPER_NAME "${_exec}")
            configure_file(
                "${CMAKE_SOURCE_DIR}/browser/app/Info_helper_type.plist.in"
                "${_plist}" @ONLY)
            add_custom_command(TARGET lethe-cef POST_BUILD
                # Remove stale aliases from incremental builds. CMake's
                # make_directory follows an existing symlink, which would
                # otherwise leave the old bundle-name alias in place.
                COMMAND ${CMAKE_COMMAND} -E remove_directory
                    "${_bundlePath2}"
                COMMAND ${CMAKE_COMMAND} -E remove_directory
                    "${_bundlePath}/Contents/Frameworks/Chromium Embedded Framework.framework"
                COMMAND ${CMAKE_COMMAND} -E make_directory
                    "${_bundlePath}/Contents/MacOS"
                COMMAND ${CMAKE_COMMAND} -E make_directory
                    "${_bundlePath}/Contents/Frameworks"
                COMMAND /bin/cp -c
                    "$<TARGET_FILE:lethe-cef-helper>"
                    "${_bundlePath}/Contents/MacOS/${_exec}"
                COMMAND /bin/cp -c
                    "$<TARGET_FILE:lethe-cef-helper>"
                    "${_bundlePath}/Contents/MacOS/${_exec2}"
                COMMAND ${CMAKE_COMMAND} -E copy
                    "${_plist}"
                    "${_bundlePath}/Contents/Info.plist"
                COMMAND /bin/cp -Rc
                    "${CEF_ROOT}/Release/Chromium Embedded Framework.framework"
                    "${_bundlePath}/Contents/Frameworks/Chromium Embedded Framework.framework"
                COMMAND ${CMAKE_COMMAND} -E make_directory
                    "${_bundlePath2}/Contents/MacOS"
                COMMAND ${CMAKE_COMMAND} -E make_directory
                    "${_bundlePath2}/Contents/Frameworks"
                COMMAND /bin/cp -c
                    "$<TARGET_FILE:lethe-cef-helper>"
                    "${_bundlePath2}/Contents/MacOS/${_exec}"
                COMMAND /bin/cp -c
                    "$<TARGET_FILE:lethe-cef-helper>"
                    "${_bundlePath2}/Contents/MacOS/${_exec2}"
                COMMAND ${CMAKE_COMMAND} -E copy
                    "${_plist}"
                    "${_bundlePath2}/Contents/Info.plist"
                COMMAND /bin/cp -Rc
                    "${CEF_ROOT}/Release/Chromium Embedded Framework.framework"
                    "${_bundlePath2}/Contents/Frameworks/Chromium Embedded Framework.framework"
                VERBATIM)
        endforeach()
        list(JOIN LETHE_CEF_HELPER_BUNDLES "," LETHE_CEF_HELPER_BUNDLES_CSV)
        message(STATUS "[lethe-cef] per-type helper bundles: ${LETHE_CEF_HELPER_BUNDLES_CSV}")

        # Ad-hoc sign the whole app (framework + helper bundles). Chromium's
        # macOS child-process launch constraints require the parent and its
        # helpers to share a signing authority; ad-hoc satisfies this for
        # local development builds. The release packaging script does the
        # same for the distributed DMG.
        find_program(LETHE_CODESIGN codesign)
        if(LETHE_CODESIGN)
            add_custom_command(TARGET lethe-cef POST_BUILD
                COMMAND ${LETHE_CODESIGN} --force --deep --sign -
                    "$<TARGET_BUNDLE_DIR:lethe-cef>"
                VERBATIM)
        endif()
        install(TARGETS lethe-cef BUNDLE DESTINATION .)

    endif()
elseif(BUILD_UI)
    # Linux: GTK3 shell; WebKitGTK engine when its dev package is present,
    # otherwise the Cairo reader viewport renders extracted text only.
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(GTK3 QUIET IMPORTED_TARGET gtk+-3.0>=3.20)
    endif()
    if(GTK3_FOUND)
        message(STATUS "[lethe] Building GUI application (GTK3)")
        add_executable(lethe
            browser/app/main.cc
            src/ui/main_window.cc
            src/ui/viewport.cc
            src/ui/e2e_driver.cc
        )
        target_include_directories(lethe PRIVATE
            ${CMAKE_SOURCE_DIR}/include ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/browser)
        target_compile_definitions(lethe PRIVATE -DUSE_GTK3 -DHAVE_OPENSSL)
        target_link_libraries(lethe PRIVATE lethe_core PkgConfig::GTK3)
        if(USE_FULLWEB)
            pkg_check_modules(WEBKITGTK QUIET IMPORTED_TARGET webkit2gtk-4.1)
            if(NOT WEBKITGTK_FOUND)
                pkg_check_modules(WEBKITGTK QUIET IMPORTED_TARGET webkit2gtk-4.0)
            endif()
            if(WEBKITGTK_FOUND)
                message(STATUS "[lethe] full-web engine: WebKitGTK ${WEBKITGTK_VERSION}")
                target_compile_definitions(lethe PRIVATE HAVE_FULLWEB)
                target_link_libraries(lethe PRIVATE PkgConfig::WEBKITGTK)
            else()
                message(STATUS "[lethe] webkit2gtk not found - reader-only shell")
            endif()
        endif()
        install(TARGETS lethe RUNTIME DESTINATION bin)
    else()
        message(STATUS "[lethe] GTK3 not found - GUI application skipped")
    endif()
endif()

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

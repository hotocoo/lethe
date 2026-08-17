
cmake_minimum_required(VERSION 3.18)
project(lethe VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_WITH_SANDBOX "Enable renderer sandboxing" ON)
option(BUILD_HARDENED "Apply strict compiler hardening" ON)
option(USE_PREBUILT_CHROMIUM "Use prebuilt Chromium SDK" OFF)

if(BUILD_HARDENED)
    message(STATUS "[lethe] Building with hardened flags")
    add_compile_definitions(-D_FORTIFY_SOURCE=2 -fstack-protector-strong)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} \
            -O3 -pipe -march=native \
            -flto=auto -fno-plt \
            -fvisibility=hidden \
            -Wall -Wextra -Werror")
    endif()
endif()

set(CHROMIUM_SDK_PATH "$ENV{CHROMIUM_SDK_PATH}")
if(USE_PREBUILT_CHROMIUM AND CHROMIUM_SDK_PATH)
    find_package(Chromium REQUIRED PATHS "${CHROMIUM_SDK_PATH}")
elseif(EXISTS "${CMAKE_SOURCE_DIR}/chromium/src")
    find_package(Chromium REQUIRED PATHS "${CMAKE_SOURCE_DIR}/chromium/src/Build/Release/obj/lib")
endif()

if(NOT TARGET Chromium::chromium)
    message(FATAL_ERROR "[lethe] Could not find Chromium. Set CHROMIUM_SDK_PATH or clone into 'chromium/'")
endif()

file(GLOB_RECURSE SRC_CORE src/core/*.cc)
file(GLOB_RECURSE SRC_RENDERER src/renderer/*.cc)
file(GLOB_RECURSE SRC_BROWSER src/browser/*.cc)
file(GLOB_RECURSE SRC_SECURITY src/security/*.cc)
file(GLOB_RECURSE SRC_NETWORK src/network/*.cc)

add_executable(lethe "${SRC_CORE}" "${SRC_RENDERER}" "${SRC_BROWSER}" 
                "${SRC_SECURITY}" "${SRC_NETWORK}")

target_include_directories(lethe PRIVATE include src browser app)

if(BUILD_WITH_SANDBOX)
    target_compile_definitions(lethe PRIVATE -DLETHE_SANDBOXING)
endif()

target_link_libraries(lethe PRIVATE Chromium::chromium)

install(TARGETS lethe DESTINATION bin)

message(STATUS "Build with sandbox: ${BUILD_WITH_SANDBOX}")
message(STATUS "Hardened build: ${BUILD_HARDENED}")

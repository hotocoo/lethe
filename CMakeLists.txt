cmake_minimum_required(VERSION 3.16)
project(lethe VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Chromium SDK path (env var or local path)
if(NOT DEFINED CHROMIUM_SDK_PATH)
    set(CHROMIUM_SDK_PATH "$ENV{CHROMIUM_SDK_PATH}")
endif()

find_package(Chromium REQUIRED PATHS "${CHROMIUM_SDK_PATH}")

add_executable(lethe src/main.cc)
target_include_directories(lethe PRIVATE include browser renderer)
target_link_libraries(lethe PRIVATE Chromium::chromium)

install(TARGETS lethe DESTINATION bin)

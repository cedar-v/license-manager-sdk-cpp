cmake_minimum_required(VERSION 3.14)
project(license-manager-cpp VERSION 1.0.0 LANGUAGES CXX)

# C++20 required (compatible with UE5.2; also works with C++23 compilers)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# FetchContent for header-only libraries
include(FetchContent)

# nlohmann/json (header-only)
FetchContent_Declare(
    nlohmann_json
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/_deps/nlohmann_json-src
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(nlohmann_json)

# spdlog (header-only)
FetchContent_Declare(
    spdlog
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/_deps/spdlog-src
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
# Suppress spdlog warnings
set(SPDLOG_WARN_LEVEL 0)
FetchContent_MakeAvailable(spdlog)

# Find libcurl (on Windows it needs to be found differently)
find_package(CURL REQUIRED)

# Source files
set(LICENSE_MANAGER_SOURCES
    src/types.cpp
    src/errors.cpp
    src/logger.cpp
    src/config.cpp
    src/models.cpp
    src/storage.cpp
    src/hardware.cpp
    src/activation.cpp
    src/heartbeat.cpp
    src/validator.cpp
    src/client.cpp
    src/util.cpp
    src/mwcompat.cpp
)

# Create static library
add_library(license-manager STATIC ${LICENSE_MANAGER_SOURCES})

# Include directories
target_include_directories(license-manager PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Private includes (for implementation)
target_include_directories(license-manager PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Link libraries
target_link_libraries(license-manager PUBLIC
    CURL::libcurl
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    spdlog::spdlog
    ws2_32
    iphlpapi
)

# Compiler flags
target_compile_options(license-manager PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:
        /W4
        /permissive-
    >
    $<$<CXX_COMPILER_ID:GNU,Clang>:
        -Wall -Wextra -Wpedantic
        -include ${CMAKE_CURRENT_SOURCE_DIR}/include/mwcompat.h
    >
)

# Alias for consistent usage
add_library(license-manager-cpp::license-manager ALIAS license-manager)

# Example: basic usage
add_executable(basic-example examples/basic.cpp)
target_link_libraries(basic-example PRIVATE license-manager-cpp::license-manager)
target_compile_options(basic-example PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:
        /W4
    >
    $<$<CXX_COMPILER_ID:GNU,Clang>:
        -Wall -Wextra
        -include ${CMAKE_CURRENT_SOURCE_DIR}/include/mwcompat.h
    >
)

# Copy license_code directory to build directory so example can find it
file(COPY ${CMAKE_SOURCE_DIR}/license_code DESTINATION ${CMAKE_BINARY_DIR})

# Installation rules
install(TARGETS license-manager
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

# Print summary
message(STATUS "")
message(STATUS "=== License Manager C++ SDK ===")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")

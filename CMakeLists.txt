cmake_minimum_required(VERSION 3.20)
project(modular_slang_demo LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(FetchContent)

set(SLANG_SDK_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/slang/build/Release")
if(NOT EXISTS "${SLANG_SDK_ROOT}")
    message(FATAL_ERROR "Expected Slang SDK directory at ${SLANG_SDK_ROOT}")
endif()

FetchContent_Declare(
    abseil
    URL https://github.com/abseil/abseil-cpp/archive/refs/tags/20240116.1.zip
)

# Only populate abseil if it hasn't been built yet
FetchContent_GetProperties(abseil)
if(NOT abseil_POPULATED)
    # Check if the built libraries already exist
    set(ABSEIL_STATUS_LIB "${CMAKE_BINARY_DIR}/_deps/abseil-build/absl/status/absl_status.lib")
    set(ABSEIL_STATUSOR_LIB "${CMAKE_BINARY_DIR}/_deps/abseil-build/absl/status/absl_statusor.lib")

    if(NOT EXISTS "${ABSEIL_STATUS_LIB}" OR NOT EXISTS "${ABSEIL_STATUSOR_LIB}")
        message(STATUS "Abseil libraries not found, building abseil...")
        FetchContent_MakeAvailable(abseil)
    else()
        message(STATUS "Abseil libraries found, skipping rebuild")
        # Manually populate the source directory without building
        FetchContent_Populate(abseil)
        add_subdirectory(${abseil_SOURCE_DIR} ${abseil_BINARY_DIR} EXCLUDE_FROM_ALL)
    endif()
endif()

add_executable(modular_slang main.cc)
set_target_properties(modular_slang PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

target_include_directories(modular_slang PRIVATE
    "${SLANG_SDK_ROOT}/include"
)

target_link_libraries(modular_slang PRIVATE
    "${SLANG_SDK_ROOT}/lib/slang.lib"
    absl::status
    absl::statusor
)

if(MSVC)
    target_compile_options(modular_slang PRIVATE /W4 /EHsc)
else()
    target_compile_options(modular_slang PRIVATE -Wall -Wextra -pedantic)
endif()

add_custom_command(TARGET modular_slang POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${SLANG_SDK_ROOT}/bin/slang.dll"
        "$<TARGET_FILE_DIR:modular_slang>/slang.dll"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${SLANG_SDK_ROOT}/bin/slang-rt.dll"
        "$<TARGET_FILE_DIR:modular_slang>/slang-rt.dll"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${SLANG_SDK_ROOT}/bin/gfx.dll"
        "$<TARGET_FILE_DIR:modular_slang>/gfx.dll"
)

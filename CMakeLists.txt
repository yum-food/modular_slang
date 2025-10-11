cmake_minimum_required(VERSION 3.20)
project(modular_slang_demo LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(SLANG_SDK_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/slang/build/slang-2025.18.2-windows-x86_64")
if(NOT EXISTS "${SLANG_SDK_ROOT}")
    message(FATAL_ERROR "Expected Slang SDK directory at ${SLANG_SDK_ROOT}")
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
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/test.slang"
        "$<TARGET_FILE_DIR:modular_slang>/test.slang"
)

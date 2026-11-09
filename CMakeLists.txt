cmake_minimum_required(VERSION 3.20)
project(Olympus VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4 /permissive- /utf-8 /MP)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Platform socket libraries (Winsock2 on Windows, standard POSIX on Linux)
set(OLYMPUS_PLATFORM_LIBS "")
if(WIN32)
    list(APPEND OLYMPUS_PLATFORM_LIBS ws2_32)
else()
    find_package(Threads REQUIRED)
    list(APPEND OLYMPUS_PLATFORM_LIBS Threads::Threads)
endif()

# ------------------------------------------------------------------------------
# 1. Edge Wire Codec Library: olympus::codec::v24919
# ------------------------------------------------------------------------------
add_library(olympus_codec_v24919 STATIC
    src/codec/v24919/hmac_sha1_96.cpp
    src/codec/v24919/bitstream.cpp
    src/codec/v24919/gcm_udp_header.cpp
    src/codec/v24919/jam_compact_codec.cpp
)
target_include_directories(olympus_codec_v24919 PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# ------------------------------------------------------------------------------
# 2. Plane 1 (Control Plane): olympus::athena
# ------------------------------------------------------------------------------
add_library(olympus_athena STATIC
    src/athena/athena_server.cpp
)
target_include_directories(olympus_athena PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(olympus_athena PUBLIC
    olympus_codec_v24919
    ${OLYMPUS_PLATFORM_LIBS}
)

# ------------------------------------------------------------------------------
# 3. Plane 2 (Simulation Plane & Sparse-Set ECS): olympus::chiron
# ------------------------------------------------------------------------------
add_library(olympus_chiron STATIC
    src/chiron/chiron_server.cpp
)
target_include_directories(olympus_chiron PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(olympus_chiron PUBLIC
    olympus_codec_v24919
    ${OLYMPUS_PLATFORM_LIBS}
)

# ------------------------------------------------------------------------------
# 4. Unified Dedicated Server Executable: olympus_server
# ------------------------------------------------------------------------------
add_executable(olympus_server
    src/main.cpp
)
target_link_libraries(olympus_server PRIVATE
    olympus_athena
    olympus_chiron
    olympus_codec_v24919
)

# ------------------------------------------------------------------------------
# 5. Verification & Wire-Protocol Unit Tests
# ------------------------------------------------------------------------------
enable_testing()
add_executable(olympus_tests
    tests/test_codec_v24919.cpp
)
target_link_libraries(olympus_tests PRIVATE
    olympus_athena
    olympus_chiron
    olympus_codec_v24919
)
add_test(NAME olympus_codec_v24919_tests COMMAND olympus_tests)

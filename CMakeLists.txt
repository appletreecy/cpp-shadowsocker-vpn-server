cmake_minimum_required(VERSION 3.10)
project(cpp_ss_server CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(ss_server
        src/main.cpp
        src/server.cpp
        src/crypto.cpp
)

# --- Find libsodium ---

# Common Homebrew locations (Apple Silicon + Intel)
set(SODIUM_HINT_DIRS
        /opt/homebrew/include        # headers
        /opt/homebrew/opt/libsodium/include
        /usr/local/include
        /usr/local/opt/libsodium/include
)

set(SODIUM_LIB_HINT_DIRS
        /opt/homebrew/lib
        /opt/homebrew/opt/libsodium/lib
        /usr/local/lib
        /usr/local/opt/libsodium/lib
)

find_path(SODIUM_INCLUDE_DIR
        NAMES sodium.h
        HINTS ${SODIUM_HINT_DIRS}
)

find_library(SODIUM_LIBRARY
        NAMES sodium
        HINTS ${SODIUM_LIB_HINT_DIRS}
)

if (NOT SODIUM_INCLUDE_DIR)
    message(FATAL_ERROR "Could not find sodium.h (libsodium headers)")
endif()

if (NOT SODIUM_LIBRARY)
    message(FATAL_ERROR "Could not find libsodium library")
endif()

message(STATUS "Found libsodium include: ${SODIUM_INCLUDE_DIR}")
message(STATUS "Found libsodium library: ${SODIUM_LIBRARY}")

target_include_directories(ss_server PRIVATE ${SODIUM_INCLUDE_DIR})
target_link_libraries(ss_server PRIVATE ${SODIUM_LIBRARY} pthread)

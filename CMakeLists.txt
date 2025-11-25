cmake_minimum_required(VERSION 3.10)
project(ss_server CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(ss_server
        src/main.cpp
        src/server.cpp
        src/crypto.cpp
)

# ---- libsodium (for chacha20-ietf-poly1305 AEAD) ----

# Common Homebrew / Linux locations
set(SODIUM_HINT_DIRS
        /opt/homebrew/include
        /opt/homebrew/opt/libsodium/include
        /usr/local/include
        /usr/local/opt/libsodium/include
        /usr/include
)

set(SODIUM_LIB_HINT_DIRS
        /opt/homebrew/lib
        /opt/homebrew/opt/libsodium/lib
        /usr/local/lib
        /usr/local/opt/libsodium/lib
        /usr/lib
        /usr/lib/x86_64-linux-gnu
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

# ---- OpenSSL (for MD5 KDF + HMAC-SHA1 HKDF) ----

find_package(OpenSSL REQUIRED)

if (NOT OpenSSL_FOUND)
    message(FATAL_ERROR "OpenSSL not found")
endif()

target_link_libraries(ss_server
        PRIVATE
        ${SODIUM_LIBRARY}
        OpenSSL::Crypto
        pthread
)

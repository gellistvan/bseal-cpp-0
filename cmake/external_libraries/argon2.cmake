# cmake/external_libraries/argon2.cmake
#
# Builds the Argon2 reference C library from the git submodule at
# submodules/argon2 (https://github.com/P-H-C/phc-winner-argon2).
# Defines the imported target argon2::argon2 for use by project targets.
#
# The Argon2 reference implementation is dual-licensed CC0-1.0 / Apache-2.0.
# The license file is in submodules/argon2/LICENSE.
#
# Usage in CMakeLists.txt:
#   include(cmake/external_libraries/argon2.cmake)
#   target_link_libraries(your_target PRIVATE argon2::argon2)

set(ARGON2_SUBMODULE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/submodules/argon2")

# On Windows, vcpkg's libsodium bundles most argon2 symbols. Building our own
# argon2_static would produce duplicate symbols at link time. We only need the
# headers for compilation; libsodium satisfies the symbols at link time.
if (WIN32)
    add_library(argon2_static INTERFACE)
    add_library(argon2::argon2 ALIAS argon2_static)
    target_include_directories(argon2_static INTERFACE
        $<BUILD_INTERFACE:${ARGON2_SUBMODULE_DIR}/include>
    )
    return()
endif()

if (NOT EXISTS "${ARGON2_SUBMODULE_DIR}/include/argon2.h")
    message(FATAL_ERROR
        "Argon2 submodule is missing. Run:\n"
        "  git submodule update --init --recursive"
    )
endif()

# Enable C so the Argon2 C sources compile. The root project uses CXX only.
enable_language(C)

# The reference implementation ships both a portable ref.c and an optimized
# opt.c.  opt.c uses 64-bit arithmetic and AVX2/SSE2 intrinsics on x86-64;
# on all other architectures or when the compiler does not support it the
# ref.c fallback is used instead.
if (CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64)$")
    set(_ARGON2_CORE_IMPL "${ARGON2_SUBMODULE_DIR}/src/opt.c")
else()
    set(_ARGON2_CORE_IMPL "${ARGON2_SUBMODULE_DIR}/src/ref.c")
endif()

add_library(argon2_static STATIC
    "${ARGON2_SUBMODULE_DIR}/src/argon2.c"
    "${ARGON2_SUBMODULE_DIR}/src/core.c"
    "${ARGON2_SUBMODULE_DIR}/src/encoding.c"
    "${ARGON2_SUBMODULE_DIR}/src/thread.c"
    "${ARGON2_SUBMODULE_DIR}/src/blake2/blake2b.c"
    "${_ARGON2_CORE_IMPL}"
)

add_library(argon2::argon2 ALIAS argon2_static)

target_include_directories(argon2_static
    PUBLIC
        $<BUILD_INTERFACE:${ARGON2_SUBMODULE_DIR}/include>
        $<INSTALL_INTERFACE:include/argon2>
)

target_compile_features(argon2_static PRIVATE c_std_99)

# Silence warnings from upstream sources that we do not own.
target_compile_options(argon2_static PRIVATE
    $<$<C_COMPILER_ID:GNU,Clang,AppleClang>:-w>
    $<$<C_COMPILER_ID:MSVC>:/W0>
)

# The opt.c path uses pthreads for parallel lanes on POSIX systems.
find_package(Threads REQUIRED)
target_link_libraries(argon2_static PUBLIC Threads::Threads)

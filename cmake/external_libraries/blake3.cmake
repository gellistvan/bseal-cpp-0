# cmake/external_libraries/blake3.cmake
#
# Builds the BLAKE3 C library from the git submodule at submodules/blake3.
# Defines the imported target blake3::blake3 for use by project targets.
#
# The BLAKE3 C implementation is dual-licensed CC0-1.0 OR Apache-2.0 WITH
# LLVM-exception. License files are in submodules/blake3/LICENSE_CC0,
# LICENSE_A2, and LICENSE_A2LLVM.
#
# Usage in CMakeLists.txt:
#   include(cmake/external_libraries/blake3.cmake)
#   target_link_libraries(your_target PRIVATE blake3::blake3)

set(BLAKE3_SUBMODULE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/submodules/blake3")
set(BLAKE3_C_DIR         "${BLAKE3_SUBMODULE_DIR}/c")

if (NOT EXISTS "${BLAKE3_C_DIR}/blake3.h")
    message(FATAL_ERROR
        "BLAKE3 submodule is missing. Run:\n"
        "  git submodule update --init --recursive"
    )
endif()

# Enable C so the BLAKE3 C sources compile. The root project uses CXX only.
enable_language(C)

add_library(blake3_static STATIC
    "${BLAKE3_C_DIR}/blake3.c"
    "${BLAKE3_C_DIR}/blake3_dispatch.c"
    "${BLAKE3_C_DIR}/blake3_portable.c"
    "${BLAKE3_C_DIR}/blake3_sse2.c"
    "${BLAKE3_C_DIR}/blake3_sse41.c"
    "${BLAKE3_C_DIR}/blake3_avx2.c"
    "${BLAKE3_C_DIR}/blake3_avx512.c"
    "${BLAKE3_C_DIR}/blake3_neon.c"
)

add_library(blake3::blake3 ALIAS blake3_static)

target_include_directories(blake3_static
    PUBLIC
        $<BUILD_INTERFACE:${BLAKE3_C_DIR}>
        $<INSTALL_INTERFACE:include/blake3>
)

# BLAKE3 only needs C99 in practice.
target_compile_features(blake3_static PRIVATE c_std_99)

# Silence warnings from upstream sources that we do not own.
target_compile_options(blake3_static PRIVATE
    $<$<C_COMPILER_ID:GNU,Clang,AppleClang>:-w>
)

# On x86/x86-64 enable per-file SIMD flags so the runtime dispatch table in
# blake3_dispatch.c can select the fastest available code path at runtime.
# On all other architectures disable the x86 SIMD files entirely and fall back
# to the portable C implementation.
if (CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|i[3-6]86)$")
    set_source_files_properties("${BLAKE3_C_DIR}/blake3_sse2.c"
        PROPERTIES COMPILE_FLAGS "-msse2")
    set_source_files_properties("${BLAKE3_C_DIR}/blake3_sse41.c"
        PROPERTIES COMPILE_FLAGS "-msse4.1")
    set_source_files_properties("${BLAKE3_C_DIR}/blake3_avx2.c"
        PROPERTIES COMPILE_FLAGS "-mavx2")
    set_source_files_properties("${BLAKE3_C_DIR}/blake3_avx512.c"
        PROPERTIES COMPILE_FLAGS "-mavx512f -mavx512vl")
    # NEON is not available on x86.
    set_source_files_properties("${BLAKE3_C_DIR}/blake3_neon.c"
        PROPERTIES HEADER_FILE_ONLY TRUE)
elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|armv[7-9])")
    # ARM: disable all x86 SIMD files, enable NEON.
    foreach(_f blake3_sse2.c blake3_sse41.c blake3_avx2.c blake3_avx512.c)
        set_source_files_properties("${BLAKE3_C_DIR}/${_f}"
            PROPERTIES HEADER_FILE_ONLY TRUE)
    endforeach()
    target_compile_definitions(blake3_static PRIVATE
        BLAKE3_NO_SSE2
        BLAKE3_NO_SSE41
        BLAKE3_NO_AVX2
        BLAKE3_NO_AVX512
        BLAKE3_USE_NEON=1
    )
else()
    # Unknown architecture: portable fallback only.
    foreach(_f blake3_sse2.c blake3_sse41.c blake3_avx2.c blake3_avx512.c blake3_neon.c)
        set_source_files_properties("${BLAKE3_C_DIR}/${_f}"
            PROPERTIES HEADER_FILE_ONLY TRUE)
    endforeach()
    target_compile_definitions(blake3_static PRIVATE
        BLAKE3_NO_SSE2
        BLAKE3_NO_SSE41
        BLAKE3_NO_AVX2
        BLAKE3_NO_AVX512
    )
endif()

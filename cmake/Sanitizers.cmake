function(bseal_enable_sanitizers_if_requested target_name)
    if (NOT BSEAL_ENABLE_SANITIZERS)
        return()
    endif()

    if (MSVC)
        message(WARNING "BSEAL_ENABLE_SANITIZERS is not supported for MSVC; sanitizers are only configured for GCC and Clang.")
        return()
    endif()

    if (BSEAL_ENABLE_TSAN)
        message(FATAL_ERROR
            "BSEAL_ENABLE_SANITIZERS (ASan/UBSan) and BSEAL_ENABLE_TSAN (TSan) are "
            "mutually exclusive. Enable only one at a time.")
    endif()

    target_compile_options(${target_name} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(${target_name} PRIVATE -fsanitize=address,undefined)
endfunction()

# ThreadSanitizer build (-DBSEAL_ENABLE_TSAN=ON).
#
# TSan detects data races in CryptoBackend concurrent stress tests and the
# pipeline worker threads.  It is INCOMPATIBLE with ASan/UBSan — use a
# separate build directory:
#
#   cmake -S . -B build-tsan -DBSEAL_ENABLE_TSAN=ON
#   cmake --build build-tsan -j
#   ctest --test-dir build-tsan --output-on-failure
#
# TSan may produce false positives with some allocators; if needed, set
# TSAN_OPTIONS=suppressions=... to suppress known-benign reports.
function(bseal_enable_tsan_if_requested target_name)
    if (NOT BSEAL_ENABLE_TSAN)
        return()
    endif()

    if (MSVC)
        message(WARNING "BSEAL_ENABLE_TSAN is not supported on MSVC.")
        return()
    endif()

    target_compile_options(${target_name} PRIVATE -fsanitize=thread -fno-omit-frame-pointer)
    target_link_options(${target_name} PRIVATE -fsanitize=thread)
endfunction()

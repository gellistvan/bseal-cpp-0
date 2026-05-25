# ---------------------------------------------------------------------------
# BSEAL fuzz targets
#
# When BSEAL_BUILD_FUZZERS=ON:
#   - If the compiler supports -fsanitize=fuzzer-no-link, targets are built
#     with -fsanitize=fuzzer,address,undefined and
#     BSEAL_FUZZER_ENGINE_LIBFUZZER is defined, disabling standalone main().
#   - Otherwise, targets are built as standalone smoke executables with a
#     deterministic seed-corpus runner, and registered as CTest tests.
#
# All six targets are always registered as CTest smoke tests so that
# `ctest --test-dir build-fuzz` verifies the targets don't crash on seeds.
# ---------------------------------------------------------------------------

include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-fsanitize=fuzzer-no-link" BSEAL_HAVE_LIBFUZZER)

set(BSEAL_FUZZ_TARGETS
    FuzzGlobalPublicHeader
    FuzzShardPublicHeader
    FuzzChunkFrameHeader
    FuzzRecordFormat
    FuzzArchiveReader
    FuzzPathSanitizer
)

set(BSEAL_FUZZ_CORPUS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/corpus")

foreach(TARGET ${BSEAL_FUZZ_TARGETS})
    add_executable(${TARGET} ${TARGET}.cpp)

    target_include_directories(${TARGET}
        PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}"
            "${CMAKE_SOURCE_DIR}/src"
    )
    target_link_libraries(${TARGET} PRIVATE bseal::core)
    target_compile_features(${TARGET} PRIVATE cxx_std_20)

    if (BSEAL_HAVE_LIBFUZZER)
        target_compile_definitions(${TARGET} PRIVATE BSEAL_FUZZER_ENGINE_LIBFUZZER)
        target_compile_options(${TARGET}  PRIVATE -fsanitize=fuzzer,address,undefined)
        target_link_options(${TARGET}     PRIVATE -fsanitize=fuzzer,address,undefined)
    endif()
endforeach()

# ---------------------------------------------------------------------------
# CTest smoke registrations — always run regardless of libFuzzer availability.
# With libFuzzer builds the binary still acts as a smoke runner when called
# with a corpus directory argument (libFuzzer reads corpus files and exits).
# For standalone builds the built-in seeds are exercised via smoke_main().
# ---------------------------------------------------------------------------

string(TOLOWER "global_public_header" _gph)
string(TOLOWER "shard_public_header"  _sph)
string(TOLOWER "chunk_frame_header"   _cfh)
string(TOLOWER "record_format"        _rf)
string(TOLOWER "archive_reader"       _ar)
string(TOLOWER "path_sanitizer"       _ps)

if (BSEAL_HAVE_LIBFUZZER)
    # libFuzzer mode: pass corpus dir + -runs=0 to replay corpus without fuzzing
    add_test(NAME fuzz.smoke.GlobalPublicHeader
        COMMAND FuzzGlobalPublicHeader
                "${BSEAL_FUZZ_CORPUS_DIR}/global_public_header" -runs=0)
    add_test(NAME fuzz.smoke.ShardPublicHeader
        COMMAND FuzzShardPublicHeader
                "${BSEAL_FUZZ_CORPUS_DIR}/shard_public_header" -runs=0)
    add_test(NAME fuzz.smoke.ChunkFrameHeader
        COMMAND FuzzChunkFrameHeader
                "${BSEAL_FUZZ_CORPUS_DIR}/chunk_frame_header" -runs=0)
    add_test(NAME fuzz.smoke.RecordFormat
        COMMAND FuzzRecordFormat
                "${BSEAL_FUZZ_CORPUS_DIR}/record_format" -runs=0)
    add_test(NAME fuzz.smoke.ArchiveReader
        COMMAND FuzzArchiveReader
                "${BSEAL_FUZZ_CORPUS_DIR}/archive_reader" -runs=0)
    add_test(NAME fuzz.smoke.PathSanitizer
        COMMAND FuzzPathSanitizer
                "${BSEAL_FUZZ_CORPUS_DIR}/path_sanitizer" -runs=0)
else()
    # Standalone smoke mode: run built-in seeds
    add_test(NAME fuzz.smoke.GlobalPublicHeader COMMAND FuzzGlobalPublicHeader)
    add_test(NAME fuzz.smoke.ShardPublicHeader  COMMAND FuzzShardPublicHeader)
    add_test(NAME fuzz.smoke.ChunkFrameHeader   COMMAND FuzzChunkFrameHeader)
    add_test(NAME fuzz.smoke.RecordFormat       COMMAND FuzzRecordFormat)
    add_test(NAME fuzz.smoke.ArchiveReader      COMMAND FuzzArchiveReader)
    add_test(NAME fuzz.smoke.PathSanitizer      COMMAND FuzzPathSanitizer)
endif()

foreach(_t GlobalPublicHeader ShardPublicHeader ChunkFrameHeader RecordFormat ArchiveReader PathSanitizer)
    set_tests_properties(fuzz.smoke.${_t} PROPERTIES LABELS "fuzz;smoke" TIMEOUT 60)
endforeach()

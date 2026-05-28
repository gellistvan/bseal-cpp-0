# ---------------------------------------------------------------------------
# BSEAL fuzz targets
#
# When BSEAL_BUILD_FUZZERS=ON:
#   - If BSEAL_FUZZING_ENGINE_LINK is set (e.g. by ClusterFuzzLite / OSS-Fuzz),
#     each target defines BSEAL_FUZZER_ENGINE_LIBFUZZER and links against the
#     provided engine. No self-managed -fsanitize=fuzzer flags are added; the
#     caller's $CXXFLAGS/$CFLAGS carry the instrumentation. CTest registrations
#     are skipped — ClusterFuzzLite invokes the binaries itself.
#   - Else if the compiler supports -fsanitize=fuzzer-no-link, targets are
#     built with -fsanitize=fuzzer,address,undefined and
#     BSEAL_FUZZER_ENGINE_LIBFUZZER is defined, disabling standalone main().
#   - Otherwise, targets are built as standalone smoke executables with a
#     deterministic seed-corpus runner, and registered as CTest tests.
# ---------------------------------------------------------------------------

include(CheckCXXCompilerFlag)
check_cxx_compiler_flag("-fsanitize=fuzzer-no-link" BSEAL_HAVE_LIBFUZZER)

# When set (e.g. by ClusterFuzzLite / OSS-Fuzz), this is the fuzzing engine
# library or linker flag to link into each target. When empty, the build
# falls back to the self-managed -fsanitize=fuzzer path for local use.
set(BSEAL_FUZZING_ENGINE_LINK "" CACHE STRING
    "External fuzzing engine to link (e.g. \$LIB_FUZZING_ENGINE). Empty = self-managed libFuzzer.")

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

    if (BSEAL_FUZZING_ENGINE_LINK)
        # External-engine mode (ClusterFuzzLite / OSS-Fuzz): instrumentation
        # comes from the caller's $CXXFLAGS; we only wire up the engine.
        target_compile_definitions(${TARGET} PRIVATE BSEAL_FUZZER_ENGINE_LIBFUZZER)
        # $LIB_FUZZING_ENGINE may be an archive path or a linker flag (-fsanitize=fuzzer).
        # target_link_libraries handles archive paths; flags need target_link_options.
        if (BSEAL_FUZZING_ENGINE_LINK MATCHES "^-")
            target_link_options(${TARGET} PRIVATE ${BSEAL_FUZZING_ENGINE_LINK})
        else()
            target_link_libraries(${TARGET} PRIVATE ${BSEAL_FUZZING_ENGINE_LINK})
        endif()
    elseif (BSEAL_HAVE_LIBFUZZER)
        target_compile_definitions(${TARGET} PRIVATE BSEAL_FUZZER_ENGINE_LIBFUZZER)
        target_compile_options(${TARGET}  PRIVATE -fsanitize=fuzzer,address,undefined)
        target_link_options(${TARGET}     PRIVATE -fsanitize=fuzzer,address,undefined)
    endif()
endforeach()

# ---------------------------------------------------------------------------
# CTest smoke registrations.
# Skipped in external-engine mode — ClusterFuzzLite invokes the binaries itself.
# With local libFuzzer builds the binary acts as a smoke runner (-runs=0).
# For standalone builds the built-in seeds are exercised via smoke_main().
# ---------------------------------------------------------------------------

if (NOT BSEAL_FUZZING_ENGINE_LINK)
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
endif()

if (NOT BSEAL_FUZZING_ENGINE_LINK)
    foreach(_t GlobalPublicHeader ShardPublicHeader ChunkFrameHeader RecordFormat ArchiveReader PathSanitizer)
        set_tests_properties(fuzz.smoke.${_t} PROPERTIES LABELS "fuzz;smoke" TIMEOUT 60)
    endforeach()
endif()

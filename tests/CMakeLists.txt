add_executable(bseal_smoke_tests smoke_tests.cpp)
target_link_libraries(bseal_smoke_tests PRIVATE bseal::core)
bseal_set_project_warnings(bseal_smoke_tests)
bseal_enable_sanitizers_if_requested(bseal_smoke_tests)
bseal_enable_coverage_if_requested(bseal_smoke_tests)
add_test(NAME bseal_smoke_tests COMMAND bseal_smoke_tests)

find_package(GTest QUIET)

if (GTest_FOUND)
    message(STATUS "Using system GoogleTest")
    set(BSEAL_GTEST_LIBS GTest::gtest_main)
else()
    message(STATUS "System GoogleTest not found; using local lightweight compatibility harness for skeleton tests")
    add_library(bseal_minigtest_main STATIC vendor/minigtest/gtest_main.cpp)
    target_include_directories(bseal_minigtest_main PUBLIC vendor/minigtest)
    target_compile_features(bseal_minigtest_main PUBLIC cxx_std_20)
    bseal_set_project_warnings(bseal_minigtest_main)
    bseal_enable_sanitizers_if_requested(bseal_minigtest_main)
bseal_enable_coverage_if_requested(bseal_minigtest_main)
    set(BSEAL_GTEST_LIBS bseal_minigtest_main)
endif()

add_executable(bseal_common_gtests
    common/TestCheckedArithmetic.cpp
)
target_link_libraries(bseal_common_gtests PRIVATE bseal::core ${BSEAL_GTEST_LIBS})
bseal_set_project_warnings(bseal_common_gtests)
bseal_enable_sanitizers_if_requested(bseal_common_gtests)
bseal_enable_coverage_if_requested(bseal_common_gtests)

add_executable(bseal_platform_gtests
    platform/TestRandom.cpp
    platform/TestMemoryLock.cpp
    platform/TestCpuFeatures.cpp
    platform/TestDurableFile.cpp
    platform/TestPassphrasePrompt.cpp
)

target_link_libraries(bseal_platform_gtests PRIVATE bseal::core ${BSEAL_GTEST_LIBS})
bseal_set_project_warnings(bseal_platform_gtests)
bseal_enable_sanitizers_if_requested(bseal_platform_gtests)
bseal_enable_coverage_if_requested(bseal_platform_gtests)

# ---------------------------------------------------------------------------
# Config header: fixture directory path for format-v1 KAT tests
# ---------------------------------------------------------------------------
file(GENERATE
        OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/generated/format-v1-kat/$<CONFIG>/FormatV1KatConfig.hpp"
        CONTENT
        "#pragma once
inline constexpr const char* BSEAL_FORMAT_FIXTURES_DIR =
    R\"bseal_path(${CMAKE_CURRENT_SOURCE_DIR}/fixtures/format-v1)bseal_path\";
"
)

add_executable(bseal_io_gtests
        io/TestAsyncReader.cpp
        io/TestAsyncWriter.cpp
        io/TestBufferPool.cpp
        io/TestShardFrameHash.cpp
        io/TestShardReader.cpp
        io/TestShardWriter.cpp
        io/TestShardWriterDurability.cpp
        io/TestFormatV1Kat.cpp
        io/TestMalformedShards.cpp
)

target_include_directories(bseal_io_gtests
        PRIVATE
        "${CMAKE_CURRENT_BINARY_DIR}/generated/format-v1-kat/$<CONFIG>"
)

target_link_libraries(bseal_io_gtests PRIVATE bseal::core blake3::blake3 ${BSEAL_GTEST_LIBS})
bseal_set_project_warnings(bseal_io_gtests)
bseal_enable_sanitizers_if_requested(bseal_io_gtests)
bseal_enable_coverage_if_requested(bseal_io_gtests)

add_executable(bseal_archive_gtests
        archive/TestPublicHeaderAuth.cpp
        archive/TestArchiveReader.cpp
        archive/TestArchiveReaderDurability.cpp
        archive/TestArchiveWriter.cpp
        archive/TestMetadata.cpp
        archive/TestPathSanitizer.cpp
        archive/TestRecordFormat.cpp
        archive/TestSafeOutputTree.cpp
        archive/TestMalformedRecords.cpp
)

target_link_libraries(bseal_archive_gtests PRIVATE bseal::core ${BSEAL_GTEST_LIBS})
bseal_set_project_warnings(bseal_archive_gtests)
bseal_enable_sanitizers_if_requested(bseal_archive_gtests)
bseal_enable_coverage_if_requested(bseal_archive_gtests)

add_executable(bseal_crypto_gtests
        crypto/TestSecureBuffer.cpp
        crypto/TestAesGcmBackend.cpp
        crypto/TestXChaCha20Poly1305Backend.cpp
        crypto/TestKdf.cpp
        crypto/TestKeySchedule.cpp
        crypto/TestCryptoBackendConcurrency.cpp
)

target_link_libraries(bseal_crypto_gtests PRIVATE bseal::core ${BSEAL_GTEST_LIBS})
bseal_set_project_warnings(bseal_crypto_gtests)
bseal_enable_sanitizers_if_requested(bseal_crypto_gtests)
bseal_enable_coverage_if_requested(bseal_crypto_gtests)
bseal_enable_tsan_if_requested(bseal_crypto_gtests)

add_executable(bseal_pipeline_gtests
        pipeline/TestWorkQueue.cpp
        pipeline/TestEncryptPipeline.cpp
        pipeline/TestDecryptPipeline.cpp
        pipeline/TestMultiWorkerPipeline.cpp
)

target_link_libraries(bseal_pipeline_gtests PRIVATE bseal::core ${BSEAL_GTEST_LIBS})
bseal_set_project_warnings(bseal_pipeline_gtests)
bseal_enable_sanitizers_if_requested(bseal_pipeline_gtests)
bseal_enable_coverage_if_requested(bseal_pipeline_gtests)
bseal_enable_tsan_if_requested(bseal_pipeline_gtests)

if (GTest_FOUND)
    include(GoogleTest)

    gtest_discover_tests(bseal_common_gtests
            TEST_PREFIX common.
            DISCOVERY_TIMEOUT 30
    )

    gtest_discover_tests(bseal_platform_gtests
            TEST_PREFIX platform.
            DISCOVERY_TIMEOUT 30
    )

    gtest_discover_tests(bseal_io_gtests
            TEST_PREFIX io.
            DISCOVERY_TIMEOUT 30
    )

    gtest_discover_tests(bseal_archive_gtests
            TEST_PREFIX archive.
            DISCOVERY_TIMEOUT 30
    )

    gtest_discover_tests(bseal_crypto_gtests
            TEST_PREFIX crypto.
            DISCOVERY_TIMEOUT 30
    )

    gtest_discover_tests(bseal_pipeline_gtests
            TEST_PREFIX pipeline.
            DISCOVERY_TIMEOUT 30
    )
else()
    add_test(NAME bseal_common_gtests COMMAND bseal_common_gtests)
    add_test(NAME bseal_platform_gtests COMMAND bseal_platform_gtests)
    add_test(NAME bseal_io_gtests COMMAND bseal_io_gtests)
    add_test(NAME bseal_archive_gtests COMMAND bseal_archive_gtests)
    add_test(NAME bseal_crypto_gtests COMMAND bseal_crypto_gtests)
    add_test(NAME bseal_pipeline_gtests COMMAND bseal_pipeline_gtests)
endif()


add_executable(bseal_perf_gtests
    perf/TestAeadThroughput.cpp
    perf/TestKdfLatency.cpp
)

target_link_libraries(bseal_perf_gtests PRIVATE bseal::core ${BSEAL_GTEST_LIBS})
bseal_set_project_warnings(bseal_perf_gtests)
bseal_enable_sanitizers_if_requested(bseal_perf_gtests)
bseal_enable_coverage_if_requested(bseal_perf_gtests)

if (GTest_FOUND)
    include(GoogleTest)
    gtest_discover_tests(bseal_perf_gtests
            TEST_PREFIX perf.
            DISCOVERY_TIMEOUT 30
    )
else()
    add_test(NAME bseal_perf_gtests COMMAND bseal_perf_gtests)
endif()

# ---------------------------------------------------------------------------
# Black-box integration tests
# ---------------------------------------------------------------------------
#
# These tests execute the built bseal application as a user would.
# They intentionally do not include project internals.
#
# The generated config header gives the test binary the absolute path to the
# freshly built bseal executable.

file(GENERATE
        OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/generated/integration/$<CONFIG>/BsealIntegrationConfig.hpp"
        CONTENT
        "#pragma once
inline constexpr const char* BSEAL_BINARY_PATH = R\"bseal_path($<TARGET_FILE:bseal>)bseal_path\";
"
)

add_executable(bseal_integration_gtests
        integration/TestBlackBoxCli.cpp
        integration/TestCliRegression.cpp
        integration/TestFormatV1Archive.cpp
        integration/TestKdfPolicyCli.cpp
)

add_dependencies(bseal_integration_gtests bseal)

target_include_directories(bseal_integration_gtests
        PRIVATE
        "${CMAKE_CURRENT_BINARY_DIR}/generated/integration/$<CONFIG>"
        "${CMAKE_CURRENT_BINARY_DIR}/generated/format-v1-kat/$<CONFIG>"
)

target_link_libraries(bseal_integration_gtests PRIVATE ${BSEAL_GTEST_LIBS})
target_compile_features(bseal_integration_gtests PRIVATE cxx_std_20)
bseal_set_project_warnings(bseal_integration_gtests)
bseal_enable_sanitizers_if_requested(bseal_integration_gtests)
bseal_enable_coverage_if_requested(bseal_integration_gtests)

if (GTest_FOUND)
    include(GoogleTest)

    gtest_discover_tests(bseal_integration_gtests
            TEST_PREFIX integration.
            DISCOVERY_TIMEOUT 60
    )
else()
    add_test(NAME bseal_integration_gtests COMMAND bseal_integration_gtests)
endif()

# ---------------------------------------------------------------------------
# Repository scanner: test-only crypto bypass guardrail
# ---------------------------------------------------------------------------
#
# scan.UnsafeBypassGuard  — verifies that unsafe test-only bypass tokens
#   (UnsafeSkipHeaderAuthenticationForTests, UnsafeAllowMissingShardAadForTests)
#   do not appear in production source files outside their declaration sites
#   in src/io/.
#
# scan.UnsafeBypassGuardSelfTest — runs the scanner's own unit tests,
#   including a negative fixture that proves the scanner detects violations.
#
# Both tests run with every `ctest` invocation.  They require Python 3 and
# have no build-system dependencies (they inspect the source tree directly).
# ---------------------------------------------------------------------------

find_package(Python3 QUIET COMPONENTS Interpreter)

if (Python3_FOUND)
    set(BSEAL_SCANNER_SCRIPT "${CMAKE_SOURCE_DIR}/tests/scripts/scan_unsafe_bypasses.py")
    set(BSEAL_SCANNER_SELFTEST "${CMAKE_SOURCE_DIR}/tests/scripts/test_scan_unsafe_bypasses.py")
    set(BSEAL_CHECKLIST_SCRIPT "${CMAKE_SOURCE_DIR}/tests/scripts/check_release_checklist.py")
    set(BSEAL_DOCS_LANGUAGE_SCRIPT "${CMAKE_SOURCE_DIR}/tests/scripts/check_docs_language.py")

    add_test(
        NAME scan.UnsafeBypassGuard
        COMMAND "${Python3_EXECUTABLE}" "${BSEAL_SCANNER_SCRIPT}"
                "--repo-root" "${CMAKE_SOURCE_DIR}"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    )
    set_tests_properties(scan.UnsafeBypassGuard PROPERTIES
        LABELS "scan"
    )

    add_test(
        NAME scan.UnsafeBypassGuardSelfTest
        COMMAND "${Python3_EXECUTABLE}" "${BSEAL_SCANNER_SELFTEST}"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    )
    set_tests_properties(scan.UnsafeBypassGuardSelfTest PROPERTIES
        LABELS "scan"
    )

    add_test(
        NAME scan.ReleaseChecklistConsistency
        COMMAND "${Python3_EXECUTABLE}" "${BSEAL_CHECKLIST_SCRIPT}"
                "--repo-root" "${CMAKE_SOURCE_DIR}"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    )
    set_tests_properties(scan.ReleaseChecklistConsistency PROPERTIES
        LABELS "scan"
    )

    add_test(
        NAME scan.DocsLanguage
        COMMAND "${Python3_EXECUTABLE}" "${BSEAL_DOCS_LANGUAGE_SCRIPT}"
                "--repo-root" "${CMAKE_SOURCE_DIR}"
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    )
    set_tests_properties(scan.DocsLanguage PROPERTIES
        LABELS "scan"
    )
else()
    message(WARNING
        "Python 3 not found; scan.* tests will not be registered. "
        "Install Python 3 to enable the unsafe bypass guardrail and docs consistency checks."
    )
endif()


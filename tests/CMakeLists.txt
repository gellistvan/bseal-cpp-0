add_executable(bseal_smoke_tests smoke_tests.cpp)
target_link_libraries(bseal_smoke_tests PRIVATE bseal::core)
bseal_set_project_warnings(bseal_smoke_tests)
bseal_enable_sanitizers_if_requested(bseal_smoke_tests)
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
    set(BSEAL_GTEST_LIBS bseal_minigtest_main)
endif()

add_executable(bseal_platform_gtests
    platform/TestRandom.cpp
    platform/TestMemoryLock.cpp
    platform/TestCpuFeatures.cpp
)

target_link_libraries(bseal_platform_gtests PRIVATE bseal::core ${BSEAL_GTEST_LIBS})
bseal_set_project_warnings(bseal_platform_gtests)
bseal_enable_sanitizers_if_requested(bseal_platform_gtests)

add_executable(bseal_io_gtests
        io/TestAsyncReader.cpp
        io/TestAsyncWriter.cpp
        io/TestBufferPool.cpp
        io/TestShardReader.cpp
        io/TestShardWriter.cpp
)

target_link_libraries(bseal_io_gtests PRIVATE bseal::core ${BSEAL_GTEST_LIBS})
bseal_set_project_warnings(bseal_io_gtests)
bseal_enable_sanitizers_if_requested(bseal_io_gtests)

add_executable(bseal_archive_gtests
        archive/TestArchiveReader.cpp
        archive/TestArchiveWriter.cpp
        archive/TestMetadata.cpp
        archive/TestPathSanitizer.cpp
        archive/TestRecordFormat.cpp
)

target_link_libraries(bseal_archive_gtests PRIVATE bseal::core ${BSEAL_GTEST_LIBS})
bseal_set_project_warnings(bseal_archive_gtests)
bseal_enable_sanitizers_if_requested(bseal_archive_gtests)

add_executable(bseal_crypto_gtests
        crypto/TestSecureBuffer.cpp
        crypto/TestAesGcmBackend.cpp
        crypto/TestXChaCha20Poly1305Backend.cpp
        crypto/TestKdf.cpp
        crypto/TestKeySchedule.cpp
)

target_link_libraries(bseal_crypto_gtests PRIVATE bseal::core ${BSEAL_GTEST_LIBS})
bseal_set_project_warnings(bseal_crypto_gtests)
bseal_enable_sanitizers_if_requested(bseal_crypto_gtests)

add_executable(bseal_pipeline_gtests
        pipeline/TestWorkQueue.cpp
        pipeline/TestEncryptPipeline.cpp
        pipeline/TestDecryptPipeline.cpp
)

target_link_libraries(bseal_pipeline_gtests PRIVATE bseal::core ${BSEAL_GTEST_LIBS})
bseal_set_project_warnings(bseal_pipeline_gtests)
bseal_enable_sanitizers_if_requested(bseal_pipeline_gtests)

if (GTest_FOUND)
    include(GoogleTest)

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
            TEST_PREFIX platform.
            DISCOVERY_TIMEOUT 30
    )
else()
    add_test(NAME bseal_platform_gtests COMMAND bseal_platform_gtests)
    add_test(NAME bseal_io_gtests COMMAND bseal_io_gtests)
    add_test(NAME bseal_archive_gtests COMMAND bseal_archive_gtests)
    add_test(NAME bseal_crypto_gtests COMMAND bseal_crypto_gtests)
    add_test(NAME bseal_pipeline_gtests COMMAND bseal_pipeline_gtests)
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
)

add_dependencies(bseal_integration_gtests bseal)

target_include_directories(bseal_integration_gtests
        PRIVATE
        "${CMAKE_CURRENT_BINARY_DIR}/generated/integration/$<CONFIG>"
)

target_link_libraries(bseal_integration_gtests PRIVATE ${BSEAL_GTEST_LIBS})
target_compile_features(bseal_integration_gtests PRIVATE cxx_std_20)
bseal_set_project_warnings(bseal_integration_gtests)
bseal_enable_sanitizers_if_requested(bseal_integration_gtests)

if (GTest_FOUND)
    include(GoogleTest)

    gtest_discover_tests(bseal_integration_gtests
            TEST_PREFIX integration.
            DISCOVERY_TIMEOUT 60
    )
else()
    add_test(NAME bseal_integration_gtests COMMAND bseal_integration_gtests)
endif()


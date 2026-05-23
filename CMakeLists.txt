cmake_minimum_required(VERSION 3.24)

project(bseal
    VERSION 0.1.0
    DESCRIPTION "BSEAL binary folder sealing skeleton"
    LANGUAGES CXX
)

option(BSEAL_BUILD_TESTS "Build smoke tests" ON)
option(BSEAL_ENABLE_SANITIZERS "Enable ASan/UBSan for local development" OFF)
option(BSEAL_ENABLE_INSTALL "Enable install rules" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(ProjectWarnings)
include(Sanitizers)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/external_libraries/blake3.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/external_libraries/argon2.cmake)

add_library(bseal_core
    src/app/BsealApp.cpp
    src/cli/Args.cpp
    src/crypto/AesGcmBackend.cpp
    src/crypto/Kdf.cpp
    src/crypto/KeySchedule.cpp
    src/crypto/SecureBuffer.cpp
    src/crypto/XChaCha20Poly1305Backend.cpp
    src/archive/ArchiveReader.cpp
    src/archive/ArchiveWriter.cpp
    src/archive/PathSanitizer.cpp
    src/archive/RecordFormat.cpp
    src/archive/SafeOutputTree.cpp
    src/io/AsyncReader.cpp
    src/io/AsyncWriter.cpp
    src/io/BufferPool.cpp
    src/io/ShardFrame.cpp
    src/io/ShardReader.cpp
    src/io/ShardWriter.cpp
    src/pipeline/DecryptPipeline.cpp
    src/pipeline/EncryptPipeline.cpp
    src/platform/CpuFeatures.cpp
    src/platform/MemoryLock.cpp
    src/platform/Random.cpp
)

add_library(bseal::core ALIAS bseal_core)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
find_package(OpenSSL REQUIRED)

target_link_libraries(bseal_core
        PRIVATE
        PkgConfig::SODIUM
        OpenSSL::Crypto
        blake3::blake3
        argon2::argon2
)


target_include_directories(bseal_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<INSTALL_INTERFACE:include>
)

target_compile_features(bseal_core PUBLIC cxx_std_20)
bseal_set_project_warnings(bseal_core)
bseal_enable_sanitizers_if_requested(bseal_core)

add_executable(bseal src/main.cpp)
target_link_libraries(bseal PRIVATE bseal::core)
bseal_set_project_warnings(bseal)
bseal_enable_sanitizers_if_requested(bseal)

if (BSEAL_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if (BSEAL_ENABLE_INSTALL)
    install(TARGETS bseal bseal_core
        EXPORT bsealTargets
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
    )
    install(DIRECTORY src/ DESTINATION include/bseal
        FILES_MATCHING PATTERN "*.hpp")
endif()

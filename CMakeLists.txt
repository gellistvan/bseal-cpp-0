cmake_minimum_required(VERSION 3.24)

project(bseal
    VERSION 0.1.0
    DESCRIPTION "BSEAL experimental directory encryption tool"
    LANGUAGES CXX
)

option(BSEAL_BUILD_TESTS "Build tests" ON)
option(BSEAL_BUILD_FUZZERS "Build coverage-guided fuzz targets (requires Clang with libFuzzer)" OFF)
option(BSEAL_ENABLE_SANITIZERS "Enable ASan/UBSan for local development" OFF)
option(BSEAL_ENABLE_TSAN "Enable ThreadSanitizer (incompatible with BSEAL_ENABLE_SANITIZERS)" OFF)
option(BSEAL_ENABLE_COVERAGE "Enable line/function coverage instrumentation (gcov/gcovr)" OFF)
option(BSEAL_ENABLE_INSTALL "Enable install rules" OFF)
option(BSEAL_FUZZ_STATIC_LINK "Link libsodium and OpenSSL statically (required for OSS-Fuzz/ClusterFuzzLite)" OFF)
# SECURITY: NEVER enable in release/production builds. Allows env vars to inject
# deterministic kdf_salt and archive_id, bypassing random generation. Nonce and key
# reuse is catastrophic for both XChaCha20-Poly1305 and AES-GCM.
option(BSEAL_ENABLE_TEST_SEAMS "Enable env-var seams for deterministic key/nonce injection (test builds only)" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(VerifySubmodules)
include(ProjectWarnings)
include(Sanitizers)
include(Coverage)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/external_libraries/blake3.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/external_libraries/argon2.cmake)

add_library(bseal_core
    src/app/BsealApp.cpp
    src/app/CoreApi.cpp
    src/app/SelfTest.cpp
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
    src/io/StdoutShardWriter.cpp
    src/pipeline/DecryptPipeline.cpp
    src/pipeline/EncryptPipeline.cpp
    src/platform/CpuFeatures.cpp
    src/platform/DurableFile.cpp
    src/platform/MemoryLock.cpp
    src/platform/PassphrasePrompt.cpp
    src/platform/ProcessMemoryLock.cpp
    src/platform/Random.cpp
)

add_library(bseal::core ALIAS bseal_core)
if (BSEAL_FUZZ_STATIC_LINK)
    # OSS-Fuzz/ClusterFuzzLite: fuzzer runner containers have no shared libs.
    # Locate the static archives directly so the binaries are self-contained.
    find_package(PkgConfig REQUIRED)
    find_library(SODIUM_STATIC_LIB NAMES libsodium.a REQUIRED)
    find_path(SODIUM_INCLUDE_DIR NAMES sodium.h PATH_SUFFIXES sodium)
    add_library(_bseal_sodium STATIC IMPORTED)
    set_target_properties(_bseal_sodium PROPERTIES IMPORTED_LOCATION "${SODIUM_STATIC_LIB}")
    if (SODIUM_INCLUDE_DIR)
        set_target_properties(_bseal_sodium PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}")
    endif()
    set(BSEAL_SODIUM_TARGET _bseal_sodium)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
elseif (WIN32)
    # Windows: use vcpkg's CMake config (unofficial-sodium) instead of pkg-config.
    find_package(unofficial-sodium CONFIG REQUIRED)
    set(BSEAL_SODIUM_TARGET unofficial-sodium::sodium)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
    set(BSEAL_SODIUM_TARGET PkgConfig::SODIUM)
endif()
find_package(OpenSSL REQUIRED)

target_link_libraries(bseal_core
        PRIVATE
        ${BSEAL_SODIUM_TARGET}
        OpenSSL::Crypto
        blake3::blake3
        argon2::argon2
)

if (WIN32)
    # BCryptGenRandom used in platform/Random.cpp on Windows.
    target_link_libraries(bseal_core PRIVATE bcrypt)
endif()


target_include_directories(bseal_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<INSTALL_INTERFACE:include>
)

target_compile_features(bseal_core PUBLIC cxx_std_20)
bseal_set_project_warnings(bseal_core)

if (BSEAL_ENABLE_TEST_SEAMS)
    target_compile_definitions(bseal_core PRIVATE BSEAL_ENABLE_TEST_SEAMS)
endif()

bseal_enable_sanitizers_if_requested(bseal_core)
bseal_enable_tsan_if_requested(bseal_core)
bseal_enable_coverage_if_requested(bseal_core)

add_executable(bseal src/main.cpp)
target_link_libraries(bseal PRIVATE bseal::core)
bseal_set_project_warnings(bseal)
bseal_enable_sanitizers_if_requested(bseal)
bseal_enable_tsan_if_requested(bseal)
bseal_enable_coverage_if_requested(bseal)

if (BSEAL_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Optional Qt 6 Widgets GUI (default OFF — no Qt dependency when disabled)
# ---------------------------------------------------------------------------

option(BSEAL_ENABLE_QT_GUI "Build the bseal-gui Qt Widgets application" OFF)

if (BSEAL_ENABLE_QT_GUI)
    find_package(Qt6 REQUIRED COMPONENTS Widgets)

    qt_add_executable(bseal-gui
        src/gui/main.cpp
        src/gui/GuiErrorPresenter.cpp
        src/gui/GuiOptions.cpp
        src/gui/GuiPreview.cpp
        src/gui/EncryptOptionsWidget.cpp
        src/gui/DecryptOptionsWidget.cpp
        src/gui/MainWindow.cpp
        src/gui/SecurePassphraseField.cpp
    )
    # Qt 6.4 does not auto-enable AUTOMOC on qt_add_executable; set per-target.
    set_target_properties(bseal-gui PROPERTIES AUTOMOC ON)

    target_link_libraries(bseal-gui PRIVATE
        bseal::core
        Qt6::Widgets
    )

    target_include_directories(bseal-gui PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
    )

    bseal_set_project_warnings(bseal-gui)
    bseal_enable_sanitizers_if_requested(bseal-gui)
    bseal_enable_tsan_if_requested(bseal-gui)
    bseal_enable_coverage_if_requested(bseal-gui)

    if (BSEAL_BUILD_TESTS)
        enable_testing()
        add_test(NAME gui.SmokeRun COMMAND bseal-gui --selftest)
        set_tests_properties(gui.SmokeRun PROPERTIES
            ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
            TIMEOUT 10
        )

        # Shared GUI source files used by all MainWindow-based test targets.
        set(BSEAL_GUI_SOURCES
            src/gui/SecurePassphraseField.cpp
            src/gui/GuiErrorPresenter.cpp
            src/gui/GuiOptions.cpp
            src/gui/GuiPreview.cpp
            src/gui/EncryptOptionsWidget.cpp
            src/gui/DecryptOptionsWidget.cpp
            src/gui/MainWindow.cpp
        )

        # Pure C++ unit tests for the GuiOptions model (no Qt required).
        add_executable(bseal_gui_options_gtests
            src/gui/GuiOptions.cpp
            tests/gui/TestGuiOptions.cpp
        )
        target_link_libraries(bseal_gui_options_gtests PRIVATE bseal::core)
        target_include_directories(bseal_gui_options_gtests PRIVATE
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        )
        bseal_set_project_warnings(bseal_gui_options_gtests)
        bseal_enable_sanitizers_if_requested(bseal_gui_options_gtests)
        add_test(NAME gui.Options COMMAND bseal_gui_options_gtests)
        set_tests_properties(gui.Options PROPERTIES TIMEOUT 10)

        # Pure C++ unit tests for GuiPreview (no Qt required).
        add_executable(bseal_gui_preview_unit_gtests
            src/gui/GuiOptions.cpp
            src/gui/GuiPreview.cpp
            tests/gui/TestGuiPreviewUnit.cpp
        )
        target_link_libraries(bseal_gui_preview_unit_gtests PRIVATE bseal::core)
        target_include_directories(bseal_gui_preview_unit_gtests PRIVATE
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        )
        bseal_set_project_warnings(bseal_gui_preview_unit_gtests)
        bseal_enable_sanitizers_if_requested(bseal_gui_preview_unit_gtests)
        add_test(NAME gui.PreviewUnit COMMAND bseal_gui_preview_unit_gtests)
        set_tests_properties(gui.PreviewUnit PROPERTIES TIMEOUT 10)

        add_executable(bseal_gui_gtests
            src/gui/SecurePassphraseField.cpp
            src/gui/GuiErrorPresenter.cpp
            tests/gui/TestSecurePassphraseField.cpp
        )
        add_executable(bseal_gui_keyfile_gtests
            ${BSEAL_GUI_SOURCES}
            tests/gui/TestMainWindowKeyfiles.cpp
        )
        add_executable(bseal_gui_integration_gtests
            ${BSEAL_GUI_SOURCES}
            tests/gui/TestGuiCoreIntegration.cpp
        )
        add_executable(bseal_gui_memlock_gtests
            ${BSEAL_GUI_SOURCES}
            tests/gui/TestGuiMemoryLock.cpp
        )
        add_executable(bseal_gui_error_presenter_gtests
            ${BSEAL_GUI_SOURCES}
            tests/gui/TestGuiErrorPresenter.cpp
        )
        add_executable(bseal_gui_nonpersistence_gtests
            ${BSEAL_GUI_SOURCES}
            tests/gui/TestGuiNonPersistence.cpp
        )
        add_executable(bseal_gui_advanced_encrypt_gtests
            ${BSEAL_GUI_SOURCES}
            tests/gui/TestGuiAdvancedEncrypt.cpp
        )
        add_executable(bseal_gui_advanced_decrypt_gtests
            ${BSEAL_GUI_SOURCES}
            tests/gui/TestGuiAdvancedDecrypt.cpp
        )
        add_executable(bseal_gui_preview_gtests
            ${BSEAL_GUI_SOURCES}
            tests/gui/TestGuiPreview.cpp
        )
        add_executable(bseal_gui_options_widgets_gtests
            ${BSEAL_GUI_SOURCES}
            tests/gui/TestGuiOptionsWidgets.cpp
        )
        add_executable(bseal_gui_validation_order_gtests
            ${BSEAL_GUI_SOURCES}
            tests/gui/TestGuiValidationOrder.cpp
        )
        add_executable(bseal_gui_parity_gtests
            ${BSEAL_GUI_SOURCES}
            tests/gui/TestGuiFeatureParity.cpp
        )

        foreach(_t bseal_gui_gtests bseal_gui_keyfile_gtests bseal_gui_integration_gtests bseal_gui_memlock_gtests bseal_gui_error_presenter_gtests bseal_gui_nonpersistence_gtests bseal_gui_advanced_encrypt_gtests bseal_gui_advanced_decrypt_gtests bseal_gui_preview_gtests bseal_gui_options_widgets_gtests bseal_gui_validation_order_gtests bseal_gui_parity_gtests)
            set_target_properties(${_t} PROPERTIES AUTOMOC ON)
            target_link_libraries(${_t} PRIVATE bseal::core Qt6::Widgets)
            target_include_directories(${_t} PRIVATE
                $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
            )
            bseal_set_project_warnings(${_t})
            bseal_enable_sanitizers_if_requested(${_t})
        endforeach()

        add_test(NAME gui.SecurePassphraseField COMMAND bseal_gui_gtests)
        set_tests_properties(gui.SecurePassphraseField PROPERTIES
            ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
            TIMEOUT 10
        )
        add_test(NAME gui.MainWindowKeyfiles COMMAND bseal_gui_keyfile_gtests)
        set_tests_properties(gui.MainWindowKeyfiles PROPERTIES
            ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
            TIMEOUT 10
        )
        add_test(NAME gui.CoreIntegration COMMAND bseal_gui_integration_gtests)
        set_tests_properties(gui.CoreIntegration PROPERTIES
            ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
            TIMEOUT 120
        )
        add_test(NAME gui.MemoryLock COMMAND bseal_gui_memlock_gtests)
        set_tests_properties(gui.MemoryLock PROPERTIES
            ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
            TIMEOUT 120
        )
        add_test(NAME gui.ErrorPresenter COMMAND bseal_gui_error_presenter_gtests)
        set_tests_properties(gui.ErrorPresenter PROPERTIES
            ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
            TIMEOUT 60
        )
        add_test(NAME gui.NonPersistence COMMAND bseal_gui_nonpersistence_gtests)
        set_tests_properties(gui.NonPersistence PROPERTIES
            ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
            TIMEOUT 10
        )
        add_test(NAME gui.AdvancedEncrypt COMMAND bseal_gui_advanced_encrypt_gtests)
        set_tests_properties(gui.AdvancedEncrypt PROPERTIES
            ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
            TIMEOUT 10
        )
        add_test(NAME gui.AdvancedDecrypt COMMAND bseal_gui_advanced_decrypt_gtests)
        set_tests_properties(gui.AdvancedDecrypt PROPERTIES
            ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
            TIMEOUT 30
        )
        add_test(NAME gui.Preview COMMAND bseal_gui_preview_gtests)
        set_tests_properties(gui.Preview PROPERTIES
            ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
            TIMEOUT 30
        )
        add_test(NAME gui.OptionsWidgets COMMAND bseal_gui_options_widgets_gtests)
        set_tests_properties(gui.OptionsWidgets PROPERTIES
            ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
            TIMEOUT 10
        )
        add_test(NAME gui.ValidationOrder COMMAND bseal_gui_validation_order_gtests)
        set_tests_properties(gui.ValidationOrder PROPERTIES
            ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
            TIMEOUT 30
        )
        add_test(NAME gui.FeatureParity COMMAND bseal_gui_parity_gtests)
        set_tests_properties(gui.FeatureParity PROPERTIES
            ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
            TIMEOUT 10
        )
    endif()

    if (BSEAL_ENABLE_INSTALL)
        install(TARGETS bseal-gui RUNTIME DESTINATION bin COMPONENT runtime)

        if (WIN32)
            # Bundle Qt DLLs next to bseal-gui.exe so the package is self-contained.
            find_program(WINDEPLOYQT_EXECUTABLE windeployqt
                HINTS "${Qt6_DIR}/../../../bin"
                REQUIRED
            )
            install(CODE "
                execute_process(
                    COMMAND \"${WINDEPLOYQT_EXECUTABLE}\"
                        --no-translations
                        --no-compiler-runtime
                        --no-system-d3d-compiler
                        --no-opengl-sw
                        \"\${CMAKE_INSTALL_PREFIX}/bin/bseal-gui.exe\"
                    RESULT_VARIABLE _rc
                )
                if(NOT _rc EQUAL 0)
                    message(FATAL_ERROR \"windeployqt failed with exit code \${_rc}\")
                endif()
            " COMPONENT runtime)
        endif()
    endif()
endif()

if (BSEAL_BUILD_FUZZERS)
    enable_testing()
    add_subdirectory(tests/fuzz)
endif()

if (BSEAL_ENABLE_INSTALL)
    install(TARGETS bseal
        RUNTIME DESTINATION bin
        COMPONENT runtime
    )
    install(TARGETS bseal_core
        EXPORT bsealTargets
        ARCHIVE DESTINATION lib
        COMPONENT dev
    )
    install(DIRECTORY src/ DESTINATION include/bseal
        COMPONENT dev
        FILES_MATCHING PATTERN "*.hpp"
    )
endif()

# ---------------------------------------------------------------------------
# CPack — minimal packaging config (ZIP on Windows, DEB on Linux)
# include(CPack) must come after all install() calls.
# ---------------------------------------------------------------------------
if (BSEAL_ENABLE_INSTALL)
    set(CPACK_PACKAGE_NAME              "bseal")
    set(CPACK_PACKAGE_VERSION           "${PROJECT_VERSION}")
    set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PROJECT_DESCRIPTION}")
    set(CPACK_PACKAGE_VENDOR            "BSEAL Project")
    set(CPACK_PACKAGE_CONTACT           "istvan.gellai@gmail.com")
    set(CPACK_RESOURCE_FILE_LICENSE     "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
    set(CPACK_STRIP_FILES               ON)
    # Package only the runtime component; exclude dev headers and static lib.
    # CPACK_ARCHIVE_COMPONENT_INSTALL must be ON — without it the ZIP/DEB
    # generators ignore CPACK_COMPONENTS_ALL and bundle every installed file.
    set(CPACK_COMPONENTS_ALL              runtime)
    set(CPACK_COMPONENT_RUNTIME_REQUIRED  ON)
    set(CPACK_ARCHIVE_COMPONENT_INSTALL   ON)

    if (WIN32)
        set(CPACK_GENERATOR   "ZIP")
        set(CPACK_SYSTEM_NAME "win64")
        # Component packaging would suffix the filename with "-runtime"; override
        # it so the output stays bseal-<version>-win64.zip.
        set(CPACK_ARCHIVE_RUNTIME_FILE_NAME
            "${CPACK_PACKAGE_NAME}-${PROJECT_VERSION}-${CPACK_SYSTEM_NAME}")
    else()
        set(CPACK_GENERATOR  "DEB")
        set(CPACK_DEBIAN_PACKAGE_SECTION  "utils")
        set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
        # Auto-detect runtime .so deps from the linked binary (requires dpkg-dev).
        set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
        set(CPACK_DEB_COMPONENT_INSTALL    ON)
        set(CPACK_DEBIAN_RUNTIME_PACKAGE_NAME "${CPACK_PACKAGE_NAME}")
    endif()

    include(CPack)
endif()

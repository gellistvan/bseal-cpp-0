# CMake generated Testfile for 
# Source directory: /home/igellai/projects/bseal-cpp-skeleton
# Build directory: /home/igellai/projects/bseal-cpp-skeleton/build-gui-test
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test([=[gui.SmokeRun]=] "/home/igellai/projects/bseal-cpp-skeleton/build-gui-test/bseal-gui" "--selftest")
set_tests_properties([=[gui.SmokeRun]=] PROPERTIES  ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT "10" _BACKTRACE_TRIPLES "/home/igellai/projects/bseal-cpp-skeleton/CMakeLists.txt;150;add_test;/home/igellai/projects/bseal-cpp-skeleton/CMakeLists.txt;0;")
add_test([=[gui.SecurePassphraseField]=] "/home/igellai/projects/bseal-cpp-skeleton/build-gui-test/bseal_gui_gtests")
set_tests_properties([=[gui.SecurePassphraseField]=] PROPERTIES  ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT "10" _BACKTRACE_TRIPLES "/home/igellai/projects/bseal-cpp-skeleton/CMakeLists.txt;202;add_test;/home/igellai/projects/bseal-cpp-skeleton/CMakeLists.txt;0;")
add_test([=[gui.MainWindowKeyfiles]=] "/home/igellai/projects/bseal-cpp-skeleton/build-gui-test/bseal_gui_keyfile_gtests")
set_tests_properties([=[gui.MainWindowKeyfiles]=] PROPERTIES  ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT "10" _BACKTRACE_TRIPLES "/home/igellai/projects/bseal-cpp-skeleton/CMakeLists.txt;207;add_test;/home/igellai/projects/bseal-cpp-skeleton/CMakeLists.txt;0;")
add_test([=[gui.CoreIntegration]=] "/home/igellai/projects/bseal-cpp-skeleton/build-gui-test/bseal_gui_integration_gtests")
set_tests_properties([=[gui.CoreIntegration]=] PROPERTIES  ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT "120" _BACKTRACE_TRIPLES "/home/igellai/projects/bseal-cpp-skeleton/CMakeLists.txt;212;add_test;/home/igellai/projects/bseal-cpp-skeleton/CMakeLists.txt;0;")
add_test([=[gui.MemoryLock]=] "/home/igellai/projects/bseal-cpp-skeleton/build-gui-test/bseal_gui_memlock_gtests")
set_tests_properties([=[gui.MemoryLock]=] PROPERTIES  ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT "120" _BACKTRACE_TRIPLES "/home/igellai/projects/bseal-cpp-skeleton/CMakeLists.txt;217;add_test;/home/igellai/projects/bseal-cpp-skeleton/CMakeLists.txt;0;")
add_test([=[gui.ErrorPresenter]=] "/home/igellai/projects/bseal-cpp-skeleton/build-gui-test/bseal_gui_error_presenter_gtests")
set_tests_properties([=[gui.ErrorPresenter]=] PROPERTIES  ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT "60" _BACKTRACE_TRIPLES "/home/igellai/projects/bseal-cpp-skeleton/CMakeLists.txt;222;add_test;/home/igellai/projects/bseal-cpp-skeleton/CMakeLists.txt;0;")
add_test([=[gui.NonPersistence]=] "/home/igellai/projects/bseal-cpp-skeleton/build-gui-test/bseal_gui_nonpersistence_gtests")
set_tests_properties([=[gui.NonPersistence]=] PROPERTIES  ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT "10" _BACKTRACE_TRIPLES "/home/igellai/projects/bseal-cpp-skeleton/CMakeLists.txt;227;add_test;/home/igellai/projects/bseal-cpp-skeleton/CMakeLists.txt;0;")
subdirs("tests")

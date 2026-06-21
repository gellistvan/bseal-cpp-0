// SPDX-License-Identifier: Apache-2.0
#include "gui/MainWindow.hpp"

#include <QApplication>
#include <string_view>

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    app.setApplicationName("bseal");
    app.setApplicationVersion("0.1.0");

    // ponytail: --selftest constructs the window and exits; used by ctest with QT_QPA_PLATFORM=offscreen
    for (int i = 1; i < argc; ++i) {
        if (std::string_view(argv[i]) == "--selftest") {
            bseal::gui::MainWindow w;
            return 0;
        }
    }

    bseal::gui::MainWindow w;
    w.show();
    return QApplication::exec();
}

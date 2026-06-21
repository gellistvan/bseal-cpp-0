// SPDX-License-Identifier: Apache-2.0
#include "gui/MainWindow.hpp"

#include <QLabel>
#include <QVBoxLayout>
#include <QWidget>

namespace bseal::gui {

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle("BSEAL");
    setMinimumSize(640, 400);

    auto* central = new QWidget(this);
    auto* layout  = new QVBoxLayout(central);
    auto* label   = new QLabel(
        "BSEAL Encryption Tool\n\nEncrypt/decrypt UI not yet implemented.\n\n"
        "Use the bseal CLI for encryption and decryption.",
        central);
    label->setAlignment(Qt::AlignCenter);
    layout->addWidget(label);
    setCentralWidget(central);
}

} // namespace bseal::gui

// Qt 6 AUTOMOC: trigger moc generation when included from MainWindow.cpp's TU.
#include "moc_MainWindow.cpp" // NOLINT(build/include)

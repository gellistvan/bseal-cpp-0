// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <QMainWindow>

namespace bseal::gui {

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);
};

} // namespace bseal::gui

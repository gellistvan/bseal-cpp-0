/****************************************************************************
** Meta object code from reading C++ file 'MainWindow.hpp'
**
** Created by: The Qt Meta Object Compiler version 68 (Qt 6.4.2)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include <memory>
#include "../../../src/gui/MainWindow.hpp"
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'MainWindow.hpp' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 68
#error "This file was generated using the moc from 6.4.2. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

#ifndef Q_CONSTINIT
#define Q_CONSTINIT
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
namespace {
struct qt_meta_stringdata_bseal__gui__MainWindow_t {
    uint offsetsAndSizes[24];
    char stringdata0[23];
    char stringdata1[14];
    char stringdata2[1];
    char stringdata3[3];
    char stringdata4[4];
    char stringdata5[14];
    char stringdata6[15];
    char stringdata7[13];
    char stringdata8[16];
    char stringdata9[16];
    char stringdata10[6];
    char stringdata11[20];
};
#define QT_MOC_LITERAL(ofs, len) \
    uint(sizeof(qt_meta_stringdata_bseal__gui__MainWindow_t::offsetsAndSizes) + ofs), len 
Q_CONSTINIT static const qt_meta_stringdata_bseal__gui__MainWindow_t qt_meta_stringdata_bseal__gui__MainWindow = {
    {
        QT_MOC_LITERAL(0, 22),  // "bseal::gui::MainWindow"
        QT_MOC_LITERAL(23, 13),  // "operationDone"
        QT_MOC_LITERAL(37, 0),  // ""
        QT_MOC_LITERAL(38, 2),  // "ok"
        QT_MOC_LITERAL(41, 3),  // "msg"
        QT_MOC_LITERAL(45, 13),  // "onBrowseInput"
        QT_MOC_LITERAL(59, 14),  // "onBrowseOutput"
        QT_MOC_LITERAL(74, 12),  // "onAddKeyfile"
        QT_MOC_LITERAL(87, 15),  // "onRemoveKeyfile"
        QT_MOC_LITERAL(103, 15),  // "onClearKeyfiles"
        QT_MOC_LITERAL(119, 5),  // "onRun"
        QT_MOC_LITERAL(125, 19)   // "onOperationFinished"
    },
    "bseal::gui::MainWindow",
    "operationDone",
    "",
    "ok",
    "msg",
    "onBrowseInput",
    "onBrowseOutput",
    "onAddKeyfile",
    "onRemoveKeyfile",
    "onClearKeyfiles",
    "onRun",
    "onOperationFinished"
};
#undef QT_MOC_LITERAL
} // unnamed namespace

Q_CONSTINIT static const uint qt_meta_data_bseal__gui__MainWindow[] = {

 // content:
      10,       // revision
       0,       // classname
       0,    0, // classinfo
       8,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       1,       // signalCount

 // signals: name, argc, parameters, tag, flags, initial metatype offsets
       1,    2,   62,    2, 0x06,    1 /* Public */,

 // slots: name, argc, parameters, tag, flags, initial metatype offsets
       5,    0,   67,    2, 0x08,    4 /* Private */,
       6,    0,   68,    2, 0x08,    5 /* Private */,
       7,    0,   69,    2, 0x08,    6 /* Private */,
       8,    0,   70,    2, 0x08,    7 /* Private */,
       9,    0,   71,    2, 0x08,    8 /* Private */,
      10,    0,   72,    2, 0x08,    9 /* Private */,
      11,    2,   73,    2, 0x08,   10 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::Bool, QMetaType::QString,    3,    4,

 // slots: parameters
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void,
    QMetaType::Void, QMetaType::Bool, QMetaType::QString,    3,    4,

       0        // eod
};

Q_CONSTINIT const QMetaObject bseal::gui::MainWindow::staticMetaObject = { {
    QMetaObject::SuperData::link<QMainWindow::staticMetaObject>(),
    qt_meta_stringdata_bseal__gui__MainWindow.offsetsAndSizes,
    qt_meta_data_bseal__gui__MainWindow,
    qt_static_metacall,
    nullptr,
    qt_incomplete_metaTypeArray<qt_meta_stringdata_bseal__gui__MainWindow_t,
        // Q_OBJECT / Q_GADGET
        QtPrivate::TypeAndForceComplete<MainWindow, std::true_type>,
        // method 'operationDone'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<bool, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>,
        // method 'onBrowseInput'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onBrowseOutput'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onAddKeyfile'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onRemoveKeyfile'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onClearKeyfiles'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onRun'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        // method 'onOperationFinished'
        QtPrivate::TypeAndForceComplete<void, std::false_type>,
        QtPrivate::TypeAndForceComplete<bool, std::false_type>,
        QtPrivate::TypeAndForceComplete<const QString &, std::false_type>
    >,
    nullptr
} };

void bseal::gui::MainWindow::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<MainWindow *>(_o);
        (void)_t;
        switch (_id) {
        case 0: _t->operationDone((*reinterpret_cast< std::add_pointer_t<bool>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2]))); break;
        case 1: _t->onBrowseInput(); break;
        case 2: _t->onBrowseOutput(); break;
        case 3: _t->onAddKeyfile(); break;
        case 4: _t->onRemoveKeyfile(); break;
        case 5: _t->onClearKeyfiles(); break;
        case 6: _t->onRun(); break;
        case 7: _t->onOperationFinished((*reinterpret_cast< std::add_pointer_t<bool>>(_a[1])),(*reinterpret_cast< std::add_pointer_t<QString>>(_a[2]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (MainWindow::*)(bool , const QString & );
            if (_t _q_method = &MainWindow::operationDone; *reinterpret_cast<_t *>(_a[1]) == _q_method) {
                *result = 0;
                return;
            }
        }
    }
}

const QMetaObject *bseal::gui::MainWindow::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *bseal::gui::MainWindow::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_bseal__gui__MainWindow.stringdata0))
        return static_cast<void*>(this);
    return QMainWindow::qt_metacast(_clname);
}

int bseal::gui::MainWindow::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QMainWindow::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 8)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 8;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 8)
            *reinterpret_cast<QMetaType *>(_a[0]) = QMetaType();
        _id -= 8;
    }
    return _id;
}

// SIGNAL 0
void bseal::gui::MainWindow::operationDone(bool _t1, const QString & _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t1))), const_cast<void*>(reinterpret_cast<const void*>(std::addressof(_t2))) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE

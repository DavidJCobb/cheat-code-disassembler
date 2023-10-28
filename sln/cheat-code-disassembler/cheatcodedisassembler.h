#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_cheatcodedisassembler.h"

class cheatcodedisassembler : public QMainWindow
{
    Q_OBJECT

public:
    cheatcodedisassembler(QWidget *parent = nullptr);
    ~cheatcodedisassembler();

private:
    Ui::cheatcodedisassemblerClass ui;
};

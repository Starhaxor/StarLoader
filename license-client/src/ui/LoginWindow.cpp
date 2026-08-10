#include "LoginWindow.h"
#include "ui_LoginWindow.h"
#include "HwidDialog.h"

#include <QPushButton>

LoginWindow::LoginWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::LoginWindow)
{
    ui->setupUi(this);
    setWindowFlags(Qt::Window | Qt::FramelessWindowHint);
    setAttribute(Qt::WA_TranslucentBackground);
    setFixedSize(size());

    connect(ui->hwidButton, &QPushButton::clicked,
            this, &LoginWindow::openHwidDialog);
}

LoginWindow::~LoginWindow()
{
    delete ui;
}

void LoginWindow::openHwidDialog()
{
    HwidDialog dialog(this);
    dialog.exec();
}

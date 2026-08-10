#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "hwiddialog.h"

#include <QPushButton>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setWindowFlags(Qt::Window | Qt::FramelessWindowHint);
    setAttribute(Qt::WA_TranslucentBackground);
    setFixedSize(size());

    connect(ui->hwidButton, &QPushButton::clicked,
            this, &MainWindow::openHwidDialog);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::openHwidDialog()
{
    HwidDialog dialog(this);
    dialog.exec();
}

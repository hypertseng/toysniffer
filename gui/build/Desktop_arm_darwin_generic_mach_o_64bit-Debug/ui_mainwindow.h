/********************************************************************************
** Form generated from reading UI file 'mainwindow.ui'
**
** Created by: Qt User Interface Compiler version 6.7.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <QtCharts/QChartView>
#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QScrollArea>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QTableView>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QTreeView>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QWidget *snifferWidget;
    QGridLayout *gridLayout_2;
    QGridLayout *gridLayout;
    QChartView *chartView;
    QWidget *toolBarWidget;
    QHBoxLayout *horizontalLayout;
    QPushButton *startCaptureButton;
    QSpacerItem *horizontalSpacer_2;
    QPushButton *stopCaptureButton;
    QSpacerItem *horizontalSpacer;
    QComboBox *interfaceComboBox;
    QSpacerItem *horizontalSpacer_3;
    QComboBox *processComboBox;
    QSpacerItem *horizontalSpacer_4;
    QComboBox *filterComboBox;
    QScrollArea *scrollArea;
    QWidget *scrollAreaWidgetContents;
    QWidget *layoutWidget;
    QHBoxLayout *horizontalLayout_2;
    QLabel *rawDataHexLabel;
    QLabel *rawDataAsciiLabel;
    QTableView *packetTableView;
    QTextEdit *logTextEdit;
    QTreeView *protocolTreeView;
    QLabel *label;
    QMenuBar *menubar;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName("MainWindow");
        MainWindow->resize(847, 655);
        QSizePolicy sizePolicy(QSizePolicy::Policy::Expanding, QSizePolicy::Policy::Expanding);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(MainWindow->sizePolicy().hasHeightForWidth());
        MainWindow->setSizePolicy(sizePolicy);
        snifferWidget = new QWidget(MainWindow);
        snifferWidget->setObjectName("snifferWidget");
        sizePolicy.setHeightForWidth(snifferWidget->sizePolicy().hasHeightForWidth());
        snifferWidget->setSizePolicy(sizePolicy);
        gridLayout_2 = new QGridLayout(snifferWidget);
        gridLayout_2->setObjectName("gridLayout_2");
        gridLayout = new QGridLayout();
        gridLayout->setObjectName("gridLayout");
        chartView = new QChartView(snifferWidget);
        chartView->setObjectName("chartView");

        gridLayout->addWidget(chartView, 4, 0, 1, 1);

        toolBarWidget = new QWidget(snifferWidget);
        toolBarWidget->setObjectName("toolBarWidget");
        QSizePolicy sizePolicy1(QSizePolicy::Policy::Expanding, QSizePolicy::Policy::Fixed);
        sizePolicy1.setHorizontalStretch(0);
        sizePolicy1.setVerticalStretch(0);
        sizePolicy1.setHeightForWidth(toolBarWidget->sizePolicy().hasHeightForWidth());
        toolBarWidget->setSizePolicy(sizePolicy1);
        horizontalLayout = new QHBoxLayout(toolBarWidget);
        horizontalLayout->setObjectName("horizontalLayout");
        horizontalLayout->setContentsMargins(8, 8, 8, 4);
        startCaptureButton = new QPushButton(toolBarWidget);
        startCaptureButton->setObjectName("startCaptureButton");
        QSizePolicy sizePolicy2(QSizePolicy::Policy::Expanding, QSizePolicy::Policy::Preferred);
        sizePolicy2.setHorizontalStretch(0);
        sizePolicy2.setVerticalStretch(0);
        sizePolicy2.setHeightForWidth(startCaptureButton->sizePolicy().hasHeightForWidth());
        startCaptureButton->setSizePolicy(sizePolicy2);

        horizontalLayout->addWidget(startCaptureButton);

        horizontalSpacer_2 = new QSpacerItem(40, 20, QSizePolicy::Policy::Expanding, QSizePolicy::Policy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_2);

        stopCaptureButton = new QPushButton(toolBarWidget);
        stopCaptureButton->setObjectName("stopCaptureButton");
        sizePolicy.setHeightForWidth(stopCaptureButton->sizePolicy().hasHeightForWidth());
        stopCaptureButton->setSizePolicy(sizePolicy);

        horizontalLayout->addWidget(stopCaptureButton);

        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Policy::Expanding, QSizePolicy::Policy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);

        interfaceComboBox = new QComboBox(toolBarWidget);
        interfaceComboBox->setObjectName("interfaceComboBox");
        sizePolicy.setHeightForWidth(interfaceComboBox->sizePolicy().hasHeightForWidth());
        interfaceComboBox->setSizePolicy(sizePolicy);

        horizontalLayout->addWidget(interfaceComboBox);

        horizontalSpacer_3 = new QSpacerItem(40, 20, QSizePolicy::Policy::Expanding, QSizePolicy::Policy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_3);

        processComboBox = new QComboBox(toolBarWidget);
        processComboBox->setObjectName("processComboBox");
        processComboBox->setMaximumSize(QSize(200, 16777215));

        horizontalLayout->addWidget(processComboBox);

        horizontalSpacer_4 = new QSpacerItem(40, 20, QSizePolicy::Policy::Expanding, QSizePolicy::Policy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_4);

        filterComboBox = new QComboBox(toolBarWidget);
        filterComboBox->setObjectName("filterComboBox");

        horizontalLayout->addWidget(filterComboBox);

        horizontalLayout->setStretch(0, 8);
        horizontalLayout->setStretch(1, 1);
        horizontalLayout->setStretch(2, 8);
        horizontalLayout->setStretch(3, 5);
        horizontalLayout->setStretch(4, 10);
        horizontalLayout->setStretch(5, 1);
        horizontalLayout->setStretch(6, 10);
        horizontalLayout->setStretch(7, 1);
        horizontalLayout->setStretch(8, 10);

        gridLayout->addWidget(toolBarWidget, 0, 0, 1, 2);

        scrollArea = new QScrollArea(snifferWidget);
        scrollArea->setObjectName("scrollArea");
        scrollArea->setWidgetResizable(true);
        scrollAreaWidgetContents = new QWidget();
        scrollAreaWidgetContents->setObjectName("scrollAreaWidgetContents");
        scrollAreaWidgetContents->setGeometry(QRect(0, 0, 693, 77));
        sizePolicy.setHeightForWidth(scrollAreaWidgetContents->sizePolicy().hasHeightForWidth());
        scrollAreaWidgetContents->setSizePolicy(sizePolicy);
        layoutWidget = new QWidget(scrollAreaWidgetContents);
        layoutWidget->setObjectName("layoutWidget");
        layoutWidget->setGeometry(QRect(10, 10, 671, 61));
        horizontalLayout_2 = new QHBoxLayout(layoutWidget);
        horizontalLayout_2->setObjectName("horizontalLayout_2");
        horizontalLayout_2->setContentsMargins(0, 0, 0, 0);
        rawDataHexLabel = new QLabel(layoutWidget);
        rawDataHexLabel->setObjectName("rawDataHexLabel");

        horizontalLayout_2->addWidget(rawDataHexLabel);

        rawDataAsciiLabel = new QLabel(layoutWidget);
        rawDataAsciiLabel->setObjectName("rawDataAsciiLabel");

        horizontalLayout_2->addWidget(rawDataAsciiLabel);

        horizontalLayout_2->setStretch(0, 3);
        horizontalLayout_2->setStretch(1, 1);
        scrollArea->setWidget(scrollAreaWidgetContents);

        gridLayout->addWidget(scrollArea, 3, 0, 1, 1);

        packetTableView = new QTableView(snifferWidget);
        packetTableView->setObjectName("packetTableView");

        gridLayout->addWidget(packetTableView, 1, 0, 1, 1);

        logTextEdit = new QTextEdit(snifferWidget);
        logTextEdit->setObjectName("logTextEdit");

        gridLayout->addWidget(logTextEdit, 1, 1, 4, 1);

        protocolTreeView = new QTreeView(snifferWidget);
        protocolTreeView->setObjectName("protocolTreeView");

        gridLayout->addWidget(protocolTreeView, 2, 0, 1, 1);

        label = new QLabel(snifferWidget);
        label->setObjectName("label");
        sizePolicy1.setHeightForWidth(label->sizePolicy().hasHeightForWidth());
        label->setSizePolicy(sizePolicy1);

        gridLayout->addWidget(label, 5, 0, 1, 2);

        gridLayout->setRowStretch(0, 7);
        gridLayout->setRowStretch(1, 27);
        gridLayout->setRowStretch(2, 14);
        gridLayout->setRowStretch(3, 14);
        gridLayout->setRowStretch(4, 26);
        gridLayout->setRowStretch(5, 2);
        gridLayout->setColumnStretch(0, 18);
        gridLayout->setColumnStretch(1, 3);

        gridLayout_2->addLayout(gridLayout, 0, 0, 1, 1);

        MainWindow->setCentralWidget(snifferWidget);
        menubar = new QMenuBar(MainWindow);
        menubar->setObjectName("menubar");
        menubar->setGeometry(QRect(0, 0, 847, 36));
        sizePolicy.setHeightForWidth(menubar->sizePolicy().hasHeightForWidth());
        menubar->setSizePolicy(sizePolicy);
        MainWindow->setMenuBar(menubar);
        statusbar = new QStatusBar(MainWindow);
        statusbar->setObjectName("statusbar");
        MainWindow->setStatusBar(statusbar);

        retranslateUi(MainWindow);

        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        MainWindow->setWindowTitle(QCoreApplication::translate("MainWindow", "MainWindow", nullptr));
        startCaptureButton->setText(QCoreApplication::translate("MainWindow", "\345\274\200\345\247\213", nullptr));
        stopCaptureButton->setText(QCoreApplication::translate("MainWindow", "\347\273\223\346\235\237", nullptr));
        rawDataHexLabel->setText(QCoreApplication::translate("MainWindow", "TextLabel", nullptr));
        rawDataAsciiLabel->setText(QString());
        label->setText(QCoreApplication::translate("MainWindow", "\344\270\255\345\233\275\347\247\221\345\255\246\351\231\242\345\244\247\345\255\2462024\345\271\264\347\247\213\350\275\257\344\273\266\344\270\216\347\263\273\347\273\237\345\256\211\345\205\250\350\257\276\347\250\213\302\267\345\256\236\351\252\214\344\270\200\357\274\232\345\270\246GUI\347\232\204\347\275\221\347\273\234\345\227\205\346\216\242\345\231\250\350\256\276\350\256\241\344\270\216\345\256\236\347\216\260             \342\200\224\342\200\224\346\233\276\345\255\220\347\221\204202428015059011", nullptr));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H

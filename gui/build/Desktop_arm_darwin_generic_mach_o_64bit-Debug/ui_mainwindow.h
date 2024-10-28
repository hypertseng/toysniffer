/********************************************************************************
** Form generated from reading UI file 'mainwindow.ui'
**
** Created by: Qt User Interface Compiler version 6.7.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QScrollArea>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QTableView>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QTreeView>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QWidget *snifferWidget;
    QVBoxLayout *verticalLayout_2;
    QVBoxLayout *verticalLayout;
    QWidget *toolBarWidget;
    QHBoxLayout *horizontalLayout;
    QPushButton *startCaptureButton;
    QSpacerItem *horizontalSpacer_2;
    QPushButton *stopCaptureButton;
    QSpacerItem *horizontalSpacer;
    QComboBox *interfaceComboBox;
    QSpacerItem *horizontalSpacer_3;
    QLineEdit *filterLineEdit;
    QTableView *packetTableView;
    QTreeView *protocolTreeView;
    QScrollArea *scrollArea;
    QWidget *scrollAreaWidgetContents;
    QWidget *widget;
    QHBoxLayout *horizontalLayout_2;
    QLabel *rawDataHexLabel;
    QLabel *rawDataAsciiLabel;
    QTextEdit *logTextEdit;
    QMenuBar *menubar;
    QStatusBar *statusbar;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName("MainWindow");
        MainWindow->resize(680, 762);
        QSizePolicy sizePolicy(QSizePolicy::Policy::Expanding, QSizePolicy::Policy::Expanding);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(MainWindow->sizePolicy().hasHeightForWidth());
        MainWindow->setSizePolicy(sizePolicy);
        snifferWidget = new QWidget(MainWindow);
        snifferWidget->setObjectName("snifferWidget");
        sizePolicy.setHeightForWidth(snifferWidget->sizePolicy().hasHeightForWidth());
        snifferWidget->setSizePolicy(sizePolicy);
        verticalLayout_2 = new QVBoxLayout(snifferWidget);
        verticalLayout_2->setObjectName("verticalLayout_2");
        verticalLayout = new QVBoxLayout();
        verticalLayout->setObjectName("verticalLayout");
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

        filterLineEdit = new QLineEdit(toolBarWidget);
        filterLineEdit->setObjectName("filterLineEdit");
        sizePolicy.setHeightForWidth(filterLineEdit->sizePolicy().hasHeightForWidth());
        filterLineEdit->setSizePolicy(sizePolicy);

        horizontalLayout->addWidget(filterLineEdit);

        horizontalLayout->setStretch(0, 10);
        horizontalLayout->setStretch(1, 1);
        horizontalLayout->setStretch(2, 10);
        horizontalLayout->setStretch(3, 5);
        horizontalLayout->setStretch(4, 10);
        horizontalLayout->setStretch(5, 1);
        horizontalLayout->setStretch(6, 12);

        verticalLayout->addWidget(toolBarWidget);

        packetTableView = new QTableView(snifferWidget);
        packetTableView->setObjectName("packetTableView");

        verticalLayout->addWidget(packetTableView);

        protocolTreeView = new QTreeView(snifferWidget);
        protocolTreeView->setObjectName("protocolTreeView");

        verticalLayout->addWidget(protocolTreeView);

        scrollArea = new QScrollArea(snifferWidget);
        scrollArea->setObjectName("scrollArea");
        scrollArea->setWidgetResizable(true);
        scrollAreaWidgetContents = new QWidget();
        scrollAreaWidgetContents->setObjectName("scrollAreaWidgetContents");
        scrollAreaWidgetContents->setGeometry(QRect(0, 0, 652, 146));
        widget = new QWidget(scrollAreaWidgetContents);
        widget->setObjectName("widget");
        widget->setGeometry(QRect(10, 10, 631, 111));
        horizontalLayout_2 = new QHBoxLayout(widget);
        horizontalLayout_2->setObjectName("horizontalLayout_2");
        horizontalLayout_2->setContentsMargins(0, 0, 0, 0);
        rawDataHexLabel = new QLabel(widget);
        rawDataHexLabel->setObjectName("rawDataHexLabel");

        horizontalLayout_2->addWidget(rawDataHexLabel);

        rawDataAsciiLabel = new QLabel(widget);
        rawDataAsciiLabel->setObjectName("rawDataAsciiLabel");

        horizontalLayout_2->addWidget(rawDataAsciiLabel);

        horizontalLayout_2->setStretch(0, 3);
        horizontalLayout_2->setStretch(1, 1);
        scrollArea->setWidget(scrollAreaWidgetContents);

        verticalLayout->addWidget(scrollArea);

        logTextEdit = new QTextEdit(snifferWidget);
        logTextEdit->setObjectName("logTextEdit");

        verticalLayout->addWidget(logTextEdit);

        verticalLayout->setStretch(0, 2);
        verticalLayout->setStretch(1, 8);
        verticalLayout->setStretch(2, 3);
        verticalLayout->setStretch(3, 5);
        verticalLayout->setStretch(4, 4);

        verticalLayout_2->addLayout(verticalLayout);

        MainWindow->setCentralWidget(snifferWidget);
        menubar = new QMenuBar(MainWindow);
        menubar->setObjectName("menubar");
        menubar->setGeometry(QRect(0, 0, 680, 36));
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
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H

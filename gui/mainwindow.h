#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "pcap.h"


QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onStartCapture();
    void onStopCapture();
    void onComboBoxChanged();
    void onFilterChanged();
    void handleFilterChange();

private:
    Ui::MainWindow *ui;
    char errbuf[PCAP_ERRBUF_SIZE]; /* error string */
    pcap_if_t *alldevs;
    QTimer *filterTimer;
};

#endif // MAINWINDOW_H

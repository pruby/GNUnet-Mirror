/********************************************************************************
** Form generated from reading ui file 'enhanced.ui'
**
** Created: Sat Dec 1 13:11:45 2007
**      by: Qt User Interface Compiler version 4.3.2
**
** WARNING! All changes made in this file will be lost when recompiling ui file!
********************************************************************************/

#ifndef UI_ENHANCED_H
#define UI_ENHANCED_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QListWidget>
#include <QtGui/QMainWindow>
#include <QtGui/QMenu>
#include <QtGui/QMenuBar>
#include <QtGui/QSplitter>
#include <QtGui/QStatusBar>
#include <QtGui/QTextBrowser>
#include <QtGui/QToolBar>
#include <QtGui/QTreeView>
#include <QtGui/QVBoxLayout>
#include <QtGui/QWidget>

class Ui_MainWindow
{
public:
    QAction *actionSave;
    QAction *actionAbout;
    QAction *actionExit;
    QWidget *centralwidget;
    QVBoxLayout *vboxLayout;
    QSplitter *splitter_2;
    QListWidget *listWidget;
    QSplitter *splitter;
    QTreeView *treeView;
    QTextBrowser *textBrowser;
    QMenuBar *menubar;
    QMenu *menuFile;
    QStatusBar *statusbar;
    QToolBar *toolBar;

    void setupUi(QMainWindow *MainWindow)
    {
    if (MainWindow->objectName().isEmpty())
        MainWindow->setObjectName(QString::fromUtf8("MainWindow"));
    MainWindow->resize(640, 480);
    MainWindow->setWindowIcon(QIcon(QString::fromUtf8(":/pixmaps/gnunet-logo-small.png")));
    actionSave = new QAction(MainWindow);
    actionSave->setObjectName(QString::fromUtf8("actionSave"));
    actionSave->setIcon(QIcon(QString::fromUtf8(":/pixmaps/media-floppy.png")));
    actionAbout = new QAction(MainWindow);
    actionAbout->setObjectName(QString::fromUtf8("actionAbout"));
    actionAbout->setIcon(QIcon(QString::fromUtf8(":/pixmaps/about.png")));
    actionExit = new QAction(MainWindow);
    actionExit->setObjectName(QString::fromUtf8("actionExit"));
    actionExit->setIcon(QIcon(QString::fromUtf8(":/pixmaps/exit.png")));
    centralwidget = new QWidget(MainWindow);
    centralwidget->setObjectName(QString::fromUtf8("centralwidget"));
    vboxLayout = new QVBoxLayout(centralwidget);
#ifndef Q_OS_MAC
    vboxLayout->setSpacing(6);
#endif
#ifndef Q_OS_MAC
    vboxLayout->setMargin(9);
#endif
    vboxLayout->setObjectName(QString::fromUtf8("vboxLayout"));
    splitter_2 = new QSplitter(centralwidget);
    splitter_2->setObjectName(QString::fromUtf8("splitter_2"));
    splitter_2->setOrientation(Qt::Horizontal);
    listWidget = new QListWidget(splitter_2);
    listWidget->setObjectName(QString::fromUtf8("listWidget"));
    listWidget->setMaximumSize(QSize(140, 16777215));
    listWidget->setIconSize(QSize(96, 84));
    listWidget->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    listWidget->setMovement(QListView::Static);
    listWidget->setSpacing(12);
    listWidget->setViewMode(QListView::IconMode);
    splitter_2->addWidget(listWidget);
    splitter = new QSplitter(splitter_2);
    splitter->setObjectName(QString::fromUtf8("splitter"));
    splitter->setOrientation(Qt::Vertical);
    treeView = new QTreeView(splitter);
    treeView->setObjectName(QString::fromUtf8("treeView"));
    splitter->addWidget(treeView);
    textBrowser = new QTextBrowser(splitter);
    textBrowser->setObjectName(QString::fromUtf8("textBrowser"));
    QSizePolicy sizePolicy(static_cast<QSizePolicy::Policy>(7), static_cast<QSizePolicy::Policy>(0));
    sizePolicy.setHorizontalStretch(0);
    sizePolicy.setVerticalStretch(0);
    sizePolicy.setHeightForWidth(textBrowser->sizePolicy().hasHeightForWidth());
    textBrowser->setSizePolicy(sizePolicy);
    textBrowser->setMaximumSize(QSize(16777215, 150));
    splitter->addWidget(textBrowser);
    splitter_2->addWidget(splitter);

    vboxLayout->addWidget(splitter_2);

    MainWindow->setCentralWidget(centralwidget);
    menubar = new QMenuBar(MainWindow);
    menubar->setObjectName(QString::fromUtf8("menubar"));
    menubar->setGeometry(QRect(0, 0, 640, 21));
    menuFile = new QMenu(menubar);
    menuFile->setObjectName(QString::fromUtf8("menuFile"));
    MainWindow->setMenuBar(menubar);
    statusbar = new QStatusBar(MainWindow);
    statusbar->setObjectName(QString::fromUtf8("statusbar"));
    MainWindow->setStatusBar(statusbar);
    toolBar = new QToolBar(MainWindow);
    toolBar->setObjectName(QString::fromUtf8("toolBar"));
    toolBar->setOrientation(Qt::Horizontal);
    MainWindow->addToolBar(static_cast<Qt::ToolBarArea>(4), toolBar);

    menubar->addAction(menuFile->menuAction());
    menuFile->addAction(actionSave);
    toolBar->addAction(actionSave);
    toolBar->addAction(actionAbout);
    toolBar->addAction(actionExit);

    retranslateUi(MainWindow);

    QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
    MainWindow->setWindowTitle(QApplication::translate("MainWindow", "gnunet-setup", 0, QApplication::UnicodeUTF8));
    actionSave->setText(QApplication::translate("MainWindow", "Save", 0, QApplication::UnicodeUTF8));
    actionAbout->setText(QApplication::translate("MainWindow", "About", 0, QApplication::UnicodeUTF8));
    actionExit->setText(QApplication::translate("MainWindow", "Exit", 0, QApplication::UnicodeUTF8));
    listWidget->clear();

    QListWidgetItem *__item = new QListWidgetItem(listWidget);
    __item->setText(QApplication::translate("MainWindow", "Meta-configuration", 0, QApplication::UnicodeUTF8));
    __item->setIcon(QIcon(QString::fromUtf8(":/pixmaps/sect-meta.png")));

    QListWidgetItem *__item1 = new QListWidgetItem(listWidget);
    __item1->setText(QApplication::translate("MainWindow", "Path settings", 0, QApplication::UnicodeUTF8));
    __item1->setIcon(QIcon(QString::fromUtf8(":/pixmaps/sect-paths.png")));

    QListWidgetItem *__item2 = new QListWidgetItem(listWidget);
    __item2->setText(QApplication::translate("MainWindow", "General settings", 0, QApplication::UnicodeUTF8));
    __item2->setIcon(QIcon(QString::fromUtf8(":/pixmaps/sect-general.png")));

    QListWidgetItem *__item3 = new QListWidgetItem(listWidget);
    __item3->setText(QApplication::translate("MainWindow", "Logging system", 0, QApplication::UnicodeUTF8));
    __item3->setIcon(QIcon(QString::fromUtf8(":/pixmaps/sect-log.png")));

    QListWidgetItem *__item4 = new QListWidgetItem(listWidget);
    __item4->setText(QApplication::translate("MainWindow", "Load management", 0, QApplication::UnicodeUTF8));
    __item4->setIcon(QIcon(QString::fromUtf8(":/pixmaps/sect-load.png")));

    QListWidgetItem *__item5 = new QListWidgetItem(listWidget);
    __item5->setText(QApplication::translate("MainWindow", "Modules", 0, QApplication::UnicodeUTF8));
    __item5->setIcon(QIcon(QString::fromUtf8(":/pixmaps/sect-modules.png")));

    QListWidgetItem *__item6 = new QListWidgetItem(listWidget);
    __item6->setText(QApplication::translate("MainWindow", "Transports", 0, QApplication::UnicodeUTF8));
    __item6->setIcon(QIcon(QString::fromUtf8(":/pixmaps/sect-transports.png")));

    QListWidgetItem *__item7 = new QListWidgetItem(listWidget);
    __item7->setText(QApplication::translate("MainWindow", "Applications", 0, QApplication::UnicodeUTF8));
    __item7->setIcon(QIcon(QString::fromUtf8(":/pixmaps/sect-apps.png")));
    menuFile->setTitle(QApplication::translate("MainWindow", "File", 0, QApplication::UnicodeUTF8));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

#endif // UI_ENHANCED_H

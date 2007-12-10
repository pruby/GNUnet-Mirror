/********************************************************************************
** Form generated from reading ui file 'gnunet-setup.ui'
**
** Created: Sun Dec 9 18:31:03 2007
**      by: Qt User Interface Compiler version 4.3.2
**
** WARNING! All changes made in this file will be lost when recompiling ui file!
********************************************************************************/

#ifndef UI_GNUNET_2D_SETUP_H
#define UI_GNUNET_2D_SETUP_H

#include <QtCore/QVariant>
#include <QtGui/QAction>
#include <QtGui/QApplication>
#include <QtGui/QButtonGroup>
#include <QtGui/QCheckBox>
#include <QtGui/QComboBox>
#include <QtGui/QGroupBox>
#include <QtGui/QHBoxLayout>
#include <QtGui/QLabel>
#include <QtGui/QLineEdit>
#include <QtGui/QPushButton>
#include <QtGui/QRadioButton>
#include <QtGui/QSpacerItem>
#include <QtGui/QSpinBox>
#include <QtGui/QStackedWidget>
#include <QtGui/QTextBrowser>
#include <QtGui/QVBoxLayout>
#include <QtGui/QWidget>

class Ui_SetupWizard
{
public:
  QVBoxLayout * vboxLayout;
  QStackedWidget *stackedWidget;
  QWidget *page;
  QVBoxLayout *vboxLayout1;
  QTextBrowser *textBrowser;
  QWidget *page_2;
  QVBoxLayout *vboxLayout2;
  QGroupBox *groupBox;
  QVBoxLayout *vboxLayout3;
  QLabel *label;
  QHBoxLayout *hboxLayout;
  QLabel *label_2;
  QSpacerItem *spacerItem;
  QComboBox *comboBox;
  QSpacerItem *spacerItem1;
  QLabel *label_3;
  QHBoxLayout *hboxLayout1;
  QLabel *label_4;
  QSpacerItem *spacerItem2;
  QLineEdit *lineEdit;
  QSpacerItem *spacerItem3;
  QLabel *label_5;
  QHBoxLayout *hboxLayout2;
  QCheckBox *checkBox;
  QSpacerItem *spacerItem4;
  QWidget *page_3;
  QVBoxLayout *vboxLayout4;
  QGroupBox *groupBox_2;
  QVBoxLayout *vboxLayout5;
  QLabel *label_6;
  QHBoxLayout *hboxLayout3;
  QLabel *label_7;
  QSpacerItem *spacerItem5;
  QLineEdit *lineEdit_2;
  QHBoxLayout *hboxLayout4;
  QLabel *label_8;
  QSpacerItem *spacerItem6;
  QLineEdit *lineEdit_3;
  QSpacerItem *spacerItem7;
  QRadioButton *radioButton;
  QRadioButton *radioButton_2;
  QSpacerItem *spacerItem8;
  QLabel *label_9;
  QHBoxLayout *hboxLayout5;
  QLabel *label_10;
  QSpacerItem *spacerItem9;
  QSpinBox *spinBox;
  QSpacerItem *spacerItem10;
  QWidget *page_4;
  QVBoxLayout *vboxLayout6;
  QGroupBox *groupBox_3;
  QVBoxLayout *vboxLayout7;
  QLabel *label_11;
  QHBoxLayout *hboxLayout6;
  QLabel *label_12;
  QSpacerItem *spacerItem11;
  QLineEdit *lineEdit_4;
  QHBoxLayout *hboxLayout7;
  QLabel *label_13;
  QSpacerItem *spacerItem12;
  QLineEdit *lineEdit_5;
  QSpacerItem *spacerItem13;
  QWidget *page_5;
  QVBoxLayout *vboxLayout8;
  QGroupBox *groupBox_4;
  QVBoxLayout *vboxLayout9;
  QLabel *label_14;
  QCheckBox *checkBox_2;
  QSpacerItem *spacerItem14;
  QLabel *label_15;
  QHBoxLayout *hboxLayout8;
  QLabel *label_16;
  QLineEdit *lineEdit_6;
  QSpacerItem *spacerItem15;
  QLabel *label_17;
  QCheckBox *checkBox_3;
  QSpacerItem *spacerItem16;
  QLabel *label_18;
  QCheckBox *checkBox_4;
  QSpacerItem *spacerItem17;
  QHBoxLayout *hboxLayout9;
  QSpacerItem *spacerItem18;
  QPushButton *pbPrev;
  QPushButton *pbNext;
  QPushButton *pbClose;

  void setupUi (QWidget * SetupWizard)
  {
    if (SetupWizard->objectName ().isEmpty ())
      SetupWizard->setObjectName (QString::fromUtf8 ("SetupWizard"));
    SetupWizard->resize (640, 480);
    SetupWizard->
      setWindowIcon (QIcon
                     (QString::fromUtf8 (":/pixmaps/gnunet-logo-small.png")));
    vboxLayout = new QVBoxLayout (SetupWizard);
#ifndef Q_OS_MAC
    vboxLayout->setSpacing (6);
#endif
#ifndef Q_OS_MAC
    vboxLayout->setMargin (9);
#endif
    vboxLayout->setObjectName (QString::fromUtf8 ("vboxLayout"));
    stackedWidget = new QStackedWidget (SetupWizard);
    stackedWidget->setObjectName (QString::fromUtf8 ("stackedWidget"));
    page = new QWidget ();
    page->setObjectName (QString::fromUtf8 ("page"));
    vboxLayout1 = new QVBoxLayout (page);
#ifndef Q_OS_MAC
    vboxLayout1->setSpacing (6);
#endif
#ifndef Q_OS_MAC
    vboxLayout1->setMargin (9);
#endif
    vboxLayout1->setObjectName (QString::fromUtf8 ("vboxLayout1"));
    textBrowser = new QTextBrowser (page);
    textBrowser->setObjectName (QString::fromUtf8 ("textBrowser"));

    vboxLayout1->addWidget (textBrowser);

    stackedWidget->addWidget (page);
    page_2 = new QWidget ();
    page_2->setObjectName (QString::fromUtf8 ("page_2"));
    vboxLayout2 = new QVBoxLayout (page_2);
#ifndef Q_OS_MAC
    vboxLayout2->setSpacing (6);
#endif
#ifndef Q_OS_MAC
    vboxLayout2->setMargin (9);
#endif
    vboxLayout2->setObjectName (QString::fromUtf8 ("vboxLayout2"));
    groupBox = new QGroupBox (page_2);
    groupBox->setObjectName (QString::fromUtf8 ("groupBox"));
    vboxLayout3 = new QVBoxLayout (groupBox);
#ifndef Q_OS_MAC
    vboxLayout3->setSpacing (6);
#endif
#ifndef Q_OS_MAC
    vboxLayout3->setMargin (9);
#endif
    vboxLayout3->setObjectName (QString::fromUtf8 ("vboxLayout3"));
    label = new QLabel (groupBox);
    label->setObjectName (QString::fromUtf8 ("label"));
    label->setFrameShape (QFrame::NoFrame);
    label->setWordWrap (true);

    vboxLayout3->addWidget (label);

    hboxLayout = new QHBoxLayout ();
#ifndef Q_OS_MAC
    hboxLayout->setSpacing (6);
#endif
    hboxLayout->setMargin (0);
    hboxLayout->setObjectName (QString::fromUtf8 ("hboxLayout"));
    label_2 = new QLabel (groupBox);
    label_2->setObjectName (QString::fromUtf8 ("label_2"));
    QFont font;
      font.setFamily (QString::fromUtf8 ("MS Shell Dlg 2"));
      font.setPointSize (8);
      font.setBold (true);
      font.setItalic (false);
      font.setUnderline (false);
      font.setWeight (75);
      font.setStrikeOut (false);
      label_2->setFont (font);

      hboxLayout->addWidget (label_2);

      spacerItem =
      new QSpacerItem (50, 20, QSizePolicy::Maximum, QSizePolicy::Minimum);

      hboxLayout->addItem (spacerItem);

      comboBox = new QComboBox (groupBox);
      comboBox->setObjectName (QString::fromUtf8 ("comboBox"));
      comboBox->setMinimumSize (QSize (420, 0));

      hboxLayout->addWidget (comboBox);


      vboxLayout3->addLayout (hboxLayout);

      spacerItem1 =
      new QSpacerItem (20, 20, QSizePolicy::Minimum, QSizePolicy::Fixed);

      vboxLayout3->addItem (spacerItem1);

      label_3 = new QLabel (groupBox);
      label_3->setObjectName (QString::fromUtf8 ("label_3"));
      label_3->setWordWrap (true);

      vboxLayout3->addWidget (label_3);

      hboxLayout1 = new QHBoxLayout ();
#ifndef Q_OS_MAC
      hboxLayout1->setSpacing (6);
#endif
      hboxLayout1->setMargin (0);
      hboxLayout1->setObjectName (QString::fromUtf8 ("hboxLayout1"));
      label_4 = new QLabel (groupBox);
      label_4->setObjectName (QString::fromUtf8 ("label_4"));
      label_4->setFont (font);

      hboxLayout1->addWidget (label_4);

      spacerItem2 =
      new QSpacerItem (50, 20, QSizePolicy::Maximum, QSizePolicy::Minimum);

      hboxLayout1->addItem (spacerItem2);

      lineEdit = new QLineEdit (groupBox);
      lineEdit->setObjectName (QString::fromUtf8 ("lineEdit"));
      lineEdit->setMinimumSize (QSize (420, 0));

      hboxLayout1->addWidget (lineEdit);


      vboxLayout3->addLayout (hboxLayout1);

      spacerItem3 =
      new QSpacerItem (20, 20, QSizePolicy::Minimum, QSizePolicy::Fixed);

      vboxLayout3->addItem (spacerItem3);

      label_5 = new QLabel (groupBox);
      label_5->setObjectName (QString::fromUtf8 ("label_5"));
      label_5->setWordWrap (true);

      vboxLayout3->addWidget (label_5);

      hboxLayout2 = new QHBoxLayout ();
#ifndef Q_OS_MAC
      hboxLayout2->setSpacing (6);
#endif
      hboxLayout2->setMargin (6);
      hboxLayout2->setObjectName (QString::fromUtf8 ("hboxLayout2"));
      checkBox = new QCheckBox (groupBox);
      checkBox->setObjectName (QString::fromUtf8 ("checkBox"));
      checkBox->setFont (font);

      hboxLayout2->addWidget (checkBox);


      vboxLayout3->addLayout (hboxLayout2);

      spacerItem4 =
      new QSpacerItem (20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);

      vboxLayout3->addItem (spacerItem4);


      vboxLayout2->addWidget (groupBox);

      stackedWidget->addWidget (page_2);
      page_3 = new QWidget ();
      page_3->setObjectName (QString::fromUtf8 ("page_3"));
      vboxLayout4 = new QVBoxLayout (page_3);
#ifndef Q_OS_MAC
      vboxLayout4->setSpacing (6);
#endif
#ifndef Q_OS_MAC
      vboxLayout4->setMargin (9);
#endif
      vboxLayout4->setObjectName (QString::fromUtf8 ("vboxLayout4"));
      groupBox_2 = new QGroupBox (page_3);
      groupBox_2->setObjectName (QString::fromUtf8 ("groupBox_2"));
      vboxLayout5 = new QVBoxLayout (groupBox_2);
#ifndef Q_OS_MAC
      vboxLayout5->setSpacing (6);
#endif
#ifndef Q_OS_MAC
      vboxLayout5->setMargin (9);
#endif
      vboxLayout5->setObjectName (QString::fromUtf8 ("vboxLayout5"));
      label_6 = new QLabel (groupBox_2);
      label_6->setObjectName (QString::fromUtf8 ("label_6"));
      label_6->setWordWrap (true);

      vboxLayout5->addWidget (label_6);

      hboxLayout3 = new QHBoxLayout ();
#ifndef Q_OS_MAC
      hboxLayout3->setSpacing (6);
#endif
      hboxLayout3->setMargin (0);
      hboxLayout3->setObjectName (QString::fromUtf8 ("hboxLayout3"));
      label_7 = new QLabel (groupBox_2);
      label_7->setObjectName (QString::fromUtf8 ("label_7"));
      label_7->setFont (font);

      hboxLayout3->addWidget (label_7);

      spacerItem5 =
      new QSpacerItem (40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

      hboxLayout3->addItem (spacerItem5);

      lineEdit_2 = new QLineEdit (groupBox_2);
      lineEdit_2->setObjectName (QString::fromUtf8 ("lineEdit_2"));
      lineEdit_2->setMinimumSize (QSize (420, 0));

      hboxLayout3->addWidget (lineEdit_2);


      vboxLayout5->addLayout (hboxLayout3);

      hboxLayout4 = new QHBoxLayout ();
#ifndef Q_OS_MAC
      hboxLayout4->setSpacing (6);
#endif
      hboxLayout4->setMargin (0);
      hboxLayout4->setObjectName (QString::fromUtf8 ("hboxLayout4"));
      label_8 = new QLabel (groupBox_2);
      label_8->setObjectName (QString::fromUtf8 ("label_8"));
      label_8->setFont (font);

      hboxLayout4->addWidget (label_8);

      spacerItem6 =
      new QSpacerItem (50, 20, QSizePolicy::Maximum, QSizePolicy::Minimum);

      hboxLayout4->addItem (spacerItem6);

      lineEdit_3 = new QLineEdit (groupBox_2);
      lineEdit_3->setObjectName (QString::fromUtf8 ("lineEdit_3"));
      lineEdit_3->setMinimumSize (QSize (420, 0));

      hboxLayout4->addWidget (lineEdit_3);


      vboxLayout5->addLayout (hboxLayout4);

      spacerItem7 =
      new QSpacerItem (20, 20, QSizePolicy::Minimum, QSizePolicy::Fixed);

      vboxLayout5->addItem (spacerItem7);

      radioButton = new QRadioButton (groupBox_2);
      radioButton->setObjectName (QString::fromUtf8 ("radioButton"));
      radioButton->setFont (font);

      vboxLayout5->addWidget (radioButton);

      radioButton_2 = new QRadioButton (groupBox_2);
      radioButton_2->setObjectName (QString::fromUtf8 ("radioButton_2"));
      radioButton_2->setFont (font);

      vboxLayout5->addWidget (radioButton_2);

      spacerItem8 =
      new QSpacerItem (20, 20, QSizePolicy::Minimum, QSizePolicy::Fixed);

      vboxLayout5->addItem (spacerItem8);

      label_9 = new QLabel (groupBox_2);
      label_9->setObjectName (QString::fromUtf8 ("label_9"));
      label_9->setWordWrap (true);

      vboxLayout5->addWidget (label_9);

      hboxLayout5 = new QHBoxLayout ();
#ifndef Q_OS_MAC
      hboxLayout5->setSpacing (6);
#endif
      hboxLayout5->setMargin (0);
      hboxLayout5->setObjectName (QString::fromUtf8 ("hboxLayout5"));
      label_10 = new QLabel (groupBox_2);
      label_10->setObjectName (QString::fromUtf8 ("label_10"));
      label_10->setFont (font);

      hboxLayout5->addWidget (label_10);

      spacerItem9 =
      new QSpacerItem (50, 20, QSizePolicy::Maximum, QSizePolicy::Minimum);

      hboxLayout5->addItem (spacerItem9);

      spinBox = new QSpinBox (groupBox_2);
      spinBox->setObjectName (QString::fromUtf8 ("spinBox"));
      spinBox->setMinimumSize (QSize (420, 0));

      hboxLayout5->addWidget (spinBox);


      vboxLayout5->addLayout (hboxLayout5);

      spacerItem10 =
      new QSpacerItem (20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);

      vboxLayout5->addItem (spacerItem10);


      vboxLayout4->addWidget (groupBox_2);

      stackedWidget->addWidget (page_3);
      page_4 = new QWidget ();
      page_4->setObjectName (QString::fromUtf8 ("page_4"));
      vboxLayout6 = new QVBoxLayout (page_4);
#ifndef Q_OS_MAC
      vboxLayout6->setSpacing (6);
#endif
#ifndef Q_OS_MAC
      vboxLayout6->setMargin (9);
#endif
      vboxLayout6->setObjectName (QString::fromUtf8 ("vboxLayout6"));
      groupBox_3 = new QGroupBox (page_4);
      groupBox_3->setObjectName (QString::fromUtf8 ("groupBox_3"));
      vboxLayout7 = new QVBoxLayout (groupBox_3);
#ifndef Q_OS_MAC
      vboxLayout7->setSpacing (6);
#endif
#ifndef Q_OS_MAC
      vboxLayout7->setMargin (9);
#endif
      vboxLayout7->setObjectName (QString::fromUtf8 ("vboxLayout7"));
      label_11 = new QLabel (groupBox_3);
      label_11->setObjectName (QString::fromUtf8 ("label_11"));
      label_11->setWordWrap (true);

      vboxLayout7->addWidget (label_11);

      hboxLayout6 = new QHBoxLayout ();
#ifndef Q_OS_MAC
      hboxLayout6->setSpacing (6);
#endif
      hboxLayout6->setMargin (0);
      hboxLayout6->setObjectName (QString::fromUtf8 ("hboxLayout6"));
      label_12 = new QLabel (groupBox_3);
      label_12->setObjectName (QString::fromUtf8 ("label_12"));
      label_12->setFont (font);

      hboxLayout6->addWidget (label_12);

      spacerItem11 =
      new QSpacerItem (50, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

      hboxLayout6->addItem (spacerItem11);

      lineEdit_4 = new QLineEdit (groupBox_3);
      lineEdit_4->setObjectName (QString::fromUtf8 ("lineEdit_4"));
      lineEdit_4->setMinimumSize (QSize (440, 0));

      hboxLayout6->addWidget (lineEdit_4);


      vboxLayout7->addLayout (hboxLayout6);

      hboxLayout7 = new QHBoxLayout ();
#ifndef Q_OS_MAC
      hboxLayout7->setSpacing (6);
#endif
      hboxLayout7->setMargin (0);
      hboxLayout7->setObjectName (QString::fromUtf8 ("hboxLayout7"));
      label_13 = new QLabel (groupBox_3);
      label_13->setObjectName (QString::fromUtf8 ("label_13"));
      label_13->setFont (font);

      hboxLayout7->addWidget (label_13);

      spacerItem12 =
      new QSpacerItem (50, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

      hboxLayout7->addItem (spacerItem12);

      lineEdit_5 = new QLineEdit (groupBox_3);
      lineEdit_5->setObjectName (QString::fromUtf8 ("lineEdit_5"));
      lineEdit_5->setMinimumSize (QSize (440, 0));

      hboxLayout7->addWidget (lineEdit_5);


      vboxLayout7->addLayout (hboxLayout7);

      spacerItem13 =
      new QSpacerItem (20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);

      vboxLayout7->addItem (spacerItem13);


      vboxLayout6->addWidget (groupBox_3);

      stackedWidget->addWidget (page_4);
      page_5 = new QWidget ();
      page_5->setObjectName (QString::fromUtf8 ("page_5"));
      vboxLayout8 = new QVBoxLayout (page_5);
#ifndef Q_OS_MAC
      vboxLayout8->setSpacing (6);
#endif
#ifndef Q_OS_MAC
      vboxLayout8->setMargin (9);
#endif
      vboxLayout8->setObjectName (QString::fromUtf8 ("vboxLayout8"));
      groupBox_4 = new QGroupBox (page_5);
      groupBox_4->setObjectName (QString::fromUtf8 ("groupBox_4"));
      vboxLayout9 = new QVBoxLayout (groupBox_4);
#ifndef Q_OS_MAC
      vboxLayout9->setSpacing (6);
#endif
#ifndef Q_OS_MAC
      vboxLayout9->setMargin (9);
#endif
      vboxLayout9->setObjectName (QString::fromUtf8 ("vboxLayout9"));
      label_14 = new QLabel (groupBox_4);
      label_14->setObjectName (QString::fromUtf8 ("label_14"));
      label_14->setWordWrap (true);

      vboxLayout9->addWidget (label_14);

      checkBox_2 = new QCheckBox (groupBox_4);
      checkBox_2->setObjectName (QString::fromUtf8 ("checkBox_2"));
      checkBox_2->setFont (font);

      vboxLayout9->addWidget (checkBox_2);

      spacerItem14 =
      new QSpacerItem (20, 20, QSizePolicy::Minimum, QSizePolicy::Fixed);

      vboxLayout9->addItem (spacerItem14);

      label_15 = new QLabel (groupBox_4);
      label_15->setObjectName (QString::fromUtf8 ("label_15"));
      label_15->setWordWrap (true);

      vboxLayout9->addWidget (label_15);

      hboxLayout8 = new QHBoxLayout ();
#ifndef Q_OS_MAC
      hboxLayout8->setSpacing (6);
#endif
      hboxLayout8->setMargin (0);
      hboxLayout8->setObjectName (QString::fromUtf8 ("hboxLayout8"));
      label_16 = new QLabel (groupBox_4);
      label_16->setObjectName (QString::fromUtf8 ("label_16"));
      label_16->setFont (font);

      hboxLayout8->addWidget (label_16);

      lineEdit_6 = new QLineEdit (groupBox_4);
      lineEdit_6->setObjectName (QString::fromUtf8 ("lineEdit_6"));

      hboxLayout8->addWidget (lineEdit_6);


      vboxLayout9->addLayout (hboxLayout8);

      spacerItem15 =
      new QSpacerItem (20, 20, QSizePolicy::Minimum, QSizePolicy::Fixed);

      vboxLayout9->addItem (spacerItem15);

      label_17 = new QLabel (groupBox_4);
      label_17->setObjectName (QString::fromUtf8 ("label_17"));
      label_17->setWordWrap (true);

      vboxLayout9->addWidget (label_17);

      checkBox_3 = new QCheckBox (groupBox_4);
      checkBox_3->setObjectName (QString::fromUtf8 ("checkBox_3"));
      checkBox_3->setFont (font);

      vboxLayout9->addWidget (checkBox_3);

      spacerItem16 =
      new QSpacerItem (20, 20, QSizePolicy::Minimum, QSizePolicy::Fixed);

      vboxLayout9->addItem (spacerItem16);

      label_18 = new QLabel (groupBox_4);
      label_18->setObjectName (QString::fromUtf8 ("label_18"));
      label_18->setWordWrap (true);

      vboxLayout9->addWidget (label_18);

      checkBox_4 = new QCheckBox (groupBox_4);
      checkBox_4->setObjectName (QString::fromUtf8 ("checkBox_4"));
      checkBox_4->setFont (font);

      vboxLayout9->addWidget (checkBox_4);

      spacerItem17 =
      new QSpacerItem (20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);

      vboxLayout9->addItem (spacerItem17);


      vboxLayout8->addWidget (groupBox_4);

      stackedWidget->addWidget (page_5);

      vboxLayout->addWidget (stackedWidget);

      hboxLayout9 = new QHBoxLayout ();
#ifndef Q_OS_MAC
      hboxLayout9->setSpacing (6);
#endif
      hboxLayout9->setMargin (0);
      hboxLayout9->setObjectName (QString::fromUtf8 ("hboxLayout9"));
      spacerItem18 =
      new QSpacerItem (40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

      hboxLayout9->addItem (spacerItem18);

      pbPrev = new QPushButton (SetupWizard);
      pbPrev->setObjectName (QString::fromUtf8 ("pbPrev"));
      pbPrev->setMinimumSize (QSize (75, 0));
      pbPrev->
      setIcon (QIcon (QString::fromUtf8 (":/pixmaps/go-previous.png")));
      pbPrev->setIconSize (QSize (22, 22));

      hboxLayout9->addWidget (pbPrev);

      pbNext = new QPushButton (SetupWizard);
      pbNext->setObjectName (QString::fromUtf8 ("pbNext"));
      pbNext->setMinimumSize (QSize (75, 0));
      pbNext->setIcon (QIcon (QString::fromUtf8 (":/pixmaps/go-next.png")));
      pbNext->setIconSize (QSize (22, 22));

      hboxLayout9->addWidget (pbNext);

      pbClose = new QPushButton (SetupWizard);
      pbClose->setObjectName (QString::fromUtf8 ("pbClose"));
      pbClose->setMinimumSize (QSize (75, 0));
      pbClose->setIcon (QIcon (QString::fromUtf8 (":/pixmaps/close.png")));
      pbClose->setIconSize (QSize (22, 22));

      hboxLayout9->addWidget (pbClose);


      vboxLayout->addLayout (hboxLayout9);


      retranslateUi (SetupWizard);

      stackedWidget->setCurrentIndex (0);


      QMetaObject::connectSlotsByName (SetupWizard);
  }                             // setupUi

  void retranslateUi (QWidget * SetupWizard)
  {
    SetupWizard->
      setWindowTitle (QApplication::
                      translate ("SetupWizard", "GNUnet setup", 0,
                                 QApplication::UnicodeUTF8));
    groupBox->
      setTitle (QApplication::
                translate ("SetupWizard",
                           "Network connection - enter information about your network connection here",
                           0, QApplication::UnicodeUTF8));
    label->
      setText (QApplication::
               translate ("SetupWizard",
                          "Choose the device that connects your computer to the internet. This is usually a modem, an ISDN card or a network card in case you are using DSL.",
                          0, QApplication::UnicodeUTF8));
    label_2->
      setText (QApplication::
               translate ("SetupWizard", "Network interface:", 0,
                          QApplication::UnicodeUTF8));
    label_3->
      setText (QApplication::
               translate ("SetupWizard",
                          "If your provider always assigns the same IP-Address to you (a \"static\" IP-Address), enter it into this field. If your IP-Address changes every now and then (\"dynamic\" IP-Address) but there's a hostname that always points to your actual IP-Address (\"Dynamic DNS\"), you can also enter it here.\n"
                          "If in doubt, leave the field empty. GNUnet will then try to determine your IP-Address.",
                          0, QApplication::UnicodeUTF8));
    label_4->
      setText (QApplication::
               translate ("SetupWizard", "IP-Address/Hostname:", 0,
                          QApplication::UnicodeUTF8));
    label_5->
      setText (QApplication::
               translate ("SetupWizard",
                          "If you are connected to the internet through another computer doing SNAT, a router or a \"hardware firewall\" and other computers on the internet cannot connect to this computer, check the this option on this page. Leave it unchecked on direct connections through modems, ISDN cards and DNAT (also known as \"port forwarding\").",
                          0, QApplication::UnicodeUTF8));
    checkBox->
      setText (QApplication::
               translate ("SetupWizard",
                          "Computer cannot receive inbound connections", 0,
                          QApplication::UnicodeUTF8));
    groupBox_2->
      setTitle (QApplication::
                translate ("SetupWizard",
                           "Load limitation - limit GNUnet's ressource usage here",
                           0, QApplication::UnicodeUTF8));
    label_6->
      setText (QApplication::
               translate ("SetupWizard",
                          "This is how much data may be sent per second. If you have a flatrate you can set it to the maximum speed of your internet connection.",
                          0, QApplication::UnicodeUTF8));
    label_7->
      setText (QApplication::
               translate ("SetupWizard", "Upstream (Bytes/s):", 0,
                          QApplication::UnicodeUTF8));
    label_8->
      setText (QApplication::
               translate ("SetupWizard", "Downstream (Bytes/s):", 0,
                          QApplication::UnicodeUTF8));
    radioButton->
      setText (QApplication::
               translate ("SetupWizard", "Use denoted bandwidth for GNUnet",
                          0, QApplication::UnicodeUTF8));
    radioButton_2->
      setText (QApplication::
               translate ("SetupWizard",
                          "Share denoted bandwidth with other applications",
                          0, QApplication::UnicodeUTF8));
    label_9->
      setText (QApplication::
               translate ("SetupWizard",
                          "Enter the percentage of processor time GNUnet is allowed to use here.",
                          0, QApplication::UnicodeUTF8));
    label_10->
      setText (QApplication::
               translate ("SetupWizard", "Maximum CPU usage (%):", 0,
                          QApplication::UnicodeUTF8));
    groupBox_3->
      setTitle (QApplication::
                translate ("SetupWizard",
                           "Security settings - specify the user and the group owning the GNUnet service here",
                           0, QApplication::UnicodeUTF8));
    label_11->
      setText (QApplication::
               translate ("SetupWizard",
                          "For security reasons, it is a good idea to let this setup create a new user account and a new group under which the GNUnet service is started at system startup.\n"
                          "\n"
                          "However, GNUnet may not be able to access files other than its own. This includes files you want to publish in GNUnet. You will have to grant read permissions to the user specified below.\n"
                          "\n"
                          "Leave the fields empty to run GNUnet with system privileges.",
                          0, QApplication::UnicodeUTF8));
    label_12->
      setText (QApplication::
               translate ("SetupWizard", "User account:", 0,
                          QApplication::UnicodeUTF8));
    label_13->
      setText (QApplication::
               translate ("SetupWizard", "Group:", 0,
                          QApplication::UnicodeUTF8));
    groupBox_4->
      setTitle (QApplication::
                translate ("SetupWizard", "Other settings", 0,
                           QApplication::UnicodeUTF8));
    label_14->
      setText (QApplication::
               translate ("SetupWizard",
                          "GNUnet is able to store data from other peers in your datastore. This is useful if an adversary has access to your inserted content and you need to deny that the content is yours. With \"content migration\" on, the content could have \"migrated\" over the internet to your node without your knowledge.\n"
                          "It also helps to spread popular content over different peers to enhance availability.",
                          0, QApplication::UnicodeUTF8));
    checkBox_2->
      setText (QApplication::
               translate ("SetupWizard", "Store migrated content", 0,
                          QApplication::UnicodeUTF8));
    label_15->
      setText (QApplication::
               translate ("SetupWizard",
                          "The GNUnet datastore contains all data that GNUnet generates (index data, inserted and migrated content). Its maximum size can be specified below.",
                          0, QApplication::UnicodeUTF8));
    label_16->
      setText (QApplication::
               translate ("SetupWizard", "Maximum datastore size (MB):", 0,
                          QApplication::UnicodeUTF8));
    label_17->
      setText (QApplication::
               translate ("SetupWizard",
                          "If you are an experienced user, you may want to tweak your GNUnet installation using the enhanced configurator.",
                          0, QApplication::UnicodeUTF8));
    checkBox_3->
      setText (QApplication::
               translate ("SetupWizard", "Open the enhanced configurator", 0,
                          QApplication::UnicodeUTF8));
    label_18->
      setText (QApplication::
               translate ("SetupWizard",
                          "After changing the configuration and/or updating GNUnet, it is sometimes required to run gnunet-update to update internal data structures. Depending on the changes made, this may take some time.",
                          0, QApplication::UnicodeUTF8));
    checkBox_4->
      setText (QApplication::
               translate ("SetupWizard", "Run gnunet-update", 0,
                          QApplication::UnicodeUTF8));
    pbPrev->
      setText (QApplication::
               translate ("SetupWizard", "Previous", 0,
                          QApplication::UnicodeUTF8));
    pbNext->
      setText (QApplication::
               translate ("SetupWizard", "Next", 0,
                          QApplication::UnicodeUTF8));
    pbClose->
      setText (QApplication::
               translate ("SetupWizard", "Close", 0,
                          QApplication::UnicodeUTF8));
    Q_UNUSED (SetupWizard);
  }                             // retranslateUi

};

namespace Ui
{
  class SetupWizard:public Ui_SetupWizard
  {
  };
}                               // namespace Ui

#endif                          // UI_GNUNET_2D_SETUP_H

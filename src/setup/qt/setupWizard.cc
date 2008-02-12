/*
     This file is part of GNUnet.
     (C) 2007 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

#include <QtCore/QObject>
#include <QtCore/QProcess>
#include <QtCore/QStringList>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtGui/QMessageBox>
#include <QtGui/QDesktopServices>

#include "setupWizard.h"
#include "config.h"
#include "plibc.h"
#include "gnunet_util.h"
#include "gnunet_setup_lib.h"
#include "gstring.h"
#ifndef Q_OS_WIN32
#include <errno.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#endif
extern "C" {
#include "wizard_util.h"
}

QString GSetupWizard::header()
{
  return QString(
        "<table bgcolor=\"#3F4C6B\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\" height=\"62\" width=\"100%\">"
          "<tr>"
            "<td colspan=\"3\" height=\"10\" nowrap=\"nowrap\" valign=\"middle\" />"
          "</tr>"
          "<tr>"
            "<td width=\"20\" />"
            "<td>"
              "<font color=\"white\" face=\"Arial, Helvetica\" size=\"6\"><b>GNUnet</b></font>"
              "<br>"
              "<font color=\"#d3d3d3\" size=\"4\" face=\"Bitstream Vera Sans, Lucida Grande, Trebuchet MS, Lucida Sans Unicode, Luxi Sans, Helvetica, Arial, Sans-Serif\">"
                  + tr("GNU&#8216;s decentralized anonymous and censorship-resistant P2P framework.") +
              "</font>"
            "<td align=\"right\">"
                "<img src=\"qrc:/pixmaps/gnunet-net-logo.png\" />&nbsp;&nbsp;&nbsp;&nbsp;"
            "</td>"
          "</tr>"
        "</table>"
        "<table bgcolor=\"#3F4C6B\" border=\"0\" cellpadding=\"0\" cellspacing=\"0\" width=\"100%\">"
          "<tr>"
            "<td>&nbsp;</td>"
          "</tr>"
        "</table>"
        "<br>"  
  );
}

GSetupWizard::GSetupWizard(QDialog *parent, struct GNUNET_GE_Context *ectx, struct GNUNET_GC_Configuration *cfg, const char *cfg_fn) : QDialog(parent)
{
  setupUi(this);
  welcome();
  
  curPage = 0;

  this->ectx = ectx;
  this->cfg = cfg;
  this->cfg_fn = cfg_fn;
  
  pbPrev->setHidden(true);
  
  connect(pbNext, SIGNAL(clicked()), this, SLOT(nextClicked()));
  connect(pbPrev, SIGNAL(clicked()), this, SLOT(prevClicked()));
  connect(pbClose, SIGNAL(clicked()) , this, SLOT(abortClicked()));
  connect(htmlWelcome, SIGNAL(anchorClicked(const QUrl &)), this, SLOT(linkHandler(const QUrl &)));
  
  loadDefaults();
}

static int insert_nic (const char *name, int defaultNIC, void *cls)
{
  QString str;
  QComboBox *cmbIF;
  
  cmbIF = (QComboBox *) cls;
  str = name;
  if (str.length() == 0)
    str = QObject::tr("(unknown connection)");
  
  cmbIF->addItem(str);
  if (defaultNIC)
    cmbIF->setCurrentIndex(cmbIF->count() - 1);

  return GNUNET_OK;
}

void GSetupWizard::loadDefaults()
{
  char *val;
  unsigned long long num;
  
  // page 2
  GNUNET_list_network_interfaces (ectx, &insert_nic, cmbIF);
  
  GNUNET_GC_get_configuration_value_string (cfg, "NETWORK", "IP", "",
                                            &val);
  editIP->setText(val);
  GNUNET_free_non_null(val);
  
  cbSNAT->setChecked(GNUNET_GC_get_configuration_value_yesno(cfg, "NAT", "LIMITED",
                                 GNUNET_NO) == GNUNET_YES);
                                 
  // page 3
  GNUNET_GC_get_configuration_value_string (cfg,
                                            "LOAD",
                                            "MAXNETUPBPSTOTAL", "50000",
                                            &val);
  editUp->setText(val);
  GNUNET_free_non_null(val);
  
  GNUNET_GC_get_configuration_value_string (cfg,
                                            "LOAD",
                                            "MAXNETDOWNBPSTOTAL", "50000",
                                            &val);
  editDown->setText(val);
  GNUNET_free_non_null(val);

  if (GNUNET_GC_get_configuration_value_yesno (cfg,
                                                "LOAD",
                                                "BASICLIMITING",
                                                GNUNET_NO) == GNUNET_YES)
  {
    rbFull->setChecked(true);
  }
  else
  {
    rbShared->setChecked(true);
  }
  
  GNUNET_GC_get_configuration_value_string (cfg,
                                            "LOAD", "MAXCPULOAD", "50", &val);
  spinCPU->setValue(atoi(val));
  GNUNET_free_non_null(val);
  
  // page 4
  char *uname = NULL;
  char *gname = NULL;
  char *user_name, *group_name;
  int cap;

  GNUNET_GC_get_configuration_value_string (cfg,
                                            "GNUNETD", "USER", "gnunet",
                                            &uname);
  GNUNET_GC_get_configuration_value_string (cfg,
                                            "GNUNETD",
                                            "GROUP", "gnunet", &gname);

#ifndef Q_OS_WIN32
  if (NULL == uname || strlen (uname) == 0)
    {
      if ((geteuid () == 0) || (NULL != getpwnam ("gnunet")))
        user_name = GNUNET_strdup ("gnunet");
      else
        {
          GNUNET_free_non_null(uname);
          uname = getenv ("USER");
          if (uname != NULL)
            user_name = GNUNET_strdup (uname);
          else
            user_name = NULL;
        }
    }
  else
    {
      user_name = GNUNET_strdup (uname);
    }
  if (NULL == gname || strlen (gname) == 0)
    {
      struct group *grp;
      
      if ((geteuid () == 0) || (NULL != getgrnam ("gnunet")))
        group_name = GNUNET_strdup ("gnunet");
      else
        {
          grp = getgrgid (getegid ());
          if ((grp != NULL) && (grp->gr_name != NULL))
            group_name = GNUNET_strdup (grp->gr_name);
          else
            group_name = NULL;
        }
    }
  else
    {
      group_name = GNUNET_strdup (gname);
    }

#else
  if (NULL == uname || strlen (uname) == 0)
    user_name = GNUNET_strdup ("");
  else
    user_name = GNUNET_strdup (uname);
  if (NULL == gname || strlen (gname) == 0)
    group_name = GNUNET_strdup ("");
  else
    group_name = GNUNET_strdup (gname);
#endif

  if (user_name != NULL)
    editUser->setText(user_name);
  if (group_name != NULL)
    editGroup->setText(group_name);
  cap = GNUNET_configure_autostart (ectx, 1, 1, NULL, NULL, NULL);
  cbAutostart->setEnabled(cap);
  cap = GNUNET_configure_user_account(1, 1, NULL, NULL);
  if (!cap) {
    editUser->setEnabled(false);
    editUser->setText("");
  }
#ifdef WINDOWS
  cap = FALSE;
#endif
  
  if (!cap) {
    editGroup->setEnabled(false);
    editGroup->setText("");
  }

  GNUNET_free_non_null(uname);
  GNUNET_free_non_null(gname);
  
  // page 5
  GNUNET_GC_get_configuration_value_number(cfg, "FS", "QUOTA", 1, 1000000, 1024, &num);
  spinQuota->setValue(num);
  
  cbMigr->setChecked(GNUNET_GC_get_configuration_value_yesno
                                (cfg, "FS", "ACTIVEMIGRATION",
                                 GNUNET_YES) == GNUNET_YES);

  cbAutostart->setChecked(GNUNET_GC_get_configuration_value_yesno
                                (cfg, "GNUNETD", "AUTOSTART",
                                 GNUNET_NO) == GNUNET_YES);
}

int GSetupWizard::saveConf()
{
  GString str;
  
  str = cmbIF->currentText();
#ifdef Q_OS_WIN32
  int idx;
  
  idx = str.lastIndexOf("- ");
  if (idx == -1)
  {
    QMessageBox::critical(this, tr("Error"), tr("Malformed interface name. Please report this to gnunet-developers@gnu.org: ") + str);
    return GNUNET_NO;
  }
  str.remove(0, idx + 2);
  str.remove(str.length() - 1, 1);
#endif

  GNUNET_GC_set_configuration_value_string(cfg, ectx, "NETWORK", "INTERFACE", str.toUtf8CStr());
  GNUNET_GC_set_configuration_value_string(cfg, ectx, "LOAD", "INTERFACES", str.toUtf8CStr());
  str = editIP->text();
  GNUNET_GC_set_configuration_value_string(cfg, ectx, "NETWORK", "IP", str.toUtf8CStr());
  GNUNET_GC_set_configuration_value_choice(cfg, ectx, "NAT", "LIMITED", cbSNAT->isChecked() ? "YES" : "NO");
  str = editDown->text();
  GNUNET_GC_set_configuration_value_string(cfg, ectx, "LOAD", "MAXNETDOWNBPSTOTAL", str.toUtf8CStr());
  str = editUp->text();
  GNUNET_GC_set_configuration_value_string(cfg, ectx, "LOAD", "MAXNETUPBPSTOTAL", str.toUtf8CStr());  
  GNUNET_GC_set_configuration_value_choice(cfg, ectx, "LOAD", "BASICLIMITING", rbFull->isChecked() ? "YES" : "NO");
  GNUNET_GC_set_configuration_value_number(cfg, ectx, "LOAD", "MAXCPULOAD", spinCPU->value());  
  str = editUser->text();
  GNUNET_GC_set_configuration_value_string(cfg, ectx, "GNUNETD", "USER", str.toUtf8CStr());
  str = editGroup->text();
  GNUNET_GC_set_configuration_value_string(cfg, ectx, "GNUNETD", "GROUP", str.toUtf8CStr());  
  GNUNET_GC_set_configuration_value_choice(cfg, ectx, "FS", "ACTIVEMIGRATION", cbMigr->isChecked() ? "YES" : "NO");
  GNUNET_GC_set_configuration_value_number(cfg, ectx, "FS", "QUOTA", spinQuota->value());  
  GNUNET_GC_set_configuration_value_choice(cfg, ectx, "GNUNETD", "AUTOSTART", cbAutostart->isChecked() ? "YES" : "NO");
  
  if (GNUNET_GC_write_configuration (cfg, cfg_fn))
    {
      QMessageBox::critical(this, tr("Error"), tr("Unable to save configuration file ") +
        QString(cfg_fn) + ": " + QString(STRERROR(errno)));
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

void GSetupWizard::abortClicked()
{
  QMessageBox::StandardButton ret;
  int ok;
  
  ret = QMessageBox::question(this, tr("Save"), tr("Do you want to save the new configuration?"),
    QMessageBox::Yes | QMessageBox::No | QMessageBox::Cancel, QMessageBox::Yes);
  switch(ret)
  {
    case QMessageBox::Yes:
      ok = saveConf();
      break;
    case QMessageBox::No:
      ok = GNUNET_OK;
      break;
    case QMessageBox::Cancel:
    default:
      ok = GNUNET_NO;
  }
  
  if (ok)
    qApp->quit();
}

void GSetupWizard::nextClicked()
{
  pbPrev->setHidden(false);
  
  if (curPage == 3)
  {
    pbNext->setIcon(QIcon(":/pixmaps/exit.png"));
    pbNext->setText(tr("Finish"));
  }
  else if (curPage == 4)
  {
    GString str;
    char *user_name, *group_name;
    
    str = editUser->text();
    user_name = strdup(str.toUtf8CStr());
    str = editGroup->text();
    group_name = strdup(str.toUtf8CStr());
    
    if (cbAutostart->isChecked() && strlen(user_name))
      if (!GNUNET_GNS_wiz_create_group_user (group_name, user_name))
        {
#ifndef Q_OS_WIN32
          QMessageBox::critical(this, tr("Error"), QString("Unable to create user account: ") +
            STRERROR(errno));
#endif
          GNUNET_free(user_name);
          GNUNET_free(group_name);
          return;
        }
  
    if (GNUNET_GNS_wiz_autostart_service (cbAutostart->isChecked(), user_name, group_name) !=
        GNUNET_OK)
      {
#ifndef Q_OS_WIN32
          QMessageBox::critical(this, tr("Error"), QString("Unable to change startup process: ") +
            STRERROR(errno));
#endif
      }

    GNUNET_free(user_name);
    GNUNET_free(group_name);
  
    if (GNUNET_OK != saveConf ())
      return;
    
    if (cbGNUpdate->isChecked())
      {
        QProcess proc;
        QStringList args;
        char *bin;
        
        args << "-L" << "INFO" << "-c" << cfg_fn;
        bin = GNUNET_get_installation_path (GNUNET_IPK_BINDIR);        
        proc.setWorkingDirectory(bin);
        proc.setStandardErrorFile(QDir::tempPath() + DIR_SEPARATOR_STR "gnunet-setup.err");
        proc.setStandardOutputFile(QDir::tempPath() + DIR_SEPARATOR_STR "gnunet-setup.out");        
        GNUNET_free_non_null(bin);
        proc.start("gnunet-update", args);
        proc.waitForFinished(-1);
        if (proc.error() != QProcess::UnknownError || proc.exitCode() != 0)
        {
          QMessageBox::critical(this, tr("Error"), "Running gnunet-setup failed, its output has been saved to " +
                     QDir::tempPath() + DIR_SEPARATOR_STR "gnunet-setup.*\n" +
                     "This maybe due to insufficient permissions, please check your configuration.\n"
                     "Finally, run gnunet-update manually.");
        }
        else
        {
          QFile(QDir::tempPath() + DIR_SEPARATOR_STR "gnunet-setup.err").remove();
          QFile(QDir::tempPath() + DIR_SEPARATOR_STR "gnunet-setup.out").remove();
        }
      }
    qApp->quit();

    return;
  }
  
  curPage++;
  stackedWidget->setCurrentIndex(curPage);
}

void GSetupWizard::prevClicked()
{
  if (curPage == 4)
  {
    pbNext->setIcon(QIcon(":/pixmaps/go-next.png"));
    pbNext->setText(tr("Next"));    
  }
  else if (curPage == 1)
    pbPrev->setHidden(true);
  else if (curPage == 0)
    return;
  
  curPage--;
  stackedWidget->setCurrentIndex(curPage);
}

void GSetupWizard::welcome()
{
  htmlWelcome->setHtml(
    "<html>"
      "<body>" +
        header() +
        "<center>"
          "<font size=\"5\"><b>" + tr("Welcome to ") + PACKAGE_STRING "</b></font>"
          "<br />"
          "<br />"
          "<table width=\"91%\">"
            "<tr>"
              "<td>"
                "<font size=\"4\">" +
    tr("This assistant will ask you a few basic questions in order to configure GNUnet.") +
                  "<br /><br />" +
    tr("Please visit our homepage at") +
                  "<br /><br />&nbsp;&nbsp;&nbsp;&nbsp;<a href=\"http://gnunet.org\">http://gnunet.org</a><br /><br />" +
    tr("and join our community:") +
                  "<ul>" +
                    "<li>" +
    tr("Help, discussion and polls: ") +
                      "<a href=\"http://gnunet.org/drupal/\">http://gnunet.org/drupal/</a>" +
                    "</li>" +
                    "<li>" +
    tr("IRC chat with users and developers: ") +
                      "<a href=\"http://irc.netsplit.de/channels/?chat=gnunet\">#gnunet</a> " +
    tr("on Freenode") +
                    "</li>" +
                  "</ul>" +
                  "</font>"
              "</td>"
            "</tr>"
            "<tr>"
              "<td colspan=\"2\">&nbsp;</td>"
            "</tr>"
            "<tr>"
              "<td colspan=\"2\">&nbsp;</td>"
            "</tr>"
            "<tr>"
              "<td>"
               "<font size=\"4\">" +
                  tr("Have a lot fun,") +
                  "<br /><br />"
                  "&nbsp;&nbsp;&nbsp;&nbsp;" +
                  tr("The GNUnet team") +
                "</font>"
              "</td>"
            "</tr>"
          "</table>"
        "</center>"
      "</body>"
    "</html>");
}

void GSetupWizard::linkHandler(const QUrl &link)
{
  QDesktopServices::openUrl(link);
  welcome();
}

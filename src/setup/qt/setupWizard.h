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

#include <Qt/qobject.h>
#include <Qt/qdialog.h>

#include "ui_gnunet-setup.h"

class GSetupWizard:public QDialog, private
  Ui::SetupWizard
{
  Q_OBJECT
public:
  GSetupWizard (QDialog * parent, struct GNUNET_GE_Context *ectx,
                struct GNUNET_GC_Configuration *cfg, const char *cfg_fn);

  protected
    slots:void
  nextClicked ();
  void
  prevClicked ();
  void
  abortClicked ();
  void linkHandler(const QUrl &link);
protected:
  QString
  header ();
  void
  loadDefaults ();
  int
  saveConf ();
  void welcome();

  unsigned int
    curPage;
  const char *
    cfg_fn;
  struct GNUNET_GE_Context *
    ectx;
  struct GNUNET_GC_Configuration *
    cfg;
};

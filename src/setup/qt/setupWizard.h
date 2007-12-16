#include <Qt/qobject.h>
#include <Qt/qdialog.h>

#include "ui_gnunet-setup.h"

class GSetupWizard:public QDialog, private
  Ui::SetupWizard
{
  Q_OBJECT
public:
  GSetupWizard (QDialog * parent, struct GNUNET_GE_Context *ectx, struct GNUNET_GC_Configuration *cfg, const char *cfg_fn);

protected slots:
  void nextClicked();
  void prevClicked();
  void abortClicked();
protected:
  QString header();
  void loadDefaults();
  int saveConf();

  unsigned int curPage;
  const char *cfg_fn;
  struct GNUNET_GE_Context *
    ectx;
  struct GNUNET_GC_Configuration *
    cfg;
};

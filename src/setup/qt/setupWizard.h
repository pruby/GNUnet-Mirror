#include <Qt/qobject.h>
#include <Qt/qdialog.h>

#include "ui_gnunet-setup.h"

class GSetupWizard : public QDialog, private Ui::SetupWizard 
{
  Q_OBJECT
  
public:
  GSetupWizard(QDialog *parent = NULL);
  void setErrorContext(struct GNUNET_GE_Context *ectx);
  void setConfig(struct GNUNET_GC_Configuration *cfg);

protected:
  struct GNUNET_GE_Context *ectx;
  struct GNUNET_GC_Configuration *cfg;
};

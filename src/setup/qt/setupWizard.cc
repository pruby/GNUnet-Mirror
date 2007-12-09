#include "setupWizard.h"

GSetupWizard::GSetupWizard(QDialog *parent) : QDialog(parent)
{
  setupUi(this);
}

void GSetupWizard::setErrorContext(struct GNUNET_GE_Context *ectx)
{
  this->ectx = ectx;
}

void GSetupWizard::setConfig(struct GNUNET_GC_Configuration *cfg)
{
  this->cfg = cfg;
}

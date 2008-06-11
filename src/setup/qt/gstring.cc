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
/**
 * @file src/setup/qt/gstring.cc
 * @brief Extended QString
 * @author Nils Durner
 */

#include <QtCore/QByteArray>
#include <malloc.h>
#include "gstring.h"

GString::GString(const char *str) : QString(str)
{
  cstr = NULL;
}

GString::GString() : QString()
{
  cstr = NULL;
}

GString::~GString()
{
  if (cstr)
    ::free(cstr);
}

GString &GString::operator=(const QString &src)
{
  if (cstr)
  {
    ::free(cstr);
    cstr = NULL;
  }

  QString::operator=(src);
  return *this;
}

GString &GString::operator=(const GString &src)
{
  if (cstr)
  {
    ::free(cstr);
    cstr = NULL;
  }

  QString::operator=(src);
  return *this;
}

GString &GString::operator=(const char *src)
{
  if (cstr)
  {
    ::free(cstr);
    cstr = NULL;
  }

  QString::operator=(src);
  return *this;
}

GString::GString(QString &src) : QString(src)
{
  cstr = NULL;
}

char *GString::toCString()
{
  QByteArray bytes = toLocal8Bit();
  
  if (cstr)
    ::free(cstr);
  
  return cstr = strdup(bytes.data());
}

char *GString::toUtf8CStr()
{
  QByteArray bytes = toUtf8();
  
  if (cstr)
    ::free(cstr);
  
  return cstr = strdup(bytes.data());
}

/* end of gstring.cc */

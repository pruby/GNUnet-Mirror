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
 * @file src/setup/qt/gstring.h
 * @brief Extended QString
 * @author Nils Durner
 */

#ifndef GNUNET_GSTRING_H_
#define GNUNET_GSTRING_H_

#include <QtCore/QString>

class GString:public QString
{
public:
  GString ();
  GString (const char *str);
    GString (QString & src);
   ~GString ();
    GString & operator= (const QString & src);
    GString & operator= (const GString & src);
    GString & operator= (const char *src);

 /**
  * @brief Return the content as C string
  */
  char *toCString ();

 /**
  * @brief Return the content as UTF-8 encoded C string
  */
  char *toUtf8CStr ();

protected:
  char *cstr;
};

#endif /*GNUNET_STRING_H_ */

/* end of gstring.h */
